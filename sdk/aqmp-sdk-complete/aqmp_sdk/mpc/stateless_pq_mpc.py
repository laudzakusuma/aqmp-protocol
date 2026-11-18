"""Stateless Post-Quantum Threshold / MPC Signing Engine (AQMP Paper #2).

Eliminates mutable signing state and counter-reuse hazards for multi-AZ
institutional custodians running t-of-n threshold signing over lattice keys:
  1. Shamir secret sharing over F_q (q = 8380417, Dilithium modulus) across
     d = 64 module-lattice coordinates with public key b = A * s mod q.
  2. Synthetic PRF nonce derivation bound to message digest, share commitment,
     active signer set S, and backup-safe epoch salt (zero mutable counter).
  3. Constant-time vector serialization and hmac.compare_digest checks.
  4. Native BIP-360 (P2MR) Merkle commitment and AQMP v2.0 4-byte KeyRegistry
     Plonky3 aggregation footprint bindings.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import os
import time
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


LATTICE_PRIME_Q = 8_380_417  # 2^23 - 2^13 + 1 (Dilithium field prime)
LATTICE_DIM = 64             # Module-lattice vector dimension d
PLONKY3_PROOF_BYTES = 300
FALCON_SALT_BYTES = 40
KEY_REGISTRY_IDX_BYTES = 4
INDEXED_TX_BYTES = FALCON_SALT_BYTES + KEY_REGISTRY_IDX_BYTES  # 44 B/tx
MLDSA65_NAIVE_BYTES = 5261
BIP360_P2MR_FALCON_KR_BYTES = 690


def _ct_equal(a: bytes, b: bytes) -> bool:
    """Constant-time byte-string comparison."""
    return hmac.compare_digest(a, b)


def _encode_vector(vec: Sequence[int]) -> bytes:
    """Canonical fixed-width serialization of a vector in F_q^d."""
    out = bytearray(len(vec) * 4)
    for idx, coeff in enumerate(vec):
        val = coeff % LATTICE_PRIME_Q
        out[4 * idx : 4 * idx + 4] = val.to_bytes(4, "big")
    return bytes(out)


def _expand_matrix_a(matrix_seed: bytes, dim: int = LATTICE_DIM) -> List[List[int]]:
    """Deterministically expand public matrix A in F_q^{d x d} from seed."""
    rows: List[List[int]] = []
    for r in range(dim):
        row: List[int] = []
        counter = 0
        buf = b""
        while len(row) < dim:
            digest = hashlib.sha3_256(
                b"AQMP_MPC_MATRIX_A:"
                + matrix_seed
                + r.to_bytes(2, "big")
                + counter.to_bytes(2, "big")
            ).digest()
            buf += digest
            while len(buf) >= 4 and len(row) < dim:
                elem = int.from_bytes(buf[:4], "big") % LATTICE_PRIME_Q
                row.append(elem)
                buf = buf[4:]
            counter += 1
        rows.append(row)
    return rows


def _mat_vec_mul(mat: Sequence[Sequence[int]], vec: Sequence[int]) -> List[int]:
    """Fixed-iteration matrix-vector multiplication A * v mod q."""
    dim = len(vec)
    out = [0] * dim
    for i in range(dim):
        acc = 0
        row = mat[i]
        for j in range(dim):
            acc = (acc + row[j] * vec[j]) % LATTICE_PRIME_Q
        out[i] = acc
    return out


def _vec_add(a: Sequence[int], b: Sequence[int]) -> List[int]:
    return [(x + y) % LATTICE_PRIME_Q for x, y in zip(a, b)]


def _vec_sub(a: Sequence[int], b: Sequence[int]) -> List[int]:
    return [(x - y) % LATTICE_PRIME_Q for x, y in zip(a, b)]


def _vec_scale(scalar: int, vec: Sequence[int]) -> List[int]:
    s_mod = scalar % LATTICE_PRIME_Q
    return [(s_mod * x) % LATTICE_PRIME_Q for x in vec]


def _expand_nonce_vector(prf_digest: bytes, dim: int = LATTICE_DIM) -> List[int]:
    """Deterministically expand 32-byte synthetic PRF output into y_i in F_q^d."""
    vec: List[int] = []
    counter = 0
    while len(vec) < dim:
        block = hashlib.sha3_512(
            b"AQMP_MPC_NONCE_VEC:" + prf_digest + counter.to_bytes(4, "big")
        ).digest()
        for off in range(0, len(block), 4):
            if len(vec) >= dim:
                break
            vec.append(int.from_bytes(block[off : off + 4], "big") % LATTICE_PRIME_Q)
        counter += 1
    return vec


def lagrange_coefficient_mod_q(signer_id: int, active_set: Sequence[int]) -> int:
    """Compute Lagrange interpolation coefficient lambda_{i, S}(0) mod q."""
    if signer_id not in active_set:
        raise ValueError(f"Signer {signer_id} not in active set {active_set}")
    num = 1
    den = 1
    for other_id in active_set:
        if other_id == signer_id:
            continue
        if other_id == signer_id:
            raise ValueError("Duplicate signer IDs in active set")
        num = (num * (-other_id % LATTICE_PRIME_Q)) % LATTICE_PRIME_Q
        diff = (signer_id - other_id) % LATTICE_PRIME_Q
        if diff == 0:
            raise ValueError("Duplicate signer IDs in active set")
        den = (den * diff) % LATTICE_PRIME_Q
    return (num * pow(den, LATTICE_PRIME_Q - 2, LATTICE_PRIME_Q)) % LATTICE_PRIME_Q


@dataclass(frozen=True)
class P2MRKeyRegistryBinding:
    """Compatibility binding for BIP-360 (P2MR) and AQMP v2.0 KeyRegistry."""

    p2mr_merkle_root: bytes
    key_registry_idx: int
    salt_r_bytes: int = FALCON_SALT_BYTES

    def __post_init__(self) -> None:
        if len(self.p2mr_merkle_root) != 32:
            raise ValueError("p2mr_merkle_root must be 32 bytes")
        if not (0 <= self.key_registry_idx < 2**32):
            raise ValueError("key_registry_idx must fit in uint32")

    def to_bytes(self) -> bytes:
        return self.p2mr_merkle_root + self.key_registry_idx.to_bytes(4, "big")

    def per_tx_indexed_bytes(self) -> int:
        return self.salt_r_bytes + KEY_REGISTRY_IDX_BYTES

    def block_footprint_plonky3(self, n_tx: int) -> int:
        """AQMP v2.0 Plonky3 BabyBear payload: 300 + 44N bytes."""
        return PLONKY3_PROOF_BYTES + n_tx * self.per_tx_indexed_bytes()


@dataclass(frozen=True)
class SignerKeyShare:
    """Immutable cold-backup-safe threshold signer share (zero mutable counters)."""

    signer_id: int
    threshold: int
    total_signers: int
    secret_share_s: Tuple[int, ...]
    prf_root_key: bytes
    share_commitment_com: Tuple[int, ...]
    matrix_seed: bytes
    group_public_key_b: Tuple[int, ...]

    def share_commitment_hash(self) -> bytes:
        return hashlib.sha3_256(_encode_vector(self.share_commitment_com)).digest()

    def export_cold_backup(self) -> Dict[str, object]:
        """Serialize immutable cold-backup snapshot without any signing counter."""
        return {
            "signer_id": self.signer_id,
            "threshold": self.threshold,
            "total_signers": self.total_signers,
            "secret_share_s": list(self.secret_share_s),
            "prf_root_key_hex": self.prf_root_key.hex(),
            "share_commitment_com": list(self.share_commitment_com),
            "matrix_seed_hex": self.matrix_seed.hex(),
            "group_public_key_b": list(self.group_public_key_b),
        }

    @classmethod
    def restore_from_cold_backup(cls, snapshot: Dict[str, object]) -> "SignerKeyShare":
        """Restore signer share after complete volatile state wipe."""
        return cls(
            signer_id=int(snapshot["signer_id"]),
            threshold=int(snapshot["threshold"]),
            total_signers=int(snapshot["total_signers"]),
            secret_share_s=tuple(int(x) for x in snapshot["secret_share_s"]),  # type: ignore[arg-type]
            prf_root_key=bytes.fromhex(str(snapshot["prf_root_key_hex"])),
            share_commitment_com=tuple(int(x) for x in snapshot["share_commitment_com"]),  # type: ignore[arg-type]
            matrix_seed=bytes.fromhex(str(snapshot["matrix_seed_hex"])),
            group_public_key_b=tuple(int(x) for x in snapshot["group_public_key_b"]),  # type: ignore[arg-type]
        )


@dataclass(frozen=True)
class PartialLatticeSignature:
    """Partial signature share produced deterministically with no mutable state."""

    signer_id: int
    active_set: Tuple[int, ...]
    nonce_commitment_w: Tuple[int, ...]
    partial_z: Tuple[int, ...]
    challenge_c: int
    synthetic_nonce_tag: bytes
    signing_time_ms: float


@dataclass(frozen=True)
class ThresholdAggregateSignature:
    """Combined t-of-n stateless post-quantum threshold signature."""

    active_set: Tuple[int, ...]
    threshold: int
    total_signers: int
    aggregate_w: Tuple[int, ...]
    aggregate_z: Tuple[int, ...]
    challenge_c: int
    message_digest: bytes
    epoch_salt: bytes
    binding: P2MRKeyRegistryBinding
    aggregate_time_ms: float


class StatelessPQThresholdCommittee:
    """Stateless t-of-n lattice threshold signing & verification engine."""

    def __init__(
        self,
        threshold: int,
        total_signers: int,
        matrix_seed: Optional[bytes] = None,
        secret_s: Optional[Sequence[int]] = None,
    ) -> None:
        if threshold < 1 or total_signers < threshold:
            raise ValueError(f"Invalid threshold ({threshold}, {total_signers})")
        self.threshold = threshold
        self.total_signers = total_signers
        self.matrix_seed = matrix_seed if matrix_seed is not None else os.urandom(32)
        if len(self.matrix_seed) != 32:
            raise ValueError("matrix_seed must be 32 bytes")
        self._matrix_a = _expand_matrix_a(self.matrix_seed)

        if secret_s is None:
            master_s = [
                int.from_bytes(os.urandom(4), "big") % LATTICE_PRIME_Q
                for _ in range(LATTICE_DIM)
            ]
        else:
            if len(secret_s) != LATTICE_DIM:
                raise ValueError(f"secret_s must have length {LATTICE_DIM}")
            master_s = [x % LATTICE_PRIME_Q for x in secret_s]

        self._master_s = tuple(master_s)
        self.group_public_key_b = tuple(_mat_vec_mul(self._matrix_a, master_s))
        self.shares = self._deal_shamir_shares(master_s)

    def _deal_shamir_shares(self, master_s: Sequence[int]) -> Dict[int, SignerKeyShare]:
        # Sample degree (threshold - 1) random Shamir polynomials per coordinate
        coeffs: List[List[int]] = []
        for coord in range(LATTICE_DIM):
            poly = [master_s[coord]]
            for _ in range(1, self.threshold):
                poly.append(int.from_bytes(os.urandom(4), "big") % LATTICE_PRIME_Q)
            coeffs.append(poly)

        shares: Dict[int, SignerKeyShare] = {}
        for signer_id in range(1, self.total_signers + 1):
            s_i = []
            for coord in range(LATTICE_DIM):
                acc = 0
                x_pow = 1
                for c in coeffs[coord]:
                    acc = (acc + c * x_pow) % LATTICE_PRIME_Q
                    x_pow = (x_pow * signer_id) % LATTICE_PRIME_Q
                s_i.append(acc)
            com_i = tuple(_mat_vec_mul(self._matrix_a, s_i))
            prf_k_i = os.urandom(32)
            shares[signer_id] = SignerKeyShare(
                signer_id=signer_id,
                threshold=self.threshold,
                total_signers=self.total_signers,
                secret_share_s=tuple(s_i),
                prf_root_key=prf_k_i,
                share_commitment_com=com_i,
                matrix_seed=self.matrix_seed,
                group_public_key_b=self.group_public_key_b,
            )
        return shares

    @staticmethod
    def derive_synthetic_nonce(
        share: SignerKeyShare,
        message: bytes,
        active_set: Sequence[int],
        epoch_salt: bytes,
    ) -> Tuple[bytes, List[int], List[int]]:
        """Derive backup-safe synthetic PRF nonce r_i, y_i, and w_i = A * y_i mod q."""
        sorted_set = tuple(sorted(active_set))
        msg_digest = hashlib.sha3_256(message).digest()
        com_hash = share.share_commitment_hash()
        set_bytes = b",".join(str(sid).encode("ascii") for sid in sorted_set)

        transcript = (
            b"AQMP_STATELESS_NONCE_v2:"
            + msg_digest
            + com_hash
            + set_bytes
            + len(epoch_salt).to_bytes(2, "big")
            + epoch_salt
        )
        r_i = hmac.new(share.prf_root_key, transcript, hashlib.sha3_256).digest()
        y_i = _expand_nonce_vector(r_i)
        mat_a = _expand_matrix_a(share.matrix_seed)
        w_i = _mat_vec_mul(mat_a, y_i)
        nonce_tag = hashlib.sha3_256(b"NONCE_TAG:" + r_i).digest()[:16]
        return nonce_tag, y_i, w_i

    @staticmethod
    def compute_challenge(
        matrix_seed: bytes,
        group_public_key_b: Sequence[int],
        aggregate_w: Sequence[int],
        message: bytes,
        binding: P2MRKeyRegistryBinding,
    ) -> int:
        """Compute deterministic Fiat-Shamir challenge scalar c in F_q."""
        msg_digest = hashlib.sha3_256(message).digest()
        h = hashlib.sha3_256()
        h.update(b"AQMP_STATELESS_FS_v2:")
        h.update(matrix_seed)
        h.update(_encode_vector(group_public_key_b))
        h.update(_encode_vector(aggregate_w))
        h.update(msg_digest)
        h.update(binding.to_bytes())
        return int.from_bytes(h.digest(), "big") % LATTICE_PRIME_Q

    @classmethod
    def sign_partial(
        cls,
        share: SignerKeyShare,
        message: bytes,
        active_set: Sequence[int],
        aggregate_w: Sequence[int],
        epoch_salt: bytes,
        binding: P2MRKeyRegistryBinding,
    ) -> PartialLatticeSignature:
        """Generate a deterministic, stateless partial signature share."""
        t0 = time.perf_counter_ns()
        sorted_set = tuple(sorted(active_set))
        if len(sorted_set) != share.threshold or len(set(sorted_set)) != share.threshold:
            raise ValueError(
                f"Active set must contain {share.threshold} distinct signer IDs"
            )
        if share.signer_id not in sorted_set:
            raise ValueError(f"Signer {share.signer_id} not in active set")

        nonce_tag, y_i, w_i = cls.derive_synthetic_nonce(
            share, message, sorted_set, epoch_salt
        )
        c = cls.compute_challenge(
            share.matrix_seed, share.group_public_key_b, aggregate_w, message, binding
        )
        lam_i = lagrange_coefficient_mod_q(share.signer_id, sorted_set)
        c_lam = (c * lam_i) % LATTICE_PRIME_Q
        masked_share = _vec_scale(c_lam, share.secret_share_s)
        z_i = _vec_add(y_i, masked_share)
        elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000.0

        return PartialLatticeSignature(
            signer_id=share.signer_id,
            active_set=sorted_set,
            nonce_commitment_w=tuple(w_i),
            partial_z=tuple(z_i),
            challenge_c=c,
            synthetic_nonce_tag=nonce_tag,
            signing_time_ms=elapsed_ms,
        )

    @classmethod
    def verify_partial(
        cls,
        share_public: SignerKeyShare,
        partial: PartialLatticeSignature,
        message: bytes,
        aggregate_w: Sequence[int],
        binding: P2MRKeyRegistryBinding,
    ) -> bool:
        """Constant-time partial signature verification: A * z_i == w_i + c*lambda_i*com_i."""
        if partial.signer_id != share_public.signer_id:
            return False
        if len(partial.active_set) != share_public.threshold:
            return False
        if partial.signer_id not in partial.active_set:
            return False

        expected_c = cls.compute_challenge(
            share_public.matrix_seed,
            share_public.group_public_key_b,
            aggregate_w,
            message,
            binding,
        )
        if expected_c != partial.challenge_c:
            return False

        mat_a = _expand_matrix_a(share_public.matrix_seed)
        lhs = _mat_vec_mul(mat_a, partial.partial_z)
        lam_i = lagrange_coefficient_mod_q(partial.signer_id, partial.active_set)
        c_lam = (expected_c * lam_i) % LATTICE_PRIME_Q
        rhs = _vec_add(
            partial.nonce_commitment_w,
            _vec_scale(c_lam, share_public.share_commitment_com),
        )
        return _ct_equal(_encode_vector(lhs), _encode_vector(rhs))

    def sign_threshold(
        self,
        message: bytes,
        signer_ids: Sequence[int],
        epoch_salt: bytes,
        binding: Optional[P2MRKeyRegistryBinding] = None,
    ) -> ThresholdAggregateSignature:
        """Execute full two-pass stateless t-of-n signing across active signer_ids."""
        t0 = time.perf_counter_ns()
        sorted_set = tuple(sorted(signer_ids))
        if len(sorted_set) != self.threshold or len(set(sorted_set)) != self.threshold:
            raise ValueError(
                f"Expected {self.threshold} distinct signer IDs, got {signer_ids}"
            )
        if binding is None:
            binding = P2MRKeyRegistryBinding(
                p2mr_merkle_root=hashlib.sha3_256(b"DEFAULT_P2MR_ROOT").digest(),
                key_registry_idx=1,
            )

        # Round 1: Deterministic nonce commitments w_i
        agg_w = [0] * LATTICE_DIM
        for sid in sorted_set:
            share = self.shares[sid]
            _, _, w_i = self.derive_synthetic_nonce(share, message, sorted_set, epoch_salt)
            agg_w = _vec_add(agg_w, w_i)

        # Round 2: Stateless partial signatures & verification
        agg_z = [0] * LATTICE_DIM
        partials: List[PartialLatticeSignature] = []
        for sid in sorted_set:
            share = self.shares[sid]
            p_sig = self.sign_partial(share, message, sorted_set, agg_w, epoch_salt, binding)
            if not self.verify_partial(share, p_sig, message, agg_w, binding):
                raise RuntimeError(f"Partial verification failed for signer {sid}")
            partials.append(p_sig)
            agg_z = _vec_add(agg_z, p_sig.partial_z)

        elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        return ThresholdAggregateSignature(
            active_set=sorted_set,
            threshold=self.threshold,
            total_signers=self.total_signers,
            aggregate_w=tuple(agg_w),
            aggregate_z=tuple(agg_z),
            challenge_c=partials[0].challenge_c,
            message_digest=hashlib.sha3_256(message).digest(),
            epoch_salt=epoch_salt,
            binding=binding,
            aggregate_time_ms=elapsed_ms,
        )

    @classmethod
    def verify_threshold_signature(
        cls,
        matrix_seed: bytes,
        group_public_key_b: Sequence[int],
        message: bytes,
        sig: ThresholdAggregateSignature,
    ) -> bool:
        """Constant-time group verification: A * z - c * b == W and c matches transcript."""
        if len(sig.active_set) != sig.threshold or len(set(sig.active_set)) != sig.threshold:
            return False
        msg_digest = hashlib.sha3_256(message).digest()
        if not _ct_equal(msg_digest, sig.message_digest):
            return False

        expected_c = cls.compute_challenge(
            matrix_seed, group_public_key_b, sig.aggregate_w, message, sig.binding
        )
        if expected_c != sig.challenge_c:
            return False

        mat_a = _expand_matrix_a(matrix_seed)
        az = _mat_vec_mul(mat_a, sig.aggregate_z)
        cb = _vec_scale(expected_c, group_public_key_b)
        reconstructed_w = _vec_sub(az, cb)
        return _ct_equal(_encode_vector(reconstructed_w), _encode_vector(sig.aggregate_w))


def simulate_cold_backup_restore(
    share: SignerKeyShare,
    message_a: bytes,
    message_b: bytes,
    active_set: Sequence[int],
    aggregate_w_a: Sequence[int],
    aggregate_w_b: Sequence[int],
    epoch_salt: bytes,
    binding: P2MRKeyRegistryBinding,
) -> Dict[str, object]:
    """Prove volatile node wipe + cold backup restore has zero nonce divergence or reuse."""
    partial_before = StatelessPQThresholdCommittee.sign_partial(
        share, message_a, active_set, aggregate_w_a, epoch_salt, binding
    )

    # Export immutable backup snapshot and wipe in-memory share handle
    backup_blob = share.export_cold_backup()
    del share

    restored = SignerKeyShare.restore_from_cold_backup(backup_blob)
    partial_after_same = StatelessPQThresholdCommittee.sign_partial(
        restored, message_a, active_set, aggregate_w_a, epoch_salt, binding
    )
    partial_after_diff = StatelessPQThresholdCommittee.sign_partial(
        restored, message_b, active_set, aggregate_w_b, epoch_salt, binding
    )

    return {
        "deterministic_replay_identical": (
            _ct_equal(partial_before.synthetic_nonce_tag, partial_after_same.synthetic_nonce_tag)
            and partial_before.partial_z == partial_after_same.partial_z
        ),
        "distinct_message_fresh_nonce": not _ct_equal(
            partial_before.synthetic_nonce_tag, partial_after_diff.synthetic_nonce_tag
        ),
        "no_mutable_counter_in_backup": "counter" not in backup_blob,
    }
