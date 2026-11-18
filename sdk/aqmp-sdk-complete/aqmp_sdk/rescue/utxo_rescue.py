"""Knowledge-Asymmetry Frozen UTXO Rescue Protocol (AQMP Paper #2).

Enables rightful owners of quantum-vulnerable or draft-BIP-361 frozen Bitcoin
UTXOs to migrate funds to a PQC destination WITHOUT exposing the raw ECDSA
public key on-chain:
  1. Unhardened BIP-32 xpub chain-code knowledge proof: proves possession of the
     256-bit symmetric parent chain code c_par and pre-compromise derivation
     index via a post-quantum module-lattice Fiat-Shamir proof of knowledge
     over F_q^32 (q = 8380417) without exposing P_par or P_child in plaintext.
  2. Exact 580-byte compact stateful timestamped inclusion proof:
       32 B chain-code knowledge commitment
     + 64 B lattice PoK commitment & challenge (H(w_KA) || c_digest)
     + 164 B timestamped UTXO snapshot Merkle proof (4B index + 5*32B siblings)
     + 320 B PQC lattice-NIZK & destination binding (128B z_KA + 128B b_KA + 64B dest_tag)
     = 580 B rescue witness.
  3. AQMP v2.0 Dual-Commit XOR binding (32 B Commit Tx1 + 64 B Reveal/Rotate Tx2
     = 96 B DCL cycle, total 676 B) gated by Fukuda's confirmation window
     Delta_eff >= Delta*(epsilon) = ceil(4 / (1 - epsilon)).
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import os
from typing import List, Optional, Sequence, Tuple

try:
    from aqmp_sdk.dcl.dual_commit import (
        DUAL_COMMIT_CYCLE_BYTES,
        DualCommitXORCommitTx,
        DualCommitXORRevealTx,
        DualCommitXORVerifier,
    )
    from aqmp_sdk.oracle.threat_oracle import (
        FukudaLivenessViolationError,
        enforce_finality_window,
    )
except ImportError:
    from dcl.dual_commit import (
        DUAL_COMMIT_CYCLE_BYTES,
        DualCommitXORCommitTx,
        DualCommitXORRevealTx,
        DualCommitXORVerifier,
    )
    from oracle.threat_oracle import (
        FukudaLivenessViolationError,
        enforce_finality_window,
    )


RESCUE_LATTICE_Q = 8_380_417
RESCUE_LATTICE_DIM = 32

RESCUE_CHAINCODE_COM_BYTES = 32
RESCUE_BINDING_BYTES = 64
RESCUE_MERKLE_PROOF_BYTES = 164  # 4 B leaf index + 5 * 32 B sibling hashes
RESCUE_PQC_NIZK_BYTES = 320      # 128 B z_KA + 128 B b_KA + 64 B dest_tag
RESCUE_PROOF_BYTES = (
    RESCUE_CHAINCODE_COM_BYTES
    + RESCUE_BINDING_BYTES
    + RESCUE_MERKLE_PROOF_BYTES
    + RESCUE_PQC_NIZK_BYTES
)  # 580 B exact budget
RESCUE_MERKLE_DEPTH = 5


def _sha3(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def _hash160_sim(pubkey_bytes: bytes) -> bytes:
    """20-byte Bitcoin-style address digest (SHA256 -> BLAKE2s-20)."""
    h1 = hashlib.sha256(pubkey_bytes).digest()
    return hashlib.blake2s(h1, digest_size=20).digest()


def _encode_vec32(vec: Sequence[int]) -> bytes:
    out = bytearray(RESCUE_LATTICE_DIM * 4)
    for i, val in enumerate(vec):
        out[4 * i : 4 * i + 4] = (val % RESCUE_LATTICE_Q).to_bytes(4, "big")
    return bytes(out)


def _decode_vec32(blob: bytes) -> List[int]:
    if len(blob) != RESCUE_LATTICE_DIM * 4:
        raise ValueError(f"Expected {RESCUE_LATTICE_DIM * 4} bytes, got {len(blob)}")
    return [
        int.from_bytes(blob[4 * i : 4 * i + 4], "big") % RESCUE_LATTICE_Q
        for i in range(RESCUE_LATTICE_DIM)
    ]


def _expand_rescue_vec(seed: bytes, domain: bytes) -> List[int]:
    vec: List[int] = []
    ctr = 0
    while len(vec) < RESCUE_LATTICE_DIM:
        block = hashlib.sha3_512(domain + seed + ctr.to_bytes(4, "big")).digest()
        for off in range(0, len(block), 4):
            if len(vec) >= RESCUE_LATTICE_DIM:
                break
            vec.append(int.from_bytes(block[off : off + 4], "big") % RESCUE_LATTICE_Q)
        ctr += 1
    return vec


def _rescue_matrix_a(utxo_id: bytes) -> List[List[int]]:
    rows: List[List[int]] = []
    for r in range(RESCUE_LATTICE_DIM):
        row = _expand_rescue_vec(utxo_id + r.to_bytes(2, "big"), b"KA_MAT_A:")
        rows.append(row)
    return rows


def _mat_vec_mul32(mat: Sequence[Sequence[int]], vec: Sequence[int]) -> List[int]:
    out = [0] * RESCUE_LATTICE_DIM
    for i in range(RESCUE_LATTICE_DIM):
        acc = 0
        row = mat[i]
        for j in range(RESCUE_LATTICE_DIM):
            acc = (acc + row[j] * vec[j]) % RESCUE_LATTICE_Q
        out[i] = acc
    return out


@dataclass(frozen=True)
class BIP32LegacyAccount:
    """Private off-chain BIP-32 unhardened HD wallet state (never broadcast)."""

    parent_pubkey_compressed: bytes  # 33 B P_par
    parent_chain_code: bytes         # 32 B c_par (256-bit symmetric secret)
    derivation_index: int            # Unhardened child index i in [0, 2^31 - 1]
    child_pubkey_compressed: bytes   # 33 B P_child
    address_hash160: bytes           # 20 B legacy UTXO address commitment

    @classmethod
    def from_master_seed(
        cls,
        master_seed: bytes,
        derivation_index: int = 0,
    ) -> "BIP32LegacyAccount":
        if not (0 <= derivation_index < 2**31):
            raise ValueError("Unhardened BIP-32 index must be in [0, 2^31 - 1]")
        parent_sk_seed = hmac.new(b"Bitcoin seed", master_seed, hashlib.sha512).digest()
        c_par = parent_sk_seed[32:]
        p_par = b"\x02" + _sha3(b"PAR_PK:" + parent_sk_seed[:32])
        il_ir = hmac.new(
            c_par, p_par + derivation_index.to_bytes(4, "big"), hashlib.sha512
        ).digest()
        p_child = b"\x03" + _sha3(b"CHILD_PK:" + p_par + il_ir[:32])
        addr_h160 = _hash160_sim(p_child)
        return cls(
            parent_pubkey_compressed=p_par,
            parent_chain_code=c_par,
            derivation_index=derivation_index,
            child_pubkey_compressed=p_child,
            address_hash160=addr_h160,
        )

    def chaincode_knowledge_token(self) -> bytes:
        """Private symmetric token bound to c_par and P_par (never serialized on-chain)."""
        return hmac.new(
            self.parent_chain_code,
            b"BIP32_KA_TOKEN:"
            + self.parent_pubkey_compressed
            + self.derivation_index.to_bytes(4, "big")
            + self.address_hash160,
            hashlib.sha3_256,
        ).digest()


@dataclass(frozen=True)
class FrozenUTXORecord:
    """Snapshot record committed into the pre-sunset UTXO Merkle tree."""

    utxo_id: bytes              # 32 B txid:vout hash
    satoshis: int
    address_hash160: bytes      # 20 B address digest
    freeze_height: int
    public_asymmetry_tag: bytes # 32 B tag = H(b_KA || utxo_id || addr_h160)

    def leaf_hash(self) -> bytes:
        return _sha3(
            b"FROZEN_UTXO_LEAF:"
            + self.utxo_id
            + self.satoshis.to_bytes(8, "big")
            + self.address_hash160
            + self.freeze_height.to_bytes(8, "big")
            + self.public_asymmetry_tag
        )


def build_snapshot_merkle_tree(
    records: Sequence[FrozenUTXORecord], depth: int = RESCUE_MERKLE_DEPTH
) -> Tuple[bytes, List[List[bytes]]]:
    """Build fixed-depth padded Merkle tree over frozen UTXOs."""
    capacity = 1 << depth
    if not records or len(records) > capacity:
        raise ValueError(f"Record count must be in [1, {capacity}]")
    pad_leaf = _sha3(b"EMPTY_UTXO_PAD")
    leaves = [rec.leaf_hash() for rec in records]
    while len(leaves) < capacity:
        leaves.append(pad_leaf)

    levels: List[List[bytes]] = [leaves]
    cur = leaves
    while len(cur) > 1:
        nxt = [_sha3(cur[i] + cur[i + 1]) for i in range(0, len(cur), 2)]
        levels.append(nxt)
        cur = nxt
    return cur[0], levels


def export_merkle_inclusion_164b(
    levels: Sequence[Sequence[bytes]], leaf_index: int
) -> bytes:
    """Serialize 164-byte Merkle inclusion proof (4B index + 5 * 32B siblings)."""
    idx = leaf_index
    buf = bytearray(leaf_index.to_bytes(4, "big"))
    for level in levels[:-1]:
        sibling_idx = idx ^ 1
        buf.extend(level[sibling_idx])
        idx //= 2
    if len(buf) != RESCUE_MERKLE_PROOF_BYTES:
        raise AssertionError(f"Expected {RESCUE_MERKLE_PROOF_BYTES} B, got {len(buf)}")
    return bytes(buf)


def verify_merkle_inclusion_164b(
    leaf_hash: bytes, inclusion_164b: bytes, expected_root: bytes
) -> bool:
    if len(inclusion_164b) != RESCUE_MERKLE_PROOF_BYTES or len(expected_root) != 32:
        return False
    idx = int.from_bytes(inclusion_164b[:4], "big")
    cur = leaf_hash
    for step in range(RESCUE_MERKLE_DEPTH):
        off = 4 + step * 32
        sibling = inclusion_164b[off : off + 32]
        if idx % 2 == 0:
            cur = _sha3(cur + sibling)
        else:
            cur = _sha3(sibling + cur)
        idx //= 2
    return hmac.compare_digest(cur, expected_root)


@dataclass(frozen=True)
class RescueProofBundle:
    """Complete Knowledge-Asymmetry UTXO rescue payload (580 B witness + 96 B Dual-Commit XOR)."""

    utxo_record: FrozenUTXORecord
    pqc_dest_address: bytes          # 32 B post-quantum destination hash
    chaincode_commitment: bytes      # 32 B
    derivation_binding: bytes        # 64 B: H(w_KA) (32 B) || c_digest (32 B)
    merkle_inclusion_proof: bytes    # 164 B
    pqc_destination_nizk: bytes      # 320 B: z_KA (128 B) || b_KA (128 B) || dest_tag (64 B)
    dcl_commit_tx1: DualCommitXORCommitTx
    dcl_reveal_tx2: DualCommitXORRevealTx
    rescue_message: bytes

    @property
    def rescue_witness_bytes(self) -> int:
        return (
            len(self.chaincode_commitment)
            + len(self.derivation_binding)
            + len(self.merkle_inclusion_proof)
            + len(self.pqc_destination_nizk)
        )

    @property
    def dcl_cycle_bytes(self) -> int:
        return self.dcl_commit_tx1.size_bytes + self.dcl_reveal_tx2.size_bytes

    @property
    def total_on_chain_bytes(self) -> int:
        return self.rescue_witness_bytes + self.dcl_cycle_bytes

    def serialized_witness_blob(self) -> bytes:
        return (
            self.chaincode_commitment
            + self.derivation_binding
            + self.merkle_inclusion_proof
            + self.pqc_destination_nizk
        )


@dataclass(frozen=True)
class RescueVerificationResult:
    valid: bool
    witness_bytes: int
    dcl_bytes: int
    total_bytes: int
    merkle_valid: bool
    knowledge_binding_valid: bool
    xor_commit_valid: bool
    delta_star_blocks: Optional[int]
    rotated_anchor: Optional[bytes]
    reason: str


class KnowledgeAsymmetryRescueEngine:
    """Engine constructing and verifying 580 B + 96 B frozen UTXO rescue proofs."""

    def __init__(self, snapshot_utxo_root: bytes, hash_alg: str = "sha256") -> None:
        if len(snapshot_utxo_root) != 32:
            raise ValueError("snapshot_utxo_root must be 32 bytes")
        self.snapshot_utxo_root = snapshot_utxo_root
        self.dcl_verifier = DualCommitXORVerifier(hash_alg=hash_alg, track_replay=True)

    @staticmethod
    def _derive_ka_lattice_key(
        account: BIP32LegacyAccount, utxo_id: bytes
    ) -> Tuple[List[int], List[int]]:
        """Derive secret vector s_KA and public vector b_KA = A * s_KA mod q."""
        ka_token = account.chaincode_knowledge_token()
        s_ka = _expand_rescue_vec(ka_token + utxo_id, b"KA_SECRET_VEC:")
        mat_a = _rescue_matrix_a(utxo_id)
        b_ka = _mat_vec_mul32(mat_a, s_ka)
        return s_ka, b_ka

    @classmethod
    def build_frozen_utxo_record(
        cls,
        account: BIP32LegacyAccount,
        utxo_id: bytes,
        satoshis: int,
        freeze_height: int,
    ) -> FrozenUTXORecord:
        if len(utxo_id) != 32:
            raise ValueError("utxo_id must be 32 bytes")
        _, b_ka = cls._derive_ka_lattice_key(account, utxo_id)
        b_bytes = _encode_vec32(b_ka)
        asymmetry_tag = _sha3(
            b"KA_SNAPSHOT_TAG:" + b_bytes + utxo_id + account.address_hash160
        )
        return FrozenUTXORecord(
            utxo_id=utxo_id,
            satoshis=satoshis,
            address_hash160=account.address_hash160,
            freeze_height=freeze_height,
            public_asymmetry_tag=asymmetry_tag,
        )

    @staticmethod
    def _fiat_shamir_challenge(
        chaincode_com: bytes,
        h_w: bytes,
        b_bytes: bytes,
        utxo_id: bytes,
        pqc_dest: bytes,
    ) -> bytes:
        return _sha3(
            b"KA_FS_CHALLENGE:" + chaincode_com + h_w + b_bytes + utxo_id + pqc_dest
        )

    def create_rescue_bundle(
        self,
        account: BIP32LegacyAccount,
        utxo_record: FrozenUTXORecord,
        merkle_levels: Sequence[Sequence[bytes]],
        leaf_index: int,
        pqc_dest_address: bytes,
        dcl_secret_x: bytes,
        dcl_next_secret_x_prime: bytes,
    ) -> RescueProofBundle:
        if len(pqc_dest_address) != 32:
            raise ValueError("pqc_dest_address must be 32 bytes")

        ka_token = account.chaincode_knowledge_token()
        s_ka, b_ka = self._derive_ka_lattice_key(account, utxo_record.utxo_id)
        b_bytes = _encode_vec32(b_ka)
        expected_tag = _sha3(
            b"KA_SNAPSHOT_TAG:"
            + b_bytes
            + utxo_record.utxo_id
            + account.address_hash160
        )
        if not hmac.compare_digest(expected_tag, utxo_record.public_asymmetry_tag):
            raise ValueError("Account does not match frozen UTXO asymmetry tag")

        chaincode_com = _sha3(
            b"KA_CC_COM:" + ka_token + utxo_record.utxo_id + pqc_dest_address
        )
        merkle_proof = export_merkle_inclusion_164b(merkle_levels, leaf_index)

        # Post-quantum lattice PoK of s_KA without exposing c_par, P_par, or P_child
        y_rand = _expand_rescue_vec(
            os.urandom(32) + ka_token + pqc_dest_address, b"KA_MASK_Y:"
        )
        mat_a = _rescue_matrix_a(utxo_record.utxo_id)
        w_ka = _mat_vec_mul32(mat_a, y_rand)
        h_w = _sha3(_encode_vec32(w_ka))
        c_digest = self._fiat_shamir_challenge(
            chaincode_com, h_w, b_bytes, utxo_record.utxo_id, pqc_dest_address
        )
        c_scalar = int.from_bytes(c_digest, "big") % RESCUE_LATTICE_Q
        z_ka = [
            (y_rand[i] + c_scalar * s_ka[i]) % RESCUE_LATTICE_Q
            for i in range(RESCUE_LATTICE_DIM)
        ]

        deriv_binding = h_w + c_digest  # 32 B + 32 B = 64 B
        dest_tag_left = _sha3(
            b"KA_DEST_TAG_L:" + chaincode_com + deriv_binding + merkle_proof + pqc_dest_address
        )
        dest_tag_right = _sha3(
            b"KA_DEST_TAG_R:" + dest_tag_left + b_bytes + pqc_dest_address
        )
        dest_nizk = _encode_vec32(z_ka) + b_bytes + dest_tag_left + dest_tag_right  # 128+128+64 = 320 B

        rescue_msg = (
            utxo_record.utxo_id
            + utxo_record.satoshis.to_bytes(8, "big")
            + pqc_dest_address
            + chaincode_com
            + deriv_binding
        )
        commit_tx1 = self.dcl_verifier.create_commit(dcl_secret_x, rescue_msg)
        reveal_tx2 = self.dcl_verifier.create_reveal(
            dcl_secret_x, dcl_next_secret_x_prime
        )

        return RescueProofBundle(
            utxo_record=utxo_record,
            pqc_dest_address=pqc_dest_address,
            chaincode_commitment=chaincode_com,
            derivation_binding=deriv_binding,
            merkle_inclusion_proof=merkle_proof,
            pqc_destination_nizk=dest_nizk,
            dcl_commit_tx1=commit_tx1,
            dcl_reveal_tx2=reveal_tx2,
            rescue_message=rescue_msg,
        )

    def verify_rescue_bundle(
        self,
        bundle: RescueProofBundle,
        anchor_y: bytes,
        delta_eff: int,
        epsilon: float,
    ) -> RescueVerificationResult:
        witness_bytes = bundle.rescue_witness_bytes
        dcl_bytes = bundle.dcl_cycle_bytes
        total_bytes = bundle.total_on_chain_bytes

        if witness_bytes != RESCUE_PROOF_BYTES or dcl_bytes != DUAL_COMMIT_CYCLE_BYTES:
            return RescueVerificationResult(
                valid=False,
                witness_bytes=witness_bytes,
                dcl_bytes=dcl_bytes,
                total_bytes=total_bytes,
                merkle_valid=False,
                knowledge_binding_valid=False,
                xor_commit_valid=False,
                delta_star_blocks=None,
                rotated_anchor=None,
                reason="Invalid rescue witness or Dual-Commit XOR byte length",
            )

        # 1. Fukuda confirmation window gate
        try:
            decision = enforce_finality_window(delta_eff=delta_eff, epsilon=epsilon)
        except FukudaLivenessViolationError as exc:
            return RescueVerificationResult(
                valid=False,
                witness_bytes=witness_bytes,
                dcl_bytes=dcl_bytes,
                total_bytes=total_bytes,
                merkle_valid=False,
                knowledge_binding_valid=False,
                xor_commit_valid=False,
                delta_star_blocks=None,
                rotated_anchor=None,
                reason=str(exc),
            )

        # 2. Timestamped UTXO snapshot Merkle inclusion
        merkle_ok = verify_merkle_inclusion_164b(
            bundle.utxo_record.leaf_hash(),
            bundle.merkle_inclusion_proof,
            self.snapshot_utxo_root,
        )
        if not merkle_ok:
            return RescueVerificationResult(
                valid=False,
                witness_bytes=witness_bytes,
                dcl_bytes=dcl_bytes,
                total_bytes=total_bytes,
                merkle_valid=False,
                knowledge_binding_valid=False,
                xor_commit_valid=False,
                delta_star_blocks=decision.delta_star_blocks,
                rotated_anchor=None,
                reason="Snapshot Merkle inclusion verification failed",
            )

        # 3. Post-quantum lattice PoK & destination binding verification (zero secret keys)
        z_ka = _decode_vec32(bundle.pqc_destination_nizk[:128])
        b_bytes = bundle.pqc_destination_nizk[128:256]
        b_ka = _decode_vec32(b_bytes)
        dest_tag_left = bundle.pqc_destination_nizk[256:288]
        dest_tag_right = bundle.pqc_destination_nizk[288:320]

        expected_tag = _sha3(
            b"KA_SNAPSHOT_TAG:"
            + b_bytes
            + bundle.utxo_record.utxo_id
            + bundle.utxo_record.address_hash160
        )
        h_w_claimed = bundle.derivation_binding[:32]
        c_digest_claimed = bundle.derivation_binding[32:]
        expected_c_digest = self._fiat_shamir_challenge(
            bundle.chaincode_commitment,
            h_w_claimed,
            b_bytes,
            bundle.utxo_record.utxo_id,
            bundle.pqc_dest_address,
        )

        c_scalar = int.from_bytes(expected_c_digest, "big") % RESCUE_LATTICE_Q
        mat_a = _rescue_matrix_a(bundle.utxo_record.utxo_id)
        az = _mat_vec_mul32(mat_a, z_ka)
        w_reconstructed = [
            (az[i] - c_scalar * b_ka[i]) % RESCUE_LATTICE_Q
            for i in range(RESCUE_LATTICE_DIM)
        ]
        h_w_reconstructed = _sha3(_encode_vec32(w_reconstructed))

        exp_dest_left = _sha3(
            b"KA_DEST_TAG_L:"
            + bundle.chaincode_commitment
            + bundle.derivation_binding
            + bundle.merkle_inclusion_proof
            + bundle.pqc_dest_address
        )
        exp_dest_right = _sha3(
            b"KA_DEST_TAG_R:" + exp_dest_left + b_bytes + bundle.pqc_dest_address
        )
        expected_msg = (
            bundle.utxo_record.utxo_id
            + bundle.utxo_record.satoshis.to_bytes(8, "big")
            + bundle.pqc_dest_address
            + bundle.chaincode_commitment
            + bundle.derivation_binding
        )

        ka_ok = (
            hmac.compare_digest(expected_tag, bundle.utxo_record.public_asymmetry_tag)
            and hmac.compare_digest(expected_c_digest, c_digest_claimed)
            and hmac.compare_digest(h_w_reconstructed, h_w_claimed)
            and hmac.compare_digest(exp_dest_left, dest_tag_left)
            and hmac.compare_digest(exp_dest_right, dest_tag_right)
            and hmac.compare_digest(expected_msg, bundle.rescue_message)
        )
        if not ka_ok:
            return RescueVerificationResult(
                valid=False,
                witness_bytes=witness_bytes,
                dcl_bytes=dcl_bytes,
                total_bytes=total_bytes,
                merkle_valid=True,
                knowledge_binding_valid=False,
                xor_commit_valid=False,
                delta_star_blocks=decision.delta_star_blocks,
                rotated_anchor=None,
                reason="Knowledge-asymmetry lattice PoK or destination binding failed",
            )

        # 4. Dual-Commit XOR anti-front-running verification & anchor rotation
        dcl_res = self.dcl_verifier.verify_and_rotate(
            anchor_y=anchor_y,
            commit_tx=bundle.dcl_commit_tx1,
            reveal_tx=bundle.dcl_reveal_tx2,
            message=bundle.rescue_message,
            delta_eff=delta_eff,
            epsilon=epsilon,
        )
        return RescueVerificationResult(
            valid=dcl_res.valid,
            witness_bytes=witness_bytes,
            dcl_bytes=dcl_bytes,
            total_bytes=total_bytes,
            merkle_valid=True,
            knowledge_binding_valid=True,
            xor_commit_valid=dcl_res.xor_commit_matched,
            delta_star_blocks=decision.delta_star_blocks,
            rotated_anchor=dcl_res.rotated_anchor,
            reason=dcl_res.reason,
        )
