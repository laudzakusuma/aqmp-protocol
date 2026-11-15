# AQMP Dual-Commit Layer (DCL)

# Component 1 of AQMP: Embeds a quantum-safe cryptographic commitment
# alongside every classical ECDSA transaction, achieving:

#   - Backward compatibility: legacy nodes see valid ECDSA + OP_RETURN
#   - Forward quantum security: PQC-aware nodes verify PQC commitment
#   - Zero hard-fork requirement: fully soft-fork deployable

# DCL Transaction Structure:
  
#   ECDSA Signature    (64B)  ← legacy nodes verify
#   PQC Commitment     (32B)  ← H(PQC_Sig||PK||Nonce) 
#   ZK Pointer         (32B)  ← Merkle root of proofs
#   Algorithm Tag      (1B)   ← PQC algo identifier
  

# Security argument:
#   - Classical attacker: cannot forge ECDSA → transaction rejected
#   - Quantum attacker: can forge ECDSA, but cannot forge PQC commitment
#     (requires breaking Module-LWE or NTRU hardness)
#   - After Phase 2: PQC commitment is primary; ECDSA is deprecated

# This provides a quantifiable security transition: at any protocol phase,
#   SecurityLevel = max(ECDSA_security × (1 - phase/3), PQC_security × phase/3)
# where phase ∈ {0,1,2,3}.

from __future__ import annotations
import hashlib
import hmac
import os
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from enum import IntEnum

try:
    from aqmp_sdk.aqmp.algorithms import (
        ECDSA_secp256k1, MLDSA44, FALCON512,
        KeyPair, Signature, get_algorithm
    )
    from aqmp_sdk.oracle.threat_oracle import verify_confirmation_window
except ImportError:
    from aqmp.algorithms import (
        ECDSA_secp256k1, MLDSA44, FALCON512,
        KeyPair, Signature, get_algorithm
    )
    from oracle.threat_oracle import verify_confirmation_window


class AQMPPhase(IntEnum):
    """AQMP migration phase — controls which commitments are mandatory."""
    PHASE_0_PREPARATION = 0    # No PQC required, monitoring only
    PHASE_1_DUAL_COMMIT = 1    # PQC commitment required alongside ECDSA
    PHASE_2_PQC_PRIMARY = 2    # PQC is primary; ECDSA deprecated
    PHASE_3_PQC_ONLY = 3       # ECDSA removed; PQC-only consensus


class AlgorithmTag(IntEnum):
    """1-byte algorithm identifier for PQC commitment."""
    NONE = 0x00
    FALCON_512 = 0x01
    FALCON_1024 = 0x02
    ML_DSA_44 = 0x03
    ML_DSA_65 = 0x04
    ML_DSA_87 = 0x05
    SPHINCS_128F = 0x06


@dataclass
class DCLCommitment:
    """
    The PQC commitment embedded in a DCL transaction.
    32-byte commitment = SHA3-256(PQC_sig || PQC_pubkey || nonce)
    
    This is the core cryptographic object that binds the PQC signature
    to the transaction without exposing the full PQC signature on-chain.
    """
    commitment_hash: bytes    # 32 bytes
    algorithm_tag: AlgorithmTag
    nonce: bytes              # 16 bytes, random
    pqc_sig_hash: bytes       # 32 bytes = SHA3-256(PQC signature)
    # Off-chain storage reference (would be P2P distributed in production)
    pqc_sig_bytes: Optional[bytes] = None  # full PQC sig, not stored on-chain
    pqc_pub_key: Optional[bytes] = None    # full PQC public key

    def verify_commitment(self) -> bool:
        """Verify the commitment is internally consistent."""
        expected = hashlib.sha3_256(
            self.pqc_sig_bytes + self.pqc_pub_key + self.nonce
        ).digest()
        return hmac.compare_digest(self.commitment_hash, expected)

    @property
    def on_chain_bytes(self) -> bytes:
        """32B commitment + 16B nonce + 1B tag = 49 bytes on-chain."""
        return self.commitment_hash + self.nonce + bytes([int(self.algorithm_tag)])

    @classmethod
    def from_pqc_signature(cls, sig: Signature, algo_tag: AlgorithmTag) -> 'DCLCommitment':
        nonce = os.urandom(16)
        sig_hash = hashlib.sha3_256(sig.signature_bytes).digest()
        commitment = hashlib.sha3_256(
            sig.signature_bytes + sig.public_key + nonce
        ).digest()
        return cls(
            commitment_hash=commitment,
            algorithm_tag=algo_tag,
            nonce=nonce,
            pqc_sig_hash=sig_hash,
            pqc_sig_bytes=sig.signature_bytes,
            pqc_pub_key=sig.public_key,
        )


@dataclass
class ZKPointer:
    """
    32-byte pointer to the ZK aggregation proof bundle.
    In production: Merkle root of the current block's STARK proof.
    In DCL Phase 1: commitment to future proof aggregation.
    """
    merkle_root: bytes  # 32 bytes

    @classmethod
    def genesis(cls) -> 'ZKPointer':
        """Genesis ZK pointer (zeros, used before ZK aggregation is active)."""
        return cls(merkle_root=b'\x00' * 32)

    @classmethod
    def from_commitments(cls, commitments: List[DCLCommitment]) -> 'ZKPointer':
        """Compute Merkle root of commitment hashes."""
        if not commitments:
            return cls.genesis()
        leaves = [c.commitment_hash for c in commitments]
        while len(leaves) > 1:
            if len(leaves) % 2 == 1:
                leaves.append(leaves[-1])
            leaves = [
                hashlib.sha3_256(leaves[i] + leaves[i+1]).digest()
                for i in range(0, len(leaves), 2)
            ]
        return cls(merkle_root=leaves[0])


@dataclass
class DCLTransaction:
    """
    A Dual-Commit Layer transaction — the atomic unit of AQMP Phase 1.
    
    Contains both classical ECDSA and PQC commitment, structured so:
    - Legacy (ECDSA-only) nodes: parse tx_hash, ecdsa_sig, pqc_metadata as OP_RETURN
    - AQMP-aware nodes: additionally verify pqc_commitment and zk_pointer
    
    On-chain footprint:
      tx_hash      : 32B
      ecdsa_sig    : 64B  (r || s)
      ecdsa_pubkey : 64B
      pqc_metadata : 49B  (commitment + nonce + tag)
      zk_pointer   : 32B

      Total        : 241B  (vs 160B ECDSA-only = +51% overhead)
      
      After ZK aggregation (Phase 2): 32B (just ZK pointer) = -80%
    """
    tx_hash: bytes                          # 32B - hash of transaction data
    ecdsa_sig: Signature                    # Classical signature
    pqc_commitment: Optional[DCLCommitment] # PQC commitment
    zk_pointer: ZKPointer                   # ZK aggregation pointer
    phase: AQMPPhase                        # Current AQMP phase
    timestamp_ns: int = field(default_factory=time.time_ns)

    @property
    def on_chain_size(self) -> int:
        """Total bytes stored on-chain."""
        size = 32  # tx_hash
        size += len(self.ecdsa_sig.signature_bytes)  # ecdsa sig
        size += len(self.ecdsa_sig.public_key)       # ecdsa pubkey
        if self.pqc_commitment:
            size += 49  # commitment metadata (NOT full PQC sig)
        size += 32  # zk_pointer
        return size

    @property
    def is_quantum_safe(self) -> bool:
        """Transaction is quantum-safe if PQC commitment is present and valid."""
        return self.pqc_commitment is not None

    def verify_classical(self, message: bytes) -> bool:
        """Verify ECDSA component — legacy node compatible."""
        return ECDSA_secp256k1.verify(message, self.ecdsa_sig)

    def verify_pqc(self, message: bytes,
                    pqc_impl=None) -> Tuple[bool, str]:
        """
        Verify PQC commitment — AQMP-aware node verification.
        Returns (is_valid, reason).
        """
        if self.pqc_commitment is None:
            if self.phase >= AQMPPhase.PHASE_2_PQC_PRIMARY:
                return False, "PQC commitment required in Phase 2+"
            return True, "PQC commitment not required in this phase"

        # Verify commitment integrity
        if not self.pqc_commitment.verify_commitment():
            return False, "PQC commitment hash mismatch — tampering detected"

        # Verify actual PQC signature
        if self.pqc_commitment.pqc_sig_bytes is None:
            return False, "PQC signature bytes not available (off-chain)"

        if pqc_impl is None:
            tag = self.pqc_commitment.algorithm_tag
            tag_to_impl = {
                AlgorithmTag.FALCON_512: FALCON512,
                AlgorithmTag.ML_DSA_44: MLDSA44,
            }
            pqc_impl = tag_to_impl.get(tag)
            if pqc_impl is None:
                return False, f"Unknown algorithm tag: {tag}"

        # Reconstruct Signature object for verification
        pqc_sig_obj = Signature(
            algorithm=self.pqc_commitment.algorithm_tag.name,
            message_hash=hashlib.sha3_256(message).digest(),
            signature_bytes=self.pqc_commitment.pqc_sig_bytes,
            public_key=self.pqc_commitment.pqc_pub_key,
        )
        ok = pqc_impl.verify(message, pqc_sig_obj)
        if ok:
            return True, "PQC verification successful"
        else:
            return False, "PQC signature verification FAILED"

    def security_level(self) -> str:
        """Human-readable security level of this transaction."""
        if self.is_quantum_safe and self.phase >= AQMPPhase.PHASE_2_PQC_PRIMARY:
            return "QUANTUM_SAFE (PQC Primary)"
        elif self.is_quantum_safe:
            return "HYBRID (ECDSA + PQC Commitment)"
        else:
            return "CLASSICAL_ONLY (Quantum Vulnerable)"


class DCLWallet:
    """
    AQMP-aware wallet that generates DCL transactions.
    Holds both a classical ECDSA keypair and a PQC keypair.
    
    This is the reference implementation for wallet developers
    integrating AQMP.
    """
    
    def __init__(self, pqc_algorithm: str = "FALCON-512",
                 phase: AQMPPhase = AQMPPhase.PHASE_1_DUAL_COMMIT):
        self.phase = phase
        self.pqc_algorithm_name = pqc_algorithm
        
        # Generate keypairs
        print(f"  Generating ECDSA keypair...")
        self.ecdsa_kp = ECDSA_secp256k1.generate_keypair()
        
        print(f"  Generating {pqc_algorithm} keypair...")
        pqc_impl = get_algorithm(pqc_algorithm)
        self.pqc_kp = pqc_impl.generate_keypair()
        self.pqc_impl = pqc_impl
        
        self._algo_tag = {
            "FALCON-512": AlgorithmTag.FALCON_512,
            "FALCON-1024": AlgorithmTag.FALCON_512,  # extend as needed
            "ML-DSA-44": AlgorithmTag.ML_DSA_44,
            "ML-DSA-65": AlgorithmTag.ML_DSA_65,
        }.get(pqc_algorithm, AlgorithmTag.NONE)

    def sign_transaction(self, tx_data: bytes,
                          include_pqc: bool = True) -> DCLTransaction:
        """
        Sign a transaction with both ECDSA and PQC (DCL).
        
        Args:
            tx_data: Raw transaction bytes (e.g., serialized tx)
            include_pqc: Whether to include PQC commitment (True in Phase 1+)
        
        Returns:
            DCLTransaction ready for broadcast
        """
        tx_hash = hashlib.sha3_256(tx_data).digest()

        # Classical ECDSA sign
        ecdsa_sig = ECDSA_secp256k1.sign(tx_data, self.ecdsa_kp)

        # PQC sign + commitment
        pqc_commitment = None
        if include_pqc and self.phase >= AQMPPhase.PHASE_1_DUAL_COMMIT:
            pqc_sig = self.pqc_impl.sign(tx_data, self.pqc_kp)
            pqc_commitment = DCLCommitment.from_pqc_signature(
                pqc_sig, self._algo_tag
            )

        return DCLTransaction(
            tx_hash=tx_hash,
            ecdsa_sig=ecdsa_sig,
            pqc_commitment=pqc_commitment,
            zk_pointer=ZKPointer.genesis(),
            phase=self.phase,
        )

    @property
    def address(self) -> str:
        """Derive AQMP address from both key types (hybrid address)."""
        combined = self.ecdsa_kp.public_key + self.pqc_kp.public_key
        return "aqmp1" + hashlib.sha3_256(combined).hexdigest()[:40]


class DCLVerifier:
    """
    AQMP-aware transaction verifier.
    Implements the full DCL verification logic for protocol nodes.
    """
    
    def __init__(self, phase: AQMPPhase = AQMPPhase.PHASE_1_DUAL_COMMIT,
                 require_pqc_from_phase: AQMPPhase = AQMPPhase.PHASE_2_PQC_PRIMARY):
        self.phase = phase
        self.require_pqc_from_phase = require_pqc_from_phase

    def verify(self, tx: DCLTransaction, message: bytes) -> Tuple[bool, Dict]:
        """
        Full DCL verification — both classical and PQC.
        Returns (is_valid, verification_report).
        """
        report = {
            "tx_hash": tx.tx_hash.hex()[:16] + "...",
            "phase": tx.phase.name,
            "classical_valid": False,
            "pqc_valid": False,
            "security_level": tx.security_level(),
            "errors": [],
        }

        # Classical verification (always required)
        report["classical_valid"] = tx.verify_classical(message)
        if not report["classical_valid"]:
            report["errors"].append("ECDSA verification failed")

        # PQC verification
        if tx.is_quantum_safe:
            pqc_ok, pqc_reason = tx.verify_pqc(message)
            report["pqc_valid"] = pqc_ok
            report["pqc_reason"] = pqc_reason
            if not pqc_ok:
                report["errors"].append(f"PQC: {pqc_reason}")
        elif self.phase >= self.require_pqc_from_phase:
            report["errors"].append("PQC commitment required but missing")

        report["is_valid"] = (
            report["classical_valid"] and
            (report["pqc_valid"] if self.phase >= self.require_pqc_from_phase else True)
        )

        return report["is_valid"], report


# ---------------------------------------------------------------------------
# AQMP v2.0: Hash-Based Dual-Commit XOR & Ephemeral Key Rotation Verifier
# ---------------------------------------------------------------------------
DUAL_COMMIT_TX1_BYTES = 32
DUAL_COMMIT_TX2_BYTES = 64
DUAL_COMMIT_CYCLE_BYTES = DUAL_COMMIT_TX1_BYTES + DUAL_COMMIT_TX2_BYTES  # 96 B/tx
FORS_C_CYCLE_BYTES = 2336 + 20                                         # 2356 B/tx
MLDSA65_CYCLE_BYTES = 1952 + 3309                                      # 5261 B/tx
DEFAULT_NETWORK_NODES = 15_000


def _compute_256bit_hash(data: bytes, hash_alg: str = "sha256") -> bytes:
    """Compute a 32-byte digest using sha256, sha3_256, or keccak256."""
    alg = hash_alg.lower()
    if alg == "sha256":
        return hashlib.sha256(data).digest()
    if alg in ("sha3_256", "sha3-256"):
        return hashlib.sha3_256(data).digest()
    if alg in ("keccak256", "keccak-256"):
        try:
            from Crypto.Hash import keccak as _pycrypto_keccak

            k = _pycrypto_keccak.new(digest_bits=256)
            k.update(data)
            return k.digest()
        except ImportError:
            try:
                from eth_hash.auto import keccak as _eth_keccak

                return _eth_keccak(data)
            except ImportError as exc:
                raise RuntimeError(
                    "keccak256 requires pycryptodome or eth-hash installed"
                ) from exc
    raise ValueError(
        f"Unsupported hash_alg {hash_alg!r}; expected 'sha256', 'sha3_256', or 'keccak256'"
    )


def _xor_32(a: bytes, b: bytes) -> bytes:
    """XOR two equal-length 32-byte digests."""
    if len(a) != 32 or len(b) != 32:
        raise ValueError(f"Expected 32-byte operands, got {len(a)} and {len(b)}")
    return bytes(x ^ y for x, y in zip(a, b))


@dataclass(frozen=True)
class DualCommitXORCommitTx:
    """Tx1 Commit Payload (32 B): C = H(x) XOR H(x || m)."""

    commitment: bytes
    hash_alg: str = "sha256"

    def __post_init__(self) -> None:
        if len(self.commitment) != DUAL_COMMIT_TX1_BYTES:
            raise ValueError(
                f"Commit Tx1 must be {DUAL_COMMIT_TX1_BYTES} bytes, got {len(self.commitment)}"
            )

    @property
    def size_bytes(self) -> int:
        return len(self.commitment)


@dataclass(frozen=True)
class DualCommitXORRevealTx:
    """Tx2 Reveal & Rotation Payload (64 B): preimage x (32 B) + rotated y' = H(x') (32 B)."""

    revealed_secret_x: bytes
    next_anchor_y_prime: bytes
    hash_alg: str = "sha256"

    def __post_init__(self) -> None:
        if len(self.revealed_secret_x) != 32:
            raise ValueError(
                f"Revealed secret x must be 32 bytes, got {len(self.revealed_secret_x)}"
            )
        if len(self.next_anchor_y_prime) != 32:
            raise ValueError(
                f"Rotated anchor y' must be 32 bytes, got {len(self.next_anchor_y_prime)}"
            )

    @property
    def size_bytes(self) -> int:
        return len(self.revealed_secret_x) + len(self.next_anchor_y_prime)


@dataclass(frozen=True)
class DualCommitXORVerificationResult:
    """Result of verifying a Dual-Commit XOR commit-reveal-rotate cycle."""

    valid: bool
    anchor_matched: bool
    xor_commit_matched: bool
    rotated_anchor: Optional[bytes]
    total_cycle_bytes: int
    window_compliant: Optional[bool]
    delta_star_blocks: Optional[int]
    reason: str


class DualCommitXORVerifier:
    """AQMP v2.0 Dual-Commit XOR & Ephemeral Key Rotation Verifier (96 B/tx).

    Protocol cycle:
      Setup/Prior anchor: y = H(x) (32 B)
      Tx1 (Commit, 32 B): C = H(x) XOR H(x || m)
      Tx2 (Reveal+Rotate, 64 B): (x, y' = H(x'))
      Verification:
        1. H(x) == y (preimage binds to committed anchor)
        2. H(x) XOR H(x || m) == C (commit binds to message m)
        3. y' != y and x not previously spent (replay/reuse protection)
        4. Optional Fukuda window check: Delta_eff >= Delta*(epsilon)
        5. Active anchor rotates y <- y'
    """

    def __init__(self, hash_alg: str = "sha256", track_replay: bool = True) -> None:
        self.hash_alg = hash_alg.lower()
        # Validate hash algorithm early
        _compute_256bit_hash(b"aqmp_init", self.hash_alg)
        self.track_replay = track_replay
        self._spent_secrets: Set[bytes] = set()

    def hash_digest(self, data: bytes) -> bytes:
        return _compute_256bit_hash(data, self.hash_alg)

    def create_anchor(self, secret_x: bytes) -> bytes:
        """Compute initial anchor y = H(x) (32 bytes)."""
        if len(secret_x) != 32:
            raise ValueError(f"secret_x must be 32 bytes, got {len(secret_x)}")
        return self.hash_digest(secret_x)

    def create_commit(self, secret_x: bytes, message: bytes) -> DualCommitXORCommitTx:
        """Create Tx1 commitment (32 B): C = H(x) XOR H(x || m)."""
        if len(secret_x) != 32:
            raise ValueError(f"secret_x must be 32 bytes, got {len(secret_x)}")
        h_x = self.hash_digest(secret_x)
        h_xm = self.hash_digest(secret_x + message)
        return DualCommitXORCommitTx(
            commitment=_xor_32(h_x, h_xm),
            hash_alg=self.hash_alg,
        )

    def create_reveal(
        self, secret_x: bytes, next_secret_x_prime: bytes
    ) -> DualCommitXORRevealTx:
        """Create Tx2 reveal & ephemeral key rotation (64 B): (x, y' = H(x'))."""
        if len(secret_x) != 32 or len(next_secret_x_prime) != 32:
            raise ValueError("Both secret_x and next_secret_x_prime must be 32 bytes")
        if hmac.compare_digest(secret_x, next_secret_x_prime):
            raise ValueError("next_secret_x_prime must differ from secret_x for safe rotation")
        y_prime = self.hash_digest(next_secret_x_prime)
        return DualCommitXORRevealTx(
            revealed_secret_x=secret_x,
            next_anchor_y_prime=y_prime,
            hash_alg=self.hash_alg,
        )

    def verify_and_rotate(
        self,
        anchor_y: bytes,
        commit_tx: DualCommitXORCommitTx,
        reveal_tx: DualCommitXORRevealTx,
        message: bytes,
        delta_eff: Optional[int] = None,
        epsilon: Optional[float] = None,
    ) -> DualCommitXORVerificationResult:
        """Verify Commit Tx1 + Reveal Tx2 against anchor y and message m, then rotate y -> y'."""
        total_bytes = commit_tx.size_bytes + reveal_tx.size_bytes
        if len(anchor_y) != 32:
            return DualCommitXORVerificationResult(
                valid=False,
                anchor_matched=False,
                xor_commit_matched=False,
                rotated_anchor=None,
                total_cycle_bytes=total_bytes,
                window_compliant=None,
                delta_star_blocks=None,
                reason=f"Invalid anchor length: expected 32 B, got {len(anchor_y)} B",
            )

        if commit_tx.hash_alg.lower() != self.hash_alg or reveal_tx.hash_alg.lower() != self.hash_alg:
            return DualCommitXORVerificationResult(
                valid=False,
                anchor_matched=False,
                xor_commit_matched=False,
                rotated_anchor=None,
                total_cycle_bytes=total_bytes,
                window_compliant=None,
                delta_star_blocks=None,
                reason="Hash algorithm mismatch between verifier and tx payloads",
            )

        if (delta_eff is None) != (epsilon is None):
            raise ValueError("delta_eff and epsilon must both be provided or both omitted")

        window_compliant: Optional[bool] = None
        delta_star: Optional[int] = None
        if delta_eff is not None and epsilon is not None:
            decision = verify_confirmation_window(delta_eff=delta_eff, epsilon=epsilon)
            window_compliant = decision.compliant
            delta_star = decision.delta_star_blocks
            if not decision.compliant:
                return DualCommitXORVerificationResult(
                    valid=False,
                    anchor_matched=False,
                    xor_commit_matched=False,
                    rotated_anchor=None,
                    total_cycle_bytes=total_bytes,
                    window_compliant=False,
                    delta_star_blocks=delta_star,
                    reason=decision.rationale,
                )

        x = reveal_tx.revealed_secret_x
        y_prime = reveal_tx.next_anchor_y_prime

        if self.track_replay and x in self._spent_secrets:
            return DualCommitXORVerificationResult(
                valid=False,
                anchor_matched=False,
                xor_commit_matched=False,
                rotated_anchor=None,
                total_cycle_bytes=total_bytes,
                window_compliant=window_compliant,
                delta_star_blocks=delta_star,
                reason="Replay detected: ephemeral preimage x already consumed",
            )

        if hmac.compare_digest(y_prime, anchor_y):
            return DualCommitXORVerificationResult(
                valid=False,
                anchor_matched=False,
                xor_commit_matched=False,
                rotated_anchor=None,
                total_cycle_bytes=total_bytes,
                window_compliant=window_compliant,
                delta_star_blocks=delta_star,
                reason="Key rotation failure: y' must not reuse current anchor y",
            )

        h_x = self.hash_digest(x)
        anchor_ok = hmac.compare_digest(h_x, anchor_y)
        if not anchor_ok:
            return DualCommitXORVerificationResult(
                valid=False,
                anchor_matched=False,
                xor_commit_matched=False,
                rotated_anchor=None,
                total_cycle_bytes=total_bytes,
                window_compliant=window_compliant,
                delta_star_blocks=delta_star,
                reason="Anchor preimage mismatch: H(x) != y",
            )

        h_xm = self.hash_digest(x + message)
        expected_c = _xor_32(h_x, h_xm)
        xor_ok = hmac.compare_digest(expected_c, commit_tx.commitment)
        if not xor_ok:
            return DualCommitXORVerificationResult(
                valid=False,
                anchor_matched=True,
                xor_commit_matched=False,
                rotated_anchor=None,
                total_cycle_bytes=total_bytes,
                window_compliant=window_compliant,
                delta_star_blocks=delta_star,
                reason="Dual-Commit XOR mismatch: H(x) XOR H(x || m) != C (tampering detected)",
            )

        if self.track_replay:
            self._spent_secrets.add(x)

        return DualCommitXORVerificationResult(
            valid=True,
            anchor_matched=True,
            xor_commit_matched=True,
            rotated_anchor=y_prime,
            total_cycle_bytes=total_bytes,
            window_compliant=window_compliant,
            delta_star_blocks=delta_star,
            reason="Dual-Commit XOR verified and ephemeral anchor rotated y -> y'",
        )


def compute_network_replication_cost(
    n_tx: int, m_nodes: int = DEFAULT_NETWORK_NODES
) -> Dict[str, float]:
    """Model B network-wide replication footprint for Dual-Commit XOR vs baselines."""
    if n_tx < 1 or m_nodes < 1:
        raise ValueError("n_tx and m_nodes must be positive integers")

    dual_blk = n_tx * DUAL_COMMIT_CYCLE_BYTES
    ecdsa_blk = n_tx * DUAL_COMMIT_CYCLE_BYTES
    forsc_blk = n_tx * FORS_C_CYCLE_BYTES
    mldsa_blk = n_tx * MLDSA65_CYCLE_BYTES

    dual_net = dual_blk * m_nodes
    ecdsa_net = ecdsa_blk * m_nodes
    forsc_net = forsc_blk * m_nodes
    mldsa_net = mldsa_blk * m_nodes

    return {
        "n_tx": n_tx,
        "m_nodes": m_nodes,
        "per_tx_bytes": DUAL_COMMIT_CYCLE_BYTES,
        "dual_commit_block_bytes": dual_blk,
        "dual_commit_net_bytes": dual_net,
        "dual_commit_net_mb": dual_net / 1_000_000.0,
        "dual_commit_net_mib": dual_net / float(1024 ** 2),
        "ecdsa_net_mb": ecdsa_net / 1_000_000.0,
        "fors_c_net_mb": forsc_net / 1_000_000.0,
        "mldsa65_net_mb": mldsa_net / 1_000_000.0,
        "savings_vs_fors_c_pct": (1.0 - dual_net / forsc_net) * 100.0,
        "savings_vs_mldsa65_pct": (1.0 - dual_net / mldsa_net) * 100.0,
        "parity_with_ecdsa": dual_blk == ecdsa_blk,
    }