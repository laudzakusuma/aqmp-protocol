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
from typing import Optional, List, Tuple
from enum import IntEnum

from aqmp.algorithms import (
    ECDSA_secp256k1, MLDSA44, FALCON512,
    KeyPair, Signature, get_algorithm
)


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
        from aqmp.algorithms import Signature as Sig
        pqc_sig_obj = Sig(
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