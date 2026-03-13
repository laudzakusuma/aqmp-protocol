# AQMP Algorithm Registry
# Wraps all NIST PQC standard algorithms + classical ECDSA into a unified interface.
# Used as the foundation for Dual-Commit Layer and ZK Aggregation components.


from __future__ import annotations
import time
import hashlib
import hmac
import os
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Tuple, Optional

# Classical ECDSA (secp256k1 via cryptography)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# PQC Algorithms
import pqcrypto.sign.falcon_512 as _falcon512
import pqcrypto.sign.falcon_1024 as _falcon1024
import pqcrypto.sign.ml_dsa_44 as _mldsa44        # Dilithium2
import pqcrypto.sign.ml_dsa_65 as _mldsa65        # Dilithium3
import pqcrypto.sign.ml_dsa_87 as _mldsa87        # Dilithium5
import pqcrypto.sign.sphincs_sha2_128f_simple as _sphincs128f
import pqcrypto.sign.sphincs_sha2_128s_simple as _sphincs128s


class NISTLevel(Enum):
    NONE = 0
    LEVEL_1 = 1   # ~128-bit quantum security
    LEVEL_2 = 2   # ~128-bit classical (harder constraints)
    LEVEL_3 = 3   # ~192-bit quantum security
    LEVEL_5 = 5   # ~256-bit quantum security


@dataclass
class AlgorithmProfile:
    name: str
    nist_level: NISTLevel
    pub_key_bytes: int
    priv_key_bytes: int
    sig_bytes_typical: int
    quantum_safe: bool
    basis: str
    # Measured benchmarks (filled by BenchmarkSuite)
    keygen_ms: float = 0.0
    sign_ms: float = 0.0
    verify_ms: float = 0.0
    sign_ms_stddev: float = 0.0
    verify_ms_stddev: float = 0.0
    benchmark_n: int = 0


@dataclass
class KeyPair:
    algorithm: str
    public_key: bytes
    private_key: bytes

    def public_key_hex(self) -> str:
        return self.public_key.hex()


@dataclass
class Signature:
    algorithm: str
    message_hash: bytes   # SHA3-256 of original message
    signature_bytes: bytes
    public_key: bytes
    timestamp_ns: int = field(default_factory=lambda: time.time_ns())

    @property
    def size(self) -> int:
        return len(self.signature_bytes)

    def overhead_vs_ecdsa(self) -> float:
        ECDSA_SIG_BYTES = 64
        return self.size / ECDSA_SIG_BYTES


# Algorithm Implementations

class ECDSA_secp256k1:
    """Classical ECDSA — quantum-vulnerable baseline."""
    PROFILE = AlgorithmProfile(
        name="ECDSA-secp256k1",
        nist_level=NISTLevel.NONE,
        pub_key_bytes=64,
        priv_key_bytes=32,
        sig_bytes_typical=64,
        quantum_safe=False,
        basis="Elliptic Curve Discrete Log (ECDLP)"
    )

    @staticmethod
    def generate_keypair() -> KeyPair:
        sk = ec.generate_private_key(ec.SECP256K1(), default_backend())
        pk_bytes = sk.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint
        )[1:]  # strip 0x04 prefix → 64 bytes
        sk_bytes = sk.private_numbers().private_value.to_bytes(32, 'big')
        return KeyPair("ECDSA-secp256k1", pk_bytes, sk_bytes)

    @staticmethod
    def sign(message: bytes, keypair: KeyPair) -> Signature:
        sk_int = int.from_bytes(keypair.private_key, 'big')
        sk = ec.derive_private_key(sk_int, ec.SECP256K1(), default_backend())
        der_sig = sk.sign(message, ec.ECDSA(hashes.SHA256()))
        # Encode as r||s (64 bytes) from DER
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        r, s = decode_dss_signature(der_sig)
        sig_bytes = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
        msg_hash = hashlib.sha3_256(message).digest()
        return Signature("ECDSA-secp256k1", msg_hash, sig_bytes, keypair.public_key)

    @staticmethod
    def verify(message: bytes, sig: Signature) -> bool:
        try:
            r = int.from_bytes(sig.signature_bytes[:32], 'big')
            s = int.from_bytes(sig.signature_bytes[32:], 'big')
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
            der_sig = encode_dss_signature(r, s)
            pk_bytes = b'\x04' + sig.public_key  # re-add prefix
            pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pk_bytes)
            pk.verify(der_sig, message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False


class FALCON512:
    PROFILE = AlgorithmProfile(
        name="FALCON-512",
        nist_level=NISTLevel.LEVEL_1,
        pub_key_bytes=897,
        priv_key_bytes=1281,
        sig_bytes_typical=666,
        quantum_safe=True,
        basis="NTRU Lattice"
    )

    @staticmethod
    def generate_keypair() -> KeyPair:
        pk, sk = _falcon512.generate_keypair()
        return KeyPair("FALCON-512", pk, sk)

    @staticmethod
    def sign(message: bytes, keypair: KeyPair) -> Signature:
        sig_bytes = _falcon512.sign(keypair.private_key, message)
        msg_hash = hashlib.sha3_256(message).digest()
        return Signature("FALCON-512", msg_hash, sig_bytes, keypair.public_key)

    @staticmethod
    def verify(message: bytes, sig: Signature) -> bool:
        try:
            _falcon512.verify(sig.public_key, message, sig.signature_bytes)
            return True
        except Exception:
            return False


class FALCON1024:
    PROFILE = AlgorithmProfile(
        name="FALCON-1024",
        nist_level=NISTLevel.LEVEL_5,
        pub_key_bytes=1793,
        priv_key_bytes=2305,
        sig_bytes_typical=1280,
        quantum_safe=True,
        basis="NTRU Lattice"
    )

    @staticmethod
    def generate_keypair() -> KeyPair:
        pk, sk = _falcon1024.generate_keypair()
        return KeyPair("FALCON-1024", pk, sk)

    @staticmethod
    def sign(message: bytes, keypair: KeyPair) -> Signature:
        sig_bytes = _falcon1024.sign(keypair.private_key, message)
        msg_hash = hashlib.sha3_256(message).digest()
        return Signature("FALCON-1024", msg_hash, sig_bytes, keypair.public_key)

    @staticmethod
    def verify(message: bytes, sig: Signature) -> bool:
        try:
            _falcon1024.verify(sig.public_key, message, sig.signature_bytes)
            return True
        except Exception:
            return False


class MLDSA44:  # CRYSTALS-Dilithium2 / ML-DSA-44
    PROFILE = AlgorithmProfile(
        name="ML-DSA-44 (Dilithium2)",
        nist_level=NISTLevel.LEVEL_2,
        pub_key_bytes=1312,
        priv_key_bytes=2528,
        sig_bytes_typical=2420,
        quantum_safe=True,
        basis="Module-LWE (Lattice)"
    )

    @staticmethod
    def generate_keypair() -> KeyPair:
        pk, sk = _mldsa44.generate_keypair()
        return KeyPair("ML-DSA-44", pk, sk)

    @staticmethod
    def sign(message: bytes, keypair: KeyPair) -> Signature:
        sig_bytes = _mldsa44.sign(keypair.private_key, message)
        msg_hash = hashlib.sha3_256(message).digest()
        return Signature("ML-DSA-44", msg_hash, sig_bytes, keypair.public_key)

    @staticmethod
    def verify(message: bytes, sig: Signature) -> bool:
        try:
            _mldsa44.verify(sig.public_key, message, sig.signature_bytes)
            return True
        except Exception:
            return False


class MLDSA65:  # CRYSTALS-Dilithium3 / ML-DSA-65
    PROFILE = AlgorithmProfile(
        name="ML-DSA-65 (Dilithium3)",
        nist_level=NISTLevel.LEVEL_3,
        pub_key_bytes=1952,
        priv_key_bytes=4000,
        sig_bytes_typical=3293,
        quantum_safe=True,
        basis="Module-LWE (Lattice)"
    )

    @staticmethod
    def generate_keypair() -> KeyPair:
        pk, sk = _mldsa65.generate_keypair()
        return KeyPair("ML-DSA-65", pk, sk)

    @staticmethod
    def sign(message: bytes, keypair: KeyPair) -> Signature:
        sig_bytes = _mldsa65.sign(keypair.private_key, message)
        msg_hash = hashlib.sha3_256(message).digest()
        return Signature("ML-DSA-65", msg_hash, sig_bytes, keypair.public_key)

    @staticmethod
    def verify(message: bytes, sig: Signature) -> bool:
        try:
            _mldsa65.verify(sig.public_key, message, sig.signature_bytes)
            return True
        except Exception:
            return False


class SPHINCS128F:
    PROFILE = AlgorithmProfile(
        name="SPHINCS+-SHA2-128f",
        nist_level=NISTLevel.LEVEL_1,
        pub_key_bytes=32,
        priv_key_bytes=64,
        sig_bytes_typical=17088,
        quantum_safe=True,
        basis="Hash-based (Stateless)"
    )

    @staticmethod
    def generate_keypair() -> KeyPair:
        pk, sk = _sphincs128f.generate_keypair()
        return KeyPair("SPHINCS+-128f", pk, sk)

    @staticmethod
    def sign(message: bytes, keypair: KeyPair) -> Signature:
        sig_bytes = _sphincs128f.sign(keypair.private_key, message)
        msg_hash = hashlib.sha3_256(message).digest()
        return Signature("SPHINCS+-128f", msg_hash, sig_bytes, keypair.public_key)

    @staticmethod
    def verify(message: bytes, sig: Signature) -> bool:
        try:
            _sphincs128f.verify(sig.public_key, message, sig.signature_bytes)
            return True
        except Exception:
            return False


# Registry

ALGORITHM_REGISTRY = {
    "ECDSA-secp256k1": ECDSA_secp256k1,
    "FALCON-512": FALCON512,
    "FALCON-1024": FALCON1024,
    "ML-DSA-44": MLDSA44,
    "ML-DSA-65": MLDSA65,
    "SPHINCS+-128f": SPHINCS128F,
}

def get_algorithm(name: str):
    """Get algorithm class by name."""
    if name not in ALGORITHM_REGISTRY:
        raise ValueError(f"Unknown algorithm: {name}. Available: {list(ALGORITHM_REGISTRY.keys())}")
    return ALGORITHM_REGISTRY[name]