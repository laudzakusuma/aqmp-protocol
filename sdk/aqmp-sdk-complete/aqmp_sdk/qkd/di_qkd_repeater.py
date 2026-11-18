"""Quantum Repeater & DI-QKD Physics Engine with Classical Auth Latency (Paper #3).

Models memory-assisted M-segment quantum repeaters over ultra-low-loss telecom
optical fiber (alpha = 0.20 dB/km at 1550 nm) and Device-Independent QKD
(DI-QKD) Devetak-Winter secret key rates under finite quantum memory coherence
time tau_coh in [1 ms, 100 ms].

Compares five classical channel authentication modes:
  1. Ideal Zero-Latency Baseline (0 B, 0 ms)
  2. AQMP v2.0 384-bit Wide-Sponge Dual-Commit XOR (144 B, 8 us/hop, 187-bit QROM)
  3. FALCON-512 (690 B key-recovery payload, 0.42 ms/hop)
  4. ML-DSA-65 (3,309 B signature payload, 0.73 ms/hop)
  5. SPHINCS+-128f (17,088 B signature payload, 14.50 ms/hop)
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, getcontext
from enum import Enum
import hashlib
import hmac
import math
from typing import Dict, Optional, Set, Tuple


getcontext().prec = 100

# Physical Optical Fiber & Quantum Hardware Constants
ALPHA_DB_PER_KM = 0.20          # Ultra-low-loss 1550 nm telecom fiber attenuation
C_FIBER_KM_PER_MS = 200.0       # Speed of light in silica fiber (c / 1.5)
DEFAULT_DETECTOR_EFF = 0.92     # SNSPD detection efficiency eta_d
DEFAULT_BSM_PROB = 0.50         # Linear-optic Bell-state measurement probability
DEFAULT_SOURCE_RATE_HZ = 1e8    # 100 MHz entangled photon-pair source
DEFAULT_F0 = 0.99               # Initial Werner-state fidelity before memory holding
DEFAULT_CTRL_MBPS = 10.0        # Classical authenticated control channel (10 Mbps)
TSIRELSON_BOUND = 2.0 * math.sqrt(2.0)

# AQMP v2.0 384-bit Wide-Sponge Dual-Commit XOR Parameters
WIDE_SPONGE_DIGEST_BYTES = 48   # 384 bits (SHA-384 / SHA3-384)
WIDE_SPONGE_COMMIT_BYTES = 48
WIDE_SPONGE_REVEAL_BYTES = 96   # 48 B x + 48 B y' = 96 B
WIDE_SPONGE_CYCLE_BYTES = WIDE_SPONGE_COMMIT_BYTES + WIDE_SPONGE_REVEAL_BYTES  # 144 B


class AuthSchemeType(str, Enum):
    IDEAL_ZERO_LATENCY = "Ideal_Zero_Latency"
    AQMP_384_DUAL_COMMIT_XOR = "AQMP_384_Dual_Commit_XOR"
    FALCON_512 = "FALCON_512"
    ML_DSA_65 = "ML_DSA_65"
    SPHINCS_PLUS_128F = "SPHINCS_Plus_128f"


@dataclass(frozen=True)
class AuthSchemeSpec:
    """Classical authentication payload, CPU time, and QROM security parameters."""

    scheme: AuthSchemeType
    label: str
    payload_bytes: int
    cpu_time_per_hop_ms: float
    qrom_security_bits_at_2p64: float

    def per_hop_delay_ms(self, ctrl_bandwidth_mbps: float = DEFAULT_CTRL_MBPS) -> float:
        if ctrl_bandwidth_mbps <= 0:
            raise ValueError("ctrl_bandwidth_mbps must be positive")
        serialization_ms = (self.payload_bytes * 8.0) / (ctrl_bandwidth_mbps * 1_000.0)
        return self.cpu_time_per_hop_ms + serialization_ms

    def total_auth_delay_ms(
        self, n_hops_m: int, ctrl_bandwidth_mbps: float = DEFAULT_CTRL_MBPS
    ) -> float:
        if n_hops_m < 1:
            raise ValueError("n_hops_m must be >= 1")
        return n_hops_m * self.per_hop_delay_ms(ctrl_bandwidth_mbps)


AUTH_SCHEME_REGISTRY: Dict[AuthSchemeType, AuthSchemeSpec] = {
    AuthSchemeType.IDEAL_ZERO_LATENCY: AuthSchemeSpec(
        scheme=AuthSchemeType.IDEAL_ZERO_LATENCY,
        label="Ideal Unauthenticated (Zero Latency)",
        payload_bytes=0,
        cpu_time_per_hop_ms=0.0,
        qrom_security_bits_at_2p64=0.0,
    ),
    AuthSchemeType.AQMP_384_DUAL_COMMIT_XOR: AuthSchemeSpec(
        scheme=AuthSchemeType.AQMP_384_DUAL_COMMIT_XOR,
        label="AQMP v2.0 384-bit Dual-Commit XOR (144 B)",
        payload_bytes=WIDE_SPONGE_CYCLE_BYTES,
        cpu_time_per_hop_ms=0.008,  # 8 microseconds (two SHA-384 + 48B XOR)
        qrom_security_bits_at_2p64=187.0,
    ),
    AuthSchemeType.FALCON_512: AuthSchemeSpec(
        scheme=AuthSchemeType.FALCON_512,
        label="FALCON-512 Key-Recovery (690 B)",
        payload_bytes=690,
        cpu_time_per_hop_ms=0.420,
        qrom_security_bits_at_2p64=128.0,
    ),
    AuthSchemeType.ML_DSA_65: AuthSchemeSpec(
        scheme=AuthSchemeType.ML_DSA_65,
        label="Naive ML-DSA-65 (3,309 B)",
        payload_bytes=3309,
        cpu_time_per_hop_ms=0.730,
        qrom_security_bits_at_2p64=192.0,
    ),
    AuthSchemeType.SPHINCS_PLUS_128F: AuthSchemeSpec(
        scheme=AuthSchemeType.SPHINCS_PLUS_128F,
        label="SPHINCS+-128f (17,088 B)",
        payload_bytes=17088,
        cpu_time_per_hop_ms=14.500,
        qrom_security_bits_at_2p64=128.0,
    ),
}


def compute_qrom_384_security_bits(log2_q_f: int = 64) -> float:
    """Compute concrete QROM security bits for 384-bit domain-separated sponge:
    Adv(A) <= (8 * (q_F + 1)^2 + 32 * q_F^3) / 2^384.
    """
    q_f = 1 << log2_q_f
    denom = Decimal(1 << 384)
    adv = (Decimal(8) * Decimal(q_f + 1) ** 2 + Decimal(32) * Decimal(q_f) ** 3) / denom
    ln2 = Decimal(2).ln()
    return float(-(adv.ln() / ln2))


def fiber_attenuation(
    distance_km: float, n_hops_m: int = 1, alpha_db_per_km: float = ALPHA_DB_PER_KM
) -> float:
    """Single-segment fiber transmittance eta(L, M) = 10^(-alpha * (L / M) / 10)."""
    if distance_km <= 0:
        raise ValueError("distance_km must be positive")
    if n_hops_m < 1:
        raise ValueError("n_hops_m must be >= 1")
    seg_km = distance_km / float(n_hops_m)
    return 10.0 ** (-alpha_db_per_km * seg_km / 10.0)


def repeater_entanglement_rate_hz(
    distance_km: float,
    n_hops_m: int = 8,
    alpha_db_per_km: float = ALPHA_DB_PER_KM,
    detector_eff: float = DEFAULT_DETECTOR_EFF,
    bsm_prob: float = DEFAULT_BSM_PROB,
    source_rate_hz: float = DEFAULT_SOURCE_RATE_HZ,
) -> float:
    """Memory-assisted M-segment quantum repeater raw entanglement rate R_ent(L, M).

    Uses multiplexed elementary link generation across M buffered links with
    harmonic mean multiplexing factor H_M and (M - 1) Bell-state swaps.
    """
    eta_seg = fiber_attenuation(distance_km, n_hops_m, alpha_db_per_km)
    harmonic_m = sum(1.0 / k for k in range(1, n_hops_m + 1))
    swap_factor = bsm_prob ** n_hops_m
    return source_rate_hz * eta_seg * (detector_eff ** 2) * swap_factor / harmonic_m


def werner_fidelity(
    delta_t_ms: float, tau_coh_ms: float, f0: float = DEFAULT_F0
) -> float:
    """Werner-state memory dephasing fidelity:
    F(dt) = F0 * exp(-dt / tau_coh) + (1 - exp(-dt / tau_coh)) / 4.
    """
    if delta_t_ms < 0:
        raise ValueError("delta_t_ms must be non-negative")
    if tau_coh_ms <= 0:
        raise ValueError("tau_coh_ms must be positive")
    decay = math.exp(-delta_t_ms / tau_coh_ms)
    return f0 * decay + (1.0 - decay) / 4.0


def chsh_s_parameter(fidelity: float) -> float:
    """Compute CHSH Bell parameter S = 2*sqrt(2) * (4F - 1)/3 for a Werner state."""
    visibility = max(0.0, (4.0 * fidelity - 1.0) / 3.0)
    return TSIRELSON_BOUND * visibility


def binary_entropy(p: float) -> float:
    """Binary Shannon entropy h(p) in [0, 1]."""
    if p <= 0.0 or p >= 1.0:
        return 0.0
    return -p * math.log2(p) - (1.0 - p) * math.log2(1.0 - p)


def devetak_winter_key_fraction(s_param: float, qber: float) -> float:
    """DI-QKD asymptotic Devetak-Winter secret key fraction per entangled pair:
    max(0, 1 - h((1 + sqrt((S/2)^2 - 1))/2) - h(QBER)).
    """
    if s_param <= 2.0:
        return 0.0
    if qber < 0.0 or qber >= 0.5:
        return 0.0
    inner = min(max((s_param / 2.0) ** 2 - 1.0, 0.0), 1.0)
    holevo_arg = 0.5 * (1.0 + math.sqrt(inner))
    rate = 1.0 - binary_entropy(holevo_arg) - binary_entropy(qber)
    return max(0.0, rate)


@dataclass(frozen=True)
class DIQKDSimulationPoint:
    scheme: AuthSchemeType
    distance_km: float
    n_hops_m: int
    tau_coh_ms: float
    ctrl_bandwidth_mbps: float
    auth_payload_bytes: int
    delta_t_prop_ms: float
    delta_t_auth_ms: float
    delta_t_total_ms: float
    fidelity: float
    chsh_s: float
    qber: float
    raw_ent_rate_hz: float
    dw_key_fraction: float
    secret_key_rate_bps: float
    bell_violated: bool
    positive_key_rate: bool


def simulate_diqkd_repeater_point(
    scheme_type: AuthSchemeType,
    distance_km: float,
    tau_coh_ms: float = 25.0,
    n_hops_m: int = 8,
    f0: float = DEFAULT_F0,
    ctrl_bandwidth_mbps: float = DEFAULT_CTRL_MBPS,
) -> DIQKDSimulationPoint:
    """Evaluate DI-QKD secret key rate and Bell parameter at (scheme, L, tau_coh, M)."""
    spec = AUTH_SCHEME_REGISTRY[scheme_type]
    # Elementary-link optical classical announcement propagation delay
    delta_t_prop_ms = (distance_km / float(n_hops_m)) / C_FIBER_KM_PER_MS
    delta_t_auth_ms = spec.total_auth_delay_ms(n_hops_m, ctrl_bandwidth_mbps)
    delta_t_total_ms = delta_t_prop_ms + delta_t_auth_ms

    fidelity = werner_fidelity(delta_t_total_ms, tau_coh_ms, f0=f0)
    s_val = chsh_s_parameter(fidelity)
    qber = 1.0 - fidelity
    raw_rate = repeater_entanglement_rate_hz(distance_km, n_hops_m=n_hops_m)
    dw_frac = devetak_winter_key_fraction(s_val, qber)
    skr = raw_rate * dw_frac

    return DIQKDSimulationPoint(
        scheme=scheme_type,
        distance_km=float(distance_km),
        n_hops_m=n_hops_m,
        tau_coh_ms=float(tau_coh_ms),
        ctrl_bandwidth_mbps=float(ctrl_bandwidth_mbps),
        auth_payload_bytes=spec.payload_bytes,
        delta_t_prop_ms=delta_t_prop_ms,
        delta_t_auth_ms=delta_t_auth_ms,
        delta_t_total_ms=delta_t_total_ms,
        fidelity=fidelity,
        chsh_s=s_val,
        qber=qber,
        raw_ent_rate_hz=raw_rate,
        dw_key_fraction=dw_frac,
        secret_key_rate_bps=skr,
        bell_violated=s_val > 2.0,
        positive_key_rate=skr > 0.0,
    )


def compute_critical_coherence_ms(
    scheme_type: AuthSchemeType,
    distance_km: float = 200.0,
    n_hops_m: int = 8,
    f0: float = DEFAULT_F0,
    ctrl_bandwidth_mbps: float = DEFAULT_CTRL_MBPS,
) -> Tuple[float, float]:
    """Compute critical minimum coherence times (tau_Bell*, tau_DW*) in milliseconds
    required to achieve S > 2 and positive Devetak-Winter rate r_DI-QKD > 0.
    """
    spec = AUTH_SCHEME_REGISTRY[scheme_type]
    delta_t_ms = (distance_km / float(n_hops_m)) / C_FIBER_KM_PER_MS + spec.total_auth_delay_ms(
        n_hops_m, ctrl_bandwidth_mbps
    )
    if delta_t_ms <= 0.0:
        return 0.0, 0.0

    # Exact closed-form for Bell violation threshold S > 2 -> F_bell = (3/sqrt(2) + 1)/4
    f_bell = (3.0 / math.sqrt(2.0) + 1.0) / 4.0
    decay_bell = (f_bell - 0.25) / (f0 - 0.25)
    tau_bell_ms = delta_t_ms / (-math.log(decay_bell))

    # Numerical bisection for exact Devetak-Winter positivity threshold f_DW > 0
    lo, hi = tau_bell_ms, max(tau_bell_ms * 10.0, 1000.0)
    for _ in range(80):
        mid = 0.5 * (lo + hi)
        fid = werner_fidelity(delta_t_ms, mid, f0=f0)
        s_val = chsh_s_parameter(fid)
        if devetak_winter_key_fraction(s_val, 1.0 - fid) > 0.0:
            hi = mid
        else:
            lo = mid
    return tau_bell_ms, hi


class WideSponge384Authenticator:
    """AQMP v2.0 384-bit Wide-Sponge Dual-Commit XOR Channel Authenticator.

    Provides 48 B Commit (C = F_PRE(x) XOR F_MSG(x || m)) + 96 B Reveal/Rotate
    (x, y' = F_PRE(x')) = 144 B total authenticated frame with >= 187.00-bit
    QROM security at q_F = 2^64.
    """

    def __init__(self) -> None:
        self._spent_secrets: Set[bytes] = set()

    @staticmethod
    def _hash_pre(x: bytes) -> bytes:
        return hashlib.sha384(b"AQMP384_PRE:" + x).digest()

    @staticmethod
    def _hash_msg(x: bytes, message: bytes) -> bytes:
        return hashlib.sha384(b"AQMP384_MSG:" + x + message).digest()

    @staticmethod
    def _xor_48(a: bytes, b: bytes) -> bytes:
        if len(a) != WIDE_SPONGE_DIGEST_BYTES or len(b) != WIDE_SPONGE_DIGEST_BYTES:
            raise ValueError("Expected 48-byte operands for 384-bit sponge XOR")
        return bytes(u ^ v for u, v in zip(a, b))

    def create_anchor(self, secret_x: bytes) -> bytes:
        if len(secret_x) != WIDE_SPONGE_DIGEST_BYTES:
            raise ValueError("secret_x must be 48 bytes")
        return self._hash_pre(secret_x)

    def create_commit(self, secret_x: bytes, classical_msg: bytes) -> bytes:
        if len(secret_x) != WIDE_SPONGE_DIGEST_BYTES:
            raise ValueError("secret_x must be 48 bytes")
        return self._xor_48(
            self._hash_pre(secret_x), self._hash_msg(secret_x, classical_msg)
        )

    def create_reveal(self, secret_x: bytes, next_secret_x_prime: bytes) -> Tuple[bytes, bytes]:
        if (
            len(secret_x) != WIDE_SPONGE_DIGEST_BYTES
            or len(next_secret_x_prime) != WIDE_SPONGE_DIGEST_BYTES
        ):
            raise ValueError("Both secret_x and next_secret_x_prime must be 48 bytes")
        if hmac.compare_digest(secret_x, next_secret_x_prime):
            raise ValueError("next_secret_x_prime must differ from secret_x")
        return secret_x, self._hash_pre(next_secret_x_prime)

    def verify_and_rotate(
        self,
        anchor_y: bytes,
        commit_c: bytes,
        revealed_x: bytes,
        next_anchor_y_prime: bytes,
        classical_msg: bytes,
    ) -> Tuple[bool, Optional[bytes], str]:
        if (
            len(anchor_y) != WIDE_SPONGE_DIGEST_BYTES
            or len(commit_c) != WIDE_SPONGE_DIGEST_BYTES
            or len(revealed_x) != WIDE_SPONGE_DIGEST_BYTES
            or len(next_anchor_y_prime) != WIDE_SPONGE_DIGEST_BYTES
        ):
            return False, None, "Malformed 48-byte Dual-Commit-384 payload"

        if revealed_x in self._spent_secrets:
            return False, None, "Replay rejected: ephemeral preimage x already spent"
        if hmac.compare_digest(next_anchor_y_prime, anchor_y):
            return False, None, "Rotation rejected: next anchor y' equals current anchor y"

        fx = self._hash_pre(revealed_x)
        if not hmac.compare_digest(fx, anchor_y):
            return False, None, "Anchor preimage mismatch: F_PRE(x) != y"

        expected_c = self._xor_48(fx, self._hash_msg(revealed_x, classical_msg))
        if not hmac.compare_digest(expected_c, commit_c):
            return False, None, "XOR commitment mismatch: F_PRE(x) XOR F_MSG(x || m) != C"

        self._spent_secrets.add(revealed_x)
        return True, next_anchor_y_prime, "384-bit Wide-Sponge Dual-Commit XOR verified"
