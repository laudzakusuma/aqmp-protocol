"""DI-QKD & Memory-Assisted Quantum Repeater Classical Authentication Module."""

from aqmp_sdk.qkd.di_qkd_repeater import (
    ALPHA_DB_PER_KM,
    C_FIBER_KM_PER_MS,
    AuthSchemeSpec,
    AuthSchemeType,
    DIQKDSimulationPoint,
    WideSponge384Authenticator,
    binary_entropy,
    chsh_s_parameter,
    compute_critical_coherence_ms,
    compute_qrom_384_security_bits,
    devetak_winter_key_fraction,
    fiber_attenuation,
    repeater_entanglement_rate_hz,
    simulate_diqkd_repeater_point,
    werner_fidelity,
)

__all__ = [
    "ALPHA_DB_PER_KM",
    "C_FIBER_KM_PER_MS",
    "AuthSchemeSpec",
    "AuthSchemeType",
    "DIQKDSimulationPoint",
    "WideSponge384Authenticator",
    "binary_entropy",
    "chsh_s_parameter",
    "compute_critical_coherence_ms",
    "compute_qrom_384_security_bits",
    "devetak_winter_key_fraction",
    "fiber_attenuation",
    "repeater_entanglement_rate_hz",
    "simulate_diqkd_repeater_point",
    "werner_fidelity",
]
