"""Automated pytest suite for AQMP Paper #3:
DI-QKD & Memory-Assisted Quantum Repeater Physics + 384-bit Wide-Sponge Auth.
"""

from __future__ import annotations

import math
import os
import pytest

from aqmp_sdk.qkd.di_qkd_repeater import (
    AuthSchemeType,
    TSIRELSON_BOUND,
    WideSponge384Authenticator,
    binary_entropy,
    chsh_s_parameter,
    compute_critical_coherence_ms,
    compute_qrom_384_security_bits,
    devetak_winter_key_fraction,
    fiber_attenuation,
    simulate_diqkd_repeater_point,
    werner_fidelity,
)


def test_chsh_tsirelson_bound_and_binary_entropy_invariants():
    # Binary entropy range and symmetry h(p) == h(1 - p)
    for p in [0.0, 0.01, 0.11, 0.25, 0.5, 0.75, 0.99, 1.0]:
        h_val = binary_entropy(p)
        assert 0.0 <= h_val <= 1.0
        assert h_val == pytest.approx(binary_entropy(1.0 - p), abs=1e-12)
    assert binary_entropy(0.5) == pytest.approx(1.0, abs=1e-12)

    # Pure maximally entangled Werner state F=1 hits Tsirelson bound 2*sqrt(2)
    assert chsh_s_parameter(1.0) == pytest.approx(TSIRELSON_BOUND, abs=1e-12)
    # Depolarized state F=0.25 yields S=0
    assert chsh_s_parameter(0.25) == pytest.approx(0.0, abs=1e-12)
    # Bell threshold S=2 occurs at F = (3/sqrt(2) + 1)/4
    f_bell = (3.0 / math.sqrt(2.0) + 1.0) / 4.0
    assert chsh_s_parameter(f_bell) == pytest.approx(2.0, abs=1e-12)

    # Fiber attenuation decays monotonically with distance
    assert fiber_attenuation(100.0, 1) == pytest.approx(0.01, rel=1e-9)
    assert fiber_attenuation(200.0, 8) > fiber_attenuation(200.0, 1)


def test_monotonic_fidelity_decay_and_aqmp384_keyrate_preservation():
    # Monotonic decay of fidelity and Bell parameter with delay
    f_fast = werner_fidelity(1.0, tau_coh_ms=25.0)
    f_mid = werner_fidelity(8.0, tau_coh_ms=25.0)
    f_slow = werner_fidelity(27.0, tau_coh_ms=25.0)
    assert f_fast > f_mid > f_slow > 0.25
    assert chsh_s_parameter(f_fast) > chsh_s_parameter(f_mid) > chsh_s_parameter(f_slow)

    # At tau_coh = 25 ms, L = 200 km, M = 8 hops:
    # AQMP-384 preserves Bell violation (S > 2) and positive DI-QKD secret key rate,
    # whereas ML-DSA-65 and SPHINCS+-128f collapse below S = 2 (0 bps).
    ideal = simulate_diqkd_repeater_point(
        AuthSchemeType.IDEAL_ZERO_LATENCY, distance_km=200.0, tau_coh_ms=25.0, n_hops_m=8
    )
    aqmp = simulate_diqkd_repeater_point(
        AuthSchemeType.AQMP_384_DUAL_COMMIT_XOR, distance_km=200.0, tau_coh_ms=25.0, n_hops_m=8
    )
    falcon = simulate_diqkd_repeater_point(
        AuthSchemeType.FALCON_512, distance_km=200.0, tau_coh_ms=25.0, n_hops_m=8
    )
    mldsa = simulate_diqkd_repeater_point(
        AuthSchemeType.ML_DSA_65, distance_km=200.0, tau_coh_ms=25.0, n_hops_m=8
    )
    sphincs = simulate_diqkd_repeater_point(
        AuthSchemeType.SPHINCS_PLUS_128F, distance_km=200.0, tau_coh_ms=25.0, n_hops_m=8
    )

    assert ideal.secret_key_rate_bps >= aqmp.secret_key_rate_bps > 0.0
    assert 2.0 < aqmp.chsh_s <= TSIRELSON_BOUND
    assert aqmp.bell_violated is True
    assert aqmp.positive_key_rate is True

    assert falcon.secret_key_rate_bps == 0.0
    assert mldsa.chsh_s < 2.0 and mldsa.secret_key_rate_bps == 0.0
    assert sphincs.chsh_s < 2.0 and sphincs.secret_key_rate_bps == 0.0

    # Critical coherence time ordering
    _, tau_aqmp = compute_critical_coherence_ms(AuthSchemeType.AQMP_384_DUAL_COMMIT_XOR, 200.0, 8)
    _, tau_mldsa = compute_critical_coherence_ms(AuthSchemeType.ML_DSA_65, 200.0, 8)
    _, tau_sphincs = compute_critical_coherence_ms(AuthSchemeType.SPHINCS_PLUS_128F, 200.0, 8)
    assert tau_aqmp < 25.0 < tau_mldsa < tau_sphincs
    assert devetak_winter_key_fraction(2.0, 0.01) == 0.0


def test_wide_sponge_384_qrom_187bit_and_auth_cycle():
    # Concrete 384-bit QROM bound at q_F = 2^64 achieves >= 187.00 bits
    qrom_bits = compute_qrom_384_security_bits(log2_q_f=64)
    assert qrom_bits >= 187.0

    auth = WideSponge384Authenticator()
    x0 = os.urandom(48)
    x1 = os.urandom(48)
    msg = b"ENTANGLEMENT_SWAP:LINK_0_TO_1:ROUND_42"

    y0 = auth.create_anchor(x0)
    commit_c = auth.create_commit(x0, msg)
    rx, y1 = auth.create_reveal(x0, x1)

    assert len(y0) == 48 and len(commit_c) == 48 and len(rx) == 48 and len(y1) == 48
    assert len(commit_c) + len(rx) + len(y1) == 144

    # Forged message fails XOR commitment check
    bad_ok, _, _ = auth.verify_and_rotate(y0, commit_c, rx, y1, b"TAMPERED_MSG")
    assert bad_ok is False

    # Valid commit-reveal-rotate succeeds
    ok, rot, _ = auth.verify_and_rotate(y0, commit_c, rx, y1, msg)
    assert ok is True and rot == y1

    # Replay of spent preimage x0 fails
    rep_ok, _, _ = auth.verify_and_rotate(y0, commit_c, rx, y1, msg)
    assert rep_ok is False
