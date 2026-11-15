"""Comprehensive AQMP v2.0 Automated Unit Test Suite."""

from __future__ import annotations

from fractions import Fraction
import math
import os

import pytest

from aqmp_sdk.apse.engine import (
    AdaptiveParameterSelectionEngine,
    AggregationMode,
    N_STAR_CL,
    N_STAR_ECDSA,
    N_STAR_EL,
    N_STAR_PLONKY3,
    ecdsa_bytes,
    falcon_kr_unaggregated_bytes,
    falcon_std_unaggregated_bytes,
    labrador_cl_indexed_bytes,
    labrador_el_indexed_bytes,
    labrador_el_overhead_bytes,
    mldsa65_bytes,
    plonky3_indexed_bytes,
)
from aqmp_sdk.aqmp.algorithms import ECDSA_secp256k1, FALCON512, MLDSA44, MLDSA65
from aqmp_sdk.dcl.dual_commit import (
    AQMPPhase,
    DCLVerifier,
    DCLWallet,
    DUAL_COMMIT_CYCLE_BYTES,
    DUAL_COMMIT_TX1_BYTES,
    DUAL_COMMIT_TX2_BYTES,
    DualCommitXORCommitTx,
    DualCommitXORRevealTx,
    DualCommitXORVerifier,
    compute_network_replication_cost,
)
from aqmp_sdk.oracle.threat_oracle import (
    FukudaLivenessViolationError,
    QuantumThreatOracle,
    ThreatIndicator,
    compute_fukuda_deadline,
    enforce_finality_window,
    verify_confirmation_window,
)
from aqmp_sdk.zk_agg.aggregator import ZKAggregator, analyze_compression_at_scale_v2


# ---------------------------------------------------------------------------
# 1. APSE v2.0 Threshold Switching & Byte Footprint Tests
# ---------------------------------------------------------------------------


def test_apse_exact_byte_equations_at_key_points():
    assert ecdsa_bytes(1) == 96
    assert mldsa65_bytes(1) == 5261
    assert falcon_kr_unaggregated_bytes(1) == 690
    assert falcon_std_unaggregated_bytes(1) == 1563
    assert plonky3_indexed_bytes(1) == 344

    # Break-even vs ECDSA at N = 6 (N=5: 520 > 480; N=6: 564 < 576)
    assert plonky3_indexed_bytes(5) > ecdsa_bytes(5)
    assert plonky3_indexed_bytes(N_STAR_ECDSA) < ecdsa_bytes(N_STAR_ECDSA)

    # Empirical N = 250 footprint checks
    assert plonky3_indexed_bytes(250) == 11_300
    assert ecdsa_bytes(250) == 24_000
    assert mldsa65_bytes(250) == 1_315_250

    # EL LaBRADOR break-even at N*_EL = 81
    assert labrador_el_overhead_bytes(80) == 52_009
    assert labrador_el_indexed_bytes(80) == 55_529
    assert falcon_kr_unaggregated_bytes(80) == 55_200
    assert labrador_el_indexed_bytes(80) > falcon_kr_unaggregated_bytes(80)

    assert labrador_el_overhead_bytes(81) == 52_011
    assert labrador_el_indexed_bytes(81) == 55_575
    assert falcon_kr_unaggregated_bytes(81) == 55_890
    assert labrador_el_indexed_bytes(81) < falcon_kr_unaggregated_bytes(81)

    # CL LaBRADOR break-even at N*_CL = 111
    assert labrador_cl_indexed_bytes(110) == 76_520
    assert falcon_kr_unaggregated_bytes(110) == 75_900
    assert labrador_cl_indexed_bytes(110) > falcon_kr_unaggregated_bytes(110)

    assert labrador_cl_indexed_bytes(111) == 76_564
    assert falcon_kr_unaggregated_bytes(111) == 76_590
    assert labrador_cl_indexed_bytes(111) < falcon_kr_unaggregated_bytes(111)


@pytest.mark.parametrize("n_tx", [1, 6, 80, 81, 110, 111, 250])
@pytest.mark.parametrize("layer", ["EL", "CL"])
def test_apse_plonky3_active_within_budget(n_tx: int, layer: str):
    engine = AdaptiveParameterSelectionEngine(proving_budget_ms=810.0)
    sel = engine.select_mode(
        n_tx=n_tx, layer=layer, plonky3_active=True, proving_time_ms=810.0
    )
    assert sel.mode == AggregationMode.PLONKY3_INDEXED_AGGREGATION
    assert sel.payload_bytes == 300 + 44 * n_tx
    assert sel.fallback_triggered is False
    assert sel.breakeven_threshold_n == N_STAR_PLONKY3


@pytest.mark.parametrize(
    "n_tx,expected_mode,expected_bytes",
    [
        (1, AggregationMode.FALCON_KEY_RECOVERY_UNAGGREGATED, 690),
        (6, AggregationMode.FALCON_KEY_RECOVERY_UNAGGREGATED, 690 * 6),
        (80, AggregationMode.FALCON_KEY_RECOVERY_UNAGGREGATED, 690 * 80),
        (81, AggregationMode.LABRADOR_INDEXED_AGGREGATION, 55_575),
        (110, AggregationMode.LABRADOR_INDEXED_AGGREGATION, 56_908),
        (111, AggregationMode.LABRADOR_INDEXED_AGGREGATION, 56_953),
        (250, AggregationMode.LABRADOR_INDEXED_AGGREGATION, 63_219),
    ],
)
def test_apse_el_labrador_fallback_switching(
    n_tx: int, expected_mode: AggregationMode, expected_bytes: int
):
    engine = AdaptiveParameterSelectionEngine(proving_budget_ms=810.0)

    # Case A: Plonky3 explicitly disabled
    sel_disabled = engine.select_mode(n_tx=n_tx, layer="EL", plonky3_active=False)
    assert sel_disabled.mode == expected_mode
    assert sel_disabled.payload_bytes == expected_bytes
    assert sel_disabled.fallback_triggered is True
    assert sel_disabled.breakeven_threshold_n == N_STAR_EL

    # Case B: Proving time exceeds 810 ms target budget
    sel_overbudget = engine.select_mode(
        n_tx=n_tx, layer="EL", plonky3_active=True, proving_time_ms=810.5
    )
    assert sel_overbudget.mode == expected_mode
    assert sel_overbudget.payload_bytes == expected_bytes
    assert sel_overbudget.fallback_triggered is True


@pytest.mark.parametrize(
    "n_tx,expected_mode,expected_bytes",
    [
        (1, AggregationMode.FALCON_KEY_RECOVERY_UNAGGREGATED, 690),
        (6, AggregationMode.FALCON_KEY_RECOVERY_UNAGGREGATED, 690 * 6),
        (80, AggregationMode.FALCON_KEY_RECOVERY_UNAGGREGATED, 690 * 80),
        (81, AggregationMode.FALCON_KEY_RECOVERY_UNAGGREGATED, 690 * 81),
        (110, AggregationMode.FALCON_KEY_RECOVERY_UNAGGREGATED, 690 * 110),
        (111, AggregationMode.LABRADOR_INDEXED_AGGREGATION, 76_564),
        (250, AggregationMode.LABRADOR_INDEXED_AGGREGATION, 82_680),
    ],
)
def test_apse_cl_labrador_fallback_switching(
    n_tx: int, expected_mode: AggregationMode, expected_bytes: int
):
    engine = AdaptiveParameterSelectionEngine(proving_budget_ms=810.0)
    sel = engine.select_mode(n_tx=n_tx, layer="CL", plonky3_active=False)
    assert sel.mode == expected_mode
    assert sel.payload_bytes == expected_bytes
    assert sel.fallback_triggered is True
    assert sel.breakeven_threshold_n == N_STAR_CL


def test_apse_invalid_inputs_and_zk_aggregator_v2_helper():
    engine = AdaptiveParameterSelectionEngine()
    with pytest.raises(ValueError):
        engine.select_mode(n_tx=0)
    with pytest.raises(ValueError):
        engine.select_mode(n_tx=10, layer="L3")
    with pytest.raises(ValueError):
        engine.select_mode(n_tx=10, proving_time_ms=-1.0)

    v2_rows = analyze_compression_at_scale_v2(block_sizes=[1, 6, 80, 81, 110, 111, 250])
    row_250 = next(r for r in v2_rows if r["n_tx"] == 250)
    assert row_250["plonky3_indexed_bytes"] == 11_300
    assert row_250["ecdsa_baseline_bytes"] == 24_000
    assert row_250["beats_ecdsa"] is True


# ---------------------------------------------------------------------------
# 2. Dual-Commit XOR & Ephemeral Key Rotation Verifier Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("hash_alg", ["sha256", "sha3_256", "keccak256"])
def test_dual_commit_xor_soundness_rotation_and_tamper_resistance(hash_alg: str):
    verifier = DualCommitXORVerifier(hash_alg=hash_alg, track_replay=True)

    x0 = os.urandom(32)
    x1 = os.urandom(32)
    x2 = os.urandom(32)
    msg1 = b'{"to": "0xAlice", "value": "2.5 ETH", "nonce": 1}'
    msg2 = b'{"to": "0xBob", "value": "1.0 ETH", "nonce": 2}'

    y0 = verifier.create_anchor(x0)
    assert len(y0) == 32

    commit1 = verifier.create_commit(x0, msg1)
    reveal1 = verifier.create_reveal(x0, x1)
    assert commit1.size_bytes == DUAL_COMMIT_TX1_BYTES == 32
    assert reveal1.size_bytes == DUAL_COMMIT_TX2_BYTES == 64
    assert commit1.size_bytes + reveal1.size_bytes == DUAL_COMMIT_CYCLE_BYTES == 96

    # Verify tamper resistance BEFORE consuming x0 in replay set:
    # 1. Modified message must fail XOR commit check
    tampered_msg_res = verifier.verify_and_rotate(y0, commit1, reveal1, msg1 + b" ")
    assert tampered_msg_res.valid is False
    assert tampered_msg_res.anchor_matched is True
    assert tampered_msg_res.xor_commit_matched is False

    # 2. Modified commitment C must fail XOR commit check
    bad_c = bytes([commit1.commitment[0] ^ 0xFF]) + commit1.commitment[1:]
    tampered_c_res = verifier.verify_and_rotate(
        y0, DualCommitXORCommitTx(bad_c, hash_alg=hash_alg), reveal1, msg1
    )
    assert tampered_c_res.valid is False
    assert tampered_c_res.xor_commit_matched is False

    # 3. Wrong preimage x must fail anchor check
    wrong_x = bytes([x0[0] ^ 0x01]) + x0[1:]
    bad_reveal_x = DualCommitXORRevealTx(wrong_x, reveal1.next_anchor_y_prime, hash_alg=hash_alg)
    tampered_x_res = verifier.verify_and_rotate(y0, commit1, bad_reveal_x, msg1)
    assert tampered_x_res.valid is False
    assert tampered_x_res.anchor_matched is False

    # 4. Self-rotation y' == y must fail
    self_rot = DualCommitXORRevealTx(x0, y0, hash_alg=hash_alg)
    self_rot_res = verifier.verify_and_rotate(y0, commit1, self_rot, msg1)
    assert self_rot_res.valid is False

    # 5. Insufficient Fukuda window must reject before finalizing
    non_compliant = verifier.verify_and_rotate(
        y0, commit1, reveal1, msg1, delta_eff=7, epsilon=0.50
    )
    assert non_compliant.valid is False
    assert non_compliant.window_compliant is False
    assert non_compliant.delta_star_blocks == 8

    # 6. Legitimate verification + Fukuda compliance (Delta_eff=8 >= Delta*=8) succeeds & rotates
    res1 = verifier.verify_and_rotate(
        y0, commit1, reveal1, msg1, delta_eff=8, epsilon=0.50
    )
    assert res1.valid is True
    assert res1.anchor_matched is True
    assert res1.xor_commit_matched is True
    assert res1.window_compliant is True
    assert res1.rotated_anchor == verifier.create_anchor(x1)

    # 7. Replay of spent preimage x0 must be rejected
    replay_res = verifier.verify_and_rotate(y0, commit1, reveal1, msg1)
    assert replay_res.valid is False
    assert "Replay" in replay_res.reason

    # 8. Epoch 2 using rotated anchor y1 succeeds
    y1 = res1.rotated_anchor
    assert y1 is not None
    commit2 = verifier.create_commit(x1, msg2)
    reveal2 = verifier.create_reveal(x1, x2)
    res2 = verifier.verify_and_rotate(y1, commit2, reveal2, msg2)
    assert res2.valid is True
    assert res2.rotated_anchor == verifier.create_anchor(x2)


def test_dual_commit_xor_network_footprint_model_b():
    stats = compute_network_replication_cost(n_tx=250, m_nodes=15_000)
    assert stats["per_tx_bytes"] == 96
    assert stats["dual_commit_block_bytes"] == 24_000
    assert stats["dual_commit_net_mb"] == pytest.approx(360.00, rel=0, abs=1e-9)
    assert stats["ecdsa_net_mb"] == pytest.approx(360.00, rel=0, abs=1e-9)
    assert stats["fors_c_net_mb"] == pytest.approx(8_835.00, rel=0, abs=1e-9)
    assert stats["mldsa65_net_mb"] == pytest.approx(19_728.75, rel=0, abs=1e-9)
    assert stats["parity_with_ecdsa"] is True


# ---------------------------------------------------------------------------
# 3. Formal Quantum Threat Oracle & Fukuda Migration Deadline (Delta*) Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "epsilon,expected_delta_star",
    [
        (0.10, 5),
        (0.25, 6),
        (0.50, 8),
        (0.75, 16),
        (0.90, 40),
        (0.95, 80),
    ],
)
def test_fukuda_deadline_benchmark_milestones(epsilon: float, expected_delta_star: int):
    assert compute_fukuda_deadline(epsilon) == expected_delta_star
    assert QuantumThreatOracle.compute_fukuda_deadline(epsilon) == expected_delta_star


def test_fukuda_deadline_sweep_across_001_to_095():
    for i in range(1, 96):
        eps = round(i * 0.01, 2)
        expected = math.ceil(Fraction(4, 1) / (Fraction(1, 1) - Fraction(i, 100)))
        actual = compute_fukuda_deadline(eps)
        assert actual == expected

        # Exact boundary enforcement: delta_eff == actual passes; actual - 1 fails
        ok_decision = enforce_finality_window(delta_eff=actual, epsilon=eps)
        assert ok_decision.compliant is True
        assert ok_decision.delta_star_blocks == actual

        fail_decision = verify_confirmation_window(delta_eff=actual - 1, epsilon=eps)
        assert fail_decision.compliant is False
        assert fail_decision.status == "VULNERABLE"
        with pytest.raises(FukudaLivenessViolationError):
            enforce_finality_window(delta_eff=actual - 1, epsilon=eps)


def test_fukuda_deadline_invalid_epsilon_bounds():
    for bad in [0.0, -0.1, 1.0, 1.05, float("nan"), float("inf")]:
        with pytest.raises(ValueError):
            compute_fukuda_deadline(bad)


# ---------------------------------------------------------------------------
# 4. Backwards Compatibility Tests (v1 DCL, ZKAggregator, QTO)
# ---------------------------------------------------------------------------


def test_legacy_algorithms_and_dcl_compatibility():
    msg = b"aqmp-v2-backcompat-tx"
    for algo_cls in (ECDSA_secp256k1, FALCON512, MLDSA44, MLDSA65):
        kp = algo_cls.generate_keypair()
        sig = algo_cls.sign(msg, kp)
        assert algo_cls.verify(msg, sig) is True
        assert algo_cls.verify(msg + b"tamper", sig) is False

    wallet = DCLWallet(pqc_algorithm="FALCON-512", phase=AQMPPhase.PHASE_1_DUAL_COMMIT)
    tx = wallet.sign_transaction(msg)
    verifier = DCLVerifier(phase=AQMPPhase.PHASE_1_DUAL_COMMIT)
    ok, report = verifier.verify(tx, msg)
    assert ok is True
    assert report["classical_valid"] is True
    assert report["pqc_valid"] is True

    agg = ZKAggregator(block_height=42)
    assert agg.add_signature(
        tx_id=tx.tx_hash,
        message=msg,
        sig_bytes=tx.pqc_commitment.pqc_sig_bytes,
        pub_key=tx.pqc_commitment.pqc_pub_key,
        algorithm="FALCON-512",
        verify_fn=FALCON512.verify,
    )
    proof = agg.generate_proof()
    assert proof is not None
    proof_ok, _ = proof.verify(agg._pending)
    assert proof_ok is True

    oracle = QuantumThreatOracle()
    oracle.add_indicator(
        ThreatIndicator(
            source="NIST",
            indicator_type="policy",
            severity=50,
            description="PQC migration advisory",
            verified=True,
        )
    )
    level, assessment = oracle.assess_threat_level(2031)
    assert int(level) >= 1
    assert assessment["year"] == 2031
