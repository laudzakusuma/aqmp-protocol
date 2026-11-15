"""Automated tests for AQMP v2.0 Formal QROM Security Bounds & EasyCrypt Spec."""

from __future__ import annotations

import csv
from decimal import Decimal, getcontext
from pathlib import Path
import sys

import pytest


REPO_ROOT = Path(__file__).resolve().parents[4]
FORMAL_DIR = REPO_ROOT / "formal_proofs"
if str(FORMAL_DIR) not in sys.path:
    sys.path.insert(0, str(FORMAL_DIR))

from qrom_reduction_verifier import (  # noqa: E402
    DEFAULT_N_BITS,
    EXTENDED_N_BITS,
    compute_exact_qrom_bound,
    export_concrete_bounds_csv,
    simulate_game_hop_chain,
)


def test_easycrypt_spec_exists_and_contains_required_games_and_bound():
    ec_path = FORMAL_DIR / "AQMP_DualCommit_QROM.ec"
    assert ec_path.is_file(), f"Missing EasyCrypt spec at {ec_path}"
    text = ec_path.read_text(encoding="utf-8")

    for token in (
        "Game_G0_Real",
        "Game_G1_CompressedOracle",
        "Game_G2_CommitBinding_XORMask",
        "Game_G3_ForwardSecure_Rotation",
        "CompressedQRO",
        "fukuda_deadline",
        "8.0 * ((q_F + 1)%r ^ 2)",
        "32.0 * ((q_F)%r ^ 3)",
        "aqmp_v2_euf_cma_qrom_soundness",
    ):
        assert token in text, f"Expected EasyCrypt construct {token!r} missing"


@pytest.mark.parametrize("log2_q", [20, 28, 32, 36, 40, 41, 48, 56, 64])
def test_qrom_concrete_bound_formula_and_precision(log2_q: int):
    getcontext().prec = 100
    r = compute_exact_qrom_bound(log2_q, n_bits=DEFAULT_N_BITS)
    q_f = 1 << log2_q
    assert r.q_f == q_f
    assert r.n_bits == 256

    denom = Decimal(1 << 256)
    expected_o2h = float((Decimal(8) * Decimal(q_f + 1) ** 2) / denom)
    expected_coll = float((Decimal(32) * Decimal(q_f) ** 3) / denom)
    assert r.o2h_preimage_term == pytest.approx(expected_o2h, rel=1e-12)
    assert r.compressed_collision_term == pytest.approx(expected_coll, rel=1e-12)

    # Pre-reveal O2H preimage security stays >= 125 bits (approx, via (q_F+1)^2)
    # up to q_F = 2^64, and ~173 bits (>= 172.99) for q_F <= 2^40.
    if log2_q <= 40:
        assert r.o2h_security_bits >= 172.99
        assert r.total_security_bits >= 130.99
        assert r.achieves_128bit_combined is True

    # Under 384-bit domain-separated sponge extension, combined bound > 187 bits even at q_F = 2^64
    assert EXTENDED_N_BITS == 384
    assert r.wide_384_total_security_bits >= 187.0


def test_qrom_game_hop_simulation_and_csv_export(tmp_path: Path):
    sim = simulate_game_hop_chain()
    assert sim["g0_real_verified"] is True
    assert sim["g1_compressed_db_entries"] == 2
    assert sim["g2_xor_mask_indistinguishable"] is True
    assert sim["g3_forward_rotation_fresh"] is True

    csv_file = FORMAL_DIR / "qrom_concrete_bounds.csv"
    export_concrete_bounds_csv(csv_file)
    assert csv_file.is_file()

    with csv_file.open("r", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 13
    assert rows[0]["log2_q_F"] == "20"
    assert rows[-1]["log2_q_F"] == "64"
    # Verify exact crossover point at q_F = 2^41 where 32*(2^41)^3 / 2^256 == 2^-128
    row_41 = next(row for row in rows if row["log2_q_F"] == "41")
    assert float(row_41["collision_security_bits"]) == pytest.approx(128.0, abs=1e-3)
