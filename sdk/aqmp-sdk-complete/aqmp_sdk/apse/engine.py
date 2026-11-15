"""Adaptive Parameter Selection Engine (APSE v2.0) for AQMP v2.0.

Replaces heuristic percentage scoring with exact byte-footprint models and
deterministic ZK-aggregation break-even switching thresholds derived in the
AQMP v2.0 empirical benchmark suite:
  - Plonky3 two-stage STARK-to-SNARK (300 B + 44N B): N*_Plonky3 = 1 vs FALCON-KR,
    N*_ECDSA = 6 vs Classical ECDSA (96N B), 11,300 B vs 24,000 B at N = 250.
  - Indexed LaBRADOR fallback vs Unaggregated FALCON Key-Recovery (690N B):
      Execution Layer (EL): N*_EL = 81 tx/block
      Consensus Layer (CL): N*_CL = 111 tx/block
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import math


# ---------------------------------------------------------------------------
# Exact Byte-Footprint Constants (bytes)
# ---------------------------------------------------------------------------
ECDSA_PK_BYTES = 32
ECDSA_SIG_BYTES = 64
ECDSA_TOTAL_BYTES = ECDSA_PK_BYTES + ECDSA_SIG_BYTES  # 96 B

MLDSA65_PK_BYTES = 1952
MLDSA65_SIG_BYTES = 3309
MLDSA65_TOTAL_BYTES = MLDSA65_PK_BYTES + MLDSA65_SIG_BYTES  # 5261 B

FALCON_PK_BYTES = 897            # p
FALCON_SALT_BYTES = 40           # R
FALCON_SIG_STD_BYTES = 626       # S
FALCON_SIG_KR_BYTES = 650        # S_tilde (key-recovery signature)
KEY_REGISTRY_INDEX_BYTES = 4     # idx

LABRADOR_EL_BASE_BYTES = 51200   # 50 KiB base proof
LABRADOR_EL_LOG_COEFF = 128
LABRADOR_CL_FIXED_BYTES = 71680  # 70 KiB fixed overhead
PLONKY3_PROOF_BYTES = 300        # BabyBear recursive proof

TARGET_PROVING_BUDGET_MS = 810.0

# Exact break-even thresholds (N*)
N_STAR_EL = 81
N_STAR_CL = 111
N_STAR_ECDSA = 6
N_STAR_PLONKY3 = 1


class AggregationMode(str, Enum):
    """Deterministic APSE v2.0 state-switching modes."""

    PLONKY3_INDEXED_AGGREGATION = "Plonky3_Indexed_Aggregation"
    FALCON_KEY_RECOVERY_UNAGGREGATED = "FALCON_KeyRecovery_Unaggregated"
    LABRADOR_INDEXED_AGGREGATION = "LaBRADOR_Indexed_Aggregation"


def _validate_n(n_tx: int) -> int:
    if isinstance(n_tx, bool) or not isinstance(n_tx, int) or n_tx < 1:
        raise ValueError(f"n_tx must be a positive integer >= 1, got {n_tx!r}")
    return n_tx


def ecdsa_bytes(n_tx: int) -> int:
    """Classical ECDSA baseline: N * (32 + 64) = 96N bytes."""
    n = _validate_n(n_tx)
    return n * ECDSA_TOTAL_BYTES


def mldsa65_bytes(n_tx: int) -> int:
    """Naive ML-DSA-65 (Dilithium3): N * (1952 + 3309) = 5261N bytes."""
    n = _validate_n(n_tx)
    return n * MLDSA65_TOTAL_BYTES


def falcon_kr_unaggregated_bytes(n_tx: int) -> int:
    """EL Case 1 (FALCON Key-Recovery, No Aggregation): N * (650 + 40) = 690N bytes."""
    n = _validate_n(n_tx)
    return n * (FALCON_SIG_KR_BYTES + FALCON_SALT_BYTES)


def falcon_std_unaggregated_bytes(n_tx: int) -> int:
    """EL Case 2 (FALCON Standard, No Aggregation): N * (897 + 626 + 40) = 1563N bytes."""
    n = _validate_n(n_tx)
    return n * (FALCON_PK_BYTES + FALCON_SIG_STD_BYTES + FALCON_SALT_BYTES)


def labrador_el_overhead_bytes(n_tx: int) -> int:
    """a_{N,EL} = 51200 + floor(128 * log2(max(N, 2))) bytes."""
    n = _validate_n(n_tx)
    m = max(n, 2)
    if (m & (m - 1)) == 0:
        log2_term = LABRADOR_EL_LOG_COEFF * (m.bit_length() - 1)
    else:
        log2_term = math.floor(LABRADOR_EL_LOG_COEFF * math.log2(m))
    return LABRADOR_EL_BASE_BYTES + log2_term


def labrador_el_unindexed_bytes(n_tx: int) -> int:
    """EL Case 3a (LaBRADOR ZK-Aggregation, Unindexed Full PK): a_{N,EL} + 937N bytes."""
    n = _validate_n(n_tx)
    return labrador_el_overhead_bytes(n) + n * (FALCON_PK_BYTES + FALCON_SALT_BYTES)


def labrador_el_indexed_bytes(n_tx: int) -> int:
    """EL Case 3b (LaBRADOR ZK-Aggregation + KeyRegistry 4B): a_{N,EL} + 44N bytes."""
    n = _validate_n(n_tx)
    return labrador_el_overhead_bytes(n) + n * (FALCON_SALT_BYTES + KEY_REGISTRY_INDEX_BYTES)


def labrador_cl_indexed_bytes(n_tx: int) -> int:
    """CL Case 3 (Consensus Layer LaBRADOR, 70 KiB fixed overhead): 71680 + 44N bytes."""
    n = _validate_n(n_tx)
    return LABRADOR_CL_FIXED_BYTES + n * (FALCON_SALT_BYTES + KEY_REGISTRY_INDEX_BYTES)


def plonky3_indexed_bytes(n_tx: int) -> int:
    """AQMP v2.0 Plonky3 BabyBear recursive proof + KeyRegistry: 300 + 44N bytes."""
    n = _validate_n(n_tx)
    return PLONKY3_PROOF_BYTES + n * (FALCON_SALT_BYTES + KEY_REGISTRY_INDEX_BYTES)


def aqmp_v2_adaptive_bytes(n_tx: int) -> int:
    """min(690N, 300 + 44N) bytes."""
    return min(falcon_kr_unaggregated_bytes(n_tx), plonky3_indexed_bytes(n_tx))


@dataclass(frozen=True)
class APSESelectionResult:
    """Result of deterministic APSE v2.0 mode and footprint selection."""

    mode: AggregationMode
    layer: str
    n_tx: int
    payload_bytes: int
    ecdsa_baseline_bytes: int
    mldsa65_baseline_bytes: int
    falcon_kr_bytes: int
    overhead_vs_ecdsa: float
    reduction_vs_mldsa65_pct: float
    breakeven_threshold_n: int
    plonky3_active: bool
    proving_time_ms: float
    proving_budget_ms: float
    fallback_triggered: bool
    rationale: str


class AdaptiveParameterSelectionEngine:
    """Deterministic state-switching engine for AQMP v2.0 (APSE v2.0)."""

    def __init__(
        self,
        proving_budget_ms: float = TARGET_PROVING_BUDGET_MS,
        el_breakeven_n: int = N_STAR_EL,
        cl_breakeven_n: int = N_STAR_CL,
    ) -> None:
        if proving_budget_ms <= 0:
            raise ValueError("proving_budget_ms must be positive")
        self.proving_budget_ms = float(proving_budget_ms)
        self.el_breakeven_n = int(el_breakeven_n)
        self.cl_breakeven_n = int(cl_breakeven_n)

    def select_mode(
        self,
        n_tx: int,
        layer: str = "EL",
        plonky3_active: bool = True,
        proving_time_ms: float = TARGET_PROVING_BUDGET_MS,
    ) -> APSESelectionResult:
        """Select optimal AQMP v2.0 proof mode and compute exact byte footprint.

        Args:
            n_tx: Transactions in the block (N >= 1).
            layer: "EL" (Execution Layer) or "CL" (Consensus Layer).
            plonky3_active: Whether Plonky3 two-stage STARK-to-SNARK recursion is enabled.
            proving_time_ms: Measured or projected prover latency in milliseconds.
        """
        n = _validate_n(n_tx)
        norm_layer = layer.upper()
        if norm_layer not in {"EL", "CL"}:
            raise ValueError(f"layer must be 'EL' or 'CL', got {layer!r}")
        if proving_time_ms < 0:
            raise ValueError(f"proving_time_ms must be non-negative, got {proving_time_ms!r}")

        ecdsa_b = ecdsa_bytes(n)
        mldsa_b = mldsa65_bytes(n)
        falcon_kr_b = falcon_kr_unaggregated_bytes(n)

        budget_ok = proving_time_ms <= self.proving_budget_ms
        if plonky3_active and budget_ok and n >= N_STAR_PLONKY3:
            mode = AggregationMode.PLONKY3_INDEXED_AGGREGATION
            payload_b = plonky3_indexed_bytes(n)
            threshold_n = N_STAR_PLONKY3
            fallback = False
            rationale = (
                f"Plonky3 STARK-to-SNARK recursion active within {self.proving_budget_ms:.0f} ms "
                f"budget ({proving_time_ms:.1f} ms): payload = 300 + 44*{n} = {payload_b} B"
            )
        else:
            fallback = True
            threshold_n = self.el_breakeven_n if norm_layer == "EL" else self.cl_breakeven_n
            reason_prefix = (
                "Plonky3 disabled"
                if not plonky3_active
                else f"Proving time {proving_time_ms:.1f} ms exceeded {self.proving_budget_ms:.0f} ms budget"
            )
            if n < threshold_n:
                mode = AggregationMode.FALCON_KEY_RECOVERY_UNAGGREGATED
                payload_b = falcon_kr_b
                rationale = (
                    f"{reason_prefix}; N={n} < N*_{norm_layer}={threshold_n} -> "
                    f"stay in FALCON key-recovery unaggregated mode ({payload_b} B)"
                )
            else:
                mode = AggregationMode.LABRADOR_INDEXED_AGGREGATION
                payload_b = (
                    labrador_el_indexed_bytes(n)
                    if norm_layer == "EL"
                    else labrador_cl_indexed_bytes(n)
                )
                rationale = (
                    f"{reason_prefix}; N={n} >= N*_{norm_layer}={threshold_n} -> "
                    f"switch to {norm_layer} LaBRADOR + KeyRegistry indexed aggregation ({payload_b} B)"
                )

        return APSESelectionResult(
            mode=mode,
            layer=norm_layer,
            n_tx=n,
            payload_bytes=payload_b,
            ecdsa_baseline_bytes=ecdsa_b,
            mldsa65_baseline_bytes=mldsa_b,
            falcon_kr_bytes=falcon_kr_b,
            overhead_vs_ecdsa=payload_b / ecdsa_b,
            reduction_vs_mldsa65_pct=(1.0 - payload_b / mldsa_b) * 100.0,
            breakeven_threshold_n=threshold_n,
            plonky3_active=plonky3_active,
            proving_time_ms=float(proving_time_ms),
            proving_budget_ms=self.proving_budget_ms,
            fallback_triggered=fallback,
            rationale=rationale,
        )
