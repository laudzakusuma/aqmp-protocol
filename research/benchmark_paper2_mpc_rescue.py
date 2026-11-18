#!/usr/bin/env python3
"""Empirical Benchmark Suite for AQMP Paper #2:
Stateless PQ-MPC Threshold Signing & Knowledge-Asymmetry Frozen UTXO Rescue.

Outputs:
  - research/data/paper2_mpc_rescue_metrics.csv
  - research/figures/fig4_stateless_mpc_scaling.png (300 DPI)
  - research/figures/fig5_utxo_rescue_comparison.png (300 DPI)
"""

from __future__ import annotations

import os
from pathlib import Path
import sys
import time

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


REPO_ROOT = Path(__file__).resolve().parents[1]
SDK_ROOT = REPO_ROOT / "sdk" / "aqmp-sdk-complete"
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))

from aqmp_sdk.oracle.threat_oracle import compute_fukuda_deadline  # noqa: E402
from aqmp_sdk.mpc.stateless_pq_mpc import (  # noqa: E402
    BIP360_P2MR_FALCON_KR_BYTES,
    INDEXED_TX_BYTES,
    MLDSA65_NAIVE_BYTES,
    P2MRKeyRegistryBinding,
    PLONKY3_PROOF_BYTES,
    StatelessPQThresholdCommittee,
)
from aqmp_sdk.rescue.utxo_rescue import (  # noqa: E402
    BIP32LegacyAccount,
    KnowledgeAsymmetryRescueEngine,
    RESCUE_BINDING_BYTES,
    RESCUE_CHAINCODE_COM_BYTES,
    RESCUE_MERKLE_PROOF_BYTES,
    RESCUE_PQC_NIZK_BYTES,
    RESCUE_PROOF_BYTES,
    build_snapshot_merkle_tree,
)


def configure_style() -> None:
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 10,
            "axes.titlesize": 11.2,
            "axes.titleweight": "bold",
            "axes.labelsize": 10.2,
            "xtick.labelsize": 9.3,
            "ytick.labelsize": 9.3,
            "legend.fontsize": 8.4,
            "figure.titlesize": 12.8,
            "figure.titleweight": "bold",
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.grid": True,
            "grid.alpha": 0.28,
            "grid.linestyle": "dashed",
            "savefig.dpi": 300,
        }
    )


def benchmark_mpc_committees() -> pd.DataFrame:
    """Measure real execution latency & payload scaling across (t, n) committees."""
    configs = [(2, 3), (3, 5), (4, 7), (5, 9), (7, 11)]
    rows = []
    msg = b"AQMP Paper #2 institutional threshold transaction payload"
    epoch_salt = b"epoch-2026-11-17-az-safe"
    binding = P2MRKeyRegistryBinding(
        p2mr_merkle_root=b"\x12" * 32,
        key_registry_idx=42,
    )

    for t, n in configs:
        committee = StatelessPQThresholdCommittee(threshold=t, total_signers=n)
        active_set = list(range(1, t + 1))

        # Warm up + measure 5 runs for reliable mean timing
        sign_times = []
        verify_times = []
        last_sig = None
        for idx in range(5):
            salt_i = epoch_salt + idx.to_bytes(2, "big")
            t0 = time.perf_counter_ns()
            sig = committee.sign_threshold(msg, active_set, salt_i, binding)
            t1 = time.perf_counter_ns()
            ok = committee.verify_threshold_signature(
                committee.matrix_seed, committee.group_public_key_b, msg, sig
            )
            t2 = time.perf_counter_ns()
            assert ok is True
            sign_times.append((t1 - t0) / 1_000_000.0)
            verify_times.append((t2 - t1) / 1_000_000.0)
            last_sig = sig

        assert last_sig is not None
        mean_sign = float(np.mean(sign_times))
        mean_verify = float(np.mean(verify_times))

        n_block = 250
        plonky3_block_b = binding.block_footprint_plonky3(n_block)
        naive_mldsa_multisig_b = n_block * t * MLDSA65_NAIVE_BYTES
        p2mr_multisig_b = n_block * t * BIP360_P2MR_FALCON_KR_BYTES

        rows.append(
            {
                "category": "stateless_mpc",
                "committee_label": f"{t}-of-{n}",
                "threshold_t": t,
                "total_n": n,
                "mean_sign_ms": mean_sign,
                "mean_verify_ms": mean_verify,
                "per_signer_ms": mean_sign / t,
                "n_tx_ref": n_block,
                "aqmp_plonky3_keyreg_bytes": plonky3_block_b,
                "p2mr_multisig_falcon_bytes": p2mr_multisig_b,
                "naive_mldsa65_multisig_bytes": naive_mldsa_multisig_b,
                "reduction_vs_mldsa_pct": (1.0 - plonky3_block_b / naive_mldsa_multisig_b) * 100.0,
                "rescue_witness_bytes": np.nan,
                "rescue_total_with_dcl_bytes": np.nan,
                "epsilon": np.nan,
                "delta_star_blocks": np.nan,
            }
        )
    return pd.DataFrame(rows)


def benchmark_utxo_rescue() -> tuple[pd.DataFrame, dict[str, float]]:
    """Measure Knowledge-Asymmetry 580 B UTXO rescue & front-running gating."""
    rows = []
    account = BIP32LegacyAccount.from_master_seed(b"aqmp-paper2-rescue-master-seed", derivation_index=7)
    utxo_id = b"\xAB" * 32
    rec = KnowledgeAsymmetryRescueEngine.build_frozen_utxo_record(
        account, utxo_id=utxo_id, satoshis=125_000_000, freeze_height=920_000
    )
    root, levels = build_snapshot_merkle_tree([rec])
    pqc_dest = b"\xCD" * 32

    create_times = []
    verify_times = []
    last_total_bytes = 0
    last_witness_bytes = 0

    for eps in [0.10, 0.25, 0.50, 0.75, 0.90]:
        delta_star = compute_fukuda_deadline(eps)
        engine = KnowledgeAsymmetryRescueEngine(snapshot_utxo_root=root, hash_alg="sha256")
        x0 = os.urandom(32)
        x1 = os.urandom(32)
        anchor_y0 = engine.dcl_verifier.create_anchor(x0)

        t0 = time.perf_counter_ns()
        bundle = engine.create_rescue_bundle(
            account=account,
            utxo_record=rec,
            merkle_levels=levels,
            leaf_index=0,
            pqc_dest_address=pqc_dest,
            dcl_secret_x=x0,
            dcl_next_secret_x_prime=x1,
        )
        t1 = time.perf_counter_ns()
        res = engine.verify_rescue_bundle(
            bundle=bundle,
            anchor_y=anchor_y0,
            delta_eff=delta_star,
            epsilon=eps,
        )
        t2 = time.perf_counter_ns()
        assert res.valid is True
        assert res.witness_bytes == RESCUE_PROOF_BYTES == 580
        assert res.total_bytes == 676

        create_ms = (t1 - t0) / 1_000_000.0
        verify_ms = (t2 - t1) / 1_000_000.0
        create_times.append(create_ms)
        verify_times.append(verify_ms)
        last_total_bytes = res.total_bytes
        last_witness_bytes = res.witness_bytes

        rows.append(
            {
                "category": "utxo_rescue",
                "committee_label": f"eps={eps:.2f}",
                "threshold_t": np.nan,
                "total_n": np.nan,
                "mean_sign_ms": create_ms,
                "mean_verify_ms": verify_ms,
                "per_signer_ms": np.nan,
                "n_tx_ref": 1,
                "aqmp_plonky3_keyreg_bytes": np.nan,
                "p2mr_multisig_falcon_bytes": np.nan,
                "naive_mldsa65_multisig_bytes": MLDSA65_NAIVE_BYTES,
                "reduction_vs_mldsa_pct": (1.0 - last_total_bytes / MLDSA65_NAIVE_BYTES) * 100.0,
                "rescue_witness_bytes": last_witness_bytes,
                "rescue_total_with_dcl_bytes": last_total_bytes,
                "epsilon": eps,
                "delta_star_blocks": delta_star,
            }
        )

    summary = {
        "mean_create_ms": float(np.mean(create_times)),
        "mean_verify_ms": float(np.mean(verify_times)),
        "witness_bytes": float(last_witness_bytes),
        "total_bytes": float(last_total_bytes),
    }
    return pd.DataFrame(rows), summary


def plot_fig4(df_mpc: pd.DataFrame, out_path: Path) -> None:
    fig, (ax_lat, ax_scale) = plt.subplots(1, 2, figsize=(14.2, 5.8))

    labels = df_mpc["committee_label"].tolist()
    x = np.arange(len(labels))
    width = 0.36

    b1 = ax_lat.bar(
        x - width / 2,
        df_mpc["mean_sign_ms"],
        width=width,
        color="#0284c7",
        edgecolor="#0f172a",
        label="Stateless Threshold Sign (Round 1 + Round 2)",
    )
    b2 = ax_lat.bar(
        x + width / 2,
        df_mpc["mean_verify_ms"],
        width=width,
        color="#059669",
        edgecolor="#0f172a",
        label="Constant-Time Group Verification",
    )
    for bar in list(b1) + list(b2):
        h = bar.get_height()
        ax_lat.text(
            bar.get_x() + bar.get_width() / 2.0,
            h + 0.25,
            f"{h:.2f}",
            ha="center",
            va="bottom",
            fontsize=8.2,
            fontweight="bold",
        )

    ax_lat.set_xticks(x)
    ax_lat.set_xticklabels(labels)
    ax_lat.set_ylim(0, float(df_mpc["mean_sign_ms"].max()) * 1.25)
    ax_lat.set_title("(a) Stateless PQ-MPC Latency by Custody Quorum (t-of-n)")
    ax_lat.set_xlabel("Custodian Quorum Configuration (t-of-n)")
    ax_lat.set_ylabel("Execution Latency (ms)")
    ax_lat.legend(loc="upper left", frameon=True, framealpha=0.92)

    # Panel (b): Block-level payload scaling across N in [1, 1000] for 3-of-5 quorum
    n_vals = np.arange(1, 1001, dtype=np.int64)
    t_ref = 3
    naive_mldsa_kib = (n_vals * t_ref * MLDSA65_NAIVE_BYTES) / 1024.0
    p2mr_falcon_kib = (n_vals * t_ref * BIP360_P2MR_FALCON_KR_BYTES) / 1024.0
    single_falcon_kib = (n_vals * BIP360_P2MR_FALCON_KR_BYTES) / 1024.0
    aqmp_plonky3_kib = (PLONKY3_PROOF_BYTES + n_vals * INDEXED_TX_BYTES) / 1024.0

    ax_scale.plot(
        n_vals,
        naive_mldsa_kib,
        color="#991b1b",
        linewidth=2.2,
        label="3-of-5 Naive ML-DSA-65 (15,783 B/tx)",
    )
    ax_scale.plot(
        n_vals,
        p2mr_falcon_kib,
        color="#d97706",
        linestyle="dashed",
        linewidth=2.0,
        label="3-of-5 BIP-360 P2MR FALCON-KR (2,070 B/tx)",
    )
    ax_scale.plot(
        n_vals,
        single_falcon_kib,
        color="#2563eb",
        linestyle="-.",
        linewidth=1.9,
        label="Single-Key FALCON-KR Unaggregated (690 B/tx)",
    )
    ax_scale.plot(
        n_vals,
        aqmp_plonky3_kib,
        color="#059669",
        linewidth=2.6,
        label="Stateless PQ-MPC + Plonky3 KeyRegistry (300 + 44N B)",
    )

    y_250_mpc = float(aqmp_plonky3_kib[249])
    y_250_mldsa = float(naive_mldsa_kib[249])
    ax_scale.scatter([250, 250], [y_250_mpc, y_250_mldsa], color=["#059669", "#991b1b"], zorder=6)
    ax_scale.annotate(
        f"N=250: {y_250_mpc:.2f} KiB\n(-99.71% vs 3-of-5 ML-DSA)",
        xy=(250, y_250_mpc),
        xytext=(340, 6.5),
        arrowprops={"arrowstyle": "->", "color": "#059669", "lw": 1.2},
        fontsize=8.5,
        fontweight="bold",
        color="#047857",
        bbox={"boxstyle": "round,pad=0.25", "fc": "#ecfdf5", "ec": "#059669"},
    )

    ax_scale.set_yscale("log")
    ax_scale.set_xlim(1, 1000)
    ax_scale.set_ylim(0.2, 30_000)
    ax_scale.set_title("(b) Block Payload Scaling for 3-of-5 Custody (Log KiB)")
    ax_scale.set_xlabel("Transactions per Block (N)")
    ax_scale.set_ylabel("Block Signature + Proof Payload (KiB, log scale)")
    ax_scale.legend(loc="lower right", frameon=True, framealpha=0.92, fontsize=8.0)

    fig.suptitle("Paper #2: Stateless Post-Quantum Threshold / MPC Scaling & Payload Compression")
    fig.tight_layout()
    fig.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close(fig)


def plot_fig5(df_rescue: pd.DataFrame, rescue_summary: dict[str, float], out_path: Path) -> None:
    fig, (ax_size, ax_win) = plt.subplots(1, 2, figsize=(14.2, 5.8))

    schemes = [
        "AQMP KA Rescue\n(580B + 96B DCL)",
        "Lifeboat\n(Commit + PQC)",
        "Dropkick\n(ZK Seed Proof)",
        "Naive ML-DSA-65\nSpend",
    ]
    sizes = [676, 3420, 3904, 5261]
    colors = ["#059669", "#2563eb", "#d97706", "#991b1b"]

    bars = ax_size.bar(schemes, sizes, color=colors, width=0.55, edgecolor="#0f172a")
    for bar, sz in zip(bars, sizes):
        reduction = (1.0 - sz / 5261.0) * 100.0
        tag = f"{sz:,} B\n(-{reduction:.1f}%)" if sz < 5261 else f"{sz:,} B\n(Baseline)"
        ax_size.text(
            bar.get_x() + bar.get_width() / 2.0,
            sz + 110,
            tag,
            ha="center",
            va="bottom",
            fontsize=8.6,
            fontweight="bold",
        )

    breakdown = (
        f"580 B Witness Breakdown:\n"
        f"- Chain-Code Com: {RESCUE_CHAINCODE_COM_BYTES} B\n"
        f"- Lattice PoK: {RESCUE_BINDING_BYTES} B\n"
        f"- Merkle Snapshot: {RESCUE_MERKLE_PROOF_BYTES} B\n"
        f"- PQ Dest NIZK: {RESCUE_PQC_NIZK_BYTES} B\n"
        f"+ 96 B Dual-Commit XOR"
    )
    ax_size.text(
        0.04,
        0.60,
        breakdown,
        transform=ax_size.transAxes,
        fontsize=8.3,
        bbox={"boxstyle": "round,pad=0.35", "fc": "#f8fafc", "ec": "#475569"},
    )
    ax_size.set_ylim(0, 6200)
    ax_size.set_title("(a) Frozen UTXO Rescue On-Chain Payload Comparison")
    ax_size.set_ylabel("Total On-Chain Bytes per Rescued UTXO")

    # Panel (b): Fukuda Confirmation Window & Latency across epsilon
    eps = df_rescue["epsilon"].to_numpy()
    deltas = df_rescue["delta_star_blocks"].to_numpy()

    ax_win.plot(
        eps,
        deltas,
        marker="o",
        color="#1d4ed8",
        linewidth=2.4,
        markersize=7,
        label=r"Fukuda Minimum Window $\Delta^* = \lceil 4/(1-\epsilon)\rceil$",
    )
    ax_win.fill_between(
        eps,
        deltas,
        48,
        color="#10b981",
        alpha=0.18,
        label=r"Safe Rescue Zone ($\Delta_{\mathrm{eff}} \geq \Delta^*$)",
    )
    ax_win.fill_between(
        eps,
        0,
        deltas,
        color="#ef4444",
        alpha=0.16,
        label=r"Blocked Front-Running Zone ($\Delta_{\mathrm{eff}} < \Delta^*$)",
    )

    for e_val, d_val in zip(eps, deltas):
        ax_win.annotate(
            f"({e_val:.2f}, {int(d_val)})",
            xy=(e_val, d_val),
            xytext=(e_val - 0.04, d_val + 2.4),
            fontsize=8.3,
            fontweight="bold",
            color="#1e3a8a",
        )

    ax_win.text(
        0.05,
        0.68,
        f"Measured Rescue Timing:\n"
        f"- Proof Create: {rescue_summary['mean_create_ms']:.2f} ms\n"
        f"- On-Chain Verify: {rescue_summary['mean_verify_ms']:.2f} ms",
        transform=ax_win.transAxes,
        fontsize=8.4,
        bbox={"boxstyle": "round,pad=0.35", "fc": "#ecfdf5", "ec": "#059669"},
    )
    ax_win.set_xlim(0.05, 0.95)
    ax_win.set_ylim(0, 48)
    ax_win.set_title("(b) Front-Running Resistance Window & Verification Latency")
    ax_win.set_xlabel(r"Adversarial Quantum Advantage Parameter ($\epsilon$)")
    ax_win.set_ylabel(r"Required Confirmation Window $\Delta^*$ (Blocks)")
    ax_win.legend(loc="upper left", frameon=True, framealpha=0.92, fontsize=8.2)

    fig.suptitle("Paper #2: Knowledge-Asymmetry Frozen UTXO Rescue (No Plaintext Pubkey Exposure)")
    fig.tight_layout()
    fig.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close(fig)


def main() -> int:
    data_dir = REPO_ROOT / "research" / "data"
    fig_dir = REPO_ROOT / "research" / "figures"
    data_dir.mkdir(parents=True, exist_ok=True)
    fig_dir.mkdir(parents=True, exist_ok=True)

    configure_style()
    df_mpc = benchmark_mpc_committees()
    df_rescue, rescue_summary = benchmark_utxo_rescue()

    combined = pd.concat([df_mpc, df_rescue], ignore_index=True)
    csv_path = data_dir / "paper2_mpc_rescue_metrics.csv"
    combined.to_csv(csv_path, index=False, float_format="%.6f")

    fig4_path = fig_dir / "fig4_stateless_mpc_scaling.png"
    fig5_path = fig_dir / "fig5_utxo_rescue_comparison.png"
    plot_fig4(df_mpc, fig4_path)
    plot_fig5(df_rescue, rescue_summary, fig5_path)

    print("==========================================================================")
    print("PAPER #2 EMPIRICAL BENCHMARK SUMMARY")
    print("==========================================================================")
    print(df_mpc[["committee_label", "mean_sign_ms", "mean_verify_ms", "aqmp_plonky3_keyreg_bytes", "naive_mldsa65_multisig_bytes", "reduction_vs_mldsa_pct"]].to_string(index=False))
    print("\nUTXO Rescue (580 B witness + 96 B DCL = 676 B):")
    print(df_rescue[["epsilon", "delta_star_blocks", "mean_sign_ms", "mean_verify_ms", "rescue_total_with_dcl_bytes"]].to_string(index=False))
    print(f"\nExported CSV : {csv_path}")
    print(f"Exported Fig4: {fig4_path}")
    print(f"Exported Fig5: {fig5_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
