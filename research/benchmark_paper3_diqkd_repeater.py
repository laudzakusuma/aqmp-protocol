#!/usr/bin/env python3
"""Empirical Physics Benchmark Suite for AQMP Paper #3:
Decoherence-Resilient Classical Authentication for DI-QKD and Quantum Repeaters.

Outputs:
  - research/data/paper3_diqkd_repeater_metrics.csv
  - research/figures/fig6_diqkd_keyrate_vs_distance.png (300 DPI)
  - research/figures/fig7_coherence_decoherence_boundary.png (300 DPI)
"""

from __future__ import annotations

from dataclasses import asdict
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

from aqmp_sdk.qkd.di_qkd_repeater import (  # noqa: E402
    AUTH_SCHEME_REGISTRY,
    AuthSchemeType,
    TSIRELSON_BOUND,
    WideSponge384Authenticator,
    compute_critical_coherence_ms,
    compute_qrom_384_security_bits,
    simulate_diqkd_repeater_point,
)


ALL_SCHEMES = [
    AuthSchemeType.IDEAL_ZERO_LATENCY,
    AuthSchemeType.AQMP_384_DUAL_COMMIT_XOR,
    AuthSchemeType.FALCON_512,
    AuthSchemeType.ML_DSA_65,
    AuthSchemeType.SPHINCS_PLUS_128F,
]

SCHEME_STYLE = {
    AuthSchemeType.IDEAL_ZERO_LATENCY: ("Ideal Zero-Latency (0 B)", "#111827", "dotted", 2.0),
    AuthSchemeType.AQMP_384_DUAL_COMMIT_XOR: ("AQMP v2.0 384b Dual-Commit XOR (144 B)", "#059669", "solid", 2.6),
    AuthSchemeType.FALCON_512: ("FALCON-512 (690 B)", "#2563eb", "dashed", 2.0),
    AuthSchemeType.ML_DSA_65: ("Naive ML-DSA-65 (3,309 B)", "#d97706", "dashdot", 2.0),
    AuthSchemeType.SPHINCS_PLUS_128F: ("SPHINCS+-128f (17,088 B)", "#991b1b", "solid", 1.8),
}


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
            "legend.fontsize": 8.2,
            "figure.titlesize": 12.6,
            "figure.titleweight": "bold",
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.grid": True,
            "grid.alpha": 0.28,
            "grid.linestyle": "dashed",
            "savefig.dpi": 300,
        }
    )


def benchmark_wide_sponge_cpu() -> float:
    """Measure real AQMP-384 Dual-Commit XOR verification microsecond latency."""
    auth = WideSponge384Authenticator()
    x_list = [bytes([i % 250 + 1]) * 48 for i in range(1, 202)]
    msg = b"BSM_OUTCOME:SWAP_BELL_PHI_PLUS:HOP_3"

    anchors = [auth.create_anchor(x) for x in x_list[:-1]]
    commits = [auth.create_commit(x, msg) for x in x_list[:-1]]
    reveals = [auth.create_reveal(x_list[i], x_list[i + 1]) for i in range(200)]

    t0 = time.perf_counter_ns()
    for i in range(200):
        ok, _, _ = auth.verify_and_rotate(
            anchors[i], commits[i], reveals[i][0], reveals[i][1], msg
        )
        assert ok is True
    t1 = time.perf_counter_ns()
    return ((t1 - t0) / 200.0) / 1_000.0  # microseconds per cycle


def run_sweeps() -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    distances = np.linspace(10.0, 500.0, 50)
    dist_rows = []
    for L in distances:
        for st in ALL_SCHEMES:
            pt = simulate_diqkd_repeater_point(st, distance_km=float(L), tau_coh_ms=25.0, n_hops_m=8)
            d = asdict(pt)
            d["sweep_type"] = "distance_sweep"
            d["scheme"] = st.value
            d["tau_bell_crit_ms"] = np.nan
            d["tau_dw_crit_ms"] = np.nan
            dist_rows.append(d)

    taus = np.linspace(1.0, 100.0, 50)
    tau_rows = []
    for tau in taus:
        for st in ALL_SCHEMES:
            pt = simulate_diqkd_repeater_point(st, distance_km=200.0, tau_coh_ms=float(tau), n_hops_m=8)
            d = asdict(pt)
            d["sweep_type"] = "coherence_sweep"
            d["scheme"] = st.value
            d["tau_bell_crit_ms"] = np.nan
            d["tau_dw_crit_ms"] = np.nan
            tau_rows.append(d)

    hop_rows = []
    for m in range(2, 17):
        for st in ALL_SCHEMES:
            pt = simulate_diqkd_repeater_point(st, distance_km=200.0, tau_coh_ms=25.0, n_hops_m=m)
            t_bell, t_dw = compute_critical_coherence_ms(st, distance_km=200.0, n_hops_m=m)
            d = asdict(pt)
            d["sweep_type"] = "hop_boundary"
            d["scheme"] = st.value
            d["tau_bell_crit_ms"] = t_bell
            d["tau_dw_crit_ms"] = t_dw
            hop_rows.append(d)

    return pd.DataFrame(dist_rows), pd.DataFrame(tau_rows), pd.DataFrame(hop_rows)


def plot_fig6(df_dist: pd.DataFrame, out_path: Path) -> None:
    fig, (ax_kr, ax_s) = plt.subplots(1, 2, figsize=(14.4, 5.8))

    for st in ALL_SCHEMES:
        sub = df_dist[df_dist["scheme"] == st.value]
        label, color, ls, lw = SCHEME_STYLE[st]
        # Floor tiny zeros at 1e-1 only on log plot when showing positive curves
        y_kr = sub["secret_key_rate_bps"].to_numpy()
        pos_mask = y_kr > 0
        if np.any(pos_mask):
            ax_kr.plot(
                sub["distance_km"].to_numpy()[pos_mask],
                y_kr[pos_mask],
                label=label,
                color=color,
                linestyle=ls,
                linewidth=lw,
            )
        else:
            ax_kr.plot([], [], label=f"{label} [Collapsed: 0 bps]", color=color, linestyle=ls, linewidth=lw)

        ax_s.plot(
            sub["distance_km"],
            sub["chsh_s"],
            label=label,
            color=color,
            linestyle=ls,
            linewidth=lw,
        )

    ax_kr.set_yscale("log")
    ax_kr.set_xlim(10, 500)
    ax_kr.set_ylim(1e2, 2e5)
    ax_kr.set_title("(a) DI-QKD Secret Key Rate vs. Fiber Distance (tau_coh=25 ms, M=8)")
    ax_kr.set_xlabel("Total Optical Fiber Distance L (km)")
    ax_kr.set_ylabel("Asymptotic Secret Key Rate r_DI-QKD (bits/s, log)")
    ax_kr.text(
        0.04,
        0.08,
        "Collapsed to 0 bps at all distances:\n"
        "- FALCON-512 (dt_auth = 7.78 ms)\n"
        "- ML-DSA-65 (dt_auth = 27.02 ms)\n"
        "- SPHINCS+-128f (dt_auth = 225.36 ms)",
        transform=ax_kr.transAxes,
        fontsize=8.3,
        bbox={"boxstyle": "round,pad=0.35", "fc": "#fef2f2", "ec": "#dc2626"},
    )
    ax_kr.legend(loc="upper right", frameon=True, framealpha=0.92, fontsize=8.0)

    ax_s.axhline(TSIRELSON_BOUND, color="#6b7280", linestyle="dotted", linewidth=1.2, label="Tsirelson Bound (2*sqrt(2))")
    ax_s.axhline(2.0, color="#dc2626", linestyle="dashed", linewidth=1.6, label="Classical Bell Limit (S = 2.0)")
    ax_s.axhspan(0, 2.0, color="#ef4444", alpha=0.10)
    ax_s.axhspan(2.0, 2.9, color="#10b981", alpha=0.07)

    ax_s.set_xlim(10, 500)
    ax_s.set_ylim(0.0, 2.95)
    ax_s.set_title("(b) CHSH Bell Parameter S Retention Across Repeater Span")
    ax_s.set_xlabel("Total Optical Fiber Distance L (km)")
    ax_s.set_ylabel("Effective CHSH Parameter S(dt)")
    ax_s.annotate(
        "AQMP-384 preserves S > 2.63\nacross full 500 km span",
        xy=(250, 2.65),
        xytext=(165, 2.18),
        arrowprops={"arrowstyle": "->", "color": "#059669", "lw": 1.2},
        fontsize=8.4,
        fontweight="bold",
        color="#047857",
        bbox={"boxstyle": "round,pad=0.25", "fc": "#ecfdf5", "ec": "#059669"},
    )
    ax_s.legend(loc="center right", frameon=True, framealpha=0.92, fontsize=7.8)

    fig.suptitle("Paper #3: Decoherence Collapse vs. AQMP-384 DI-QKD Preservation (M=8 Hops)")
    fig.tight_layout()
    fig.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close(fig)


def plot_fig7(df_tau: pd.DataFrame, df_hop: pd.DataFrame, out_path: Path) -> None:
    fig, (ax_tau, ax_hop) = plt.subplots(1, 2, figsize=(14.4, 5.8))

    for st in ALL_SCHEMES:
        sub_t = df_tau[df_tau["scheme"] == st.value]
        label, color, ls, lw = SCHEME_STYLE[st]
        ax_tau.plot(
            sub_t["tau_coh_ms"],
            sub_t["dw_key_fraction"],
            label=label,
            color=color,
            linestyle=ls,
            linewidth=lw,
        )

        sub_h = df_hop[df_hop["scheme"] == st.value]
        if st != AuthSchemeType.IDEAL_ZERO_LATENCY:
            ax_hop.plot(
                sub_h["n_hops_m"],
                sub_h["tau_dw_crit_ms"],
                marker="o",
                markersize=4.5,
                label=label,
                color=color,
                linestyle=ls,
                linewidth=lw,
            )

    ax_tau.axvline(25.0, color="#475569", linestyle="dashed", linewidth=1.3)
    ax_tau.text(26.5, 0.72, "Ref tau_coh = 25 ms", fontsize=8.4, fontweight="bold", color="#334155")
    ax_tau.set_xlim(1, 100)
    ax_tau.set_ylim(0, 0.90)
    ax_tau.set_title("(a) Devetak-Winter Secret Key Fraction vs. Memory Coherence Time")
    ax_tau.set_xlabel("Quantum Memory Coherence Time tau_coh (ms)")
    ax_tau.set_ylabel("Asymptotic Secret Key Fraction f_DW")
    ax_tau.legend(loc="lower right", frameon=True, framealpha=0.92, fontsize=8.0)

    ax_hop.set_yscale("log")
    ax_hop.axhspan(1.0, 100.0, color="#10b981", alpha=0.12, label="Realistic Quantum Memory Regime (1 to 100 ms)")
    ax_hop.axhline(100.0, color="#047857", linestyle="dotted", linewidth=1.4)
    ax_hop.set_xlim(2, 16)
    ax_hop.set_ylim(0.2, 20_000.0)
    ax_hop.set_title("(b) Critical Coherence Boundary tau_coh,DW* vs. Repeater Hops (L=200 km)")
    ax_hop.set_xlabel("Repeater Segment Count (M Hops)")
    ax_hop.set_ylabel("Minimum Required Coherence Time tau_DW* (ms, log)")
    ax_hop.legend(loc="lower right", frameon=True, framealpha=0.94, fontsize=7.8)

    fig.suptitle("Paper #3: Quantum Memory Coherence Thresholds Across Authentication Layers")
    fig.tight_layout()
    fig.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close(fig)


def main() -> int:
    data_dir = REPO_ROOT / "research" / "data"
    fig_dir = REPO_ROOT / "research" / "figures"
    data_dir.mkdir(parents=True, exist_ok=True)
    fig_dir.mkdir(parents=True, exist_ok=True)

    configure_style()
    cpu_us = benchmark_wide_sponge_cpu()
    qrom_bits = compute_qrom_384_security_bits(64)

    df_dist, df_tau, df_hop = run_sweeps()
    all_df = pd.concat([df_dist, df_tau, df_hop], ignore_index=True)
    csv_path = data_dir / "paper3_diqkd_repeater_metrics.csv"
    all_df.to_csv(csv_path, index=False, float_format="%.6f")

    fig6_path = fig_dir / "fig6_diqkd_keyrate_vs_distance.png"
    fig7_path = fig_dir / "fig7_coherence_decoherence_boundary.png"
    plot_fig6(df_dist, fig6_path)
    plot_fig7(df_tau, df_hop, fig7_path)

    print("==========================================================================")
    print("PAPER #3 EMPIRICAL PHYSICS & AUTHENTICATION BENCHMARK SUMMARY")
    print("==========================================================================")
    print(f"AQMP-384 Dual-Commit XOR CPU Verify Time : {cpu_us:.2f} us/cycle")
    print(f"AQMP-384 QROM Security Bound (q_F=2^64)  : {qrom_bits:.2f} bits")
    print("\nSnapshot at L = 200 km, M = 8 hops, tau_coh = 25 ms:")
    snap = df_dist[(df_dist["distance_km"].round(0) == 200) | ((df_dist["distance_km"] - 200.0).abs() < 6.0)]
    first_near_200 = snap.drop_duplicates(subset=["scheme"])
    print(
        first_near_200[
            ["scheme", "auth_payload_bytes", "delta_t_auth_ms", "fidelity", "chsh_s", "secret_key_rate_bps"]
        ].to_string(index=False)
    )
    print("\nCritical Minimum Coherence Time (L = 200 km, M = 8 hops):")
    hop8 = df_hop[df_hop["n_hops_m"] == 8]
    print(hop8[["scheme", "tau_bell_crit_ms", "tau_dw_crit_ms"]].to_string(index=False))
    print(f"\nExported CSV : {csv_path} ({csv_path.stat().st_size:,} bytes)")
    print(f"Exported Fig6: {fig6_path}")
    print(f"Exported Fig7: {fig7_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
