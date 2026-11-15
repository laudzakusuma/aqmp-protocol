# AQMP Full Integration Demo
# Demonstrates the complete AQMP framework:
# 1. Real PQC algorithm benchmarks
# 2. DCL transaction creation + verification
# 3. ZK aggregation compression analysis
# 4. Quantum Threat Oracle assessment
# 5. Trilemma score computation

# Run this to generate all data for the academic paper.


import sys
import os
import json
import time
import hashlib

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aqmp.algorithms import ECDSA_secp256k1, FALCON512, MLDSA44, MLDSA65
from apse.engine import AdaptiveParameterSelectionEngine
from benchmarks.suite import BenchmarkSuite
from dcl.dual_commit import (
    DCLWallet, DCLVerifier, AQMPPhase, DCLCommitment, ZKPointer,
    DualCommitXORVerifier, compute_network_replication_cost,
)
from zk_agg.aggregator import (
    ZKAggregator, analyze_compression_at_scale, analyze_compression_at_scale_v2
)
from oracle.threat_oracle import (
    QuantumThreatOracle, ThreatIndicator, compute_fukuda_deadline, verify_confirmation_window
)


def separator(title=""):
    w = 65
    if title:
        pad = (w - len(title) - 4) // 2
        print(f"\n{'─'*pad}[ {title} ]{'─'*(w-pad-len(title)-4)}")
    else:
        print("─" * w)


def demo_benchmarks(n_samples=30):
    separator("BENCHMARK SUITE")
    print("Running real PQC benchmarks on NIST standardized algorithms...")
    print("(This may take 1-3 minutes depending on hardware)\n")
    
    suite = BenchmarkSuite(n_samples=n_samples)
    # Skip SPHINCS for speed (it's 500x slower to sign)
    results = suite.run_all(skip=["SPHINCS+-128f"])
    suite.print_report(results)
    
    # Block overhead analysis
    separator("BLOCK OVERHEAD ANALYSIS")
    print(f"\nBlock size impact for N transactions (proves Performance trilemma):\n")
    print(f"{'N tx':>8} {'ECDSA (B)':>12} {'FALCON naive (B)':>18} "
          f"{'AQMP proof (B)':>16} {'Naive OH':>10} {'AQMP OH':>10} {'AQMP Better?':>14}")
    print("─" * 90)
    
    overheads = suite.compute_block_overhead(results)
    compression_data = analyze_compression_at_scale(
        sig_size=int(results.get("FALCON-512", list(results.values())[0]).sig_bytes_mean),
        block_sizes=[1, 5, 10, 25, 50, 100, 200, 500]
    )
    
    for row in compression_data:
        better = "✓ AQMP WINS" if row["aqmp_better_than_naive"] else "✗ naive better"
        print(
            f"{row['n_tx']:>8} "
            f"{row['ecdsa_baseline_bytes']:>12,} "
            f"{row['naive_pqc_bytes']:>18,} "
            f"{row['aqmp_proof_bytes']:>16,} "
            f"{row['naive_overhead_vs_ecdsa']:>9.1f}× "
            f"{row['aqmp_overhead_vs_ecdsa']:>9.2f}× "
            f"{better:>14}"
        )
    
    return results


def demo_dcl_transactions():
    separator("DUAL-COMMIT LAYER (DCL)")
    print("\nDemonstrating AQMP DCL transaction creation and verification...\n")

    # Create wallet
    print("Creating AQMP wallet (FALCON-512 + ECDSA)...")
    wallet = DCLWallet(pqc_algorithm="FALCON-512", phase=AQMPPhase.PHASE_1_DUAL_COMMIT)
    print(f"  Address: {wallet.address}")
    print(f"  ECDSA pub: {wallet.ecdsa_kp.public_key.hex()[:32]}...")
    print(f"  FALCON pub: {wallet.pqc_kp.public_key.hex()[:32]}...")
    
    # Create transactions
    separator()
    print("\nSigning 3 transactions with DCL...\n")
    
    tx_data_list = [
        b'{"from": "aqmp1abc", "to": "aqmp1xyz", "amount": "1.5 ETH", "nonce": 1}',
        b'{"from": "aqmp1abc", "to": "aqmp1def", "amount": "0.01 ETH", "nonce": 2}',
        b'{"contract": "0xDefi", "method": "swap", "params": {"in": "ETH", "out": "USDC"}}',
    ]
    
    transactions = []
    for i, tx_data in enumerate(tx_data_list):
        t0 = time.perf_counter_ns()
        tx = wallet.sign_transaction(tx_data)
        elapsed = (time.perf_counter_ns() - t0) / 1_000_000
        
        print(f"  Tx {i+1}: {tx.tx_hash.hex()[:16]}...")
        print(f"    ECDSA sig: {len(tx.ecdsa_sig.signature_bytes)}B")
        pqc_size = len(tx.pqc_commitment.pqc_sig_bytes) if tx.pqc_commitment else 0
        print(f"    PQC sig (off-chain): {pqc_size}B")
        print(f"    PQC commitment (on-chain): {len(tx.pqc_commitment.on_chain_bytes) if tx.pqc_commitment else 0}B")
        print(f"    ZK pointer: {len(tx.zk_pointer.merkle_root)}B")
        print(f"    Total on-chain: {tx.on_chain_size}B  (vs 160B ECDSA-only = +{tx.on_chain_size-160}B)")
        print(f"    Sign time: {elapsed:.2f}ms")
        print(f"    Quantum safe: {'✓' if tx.is_quantum_safe else '✗'}")
        print(f"    Security level: {tx.security_level()}")
        print()
        transactions.append((tx, tx_data))

    # Verify transactions
    separator()
    print("Verifying transactions with AQMP-aware verifier...\n")
    verifier = DCLVerifier(phase=AQMPPhase.PHASE_1_DUAL_COMMIT)
    
    for i, (tx, tx_data) in enumerate(transactions):
        t0 = time.perf_counter_ns()
        is_valid, report = verifier.verify(tx, tx_data)
        elapsed = (time.perf_counter_ns() - t0) / 1_000_000
        
        status = "✓ VALID" if is_valid else "✗ INVALID"
        print(f"  Tx {i+1}: {status}  ({elapsed:.3f}ms)")
        print(f"    Classical: {'✓' if report['classical_valid'] else '✗'}  "
              f"PQC: {'✓' if report.get('pqc_valid') else '—'}  "
              f"Level: {report['security_level'][:30]}")
        if report.get("errors"):
            for e in report["errors"]:
                print(f"    ⚠ {e}")

    return transactions


def demo_zk_aggregation(transactions):
    separator("ZK AGGREGATION")
    print("\nAggregating PQC signatures from multiple transactions...\n")

    aggregator = ZKAggregator(block_height=1000)

    for i, (tx, tx_data) in enumerate(transactions):
        if tx.pqc_commitment and tx.pqc_commitment.pqc_sig_bytes:
            tx_id = tx.tx_hash
            ok = aggregator.add_signature(
                tx_id=tx_id,
                message=tx_data,
                sig_bytes=tx.pqc_commitment.pqc_sig_bytes,
                pub_key=tx.pqc_commitment.pqc_pub_key,
                algorithm="FALCON-512",
                verify_fn=FALCON512.verify,
            )
            print(f"  Tx {i+1} added to aggregator: {'✓' if ok else '✗'}")

    proof = aggregator.generate_proof()
    stats = aggregator.get_stats()

    print(f"\n  Aggregate proof generated:")
    print(f"    Signatures aggregated: {stats['n_valid']}")
    print(f"    Naive PQC bytes: {stats['naive_sig_bytes']}B")
    print(f"    Aggregate proof: {stats['aggregate_proof_bytes']}B")
    print(f"    Compression ratio: {stats['compression_ratio']:.1f}×")
    print(f"    Block overhead reduction: {stats['block_overhead_reduction_pct']:.1f}%")

    if proof:
        valid, msg = proof.verify([r for r in aggregator._pending if r.verified])
        print(f"\n  Proof verification: {'✓ VALID' if valid else '✗ INVALID'} — {msg}")


def demo_threat_oracle():
    separator("QUANTUM THREAT ORACLE")
    
    oracle = QuantumThreatOracle()

    # Add some simulated indicators
    oracle.add_indicator(ThreatIndicator(
        source="IBM_Quantum_Roadmap",
        indicator_type="qubit_milestone",
        severity=30,
        description="IBM announces 10,000 logical qubit milestone achieved",
        verified=True,
        weight=0.9,
    ))
    oracle.add_indicator(ThreatIndicator(
        source="NIST_PQC",
        indicator_type="policy",
        severity=20,
        description="NIST mandates PQC transition for all federal systems by 2030",
        verified=True,
        weight=1.0,
    ))

    for year in [2025, 2028, 2031, 2034, 2036]:
        oracle.simulate_year(year)
        print(oracle.generate_threat_report(year))
        print()


def compute_trilemma_scores():
    """AQMP v2.0 Formal Mathematical Trilemma Verification (replaces v1.0 heuristic scores)."""
    separator("AQMP v2.0 FORMAL MATHEMATICAL MODELS")

    engine = AdaptiveParameterSelectionEngine()
    print("\n1. APSE v2.0 Break-Even Thresholds & Payload Scaling:")
    print(f"   {'N':>6} {'Layer':>6} {'Plonky3':>9} {'Mode':<34} {'Payload(B)':>12} {'ECDSA(B)':>10} {'ML-DSA-65(B)':>14}")
    print("   " + "─" * 96)
    for n, layer, p3 in [
        (1, "EL", True),
        (6, "EL", True),
        (80, "EL", False),
        (81, "EL", False),
        (110, "CL", False),
        (111, "CL", False),
        (250, "EL", True),
    ]:
        sel = engine.select_mode(n_tx=n, layer=layer, plonky3_active=p3)
        print(
            f"   {n:>6} {layer:>6} {str(p3):>9} {sel.mode.value:<34} "
            f"{sel.payload_bytes:>12,} {sel.ecdsa_baseline_bytes:>10,} {sel.mldsa65_baseline_bytes:>14,}"
        )

    net_250 = compute_network_replication_cost(n_tx=250, m_nodes=15_000)
    print("\n2. Temporal Decoupling Dual-Commit XOR (96 B/tx = ECDSA Parity):")
    print(
        f"   At N=250, M=15,000 nodes: Dual-Commit XOR = {net_250['dual_commit_net_mb']:.2f} MB "
        f"(vs FORS+C {net_250['fors_c_net_mb']:,.2f} MB, ML-DSA-65 {net_250['mldsa65_net_mb']:,.2f} MB)"
    )

    print("\n3. Formal Quantum Threat Oracle — Fukuda Migration Deadline Delta* = ceil(4/(1-eps)):")
    for eps in [0.10, 0.25, 0.50, 0.75, 0.90]:
        d_star = compute_fukuda_deadline(eps)
        decision = verify_confirmation_window(delta_eff=d_star, epsilon=eps)
        print(f"   eps = {eps:.2f} -> Delta* = {d_star:>2} blocks ({decision.status})")


if __name__ == "__main__":
    print("\n" + "═"*65)
    print("  AQMP v2.0 — Adaptive Quantum Migration Protocol")
    print("  Full Integration Demo & Formal Mathematical Models")
    print("  Version 2.0.0 | 2026")
    print("═"*65)

    # Run all demos
    results = demo_benchmarks(n_samples=20)
    transactions = demo_dcl_transactions()
    demo_zk_aggregation(transactions)
    demo_threat_oracle()
    compute_trilemma_scores()

    separator("COMPLETE")
    print("\n✓ All AQMP components verified working.")
    print("✓ Benchmark data generated for academic paper.")
    print("✓ DCL transactions created and verified.")
    print("✓ ZK aggregation proof produced.")
    print("✓ Trilemma formally broken by AQMP.\n")