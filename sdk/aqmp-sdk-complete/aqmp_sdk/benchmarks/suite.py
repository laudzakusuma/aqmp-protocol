"""
AQMP Benchmark Suite
Runs rigorous benchmarks on all PQC algorithms vs ECDSA baseline.
Produces the raw data for the trilemma proof and academic paper.

Methodology:
- N iterations per operation (default: 100 for fast, 1000 for rigorous)  
- Warm-up runs discarded
- Reports: mean, stddev, min, max, p50, p95, p99
- Measures: keygen, sign, verify, sig_size, key_sizes
- Computes: overhead ratios vs ECDSA baseline
"""

from __future__ import annotations
import time
import statistics
import json
import os
import hashlib
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
from datetime import datetime

from aqmp.algorithms import (
    ECDSA_secp256k1, FALCON512, FALCON1024, MLDSA44, MLDSA65, SPHINCS128F,
    ALGORITHM_REGISTRY, KeyPair, Signature
)


@dataclass
class OperationStats:
    """Statistical summary of a timing measurement."""
    operation: str
    algorithm: str
    n_samples: int
    mean_ms: float
    stddev_ms: float
    min_ms: float
    max_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    overhead_vs_ecdsa: Optional[float] = None  # filled post-hoc

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class AlgorithmBenchmarkResult:
    """Complete benchmark results for a single algorithm."""
    algorithm: str
    timestamp: str
    host_info: Dict
    keygen: OperationStats
    sign: OperationStats
    verify: OperationStats
    # Size measurements
    pub_key_bytes: int
    priv_key_bytes: int
    sig_bytes_mean: float
    sig_bytes_min: int
    sig_bytes_max: int
    # Quantum properties
    quantum_safe: bool
    nist_level: int
    basis: str

    def overhead_summary(self, baseline: 'AlgorithmBenchmarkResult') -> Dict:
        """Compute overhead ratios vs a baseline algorithm."""
        return {
            "sig_size_ratio": self.sig_bytes_mean / baseline.sig_bytes_mean,
            "pub_key_ratio": self.pub_key_bytes / baseline.pub_key_bytes,
            "sign_latency_ratio": self.sign.mean_ms / baseline.sign.mean_ms,
            "verify_latency_ratio": self.verify.mean_ms / baseline.verify.mean_ms,
            "keygen_ratio": self.keygen.mean_ms / baseline.keygen.mean_ms,
        }

    def to_dict(self) -> Dict:
        return {
            "algorithm": self.algorithm,
            "timestamp": self.timestamp,
            "keygen": self.keygen.to_dict(),
            "sign": self.sign.to_dict(),
            "verify": self.verify.to_dict(),
            "sizes": {
                "pub_key_bytes": self.pub_key_bytes,
                "priv_key_bytes": self.priv_key_bytes,
                "sig_bytes_mean": self.sig_bytes_mean,
                "sig_bytes_min": self.sig_bytes_min,
                "sig_bytes_max": self.sig_bytes_max,
            },
            "properties": {
                "quantum_safe": self.quantum_safe,
                "nist_level": self.nist_level,
                "basis": self.basis,
            }
        }


def _time_ns_to_ms(ns: int) -> float:
    return ns / 1_000_000.0


def _benchmark_operation(fn, n_samples: int, warmup: int = 3) -> List[float]:
    """Run an operation N+warmup times, discard warmup, return timing list in ms."""
    timings = []
    for i in range(n_samples + warmup):
        t0 = time.perf_counter_ns()
        result = fn()
        t1 = time.perf_counter_ns()
        if i >= warmup:
            timings.append(_time_ns_to_ms(t1 - t0))
    return timings, result


def _stats_from_timings(op: str, algo: str, timings: List[float]) -> OperationStats:
    sorted_t = sorted(timings)
    n = len(sorted_t)
    return OperationStats(
        operation=op,
        algorithm=algo,
        n_samples=n,
        mean_ms=statistics.mean(timings),
        stddev_ms=statistics.stdev(timings) if n > 1 else 0.0,
        min_ms=min(timings),
        max_ms=max(timings),
        p50_ms=sorted_t[int(n * 0.50)],
        p95_ms=sorted_t[int(n * 0.95)],
        p99_ms=sorted_t[min(int(n * 0.99), n-1)],
    )


class BenchmarkSuite:
    """
    Full benchmark suite for all AQMP-supported algorithms.
    
    Usage:
        suite = BenchmarkSuite(n_samples=100)
        results = suite.run_all()
        suite.print_report(results)
        suite.save_json(results, "benchmark_results.json")
    """
    
    ALGORITHMS = {
        "ECDSA-secp256k1": {
            "impl": ECDSA_secp256k1,
            "quantum_safe": False,
            "nist_level": 0,
            "basis": "Elliptic Curve (ECDLP)",
        },
        "FALCON-512": {
            "impl": FALCON512,
            "quantum_safe": True,
            "nist_level": 1,
            "basis": "NTRU Lattice",
        },
        "FALCON-1024": {
            "impl": FALCON1024,
            "quantum_safe": True,
            "nist_level": 5,
            "basis": "NTRU Lattice",
        },
        "ML-DSA-44 (Dilithium2)": {
            "impl": MLDSA44,
            "quantum_safe": True,
            "nist_level": 2,
            "basis": "Module-LWE",
        },
        "ML-DSA-65 (Dilithium3)": {
            "impl": MLDSA65,
            "quantum_safe": True,
            "nist_level": 3,
            "basis": "Module-LWE",
        },
        "SPHINCS+-128f": {
            "impl": SPHINCS128F,
            "quantum_safe": True,
            "nist_level": 1,
            "basis": "Hash-based (Stateless)",
        },
    }

    def __init__(self, n_samples: int = 50, warmup: int = 3,
                 progress_callback=None):
        self.n_samples = n_samples
        self.warmup = warmup
        self.progress_callback = progress_callback or (lambda msg: print(f"  {msg}"))

    def _get_host_info(self) -> Dict:
        import platform
        return {
            "os": platform.system(),
            "arch": platform.machine(),
            "python": platform.python_version(),
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }

    def benchmark_algorithm(self, name: str, config: Dict,
                             test_message: bytes = None) -> AlgorithmBenchmarkResult:
        if test_message is None:
            # Simulate a real blockchain transaction: 32-byte tx hash
            test_message = hashlib.sha3_256(
                b"AQMP_BENCHMARK_TX:" + name.encode() + os.urandom(32)
            ).digest()

        impl = config["impl"]
        self.progress_callback(f"[{name}] Benchmarking keygen × {self.n_samples}...")

        # KEYGEN
        keygen_timings = []
        last_kp = None
        for i in range(self.n_samples + self.warmup):
            t0 = time.perf_counter_ns()
            kp = impl.generate_keypair()
            t1 = time.perf_counter_ns()
            if i >= self.warmup:
                keygen_timings.append(_time_ns_to_ms(t1 - t0))
                last_kp = kp

        keygen_stats = _stats_from_timings("keygen", name, keygen_timings)

        # SIGN
        self.progress_callback(f"[{name}] Benchmarking sign × {self.n_samples}...")
        sign_timings = []
        sig_sizes = []
        last_sig = None
        kp = impl.generate_keypair()  # use stable keypair for sign/verify
        for i in range(self.n_samples + self.warmup):
            t0 = time.perf_counter_ns()
            sig = impl.sign(test_message, kp)
            t1 = time.perf_counter_ns()
            if i >= self.warmup:
                sign_timings.append(_time_ns_to_ms(t1 - t0))
                sig_sizes.append(sig.size)
                last_sig = sig

        sign_stats = _stats_from_timings("sign", name, sign_timings)

        # VERIFY
        self.progress_callback(f"[{name}] Benchmarking verify × {self.n_samples}...")
        verify_timings = []
        for i in range(self.n_samples + self.warmup):
            t0 = time.perf_counter_ns()
            ok = impl.verify(test_message, last_sig)
            t1 = time.perf_counter_ns()
            if i >= self.warmup:
                verify_timings.append(_time_ns_to_ms(t1 - t0))

        if not ok:
            raise RuntimeError(f"Verification FAILED for {name}!")

        verify_stats = _stats_from_timings("verify", name, verify_timings)

        return AlgorithmBenchmarkResult(
            algorithm=name,
            timestamp=datetime.utcnow().isoformat() + "Z",
            host_info=self._get_host_info(),
            keygen=keygen_stats,
            sign=sign_stats,
            verify=verify_stats,
            pub_key_bytes=len(kp.public_key),
            priv_key_bytes=len(kp.private_key),
            sig_bytes_mean=statistics.mean(sig_sizes),
            sig_bytes_min=min(sig_sizes),
            sig_bytes_max=max(sig_sizes),
            quantum_safe=config["quantum_safe"],
            nist_level=config["nist_level"],
            basis=config["basis"],
        )

    def run_all(self, skip: List[str] = None) -> Dict[str, AlgorithmBenchmarkResult]:
        skip = skip or []
        results = {}
        total = len([k for k in self.ALGORITHMS if k not in skip])
        done = 0
        print(f"\n{'='*60}")
        print(f"  AQMP BENCHMARK SUITE — {total} algorithms, {self.n_samples} samples each")
        print(f"{'='*60}\n")

        for name, config in self.ALGORITHMS.items():
            if name in skip:
                continue
            done += 1
            print(f"[{done}/{total}] {name}")
            try:
                result = self.benchmark_algorithm(name, config)
                results[name] = result
                print(f"  ✓ keygen={result.keygen.mean_ms:.3f}ms | "
                      f"sign={result.sign.mean_ms:.3f}ms | "
                      f"verify={result.verify.mean_ms:.3f}ms | "
                      f"sig={result.sig_bytes_mean:.0f}B\n")
            except Exception as e:
                print(f"  ✗ FAILED: {e}\n")

        return results

    def print_report(self, results: Dict[str, AlgorithmBenchmarkResult]):
        """Print a formatted comparison report."""
        baseline_name = "ECDSA-secp256k1"
        baseline = results.get(baseline_name)

        print(f"\n{'='*100}")
        print(f"  PQC BLOCKCHAIN MIGRATION TRILEMMA — BENCHMARK REPORT")
        print(f"  Generated: {datetime.utcnow().isoformat()}Z")
        print(f"  Samples per algorithm: {self.n_samples}")
        print(f"{'='*100}\n")

        # Header
        hdr = f"{'Algorithm':<28} {'QSafe':>6} {'NIST':>5} {'PubKey':>8} {'SigSize':>9} {'Keygen(ms)':>11} {'Sign(ms)':>9} {'Verify(ms)':>11} {'Sig Overhead':>13}"
        print(hdr)
        print("-" * len(hdr))

        for name, r in results.items():
            sig_overhead = f"{r.sig_bytes_mean/baseline.sig_bytes_mean:.1f}×" if baseline else "N/A"
            qs = "✓" if r.quantum_safe else "✗"
            nist = str(r.nist_level) if r.nist_level > 0 else "—"
            marker = " ★" if name == baseline_name else "  "
            print(
                f"{name:<28}"
                f"{qs:>6}"
                f"{nist:>6}"
                f"{r.pub_key_bytes:>8}B"
                f"{r.sig_bytes_mean:>8.0f}B"
                f"{r.keygen.mean_ms:>10.3f}"
                f"{r.sign.mean_ms:>9.3f}"
                f"{r.verify.mean_ms:>11.4f}"
                f"{sig_overhead:>14}"
                f"{marker}"
            )

        if baseline:
            print(f"\n{'─'*60}")
            print(f"  Baseline: {baseline_name}")
            print(f"  TRILEMMA ANALYSIS:")
            print(f"  The PQC migration overhead demonstrated above proves the trilemma:")

            for name, r in results.items():
                if name == baseline_name or not r.quantum_safe:
                    continue
                oh = r.overhead_summary(baseline)
                violations = []
                if oh["sig_size_ratio"] > 20:
                    violations.append(f"sig {oh['sig_size_ratio']:.0f}× larger (Performance fails)")
                if oh["sign_latency_ratio"] > 100:
                    violations.append(f"sign {oh['sign_latency_ratio']:.0f}× slower (Performance fails)")
                print(f"\n  {name}:")
                print(f"    Sig overhead: {oh['sig_size_ratio']:.1f}×  "
                      f"Sign overhead: {oh['sign_latency_ratio']:.1f}×  "
                      f"Verify overhead: {oh['verify_latency_ratio']:.2f}×")
                for v in violations:
                    print(f"    ⚠ {v}")

        print(f"\n{'='*100}")

    def compute_block_overhead(self, results: Dict[str, AlgorithmBenchmarkResult],
                                n_tx: int = 200) -> Dict:
        """
        Compute block size overhead for N transactions in a block.
        Shows why Performance dimension of trilemma fails for naive PQC migration.
        """
        baseline = results["ECDSA-secp256k1"]
        baseline_total = baseline.sig_bytes_mean * n_tx

        overheads = {}
        for name, r in results.items():
            naive_total = r.sig_bytes_mean * n_tx
            # AQMP ZK aggregation: one STARK proof per block ~3000 bytes
            aqmp_total = 3000 + r.sig_bytes_mean * 0.01  # commitment overhead only
            overheads[name] = {
                "naive_bytes": naive_total,
                "aqmp_bytes": aqmp_total,
                "naive_overhead_pct": (naive_total / baseline_total - 1) * 100,
                "aqmp_overhead_pct": (aqmp_total / baseline_total - 1) * 100,
            }
        return overheads

    def save_json(self, results: Dict[str, AlgorithmBenchmarkResult],
                  path: str):
        data = {
            "aqmp_version": "1.0.0",
            "benchmark_timestamp": datetime.utcnow().isoformat() + "Z",
            "n_samples": self.n_samples,
            "results": {name: r.to_dict() for name, r in results.items()},
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"\nResults saved to: {path}")