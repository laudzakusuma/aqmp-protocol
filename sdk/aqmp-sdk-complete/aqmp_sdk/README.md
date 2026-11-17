# AQMP v2.0 SDK (`aqmp_sdk`)

> **Breaking the PQC Blockchain Migration Trilemma**
> Python reference SDK for AQMP v2.0 (Adaptive Quantum Migration Protocol): APSE v2.0 break-even routing, 96-byte Dual-Commit XOR verification, Plonky3 BabyBear recursive aggregation parameters, and Fukuda consensus migration deadlines.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![NIST PQC](https://img.shields.io/badge/NIST%20PQC-FIPS%20203%2F204%2F205-green.svg)](https://csrc.nist.gov/pqc)

## Overview: AQMP v2.0 Empirical Guarantees

AQMP v2.0 replaces heuristic migration scoring with exact mathematical byte-footprint equations, deterministic ZK-aggregation break-even switching, and formal QROM bounds:

| Protocol / Strategy | Break-Even ($N^*$) | Payload @ $N=250$ | Network Cost ($15\text{k}$ nodes) | Liveness / Finality Guarantee |
|---------------------|--------------------|-------------------|------------------------------------|-------------------------------|
| Classical ECDSA Baseline | N/A | $24{,}000\text{ B}$ ($96\text{ B/tx}$) | $360.00\text{ MB}$ | Quantum-vulnerable ($\epsilon$-broken) |
| Naive ML-DSA-65 | N/A | $1{,}315{,}250\text{ B}$ ($5{,}261\text{ B/tx}$) | $19{,}728.75\text{ MB}$ | Post-quantum (no aggregation) |
| LaBRADOR Indexed Fallback (EL / CL) | $N^*_{\text{EL}}=81$, $N^*_{\text{CL}}=111$ | $63{,}219\text{ B}$ (EL) / $82{,}680\text{ B}$ (CL) | N/A | $a_{N,\text{EL}} + 44N$ / $71{,}680 + 44N$ |
| **AQMP v2.0 (Plonky3 + `KeyRegistry`)** | **$N^*_{\text{ECDSA}} = 6$ tx/block** | **$11{,}300\text{ B}$ ($300 + 44N$)** | N/A | **$-99.14\%$ vs ML-DSA-65, $-52.92\%$ vs ECDSA** |
| **AQMP v2.0 Dual-Commit XOR** | **$N = 1$ (exact ECDSA parity)** | **$24{,}000\text{ B}$ ($32\text{ B} + 64\text{ B}$)** | **$360.00\text{ MB}$** | **$\Delta_{\text{eff}} \ge \Delta^* = \lceil 4/(1-\epsilon)\rceil$** |

Fukuda Threat Oracle Deadlines: $\Delta^* \in \{5, 6, 8, 16, 40\}$ blocks for adversarial quantum advantage $\epsilon \in \{0.10, 0.25, 0.50, 0.75, 0.90\}$.

## Quick Start

### Create a DCL Transaction

```python
from aqmp_sdk.dcl.dual_commit import DCLWallet, DCLVerifier, AQMPPhase

# Create AQMP wallet (ECDSA + FALCON-512)
wallet = DCLWallet(pqc_algorithm="FALCON-512", phase=AQMPPhase.PHASE_1_DUAL_COMMIT)
print(f"Address: {wallet.address}")

# Sign a transaction (creates both ECDSA and PQC commitment)
tx_data = b'{"to": "aqmp1abc", "amount": "1.5 ETH"}'
tx = wallet.sign_transaction(tx_data)

print(f"Quantum safe: {tx.is_quantum_safe}")          # True
print(f"On-chain size: {tx.on_chain_size}B")          # 241B (vs 160B ECDSA-only)

verifier = DCLVerifier()
is_valid, report = verifier.verify(tx, tx_data)
print(f"Valid: {is_valid}, Security: {report['security_level']}")
```

### Run APSE v2.0 and Dual-Commit XOR

```python
from aqmp_sdk.apse.engine import AdaptiveParameterSelectionEngine
from aqmp_sdk.dcl.dual_commit import DualCommitXORVerifier

apse = AdaptiveParameterSelectionEngine()
el_res = apse.select_mode(n_tx=250, layer="EL", plonky3_active=True, proving_time_ms=420.0)
print(el_res.mode, el_res.payload_bytes)  # Plonky3_Indexed_Aggregation, 11300
```

### Quantum Threat Oracle and Fukuda Deadline

```python
from aqmp_sdk.oracle.threat_oracle import QuantumThreatOracle, compute_fukuda_deadline

oracle = QuantumThreatOracle()
oracle.simulate_year(2031)
print(oracle.generate_threat_report())
print("Delta*(0.50) =", compute_fukuda_deadline(0.50))  # 8 blocks
```

## Architecture

```
aqmp_sdk/
├── aqmp/
│   └── algorithms.py      # Unified interface: ECDSA + NIST PQC algos (with fallback)
├── apse/
│   └── engine.py          # APSE v2.0: Plonky3 / LaBRADOR break-even switching
├── benchmarks/
│   └── suite.py           # Benchmark suite (mean/stddev/p99)
├── dcl/
│   └── dual_commit.py     # Dual-Commit Layer + 96B Dual-Commit XOR verifier
├── zk_agg/
│   └── aggregator.py      # ZK aggregation & APSE v2.0 scale analysis
├── zk_circuit/
│   └── plonky3_babybear_spec.json  # Plonky3 BabyBear 300B STARK-to-SNARK spec
├── oracle/
│   └── threat_oracle.py   # Quantum Threat Oracle & Fukuda Delta* deadlines
├── tests/
│   ├── test_aqmp_v2.py           # Automated AQMP v2.0 pytest suite
│   └── test_qrom_formal_bounds.py # EasyCrypt & QROM formal bound tests
└── demo.py                # Full integration demo
```

## Supported Algorithms

| Algorithm | NIST Level | Sig Size | Basis | AQMP Use |
|-----------|-----------|----------|-------|----------|
| ECDSA-secp256k1 | N/A | 64B | ECC (quantum-vulnerable) | Baseline |
| **FALCON-512** | 1 | ~666B (650B KR) | NTRU Lattice | Micro/routine tx |
| **FALCON-1024** | 5 | ~1280B | NTRU Lattice | High-security |
| **ML-DSA-44** (Dilithium2) | 2 | 2420B | Module-LWE | Standard tx |
| **ML-DSA-65** (Dilithium3) | 3 | 3309B | Module-LWE | High-value tx |
| **SPHINCS+-128f** | 1 | 17088B | Hash-based | Max conservatism |

## Academic Paper & Formal Proofs

- LaTeX manuscript: `research/aqmp_v2_iacr_paper.tex`
- Word & PDF manuscripts: `research/pqc_trilemma_paper_v2.docx`, `research/pqc_trilemma_paper_v2.pdf`
- EasyCrypt QROM specification: `formal_proofs/AQMP_DualCommit_QROM.ec`

## License

MIT (see [LICENSE](LICENSE)).
