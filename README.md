# AQMP v2.0: Adaptive Quantum Migration Protocol

> **Breaking the PQC Blockchain Migration Trilemma**
> Open-source framework achieving Quantum Security, Performance Parity, and Backward Compatibility via formal byte-footprint equations and QROM proofs.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![NIST PQC](https://img.shields.io/badge/NIST%20PQC-FIPS%20203%2F204%2F205-green.svg)](https://csrc.nist.gov/pqc)

## The Problem: The PQC Blockchain Migration Trilemma

Migrating blockchains to Post-Quantum Cryptography (PQC) creates a three-way conflict called the **PQC Blockchain Migration Trilemma**:

```
                    QUANTUM SECURITY
                           ▲
                          / \
                         /   \
                        /     \
          PERFORMANCE ◄─────────► COMPATIBILITY
```

No single-step migration strategy satisfies all three properties simultaneously:
- Hard Fork Migration: Security + Performance, breaks Compatibility
- Soft Fork Hybrid: Security + Compatibility, loses Performance
- Layered Migration: Performance + Compatibility, weakens Security

Formal impossibility bounds and QROM security proofs are documented in [research/aqmp_v2_iacr_paper.tex](research/aqmp_v2_iacr_paper.tex), [research/pqc_trilemma_paper_v2.pdf](research/pqc_trilemma_paper_v2.pdf), and [formal_proofs/AQMP_DualCommit_QROM.ec](formal_proofs/AQMP_DualCommit_QROM.ec).

## The Solution: AQMP v2.0

AQMP v2.0 separates upgrade timelines through **Temporal Decoupling** across four components:

| Component | Function | Trilemma Axis |
|-----------|----------|---------------|
| **Dual-Commit Layer (DCL & XOR)** | 96 B/tx commit-reveal-rotate cycle with ECDSA parity | Compatibility |
| **ZK-Aggregated Proofs** | N FALCON-512 sigs folded into a 300 B Plonky3 BabyBear proof | Performance |
| **APSE v2.0 Engine** | Deterministic Plonky3 / LaBRADOR switching at $N^*_{\text{EL}}=81$, $N^*_{\text{CL}}=111$ | Performance |
| **Quantum Threat Oracle (QTO)** | Enforces Fukuda migration deadline $\Delta^* = \lceil 4/(1 - \epsilon) \rceil$ | Security |

### Empirical Mathematical Guarantees

| Protocol / Strategy | Break-Even ($N^*$) | Payload @ $N=250$ | Network Cost ($15\text{k}$ nodes) | Liveness / Finality Guarantee |
|---------------------|--------------------|-------------------|------------------------------------|-------------------------------|
| Classical ECDSA Baseline | N/A | $24{,}000\text{ B}$ ($96\text{ B/tx}$) | $360.00\text{ MB}$ | Quantum-vulnerable ($\epsilon$-broken) |
| Naive ML-DSA-65 | N/A | $1{,}315{,}250\text{ B}$ ($5{,}261\text{ B/tx}$) | $19{,}728.75\text{ MB}$ | Post-quantum (no aggregation) |
| LaBRADOR Indexed Fallback (EL / CL) | $N^*_{\text{EL}}=81$, $N^*_{\text{CL}}=111$ | $63{,}219\text{ B}$ (EL) / $82{,}680\text{ B}$ (CL) | N/A | $a_{N,\text{EL}} + 44N$ / $71{,}680 + 44N$ |
| **AQMP v2.0 (Plonky3 + `KeyRegistry`)** | **$N^*_{\text{ECDSA}} = 6$ tx/block** | **$11{,}300\text{ B}$ ($300 + 44N$)** | N/A | **$-99.14\%$ vs ML-DSA-65, $-52.92\%$ vs ECDSA** |
| **AQMP v2.0 Dual-Commit XOR** | **$N = 1$ (exact ECDSA parity)** | **$24{,}000\text{ B}$ ($32\text{ B} + 64\text{ B}$)** | **$360.00\text{ MB}$** | **$\Delta_{\text{eff}} \ge \Delta^* = \lceil 4/(1-\epsilon)\rceil$** |

Fukuda Threat Oracle Deadlines: $\Delta^* \in \{5, 6, 8, 16, 40\}$ blocks for adversarial quantum advantage $\epsilon \in \{0.10, 0.25, 0.50, 0.75, 0.90\}$.

## Quick Start

```bash
pip install -r requirements.txt
pytest -v
python formal_proofs/qrom_reduction_verifier.py
```

### Run APSE v2.0 and Dual-Commit XOR

```python
from sdk.aqmp_sdk_complete.aqmp_sdk.apse.engine import AdaptiveParameterSelectionEngine
from sdk.aqmp_sdk_complete.aqmp_sdk.oracle.threat_oracle import compute_fukuda_deadline

apse = AdaptiveParameterSelectionEngine()
res = apse.select_mode(n_tx=250, layer="EL", plonky3_active=True, proving_time_ms=420.0)
print(res.mode, res.payload_bytes)  # AggregationMode.PLONKY3_INDEXED_AGGREGATION, 11300
print("Delta*(0.50) =", compute_fukuda_deadline(0.50))  # 8 blocks
```

## Repository Structure

```
aqmp-protocol/
├── formal_proofs/
│   ├── AQMP_DualCommit_QROM.ec       # EasyCrypt QROM proof specification
│   ├── qrom_reduction_verifier.py    # Concrete QROM bound verifier & game-hop sim
│   └── qrom_concrete_bounds.csv      # Bounds across q_F in [2^20, 2^64]
├── research/
│   ├── aqmp_v2_iacr_paper.tex        # IEEE/IACR LaTeX manuscript
│   ├── pqc_trilemma_paper_v2.docx    # Formatted Word manuscript with figures
│   ├── pqc_trilemma_paper_v2.pdf     # Exported PDF manuscript
│   ├── data/                         # Model A/B/C empirical CSV datasets
│   └── figures/                      # 300 DPI publication PNG plots
└── sdk/aqmp-sdk-complete/
    ├── aqmp_proposals/               # BIP-XXX-AQMP-BTC.md & EIP-7891-DCL.md
    └── aqmp_sdk/
        ├── apse/engine.py            # APSE v2.0 break-even switching engine
        ├── dcl/dual_commit.py        # DCL & 96 B/tx Dual-Commit XOR verifier
        ├── oracle/threat_oracle.py   # Quantum Threat Oracle & Fukuda Delta*
        ├── zk_agg/aggregator.py      # ZK aggregation & APSE v2.0 scaling
        ├── zk_circuit/plonky3_babybear_spec.json
        └── tests/                    # Automated pytest suite (54 tests)
```

## Supported Algorithms

| Algorithm | NIST Level | Sig Size | Basis | AQMP Use |
|-----------|-----------|----------|-------|----------|
| ECDSA-secp256k1 | N/A | 64B | ECC (quantum-vulnerable) | Legacy baseline |
| **FALCON-512** | 1 | 626B std / 650B KR | NTRU Lattice | Primary aggregated auth |
| **FALCON-1024** | 5 | ~1280B | NTRU Lattice | High-security accounts |
| **ML-DSA-44** (Dilithium2) | 2 | 2420B | Module-LWE | Standard unaggregated tx |
| **ML-DSA-65** (Dilithium3) | 3 | 3309B | Module-LWE | High-value tx |
| **SPHINCS+-128f** | 1 | 17088B | Hash-based | Conservative fallback |

## Citation

```bibtex
@article{kusuma2026aqmp,
  title={Breaking the Post-Quantum Cryptography Blockchain Migration Trilemma:
         The Adaptive Quantum Migration Protocol (AQMP v2.0)},
  author={Laudza Kusuma},
  note={Independent Researcher, Zenodo Record 24303569},
  year={2026}
}
```

## License

MIT (see [LICENSE](LICENSE)).
