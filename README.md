# AQMP v2.0: Adaptive Quantum Migration Protocol

> **Breaking the PQC Blockchain Migration Trilemma**
> Open-source framework achieving Quantum Security, Performance Parity, and Backward Compatibility across blockchain protocols and quantum repeater networks.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![NIST PQC](https://img.shields.io/badge/NIST%20PQC-FIPS%20203%2F204%2F205-green.svg)](https://csrc.nist.gov/pqc)

## Published Research Trilogy & Zenodo DOIs

**Author:** Laudza Kusuma (Independent Researcher)

1. **Paper #1 (AQMP v2.0 Core Protocol & QROM Proofs):** [https://doi.org/10.5281/zenodo.24303569](https://doi.org/10.5281/zenodo.24303569) (Concept DOI: `10.5281/zenodo.18993494`)
2. **Paper #2 (Stateless PQ-MPC & 676B Knowledge-Asymmetry UTXO Rescue):** [https://doi.org/10.5281/zenodo.24341314](https://doi.org/10.5281/zenodo.24341314)
3. **Paper #3 (AQMP-384 Classical Authentication for DI-QKD & Quantum Repeaters):** [https://doi.org/10.5281/zenodo.24343601](https://doi.org/10.5281/zenodo.24343601)

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

Formal impossibility bounds and QROM security proofs are documented in [research/aqmp_v2_iacr_paper.tex](research/aqmp_v2_iacr_paper.tex), [research/pqc_trilemma_paper_v2.pdf](research/pqc_trilemma_paper_v2.pdf), [research/paper2_stateless_mpc_rescue.pdf](research/paper2_stateless_mpc_rescue.pdf), [research/paper3_aqmp_diqkd_repeaters.pdf](research/paper3_aqmp_diqkd_repeaters.pdf), and [formal_proofs/AQMP_DualCommit_QROM.ec](formal_proofs/AQMP_DualCommit_QROM.ec).

## The Solution: AQMP v2.0

AQMP v2.0 separates upgrade timelines through **Temporal Decoupling** across six core modules:

| Component | Function | Research Scope |
|-----------|----------|----------------|
| **Dual-Commit Layer (DCL & XOR)** | 96 B/tx (256-bit) & 144 B (384-bit) commit-reveal-rotate cycle | Compatibility & QROM |
| **APSE v2.0 & Plonky3 BabyBear** | Deterministic switching at $N^*_{\text{EL}}=81$, $N^*_{\text{CL}}=111$, $N^*_{\text{ECDSA}}=6$ | Execution Performance |
| **Quantum Threat Oracle (QTO)** | Enforces Fukuda migration deadline $\Delta^* = \lceil 4/(1 - \epsilon) \rceil$ | Consensus Liveness |
| **Stateless PQ-MPC Custody** | Zero-counter $t$-of-$n$ lattice threshold signatures safe across backup restores | Multi-Zone Custody |
| **Knowledge-Asymmetry Rescue** | 580 B BIP-32 chain-code proof + 96 B DCL (`676 B` total, zero plaintext pubkey) | Legacy UTXO Rescue |
| **DI-QKD Repeater Auth** | 144 B AQMP-384 channel authentication (`187.00-bit` QROM, `S = 2.669` at 200 km) | Quantum Repeaters |

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

## Repository Structure

```
aqmp-protocol/
├── formal_proofs/
│   ├── AQMP_DualCommit_QROM.ec       # EasyCrypt QROM proof specification
│   ├── qrom_reduction_verifier.py    # Concrete QROM bound verifier & game-hop sim
│   └── qrom_concrete_bounds.csv      # Bounds across q_F in [2^20, 2^64]
├── research/
│   ├── aqmp_v2_iacr_paper.tex        # Paper #1 LaTeX manuscript
│   ├── pqc_trilemma_paper_v2.pdf     # Paper #1 PDF (Zenodo 24303569)
│   ├── paper2_stateless_mpc_rescue.tex / .docx / .pdf  # Paper #2 (Zenodo 24341314)
│   ├── paper3_aqmp_diqkd_repeaters.tex / .docx / .pdf  # Paper #3 (Zenodo 24343601)
│   ├── data/                         # Paper #1-#3 empirical CSV datasets
│   └── figures/                      # 300 DPI publication PNG plots (fig1 to fig7)
└── sdk/aqmp-sdk-complete/
    ├── aqmp_proposals/               # BIP-XXX-AQMP-BTC.md & EIP-7891-DCL.md
    └── aqmp_sdk/
        ├── apse/engine.py            # APSE v2.0 break-even switching engine
        ├── dcl/dual_commit.py        # DCL & 96 B/tx Dual-Commit XOR verifier
        ├── mpc/stateless_pq_mpc.py   # Paper #2: Stateless t-of-n PQ-MPC engine
        ├── rescue/utxo_rescue.py     # Paper #2: 580B + 96B frozen UTXO rescue
        ├── qkd/di_qkd_repeater.py    # Paper #3: DI-QKD & repeater physics + AQMP-384
        ├── oracle/threat_oracle.py   # Quantum Threat Oracle & Fukuda Delta*
        ├── zk_agg/aggregator.py      # ZK aggregation & APSE v2.0 scaling
        ├── zk_circuit/plonky3_babybear_spec.json
        └── tests/                    # Automated pytest suite (62 tests)
```

## Citation

```bibtex
@article{kusuma2026aqmp_trilogy,
  title={Adaptive Quantum Migration Protocol (AQMP v2.0) Research Trilogy},
  author={Laudza Kusuma},
  note={Independent Researcher, Zenodo DOIs: 10.5281/zenodo.24303569, 10.5281/zenodo.24341314, 10.5281/zenodo.24343601},
  year={2026}
}
```

## License

MIT (see [LICENSE](LICENSE)).
