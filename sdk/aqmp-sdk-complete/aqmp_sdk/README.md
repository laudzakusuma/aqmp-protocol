# AQMP v2.0 SDK (`aqmp_sdk`)

> **Breaking the PQC Blockchain Migration Trilemma**
> Python reference SDK for the AQMP v2.0 research trilogy (APSE v2.0 break-even routing, Dual-Commit XOR verification, stateless PQ-MPC threshold custody, 676B frozen UTXO rescue, and DI-QKD repeater authentication).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![NIST PQC](https://img.shields.io/badge/NIST%20PQC-FIPS%20203%2F204%2F205-green.svg)](https://csrc.nist.gov/pqc)

## Published Research Trilogy & Zenodo DOIs

**Author:** Laudza Kusuma (Independent Researcher)

1. **Paper #1 (AQMP v2.0 Core Protocol & QROM Proofs):** [https://doi.org/10.5281/zenodo.24303569](https://doi.org/10.5281/zenodo.24303569) (Concept DOI: `10.5281/zenodo.18993494`)
2. **Paper #2 (Stateless PQ-MPC & 676B Knowledge-Asymmetry UTXO Rescue):** [https://doi.org/10.5281/zenodo.24341314](https://doi.org/10.5281/zenodo.24341314)
3. **Paper #3 (AQMP-384 Classical Authentication for DI-QKD & Quantum Repeaters):** [https://doi.org/10.5281/zenodo.24343601](https://doi.org/10.5281/zenodo.24343601)

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

wallet = DCLWallet(pqc_algorithm="FALCON-512", phase=AQMPPhase.PHASE_1_DUAL_COMMIT)
tx_data = b'{"to": "aqmp1abc", "amount": "1.5 ETH"}'
tx = wallet.sign_transaction(tx_data)

verifier = DCLVerifier()
is_valid, report = verifier.verify(tx, tx_data)
print(f"Valid: {is_valid}, Security: {report['security_level']}")
```

### Run APSE v2.0, PQ-MPC, UTXO Rescue, and DI-QKD Physics

```python
from aqmp_sdk.apse.engine import AdaptiveParameterSelectionEngine
from aqmp_sdk.oracle.threat_oracle import compute_fukuda_deadline
from aqmp_sdk.qkd.di_qkd_repeater import AuthSchemeType, simulate_diqkd_repeater_point

apse = AdaptiveParameterSelectionEngine()
el_res = apse.select_mode(n_tx=250, layer="EL", plonky3_active=True, proving_time_ms=420.0)
print(el_res.mode, el_res.payload_bytes)  # Plonky3_Indexed_Aggregation, 11300
print("Delta*(0.50) =", compute_fukuda_deadline(0.50))  # 8 blocks
pt = simulate_diqkd_repeater_point(AuthSchemeType.AQMP_384_DUAL_COMMIT_XOR, distance_km=200.0)
print(f"CHSH S={pt.chsh_s:.3f}, SKR={pt.secret_key_rate_bps:.1f} bps")
```

## Architecture

```
aqmp_sdk/
├── aqmp/
│   └── algorithms.py               # Unified interface: ECDSA + NIST PQC algos
├── apse/
│   └── engine.py                   # APSE v2.0: Plonky3 / LaBRADOR break-even switching
├── benchmarks/
│   └── suite.py                    # Benchmark suite (mean/stddev/p99)
├── dcl/
│   └── dual_commit.py              # Dual-Commit Layer + 96B Dual-Commit XOR verifier
├── mpc/
│   └── stateless_pq_mpc.py         # Paper #2: Stateless t-of-n lattice MPC engine
├── rescue/
│   └── utxo_rescue.py              # Paper #2: 580B BIP-32 rescue + 96B DCL
├── qkd/
│   └── di_qkd_repeater.py          # Paper #3: DI-QKD & repeater physics + AQMP-384
├── zk_agg/
│   └── aggregator.py               # ZK aggregation & APSE v2.0 scale analysis
├── zk_circuit/
│   └── plonky3_babybear_spec.json  # Plonky3 BabyBear 300B STARK-to-SNARK spec
├── oracle/
│   └── threat_oracle.py            # Quantum Threat Oracle & Fukuda Delta* deadlines
├── tests/                          # Automated pytest suite (62 tests)
└── demo.py                         # Full integration demo
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

## Academic Papers & Formal Proofs

- Paper #1: `research/aqmp_v2_iacr_paper.tex`, `research/pqc_trilemma_paper_v2.docx`, `research/pqc_trilemma_paper_v2.pdf` ([10.5281/zenodo.24303569](https://doi.org/10.5281/zenodo.24303569))
- Paper #2: `research/paper2_stateless_mpc_rescue.tex`, `.docx`, `.pdf` ([10.5281/zenodo.24341314](https://doi.org/10.5281/zenodo.24341314))
- Paper #3: `research/paper3_aqmp_diqkd_repeaters.tex`, `.docx`, `.pdf` ([10.5281/zenodo.24343601](https://doi.org/10.5281/zenodo.24343601))
- EasyCrypt QROM specification: `formal_proofs/AQMP_DualCommit_QROM.ec`

## License

MIT (see [LICENSE](LICENSE)).
