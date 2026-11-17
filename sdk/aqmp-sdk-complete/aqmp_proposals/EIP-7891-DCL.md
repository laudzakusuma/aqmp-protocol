---
eip: 7891
title: Dual-Commit Layer (DCL) & APSE v2.0 Post-Quantum Transaction Authentication
description: >
  A soft-fork mechanism combining 96-byte Dual-Commit XOR temporal decoupling,
  APSE v2.0 deterministic ZK-aggregation (Plonky3 BabyBear and LaBRADOR fallback),
  KeyRegistry 4B indexing, and Fukuda oracle finality bounds.
author: >
  Laudza Kusuma <laudza@aqmp.protocol>,
  AQMP Research Team (@aqmp-protocol)
discussions-to: https://ethereum-magicians.org/t/eip-7891-dual-commit-layer-pqc/
status: Draft (v2.0)
type: Standards Track
category: Core
created: 2025-01-15
updated: 2026-11-15
requires: 2718, 4337
---

## Abstract

This EIP defines **EIP-7891 v2.0 (Dual-Commit Layer and APSE v2.0)**, an upgrade
to Ethereum post-quantum transaction authentication combining five components:

1. **96-byte Dual-Commit XOR** ($C = F(x) \oplus F(x \parallel m)$ in Commit Tx1 [$32\text{ B}$],
   reveal $x$ and rotate $y' = F(x')$ in Reveal Tx2 [$64\text{ B}$]), matching the exact bandwidth
   of Classical ECDSA ($96\text{ B/tx}$, $360.00\text{ MB}$ across $15{,}000$ nodes at $N=250$)
   versus ERC-4337 ephemeral FORS+C ($2{,}356\text{ B/tx}$, $8{,}835.00\text{ MB}$).
2. **4-byte `KeyRegistry` Account Indexing**, compressing FALCON-512 public keys
   ($p = 897\text{ B}$) to `idx = 4 B` and reducing per-transaction witness overhead to $44\text{ B/tx}$
   ($R = 40\text{ B}$ salt plus $\text{idx} = 4\text{ B}$).
3. **Plonky3 Two-Stage STARK-to-SNARK Recursion** over the 31-bit **BabyBear** field
   ($p = 2^{31} - 2^{27} + 1$) with Poseidon2 hashing, producing a **$300\text{ B}$ constant
   proof** within an **$810\text{ ms}$ proving budget** ($\text{Payload} = 300 + 44N\text{ B}$).
   This beats Classical ECDSA starting at $N^*_{\text{ECDSA}} = 6\text{ tx/block}$ ($11{,}300\text{ B}$ vs.
   $24{,}000\text{ B}$ at $N = 250$).
4. **APSE v2.0 Deterministic LaBRADOR Fallback**, keeping blocks in FALCON-512 Key-Recovery
   ($690N\text{ B}$) below $N^*_{\text{EL}} = 81$ (EL) or $N^*_{\text{CL}} = 111$ (CL) and
   switching to indexed LaBRADOR aggregation at and above those break-even counts.
5. **Fukuda Quantum Threat Oracle Window** ($\Delta_{\text{eff}} \ge \Delta^* = \lceil 4/(1 - \epsilon) \rceil$).

## Motivation

### The Quantum Threat

Ethereum transaction authentication depends exclusively on ECDSA over
`secp256k1` (`ecrecover`). Shor's algorithm on a Cryptographically
Relevant Quantum Computer (CRQC) recovers any exposed ECDSA private key in polynomial time.
Once a public key appears on-chain during broadcast, that account remains exposed
to retrospective recovery.

The NSA, NIST, ENISA, BSI, and NCSC have published transition timelines targeting
2030 to 2035. NIST completed its initial PQC signature standardization in August 2024
(FIPS 203/204/205), alongside draft FIPS 206 (FALCON).

### The Migration Trilemma

Existing migration paths sacrifice one of the three core properties:

| Approach | Security | Performance | Compatibility |
|----------|----------|-------------|---------------|
| Hard Fork (PQC-only) | Full | Acceptable | Breaks existing tooling and EOAs |
| Soft Fork (SPHINCS+) | Full | 267x sig overhead | Backward compatible |
| ERC-4337 PQC wallets | Partial | Good | New smart accounts only |
| **DCL (this EIP)** | **Full** | **+49% overhead (Phase 1); 96 B/tx XOR or 300+44N B (v2.0)** | **Full, zero hard fork** |

### Harvest-Now-Decrypt-Later (HNDL)

Adversaries can archive Ethereum transactions broadcast today and derive private keys
once a CRQC exists. DCL binds a PQC commitment at signing time so archived classical
signatures alone cannot authorize future forged transactions after migration phases activate.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119 and RFC 8174.

### Transaction Type

DCL introduces EIP-2718 transaction envelope type `0x05`:

```
DCLTransaction = {
    chainId:        uint64,
    nonce:          uint64,
    maxPriorityFee: uint256,
    maxFee:         uint256,
    gasLimit:       uint64,
    to:             address,
    value:          uint256,
    data:           bytes,
    accessList:     AccessList,

    // Classical authentication (unchanged)
    signatureYParity: uint8,
    signatureR:       uint256,
    signatureS:       uint256,

    // DCL extension (new fields)
    pqcAlgorithmId:   uint8,      // 0x01=FALCON-512, 0x03=ML-DSA-44, 0x00=none
    pqcCommitment:    bytes32,    // SHA3-256(pqc_sig || pqc_pk || nonce)
    pqcNonce:         bytes16,    // 16-byte random nonce (binding)
    zkPointer:        bytes32,    // Merkle root of ZK aggregate proof bundle
                                  // (zeros if ZK aggregation not active)
}
```

### Algorithm Identifiers

| ID | Algorithm | NIST Standard | Key Size | Sig Size |
|----|-----------|---------------|----------|----------|
| `0x00` | None (legacy) | N/A | N/A | N/A |
| `0x01` | FALCON-512 | FIPS 206 | 897B pk | ~666B sig |
| `0x02` | FALCON-1024 | FIPS 206 | 1793B pk | ~1280B sig |
| `0x03` | ML-DSA-44 (Dilithium2) | FIPS 204 | 1312B pk | 2420B sig |
| `0x04` | ML-DSA-65 (Dilithium3) | FIPS 204 | 1952B pk | 3293B sig |
| `0x05` | ML-DSA-87 (Dilithium5) | FIPS 204 | 2592B pk | 4595B sig |

### Commitment Construction

```python
def compute_pqc_commitment(pqc_sig: bytes, pqc_pk: bytes, nonce: bytes16) -> bytes32:
    """
    Compute the 32-byte DCL commitment embedded in the transaction.

    Properties:
      - Binding: SHA3-256 collision resistance (128-bit quantum security)
      - Hiding: random 16-byte nonce prevents preimage correlation
      - Compact: fixed 32 bytes on-chain across all PQC algorithms
    """
    return SHA3_256(pqc_sig || pqc_pk || nonce)
```

Full PQC signatures and public keys stay off-chain during Phase 1, propagating over
the P2P mempool and stored by archival nodes. The on-chain commitment acts as the binding anchor.

### Commitment Verification

AQMP-aware clients MUST:

1. Retrieve the full PQC signature and public key from the P2P gossip layer
   (indexed by the commitment hash).
2. Verify the PQC signature under the specified NIST PQC algorithm.
3. Recompute `SHA3_256(pqc_sig || pqc_pk || nonce)` and verify equality with
   `pqcCommitment`.
4. If `zkPointer != bytes32(0)`, verify the ZK aggregate proof bundle.

Legacy clients without DCL support MUST:
- Accept `type=0x05` transactions when the ECDSA signature is valid.
- Treat `pqcAlgorithmId`, `pqcCommitment`, `pqcNonce`, and `zkPointer` as opaque bytes.

### AQMP Migration Phases

Phase transitions occur via on-chain governance or Quantum Threat Oracle (`EIP-7891-QTO`) attestations:

**Phase 0: Preparation** (default on EIP activation):
- `type=0x05` transactions are valid with `pqcAlgorithmId=0x00` (no PQC).
- No PQC commitment checks are enforced.
- Clients deploy DCL transaction parsing.

**Phase 1: Dual Commit Active**:
- `type=0x05` transactions with `pqcAlgorithmId != 0x00` MUST supply valid
  `pqcCommitment` and `pqcNonce` values.
- `type=0x02` legacy transactions remain valid.
- Both transaction types receive equal consensus priority.

**Phase 2: PQC Primary** (requires separate activation EIP):
- `type=0x05` with valid PQC commitment REQUIRED for transfers above a governance
  value threshold (default: 1 ETH).
- `type=0x02` transactions below the threshold remain valid.

**Phase 3: PQC Only** (separate governance vote required):
- All transactions MUST use `type=0x05` with valid PQC commitments.
- Classical-only transactions are rejected.

### Gas Costs

| Field | Additional Gas |
|-------|---------------|
| `pqcAlgorithmId` (1 byte) | 4 |
| `pqcCommitment` (32 bytes) | 512 |
| `pqcNonce` (16 bytes) | 256 |
| `zkPointer` (32 bytes) | 512 |
| PQC commitment verification | 50,000 |
| **Total DCL overhead** | **~51,284 gas** |

PQC commitment verification gas (50,000) covers off-chain signature lookup and
SHA3-256 verification. Under Phase 2 ZK aggregation, batch verification amortizes
this cost to roughly 500 gas per transaction.

### APSE v2.0 Deterministic State-Switching and `KeyRegistry` Specification

Execution Layer (EL) and Consensus Layer (CL) block builders run APSE v2.0 with
a `KeyRegistry` precompile that maps registered FALCON-512 public keys ($p = 897\text{ B}$)
to 4-byte `uint32` indices (`idx = 4 B`), shrinking per-transaction metadata to
$R + \text{idx} = 40 + 4 = 44\text{ B}$:

1. **Primary Mode (`Plonky3_Indexed_Aggregation`):** When Plonky3 two-stage
   STARK-to-SNARK recursion over the BabyBear field ($p = 2^{31} - 2^{27} + 1$)
   completes within the **$810\text{ ms}$** hardware proving budget and $N \ge 1$:
   $$\text{Payload}_{\text{Plonky3}}(N) = 300 + 44N \text{ bytes}$$
   - Break-even vs. FALCON Key-Recovery ($690N\text{ B}$): $N^*_{\text{Plonky3}} = 1$.
   - Break-even vs. Classical ECDSA ($96N\text{ B}$): **$N^*_{\text{ECDSA}} = 6$ tx/block** ($564\text{ B} < 576\text{ B}$).
   - At $N = 250$: **$11{,}300\text{ B}$** ($11.04\text{ KiB}$) vs. $24{,}000\text{ B}$ ECDSA ($-52.9\%$) and $1{,}315{,}250\text{ B}$ ML-DSA-65 ($-99.14\%$).
2. **LaBRADOR Fallback Mode:** When Plonky3 is disabled or proving latency exceeds $810\text{ ms}$:
   - **Execution Layer (`EL`):** $a_{N,\text{EL}} = 51{,}200 + \lfloor 128 \log_2(\max(N, 2)) \rfloor$ bytes.
     Stay in `FALCON_KeyRecovery_Unaggregated` ($690N\text{ B}$) for $N < 81$;
     switch to `LaBRADOR_Indexed_Aggregation` ($a_{N,\text{EL}} + 44N\text{ B}$) for **$N \ge N^*_{\text{EL}} = 81$**.
   - **Consensus Layer (`CL`):** Fixed $70\text{ KiB} = 71{,}680\text{ B}$ overhead.
     Stay in `FALCON_KeyRecovery_Unaggregated` ($690N\text{ B}$) for $N < 111$;
     switch to `LaBRADOR_Indexed_Aggregation` ($71{,}680 + 44N\text{ B}$) for **$N \ge N^*_{\text{CL}} = 111$**.

### ERC-4337 Ephemeral FORS+C vs. Dual-Commit XOR Key Rotation

Account Abstraction (`ERC-4337`) Smart Accounts have two post-quantum key-rotation options:
- **Ephemeral FORS+C ($n=16, K=26, A=5$):** Requires $2{,}336\text{ B}$ signature
  payload plus a $20\text{ B}$ commitment update ($2{,}356\text{ B/tx}$, replicating
  $8{,}835.00\text{ MB}$ across $15{,}000$ nodes at $N = 250$).
- **AQMP v2.0 Dual-Commit XOR:** Requires $32\text{ B}$ Commit Tx1 ($C = F(x) \oplus F(x \parallel m)$)
  and $64\text{ B}$ Reveal/Rotate Tx2 ($x \parallel y' = F(x')$) totaling **$96\text{ B/tx}$**
  ($360.00\text{ MB}$ across $15{,}000$ nodes at $N = 250$), a **$95.93\%$** bandwidth reduction
  relative to FORS+C and exact $1.00\times$ parity with Classical ECDSA, gated by Fukuda's
  confirmation window $\Delta_{\text{eff}} \ge \Delta^* = \lceil 4/(1 - \epsilon) \rceil$.

### New Precompile: PQC_COMMITMENT_VERIFY (0x0B)

```
Input:  commitment (32B) || nonce (16B) || algo_id (1B) || sig_hash (32B)
Output: 0x01 (valid) or 0x00 (invalid)
Gas:    50,000 base + 1,000 per 100 bytes of sig
```

This precompile lets smart contracts verify DCL commitments on-chain so DeFi
protocols and DAOs can require PQC-authenticated governance transactions.

## Rationale

### Why Soft Fork?

A hard fork forcing all wallets and DApps to upgrade at once would fragment Ethereum.
DCL introduces quantum security incrementally so lower gas costs and threat-oracle
alerts drive migration without sudden breakage.

### Why Commitment Rather Than Full Signature?

Storing raw FALCON-512 (~666B) or ML-DSA-44 (2,420B) signatures in every transaction
would expand block sizes by 10 to 38x. Storing only a 32-byte commitment preserves
cryptographic binding while keeping full signatures retrievable from archival P2P storage.

### Why Not ERC-4337 (Account Abstraction) Alone?

ERC-4337 brings PQC signing to new smart-contract wallets, yet leaves existing EOA
accounts exposed unless users manually sweep funds in a multi-year migration.
DCL protects existing EOAs directly from activation day.

### Algorithm Selection

FALCON-512 serves as the primary DCL algorithm for three reasons:
- Compact signatures among NIST PQC candidates (~666B standard, 650B key-recovery)
- Sub-millisecond verification (~0.04ms on commodity CPUs)
- NIST Level 1 security (128-bit quantum security) under FIPS 206

ML-DSA-44 and ML-DSA-65 serve high-value transfers (> 10 ETH) because:
- NIST Level 2/3 security margins
- Module-LWE security assumption (FIPS 204), independent of NTRU

## Backwards Compatibility

This EIP is fully backward compatible. Existing `type=0x01` and `type=0x02`
transactions keep working unchanged. Transaction type `0x05` is strictly additive
until a dedicated governance vote activates Phase 3.

## Security Considerations

### Commitment Pre-Image Resistance

DCL commitments use SHA3-256 (128-bit quantum preimage resistance under Grover search).
A CRQC attacker cannot swap a PQC signature without finding a SHA3-256 preimage or collision.

### Double-Spend Protection

Each commitment includes a fresh random 16-byte nonce so identical transaction bodies
yield independent commitment digests, blocking replay attacks.

### Transition Period Vulnerability

During Phases 0 and 1, classical ECDSA remains sufficient for legacy consensus.
Phase 2 must activate before a CRQC can forge ECDSA keys faster than block finality,
guided by the Quantum Threat Oracle (`EIP-7891-QTO`) and Fukuda's $\Delta^*$ bound.

### PQC Algorithm Security Assumptions

FALCON-512 relies on NTRU lattice hardness, and ML-DSA relies on Module-LWE hardness.
High-assurance accounts may specify ML-DSA-65 (`0x04`) or FALCON-1024 (`0x02`).

## Reference Implementation

Reference implementation lives in `sdk/aqmp-sdk-complete`:
- `aqmp_sdk/dcl/dual_commit.py`: `DCLTransaction`, `DCLWallet`, `DCLVerifier`, and `DualCommitXORVerifier`
- `aqmp_sdk/apse/engine.py`: APSE v2.0 break-even switching engine
- `aqmp_sdk/aqmp/algorithms.py`: Algorithm registry (FALCON-512, ML-DSA-44/65)
- `aqmp_sdk/benchmarks/suite.py`: Latency and footprint benchmarks

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).
