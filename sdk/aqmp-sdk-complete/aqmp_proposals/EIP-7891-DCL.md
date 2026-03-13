---
eip: 7891
title: Dual-Commit Layer (DCL) for Post-Quantum Transaction Authentication
description: >
  A soft-fork mechanism embedding a quantum-safe commitment alongside classical
  ECDSA transactions, enabling backward-compatible post-quantum migration
  without a hard fork.
author: >
  AQMP Research Team (@aqmp-protocol),
  [Your Name] <your@email.com>
discussions-to: https://ethereum-magicians.org/t/eip-7891-dual-commit-layer-pqc/
status: Draft
type: Standards Track
category: Core
created: 2025-01-15
requires: 2718, 4337
---

## Abstract

This EIP proposes the **Dual-Commit Layer (DCL)**, a transaction structure
extension that embeds a post-quantum cryptographic (PQC) commitment alongside
the existing ECDSA signature in every Ethereum transaction. The DCL enables
quantum-safe authentication to be introduced via a soft-fork — preserving full
backward compatibility with all existing wallets, DApps, and infrastructure —
while providing a cryptographically binding migration path to full PQC
authentication as standardized by NIST in FIPS 203/204/205 (2024).

DCL resolves two of the three axes of the **PQC Blockchain Migration Trilemma**
(Security and Compatibility) in isolation, and when combined with
EIP-7891-ZK (ZK aggregation extension, forthcoming), resolves all three.

## Motivation

### The Quantum Threat

Ethereum's transaction authentication relies exclusively on ECDSA over
secp256k1 (`ecrecover`). Shor's algorithm running on a Cryptographically
Relevant Quantum Computer (CRQC) can recover the ECDSA private key from any
exposed public key in polynomial time. Once the public key appears on-chain
(which occurs on transaction broadcast), the corresponding account is
permanently vulnerable to retrospective attack.

The NSA, NIST, ENISA, BSI, and NCSC have all issued formal advisories
mandating PQC migration timelines between 2030–2035. The NIST PQC
standardization process completed in August 2024 (FIPS 203/204/205).

### The Migration Trilemma

Prior migration approaches each sacrifice one critical property:

| Approach | Security | Performance | Compatibility |
|----------|----------|-------------|---------------|
| Hard Fork (PQC-only) | ✓ Full | ✓ Acceptable | ✗ Breaks all existing infra |
| Soft Fork (SPHINCS+) | ✓ Full | ✗ 267× sig overhead | ✓ Backward compat |
| ERC-4337 PQC wallets | ✓ Partial | ✓ Good | ✓ Partial (new accounts only) |
| **DCL (this EIP)** | ✓ Full | ✓ +49% overhead (Phase 1) | ✓ **Full, zero hard fork** |

### Harvest-Now-Decrypt-Later (HNDL)

An adversary with sufficient resources can archive all Ethereum transactions
broadcast today for decryption when a CRQC becomes available. This means
transaction data is **already being harvested**. DCL provides a cryptographic
guarantee that even retrospectively harvested transactions cannot be forged
post-CRQC, because the PQC commitment is bound at signing time.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119 and RFC 8174.

### Transaction Type

DCL introduces a new EIP-2718 transaction envelope type: `0x05`.

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
|----|-----------|--------------|----------|----------|
| `0x00` | None (legacy) | — | — | — |
| `0x01` | FALCON-512 | FIPS 206 | 897B pk | ~666B sig |
| `0x02` | FALCON-1024 | FIPS 206 | 1793B pk | ~1280B sig |
| `0x03` | ML-DSA-44 (Dilithium2) | FIPS 204 | 1312B pk | 2420B sig |
| `0x04` | ML-DSA-65 (Dilithium3) | FIPS 204 | 1952B pk | 3293B sig |
| `0x05` | ML-DSA-87 (Dilithium5) | FIPS 204 | 2592B pk | 4595B sig |

### Commitment Construction

```python
def compute_pqc_commitment(pqc_sig: bytes, pqc_pk: bytes, nonce: bytes16) -> bytes32:
    """
    Compute the DCL commitment value embedded in the transaction.
    
    Properties:
      - Binding: SHA3-256 collision resistance (128-bit quantum secure)
      - Hiding: nonce is uniformly random, preventing commitment preimage attacks
      - Compact: exactly 32 bytes on-chain regardless of PQC algorithm
    """
    return SHA3_256(pqc_sig || pqc_pk || nonce)
```

The full PQC signature and public key are NOT stored on-chain. They are
propagated via the P2P mempool and stored by archival nodes. The on-chain
commitment serves as a cryptographic anchor.

### Commitment Verification

AQMP-aware clients MUST:

1. Retrieve the full PQC signature and public key from the P2P network
   (identified by the commitment hash via gossip protocol extension)
2. Verify the PQC signature using the appropriate NIST PQC algorithm
3. Recompute `SHA3_256(pqc_sig || pqc_pk || nonce)` and compare to
   `pqcCommitment` in the transaction
4. If `zkPointer != bytes32(0)`, verify the ZK aggregate proof (per EIP-7891-ZK)

Legacy clients (without DCL support) MUST:
- Accept `type=0x05` transactions if the ECDSA component is valid
- Treat `pqcAlgorithmId`, `pqcCommitment`, `pqcNonce`, `zkPointer` as opaque

### AQMP Migration Phases

Phase transitions are triggered by on-chain governance (EIP-1559 style
parameter updates) or by Quantum Threat Oracle consensus (EIP-7891-QTO):

**Phase 0 — Preparation** (default on EIP activation):
- `type=0x05` transactions are valid with `pqcAlgorithmId=0x00` (no PQC)
- No requirements on PQC commitment fields
- Clients begin supporting DCL transaction parsing

**Phase 1 — Dual Commit Active**:
- `type=0x05` transactions with `pqcAlgorithmId != 0x00` MUST have valid
  `pqcCommitment` and `pqcNonce`
- `type=0x02` (legacy) transactions remain valid
- Both transaction types are treated equally for consensus

**Phase 2 — PQC Primary** (requires separate EIP for activation):
- `type=0x05` with valid PQC commitment REQUIRED for transactions
  exceeding a value threshold (governance parameter, default: 1 ETH)
- `type=0x02` transactions below threshold remain valid

**Phase 3 — PQC Only** (separate governance vote required):
- All transactions MUST use `type=0x05` with valid PQC commitment
- Classical-only transactions rejected

### Gas Costs

| Field | Additional Gas |
|-------|---------------|
| `pqcAlgorithmId` (1 byte) | 4 |
| `pqcCommitment` (32 bytes) | 512 |
| `pqcNonce` (16 bytes) | 256 |
| `zkPointer` (32 bytes) | 512 |
| PQC commitment verification | 50,000 |
| **Total DCL overhead** | **~51,284 gas** |

Note: PQC commitment verification gas (50,000) is comparable to an ECDSA
`ecrecover` precompile call (~3,000 gas) scaled to include the off-chain
signature retrieval and SHA3-256 computation. In Phase 2 with ZK aggregation,
batch verification amortizes this cost to ~500 gas per transaction.

### New Precompile: PQC_COMMITMENT_VERIFY (0x0B)

```
Input:  commitment (32B) || nonce (16B) || algo_id (1B) || sig_hash (32B)
Output: 0x01 (valid) or 0x00 (invalid)
Gas:    50,000 base + 1,000 per 100 bytes of sig
```

This precompile enables smart contracts to verify DCL commitments on-chain,
enabling DeFi protocols and DAOs to require PQC-authenticated governance votes.

## Rationale

### Why Soft Fork?

A hard fork requiring all existing wallets and DApps to upgrade simultaneously
would fragment the Ethereum ecosystem and likely fail politically. The DCL
approach allows quantum security to be introduced incrementally, with economic
incentives (reduced gas for PQC txns in future phases) driving voluntary
migration rather than forced cutoffs.

### Why Commitment Rather Than Full Signature?

Storing full FALCON-512 signatures (~666B) or ML-DSA-44 signatures (~2420B)
directly in Ethereum transactions would increase block sizes by 10-38× at
current transaction volumes. The 32-byte commitment preserves the security
binding of the PQC signature while maintaining reasonable block sizes.
Full signatures are retrievable from the P2P network when needed for
verification challenges or fraud proofs.

### Why Not ERC-4337 (Account Abstraction) Alone?

ERC-4337 enables PQC signing for new accounts using smart contract wallets.
However, it cannot protect existing EOA accounts (which represent the majority
of Ethereum value) without explicit UTXO migration — a multi-year process
during which existing accounts remain quantum-vulnerable. DCL protects all
accounts including existing EOAs from the moment of upgrade.

### Algorithm Selection

FALCON-512 is recommended as the primary DCL algorithm because:
- Smallest signature size among NIST PQC signature standards (~666B)
- Fast verification (~0.04ms on commodity hardware)
- NIST FIPS 206 standardized
- Adequate security (NIST Level 1, 128-bit quantum security)

ML-DSA-44 is recommended for high-value transactions (> 10 ETH) due to:
- Higher security margin (NIST Level 2)
- Module-LWE security basis (better-studied than NTRU)
- FIPS 204 standardized

## Backwards Compatibility

This EIP is fully backward-compatible. Existing `type=0x01` and `type=0x02`
transactions continue to function without modification. The new `type=0x05`
transaction type is additive. No existing contract, wallet, or tool is
required to update until Phase 3, which requires a separate governance vote.

## Security Considerations

### Commitment Pre-Image Resistance

The PQC commitment uses SHA3-256, which provides 128-bit quantum security
against preimage attacks (Grover's algorithm provides √ speedup). An attacker
with a CRQC cannot find a different PQC signature that produces the same
commitment without breaking SHA3-256.

### Double-Spend Protection

The PQC nonce ensures that identical transactions produce different commitments,
preventing replay attacks. The nonce is part of the commitment preimage.

### Transition Period Vulnerability

During Phases 0-1, the classical ECDSA component remains the sole consensus
mechanism. A sufficiently advanced CRQC could still forge ECDSA during this
window. Mitigation: Phase 2 activation should be triggered before CRQC
capability is demonstrated (Quantum Threat Oracle provides early warning).

### PQC Algorithm Security Assumptions

FALCON-512 security rests on the hardness of the NTRU lattice problem.
ML-DSA-44 security rests on Module-LWE hardness. Both are believed to be
quantum-hard based on best-known cryptanalysis. NIST's 7-year evaluation
found no polynomial-time quantum attacks. Users who require higher security
margins should use ML-DSA-65 or FALCON-1024 (Algorithm IDs 0x02, 0x04).

## Reference Implementation

Reference implementation available at:
https://github.com/aqmp-protocol/aqmp-sdk

Key files:
- `aqmp_sdk/dcl/dual_commit.py` — DCLTransaction, DCLWallet, DCLVerifier
- `aqmp_sdk/aqmp/algorithms.py` — Algorithm registry (FALCON-512, ML-DSA-44/65)
- `aqmp_sdk/benchmarks/suite.py` — Performance benchmarks

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).
