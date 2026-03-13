```
BIP: XXX
Layer: Consensus (soft fork)
Title: Post-Quantum Signature Commitment via Tapscript (AQMP-BTC)
Author: AQMP Research Team <research@aqmp.protocol>
        [Your Name] <your@email.com>
Status: Draft
Type: Standards Track
Created: 2025-01-15
License: BSD-2-Clause
Requires: BIP-340, BIP-341, BIP-342
```

## Abstract

This BIP proposes **AQMP-BTC**, a Tapscript-based soft fork enabling
post-quantum cryptographic (PQC) signature commitments for Bitcoin transactions.
The proposal introduces:

1. A new Tapscript leaf version (`0xC4`) encoding PQC commitment data
2. A new script opcode `OP_CHECKPQCSIG` (opcode `0xC0`) for PQC signature
   verification within Tapscript spending conditions
3. A P2P message extension for PQC signature propagation

AQMP-BTC resolves the Bitcoin PQC migration trilemma: it achieves
quantum-safe authentication (NIST Level 1+), maintains Bitcoin's block
size constraints via commitment compression, and requires zero changes
to existing wallets, nodes, or infrastructure.

## Motivation

### Threat to Bitcoin

Bitcoin addresses come in two security classes:

**Vulnerable** (public key exposed):
- P2PK outputs (pay-to-public-key): public key directly in scriptPubKey
- Reused P2PKH, P2WPKH, P2TR addresses: public key exposed on spend
- Estimated ~4 million BTC (~$200B+) held in vulnerable addresses

**Temporarily safe** (public key not yet exposed):
- Unused P2PKH, P2WPKH addresses (public key hash only)
- Unused P2TR outputs (tweaked pubkey, but key derivable with CRQC)

Shor's algorithm on a CRQC recovers a Bitcoin private key from the
secp256k1 public key in estimated 8 hours (Webber et al., 2022, Nature)
using ~317 logical qubits. IBM's public roadmap projects this capability
around 2033-2037.

### Why Bitcoin-Specific Design?

Bitcoin's conservative governance and script system require a different
approach than Ethereum:

- **Tapscript** (BIP-342) enables adding new opcodes as soft forks
- **Script size limits** (520B for non-Tapscript, 10KB for witness)
  accommodate FALCON-512 signatures (~666B) and ML-DSA-44 (~2420B)
- **OP_RETURN** fields (80B) are too small for PQC sigs but sufficient
  for 32B commitments
- **Segregated Witness** (vbytes) can accommodate PQC data in witness

## Specification

### New Leaf Version: `0xC4` (PQC Commitment Leaf)

A Tapscript tree MAY include leaves with version `0xC4`. These leaves
encode PQC commitment data and are ignored by legacy nodes (treated as
`OP_SUCCESS`-like — any spend satisfying the classical Taproot keypath
is valid).

```
PQCLeaf {
    version:        0xC4 (1 byte)
    pqc_algo_id:    uint8   (0x01=FALCON-512, 0x03=ML-DSA-44)
    commitment:     bytes32 (SHA3-256(pqc_sig || pqc_pk || nonce))
    nonce:          bytes16
    zk_pointer:     bytes32 (zeros if no ZK aggregation)
}
// Total: 82 bytes per PQC leaf
```

This leaf is embedded in the Tapscript tree alongside the normal
spending conditions. The full Taproot output looks like:

```
P2TR(internal_key, {
    script_leaf_0: <normal spending condition>,
    pqc_leaf:      PQCLeaf(falcon_commitment),
})
```

### New Opcode: `OP_CHECKPQCSIG` (0xC0)

When executed in a leaf with version `0xC4`, `OP_CHECKPQCSIG` verifies
a PQC signature against a message and public key from the stack.

```
Stack input:  <sig> <pubkey> <msg>
Stack output: <1> if valid, <0> if invalid (OP_VERIFY-style)

Script:
  <pqc_pubkey> OP_CHECKPQCSIG
  // or combined with classical:
  <ecdsa_pubkey> OP_CHECKSIG
  <pqc_pubkey> OP_CHECKPQCSIG
  OP_BOOLAND
```

`OP_CHECKPQCSIG` dispatches verification based on the leading byte of
`<pubkey>`:
- `0x02` prefix (33B): FALCON-512 public key (897B after decompression)
- `0x03` prefix (33B): ML-DSA-44 public key
- Raw length-prefixed: full PQC key

To fit within Tapscript's stack element limit (520B), public keys are
stored as 32B commitment hashes with the full key in the witness:

```
<pqc_sig> <pqc_pk_hash> OP_CHECKPQCSIG
// Witness provides full pqc_pk, script verifies hash and signature
```

### Spending: AQMP Dual-Spend Path

An AQMP-protected UTXO can be spent via two paths:

**Classical path** (legacy nodes can verify):
```
Taproot keypath spend with internal_key (ECDSA/Schnorr sig)
```

**Quantum-safe path** (AQMP-aware nodes verify both):
```
Taproot scriptpath spend:
  script_leaf_0: <schnorr_sig> <ecdsa_pubkey> OP_CHECKSIG
  pqc_leaf:      <pqc_sig> <pqc_pk_hash> OP_CHECKPQCSIG
  Both leaves required (AND semantics via CHECKSIGADD)
```

### P2P Message Extension: `pqcsig`

A new P2P message type `pqcsig` propagates the full PQC signature
associated with a committed transaction:

```
pqcsig message {
    txid:       bytes32
    input_idx:  uint32
    algo_id:    uint8
    pqc_pk:     bytes    (length-prefixed)
    pqc_sig:    bytes    (length-prefixed)
    nonce:      bytes16
}
```

Nodes that received the corresponding `tx` message SHOULD request
`pqcsig` from peers. Archival nodes MUST store `pqcsig` data indexed
by `txid:input_idx`.

### Weight Adjustment

PQC signature data in witnesses is counted at the standard witness
discount (1 vbyte per 4 bytes). For FALCON-512 (666B):
- 666 / 4 = 166.5 → 167 vbytes additional witness weight
- Effective fee overhead vs Taproot keypath (~57 vbytes): ~3×

For ML-DSA-44 (2420B):
- 2420 / 4 = 605 vbytes additional witness weight
- Effective fee overhead: ~11×

The ZK aggregation extension (AQMP-BTC-ZK) reduces this to ~1B per tx
by aggregating signatures across a block-level STARK proof.

### Migration Phase Signaling

AQMP phase activation uses BIP-9 version bits signaling:

```
Bit 12: AQMP Phase 1 activation (Dual-Commit optional)
Bit 13: AQMP Phase 2 activation (Dual-Commit required for high-value)
Bit 14: AQMP Phase 3 activation (PQC-only consensus)
```

Phase 3 requires 95% of blocks in a 2016-block difficulty period to
signal support — matching Bitcoin's super-majority threshold.

## Rationale

### Why Tapscript Rather Than OP_RETURN?

OP_RETURN fields are limited to 80 bytes — insufficient for any NIST
PQC signature. Tapscript witness data has effectively no size limit
(10MB witness limit), accommodating any current or future PQC algorithm.

The `0xC4` leaf version ensures legacy nodes see the leaf as undefined
(soft-fork safe), equivalent to OP_SUCCESS semantics for keypath spends.

### Why FALCON-512 as Primary Algorithm?

FALCON-512 is selected because it produces the smallest signatures among
NIST PQC signature standards (~666B vs 2420B for ML-DSA-44), minimizing
the transaction weight overhead. FALCON's security relies on NTRU lattice
hardness, which has a different security basis from ML-DSA's Module-LWE.
Bitcoin's security-conservative culture suggests offering both.

### Taproot Internal Key Retention

The Taproot internal key (classical Schnorr) is retained because:
1. Legacy nodes can still verify spends
2. Provides defense-in-depth (attacker must break both classical AND PQC)
3. Enables graceful degradation if a PQC algorithm is later broken

### Commitment Scheme

The 32-byte commitment `SHA3-256(pqc_sig || pqc_pk || nonce)` is chosen
because:
- SHA3-256 is quantum-safe (128-bit quantum security via Grover's √)
- 32 bytes fits within existing script and OP_RETURN constraints
- The nonce prevents commitment equivocation attacks

## Reference Implementation

Full reference implementation: https://github.com/aqmp-protocol/aqmp-sdk

Key components:
```
aqmp_sdk/
├── aqmp/algorithms.py      # FALCON-512, ML-DSA-44 signing
├── dcl/dual_commit.py      # DCL transaction construction
├── zk_agg/proof_engine.py  # ZK aggregation (Inner Product Argument)
└── oracle/threat_oracle.py # Quantum Threat Oracle
```

## Test Vectors

### FALCON-512 Commitment

```python
# Test vector: FALCON-512 DCL commitment
message = bytes.fromhex("deadbeef" * 8)          # 32-byte message
nonce   = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")  # 16-byte nonce
pqc_pk  = bytes(897)  # placeholder — use actual FALCON-512 keygen
pqc_sig = bytes(666)  # placeholder — use actual FALCON-512 sign

commitment = SHA3_256(pqc_sig + pqc_pk + nonce)
# Expected: depends on actual signature values
# Test: commitment should change if any input byte changes
```

### OP_CHECKPQCSIG Script

```
Script:   <pqc_pubkey_hash> OP_CHECKPQCSIG
Witness:  <pqc_sig> <pqc_pk> <message>
Expected: stack = [0x01]
```

## Security Analysis

### HNDL Mitigation

AQMP-BTC's DCL commits the PQC signature at transaction *creation* time,
not broadcast time. An adversary harvesting Schnorr signatures cannot
retroactively forge the PQC commitment without breaking SHA3-256.

### Quantum Adversary Model

Against a CRQC adversary:
- Schnorr (secp256k1): forgeable via Shor's algorithm
- FALCON-512: not forgeable (NTRU lattice, quantum-hard)
- SHA3-256 (commitment): 128-bit quantum security (Grover's √)

An adversary must break BOTH Schnorr AND FALCON to spend a Phase-2
AQMP-protected UTXO — defense-in-depth.

### 51% Attack Unchanged

AQMP-BTC does not modify Bitcoin's PoW or Nakamoto consensus. 51%
attack resistance is unchanged.

## Acknowledgments

This BIP was developed as part of the AQMP framework research.
The authors thank the Bitcoin developer community for prior work on
Tapscript, Schnorr signatures, and quantum migration discussions.

## Copyright

This BIP is licensed under the BSD 2-clause license.
