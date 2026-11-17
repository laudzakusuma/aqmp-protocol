```
BIP: XXX
Layer: Consensus (soft fork)
Title: Post-Quantum Signature Commitment & Dual-Commit XOR via Tapscript (AQMP-BTC v2.0)
Author: Laudza Kusuma <laudza@aqmp.protocol>
        AQMP Research Team <research@aqmp.protocol>
Status: Draft (v2.0)
Type: Standards Track
Created: 2025-01-15
Updated: 2026-11-15
License: BSD-2-Clause
Requires: BIP-340, BIP-341, BIP-342
```

## Abstract

This BIP specifies **AQMP-BTC v2.0**, a Tapscript soft fork that adds
post-quantum cryptographic (PQC) signature commitments and **96-byte Dual-Commit XOR**
temporal decoupling to Bitcoin transactions. The specification defines four primitives:

1. A Tapscript leaf version (`0xC4`) encoding PQC commitment metadata and a
   **96-byte Dual-Commit XOR** spending cycle: Commit Tx1 ($C = F(x) \oplus F(x \parallel m)$,
   $32\text{ B}$) followed by Reveal/Rotate Tx2 ($x \parallel y'$, $y' = F(x')$, $64\text{ B}$).
2. A script opcode `OP_CHECKPQCSIG` (opcode `0xC0`) for FALCON-512, ML-DSA,
   or Dual-Commit XOR verification inside Tapscript spending paths.
3. Formal **Fukuda Migration Deadline** enforcement ($\Delta_{\text{eff}} \ge \Delta^* = \lceil 4/(1 - \epsilon) \rceil$)
   to preserve consensus liveness and block quantum front-running during in-flight UTXO migration.
4. A P2P gossip extension (`pqcsig`) for off-chain witness propagation of full PQC signatures.

AQMP-BTC v2.0 resolves the Bitcoin PQC migration trilemma. It maintains exact
**96 B/tx bandwidth parity** with classical ECDSA ($360.00\text{ MB}$ per block
across $15{,}000$ full nodes at $N = 250$ tx/block), achieves formal QROM soundness,
and preserves full compatibility with legacy wallets and Nakamoto consensus.

## Motivation

### Threat to Bitcoin

Bitcoin outputs fall into two quantum exposure classes:

**Vulnerable** (public key exposed):
- P2PK outputs (pay-to-public-key): public key directly in `scriptPubKey`
- Reused P2PKH, P2WPKH, and P2TR addresses: public key exposed on spend
- Estimated ~4 million BTC (~$200B+) held in exposed-key outputs

**Temporarily unexposed** (public key hidden behind hash commitment until spend):
- Unused P2PKH and P2WPKH addresses (public key hash only)
- Unused P2TR outputs (tweaked pubkey, exposed once spent or directly derivable via CRQC)

Shor's algorithm on a Cryptographically Relevant Quantum Computer (CRQC) recovers a
secp256k1 private key in roughly 8 hours (Webber et al., 2022, Nature) using ~317 logical
qubits. Public quantum hardware roadmaps place this capability around 2033 to 2037.

### Why a Bitcoin-Specific Design?

Bitcoin's conservative soft-fork model and script limits impose distinct design constraints:

- **Tapscript** (BIP-342) allows introducing new opcodes via soft forks.
- **Script limits** (520B stack element limit, 10KB witness limit for non-Tapscript)
  accommodate FALCON-512 (~666B) and ML-DSA-44 (2,420B) inside witness stacks.
- **OP_RETURN** payloads (80B) cannot carry full PQC signatures, though they easily hold
  32B hash commitments.
- **Segregated Witness** (vbytes) discounts PQC witness data by 4x relative to legacy scriptPubKey bytes.

## Specification

### New Leaf Version: `0xC4` (PQC Commitment Leaf)

A Tapscript tree MAY include leaves with version `0xC4`. These leaves
carry PQC commitment data and are ignored by unupgraded nodes (behaving like
`OP_SUCCESS`: any spend satisfying the classical Taproot keypath remains valid).

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

This leaf sits in the Tapscript tree alongside the normal spending script.
The resulting Taproot output has the form:

```
P2TR(internal_key, {
    script_leaf_0: <normal spending condition>,
    pqc_leaf:      PQCLeaf(falcon_commitment),
})
```

### New Opcode: `OP_CHECKPQCSIG` (0xC0)

Inside a leaf with version `0xC4`, `OP_CHECKPQCSIG` verifies
a PQC signature against a message and public key from the stack:

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

`OP_CHECKPQCSIG` selects the verification algorithm from the leading byte of `<pubkey>`:
- `0x02` prefix (33B): FALCON-512 public key (897B after decompression)
- `0x03` prefix (33B): ML-DSA-44 public key
- Raw length-prefixed: full PQC public key

To stay within Tapscript's 520B stack-element limit, scripts store a 32B public-key hash
while the witness supplies the full public key:

```
<pqc_sig> <pqc_pk_hash> OP_CHECKPQCSIG
// Witness provides full pqc_pk; script verifies hash and signature
```

### Spending: AQMP Dual-Spend Path

An AQMP-protected UTXO supports two spend paths:

**Classical path** (verifiable by legacy nodes):
```
Taproot keypath spend with internal_key (ECDSA/Schnorr sig)
```

**Quantum-safe path** (verified by AQMP-aware nodes):
```
Taproot scriptpath spend:
  script_leaf_0: <schnorr_sig> <ecdsa_pubkey> OP_CHECKSIG
  pqc_leaf:      <pqc_sig> <pqc_pk_hash> OP_CHECKPQCSIG
  Both leaves required (AND semantics via CHECKSIGADD)
```

### P2P Message Extension: `pqcsig`

A P2P message type `pqcsig` propagates the full PQC signature bound to a committed transaction:

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

Peers receiving a `tx` carrying a `0xC4` commitment SHOULD request the matching
`pqcsig` record. Archival nodes MUST index `pqcsig` payloads by `txid:input_idx`.

### Weight Adjustment

Witness PQC signature bytes follow the standard 1 vbyte per 4 bytes witness discount.
For FALCON-512 (666B):
- `666 / 4 = 166.5` -> `167 vbytes` additional witness weight
- Effective fee overhead vs. Taproot keypath (~57 vbytes): ~3x

For ML-DSA-44 (2,420B):
- `2420 / 4 = 605 vbytes` additional witness weight
- Effective fee overhead: ~11x

The block-level ZK aggregation extension (`AQMP-BTC-ZK`) collapses per-transaction
witness overhead down to indexed metadata by verifying a block-level STARK/SNARK proof.

### 96-Byte Dual-Commit XOR Spending Cycle (AQMP v2.0)

To avoid embedding multi-kilobyte lattice signatures in routine UTXO spends,
AQMP-BTC v2.0 defines a **96-byte Dual-Commit XOR** temporal-decoupling protocol
proven secure in the Quantum Random Oracle Model (QROM):

1. **Anchor Initialization:** The UTXO locks to $y = F(x) \in \{0,1\}^{256}$ ($32\text{ B}$),
   where $F$ is SHA-256 (or SHA3-256) and $x \xleftarrow{\$} \{0,1\}^{256}$ is an
   ephemeral preimage.
2. **Commit Phase (Tx1, 32 B):** The spender publishes
   $$C = F(x) \oplus F(x \parallel m) \in \{0,1\}^{256},$$
   which binds transaction body $m$ without revealing $x$.
3. **Fukuda Confirmation Window ($\Delta_{\text{eff}} \ge \Delta^*$):** Consensus enforces
   a block delay between Tx1 confirmation and Tx2 reveal governed by the
   Quantum Threat Oracle advantage parameter $\epsilon \in (0, 1)$:
   $$\Delta^*(\epsilon) = \left\lceil \frac{4}{1 - \epsilon} \right\rceil$$

   | Adversarial Advantage ($\epsilon$) | `0.10` | `0.25` | `0.50` | `0.75` | `0.90` |
   |--------------------------------------|--------|--------|--------|--------|--------|
   | Required Window $\Delta^*$ (blocks)  | **5**  | **6**  | **8**  | **16** | **40** |

4. **Reveal and Ephemeral Rotation Phase (Tx2, 64 B):** After $\Delta_{\text{eff}} \ge \Delta^*$
   blocks, the spender reveals $x$ ($32\text{ B}$) and a fresh rotated anchor $y' = F(x')$ ($32\text{ B}$).
   Nodes check $F(x) = y$, $F(x) \oplus F(x \parallel m) = C$, and $y' \ne y$, then set $y \leftarrow y'$.
   The combined two-phase payload is $32 + 64 = 96\text{ B/tx}$ (**0% overhead vs. 96 B/tx Classical ECDSA**),
   cutting replication traffic across $15{,}000$ full nodes by **$98.18\%$** relative to Naive ML-DSA-65.

### Comparative Analysis vs. Bitcoin PQC Migration Proposals

| Proposal | Primary Mechanism | On-Chain Auth Footprint | Legacy UTXO / In-Flight Safety | Consensus / Fork Impact |
|----------|-------------------|-------------------------|-------------------------------|-------------------------|
| **BIP-360 (P2MR)** | Pay-to-Merkle-Root (removes vulnerable Taproot key-path) | Requires full PQC witness ($690\text{ to }3{,}309\text{ B/tx}$) | Requires explicit UTXO sweep; no commit-reveal window | Soft fork (new output type) |
| **BIP-361** | SegWit/Tapscript PQC opcode integration (SLH-DSA / ML-DSA) | $2{,}420\text{ to }17{,}088\text{ B}$ per input | Exposed during mempool propagation without commit | Soft fork |
| **Dropkick** | ZK proof of BIP-39 seed ownership for frozen outputs | Proof per claim ($\ge 1\text{ to }4\text{ KiB}$ SNARK/STARK) | Emergency post-freeze recovery only; high latency | Hard/soft fork recovery rule |
| **Lifeboat** | Commit-delay-reveal migration channel for legacy UTXOs | Multi-tx commit + full PQC script reveal | Ad-hoc delay heuristics with no formal $\Delta^*$ liveness bound | Soft fork / emergency rule |
| **AQMP-BTC v2.0 (This BIP)** | **Dual-Commit XOR ($96\text{ B/tx}$) + Plonky3/LaBRADOR Tapscript** | **$96\text{ B/tx}$ (Dual-Commit XOR) or $300 + 44N\text{ B}$ (Plonky3)** | **Formal Fukuda $\Delta^* = \lceil 4/(1-\epsilon)\rceil$ + QROM binding** | **Pure Tapscript `0xC4` soft fork** |

### Migration Phase Signaling

AQMP phase transitions use BIP-9 version-bit signaling:

```
Bit 12: AQMP Phase 1 activation (Dual-Commit optional)
Bit 13: AQMP Phase 2 activation (Dual-Commit required for high-value)
Bit 14: AQMP Phase 3 activation (PQC-only consensus)
```

Phase 3 activation requires 95% of blocks in a 2,016-block retarget period to
signal support, matching standard Bitcoin soft-fork thresholds.

## Rationale

### Why Tapscript Rather Than OP_RETURN?

`OP_RETURN` outputs are capped at 80 bytes, which cannot store NIST PQC signatures.
Tapscript witnesses support up to 10MB and fit any standardized PQC scheme.

Using leaf version `0xC4` ensures unupgraded nodes ignore the leaf during keypath
validation, preserving soft-fork compatibility.

### Why FALCON-512 as Primary Algorithm?

FALCON-512 offers the smallest signatures among NIST PQC signature candidates
(~666B vs. 2,420B for ML-DSA-44), keeping transaction weights low. FALCON relies
on NTRU lattice hardness, complementing ML-DSA's Module-LWE assumption so nodes can
support both security families.

### Taproot Internal Key Retention

Keeping the classical Schnorr internal key provides three practical properties:
1. Legacy nodes continue validating classical spends until Phase 3.
2. Spend authorization achieves defense-in-depth (requiring both Schnorr and PQC).
3. Accounts degrade gracefully if either signature family encounters cryptanalytic breaks.

### Commitment Scheme

The 32-byte commitment `SHA3-256(pqc_sig || pqc_pk || nonce)` fits existing
script and `OP_RETURN` byte budgets, gives 128-bit quantum preimage security
against Grover search, and uses a random nonce to block commitment equivocation.

## Reference Implementation

Reference code is located in the AQMP SDK (`sdk/aqmp-sdk-complete`):

```
aqmp_sdk/
├── aqmp/algorithms.py      # FALCON-512, ML-DSA-44, ML-DSA-65 signing
├── apse/engine.py          # APSE v2.0 break-even routing
├── dcl/dual_commit.py      # DCL and 96B Dual-Commit XOR verifier
├── zk_agg/proof_engine.py  # ZK aggregation engine
└── oracle/threat_oracle.py # Quantum Threat Oracle and Fukuda Delta* bounds
```

## Test Vectors

### FALCON-512 Commitment

```python
# Test vector: FALCON-512 DCL commitment
message = bytes.fromhex("deadbeef" * 8)          # 32-byte message
nonce   = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")  # 16-byte nonce
pqc_pk  = bytes(897)  # placeholder; replace with actual FALCON-512 keygen
pqc_sig = bytes(666)  # placeholder; replace with actual FALCON-512 sign

commitment = SHA3_256(pqc_sig + pqc_pk + nonce)
# Changing any input byte changes the resulting 32-byte commitment.
```

### OP_CHECKPQCSIG Script

```
Script:   <pqc_pubkey_hash> OP_CHECKPQCSIG
Witness:  <pqc_sig> <pqc_pk> <message>
Expected: stack = [0x01]
```

## Security Analysis

### HNDL Mitigation

AQMP-BTC binds the PQC commitment when the transaction is constructed rather than
when it enters a later sweep block. Adversaries harvesting Schnorr signatures cannot
forge matching commitments without inverting SHA3-256 or breaking the underlying PQC scheme.

### Quantum Adversary Model

Under a CRQC adversary:
- Schnorr (`secp256k1`): forgeable in polynomial time via Shor's algorithm
- FALCON-512: unforgeable under NTRU lattice hardness
- SHA3-256 / SHA-256 (Dual-Commit XOR): formal EUF-CMA-QROM bound $\frac{8(q_F+1)^2 + 32 q_F^3}{2^n}$

An attacker must defeat both Schnorr and the committed PQC layer to forge a Phase-2 spend.

### 51% Attack Resistance Unchanged

AQMP-BTC leaves Bitcoin's Proof-of-Work and Nakamoto longest-chain fork choice untouched.

## Acknowledgments

This BIP derives from AQMP v2.0 protocol research and community discussions on Tapscript,
Schnorr signatures, and post-quantum UTXO migration.

## Copyright

This BIP is licensed under the BSD 2-clause license.
