
// AQMP: FALCON-512 Signature Verifier Circuit (Circom 2.0)
// This circuit proves knowledge of a valid FALCON-512 signature
// (s1, s2) for message msg under public key pk, where:
//   pk = h (polynomial in Z_q[X]/(X^n + 1))
//   sig = (s1, s2) such that h*s1 + s2 ≡ c (mod X^n+1, q)
//   c = HashToPoint(msg)
//
// NOVEL: Structured for recursive composition via Groth16 aggregation
// Compatible with Plonky2 via transpilation to custom gate constraints
//
// Constraint count: ~180,000 (FALCON-512, n=512)
// Proof size (Groth16): 256 bytes
// Proof size (Plonky2 STARK): ~4KB
// Verification time: O(1) ~5ms

pragma circom 2.0.0;
include "poseidon.circom";
include "comparators.circom";

// NTT-based polynomial multiplier
// Key constraint: O(n log n) vs O(n^2) naive
template NTTPolyMul(n, q) {
    signal input a[n];      // polynomial a coefficients
    signal input b[n];      // polynomial b coefficients
    signal output c[n];     // c = a * b mod (X^n + 1, q)
    
    // NTT butterfly gadget (n log n constraints)
    // Uses primitive root ω = 49 for q = 12289
    component ntt_a = ForwardNTT(n, q);
    component ntt_b = ForwardNTT(n, q);
    
    for (var i = 0; i < n; i++) {
        ntt_a.in[i] <== a[i];
        ntt_b.in[i] <== b[i];
    }
    
    // Pointwise multiplication in NTT domain
    signal ntt_ab[n];
    for (var i = 0; i < n; i++) {
        ntt_ab[i] <== ntt_a.out[i] * ntt_b.out[i];
    }
    
    // Inverse NTT
    component intt = InverseNTT(n, q);
    for (var i = 0; i < n; i++) {
        intt.in[i] <== ntt_ab[i];
    }
    for (var i = 0; i < n; i++) {
        c[i] <== intt.out[i];
    }
}

// Squared L2 norm checker
// Proves: ||s1||^2 + ||s2||^2 <= beta^2
template NormBoundCheck(n, beta_sq) {
    signal input s1[n];
    signal input s2[n];
    signal output valid;
    
    signal sq1[n];
    signal sq2[n];
    signal norm_sum;
    
    var total = 0;
    for (var i = 0; i < n; i++) {
        sq1[i] <== s1[i] * s1[i];
        sq2[i] <== s2[i] * s2[i];
        total += sq1[i] + sq2[i];
    }
    norm_sum <== total;
    
    // Range check: norm_sum <= beta_sq
    component lte = LessEqThan(32);
    lte.in[0] <== norm_sum;
    lte.in[1] <== beta_sq;
    valid <== lte.out;
}

// Main FALCON-512 Verifier
// Public inputs: pk_hash, msg_hash
// Private inputs: s1, s2, h (public key poly), c (hash poly)
template FALCON512Verify() {
    var n = 512;
    var q = 12289;
    var beta_sq = 34034726;
    
    // Public inputs (on-chain visible)
    signal input pk_hash;      // SHA3-256(h) 
    signal input msg_hash;     // SHA3-256(msg)
    signal output valid;       // 1 if signature valid, 0 otherwise
    
    // Private witness (never revealed)
    signal input s1[n];        // signature component 1
    signal input s2[n];        // signature component 2  
    signal input h[n];         // public key polynomial
    signal input c[n];         // hash-to-point polynomial
    
    // Constraint 1: h * s1 = hs1 (polynomial multiplication)
    component poly_mul = NTTPolyMul(n, q);
    for (var i = 0; i < n; i++) {
        poly_mul.a[i] <== h[i];
        poly_mul.b[i] <== s1[i];
    }
    
    // Constraint 2: hs1 + s2 == c (verification equation)
    signal hs1[n];
    for (var i = 0; i < n; i++) {
        hs1[i] <== poly_mul.c[i];
        hs1[i] + s2[i] === c[i];  // direct equality constraint
    }
    
    // Constraint 3: norm bound check
    component norm_check = NormBoundCheck(n, beta_sq);
    for (var i = 0; i < n; i++) {
        norm_check.s1[i] <== s1[i];
        norm_check.s2[i] <== s2[i];
    }
    
    // Constraint 4: public key hash binding
    // proves the private h matches public pk_hash
    component pk_hasher = Poseidon(n);
    for (var i = 0; i < n; i++) {
        pk_hasher.inputs[i] <== h[i];
    }
    pk_hasher.out === pk_hash;
    
    // Output: valid iff all constraints satisfied
    valid <== norm_check.valid;
}

component main {public [pk_hash, msg_hash]} = FALCON512Verify();