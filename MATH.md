# How ML-KEM (Kyber) Works — A Mathematical Guide

> This document explains the mathematics behind ML-KEM (FIPS 203), formerly known as CRYSTALS-Kyber. It's written to be accessible to anyone with high-school algebra.

---

## 1. The Big Picture

Kyber solves a fundamental problem: **how can two people create a shared secret key over an insecure channel?**

```
    Alice                          Bob
      |                              |
      |--- Public Key (pk) -------->|
      |                              |  Bob generates:
      |                              |  • shared secret (ss)
      |<--- Ciphertext (ct) --------|  • ciphertext (ct)
      |                              |
      | Alice recovers:              |
      | • shared secret (ss)         |
      |                              |
      | ✅ Both now have the same    |
      |    shared secret (ss)        |
```

This is called **Key Encapsulation** (KEM). The shared secret is then used for AES or ChaCha20 encryption.

**Why not RSA?** A quantum computer running Shor's algorithm can break RSA and elliptic curves. Kyber is based on a **lattice problem** that resists quantum attacks.

---

## 2. The Playground: Polynomial Rings

All of Kyber's math happens inside a special mathematical structure called a **polynomial ring**.

### 2.1 What is a Polynomial?

A polynomial is just a list of numbers (coefficients) attached to powers of x:

```
f(x) = 3 + 5x + 2x² + 7x³
```

In Kyber, every polynomial has exactly **256 coefficients** (degree 0 through 255):

```
f(x) = a₀ + a₁x + a₂x² + ... + a₂₅₅x²⁵⁵
```

Each coefficient is a number modulo **q = 3329** (a prime). So every coefficient is in {0, 1, 2, ..., 3328}.

### 2.2 The Ring R_q

Kyber operates in the ring:

```
R_q = Z_q[x] / (x²⁵⁶ + 1)
```

What does this mean?

- **Z_q[x]** = polynomials with coefficients mod q = 3329
- **/ (x²⁵⁶ + 1)** = whenever we get x²⁵⁶, we replace it with **-1**

This "wrapping" rule keeps polynomials at exactly 256 terms:

```
Example: x²⁵⁶ = -1    (mod x²⁵⁶ + 1)
         x²⁵⁷ = -x
         x²⁵⁸ = -x²
```

> **Analogy**: Think of a clock. On a 12-hour clock, 15 o'clock = 3 o'clock. Here, polynomials "wrap around" at degree 256.

### 2.3 Why q = 3329?

The prime 3329 was chosen because:
- 3329 ≡ 1 (mod 256), which enables the **Number Theoretic Transform** (fast multiplication)
- It's small enough for 16-bit arithmetic (fits in an `i16`)
- It provides sufficient security margin

---

## 3. The Hard Problem: Module-LWE

Kyber's security is based on the **Module Learning With Errors (M-LWE)** problem.

### 3.1 Easy Problem (without errors)

Suppose we have a public matrix **A** and a secret vector **s**:

```
Given:     A · s = t     (mod q)
Find:      s
```

This is easy — just solve the linear system (Gaussian elimination).

### 3.2 Hard Problem (WITH errors)

Now add a small **error vector e**:

```
Given:     A · s + e = t     (mod q)
Find:      s
```

The errors **e** are tiny (coefficients in {-2, -1, 0, 1, 2}) compared to q = 3329. But they make the problem believed to be **computationally impossible** — even for quantum computers.

> **Analogy**: Imagine someone tells you "I multiplied a matrix by a secret, then jittered every answer by ±2." Even though the jitter is tiny, it completely hides the secret. It's like trying to find an invisible needle in a noisy haystack.

### 3.3 Vectors of Polynomials

In Kyber, **A** is a k×k matrix of polynomials, and **s**, **e** are vectors of k polynomials:

```
ML-KEM-512:  k=2  → 2×2 matrix (NIST Level 1)
ML-KEM-768:  k=3  → 3×3 matrix (NIST Level 3)  ← recommended
ML-KEM-1024: k=4  → 4×4 matrix (NIST Level 5)
```

Each "entry" in the matrix is a polynomial with 256 coefficients.

---

## 4. The Three Algorithms

### 4.1 Key Generation (KeyGen)

Alice generates a public key and a secret key:

```
┌─────────────────────────────────────────────────┐
│                   KEY GENERATION                 │
│                                                  │
│  1. Sample random seed d ∈ {0,1}²⁵⁶             │
│                                                  │
│  2. Expand seed into matrix A (k×k polynomials)  │
│     A = Sam(ρ)      ← deterministic from seed    │
│                                                  │
│  3. Sample secret s (k polynomials, small coeffs)│
│     Each coefficient from CBD(η₁)                │
│     η₁ = 3 for Kyber-512, 2 for Kyber-768/1024  │
│                                                  │
│  4. Sample error e (k polynomials, small coeffs) │
│     Same distribution as s                       │
│                                                  │
│  5. Compute public value:                        │
│     t = A · s + e                                │
│                                                  │
│  Public key  pk = (ρ, t)    ← share with world   │
│  Secret key  sk = s         ← keep secret!       │
└─────────────────────────────────────────────────┘
```

**The key insight**: Given (A, t), finding s is the M-LWE problem — believed impossible.

### 4.2 Encapsulation (Encaps)

Bob uses Alice's public key to generate a shared secret:

```
┌─────────────────────────────────────────────────┐
│                  ENCAPSULATION                   │
│                                                  │
│  Input: Alice's public key (ρ, t)               │
│                                                  │
│  1. Sample random message m ∈ {0,1}²⁵⁶          │
│                                                  │
│  2. Hash to get coins:                           │
│     (K̄, r) = G(m ‖ H(pk))                       │
│                                                  │
│  3. Sample ephemeral secret r (small coeffs)     │
│  4. Sample errors e₁, e₂ (small coeffs)         │
│                                                  │
│  5. Compute:                                     │
│     u = Aᵀ · r + e₁                             │
│     v = tᵀ · r + e₂ + ⌈q/2⌋ · m                │
│                                                  │
│  6. Compress and output:                         │
│     Ciphertext  ct = (Compress(u), Compress(v))  │
│     Shared secret  ss = KDF(K̄ ‖ H(ct))          │
│                                                  │
│  The ⌈q/2⌋ · m term encodes the message:        │
│  • m_i = 0  →  add 0                            │
│  • m_i = 1  →  add 1665 (≈ q/2)                 │
└─────────────────────────────────────────────────┘
```

### 4.3 Decapsulation (Decaps)

Alice recovers the shared secret using her secret key:

```
┌─────────────────────────────────────────────────┐
│                 DECAPSULATION                    │
│                                                  │
│  Input: Secret key s, Ciphertext (u, v)         │
│                                                  │
│  1. Compute:                                     │
│     v - sᵀ · u                                   │
│                                                  │
│  Why this works:                                 │
│     v - sᵀ·u = (tᵀ·r + e₂ + ⌈q/2⌋·m) - sᵀ·u  │
│                                                  │
│  Since t = A·s + e:                              │
│     tᵀ·r = (A·s+e)ᵀ·r = sᵀ·Aᵀ·r + eᵀ·r        │
│                                                  │
│  And u = Aᵀ·r + e₁, so sᵀ·u = sᵀ·Aᵀ·r + sᵀ·e₁│
│                                                  │
│  Subtracting:                                    │
│     v - sᵀ·u = ⌈q/2⌋·m + (eᵀ·r + e₂ - sᵀ·e₁)  │
│                 ════════   ═══════════════════    │
│                  signal         noise             │
│                  (large)        (small!)          │
│                                                  │
│  2. Round each coefficient to recover m:         │
│     • Close to 0      → m_i = 0                 │
│     • Close to q/2    → m_i = 1                 │
│                                                  │
│  3. Re-encrypt m to verify, derive shared secret │
│     ss = KDF(K̄ ‖ H(ct))                         │
└─────────────────────────────────────────────────┘
```

**The magic**: The error terms (eᵀ·r + e₂ - sᵀ·e₁) are all products of **small × small** polynomials, so they stay tiny compared to q/2 ≈ 1665. The rounding step easily distinguishes 0 from q/2.

---

## 5. Visual: The Noise Margin

This is why the small errors never cause decryption failure:

```
   0                        q/2 ≈ 1665                         q = 3329
   |═══════════════════════════|═══════════════════════════════|
   
   For m_i = 0:
   |←── noise (≤ ~50) ──→|
   |██|                                                        
   ↑ decoded as 0 ✓

   For m_i = 1:
                           |←── noise (≤ ~50) ──→|
                           |████|
                           ↑ decoded as 1 ✓

   The noise (~50) is much smaller than the gap to q/2 (1665),
   so rounding always gives the correct answer.
```

---

## 6. Number Theoretic Transform (NTT)

### 6.1 The Speed Problem

Multiplying two polynomials naively requires 256² = **65,536 operations**. The NTT reduces this to 256 × 8 = **~2,048 operations** — a **32× speedup**.

### 6.2 How It Works

The NTT is the "integer version" of the Fast Fourier Transform (FFT):

```
Polynomial Domain              NTT Domain
                          
f(x) = 3 + 5x + 2x²     NTT    f̂ = [f(ω⁰), f(ω¹), ..., f(ω²⁵⁵)]
g(x) = 1 + 4x + 7x²    ────→   ĝ = [g(ω⁰), g(ω¹), ..., g(ω²⁵⁵)]
                          
Multiply: O(n²) = slow          Multiply: O(n) = fast!
                                 ĥᵢ = f̂ᵢ · ĝᵢ  (pointwise)
                          
h(x) = f(x) · g(x)     ←────   ĥ = [ĥ₀, ĥ₁, ..., ĥ₂₅₅]
                         INTT
```

Where ω = 17 is a primitive 256th root of unity modulo 3329 (meaning 17²⁵⁶ ≡ 1 mod 3329).

### 6.3 The Butterfly

The NTT uses a "butterfly" operation — the same pattern as FFT:

```
Layer 0 (128 butterflies):    Layer 1 (64 butterflies):    ...
                              
a ────────⊕──── a + ζ·b      Each layer halves the
         ╲╱                   problem size.
         ╱╲                   
b ──── ζ·⊕──── a - ζ·b       Total: 8 layers × 128 = 1024 ops
```

---

## 7. Compression: Shrinking the Ciphertext

Kyber compresses polynomials to save bandwidth. The idea: we don't need full 12-bit precision for every coefficient.

```
Compress_d(x) = ⌈(2ᵈ / q) · x⌋ mod 2ᵈ

Example (d=4):
  x = 1000  →  ⌈(16/3329) · 1000⌋ = ⌈4.81⌋ = 5
  
Decompress_d(x) = ⌈(q / 2ᵈ) · x⌋

  5  →  ⌈(3329/16) · 5⌋ = ⌈1040.3⌋ = 1040
  
  Error: |1040 - 1000| = 40  (small compared to q)
```

This is lossy, but the rounding error is small enough that decryption still works.

---

## 8. Centered Binomial Distribution (CBD)

The secret and error polynomials need "small" random coefficients. Kyber uses the **Centered Binomial Distribution** (CBD):

```
CBD(η): Generate 2η random bits (b₁...bη, b'₁...b'η)
        Output: (b₁+...+bη) - (b'₁+...+b'η)
        
η=2: Possible outputs: {-2, -1, 0, 1, 2}
     Probabilities:      1/16, 4/16, 6/16, 4/16, 1/16

η=3: Possible outputs: {-3, -2, -1, 0, 1, 2, 3}
```

This is simpler and faster than Gaussian sampling, while providing the same security.

---

## 9. Security: The Fujisaki-Okamoto Transform

The raw encryption scheme (IND-CPA) is vulnerable to chosen-ciphertext attacks. Kyber uses the **Fujisaki-Okamoto (FO) transform** to achieve **IND-CCA2** security:

```
┌────────────────────────────────────────────────────┐
│              IMPLICIT REJECTION                     │
│                                                     │
│  During Decaps:                                     │
│  1. Decrypt to get m'                               │
│  2. Re-encrypt m' to get ct'                        │
│  3. If ct' ≠ ct (tampering detected!):              │
│     → return SHAKE-256(z ‖ ct)  ← random-looking   │
│     (z is a secret random value in the secret key)  │
│  4. If ct' = ct (valid ciphertext):                 │
│     → return the real shared secret                 │
│                                                     │
│  An attacker cannot tell if they got the real       │
│  secret or a random one → no information leakage.   │
└────────────────────────────────────────────────────┘
```

This comparison is done in **constant time** to prevent side-channel attacks.

---

## 10. Complete Protocol Flow

```
┌──────── Alice ────────┐              ┌──────── Bob ────────┐
│                        │              │                      │
│  d ← random(32 bytes)  │              │                      │
│  (ρ,σ) = G(d)          │              │                      │
│  A = Sam(ρ)            │              │                      │
│  s = CBD_η₁(σ,0..k-1)  │              │                      │
│  e = CBD_η₁(σ,k..2k-1) │              │                      │
│  t = NTT(A)·NTT(s) + e │              │                      │
│                        │              │                      │
│  pk = (ρ, Encode(t))   │──── pk ────→│                      │
│  sk = (s, pk, H(pk), z)│              │  m ← random(32)     │
│                        │              │  (K̄,r) = G(m‖H(pk)) │
│                        │              │  r = CBD_η₁(r,...)    │
│                        │              │  e₁= CBD_η₂(r,...)   │
│                        │              │  e₂= CBD_η₂(r,...)   │
│                        │              │  u = NTT⁻¹(Aᵀ·r)+e₁ │
│                        │              │  v = NTT⁻¹(tᵀ·r)+e₂ │
│                        │              │      + Decompress(m) │
│                        │              │  ct=(Compress(u,v))  │
│                        │←── ct ──────│  ss = KDF(K̄‖H(ct))  │
│                        │              │                      │
│  m' = Decode(v-sᵀ·u)   │              │                      │
│  (K̄',r') = G(m'‖H(pk)) │              │                      │
│  re-encrypt → ct'       │              │                      │
│  if ct'=ct:             │              │                      │
│    ss = KDF(K̄'‖H(ct))  │              │                      │
│  else:                  │              │                      │
│    ss = KDF(z‖H(ct))   │              │                      │
│                        │              │                      │
│  ✅ ss = ss             │              │  ✅ ss = ss          │
└────────────────────────┘              └──────────────────────┘
```

---

## 11. Parameter Summary

| Parameter | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
|-----------|-----------|-----------|------------|
| Security Level | NIST 1 | NIST 3 | NIST 5 |
| k (dimension) | 2 | 3 | 4 |
| q (modulus) | 3329 | 3329 | 3329 |
| n (poly degree) | 256 | 256 | 256 |
| η₁ (secret noise) | 3 | 2 | 2 |
| η₂ (ciphertext noise) | 2 | 2 | 2 |
| d_u (compress u) | 10 | 10 | 11 |
| d_v (compress v) | 4 | 4 | 5 |
| Public key | 800 B | 1184 B | 1568 B |
| Secret key | 1632 B | 2400 B | 3168 B |
| Ciphertext | 768 B | 1088 B | 1568 B |
| Shared secret | 32 B | 32 B | 32 B |
| Failure prob. | 2⁻¹³⁹ | 2⁻¹⁶⁴ | 2⁻¹⁷⁴ |

---

## 12. Mapping to Our Code

| Math Concept | Code Location | Key Function |
|-------------|---------------|-------------|
| R_q polynomial | `poly.rs` → `Poly` | `coeffs: [i16; 256]` |
| Vector of polynomials | `polyvec.rs` → `PolyVec` | `vec: Vec<Poly>` |
| NTT / INTT | `ntt.rs`, `ntt_simd.rs` | `ntt()`, `invntt()` |
| CBD sampling | `cbd.rs` | `cbd_eta()` |
| Matrix generation | `indcpa.rs` | `gen_matrix()` |
| Compress / Decompress | `poly.rs` | `compress()`, `decompress()` |
| IND-CPA encrypt/decrypt | `indcpa.rs` | `enc()`, `dec()` |
| FO transform (KEM) | `kem.rs` | `encaps_derand()`, `decaps()` |
| Safe typed API | `safe_api.rs` | `MlKemKeyPair`, `MlKemError` |
| Barrett/Montgomery | `reduce.rs` | `barrett_reduce()`, `fqmul()` |
| Constant-time compare | `verify.rs` | `verify()`, `cmov()` |

---

## Further Reading

- [FIPS 203 (ML-KEM) Standard](https://csrc.nist.gov/pubs/fips/203/final)
- [CRYSTALS-Kyber Paper](https://pq-crystals.org/kyber/)
- [Lattice-Based Cryptography for Beginners](https://eprint.iacr.org/2015/938)
