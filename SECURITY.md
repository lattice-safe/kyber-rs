# Security Policy

## Supported Versions

| Version | Supported          |
|---------|-------------------|
| 0.1.x   | ✅ Current          |

## Reporting a Vulnerability

If you discover a security vulnerability, **please do not use public issues**.

**Email**: latticesafe@gmail.com

Please include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a detailed response
within 7 days.

## Security Properties

This crate implements ML-KEM (FIPS 203) with the following security measures:

- **Constant-time decapsulation** — implicit rejection via SHAKE-256(z || ct) prevents chosen-ciphertext attacks
- **Zeroization** — secret key material (`Poly`, `PolyVec`, `MlKemKeyPair`, `MlKemSharedSecret`) is zeroized on drop via the `zeroize` crate
- **`forbid(unsafe_code)`** — enforced when the `simd` feature is disabled; no unsafe code in scalar paths
- **Barrett & Montgomery reduction** — side-channel resistant modular arithmetic
- **Bit-for-bit parity** with the [pq-crystals/kyber](https://github.com/pq-crystals/kyber) C reference
- **KAT cross-validation** — 100 iterations × 3 security levels verified against C reference golden hashes

## Caveats — What This Crate Does NOT Provide

> **⚠️ This crate has not been independently audited or certified.**

- **No FIPS 140-3 / CMVP certification** — this is a research-quality implementation, not a certified cryptographic module
- **No formal verification** — the implementation has not been subjected to formal methods analysis
- **Limited side-channel hardening** — while core operations use constant-time primitives (`subtle` crate), the SIMD paths (`ntt_simd.rs`) use `unsafe` and platform-specific intrinsics that have not been independently verified for timing leakage
- **No hardware isolation** — this is a software-only implementation with no TEE/enclave boundaries

## SIMD & `unsafe` Usage

When the `simd` feature is enabled, `ntt_simd.rs` contains `unsafe` blocks for:
- **AVX2 (x86_64)**: SIMD intrinsics for vectorized NTT butterflies and Montgomery reduction
- **NEON (aarch64)**: SIMD intrinsics for vectorized NTT butterflies

All `unsafe` usage is confined to `ntt_simd.rs` and is gated behind `#[cfg(feature = "simd")]`. The scalar fallback path contains zero `unsafe` code, enforced by `#![forbid(unsafe_code)]`.

## Dependency Audit

| Crate | Version | Purpose | Audit Status |
|-------|---------|---------|-------------|
| `sha3` | 0.10 | SHAKE/SHA3 primitives | RustCrypto — widely reviewed |
| `subtle` | 2 | Constant-time operations | RustCrypto — widely reviewed |
| `zeroize` | 1 | Memory zeroization | RustCrypto — widely reviewed |
| `getrandom` | 0.2 | OS entropy (optional) | RustCrypto — widely reviewed |
| `serde` | 1 | Serialization (optional) | Widely reviewed |

## Scope

This policy covers the `lattice-kyber` crate published on [crates.io](https://crates.io/crates/lattice-kyber).
