# Changelog

All notable changes to this project will be documented in this file.

## [0.2.2] — 2026-08-30

### Security
- **KyberSlash-class timing side-channel (CWE-208) in `Compress_d` on the decapsulation path.** `Poly::tomsg` (KyberSlash-1) and `Poly::compress` / `PolyVec::compress` (KyberSlash-2, via FO re-encryption) divided secret-dependent coefficients by q = 3329. On targets without a hardware divider (Cortex-M0/M0+ `thumbv6m`, RISC-V without the M extension) — and at `opt-level=0` on every target — LLVM lowers `/ 3329` to the variable-time software routine `__aeabi_uidiv` / `__udivsi3`, whose latency depends on the secret dividend. The divisions are replaced with the standard post-KyberSlash constant-time multiply-shift per d ∈ {1, 4, 5, 10, 11} (same values, verified exhaustively and by the KAT suite). Mainstream targets (x86-64, aarch64, thumbv7em, wasm32) at `--release` already compiled the constant divisor to a multiply-shift and were not affected. Reported by Patryk Gralewicz under coordinated disclosure; same class as RUSTSEC-2023-0079.
- **Secret-sign-dependent branch in the compress/tomsg "freeze" step on thumbv6m.** LLVM lowered the branchless mask `u += (u >> 15) & Q` into a compare-and-branch on the (secret) coefficient sign on targets without conditional select. The mask is now computed through an optimization barrier (`core::hint::black_box`) in `reduce::freeze`, verified branch-free in the emitted assembly.
- **Secret-dependent branch in the FO re-encryption check `verify::verify` on thumbv6m.** When inlined into `kem::decaps`, LLVM lowered the `-(r as i64) >> 63` nonzero-fold into a `cmp r, #0; beq` on the accumulated ciphertext difference — a taken/not-taken branch revealing whether the re-encryption matched the ciphertext, i.e. a plaintext-checking oracle (the exact signal implicit rejection is meant to hide). The fold is rewritten as a comparison-free shift/OR sequence behind a `black_box`; the emitted `decaps` now computes the fail bit with `lsrs`/`orrs`/`ands` and no branch on the difference. This was found during the same audit as the KyberSlash fix and is a distinct, arguably more serious instance of the same CWE-208 class.
- **Secret-sign-dependent branch in the secret-key serializer `Poly::tobytes`.** The `if (t as i16) < 0` conditional add-q ran on secret-key coefficients (16 + 8 branches on thumbv6m, in the key-generation path). Replaced with the branchless `reduce::freeze`.

### Added
- `scripts/check_thumbv6m_ct.sh` + CI job: emits `thumbv6m-none-eabi` assembly and fails if any secret-processing function contains a software-division call, and if any kyber function branches on the sign of a coefficient (a global `bpl`/`bmi` assertion that is robust to inlining, covering `tomsg`, `compress`, and `tobytes`).
- Exhaustive regression tests pinning `tomsg`/`compress` (all d values) to the division-based reference formula for every representative in (-q, q), `reduce::freeze` to `rem_euclid`, and `verify` returning exactly 1 for any single-bit difference.

## [0.2.1] — 2026-07-20

### Fixed
- **`simd` feature failed to compile on x86_64.** The AVX2 helpers combined `#[inline(always)]` with `#[target_feature]`, which is a hard error on stable Rust, and carried an inner `unsafe` block that is redundant inside a `#[target_feature]` function. (The bug was invisible on aarch64, where the AVX2 module is `#[cfg]`-compiled out.) Default builds were unaffected — only `--features simd` on x86_64.
- **CI dependency audit** — updated `deny.toml` to the cargo-deny ≥ 0.18 schema (the old one could not parse `edition = "2024"`) and bumped `cargo-deny-action` v1 → v2.

## [0.2.0] — 2026-07-20

### Changed
- **Upgraded to the current RustCrypto / rust-random primitive stack:**
  - `sha3` 0.10 → **0.12** (SHAKE128/256 moved to the new **`shake` 0.1** crate; SHA3-256/512 stay in `sha3`)
  - `getrandom` 0.2 → **0.4** (`getrandom::getrandom()` → `getrandom::fill()`)
  - `zeroize` now enabled via the `zeroize_derive` feature (the `derive` alias was removed upstream)
- **MSRV raised 1.70 → 1.85** and **edition 2021 → 2024** (required by the new `digest` 0.11 / `sha3` 0.12 stack). This is a breaking change for consumers on older toolchains.
- Removed the unused `subtle` dependency; constant-time comparison and conditional move remain implemented in-crate (`verify.rs`).
- The `simd` feature is now **wired into `Poly::ntt` / `Poly::invntt_tomont`** (previously the `ntt_simd` module was compiled but never used). The SIMD (AVX2/NEON) path is cross-validated end-to-end by the KAT suite under `--features simd`.

### Security
- **Zeroize secret intermediates** that previously lingered on the stack/heap: the decrypted message `m'` and derived `(K', r')` in `kem::decaps`, the message copy and `(K, r)` in `kem::encaps_derand`, the noise seed / G-buffer in `indcpa::keypair_derand`, the IND-CPA secret key after packing, and the PRF output in `Poly::getnoise`.
- **Added the FIPS 203 §7.2 modulus check** to `safe_api::encaps_derand`: an encapsulation key whose packed coefficients are not all in `[0, q)` is now rejected with `MlKemError::InvalidPublicKey`.
- `verify::verify` no longer relies on a `debug_assert` for length: a length mismatch is treated as "not equal" instead of risking an out-of-bounds read in release builds.

### Added
- `MlKemError::InvalidPublicKey` and `MlKemError::RandomnessFailure` variants.
- `tests/safe_api_tests.rs` — validation and Fujisaki–Okamoto robustness tests (wrong-length inputs, modulus check, deterministic implicit rejection).
- Edition-2024-correct `unsafe` blocks throughout `ntt_simd.rs` (explicit `unsafe {}` inside `unsafe fn`), with `# Safety` docs on each intrinsic wrapper.
- **Test coverage raised to ~99% lines / 99% regions** (`cargo llvm-cov --all-features`): unit tests for `symmetric` (SHAKE256 known-answer, PRF/rkprf), `verify` (constant-time compare incl. length mismatch, `cmov`), `cbd` (coefficient ranges + unsupported-eta panic), and `safe_api` (`Display` for every error, accessors, `Zeroize`, OS-entropy `generate`/`encaps`, and serde round-trip). The only uncovered code is genuinely unreachable (`unreachable!()` guards, the multiple-of-8 SIMD remainder loop, and OS-RNG-failure branches). Remaining gaps are covered on Linux CI via `cargo-tarpaulin` → Codecov.

## [0.1.2] — 2026-03-07

### Added
- `safe_api` module with typed wrappers: `MlKemKeyPair`, `MlKemCiphertext`, `MlKemSharedSecret`
- `MlKemError` type with `Display`/`Error` implementations
- `MlKemKeyPair::generate()` — randomized keygen via `getrandom`
- `safe_encaps()` / `safe_encaps_derand()` — validated encapsulation with length checks
- `Zeroize` / `ZeroizeOnDrop` on `Poly`, `PolyVec`, `MlKemKeyPair`, `MlKemSharedSecret`
- `#![forbid(unsafe_code)]` enforced when `simd` feature is disabled
- CI: MSRV (1.70) check, WASM build, `cargo-deny` dependency audit

### Changed
- Expanded `SECURITY.md` with caveats, `unsafe` disclosure, and dependency audit
- Updated README with Safe API examples and feature documentation

### Fixed
- All 26 clippy warnings (operator precedence, needless range loops, unused imports, etc.)
- Removed dead `hex_encode` function from KAT tests

## [0.1.1] — 2026-03-07

### Added
- MIT LICENSE file
- Criterion benchmarks for all 3 modes (keygen/encaps/decaps)
- 3 fuzzing targets (`fuzz_kem_roundtrip`, `fuzz_decaps`, `fuzz_poly_deserialize`)
- 2 examples (`keygen_encaps`, `serialize`)
- README benchmark comparison vs C reference (1.4–1.8× faster)

## [0.1.0] — 2026-03-07

### Added
- Initial release — pure Rust ML-KEM (FIPS 203) implementation
- ML-KEM-512, ML-KEM-768, ML-KEM-1024 support
- Bit-for-bit parity with C reference (`pq-crystals/kyber`)
- KAT cross-validation (100 iterations × 3 modes)
- Constant-time decapsulation with implicit rejection
- `no_std` compatible with `alloc`
- Optional `serde` and `getrandom` features
- 15 tests (6 unit + 5 integration + 3 KAT + 1 doctest)
