# Changelog

All notable changes to this project will be documented in this file.

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
