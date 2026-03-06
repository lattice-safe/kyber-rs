# Changelog

All notable changes to this project will be documented in this file.

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
