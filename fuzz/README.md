# Fuzzing Targets for kyber-rs

This directory contains fuzz targets for the ML-KEM implementation.

## Requirements

```bash
cargo install cargo-fuzz
```

## Running

```bash
# Fuzz the KEM roundtrip
cargo +nightly fuzz run fuzz_kem_roundtrip

# Fuzz decapsulation with arbitrary ciphertexts
cargo +nightly fuzz run fuzz_decaps

# Fuzz polynomial deserialization
cargo +nightly fuzz run fuzz_poly_deserialize
```
