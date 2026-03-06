# kyber-rs

Pure Rust implementation of **ML-KEM (FIPS 203)** / **CRYSTALS-Kyber** — a post-quantum key encapsulation mechanism.

Part of the [lattice-safe](https://github.com/lattice-safe) cryptographic suite.

## Features

- ✅ **FIPS 203 compliant** — ML-KEM-512, ML-KEM-768, ML-KEM-1024
- ✅ **Pure Rust** — no C dependencies, no unsafe code
- ✅ **`no_std` compatible** — works on embedded and WASM targets
- ✅ **Bit-for-bit parity** — keygen/encaps match C reference ([pq-crystals/kyber](https://github.com/pq-crystals/kyber))
- ✅ **Constant-time decapsulation** — implicit rejection via SHAKE-256(z || ct)
- ✅ **Zeroize** — key material is zeroized after use
- ✅ **1.4–1.8× faster than C reference** — see benchmarks below

## Quick Start

```toml
[dependencies]
lattice-kyber = "0.1"
```

```rust
use kyber::{kem, params::ML_KEM_768};

// Generate key pair (use real entropy in production!)
let coins = [0u8; 64];
let (pk, sk) = kem::keypair_derand(ML_KEM_768, &coins);

// Encapsulate — sender gets ciphertext + shared secret
let enc_coins = [1u8; 32];
let (ct, ss_sender) = kem::encaps_derand(ML_KEM_768, &pk, &enc_coins);

// Decapsulate — receiver recovers the same shared secret
let ss_receiver = kem::decaps(ML_KEM_768, &ct, &sk);
assert_eq!(ss_sender, ss_receiver);
```

## Security Levels

| Mode | NIST Level | K | Public Key | Secret Key | Ciphertext | Shared Secret |
|------|-----------|---|-----------|-----------|-----------|--------------|
| ML-KEM-512 | 1 | 2 | 800 B | 1632 B | 768 B | 32 B |
| ML-KEM-768 | 3 | 3 | 1184 B | 2400 B | 1088 B | 32 B |
| ML-KEM-1024 | 5 | 4 | 1568 B | 3168 B | 1568 B | 32 B |

## Benchmarks

Apple M-series, `cargo bench` (Criterion) vs C reference (`-O3`):

| Operation | Rust (µs) | C ref (µs) | Ratio |
|-----------|----------|-----------|-------|
| **ML-KEM-512** | | | |
| keygen | 11.2 | 17.6 | **1.57×** |
| encaps | 12.7 | 20.5 | **1.62×** |
| decaps | 14.4 | 27.6 | **1.91×** |
| **ML-KEM-768** | | | |
| keygen | 18.9 | 28.3 | **1.50×** |
| encaps | 21.1 | 33.7 | **1.60×** |
| decaps | 23.5 | 45.8 | **1.95×** |
| **ML-KEM-1024** | | | |
| keygen | 30.2 | 42.7 | **1.41×** |
| encaps | 33.5 | 49.9 | **1.49×** |
| decaps | 36.2 | 64.5 | **1.78×** |

## Module Structure

| Module | Description |
|--------|-------------|
| `params` | Parameter sets and size calculations |
| `ntt` | Number-theoretic transform (q=3329, N=256) |
| `reduce` | Montgomery and Barrett reduction |
| `cbd` | Centered binomial distribution sampling |
| `poly` | Polynomial operations (NTT, compress, serialize) |
| `polyvec` | Vector of polynomials |
| `indcpa` | IND-CPA public-key encryption |
| `kem` | CCA-secure KEM (Fujisaki-Okamoto transform) |
| `symmetric` | SHAKE128/256, SHA3-256/512 wrappers |
| `verify` | Constant-time comparison |

## Examples

```bash
cargo run --example keygen_encaps   # Key generation + encapsulation demo
cargo run --example serialize       # Alice-Bob key exchange flow
```

## Fuzzing

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run fuzz_kem_roundtrip   # KEM correctness
cargo +nightly fuzz run fuzz_decaps          # Invalid ciphertext handling
cargo +nightly fuzz run fuzz_poly_deserialize # Serialization robustness
```

## License

MIT
