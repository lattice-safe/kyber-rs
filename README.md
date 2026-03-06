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

## Quick Start

```rust
use kyber::{kem, params::ML_KEM_768};

fn main() {
    // Generate a key pair (use real entropy in production!)
    let coins = [0u8; 64];
    let (pk, sk) = kem::keypair_derand(ML_KEM_768, &coins);

    // Encapsulate
    let enc_coins = [1u8; 32];
    let (ct, ss_enc) = kem::encaps_derand(ML_KEM_768, &pk, &enc_coins);

    // Decapsulate
    let ss_dec = kem::decaps(ML_KEM_768, &ct, &sk);
    assert_eq!(ss_enc, ss_dec);
}
```

## Security Levels

| Mode | NIST Level | K | Public Key | Secret Key | Ciphertext | Shared Secret |
|------|-----------|---|-----------|-----------|-----------|--------------|
| ML-KEM-512 | 1 | 2 | 800 B | 1632 B | 768 B | 32 B |
| ML-KEM-768 | 3 | 3 | 1184 B | 2400 B | 1088 B | 32 B |
| ML-KEM-1024 | 5 | 4 | 1568 B | 3168 B | 1568 B | 32 B |

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

## License

MIT
