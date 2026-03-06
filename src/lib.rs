//! Pure Rust implementation of ML-KEM (FIPS 203) / CRYSTALS-Kyber.
//!
//! A post-quantum key encapsulation mechanism standardized as FIPS 203.
//! Supports all three security levels: ML-KEM-512, ML-KEM-768, ML-KEM-1024.
//!
//! # Features
//!
//! - **FIPS 203 compliant** — ML-KEM key encapsulation
//! - **`no_std` compatible** — works on embedded and WASM targets
//! - **Zeroize** — key material is zeroized after use
//! - **Constant-time** — decapsulation uses constant-time comparison
//!
//! # Quick Start
//!
//! ```rust
//! use kyber::{kem, params::ML_KEM_768};
//!
//! // Generate a key pair
//! let coins = [0u8; 64]; // use real entropy in production!
//! let (pk, sk) = kem::keypair_derand(ML_KEM_768, &coins);
//!
//! // Encapsulate
//! let enc_coins = [1u8; 32];
//! let (ct, ss_enc) = kem::encaps_derand(ML_KEM_768, &pk, &enc_coins);
//!
//! // Decapsulate
//! let ss_dec = kem::decaps(ML_KEM_768, &ct, &sk);
//! assert_eq!(ss_enc, ss_dec);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod cbd;
pub mod indcpa;
pub mod kem;
pub mod ntt;
pub mod params;
pub mod poly;
pub mod polyvec;
pub mod reduce;
pub mod symmetric;
pub mod verify;

pub use params::{KyberMode, ML_KEM_1024, ML_KEM_512, ML_KEM_768};
