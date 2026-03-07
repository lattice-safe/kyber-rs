//! High-level, safe API wrappers for ML-KEM.
//!
//! Provides typed structs with automatic zeroization and optional serde support.

use crate::kem;
use crate::params::{KyberMode, SSBYTES};
use alloc::vec::Vec;
use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Errors that can occur during ML-KEM operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MlKemError {
    /// Public key has incorrect length for the given mode.
    InvalidPublicKeyLength { expected: usize, actual: usize },
    /// Secret key has incorrect length for the given mode.
    InvalidSecretKeyLength { expected: usize, actual: usize },
    /// Ciphertext has incorrect length for the given mode.
    InvalidCiphertextLength { expected: usize, actual: usize },
    /// Coins (entropy) has incorrect length.
    InvalidCoinsLength { expected: usize, actual: usize },
}

impl fmt::Display for MlKemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MlKemError::InvalidPublicKeyLength { expected, actual } => {
                write!(f, "invalid public key length: expected {expected}, got {actual}")
            }
            MlKemError::InvalidSecretKeyLength { expected, actual } => {
                write!(f, "invalid secret key length: expected {expected}, got {actual}")
            }
            MlKemError::InvalidCiphertextLength { expected, actual } => {
                write!(f, "invalid ciphertext length: expected {expected}, got {actual}")
            }
            MlKemError::InvalidCoinsLength { expected, actual } => {
                write!(f, "invalid coins length: expected {expected}, got {actual}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MlKemError {}

/// An ML-KEM key pair (public key + secret key).
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MlKemKeyPair {
    mode: KyberMode,
    pubkey: Vec<u8>,
    #[cfg_attr(feature = "serde", serde(with = "serde_zeroizing"))]
    seckey: zeroize::Zeroizing<Vec<u8>>,
}

impl Zeroize for MlKemKeyPair {
    fn zeroize(&mut self) {
        self.pubkey.zeroize();
        self.seckey.zeroize();
    }
}

impl Drop for MlKemKeyPair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl MlKemKeyPair {
    /// Generate a key pair deterministically from 64 bytes of coins.
    pub fn generate_derand(mode: KyberMode, coins: &[u8; 64]) -> Self {
        let (pk, sk) = kem::keypair_derand(mode, coins);
        Self {
            mode,
            pubkey: pk,
            seckey: zeroize::Zeroizing::new(sk),
        }
    }

    /// Generate a key pair using OS entropy.
    #[cfg(feature = "getrandom")]
    pub fn generate(mode: KyberMode) -> Result<Self, MlKemError> {
        let mut coins = [0u8; 64];
        getrandom::getrandom(&mut coins)
            .map_err(|_| MlKemError::InvalidCoinsLength { expected: 64, actual: 0 })?;
        let kp = Self::generate_derand(mode, &coins);
        coins.zeroize();
        Ok(kp)
    }

    /// The security mode of this key pair.
    pub fn mode(&self) -> KyberMode {
        self.mode
    }

    /// Public key bytes.
    pub fn public_key(&self) -> &[u8] {
        &self.pubkey
    }

    /// Secret key bytes.
    pub fn secret_key(&self) -> &[u8] {
        &self.seckey
    }

    /// Decapsulate a ciphertext to recover the shared secret.
    pub fn decaps(&self, ct: &MlKemCiphertext) -> Result<MlKemSharedSecret, MlKemError> {
        if ct.data.len() != self.mode.ciphertext_bytes() {
            return Err(MlKemError::InvalidCiphertextLength {
                expected: self.mode.ciphertext_bytes(),
                actual: ct.data.len(),
            });
        }
        let ss = kem::decaps(self.mode, &ct.data, &self.seckey);
        Ok(MlKemSharedSecret { data: ss })
    }
}

/// An ML-KEM ciphertext.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MlKemCiphertext {
    data: Vec<u8>,
}

impl MlKemCiphertext {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { data: bytes }
    }

    /// Ciphertext bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// An ML-KEM shared secret (32 bytes), zeroized on drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct MlKemSharedSecret {
    data: [u8; SSBYTES],
}

impl MlKemSharedSecret {
    /// Shared secret bytes.
    pub fn as_bytes(&self) -> &[u8; SSBYTES] {
        &self.data
    }
}

/// Encapsulate: generate a shared secret and ciphertext for a given public key.
pub fn encaps_derand(
    mode: KyberMode,
    pk: &[u8],
    coins: &[u8; 32],
) -> Result<(MlKemCiphertext, MlKemSharedSecret), MlKemError> {
    if pk.len() != mode.public_key_bytes() {
        return Err(MlKemError::InvalidPublicKeyLength {
            expected: mode.public_key_bytes(),
            actual: pk.len(),
        });
    }
    let (ct, ss) = kem::encaps_derand(mode, pk, coins);
    Ok((
        MlKemCiphertext { data: ct },
        MlKemSharedSecret { data: ss },
    ))
}

/// Encapsulate using OS entropy.
#[cfg(feature = "getrandom")]
pub fn encaps(
    mode: KyberMode,
    pk: &[u8],
) -> Result<(MlKemCiphertext, MlKemSharedSecret), MlKemError> {
    let mut coins = [0u8; 32];
    getrandom::getrandom(&mut coins)
        .map_err(|_| MlKemError::InvalidCoinsLength { expected: 32, actual: 0 })?;
    let result = encaps_derand(mode, pk, &coins);
    coins.zeroize();
    result
}

// Serde helper for Zeroizing<Vec<u8>>
#[cfg(feature = "serde")]
mod serde_zeroizing {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use zeroize::Zeroizing;

    pub fn serialize<S: Serializer>(val: &Zeroizing<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        let bytes: &Vec<u8> = val;
        bytes.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<Vec<u8>>, D::Error> {
        let v = Vec::<u8>::deserialize(d)?;
        Ok(Zeroizing::new(v))
    }
}
