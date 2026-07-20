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
    /// Public key failed the FIPS 203 modulus check (a coefficient was >= q).
    ///
    /// Per FIPS 203 §7.2, an encapsulation key must decode to coefficients in
    /// `[0, q)`; a malformed key that re-encodes to a different byte string is
    /// rejected here.
    InvalidPublicKey,
    /// The OS random number generator failed to produce entropy.
    RandomnessFailure,
}

impl fmt::Display for MlKemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MlKemError::InvalidPublicKeyLength { expected, actual } => {
                write!(
                    f,
                    "invalid public key length: expected {expected}, got {actual}"
                )
            }
            MlKemError::InvalidSecretKeyLength { expected, actual } => {
                write!(
                    f,
                    "invalid secret key length: expected {expected}, got {actual}"
                )
            }
            MlKemError::InvalidCiphertextLength { expected, actual } => {
                write!(
                    f,
                    "invalid ciphertext length: expected {expected}, got {actual}"
                )
            }
            MlKemError::InvalidCoinsLength { expected, actual } => {
                write!(f, "invalid coins length: expected {expected}, got {actual}")
            }
            MlKemError::InvalidPublicKey => {
                write!(
                    f,
                    "public key failed FIPS 203 modulus check (coefficient >= q)"
                )
            }
            MlKemError::RandomnessFailure => {
                write!(f, "system random number generator failed")
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
        getrandom::fill(&mut coins).map_err(|_| MlKemError::RandomnessFailure)?;
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
    // FIPS 203 §7.2 modulus check: every packed 12-bit coefficient of the
    // encapsulation key must be a valid residue in [0, q). This rejects
    // malformed keys whose ByteEncode12 would not round-trip.
    if !public_key_coeffs_in_range(pk, mode) {
        return Err(MlKemError::InvalidPublicKey);
    }
    let (ct, ss) = kem::encaps_derand(mode, pk, coins);
    Ok((MlKemCiphertext { data: ct }, MlKemSharedSecret { data: ss }))
}

/// FIPS 203 §7.2 modulus check on the polyvec portion of an encapsulation key.
///
/// The `mode.polyvec_bytes()`-byte prefix of `pk` packs `k * N` coefficients,
/// 12 bits each. Each decoded value must be a valid residue in `[0, q)`.
/// Returns `true` when every coefficient is in range.
fn public_key_coeffs_in_range(pk: &[u8], mode: KyberMode) -> bool {
    use crate::params::Q;
    let q = Q as u16;
    let pv = &pk[..mode.polyvec_bytes()];
    // 3 bytes encode two 12-bit coefficients.
    for chunk in pv.chunks_exact(3) {
        let c0 = (u16::from(chunk[0]) | (u16::from(chunk[1]) << 8)) & 0x0FFF;
        let c1 = ((u16::from(chunk[1]) >> 4) | (u16::from(chunk[2]) << 4)) & 0x0FFF;
        if c0 >= q || c1 >= q {
            return false;
        }
    }
    true
}

/// Encapsulate using OS entropy.
#[cfg(feature = "getrandom")]
pub fn encaps(
    mode: KyberMode,
    pk: &[u8],
) -> Result<(MlKemCiphertext, MlKemSharedSecret), MlKemError> {
    let mut coins = [0u8; 32];
    getrandom::fill(&mut coins).map_err(|_| MlKemError::RandomnessFailure)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::ML_KEM_768;

    #[test]
    fn accessors_report_correct_metadata() {
        let kp = MlKemKeyPair::generate_derand(ML_KEM_768, &[1u8; 64]);
        assert_eq!(kp.mode(), ML_KEM_768);
        assert_eq!(kp.public_key().len(), ML_KEM_768.public_key_bytes());
        assert_eq!(kp.secret_key().len(), ML_KEM_768.secret_key_bytes());

        let (ct, ss) = encaps_derand(ML_KEM_768, kp.public_key(), &[2u8; 32]).unwrap();
        assert_eq!(ct.as_bytes().len(), ML_KEM_768.ciphertext_bytes());
        assert_eq!(ss.as_bytes().len(), SSBYTES);

        // Ciphertext round-trips through raw bytes.
        let ct2 = MlKemCiphertext::from_bytes(ct.as_bytes().to_vec());
        assert_eq!(ct.as_bytes(), ct2.as_bytes());
    }

    #[test]
    fn cloned_keypair_decapsulates_identically() {
        let kp = MlKemKeyPair::generate_derand(ML_KEM_768, &[4u8; 64]);
        let kp2 = kp.clone();
        let (ct, _) = encaps_derand(ML_KEM_768, kp.public_key(), &[5u8; 32]).unwrap();
        assert_eq!(
            kp.decaps(&ct).unwrap().as_bytes(),
            kp2.decaps(&ct).unwrap().as_bytes()
        );
    }

    #[test]
    fn zeroize_wipes_key_material() {
        let mut kp = MlKemKeyPair::generate_derand(ML_KEM_768, &[6u8; 64]);
        kp.zeroize();
        assert!(kp.public_key().iter().all(|&b| b == 0));
        assert!(kp.secret_key().iter().all(|&b| b == 0));
    }

    #[test]
    fn error_display_is_informative() {
        let cases = [
            MlKemError::InvalidPublicKeyLength {
                expected: 1184,
                actual: 10,
            },
            MlKemError::InvalidSecretKeyLength {
                expected: 2400,
                actual: 10,
            },
            MlKemError::InvalidCiphertextLength {
                expected: 1088,
                actual: 10,
            },
            MlKemError::InvalidCoinsLength {
                expected: 32,
                actual: 0,
            },
            MlKemError::InvalidPublicKey,
            MlKemError::RandomnessFailure,
        ];
        for e in &cases {
            let s = alloc::format!("{e}");
            assert!(!s.is_empty());
        }
        // A couple of specific messages.
        assert!(alloc::format!("{}", MlKemError::InvalidPublicKey).contains("modulus check"));
        assert!(alloc::format!("{}", MlKemError::RandomnessFailure).contains("random"));
    }

    #[cfg(feature = "getrandom")]
    #[test]
    fn os_entropy_generate_and_encaps_roundtrip() {
        let kp = MlKemKeyPair::generate(ML_KEM_768).unwrap();
        let (ct, ss_enc) = encaps(ML_KEM_768, kp.public_key()).unwrap();
        let ss_dec = kp.decaps(&ct).unwrap();
        assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_roundtrip_preserves_keypair() {
        let kp = MlKemKeyPair::generate_derand(ML_KEM_768, &[8u8; 64]);
        let json = serde_json::to_string(&kp).unwrap();
        let restored: MlKemKeyPair = serde_json::from_str(&json).unwrap();

        assert_eq!(kp.mode(), restored.mode());
        assert_eq!(kp.public_key(), restored.public_key());
        assert_eq!(kp.secret_key(), restored.secret_key());

        // The restored key still works end to end.
        let (ct, ss_enc) = encaps_derand(ML_KEM_768, restored.public_key(), &[1u8; 32]).unwrap();
        assert_eq!(ss_enc.as_bytes(), restored.decaps(&ct).unwrap().as_bytes());
    }
}
