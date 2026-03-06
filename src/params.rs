//! ML-KEM / Kyber parameter sets (FIPS 203).

/// Polynomial ring degree.
pub const N: usize = 256;

/// Modulus.
pub const Q: i16 = 3329;

/// Q as i32 for arithmetic.
pub const Q32: i32 = 3329;

/// Montgomery constant: Q^{-1} mod 2^16.
pub const QINV: i32 = -3327; // q^(-1) mod 2^16

/// Symbol bytes (hash/seed length).
pub const SYMBYTES: usize = 32;

/// Shared secret bytes.
pub const SSBYTES: usize = 32;

/// Packed polynomial bytes (12 bits per coefficient).
pub const POLYBYTES: usize = 384;

/// ML-KEM security levels (FIPS 203).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum KyberMode {
    /// ML-KEM-512 (NIST Level 1): K=2
    Kyber512,
    /// ML-KEM-768 (NIST Level 3): K=3
    Kyber768,
    /// ML-KEM-1024 (NIST Level 5): K=4
    Kyber1024,
}

/// FIPS 203 aliases.
pub const ML_KEM_512: KyberMode = KyberMode::Kyber512;
pub const ML_KEM_768: KyberMode = KyberMode::Kyber768;
pub const ML_KEM_1024: KyberMode = KyberMode::Kyber1024;

impl KyberMode {
    /// Number of vectors (K parameter).
    #[inline]
    #[must_use]
    pub const fn k(self) -> usize {
        match self {
            Self::Kyber512 => 2,
            Self::Kyber768 => 3,
            Self::Kyber1024 => 4,
        }
    }

    /// ETA1: secret/error noise parameter.
    #[inline]
    #[must_use]
    pub const fn eta1(self) -> usize {
        match self {
            Self::Kyber512 => 3,
            Self::Kyber768 | Self::Kyber1024 => 2,
        }
    }

    /// ETA2: encryption noise parameter (always 2).
    #[inline]
    #[must_use]
    pub const fn eta2(self) -> usize {
        2
    }

    /// Compressed polynomial bytes for ciphertext v.
    #[inline]
    #[must_use]
    pub const fn poly_compressed_bytes(self) -> usize {
        match self {
            Self::Kyber512 | Self::Kyber768 => 128,
            Self::Kyber1024 => 160,
        }
    }

    /// Compressed polyvec bytes for ciphertext b.
    #[inline]
    #[must_use]
    pub const fn polyvec_compressed_bytes(self) -> usize {
        match self {
            Self::Kyber512 | Self::Kyber768 => self.k() * 320,
            Self::Kyber1024 => self.k() * 352,
        }
    }

    /// Polyvec serialized bytes (uncompressed).
    #[inline]
    #[must_use]
    pub const fn polyvec_bytes(self) -> usize {
        self.k() * POLYBYTES
    }

    /// IND-CPA public key bytes.
    #[inline]
    #[must_use]
    pub const fn indcpa_publickey_bytes(self) -> usize {
        self.polyvec_bytes() + SYMBYTES
    }

    /// IND-CPA secret key bytes.
    #[inline]
    #[must_use]
    pub const fn indcpa_secretkey_bytes(self) -> usize {
        self.polyvec_bytes()
    }

    /// IND-CPA ciphertext bytes.
    #[inline]
    #[must_use]
    pub const fn indcpa_bytes(self) -> usize {
        self.polyvec_compressed_bytes() + self.poly_compressed_bytes()
    }

    /// Public key size.
    #[inline]
    #[must_use]
    pub const fn public_key_bytes(self) -> usize {
        self.indcpa_publickey_bytes()
    }

    /// Secret key size (CCA).
    #[inline]
    #[must_use]
    pub const fn secret_key_bytes(self) -> usize {
        self.indcpa_secretkey_bytes() + self.indcpa_publickey_bytes() + 2 * SYMBYTES
    }

    /// Ciphertext size.
    #[inline]
    #[must_use]
    pub const fn ciphertext_bytes(self) -> usize {
        self.indcpa_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyber512_sizes() {
        let m = KyberMode::Kyber512;
        assert_eq!(m.public_key_bytes(), 800);
        assert_eq!(m.secret_key_bytes(), 1632);
        assert_eq!(m.ciphertext_bytes(), 768);
    }

    #[test]
    fn test_kyber768_sizes() {
        let m = KyberMode::Kyber768;
        assert_eq!(m.public_key_bytes(), 1184);
        assert_eq!(m.secret_key_bytes(), 2400);
        assert_eq!(m.ciphertext_bytes(), 1088);
    }

    #[test]
    fn test_kyber1024_sizes() {
        let m = KyberMode::Kyber1024;
        assert_eq!(m.public_key_bytes(), 1568);
        assert_eq!(m.secret_key_bytes(), 3168);
        assert_eq!(m.ciphertext_bytes(), 1568);
    }
}
