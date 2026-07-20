//! SHAKE / SHA3 symmetric primitives for Kyber.

use shake::digest::{ExtendableOutput, Update, XofReader};
use shake::{Shake128, Shake256};

/// SHA3-256 hash.
pub fn hash_h(out: &mut [u8; 32], input: &[u8]) {
    use sha3::Digest;
    let result = sha3::Sha3_256::digest(input);
    out.copy_from_slice(&result);
}

/// SHA3-512 hash (hash_g).
pub fn hash_g(out: &mut [u8; 64], input: &[u8]) {
    use sha3::Digest;
    let result = sha3::Sha3_512::digest(input);
    out.copy_from_slice(&result);
}

/// SHAKE-256: absorb input, squeeze output.
pub fn shake256(out: &mut [u8], input: &[u8]) {
    let mut h = Shake256::default();
    h.update(input);
    let mut reader = h.finalize_xof();
    reader.read(out);
}

/// PRF: SHAKE-256(key || nonce).
pub fn prf(out: &mut [u8], key: &[u8; 32], nonce: u8) {
    let mut h = Shake256::default();
    h.update(key);
    h.update(&[nonce]);
    let mut reader = h.finalize_xof();
    reader.read(out);
}

/// RKPRF: SHAKE-256(key || ct) for implicit rejection.
pub fn rkprf(out: &mut [u8; 32], key: &[u8], ct: &[u8]) {
    let mut h = Shake256::default();
    h.update(key);
    h.update(ct);
    let mut reader = h.finalize_xof();
    reader.read(out);
}

/// XOF state for matrix generation.
pub struct XofState {
    reader: <Shake128 as ExtendableOutput>::Reader,
}

impl XofState {
    /// Absorb seed || i || j for matrix generation.
    pub fn absorb(seed: &[u8; 32], i: u8, j: u8) -> Self {
        let mut h = Shake128::default();
        h.update(seed);
        h.update(&[i, j]);
        Self {
            reader: h.finalize_xof(),
        }
    }

    /// Squeeze bytes.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        self.reader.read(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shake256_empty_known_answer() {
        // NIST SHAKE256("") — first 32 output bytes.
        let mut out = [0u8; 32];
        shake256(&mut out, b"");
        let expected: [u8; 32] = [
            0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13, 0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e,
            0xeb, 0x24, 0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82, 0xb5, 0x0c, 0x27, 0x64,
            0x6e, 0xd5, 0x76, 0x2f,
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn hash_h_and_g_lengths_and_determinism() {
        let mut h = [0u8; 32];
        hash_h(&mut h, b"abc");
        let mut h2 = [0u8; 32];
        hash_h(&mut h2, b"abc");
        assert_eq!(h, h2);

        let mut g = [0u8; 64];
        hash_g(&mut g, b"abc");
        // G and H over the same input must differ (SHA3-512 vs SHA3-256).
        assert_ne!(&g[..32], &h[..]);
    }

    #[test]
    fn prf_and_rkprf_depend_on_all_inputs() {
        let key = [3u8; 32];
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        prf(&mut a, &key, 0);
        prf(&mut b, &key, 1);
        assert_ne!(a, b, "prf must depend on nonce");

        let mut r0 = [0u8; 32];
        let mut r1 = [0u8; 32];
        rkprf(&mut r0, &key, b"ct-one");
        rkprf(&mut r1, &key, b"ct-two");
        assert_ne!(r0, r1, "rkprf must depend on ciphertext");
    }
}
