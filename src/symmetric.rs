//! SHAKE / SHA3 symmetric primitives for Kyber.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};

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
