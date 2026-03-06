//! Constant-time comparison and conditional move.

/// Compare two byte slices in constant time. Returns 0 if equal, 1 otherwise.
pub fn verify(a: &[u8], b: &[u8]) -> u8 {
    debug_assert_eq!(a.len(), b.len());
    let mut r: u8 = 0;
    for i in 0..a.len() {
        r |= a[i] ^ b[i];
    }
    // Map nonzero to 1
    let r64 = (-(r as i64)) as u64;
    (r64 >> 63) as u8
}

/// Conditional move: copy x into r if b == 1, no-op if b == 0.
/// Constant time.
pub fn cmov(r: &mut [u8], x: &[u8], b: u8) {
    debug_assert!(b <= 1);
    let mask = (-(b as i8)) as u8; // 0x00 or 0xFF
    for i in 0..r.len() {
        r[i] ^= mask & (r[i] ^ x[i]);
    }
}
