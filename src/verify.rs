//! Constant-time comparison and conditional move.

/// Compare two byte slices in constant time. Returns 0 if equal, 1 otherwise.
///
/// A length mismatch is treated as "not equal" (returns 1) rather than
/// panicking or reading out of bounds. For equal-length inputs — the only
/// case Kyber decapsulation exercises — the comparison is constant time in
/// the byte contents.
pub fn verify(a: &[u8], b: &[u8]) -> u8 {
    if a.len() != b.len() {
        return 1;
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_equal_returns_zero() {
        assert_eq!(verify(b"hello world", b"hello world"), 0);
    }

    #[test]
    fn verify_different_returns_one() {
        assert_eq!(verify(b"hello world", b"hello xorld"), 1);
    }

    #[test]
    fn verify_length_mismatch_returns_one() {
        // Must not panic or read out of bounds; a length mismatch is "not equal".
        assert_eq!(verify(b"short", b"longer input"), 1);
        assert_eq!(verify(b"", b"x"), 1);
    }

    #[test]
    fn cmov_copies_only_when_flag_set() {
        let mut r = [1u8, 2, 3, 4];
        let x = [9u8, 9, 9, 9];
        cmov(&mut r, &x, 0);
        assert_eq!(r, [1, 2, 3, 4], "b=0 must be a no-op");
        cmov(&mut r, &x, 1);
        assert_eq!(r, [9, 9, 9, 9], "b=1 must copy x into r");
    }
}
