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
    // Map nonzero to 1 by folding the set bits down to bit 0 — a pure
    // sequence of shifts and ORs with no comparison for LLVM to lower into a
    // data-dependent `cmp r, #0; beq`. The optimization barrier additionally
    // stops the accumulator's zero-ness from being recovered and branched on
    // when this function is inlined into `kem::decaps`. Without both, a
    // taken/not-taken branch would leak whether the FO re-encryption matched
    // the ciphertext — a plaintext-checking oracle on targets (thumbv6m,
    // M-less RISC-V) whose branches are not constant time.
    let mut r = core::hint::black_box(r);
    r |= r >> 4;
    r |= r >> 2;
    r |= r >> 1;
    r & 1
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
    fn verify_returns_one_for_any_single_bit_difference() {
        // Pins the nonzero-fold: a difference in any single bit of any byte
        // must map to exactly 1 (not just a nonzero value).
        for byte in 0..8usize {
            for bit in 0..8u32 {
                let mut a = [0u8; 8];
                let mut b = [0u8; 8];
                b[byte] = 1u8 << bit;
                assert_eq!(verify(&a, &b), 1, "byte {byte} bit {bit}");
                // And the symmetric case with a nonzero baseline.
                a = [0xAAu8; 8];
                b = [0xAAu8; 8];
                b[byte] ^= 1u8 << bit;
                assert_eq!(verify(&a, &b), 1, "baseline byte {byte} bit {bit}");
            }
        }
        assert_eq!(verify(&[0xFFu8; 8], &[0xFFu8; 8]), 0);
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
