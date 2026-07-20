//! Tests for the high-level safe API: input validation (FIPS 203 §7.2/§7.3
//! type and modulus checks) and Fujisaki–Okamoto robustness.

use kyber::params::ML_KEM_768;
use kyber::safe_api::{MlKemCiphertext, MlKemError, MlKemKeyPair, encaps_derand};

#[test]
fn roundtrip_via_safe_api() {
    let kp = MlKemKeyPair::generate_derand(ML_KEM_768, &[7u8; 64]);
    let (ct, ss_enc) = encaps_derand(ML_KEM_768, kp.public_key(), &[9u8; 32]).unwrap();
    let ss_dec = kp.decaps(&ct).unwrap();
    assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes());
}

#[test]
fn encaps_rejects_wrong_length_public_key() {
    let short = vec![0u8; ML_KEM_768.public_key_bytes() - 1];
    assert!(matches!(
        encaps_derand(ML_KEM_768, &short, &[0u8; 32]),
        Err(MlKemError::InvalidPublicKeyLength { .. })
    ));
}

#[test]
fn encaps_rejects_non_reduced_public_key() {
    // Correct length, but the packed coefficients are all 0xFFF = 4095 >= q,
    // so the FIPS 203 §7.2 modulus check must reject it.
    let mut pk = vec![0xFFu8; ML_KEM_768.public_key_bytes()];
    // Leave the 32-byte seed suffix arbitrary; only the polyvec prefix matters.
    for b in pk[ML_KEM_768.polyvec_bytes()..].iter_mut() {
        *b = 0;
    }
    assert!(matches!(
        encaps_derand(ML_KEM_768, &pk, &[0u8; 32]),
        Err(MlKemError::InvalidPublicKey)
    ));
}

#[test]
fn encaps_accepts_valid_public_key() {
    let kp = MlKemKeyPair::generate_derand(ML_KEM_768, &[3u8; 64]);
    assert!(encaps_derand(ML_KEM_768, kp.public_key(), &[0u8; 32]).is_ok());
}

#[test]
fn decaps_rejects_wrong_length_ciphertext() {
    let kp = MlKemKeyPair::generate_derand(ML_KEM_768, &[1u8; 64]);
    let bad = MlKemCiphertext::from_bytes(vec![0u8; ML_KEM_768.ciphertext_bytes() - 1]);
    assert!(matches!(
        kp.decaps(&bad),
        Err(MlKemError::InvalidCiphertextLength { .. })
    ));
}

#[test]
fn tampered_ciphertext_gives_rejection_secret_not_panic() {
    let kp = MlKemKeyPair::generate_derand(ML_KEM_768, &[5u8; 64]);
    let (ct, ss_enc) = encaps_derand(ML_KEM_768, kp.public_key(), &[6u8; 32]).unwrap();

    // Flip a byte: implicit rejection must yield a deterministic secret that
    // differs from the honest one, without panicking.
    let mut bytes = ct.as_bytes().to_vec();
    bytes[0] ^= 0xFF;
    let tampered = MlKemCiphertext::from_bytes(bytes);

    let ss_reject = kp.decaps(&tampered).unwrap();
    assert_ne!(ss_enc.as_bytes(), ss_reject.as_bytes());

    // Implicit rejection is deterministic in (z, ct): same tampered ct -> same ss.
    let ss_reject2 = kp.decaps(&tampered).unwrap();
    assert_eq!(ss_reject.as_bytes(), ss_reject2.as_bytes());
}
