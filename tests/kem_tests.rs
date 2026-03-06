use kyber::kem::{decaps, encaps_derand, keypair_derand};
use kyber::params::KyberMode;

fn test_kem_roundtrip(mode: KyberMode) {
    let coins = [0u8; 64];
    let (pk, sk) = keypair_derand(mode, &coins);
    assert_eq!(pk.len(), mode.public_key_bytes());
    assert_eq!(sk.len(), mode.secret_key_bytes());

    let enc_coins = [1u8; 32];
    let (ct, ss_enc) = encaps_derand(mode, &pk, &enc_coins);
    assert_eq!(ct.len(), mode.ciphertext_bytes());

    let ss_dec = decaps(mode, &ct, &sk);
    assert_eq!(ss_enc, ss_dec);
}

#[test]
fn test_kyber512_roundtrip() {
    test_kem_roundtrip(kyber::ML_KEM_512);
}

#[test]
fn test_kyber768_roundtrip() {
    test_kem_roundtrip(kyber::ML_KEM_768);
}

#[test]
fn test_kyber1024_roundtrip() {
    test_kem_roundtrip(kyber::ML_KEM_1024);
}

#[test]
fn test_kyber768_different_coins() {
    let coins = [42u8; 64];
    let (pk, sk) = keypair_derand(kyber::ML_KEM_768, &coins);

    for nonce in 0..10u8 {
        let mut enc_coins = [0u8; 32];
        enc_coins[0] = nonce;
        let (ct, ss_enc) = encaps_derand(kyber::ML_KEM_768, &pk, &enc_coins);
        let ss_dec = decaps(kyber::ML_KEM_768, &ct, &sk);
        assert_eq!(ss_enc, ss_dec, "failed at nonce {}", nonce);
    }
}

#[test]
fn test_wrong_sk_gives_different_ss() {
    let mode = kyber::ML_KEM_768;
    let (pk, _sk) = keypair_derand(mode, &[0u8; 64]);
    let (_, sk2) = keypair_derand(mode, &[1u8; 64]);

    let (ct, ss_enc) = encaps_derand(mode, &pk, &[2u8; 32]);
    let ss_dec = decaps(mode, &ct, &sk2);
    assert_ne!(ss_enc, ss_dec);
}
