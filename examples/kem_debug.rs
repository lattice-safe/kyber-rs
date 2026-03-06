use kyber::{
    kem,
    params::{KyberMode, ML_KEM_1024, ML_KEM_512, ML_KEM_768},
};

fn test_mode(mode: KyberMode, name: &str) {
    let coins = [0u8; 64];
    let (pk, sk) = kem::keypair_derand(mode, &coins);
    assert_eq!(pk.len(), mode.public_key_bytes());
    assert_eq!(sk.len(), mode.secret_key_bytes());

    let enc_coins = [1u8; 32];
    let (ct, ss_enc) = kem::encaps_derand(mode, &pk, &enc_coins);
    assert_eq!(ct.len(), mode.ciphertext_bytes());

    let ss_dec = kem::decaps(mode, &ct, &sk);
    assert_eq!(ss_enc, ss_dec, "{}: shared secret mismatch", name);
    println!(
        "{}: ✅ PASS (pk={}B, sk={}B, ct={}B, ss={}B)",
        name,
        pk.len(),
        sk.len(),
        ct.len(),
        ss_enc.len()
    );
}

fn main() {
    test_mode(ML_KEM_512, "ML-KEM-512");
    test_mode(ML_KEM_768, "ML-KEM-768");
    test_mode(ML_KEM_1024, "ML-KEM-1024");
    println!("\nAll 3 modes pass! 🎉");
}
