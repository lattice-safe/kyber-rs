#![no_main]
use libfuzzer_sys::fuzz_target;
use kyber::kem::{keypair_derand, decaps};
use kyber::params::ML_KEM_768;

fuzz_target!(|data: &[u8]| {
    // Generate a valid key pair with fixed coins
    let coins = [0u8; 64];
    let (_pk, sk) = keypair_derand(ML_KEM_768, &coins);

    // Decapsulate arbitrary (invalid) ciphertexts
    // This must NOT panic — it should return the implicit rejection key
    if data.len() >= ML_KEM_768.ciphertext_bytes() {
        let ct = &data[..ML_KEM_768.ciphertext_bytes()];
        let _ss = decaps(ML_KEM_768, ct, &sk);
        // No assertion — just ensure it doesn't panic or crash
    }
});
