//! ML-KEM key generation, encapsulation, and decapsulation example.
//!
//! Run with: cargo run --example keygen_encaps

use kyber::kem::{decaps, encaps_derand, keypair_derand};
use kyber::params::{KyberMode, ML_KEM_1024, ML_KEM_512, ML_KEM_768};

fn demo(mode: KyberMode, name: &str) {
    // In production, use a CSPRNG for all coins
    let mut keygen_coins = [0u8; 64];
    keygen_coins[0] = 42;

    let (pk, sk) = keypair_derand(mode, &keygen_coins);
    println!("[{}] Key pair generated", name);
    println!("  Public key:  {} bytes", pk.len());
    println!("  Secret key:  {} bytes", sk.len());

    let enc_coins = [0xABu8; 32];
    let (ct, ss_sender) = encaps_derand(mode, &pk, &enc_coins);
    println!("  Ciphertext:  {} bytes", ct.len());
    println!("  Shared secret (sender):   {:02x?}", &ss_sender[..8]);

    let ss_receiver = decaps(mode, &ct, &sk);
    println!("  Shared secret (receiver): {:02x?}", &ss_receiver[..8]);
    println!(
        "  Match: {}\n",
        if ss_sender == ss_receiver {
            "✅"
        } else {
            "❌"
        }
    );
}

fn main() {
    println!("=== ML-KEM (FIPS 203) Demo ===\n");
    demo(ML_KEM_512, "ML-KEM-512");
    demo(ML_KEM_768, "ML-KEM-768");
    demo(ML_KEM_1024, "ML-KEM-1024");
}
