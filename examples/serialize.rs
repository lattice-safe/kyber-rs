//! ML-KEM serialization example — shows how to serialize and
//! transmit public keys and ciphertexts as byte arrays.
//!
//! Run with: cargo run --example serialize

use kyber::kem::{decaps, encaps_derand, keypair_derand};
use kyber::params::ML_KEM_768;

fn main() {
    println!("=== ML-KEM-768 Serialization Demo ===\n");

    // Alice: generate key pair
    let coins = [42u8; 64];
    let (pk_bytes, sk_bytes) = keypair_derand(ML_KEM_768, &coins);
    println!("Alice generates key pair:");
    println!(
        "  pk ({} bytes): {:02x?}...",
        pk_bytes.len(),
        &pk_bytes[..16]
    );
    println!("  sk ({} bytes): [kept secret]", sk_bytes.len());

    // Alice sends pk_bytes to Bob (e.g. over the network)
    println!("\n--- Alice sends public key to Bob ---\n");

    // Bob: encapsulate with Alice's public key
    let enc_coins = [0xCD; 32];
    let (ct_bytes, ss_bob) = encaps_derand(ML_KEM_768, &pk_bytes, &enc_coins);
    println!("Bob encapsulates:");
    println!(
        "  ct ({} bytes): {:02x?}...",
        ct_bytes.len(),
        &ct_bytes[..16]
    );
    println!("  shared secret: {:02x?}", &ss_bob[..]);

    // Bob sends ct_bytes to Alice
    println!("\n--- Bob sends ciphertext to Alice ---\n");

    // Alice: decapsulate
    let ss_alice = decaps(ML_KEM_768, &ct_bytes, &sk_bytes);
    println!("Alice decapsulates:");
    println!("  shared secret: {:02x?}", &ss_alice[..]);

    println!(
        "\nShared secrets match: {}",
        if ss_bob == ss_alice { "✅" } else { "❌" }
    );
    println!("\nBoth parties now share a 32-byte symmetric key for AES-256 etc.");
}
