use hex;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha512};

fn main() {
    // Test with your secret
    let secret = "snnyR7py4xpSRHNLqX95iZ9RXh5eW";

    // Expected address according to user
    let expected = "rfEugbFaAkBrPCDgnoJYZivQVFgv2TbddM";

    println!("Secret: {}", secret);
    println!("Expected address: {}", expected);
    println!();

    // Decode the secret
    let decoded = bs58::decode(secret)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .into_vec()
        .unwrap();

    let seed = &decoded[1..17]; // Skip type byte, take 16 bytes
    println!("Seed (hex): {}", hex::encode(seed));

    // Try different derivation approaches

    // Approach 1: Direct SHA512-Half of seed
    let mut hasher = Sha512::new();
    hasher.update(seed);
    let hash = hasher.finalize();
    let direct_key = &hash[..32];
    println!("\nApproach 1 - Direct SHA512-Half:");
    println!("Private key: {}", hex::encode(direct_key));

    if let Ok(sk) = SecretKey::from_slice(direct_key) {
        let secp = Secp256k1::new();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        println!("Public key: {}", hex::encode(&pk.serialize()));
    }

    // Approach 2: With sequence 0
    let mut to_hash = Vec::new();
    to_hash.extend_from_slice(seed);
    to_hash.extend_from_slice(&[0, 0, 0, 0]);

    let mut hasher = Sha512::new();
    hasher.update(&to_hash);
    let hash = hasher.finalize();
    let seq0_key = &hash[..32];
    println!("\nApproach 2 - With sequence 0:");
    println!("Private key: {}", hex::encode(seq0_key));

    if let Ok(sk) = SecretKey::from_slice(seq0_key) {
        let secp = Secp256k1::new();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        println!("Public key: {}", hex::encode(&pk.serialize()));
    }
}
