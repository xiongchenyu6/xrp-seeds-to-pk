use hex;
use ripemd::Ripemd160;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256, Sha512};

fn address_from_public_key(public_key_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key_bytes);
    let sha256_hash = hasher.finalize();

    let mut ripemd_hasher = Ripemd160::new();
    ripemd_hasher.update(&sha256_hash);
    let account_id = ripemd_hasher.finalize();

    let mut payload = Vec::with_capacity(21);
    payload.push(0x00);
    payload.extend_from_slice(&account_id);

    // Checksum
    let mut hasher = Sha256::new();
    hasher.update(&payload);
    let first_hash = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(&first_hash);
    let checksum = hasher.finalize();

    let mut address_bytes = Vec::with_capacity(25);
    address_bytes.extend_from_slice(&payload);
    address_bytes.extend_from_slice(&checksum[..4]);

    bs58::encode(&address_bytes)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .into_string()
}

fn main() {
    let secret = "snnyR7py4xpSRHNLqX95iZ9RXh5eW";
    let expected = "rfEugbFaAkBrPCDgnoJYZivQVFgv2TbddM";

    println!("Testing simple derivation possibilities");
    println!("Secret: {}", secret);
    println!("Expected: {}\n", expected);

    // Decode the secret
    let decoded = bs58::decode(secret)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .into_vec()
        .unwrap();

    let seed = &decoded[1..17]; // Skip type byte, take 16 bytes
    println!("Seed (hex): {}\n", hex::encode(seed));

    let secp = Secp256k1::new();

    // Test: Maybe OSM uses the seed as the private key directly
    println!("Test 1: Seed as private key directly");
    // Pad seed to 32 bytes
    let mut padded = vec![0u8; 16];
    padded.extend_from_slice(seed);
    if let Ok(sk) = SecretKey::from_slice(&padded) {
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let addr = address_from_public_key(&pk.serialize());
        println!("Address: {}", addr);
        if addr == expected {
            println!("FOUND!");
            return;
        }
    }

    // Test: Different padding
    let mut padded2 = seed.to_vec();
    padded2.extend_from_slice(&[0u8; 16]);
    if let Ok(sk) = SecretKey::from_slice(&padded2) {
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let addr = address_from_public_key(&pk.serialize());
        println!("Address (right pad): {}", addr);
        if addr == expected {
            println!("FOUND!");
            return;
        }
    }

    // Test: Double SHA256 instead of SHA512
    println!("\nTest 2: Double SHA256 of seed");
    let mut hasher = Sha256::new();
    hasher.update(seed);
    let hash1 = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(&hash1);
    let hash2 = hasher.finalize();

    if let Ok(sk) = SecretKey::from_slice(&hash2) {
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let addr = address_from_public_key(&pk.serialize());
        println!("Address: {}", addr);
        if addr == expected {
            println!("FOUND!");
            return;
        }
    }

    // Test: Single SHA256
    println!("\nTest 3: Single SHA256 of seed");
    let mut hasher = Sha256::new();
    hasher.update(seed);
    let hash = hasher.finalize();

    if let Ok(sk) = SecretKey::from_slice(&hash) {
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let addr = address_from_public_key(&pk.serialize());
        println!("Address: {}", addr);
        if addr == expected {
            println!("FOUND!");
            return;
        }
    }

    // Test: Maybe they use a different account index in family derivation
    println!("\nTest 4: Different account indices in family derivation");

    // Get root key first
    let mut to_hash = Vec::new();
    to_hash.extend_from_slice(seed);
    to_hash.extend_from_slice(&[0, 0, 0, 0]);

    let mut hasher = Sha512::new();
    hasher.update(&to_hash);
    let hash = hasher.finalize();
    let root_private = &hash[..32];

    if let Ok(root_sk) = SecretKey::from_slice(root_private) {
        let root_pk = PublicKey::from_secret_key(&secp, &root_sk);

        // Try account indices 0-10
        for account_idx in 0..10u32 {
            // Simple approach: hash public key + account index
            let mut to_hash = Vec::new();
            to_hash.extend_from_slice(&root_pk.serialize());
            to_hash.extend_from_slice(&account_idx.to_be_bytes());

            let mut hasher = Sha512::new();
            hasher.update(&to_hash);
            let hash = hasher.finalize();
            let account_key = &hash[..32];

            if let Ok(sk) = SecretKey::from_slice(account_key) {
                let pk = PublicKey::from_secret_key(&secp, &sk);
                let addr = address_from_public_key(&pk.serialize());
                if addr == expected {
                    println!("FOUND! Account index: {}", account_idx);
                    return;
                }
            }
        }
    }

    // Test: Maybe it's using the full decoded value (including checksum)
    println!("\nTest 5: Using full decoded value");
    let full_decoded = &decoded[1..]; // Skip only the type byte
    if full_decoded.len() >= 32 {
        let key_bytes = &full_decoded[..32];
        if let Ok(sk) = SecretKey::from_slice(key_bytes) {
            let pk = PublicKey::from_secret_key(&secp, &sk);
            let addr = address_from_public_key(&pk.serialize());
            println!("Address: {}", addr);
            if addr == expected {
                println!("FOUND!");
                return;
            }
        }
    }

    println!("\nStill no match. OSM wallet likely uses a proprietary or undocumented algorithm.");
}
