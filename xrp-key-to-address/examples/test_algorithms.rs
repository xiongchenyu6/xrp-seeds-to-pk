use hex;
use ripemd::Ripemd160;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
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

    println!("Testing different XRP key derivation algorithms");
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

    // Test 1: Root key with different discriminants
    println!("=== Test 1: Root key with different discriminants ===");
    for discriminant in [0x00u8, 0x01, 0xFF] {
        for seq in 0..3u32 {
            let mut to_hash = Vec::new();
            to_hash.extend_from_slice(seed);
            to_hash.push(discriminant);
            to_hash.extend_from_slice(&seq.to_be_bytes()[1..]); // 3 bytes

            let mut hasher = Sha512::new();
            hasher.update(&to_hash);
            let hash = hasher.finalize();
            let private_key = &hash[..32];

            if let Ok(sk) = SecretKey::from_slice(private_key) {
                let pk = PublicKey::from_secret_key(&secp, &sk);
                let addr = address_from_public_key(&pk.serialize());
                if addr == expected {
                    println!("FOUND! Discriminant: 0x{:02X}, Seq: {}", discriminant, seq);
                    println!("Private key: {}", hex::encode(private_key));
                    return;
                }
            }
        }
    }

    // Test 2: Different sequence byte lengths
    println!("\n=== Test 2: Different sequence formats ===");
    for seq in 0..3u32 {
        // Try with 4-byte sequence
        let mut to_hash = Vec::new();
        to_hash.extend_from_slice(seed);
        to_hash.extend_from_slice(&seq.to_be_bytes());

        let mut hasher = Sha512::new();
        hasher.update(&to_hash);
        let hash = hasher.finalize();
        let private_key = &hash[..32];

        if let Ok(sk) = SecretKey::from_slice(private_key) {
            let pk = PublicKey::from_secret_key(&secp, &sk);
            let addr = address_from_public_key(&pk.serialize());
            if addr == expected {
                println!("FOUND! 4-byte seq: {}", seq);
                println!("Private key: {}", hex::encode(private_key));
                return;
            }
        }
    }

    // Test 3: Generator-based with different approaches
    println!("\n=== Test 3: Generator-based family derivation ===");

    // First get the root key
    let mut root_key = None;
    for seq in 0..10u32 {
        let mut to_hash = Vec::new();
        to_hash.extend_from_slice(seed);
        to_hash.extend_from_slice(&seq.to_be_bytes());

        let mut hasher = Sha512::new();
        hasher.update(&to_hash);
        let hash = hasher.finalize();
        let private_key = &hash[..32];

        // Check if valid
        if private_key.iter().any(|&b| b != 0) {
            root_key = Some(private_key.to_vec());
            break;
        }
    }

    if let Some(root_private) = root_key {
        let root_sk = SecretKey::from_slice(&root_private).unwrap();
        let root_pk = PublicKey::from_secret_key(&secp, &root_sk);

        // Try different discriminants for the intermediate key
        for discriminant in [0x00u8, 0x01, 0xFF] {
            for account in 0..2u32 {
                for subseq in 0..3u32 {
                    let mut to_hash = Vec::new();
                    to_hash.extend_from_slice(&root_pk.serialize());
                    to_hash.push(discriminant);
                    to_hash.extend_from_slice(&account.to_be_bytes());
                    to_hash.extend_from_slice(&subseq.to_be_bytes());

                    let mut hasher = Sha512::new();
                    hasher.update(&to_hash);
                    let hash = hasher.finalize();
                    let intermediate = &hash[..32];

                    if let Ok(inter_sk) = SecretKey::from_slice(intermediate) {
                        // Try adding
                        if let Ok(inter_scalar) = Scalar::from_be_bytes(inter_sk.secret_bytes()) {
                            let mut account_sk = root_sk;
                            if let Ok(final_sk) = account_sk.add_tweak(&inter_scalar) {
                                let final_pk = PublicKey::from_secret_key(&secp, &final_sk);
                                let addr = address_from_public_key(&final_pk.serialize());
                                if addr == expected {
                                    println!("FOUND! Generator method");
                                    println!(
                                        "Discriminant: 0x{:02X}, Account: {}, Subseq: {}",
                                        discriminant, account, subseq
                                    );
                                    return;
                                }
                            }
                        }

                        // Also try using intermediate directly
                        let inter_pk = PublicKey::from_secret_key(&secp, &inter_sk);
                        let addr = address_from_public_key(&inter_pk.serialize());
                        if addr == expected {
                            println!("FOUND! Intermediate key directly");
                            println!(
                                "Discriminant: 0x{:02X}, Account: {}, Subseq: {}",
                                discriminant, account, subseq
                            );
                            return;
                        }
                    }
                }
            }
        }
    }

    // Test 4: Uncompressed public keys
    println!("\n=== Test 4: Testing with uncompressed public keys ===");
    for seq in 0..3u32 {
        let mut to_hash = Vec::new();
        to_hash.extend_from_slice(seed);
        to_hash.extend_from_slice(&seq.to_be_bytes());

        let mut hasher = Sha512::new();
        hasher.update(&to_hash);
        let hash = hasher.finalize();
        let private_key = &hash[..32];

        if let Ok(sk) = SecretKey::from_slice(private_key) {
            let pk = PublicKey::from_secret_key(&secp, &sk);
            let uncompressed = pk.serialize_uncompressed();
            let addr = address_from_public_key(&uncompressed);
            if addr == expected {
                println!("FOUND! Uncompressed key, seq: {}", seq);
                return;
            }
        }
    }

    println!("\nNo match found with standard algorithms.");
    println!("OSM wallet may use a proprietary algorithm.");
}
