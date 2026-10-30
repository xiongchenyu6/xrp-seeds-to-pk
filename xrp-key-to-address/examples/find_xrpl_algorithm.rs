use hex;
use ripemd::Ripemd160;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::Sha256;
use sha2::{Digest, Sha512};

fn sha512_half(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(data);
    let hash = hasher.finalize();
    hash[..32].to_vec()
}

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
    let expected_address = "rfEugbFaAkBrPCDgnoJYZivQVFgv2TbddM";
    let expected_private_key = "E31FF4952000DE23DCA878100EDB2E60DBB1717113D1AA0A912AF44F3078AC55";

    println!("Finding xrpl.js algorithm");
    println!("Expected private key: {}", expected_private_key);
    println!("Expected address: {}", expected_address);

    // Decode the secret
    let decoded = bs58::decode(secret)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .into_vec()
        .unwrap();

    let seed = &decoded[1..17]; // Skip type byte, take 16 bytes
    println!("Seed: {}", hex::encode(seed));

    // Get the root key (we know this part works)
    let mut root_private = None;
    for seq in 0..10u32 {
        let mut to_hash = Vec::new();
        to_hash.extend_from_slice(seed);
        to_hash.extend_from_slice(&seq.to_be_bytes());

        let key = sha512_half(&to_hash);

        // Check if valid
        if !key.iter().all(|&b| b == 0) {
            println!("Root key (seq {}): {}", seq, hex::encode(&key));
            root_private = Some(key);
            break;
        }
    }

    let root_key = root_private.unwrap();
    let secp = Secp256k1::new();
    let root_sk = SecretKey::from_slice(&root_key).unwrap();
    let root_pk = PublicKey::from_secret_key(&secp, &root_sk);

    println!("\nTrying different family derivation approaches:");

    // Try different discriminants and sequences
    for discriminant in 0..=2u8 {
        for account in 0..=1u32 {
            for subseq in 0..=10u32 {
                // Method 1: Public key + discriminant + account + subseq
                let mut to_hash = Vec::new();
                to_hash.extend_from_slice(&root_pk.serialize());
                to_hash.push(discriminant);
                to_hash.extend_from_slice(&account.to_be_bytes());
                to_hash.extend_from_slice(&subseq.to_be_bytes());

                let subkey = sha512_half(&to_hash);

                // Try adding to root
                if let Ok(subkey_sk) = SecretKey::from_slice(&subkey) {
                    if let Ok(subkey_scalar) = Scalar::from_be_bytes(subkey_sk.secret_bytes()) {
                        let mut combined = root_sk;
                        if let Ok(final_key) = combined.add_tweak(&subkey_scalar) {
                            let final_hex = hex::encode(final_key.secret_bytes()).to_uppercase();
                            if final_hex == expected_private_key {
                                println!(
                                    "FOUND! discriminant={}, account={}, subseq={}",
                                    discriminant, account, subseq
                                );

                                // Verify address
                                let final_pk = PublicKey::from_secret_key(&secp, &final_key);
                                let addr = address_from_public_key(&final_pk.serialize());
                                println!("Generated address: {}", addr);
                                println!("Match: {}", addr == expected_address);
                                return;
                            }
                        }
                    }
                }

                // Method 2: Just check if subkey itself is the target
                let subkey_hex = hex::encode(&subkey).to_uppercase();
                if subkey_hex == expected_private_key {
                    println!(
                        "FOUND! Subkey directly: discriminant={}, account={}, subseq={}",
                        discriminant, account, subseq
                    );

                    // Verify address
                    if let Ok(sk) = SecretKey::from_slice(&subkey) {
                        let pk = PublicKey::from_secret_key(&secp, &sk);
                        let addr = address_from_public_key(&pk.serialize());
                        println!("Generated address: {}", addr);
                        println!("Match: {}", addr == expected_address);
                    }
                    return;
                }
            }
        }
    }

    println!("\nNot found with standard family derivation");
}
