use anyhow::{Context, Result};
use hex;
use ripemd::Ripemd160;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256, Sha512};

fn main() -> Result<()> {
    let secret = "snnyR7py4xpSRHNLqX95iZ9RXh5eW";
    
    println!("Debugging XRP secret: {}", secret);
    
    // Decode Base58
    let decoded = bs58::decode(secret)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .into_vec()
        .context("Failed to decode Base58 secret")?;
    
    println!("Decoded bytes (hex): {}", hex::encode(&decoded));
    println!("Decoded length: {} bytes", decoded.len());
    
    let payload = &decoded[..decoded.len() - 4];
    let checksum = &decoded[decoded.len() - 4..];
    
    println!("Payload (hex): {}", hex::encode(payload));
    println!("Checksum (hex): {}", hex::encode(checksum));
    println!("Key type byte: 0x{:02X}", payload[0]);
    
    let seed = &payload[1..];
    println!("Seed (hex): {}", hex::encode(seed));
    println!("Seed length: {} bytes", seed.len());
    
    // Derive private key
    let mut sequence: u32 = 0;
    loop {
        let mut to_hash = Vec::new();
        to_hash.extend_from_slice(seed);
        to_hash.extend_from_slice(&sequence.to_be_bytes());
        
        let mut hasher = Sha512::new();
        hasher.update(&to_hash);
        let hash = hasher.finalize();
        
        let private_key = hash[..32].to_vec();
        
        // Check if valid
        if !private_key.iter().all(|&b| b == 0) {
            println!("\nDerived private key (hex): {}", hex::encode(&private_key));
            
            // Generate public key
            let secp = Secp256k1::new();
            let secret_key = SecretKey::from_slice(&private_key)?;
            let public_key = PublicKey::from_secret_key(&secp, &secret_key);
            let public_key_bytes = public_key.serialize();
            
            println!("Public key (hex): {}", hex::encode(&public_key_bytes));
            
            // Generate address
            let mut hasher = Sha256::new();
            hasher.update(&public_key_bytes);
            let sha256_hash = hasher.finalize();
            
            let mut ripemd_hasher = Ripemd160::new();
            ripemd_hasher.update(&sha256_hash);
            let account_id = ripemd_hasher.finalize();
            
            println!("Account ID (hex): {}", hex::encode(&account_id));
            
            let mut payload = Vec::with_capacity(21);
            payload.push(0x00);
            payload.extend_from_slice(&account_id);
            
            let mut address_bytes = Vec::with_capacity(25);
            address_bytes.extend_from_slice(&payload);
            
            // Calculate checksum
            let mut hasher = Sha256::new();
            hasher.update(&payload);
            let first_hash = hasher.finalize();
            
            let mut hasher = Sha256::new();
            hasher.update(&first_hash);
            let checksum = hasher.finalize();
            
            address_bytes.extend_from_slice(&checksum[..4]);
            
            let address = bs58::encode(&address_bytes)
                .with_alphabet(bs58::Alphabet::RIPPLE)
                .into_string();
            
            println!("Final address: {}", address);
            break;
        }
        
        sequence += 1;
    }
    
    Ok(())
}