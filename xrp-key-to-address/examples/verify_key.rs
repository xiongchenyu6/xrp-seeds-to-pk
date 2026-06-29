use hex;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

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
    // The private key that xrpl.js generates
    let xrpl_private_key = "E31FF4952000DE23DCA878100EDB2E60DBB1717113D1AA0A912AF44F3078AC55";
    let expected_public = "02F6A9B9AB8C5BAC77FD32AA635F65A943D203F7AD4DDF45557F5E2D6AA7A6C7B8";
    let expected_address = "rfEugbFaAkBrPCDgnoJYZivQVFgv2TbddM";
    
    println!("Verifying xrpl.js key generates correct address");
    println!("Private key: {}", xrpl_private_key);
    
    let private_bytes = hex::decode(xrpl_private_key).unwrap();
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&private_bytes).unwrap();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    
    let public_hex = hex::encode(public_key.serialize()).to_uppercase();
    println!("Public key: {}", public_hex);
    println!("Expected: {}", expected_public);
    println!("Public match: {}", public_hex == expected_public);
    
    let address = address_from_public_key(&public_key.serialize());
    println!("\nAddress: {}", address);
    println!("Expected: {}", expected_address);
    println!("Address match: {}", address == expected_address);
}