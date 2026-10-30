use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hex;
use ripemd::Ripemd160;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::{Digest, Sha256, Sha512};
use std::io::{self, BufRead};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(
        help = "XRP private key in hex format (64 hex chars) or Base58 secret key (starts with 's')"
    )]
    private_key: Option<String>,

    #[arg(
        long,
        help = "Show addresses for both secp256k1 and Ed25519 derivations"
    )]
    both: bool,

    #[arg(long, value_enum, default_value = "root", help = "Key derivation mode")]
    mode: DerivationMode,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
enum DerivationMode {
    /// Use root key directly (simple mode)
    Root,
    /// Use family seed derivation (original XRP protocol)
    Family,
    /// Use xrpl.js/ripple-keypairs derivation (most wallets)
    Xrpl,
    /// Show all derivation modes
    All,
}

#[derive(Debug)]
enum KeyType {
    Secp256k1,
    Ed25519,
}

fn decode_xrp_secret(secret: &str) -> Result<(Vec<u8>, KeyType)> {
    let decoded = bs58::decode(secret)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .into_vec()
        .context("Failed to decode Base58 secret")?;

    if decoded.len() < 5 {
        anyhow::bail!("Invalid XRP secret: too short");
    }

    let payload = &decoded[..decoded.len() - 4];
    let checksum = &decoded[decoded.len() - 4..];

    let calculated_checksum = calculate_checksum(payload);
    if checksum != &calculated_checksum[..4] {
        anyhow::bail!("Invalid XRP secret: checksum mismatch");
    }

    // XRP secret keys can have different prefixes:
    // 0x21 (33) for secp256k1 family seed
    // 0x23 (35) for Ed25519 family seed (sEd prefix)
    let key_type = match payload[0] {
        0x21 => KeyType::Secp256k1,
        0x23 => KeyType::Ed25519,
        other => anyhow::bail!("Invalid XRP secret: unknown key type 0x{:02X}", other),
    };

    // The payload after the type byte is the entropy/seed (16 bytes for XRP)
    let seed = payload[1..].to_vec();

    Ok((seed, key_type))
}

fn derive_secp256k1_root_private_key(seed: &[u8]) -> Result<Vec<u8>> {
    // XRP uses SHA512-Half for root key derivation
    // The root private key is derived by concatenating the seed with a sequence number
    // and taking the first half of SHA512 until we get a valid secp256k1 key
    let mut root_sequence: u32 = 0;
    loop {
        // Create a 20-byte buffer: 16 bytes seed + 4 bytes sequence
        let mut to_hash = Vec::with_capacity(20);
        to_hash.extend_from_slice(seed);
        to_hash.extend_from_slice(&root_sequence.to_be_bytes());

        // Calculate SHA512 and take first half (256 bits = 32 bytes)
        let mut hasher = Sha512::new();
        hasher.update(&to_hash);
        let hash = hasher.finalize();
        let root_private = hash[..32].to_vec();

        // Check if it's a valid secp256k1 private key
        if is_valid_secp256k1_key(&root_private) {
            return Ok(root_private);
        }

        root_sequence += 1;
        if root_sequence > 0xFFFFFF {
            anyhow::bail!("Failed to derive valid root private key");
        }
    }
}

fn derive_secp256k1_xrpl_address(seed: &[u8]) -> Result<String> {
    use std::process::Command;

    // Reconstruct the Base58 secret from the seed
    let mut payload = Vec::with_capacity(17);
    payload.push(0x21); // Type byte for secp256k1
    payload.extend_from_slice(seed);

    let checksum = calculate_checksum(&payload);
    let mut full_bytes = Vec::with_capacity(21);
    full_bytes.extend_from_slice(&payload);
    full_bytes.extend_from_slice(&checksum[..4]);

    let secret = bs58::encode(&full_bytes)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .into_string();

    // First try xrpl-rust (it works for some seeds)
    use xrpl_rust::wallet::Wallet;
    if let Ok(wallet) = Wallet::new(&secret, 0) {
        return Ok(wallet.classic_address.clone());
    }

    // If xrpl-rust fails, fall back to calling xrpl.js via Node.js
    // This ensures compatibility with all seeds that xrpl.js supports
    let js_code = format!(
        r#"
const xrpl = require('xrpl');
try {{
    const wallet = xrpl.Wallet.fromSeed('{}');
    console.log(wallet.classicAddress);
}} catch (e) {{
    console.error('ERROR:', e.message);
    process.exit(1);
}}
"#,
        secret
    );

    let temp_file = format!("/tmp/xrpl_derive_{}.js", std::process::id());
    std::fs::write(&temp_file, js_code)?;

    let output = Command::new("node").arg(&temp_file).output();

    // Clean up temp file
    let _ = std::fs::remove_file(&temp_file);

    let output = output.context("Failed to execute Node.js. Make sure Node.js and 'xrpl' package are installed (npm install -g xrpl)")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("Cannot find module 'xrpl'") {
            anyhow::bail!("xrpl Node.js package not found. Install with: npm install -g xrpl");
        }
        anyhow::bail!("xrpl.js failed: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let address = stdout.trim();

    if address.starts_with("ERROR:") {
        anyhow::bail!("xrpl.js error: {}", address);
    }

    Ok(address.to_string())
}

fn derive_secp256k1_family_account_key(seed: &[u8], account_index: u32) -> Result<Vec<u8>> {
    // Step 1: Derive the root/generator private key
    let root_private = derive_secp256k1_root_private_key(seed)?;

    // Step 2: Get the public generator
    let secp = Secp256k1::new();
    let root_secret = SecretKey::from_slice(&root_private).context("Invalid root private key")?;
    let root_public = PublicKey::from_secret_key(&secp, &root_secret);
    let root_public_bytes = root_public.serialize();

    // Step 3: Derive intermediate key for account
    let mut sub_sequence: u32 = 0;
    loop {
        // Create buffer: public_root + discriminant (0x00) + account_index + sub_sequence
        let mut to_hash = Vec::new();
        to_hash.extend_from_slice(&root_public_bytes);
        to_hash.push(0x00); // discriminant for derived keys
        to_hash.extend_from_slice(&account_index.to_be_bytes());
        to_hash.extend_from_slice(&sub_sequence.to_be_bytes());

        // SHA512-Half to get intermediate secret
        let mut hasher = Sha512::new();
        hasher.update(&to_hash);
        let hash = hasher.finalize();
        let intermediate_secret = &hash[..32];

        // Check if this is a valid intermediate key
        if !is_valid_secp256k1_key(intermediate_secret) {
            sub_sequence += 1;
            if sub_sequence > 0xFFFFFF {
                anyhow::bail!("Failed to derive valid intermediate key");
            }
            continue;
        }

        // Add intermediate secret to root secret to get account secret
        // This is scalar addition in the secp256k1 field
        if let Ok(intermediate_key) = SecretKey::from_slice(intermediate_secret) {
            if let Ok(root_key) = SecretKey::from_slice(&root_private) {
                // Add the intermediate key to root key using add_tweak
                let intermediate_scalar = Scalar::from_be_bytes(intermediate_key.secret_bytes())
                    .context("Invalid intermediate scalar")?;

                let mut account_secret = root_key;
                account_secret = account_secret.add_tweak(&intermediate_scalar)?;

                let account_private = account_secret.secret_bytes().to_vec();
                if is_valid_secp256k1_key(&account_private) {
                    return Ok(account_private);
                }
            }
        }

        sub_sequence += 1;
        if sub_sequence > 0xFFFFFF {
            anyhow::bail!("Failed to derive valid account key");
        }
    }
}

fn derive_ed25519_private_key(seed: &[u8]) -> Result<Vec<u8>> {
    // For Ed25519, XRP uses SHA512 of the seed directly and takes the first 32 bytes
    let mut hasher = Sha512::new();
    hasher.update(seed);
    let hash = hasher.finalize();
    Ok(hash[..32].to_vec())
}

fn is_valid_secp256k1_key(key: &[u8]) -> bool {
    // Check if the key is valid for secp256k1
    // Must be non-zero and less than the curve order
    if key.iter().all(|&b| b == 0) {
        return false;
    }

    // secp256k1 order: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    let order = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];

    for i in 0..32 {
        if key[i] < order[i] {
            return true;
        } else if key[i] > order[i] {
            return false;
        }
    }

    false
}

fn secp256k1_address_from_private_key(private_key_bytes: &[u8]) -> Result<String> {
    let secp = Secp256k1::new();
    let secret_key =
        SecretKey::from_slice(private_key_bytes).context("Invalid secp256k1 private key")?;
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let public_key_bytes = public_key.serialize();

    address_from_public_key(&public_key_bytes)
}

fn ed25519_address_from_private_key(private_key_bytes: &[u8]) -> Result<String> {
    let signing_key = SigningKey::from_bytes(
        private_key_bytes
            .try_into()
            .context("Invalid Ed25519 private key length")?,
    );
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    // For Ed25519, XRP uses a special encoding with prefix byte 0xED
    let mut public_key_bytes = Vec::with_capacity(33);
    public_key_bytes.push(0xED);
    public_key_bytes.extend_from_slice(verifying_key.as_bytes());

    address_from_public_key(&public_key_bytes)
}

fn address_from_public_key(public_key_bytes: &[u8]) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(public_key_bytes);
    let sha256_hash = hasher.finalize();

    let mut ripemd_hasher = Ripemd160::new();
    ripemd_hasher.update(&sha256_hash);
    let account_id = ripemd_hasher.finalize();

    let mut payload = Vec::with_capacity(21);
    payload.push(0x00);
    payload.extend_from_slice(&account_id);

    let checksum = calculate_checksum(&payload);

    let mut address_bytes = Vec::with_capacity(25);
    address_bytes.extend_from_slice(&payload);
    address_bytes.extend_from_slice(&checksum[..4]);

    let address = bs58::encode(&address_bytes)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .into_string();

    Ok(address)
}

fn private_key_to_xrp_addresses(input: &str, show_both: bool, mode: DerivationMode) -> Result<()> {
    let input = input.trim();

    if input.starts_with('s') {
        // It's a Base58 secret key
        let (seed, detected_type) = decode_xrp_secret(input)?;

        if mode == DerivationMode::All {
            // Show all derivation modes
            println!("Showing addresses for all derivation modes:");
            println!("Secret: {}", input);
            println!();

            // Only for secp256k1 keys
            if matches!(detected_type, KeyType::Secp256k1) {
                // Root mode
                match derive_secp256k1_root_private_key(&seed) {
                    Ok(key) => match secp256k1_address_from_private_key(&key) {
                        Ok(address) => println!("Root mode:   {}", address),
                        Err(e) => println!("Root mode:   Error - {}", e),
                    },
                    Err(e) => println!("Root mode:   Error - {}", e),
                }

                // Family mode
                match derive_secp256k1_family_account_key(&seed, 0) {
                    Ok(key) => match secp256k1_address_from_private_key(&key) {
                        Ok(address) => println!("Family mode: {}", address),
                        Err(e) => println!("Family mode: Error - {}", e),
                    },
                    Err(e) => println!("Family mode: Error - {}", e),
                }

                // Xrpl mode (uses xrpl-rust library or xrpl.js, matches OSM wallet)
                match derive_secp256k1_xrpl_address(&seed) {
                    Ok(address) => println!("Xrpl mode:   {}", address),
                    Err(e) => println!("Xrpl mode:   Error - {}", e),
                }
            } else {
                println!("Ed25519 keys only have one derivation mode:");
                match derive_ed25519_private_key(&seed) {
                    Ok(private_key) => match ed25519_address_from_private_key(&private_key) {
                        Ok(address) => println!("Ed25519:     {}", address),
                        Err(e) => println!("Ed25519:     Error - {}", e),
                    },
                    Err(e) => println!("Ed25519:     Error - {}", e),
                }
            }
        } else if show_both {
            // Show both derivations regardless of detected type
            println!("Deriving addresses for both key types from seed...");
            println!("Mode: {:?}\n", mode);

            // secp256k1 derivation
            match detected_type {
                KeyType::Secp256k1 | KeyType::Ed25519 => {
                    let private_key = match mode {
                        DerivationMode::Root => derive_secp256k1_root_private_key(&seed),
                        DerivationMode::Family => derive_secp256k1_family_account_key(&seed, 0),
                        DerivationMode::Xrpl => {
                            // For Xrpl mode, we get the address directly
                            match derive_secp256k1_xrpl_address(&seed) {
                                Ok(address) => {
                                    println!("secp256k1 address: {}", address);
                                    return Ok(());
                                }
                                Err(e) => return Err(e),
                            }
                        }
                        DerivationMode::All => unreachable!(), // Already handled above
                    };

                    match private_key {
                        Ok(key) => {
                            let address = secp256k1_address_from_private_key(&key)?;
                            println!("secp256k1 address: {}", address);
                        }
                        Err(e) => println!("secp256k1 error: {}", e),
                    }
                }
            }

            // Ed25519 derivation (doesn't use family mode)
            match derive_ed25519_private_key(&seed) {
                Ok(private_key) => {
                    let address = ed25519_address_from_private_key(&private_key)?;
                    println!("Ed25519 address:   {}", address);
                }
                Err(e) => println!("Ed25519 error: {}", e),
            }
        } else {
            // Use the detected key type
            match detected_type {
                KeyType::Secp256k1 => {
                    println!("Detected secp256k1 secret key");
                    println!("Mode: {:?}", mode);
                    match mode {
                        DerivationMode::Root => {
                            let private_key = derive_secp256k1_root_private_key(&seed)?;
                            let address = secp256k1_address_from_private_key(&private_key)?;
                            println!("{}", address);
                        }
                        DerivationMode::Family => {
                            let private_key = derive_secp256k1_family_account_key(&seed, 0)?;
                            let address = secp256k1_address_from_private_key(&private_key)?;
                            println!("{}", address);
                        }
                        DerivationMode::Xrpl => {
                            let address = derive_secp256k1_xrpl_address(&seed)?;
                            println!("{}", address);
                        }
                        DerivationMode::All => unreachable!(), // Already handled above
                    }
                }
                KeyType::Ed25519 => {
                    println!("Detected Ed25519 secret key");
                    let private_key = derive_ed25519_private_key(&seed)?;
                    let address = ed25519_address_from_private_key(&private_key)?;
                    println!("{}", address);
                }
            }
        }
    } else {
        // It's a hex private key
        let hex_input = if input.starts_with("0x") || input.starts_with("0X") {
            &input[2..]
        } else {
            input
        };

        let private_key_bytes =
            hex::decode(hex_input).context("Failed to decode private key from hex")?;

        if private_key_bytes.len() != 32 {
            anyhow::bail!(
                "Private key must be exactly 32 bytes, got {} bytes",
                private_key_bytes.len()
            );
        }

        if show_both {
            println!("Generating addresses for both key types from hex private key...\n");

            // Try secp256k1
            match secp256k1_address_from_private_key(&private_key_bytes) {
                Ok(address) => println!("secp256k1 address: {}", address),
                Err(e) => println!("secp256k1 error: {}", e),
            }

            // Try Ed25519
            match ed25519_address_from_private_key(&private_key_bytes) {
                Ok(address) => println!("Ed25519 address:   {}", address),
                Err(e) => println!("Ed25519 error: {}", e),
            }
        } else {
            // Default to secp256k1 for hex keys
            let address = secp256k1_address_from_private_key(&private_key_bytes)?;
            println!("{}", address);
        }
    }

    Ok(())
}

fn calculate_checksum(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let first_hash = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(&first_hash);
    hasher.finalize().into()
}

fn main() -> Result<()> {
    let args = Args::parse();

    let input = if let Some(key) = args.private_key {
        key
    } else {
        let stdin = io::stdin();
        let mut lines = stdin.lock().lines();
        lines
            .next()
            .context("No input provided")?
            .context("Failed to read from stdin")?
    };

    private_key_to_xrp_addresses(&input, args.both, args.mode)?;

    Ok(())
}
