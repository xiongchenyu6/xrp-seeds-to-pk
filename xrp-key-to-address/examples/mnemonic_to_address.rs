//! Derive an XRP address from a BIP39 mnemonic using BIP44 HD derivation.
//!
//! Path: m/44'/144'/0'/0/<index>  (coin type 144 = XRP)
//! This matches the iancoleman BIP39 web tool, as well as the Node (main.js)
//! and Python (main.py) versions in this repo.
//!
//! Run with:  cargo run --example mnemonic_to_address

use anyhow::Result;
use bip32::{DerivationPath, XPrv};
use bip39::Mnemonic;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

const MNEMONIC: &str =
    "finger dune cabin open outside aim hotel run yellow lesson siege birth";

fn main() -> Result<()> {
    let index: u32 = 0;
    let phrase = MNEMONIC;
    println!("{phrase}");

    // 1. mnemonic -> 64-byte BIP39 seed (PBKDF2, empty passphrase)
    let mnemonic = Mnemonic::parse_normalized(phrase)
        .map_err(|e| anyhow::anyhow!("invalid mnemonic: {e}"))?;
    let seed = mnemonic.to_seed("");

    // 2. BIP32/BIP44 derivation along m/44'/144'/0'/0/<index>
    let path: DerivationPath = format!("m/44'/144'/0'/0/{index}")
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid derivation path: {e}"))?;
    let xprv = XPrv::derive_from_path(&seed, &path)
        .map_err(|e| anyhow::anyhow!("derivation failed: {e}"))?;

    // 3. 33-byte compressed secp256k1 public key + 32-byte private key
    let public_key = xprv.public_key().to_bytes(); // [u8; 33]
    let private_key = xprv.to_bytes(); // [u8; 32]

    // 4. XRPL address = Base58Check(0x00 || RIPEMD160(SHA256(pubkey)))
    let address = address_from_public_key(&public_key)?;

    println!("Address:     {address}");
    println!("Public key:  {}", hex::encode_upper(public_key));
    println!("Private key: 00{}", hex::encode_upper(private_key));
    Ok(())
}

/// Standard XRPL classic-address encoding from a public key.
fn address_from_public_key(public_key_bytes: &[u8]) -> Result<String> {
    let sha256_hash = Sha256::digest(public_key_bytes);
    let account_id = Ripemd160::digest(sha256_hash);

    let mut payload = Vec::with_capacity(21);
    payload.push(0x00); // classic address type prefix
    payload.extend_from_slice(&account_id);

    let checksum = double_sha256(&payload);

    let mut address_bytes = Vec::with_capacity(25);
    address_bytes.extend_from_slice(&payload);
    address_bytes.extend_from_slice(&checksum[..4]);

    Ok(bs58::encode(&address_bytes)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .into_string())
}

fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    Sha256::digest(first).into()
}
