use hex;

fn main() {
    let secret = "snnyR7py4xpSRHNLqX95iZ9RXh5eW";

    println!("Debugging XRP secret: {}", secret);

    // Decode Base58
    let decoded = bs58::decode(secret)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .into_vec()
        .unwrap();

    println!("Decoded bytes (hex): {}", hex::encode(&decoded));
    println!("Decoded length: {} bytes", decoded.len());

    let payload = &decoded[..decoded.len() - 4];

    println!("Payload (hex): {}", hex::encode(payload));
    println!("Key type byte: 0x{:02X}", payload[0]);

    let seed = &payload[1..];
    println!("Seed (hex): {}", hex::encode(seed));
    println!("Seed length: {} bytes", seed.len());
}
