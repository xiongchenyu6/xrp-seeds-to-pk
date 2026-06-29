const xrpl = require("xrpl");
const bip39 = require("bip39");
const bip32 = require("bip32");

// BIP44 HD derivation for XRP (coin type 144): m/44'/144'/0'/0/<index>
// This matches the iancoleman BIP39 web tool ("derived from the BIP32 Extended Key").
function mnemonicToWallet(mnemonic, index = 0) {
  const seed = bip39.mnemonicToSeedSync(mnemonic); // 64-byte BIP39 seed (PBKDF2)
  const node = bip32.fromSeed(seed).derivePath(`m/44'/144'/0'/0/${index}`);

  const publicKey = Buffer.from(node.publicKey).toString("hex").toUpperCase();
  // secp256k1 private keys carry a "00" prefix in the XRPL representation
  const privateKey =
    "00" + Buffer.from(node.privateKey).toString("hex").toUpperCase();

  return new xrpl.Wallet(publicKey, privateKey);
}

function main() {
  const mnemonic =
    "finger dune cabin open outside aim hotel run yellow lesson siege birth";
  console.log(mnemonic);

  const wallet = mnemonicToWallet(mnemonic, 0);
  console.log("Address:    ", wallet.classicAddress);
  console.log("Public key: ", wallet.publicKey);
  console.log("Private key:", wallet.privateKey);
}

main();
