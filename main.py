from bip_utils import (
    Bip39SeedGenerator,
    Bip44,
    Bip44Coins,
    Bip44Changes,
)
from xrpl.wallet import Wallet


def mnemonic_to_wallet(mnemonic: str, index: int = 0) -> Wallet:
    # BIP44 HD derivation for XRP: m/44'/144'/0'/0/<index>
    # This matches the iancoleman BIP39 web tool ("derived from the BIP32 Extended Key").
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()  # 64-byte BIP39 seed (PBKDF2)
    addr_ctx = (
        Bip44.FromSeed(seed_bytes, Bip44Coins.RIPPLE)
        .Purpose()
        .Coin()
        .Account(0)
        .Change(Bip44Changes.CHAIN_EXT)
        .AddressIndex(index)
    )

    public_key = addr_ctx.PublicKey().RawCompressed().ToHex().upper()
    # secp256k1 private keys carry a "00" prefix in the XRPL representation
    private_key = "00" + addr_ctx.PrivateKey().Raw().ToHex().upper()

    return Wallet(public_key=public_key, private_key=private_key)


mnemonic_phrase = (
    "finger dune cabin open outside aim hotel run yellow lesson siege birth"
)

wallet = mnemonic_to_wallet(mnemonic_phrase, 0)
print(
    f"""
Address:     {wallet.classic_address}
X-Address:   {wallet.get_xaddress()}
Public key:  {wallet.public_key}
Private key: {wallet.private_key}
    """
)
