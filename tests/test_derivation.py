"""Offline regression checks using synthetic BIP39 entropy only.

Load only imports and the conversion function, never the script's example data
or top-level calls. The reference BIP32 implementation is independent of bip-utils.
"""
import ast
import hashlib
import hmac
from pathlib import Path
import socket
import unittest
from unittest.mock import patch

from bip_utils import Secp256k1PrivateKey
from coincurve import PrivateKey
from mnemonic import Mnemonic
from xrpl.core.addresscodec import encode_classic_address


def load_converter():
    tree = ast.parse((Path(__file__).resolve().parents[1] / "main.py").read_text())
    tree.body = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))
                 or isinstance(node, ast.FunctionDef) and node.name == "mnemonic_to_wallet"]
    namespace = {}
    exec(compile(tree, "main.py", "exec"), namespace)
    return namespace["mnemonic_to_wallet"]


def reference_wallet(words, index):
    seed = Mnemonic.to_seed(words)
    digest = hmac.digest(b"Bitcoin seed", seed, "sha512")
    key, chain = digest[:32], digest[32:]
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    for child in (44 | 0x80000000, 144 | 0x80000000, 0x80000000, 0, index):
        public = PrivateKey(key).public_key.format(compressed=True)
        data = (b"\0" + key if child & 0x80000000 else public) + child.to_bytes(4, "big")
        digest = hmac.digest(chain, data, "sha512")
        scalar = (int.from_bytes(digest[:32], "big") + int.from_bytes(key, "big")) % order
        key, chain = scalar.to_bytes(32, "big"), digest[32:]
    public = PrivateKey(key).public_key.format(compressed=True)
    account = hashlib.new("ripemd160", hashlib.sha256(public).digest()).digest()
    return public.hex().upper(), "00" + key.hex().upper(), encode_classic_address(account)


class DerivationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.convert = staticmethod(load_converter())

    def setUp(self):
        for target in ("socket.socket.connect", "socket.socket.connect_ex", "socket.create_connection"):
            blocker = patch(target, side_effect=AssertionError("Network is forbidden in these tests"))
            blocker.start()
            self.addCleanup(blocker.stop)

    def test_synthetic_entropy_and_address_indices(self):
        for entropy in (bytes(16), bytes(range(16)), bytes(range(32))):
            words = Mnemonic("english").to_mnemonic(entropy)
            for index in (0, 1, 7):
                with self.subTest(entropy_length=len(entropy), index=index):
                    wallet = self.convert(words, index)
                    public, private, address = reference_wallet(words, index)
                    self.assertEqual(wallet.public_key, public)
                    self.assertEqual(wallet.private_key, private)
                    self.assertEqual(wallet.classic_address, address)

    def test_ripple_uses_native_secp256k1_backend(self):
        self.assertIn("coincurve", Secp256k1PrivateKey.__module__)

    def test_invalid_mnemonic_is_rejected(self):
        with self.assertRaises(ValueError):
            self.convert("invalid synthetic input")

    def test_network_guard(self):
        with self.assertRaisesRegex(AssertionError, "Network is forbidden"):
            socket.create_connection(("127.0.0.1", 9))


if __name__ == "__main__":
    unittest.main()
