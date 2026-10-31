import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aes.sbox import S_BOX, INV_S_BOX, sub_byte, inv_sub_byte
from aes.gf import gf_mul, mix_column, inv_mix_column
from aes.padding import pad, unpad, split_blocks
from aes.key_expansion import expand_key, expand_key_trace
from aes.cipher import encrypt_block, decrypt_block


class TestAES(unittest.TestCase):
    def test_fips_197_encrypt(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = "69c4e0d86a7b0430d8cdb78070b4c55a"
        rks = expand_key(key)
        ct = encrypt_block(pt, rks)
        self.assertEqual(ct.hex(), expected)

    def test_fips_197_decrypt(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        ct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        rks = expand_key(key)
        dec = decrypt_block(ct, rks)
        self.assertEqual(dec, pt)

    def test_expand_key_returns_11(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        rks = expand_key(key)
        self.assertEqual(len(rks), 11)
        for rk in rks:
            self.assertEqual(len(rk), 16)

    def test_expand_key_wrong_length(self):
        with self.assertRaises(ValueError):
            expand_key(b"short")

    def test_pad_unpad_roundtrip(self):
        for data in [b"", b"Hello", b"A" * 16, b"A" * 32, b"x" * 100]:
            padded = pad(data)
            self.assertEqual(unpad(padded), data)

    def test_pad_adds_full_block_when_multiple(self):
        data = b"A" * 16
        padded = pad(data)
        self.assertEqual(len(padded), 32)
        self.assertEqual(padded[-1], 16)

    def test_unpad_invalid(self):
        with self.assertRaises(ValueError):
            unpad(b"")
        with self.assertRaises(ValueError):
            unpad(b"\x00" * 16)
        with self.assertRaises(ValueError):
            unpad(b"A" * 15)

    def test_split_blocks(self):
        data = b"A" * 32
        blocks = split_blocks(data)
        self.assertEqual(len(blocks), 2)
        with self.assertRaises(ValueError):
            split_blocks(b"A" * 15)


class TestSbox(unittest.TestCase):
    def test_sbox_size(self):
        self.assertEqual(len(S_BOX), 256)
        self.assertEqual(len(INV_S_BOX), 256)

    def test_inverse(self):
        for i in range(256):
            self.assertEqual(INV_S_BOX[S_BOX[i]], i)
            self.assertEqual(S_BOX[INV_S_BOX[i]], i)

    def test_sub_byte(self):
        self.assertEqual(sub_byte(0x00), 0x63)


class TestGF(unittest.TestCase):
    def test_gf_mul_known(self):
        self.assertEqual(gf_mul(0x57, 0x83), 0xC1)

    def test_gf_mul_identity(self):
        for a in range(256):
            self.assertEqual(gf_mul(a, 1), a)
            self.assertEqual(gf_mul(1, a), a)


if __name__ == "__main__":
    unittest.main()
