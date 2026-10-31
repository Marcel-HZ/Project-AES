import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aes.gf import gf_mul


class TestGF(unittest.TestCase):
    def test_gf_mul_known(self):
        self.assertEqual(gf_mul(0x57, 0x83), 0xC1)

    def test_gf_mul_identity(self):
        for a in range(256):
            self.assertEqual(gf_mul(a, 1), a)


if __name__ == "__main__":
    unittest.main()
