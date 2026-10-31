import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aes.key_expansion import expand_key
from aes.cipher import encrypt_block, decrypt_block
from utils.formatting import render_matrix, render_hex


# NIST AES-128 ECB test vectors (SP 800-38A / FIPS-197)
NIST_VECTORS = [
    {
        "name": "FIPS-197 Example",
        "key": "000102030405060708090a0b0c0d0e0f",
        "pt": "00112233445566778899aabbccddeeff",
        "ct": "69c4e0d86a7b0430d8cdb78070b4c55a",
    },
    {
        "name": "NIST SP 800-38A ECB #1",
        "key": "2b7e151628aed2a6abf7158809cf4f3c",
        "pt": "6bc1bee22e409f96e93d7e117393172a",
        "ct": "3ad77bb40d7a3660a89ecaf32466ef97",
    },
    {
        "name": "NIST SP 800-38A ECB #2",
        "key": "2b7e151628aed2a6abf7158809cf4f3c",
        "pt": "ae2d8a571e03ac9c9eb76fac45af8e51",
        "ct": "f5d3d58503b9699de785895a96fdbaaf",
    },
    {
        "name": "NIST SP 800-38A ECB #3",
        "key": "2b7e151628aed2a6abf7158809cf4f3c",
        "pt": "30c81c46a35ce411e5fbc1191a0a52ef",
        "ct": None,
    },
]


class TestNISTVectors(unittest.TestCase):
    def test_all_nist_vectors_encrypt_decrypt(self):
        for vec in NIST_VECTORS:
            key = bytes.fromhex(vec["key"])
            pt = bytes.fromhex(vec["pt"])
            expected_ct = vec["ct"]
            rks = expand_key(key)

            ct, etrace = encrypt_block(pt, rks, record=True)
            if expected_ct is not None:
                self.assertEqual(ct.hex(), expected_ct, f"{vec['name']} encrypt mismatch")

            dt, dtrace = decrypt_block(ct, rks, record=True)
            self.assertEqual(dt, pt, f"{vec['name']} decrypt mismatch")

    def test_fips_197_vector(self):
        vec = NIST_VECTORS[0]
        key = bytes.fromhex(vec["key"])
        pt = bytes.fromhex(vec["pt"])
        rks = expand_key(key)
        ct = encrypt_block(pt, rks)
        self.assertEqual(ct.hex(), vec["ct"])
        self.assertEqual(decrypt_block(ct, rks), pt)


def print_round_states(vec_name, key_hex, pt_hex):
    """Print round-by-round state for encryption and decryption."""
    key = bytes.fromhex(key_hex)
    pt = bytes.fromhex(pt_hex)
    rks = expand_key(key)

    print("=" * 70)
    print(f"NIST AES-128 Vector: {vec_name}")
    print(f"Key  : {key.hex()}")
    print(f"PT   : {pt.hex()}")
    print("=" * 70)

    ct, etrace = encrypt_block(pt, rks, record=True)
    print(f"\n[ENCRYPT] Ciphertext: {ct.hex()}")

    init = etrace["initial_add_round_key"]
    print(f"\n--- Initial AddRoundKey (RoundKey[0]) ---")
    print("before:")
    print(render_matrix(init["before"]))
    print("after:")
    print(render_matrix(init["after"]))

    for rnd in etrace["rounds"]:
        rn = rnd["round_no"]
        print(f"\n--- Round {rn} ---")
        print("[SubBytes] before:")
        print(render_matrix(rnd["sub_bytes"]["before"]))
        print("[SubBytes] after:")
        print(render_matrix(rnd["sub_bytes"]["after"]))
        print("[ShiftRows] before:")
        print(render_matrix(rnd["shift_rows"]["before"]))
        print("[ShiftRows] after:")
        print(render_matrix(rnd["shift_rows"]["after"]))
        print("[MixColumns] before:")
        print(render_matrix(rnd["mix_columns"]["before"]))
        print("[MixColumns] after:")
        print(render_matrix(rnd["mix_columns"]["after"]))
        for s in rnd["mix_columns"]["column0_detail"]["calc"]:
            print(f"  Col0: {s}")
        print("[AddRoundKey] before (RoundKey[{}]):".format(rnd["add_round_key"]["round_key_index"]))
        print(render_matrix(rnd["add_round_key"]["before"]))
        print("[AddRoundKey] after:")
        print(render_matrix(rnd["add_round_key"]["after"]))

    fr = etrace["final_round"]
    print(f"\n--- Final Round 10 (no MixColumns) ---")
    print("[SubBytes] before:")
    print(render_matrix(fr["sub_bytes"]["before"]))
    print("[SubBytes] after:")
    print(render_matrix(fr["sub_bytes"]["after"]))
    print("[ShiftRows] before:")
    print(render_matrix(fr["shift_rows"]["before"]))
    print("[ShiftRows] after:")
    print(render_matrix(fr["shift_rows"]["after"]))
    print("[AddRoundKey] before (RoundKey[10]):")
    print(render_matrix(fr["add_round_key"]["before"]))
    print("[AddRoundKey] after:")
    print(render_matrix(fr["add_round_key"]["after"]))

    dt, dtrace = decrypt_block(ct, rks, record=True)
    print(f"\n[DECRYPT] Plaintext: {dt.hex()} (match: {dt == pt})")

    initd = dtrace["initial_add_round_key"]
    print(f"\n--- Initial AddRoundKey (RoundKey[10]) ---")
    print("before:")
    print(render_matrix(initd["before"]))
    print("after:")
    print(render_matrix(initd["after"]))

    for rnd in dtrace["rounds"]:
        rn = rnd["round_no"]
        print(f"\n--- Round {rn} ---")
        print("[InvShiftRows] before:")
        print(render_matrix(rnd["inv_shift_rows"]["before"]))
        print("[InvShiftRows] after:")
        print(render_matrix(rnd["inv_shift_rows"]["after"]))
        print("[InvSubBytes] before:")
        print(render_matrix(rnd["inv_sub_bytes"]["before"]))
        print("[InvSubBytes] after:")
        print(render_matrix(rnd["inv_sub_bytes"]["after"]))
        print("[AddRoundKey] before (RoundKey[{}]):".format(rnd["add_round_key"]["round_key_index"]))
        print(render_matrix(rnd["add_round_key"]["before"]))
        print("[AddRoundKey] after:")
        print(render_matrix(rnd["add_round_key"]["after"]))
        print("[InvMixColumns] before:")
        print(render_matrix(rnd["inv_mix_columns"]["before"]))
        print("[InvMixColumns] after:")
        print(render_matrix(rnd["inv_mix_columns"]["after"]))

    frd = dtrace["final_round"]
    print(f"\n--- Final Round 0 (no InvMixColumns) ---")
    print("[InvShiftRows] before:")
    print(render_matrix(frd["inv_shift_rows"]["before"]))
    print("[InvShiftRows] after:")
    print(render_matrix(frd["inv_shift_rows"]["after"]))
    print("[InvSubBytes] before:")
    print(render_matrix(frd["inv_sub_bytes"]["before"]))
    print("[InvSubBytes] after:")
    print(render_matrix(frd["inv_sub_bytes"]["after"]))
    print("[AddRoundKey] before (RoundKey[0]):")
    print(render_matrix(frd["add_round_key"]["before"]))
    print("[AddRoundKey] after:")
    print(render_matrix(frd["add_round_key"]["after"]))


if __name__ == "__main__":
    # Run the unit tests first
    unittest.main(exit=False, verbosity=2)

    # Then print detailed round states for the first vector
    print("\n\n")
    v = NIST_VECTORS[0]
    print_round_states(v["name"], v["key"], v["pt"])
