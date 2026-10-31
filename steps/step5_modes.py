"""Step5: 分组模式对比 (ECB / CBC / GCM 概念).

写入 ctx.samples 的键：
- step5.ecb: dict
- step5.cbc: dict
- step5.gcm_note: dict
- step5.table: list[list[str]] (表格 header + rows)
"""
from aes.cipher import encrypt_block, decrypt_block
from utils import formatting as F


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _ecb_encrypt(plaintext: bytes, round_keys: list) -> bytes:
    out = b""
    for i in range(0, len(plaintext), 16):
        out += encrypt_block(plaintext[i:i + 16], round_keys)
    return out


def _cbc_encrypt(plaintext: bytes, iv: bytes, round_keys: list) -> bytes:
    out = b""
    prev = iv
    for i in range(0, len(plaintext), 16):
        block = _xor(plaintext[i:i + 16], prev)
        enc = encrypt_block(block, round_keys)
        out += enc
        prev = enc
    return out


def _cbc_decrypt(ciphertext: bytes, iv: bytes, round_keys: list) -> bytes:
    out = b""
    prev = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        dec = decrypt_block(block, round_keys)
        out += _xor(dec, prev)
        prev = block
    return out


def run(ctx):
    F.info("Step 5: 分组模式对比 (ECB / CBC / GCM)")
    if not ctx.round_keys:
        raise ValueError("请先运行 Step 2 密钥扩展")
    rk = ctx.round_keys

    pt = b"A" * 16 + b"A" * 16  # 两块相同

    # ECB
    ct_ecb = _ecb_encrypt(pt, rk)
    ecb_same = ct_ecb[:16] == ct_ecb[16:32]
    F.info(f"ECB: 明文两块相同，密文两块{'相同' if ecb_same else '不同'} → {'图案泄露' if ecb_same else '无泄露'}")

    # CBC with two different IVs
    iv0 = bytes([0] * 16)
    iv1 = bytes([1] * 16)
    ct_cbc_iv0 = _cbc_encrypt(pt, iv0, rk)
    ct_cbc_iv1 = _cbc_encrypt(pt, iv1, rk)
    cbc_diff = ct_cbc_iv0[:16] != ct_cbc_iv1[:16]
    F.info(f"CBC: 不同 IV 下相同明文块密文{'不同' if cbc_diff else '相同'}")

    # Verify CBC decrypt
    dec_iv0 = _cbc_decrypt(ct_cbc_iv0, iv0, rk)
    F.ok(f"CBC 解密还原: {dec_iv0 == pt}")

    # GCM concept only
    F.info("GCM: 不实现算法，仅概念说明（提供认证、nonce 不可复用）")

    ctx.modes = {
        "ecb": {"same": ecb_same, "ct": ct_ecb.hex()},
        "cbc": {"iv0": iv0.hex(), "iv1": iv1.hex(),
                "ct0_iv0": ct_cbc_iv0.hex(), "ct0_iv1": ct_cbc_iv1.hex(), "diff": cbc_diff},
        "gcm": "concept",
    }

    table_header = ["模式", "是否需要 IV", "相同块是否泄露", "是否提供认证", "本演示结果"]
    table_rows = [
        ["ECB", "否", "是" if ecb_same else "否", "否", "两块密文相同 → 图案泄露"],
        ["CBC", "是", "否", "否", f"不同 IV 密文{'不同' if cbc_diff else '相同'}"],
        ["GCM", "是 (nonce)", "否", "是", "概念说明，生产请用 cryptography AESGCM"],
    ]
    table = [table_header] + table_rows
    print(F.render_table(table_header, table_rows))

    ctx.samples["step5.ecb"] = {
        "plaintext": pt.hex(),
        "ct0": ct_ecb[:16].hex(),
        "ct1": ct_ecb[16:32].hex(),
        "same": ecb_same,
    }
    ctx.samples["step5.cbc"] = {
        "iv0": iv0.hex(),
        "iv1": iv1.hex(),
        "ct0_iv0": ct_cbc_iv0[:16].hex(),
        "ct0_iv1": ct_cbc_iv1[:16].hex(),
    }
    ctx.samples["step5.gcm_note"] = {
        "说明": "GCM 提供认证加密，nonce 不可复用",
        "建议": "生产请用 cryptography 库的 AESGCM",
    }
    ctx.samples["step5.table"] = table
    if 5 not in ctx.steps_done:
        ctx.steps_done.append(5)
    F.ok("Step 5 完成")
