"""Step6: 篡改检测 (CBC 静默出错 vs GCM 认证失败).

写入 ctx.samples 的键：
- step6.cbc_tamper: dict
- step6.gcm_note: dict
- step6.table: list[list[str]] (表格 header + rows)
"""
from aes.cipher import encrypt_block, decrypt_block
from steps.step5_modes import _xor, _cbc_encrypt, _cbc_decrypt
from utils import formatting as F


def run(ctx):
    F.info("Step 6: 篡改检测")
    if not ctx.round_keys:
        raise ValueError("请先运行 Step 2 密钥扩展")
    rk = ctx.round_keys

    pt = b"A" * 16 + b"A" * 16
    iv = bytes([0] * 16)
    ct = _cbc_encrypt(pt, iv, rk)

    # 正常解密
    normal = _cbc_decrypt(ct, iv, rk)
    normal_ok = normal == pt
    F.ok(f"CBC 正常解密: {'正确' if normal_ok else '错误'}")

    # 翻转密文第 1 块第 0 字节
    ct_tampered = bytearray(ct)
    ct_tampered[0] ^= 0x01
    ct_tampered = bytes(ct_tampered)
    tampered = _cbc_decrypt(ct_tampered, iv, rk)
    # 第 1 块明文错乱，第 2 块第 0 字节也受影响
    block1_corrupt = tampered[:16] != pt[:16]
    block2_byte_affected = tampered[16] != pt[16]
    F.info(f"CBC 篡改后: 第1块明文{'错乱' if block1_corrupt else '正确'}, 第2块第0字节{'受影响' if block2_byte_affected else '不受影响'}")
    F.info("CBC 翻转密文字节不抛异常，但导致对应明文块错乱及下一块对应字节受影响")

    # GCM 概念
    F.info("GCM: 翻转 1 字节 → 认证标签不匹配 → 抛认证失败异常（不实现算法，仅概念说明）")

    table_header = ["模式", "改动位置", "解密是否报错", "明文是否正确", "结论"]
    table_rows = [
        ["CBC", "密文第1块第0字节", "否", "否", "静默出错，明文错乱并传播至下一块"],
        ["GCM", "任意密文 1 字节", "是", "否", "认证失败抛异常"],
    ]
    table = [table_header] + table_rows
    print(F.render_table(table_header, table_rows))

    ctx.tamper = {
        "cbc": {"normal_ok": normal_ok, "block1_corrupt": block1_corrupt, "block2_byte_affected": block2_byte_affected},
        "gcm": "concept",
    }
    ctx.samples["step6.cbc_tamper"] = {
        "normal": normal.hex(),
        "tampered": tampered.hex(),
        "error": False,
        "correct": normal_ok,
    }
    ctx.samples["step6.gcm_note"] = {
        "说明": "GCM 翻转 1 字节导致认证标签不匹配，抛认证失败异常",
        "结论": "GCM 提供完整性保护",
    }
    ctx.samples["step6.table"] = table
    if 6 not in ctx.steps_done:
        ctx.steps_done.append(6)
    F.ok("Step 6 完成")
