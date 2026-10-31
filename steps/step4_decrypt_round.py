"""Step4: 解密过程.

写入 ctx.samples 的键：
- step4.decrypt_round1: dict (完整 decrypt trace)
- step4.unpad: str (去填充后 hex)
- step4.compare: str ("一致" / "不一致")
"""
from aes.cipher import decrypt_block
from aes.padding import unpad
from utils import formatting as F


def run(ctx):
    F.info("Step 4: 解密过程 (逐轮跟踪)")
    if not ctx.ciphertext:
        raise ValueError("请先运行 Step 3 加密")
    if not ctx.round_keys:
        raise ValueError("请先运行 Step 2 密钥扩展")

    F.info("解密操作顺序 (与加密相反):")
    F.info("初始 AddRoundKey[10] → InvShiftRows → InvSubBytes → AddRoundKey[9] → InvMixColumns → … → AddRoundKey[0]")

    res, dtrace = decrypt_block(ctx.ciphertext[:16], ctx.round_keys, record=True)
    ctx.decrypt_trace = dtrace

    full = res
    n_blocks = len(ctx.ciphertext) // 16
    for i in range(1, n_blocks):
        full += decrypt_block(ctx.ciphertext[i * 16:(i + 1) * 16], ctx.round_keys)
    ctx.decrypted_padded = full

    try:
        ctx.decrypted = unpad(full)
        unpad_ok = True
    except ValueError as e:
        F.err(f"unpad 失败: {e}")
        ctx.decrypted = full
        unpad_ok = False

    # 初始 AddRoundKey
    init = dtrace["initial_add_round_key"]
    print(F.render_before_after(init["before"], init["after"],
                                "初始 AddRoundKey (RoundKey[10])"))

    # 第 1 个解密轮 (round 9)
    r1 = dtrace["rounds"][0]
    print(F.render_before_after(r1["inv_shift_rows"]["before"], r1["inv_shift_rows"]["after"],
                                "第 1 解密轮 InvShiftRows"))
    print(F.render_before_after(r1["inv_sub_bytes"]["before"], r1["inv_sub_bytes"]["after"],
                                "第 1 解密轮 InvSubBytes"))
    print(F.render_before_after(r1["add_round_key"]["before"], r1["add_round_key"]["after"],
                                "第 1 解密轮 AddRoundKey (RoundKey[9])"))
    print(F.render_before_after(r1["inv_mix_columns"]["before"], r1["inv_mix_columns"]["after"],
                                "第 1 解密轮 InvMixColumns"))

    F.info(f"去填充前: {F.render_hex(ctx.decrypted_padded)}")
    F.info(f"去填充后: {F.render_hex(ctx.decrypted)}")

    match = (ctx.decrypted == ctx.plaintext_bytes)
    cmp_str = "一致" if match else "不一致"
    F.info(f"明文比对: {'✅' if match else '❌'} {cmp_str}")

    ctx.samples["step4.decrypt_round1"] = dtrace
    ctx.samples["step4.unpad"] = ctx.decrypted.hex()
    ctx.samples["step4.compare"] = cmp_str
    if 4 not in ctx.steps_done:
        ctx.steps_done.append(4)
    F.ok("Step 4 完成")
