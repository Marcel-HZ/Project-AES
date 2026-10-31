"""Step3: 加密过程.

写入 ctx.samples 的键：
- step3.round1: dict (完整 encrypt trace)
- step3.round_snapshots: list[str] (每轮 AddRoundKey 后状态 hex)
- step3.ciphertext: str (密文 hex)
"""
import base64
from aes.cipher import encrypt_block
from aes.padding import pad, split_blocks
from utils import formatting as F


def run(ctx):
    F.info("Step 3: 加密过程 (逐轮跟踪)")
    if not ctx.blocks:
        ctx.plaintext_bytes = ctx.plaintext.encode("utf-8")
        ctx.padded = pad(ctx.plaintext_bytes)
        ctx.blocks = split_blocks(ctx.padded)
    if not ctx.round_keys:
        raise ValueError("请先运行 Step 2 密钥扩展")

    res, trace = encrypt_block(ctx.blocks[0], ctx.round_keys, record=True)
    ctx.encrypt_trace = trace
    ctx.round_snapshots = []
    for rnd in trace["rounds"]:
        ctx.round_snapshots.append(rnd["add_round_key"]["after"])
    ctx.round_snapshots.append(trace["final_round"]["add_round_key"]["after"])

    ct = res
    for b in ctx.blocks[1:]:
        ct += encrypt_block(b, ctx.round_keys)
    ctx.ciphertext = ct

    # 初始 AddRoundKey
    init = trace["initial_add_round_key"]
    print(F.render_before_after(init["before"], init["after"],
                                "初始 AddRoundKey (RoundKey[0])"))

    # 第 1 轮
    r1 = trace["rounds"][0]
    print(F.render_before_after(r1["sub_bytes"]["before"], r1["sub_bytes"]["after"],
                                "第 1 轮 SubBytes"))
    F.info("典型映射: 0x00 → 0x63")
    print(F.render_before_after(r1["shift_rows"]["before"], r1["shift_rows"]["after"],
                                "第 1 轮 ShiftRows"))
    F.info("每行左循环位移: 第0行0、第1行1、第2行2、第3行3")
    print(F.render_before_after(r1["mix_columns"]["before"], r1["mix_columns"]["after"],
                                "第 1 轮 MixColumns"))
    detail = r1["mix_columns"]["column0_detail"]
    F.info("第 0 列 GF 计算式:")
    for s in detail["calc"]:
        F.info(f"  {s}")
    print(F.render_before_after(r1["add_round_key"]["before"], r1["add_round_key"]["after"],
                                "第 1 轮 AddRoundKey (RoundKey[1])"))

    # 第 2–10 轮摘要
    F.info("第 2–10 轮每轮摘要:")
    for rnd in trace["rounds"][1:]:
        rk = rnd["add_round_key"]["after"][:4]
        st = rnd["add_round_key"]["after"][:4]
        note = "" if rnd["round_no"] < 10 else " (末轮，无 MixColumns)"
        F.info(f"  Round {rnd['round_no']}: round key 前4字节={F.render_hex(rk)}, 状态前4字节={F.render_hex(st)}{note}")

    F.info(f"最终密文 (hex): {ctx.ciphertext.hex()}")
    F.info(f"最终密文 (base64): {base64.b64encode(ctx.ciphertext).decode()}")

    ctx.samples["step3.round1"] = trace
    ctx.samples["step3.round_snapshots"] = [s.hex() for s in ctx.round_snapshots]
    ctx.samples["step3.ciphertext"] = ctx.ciphertext.hex()
    if 3 not in ctx.steps_done:
        ctx.steps_done.append(3)
    F.ok("Step 3 完成")
