"""Step1: 明文分组与 PKCS#7 填充.

写入 ctx.samples 的键：
- step1.plaintext_hex: str
- step1.padding: int
- step1.blocks: list[str]
"""
from aes.padding import pad, split_blocks
from utils import formatting as F


def run(ctx):
    F.info("Step 1: 明文分组与 PKCS#7 填充")
    ctx.plaintext_bytes = ctx.plaintext.encode("utf-8")
    ctx.padded = pad(ctx.plaintext_bytes)
    ctx.padding_len = len(ctx.padded) - len(ctx.plaintext_bytes)
    ctx.blocks = split_blocks(ctx.padded)

    F.info(f"明文: {ctx.plaintext!r}")
    F.info(f"明文字节 (hex): {F.render_hex(ctx.plaintext_bytes)}")
    F.info(f"明文长度: {len(ctx.plaintext_bytes)} 字节")
    F.info(f"填充字节数: {ctx.padding_len}，填充字节值: 0x{ctx.padding_len:02x}")
    F.info(f"填充前: {F.render_hex(ctx.plaintext_bytes)}")
    F.info(f"填充后: {F.render_hex(ctx.padded)}")
    F.info("分组 (每块 16 字节):")
    for i, b in enumerate(ctx.blocks):
        F.info(f"  块 {i}: {F.render_hex(b)}")

    if len(ctx.plaintext_bytes) % 16 == 0:
        F.info("特别提示: 明文恰为 16 字节倍数，仍追加整块 0x10 (16 个 0x10 字节)。")
        F.info("示例: 16 字节明文 \"Hello AES 教学!\" (若恰好16字节) 将追加 16 个 0x10。")

    ctx.samples["step1.plaintext_hex"] = ctx.plaintext_bytes.hex()
    ctx.samples["step1.padding"] = ctx.padding_len
    ctx.samples["step1.blocks"] = [b.hex() for b in ctx.blocks]
    if 1 not in ctx.steps_done:
        ctx.steps_done.append(1)
    F.ok("Step 1 完成")
