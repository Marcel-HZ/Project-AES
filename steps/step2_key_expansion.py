"""Step2: 密钥扩展.

写入 ctx.samples 的键：
- step2.words: list[str]  (44 个 word 的 hex)
- step2.rcon_examples: list[dict] (rot_sub_xor_steps 中间值)
- step2.round_keys: list[str] (11 个 round key hex)
"""
from aes.key_expansion import expand_key_trace
from utils import formatting as F


def _word_hex(w: bytes) -> str:
    return F.render_hex(w)


def run(ctx):
    F.info("Step 2: 密钥扩展 (AES-128)")
    trace = expand_key_trace(ctx.key_bytes)
    ctx.round_keys = trace["round_keys"]
    ctx.key_expansion_trace = trace

    words = trace["w"]
    F.info(f"原始密钥 (hex): {F.render_hex(ctx.key_bytes)}")
    F.info("原始密钥 4 个 word:")
    for i in range(4):
        F.info(f"  w[{i}]: {_word_hex(words[i])}")

    F.info("i % 4 == 0 的字的 RotWord → SubWord → Rcon → XOR 中间值:")
    steps = trace["rot_sub_xor_steps"]
    rows = []
    for idx, s in enumerate(steps):
        i = s["i"]
        detail = i in (4, 8)
        if detail:
            rows.append([
                str(i),
                f"{s['before']:08x}",
                f"{s['rotword']:08x}",
                f"{s['subword']:08x}",
                f"{s['rcon']:02x}",
                f"{s['after_xor']:08x}",
                "是 (示例)",
            ])
        else:
            rows.append([
                str(i),
                f"{s['before']:08x}",
                f"{s['rotword']:08x}",
                f"{s['subword']:08x}",
                f"{s['rcon']:02x}",
                f"{s['after_xor']:08x}",
                "否",
            ])
    headers = ["i", "before", "RotWord", "SubWord", "Rcon", "after XOR", "详细展开"]
    print(F.render_table(headers, rows))

    F.info("11 个 Round Key (hex):")
    for i, rk in enumerate(ctx.round_keys):
        F.info(f"  RoundKey[{i}]: {F.render_hex(rk)}")

    ctx.samples["step2.words"] = [_word_hex(w) for w in words]
    ctx.samples["step2.rcon_examples"] = steps
    ctx.samples["step2.round_keys"] = [rk.hex() for rk in ctx.round_keys]
    if 2 not in ctx.steps_done:
        ctx.steps_done.append(2)
    F.ok("Step 2 完成")
