"""Markdown guide builder."""
from pathlib import Path


def _hex(b: bytes) -> str:
    return " ".join(f"{x:02x}" for x in b)


def _matrix(b: bytes) -> str:
    lines = []
    for r in range(4):
        row = " ".join(f"{b[r + 4 * c]:02x}" for c in range(4))
        lines.append(f"│ {row} │")
    return "\n".join(lines)


def _detail(detail: dict) -> str:
    if not detail:
        return ""
    lines = []
    lines.append("  第 0 列输入: " + _hex(bytes(detail["inputs"])))
    lines.append("  第 0 列输出: " + _hex(bytes(detail["outputs"])))
    for s in detail["calc"]:
        lines.append(f"  {s}")
    return "\n".join(lines)


def build_guide(ctx) -> str:
    lines = ["# AES 加密原理与实战教学", ""]
    headings = [
        ("0", "## 0. 本次样本"),
        ("1", "## 1. 明文分组与 PKCS#7 填充"),
        ("2", "## 2. 密钥扩展"),
        ("3", "## 3. 加密过程（第 1 轮详解 + 第 2–10 轮快照）"),
        ("4", "## 4. 解密过程（逆序详解 + 明文比对）"),
        ("5", "## 5. 分组模式对比（ECB / CBC / GCM）"),
        ("6", "## 6. 篡改检测（CBC 静默出错 vs GCM 认证失败）"),
        ("7", "## 7. 安全说明与结论"),
    ]
    done = set(ctx.steps_done)

    for num, h in headings:
        lines.append(h)
        lines.append("")

        if num == "0":
            lines.append(f"- 明文: {ctx.plaintext!r}")
            lines.append(f"- 明文字节长度: {len(ctx.plaintext_bytes)}")
            lines.append(f"- 密钥 (hex): {ctx.key_bytes.hex()}")
            lines.append(f"- 填充后总块数: {len(ctx.blocks)}")
            if ctx.ciphertext:
                lines.append(f"- 密文 (hex): {ctx.ciphertext.hex()}")
            lines.append("")
            continue

        step_no = int(num)
        if step_no not in done:
            lines.append("> 未运行")
            lines.append("")
            continue

        if step_no == 1:
            lines.append("### 明文与填充")
            lines.append("")
            lines.append("```text")
            lines.append(f"明文: {ctx.plaintext!r}")
            lines.append(f"明文字节 (hex): {_hex(ctx.plaintext_bytes)}")
            lines.append(f"明文长度: {len(ctx.plaintext_bytes)} 字节")
            lines.append(f"填充长度: {ctx.padding_len} 字节 (每个字节值 0x{ctx.padding_len:02x})")
            lines.append("填充前后对照:")
            lines.append(f"  填充前: {_hex(ctx.plaintext_bytes)}")
            lines.append(f"  填充后: {_hex(ctx.padded)}")
            lines.append("分组 (每块 16 字节):")
            for i, b in enumerate(ctx.blocks):
                lines.append(f"  块 {i}: {_hex(b)}")
            lines.append("```")
            lines.append("")
            continue

        if step_no == 2:
            lines.append("### 密钥扩展 (AES-128)")
            lines.append("")
            lines.append(f"原始密钥 (hex): {_hex(ctx.key_bytes)}")
            lines.append("")
            lines.append("44 个扩展字 (w[0]..w[43]):")
            lines.append("```text")
            words = ctx.samples.get("step2.words", [])
            for i, w in enumerate(words):
                lines.append(f"  w[{i:2d}]: {w}")
            lines.append("```")
            lines.append("")
            lines.append("Rcon 使用记录 (i % 4 == 0 的字):")
            lines.append("```text")
            for rec in ctx.samples.get("step2.rcon_examples", []):
                lines.append(f"  i={rec['i']}: rcon={rec['rcon']:02x}")
            lines.append("```")
            lines.append("")
            lines.append("11 个 Round Key:")
            lines.append("```text")
            for i, rk in enumerate(ctx.samples.get("step2.round_keys", [])):
                lines.append(f"  RoundKey[{i}]: {rk}")
            lines.append("```")
            lines.append("")
            continue

        if step_no == 3:
            trace = ctx.encrypt_trace
            lines.append("### 加密过程 (第一块)")
            lines.append("")
            lines.append("初始 AddRoundKey (RoundKey[0]):")
            lines.append("```text")
            init = trace["initial_add_round_key"]
            lines.append("before:")
            lines.append(_matrix(init["before"]))
            lines.append("after:")
            lines.append(_matrix(init["after"]))
            lines.append("```")
            lines.append("")
            r1 = trace["rounds"][0]
            lines.append("第 1 轮详解:")
            lines.append("")
            lines.append("SubBytes:")
            lines.append("```text")
            lines.append("before:")
            lines.append(_matrix(r1["sub_bytes"]["before"]))
            lines.append("after:")
            lines.append(_matrix(r1["sub_bytes"]["after"]))
            lines.append("典型映射: 0x00 → 0x63")
            lines.append("```")
            lines.append("")
            lines.append("ShiftRows:")
            lines.append("```text")
            lines.append("before:")
            lines.append(_matrix(r1["shift_rows"]["before"]))
            lines.append("after:")
            lines.append(_matrix(r1["shift_rows"]["after"]))
            lines.append("每行左循环位移: 第0行0、第1行1、第2行2、第3行3")
            lines.append("```")
            lines.append("")
            lines.append("MixColumns:")
            lines.append("```text")
            lines.append("before:")
            lines.append(_matrix(r1["mix_columns"]["before"]))
            lines.append("after:")
            lines.append(_matrix(r1["mix_columns"]["after"]))
            lines.append(_detail(r1["mix_columns"]["column0_detail"]))
            lines.append("```")
            lines.append("")
            lines.append("AddRoundKey (RoundKey[1]):")
            lines.append("```text")
            ark = r1["add_round_key"]
            lines.append("before:")
            lines.append(_matrix(ark["before"]))
            lines.append("after:")
            lines.append(_matrix(ark["after"]))
            lines.append("```")
            lines.append("")
            lines.append("第 2–10 轮快照:")
            lines.append("```text")
            for rnd in trace["rounds"][1:]:
                rk_hex = rnd["add_round_key"]["after"][:4].hex()
                st_hex = rnd["add_round_key"]["after"][:4].hex()
                note = "" if rnd["round_no"] < 10 else " (末轮，无 MixColumns)"
                lines.append(f"  Round {rnd['round_no']}: round_key前4字节={rk_hex}, 状态前4字节={st_hex}{note}")
            lines.append("```")
            lines.append("")
            lines.append(f"最终密文 (hex): {ctx.ciphertext.hex()}")
            lines.append(f"最终密文 (base64): {__import__('base64').b64encode(ctx.ciphertext).decode()}")
            lines.append("")
            continue

        if step_no == 4:
            dtrace = ctx.decrypt_trace
            lines.append("### 解密过程 (第一块)")
            lines.append("")
            lines.append("操作顺序 (与加密相反):")
            lines.append("初始 AddRoundKey[10] → InvShiftRows → InvSubBytes → AddRoundKey[9] → InvMixColumns → … → AddRoundKey[0]")
            lines.append("")
            lines.append("初始 AddRoundKey (RoundKey[10]):")
            lines.append("```text")
            init = dtrace["initial_add_round_key"]
            lines.append("before:")
            lines.append(_matrix(init["before"]))
            lines.append("after:")
            lines.append(_matrix(init["after"]))
            lines.append("```")
            lines.append("")
            r1 = dtrace["rounds"][0]
            lines.append("第 1 个解密轮 (round 9):")
            lines.append("")
            lines.append("InvShiftRows:")
            lines.append("```text")
            lines.append("before:")
            lines.append(_matrix(r1["inv_shift_rows"]["before"]))
            lines.append("after:")
            lines.append(_matrix(r1["inv_shift_rows"]["after"]))
            lines.append("```")
            lines.append("")
            lines.append("InvSubBytes:")
            lines.append("```text")
            lines.append("before:")
            lines.append(_matrix(r1["inv_sub_bytes"]["before"]))
            lines.append("after:")
            lines.append(_matrix(r1["inv_sub_bytes"]["after"]))
            lines.append("```")
            lines.append("")
            lines.append("AddRoundKey (RoundKey[9]):")
            lines.append("```text")
            ark = r1["add_round_key"]
            lines.append("before:")
            lines.append(_matrix(ark["before"]))
            lines.append("after:")
            lines.append(_matrix(ark["after"]))
            lines.append("```")
            lines.append("")
            lines.append("InvMixColumns:")
            lines.append("```text")
            lines.append("before:")
            lines.append(_matrix(r1["inv_mix_columns"]["before"]))
            lines.append("after:")
            lines.append(_matrix(r1["inv_mix_columns"]["after"]))
            lines.append("```")
            lines.append("")
            lines.append("去填充前后对照:")
            lines.append("```text")
            lines.append(f"  去填充前: {_hex(ctx.decrypted_padded)}")
            lines.append(f"  去填充后: {_hex(ctx.decrypted)}")
            lines.append("```")
            lines.append("")
            lines.append(f"明文比对: {'✅ 一致' if ctx.decrypted == ctx.plaintext_bytes else '❌ 不一致'}")
            lines.append("")
            continue

        if step_no == 5:
            lines.append("### 分组模式对比")
            lines.append("")
            table = ctx.samples.get("step5.table", [])
            if table:
                lines.append("```text")
                lines.append(" | ".join(table[0]))
                for row in table[1:]:
                    lines.append(" | ".join(str(x) for x in row))
                lines.append("```")
            else:
                lines.append("> 无对比数据")
            lines.append("")
            ecb = ctx.samples.get("step5.ecb", {})
            cbc = ctx.samples.get("step5.cbc", {})
            gcm = ctx.samples.get("step5.gcm_note", {})
            if ecb:
                lines.append("ECB 结果:")
                lines.append("```text")
                lines.append(f"  明文: {ecb.get('plaintext', '')}")
                lines.append(f"  密文块0: {ecb.get('ct0', '')}")
                lines.append(f"  密文块1: {ecb.get('ct1', '')}")
                lines.append(f"  两块相同: {ecb.get('same', False)}")
                lines.append("```")
            if cbc:
                lines.append("CBC 结果:")
                lines.append("```text")
                lines.append(f"  IV0: {cbc.get('iv0', '')}")
                lines.append(f"  IV1: {cbc.get('iv1', '')}")
                lines.append(f"  密文块0 (IV0): {cbc.get('ct0_iv0', '')}")
                lines.append(f"  密文块0 (IV1): {cbc.get('ct0_iv1', '')}")
                lines.append("  相同明文块在不同 IV 下密文不同")
                lines.append("```")
            if gcm:
                lines.append("GCM 概念:")
                lines.append("```text")
                for k, v in gcm.items():
                    lines.append(f"  {k}: {v}")
                lines.append("```")
            lines.append("")
            continue

        if step_no == 6:
            lines.append("### 篡改检测")
            lines.append("")
            table = ctx.samples.get("step6.table", [])
            if table:
                lines.append("```text")
                lines.append(" | ".join(table[0]))
                for row in table[1:]:
                    lines.append(" | ".join(str(x) for x in row))
                lines.append("```")
            lines.append("")
            tamper = ctx.samples.get("step6.cbc_tamper", {})
            if tamper:
                lines.append("CBC 篡改演示:")
                lines.append("```text")
                lines.append(f"  正常解密: {tamper.get('normal', '')}")
                lines.append(f"  篡改后解密: {tamper.get('tampered', '')}")
                lines.append(f"  解密是否报错: {tamper.get('error', False)}")
                lines.append(f"  明文是否正确: {tamper.get('correct', False)}")
                lines.append("  结论: CBC 翻转密文字节导致对应明文块错乱，且影响下一块对应字节，但不抛异常")
                lines.append("```")
            gcm_note = ctx.samples.get("step6.gcm_note", {})
            if gcm_note:
                lines.append("GCM 篡改检测:")
                lines.append("```text")
                for k, v in gcm_note.items():
                    lines.append(f"  {k}: {v}")
                lines.append("  结论: GCM 翻转 1 字节导致认证标签不匹配，抛认证失败异常")
                lines.append("```")
            lines.append("")
            continue

        if step_no == 7:
            lines.append("### 安全说明与结论")
            lines.append("")
            lines.append("本项目为纯 Python 教学实现，存在以下安全局限：")
            lines.append("- 无侧信道防护（非常量时间，易受时序/缓存攻击）")
            lines.append("- 无认证加密（ECB/CBC 均易受篡改与重放攻击）")
            lines.append("- 密钥管理缺失（密钥由 os.urandom 生成，未持久化或派生）")
            lines.append("")
            lines.append("生产环境建议：")
            lines.append("- 使用 `cryptography` 库的 `AESGCM` 提供认证加密")
            lines.append("- 使用随机 nonce，严禁 nonce 复用")
            lines.append("- 使用 KDF（如 PBKDF2 / HKDF）从口令派生密钥")
            lines.append("")
            continue

        lines.append("> 未运行")
        lines.append("")

    return "\n".join(lines)


def save_guide(ctx, path="AES_DEMO_GUIDE.md"):
    root = Path(__file__).resolve().parent.parent
    out = root / path
    out.write_text(build_guide(ctx), encoding="utf-8")
    return str(out.resolve())
