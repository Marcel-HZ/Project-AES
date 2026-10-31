"""Main entry: AES 教学项目."""
import argparse
import os
import sys

from context import Context
from utils import formatting as F
from utils.markdown import save_guide
import steps.step1_padding as s1
import steps.step2_key_expansion as s2
import steps.step3_encrypt_round as s3
import steps.step4_decrypt_round as s4
import steps.step5_modes as s5
import steps.step6_tamper as s6

STEPS = {1: s1, 2: s2, 3: s3, 4: s4, 5: s5, 6: s6}

# 步骤依赖：步骤号 -> 需要的 ctx 字段名
DEPS = {
    1: [],
    2: ["key_bytes"],
    3: ["round_keys", "blocks"],
    4: ["ciphertext", "round_keys", "plaintext_bytes"],
    5: ["round_keys"],
    6: ["round_keys"],
}

# 单步重置字段：步骤号 -> 需要清空的 ctx 字段
RESET_FIELDS = {
    1: ["plaintext_bytes", "padded", "padding_len", "blocks"],
    2: ["round_keys", "key_expansion_trace"],
    3: ["encrypt_trace", "ciphertext", "round_snapshots"],
    4: ["decrypted_padded", "decrypted", "decrypt_trace"],
    5: ["modes"],
    6: ["tamper"],
}


def _reset_step(ctx, n):
    for f in RESET_FIELDS.get(n, []):
        if isinstance(getattr(ctx, f), list):
            setattr(ctx, f, [])
        elif isinstance(getattr(ctx, f), dict):
            setattr(ctx, f, {})
        else:
            setattr(ctx, f, type(getattr(ctx, f))())


def _check_deps(ctx, n):
    missing = [f for f in DEPS.get(n, []) if not getattr(ctx, f)]
    if missing:
        raise ValueError(f"缺少依赖: {', '.join(missing)}，请先运行前置步骤")


def run_step(ctx, n):
    _check_deps(ctx, n)
    _reset_step(ctx, n)
    STEPS[n].run(ctx)
    save_guide(ctx)


def _print_banner():
    print("═" * 64)
    print("AES 加密原理与实战教学项目")
    print("声明: 纯 Python 实现 AES-128，仅用于教学可视化，")
    print("      明确不用于生产环境。")
    print("═" * 64)


def main():
    parser = argparse.ArgumentParser(description="AES 教学项目")
    parser.add_argument("--text", default=None, help="明文（默认交互输入）")
    parser.add_argument("--key", default=None, help="密钥 hex，格式 hex:......")
    parser.add_argument("--no-pause", action="store_true", help="禁用暂停")
    parser.add_argument("--run-all", action="store_true", help="依次运行 1-6 步")
    args = parser.parse_args()

    _print_banner()

    text = args.text if args.text is not None else input("请输入明文：")
    if text == "":
        text = "Hello AES 教学!"
    if args.key:
        k = args.key
        if k.startswith("hex:"):
            k = k[4:]
        key = bytes.fromhex(k)
        if len(key) != 16:
            F.err("密钥必须为 16 字节（32 个 hex 字符）")
            sys.exit(1)
    else:
        key = os.urandom(16)
    print("密钥:", key.hex())

    ctx = Context(plaintext=text, key_bytes=key)

    if args.run_all:
        for n in range(1, 7):
            try:
                run_step(ctx, n)
            except Exception as e:
                F.err(f"Step {n} 失败: {e}")
                break
            if not args.no_pause:
                F.pause()
        return

    while True:
        try:
            cmd = input("菜单 (1-6/a/s/q): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if cmd in ("q",):
            if ctx.steps_done:
                save_guide(ctx)
            break
        if cmd == "a":
            for n in range(1, 7):
                try:
                    run_step(ctx, n)
                except Exception as e:
                    F.err(f"Step {n} 失败: {e}")
                    break
                if not args.no_pause:
                    F.pause()
            continue
        if cmd == "s":
            print(f"明文: {ctx.plaintext!r}")
            print(f"密钥: {ctx.key_bytes.hex()}")
            print(f"密文: {ctx.ciphertext.hex()}")
            print(f"已运行步骤: {ctx.steps_done}")
            continue
        if cmd in ("1", "2", "3", "4", "5", "6"):
            try:
                run_step(ctx, int(cmd))
            except Exception as e:
                F.err(str(e))
            continue
        F.warn("非法输入")


if __name__ == "__main__":
    main()
