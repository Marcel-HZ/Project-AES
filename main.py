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
    print()
    print("【步骤说明】")
    print("  1  明文分组与 PKCS#7 填充   UTF-8 编码、PKCS#7 填充、16 字节分组")
    print("  2  密钥扩展                AES-128 密钥扩展，生成 11 个 Round Key")
    print("  3  加密过程                逐轮跟踪 SubBytes/ShiftRows/MixColumns/AddRoundKey")
    print("  4  解密过程                逆序解密，去填充后比对明文")
    print("  5  分组模式对比            ECB / CBC / GCM 对比（图案泄露、IV 影响）")
    print("  6  篡改检测                CBC 静默出错 vs GCM 认证失败")
    print()
    print("【快捷命令】")
    print("  a  依次运行全部步骤 (1-6)")
    print("  s  查看当前状态（明文/密钥/密文/已运行步骤）")
    print("  q  退出并保存 Markdown 指南")
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
    print()

    ctx = Context(plaintext=text, key_bytes=key)

    if args.run_all:
        for n in range(1, 7):
            try:
                print(f"\n>>> 正在运行步骤 {n} ...")
                run_step(ctx, n)
            except Exception as e:
                F.err(f"Step {n} 失败: {e}")
                break
            if not args.no_pause:
                F.pause()
        return

    while True:
        try:
            print()
            cmd = input("请选择操作 [1-6 / a / s / q]：").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if cmd in ("q",):
            if ctx.steps_done:
                save_guide(ctx)
                print("已保存 Markdown 指南，程序退出。")
            else:
                print("未运行任何步骤，直接退出。")
            break

        if cmd == "a":
            for n in range(1, 7):
                try:
                    print(f"\n>>> 正在运行步骤 {n} ...")
                    run_step(ctx, n)
                except Exception as e:
                    F.err(f"Step {n} 失败: {e}")
                    break
                if not args.no_pause:
                    F.pause()
            continue

        if cmd == "s":
            print("─" * 40)
            print(f"明文     : {ctx.plaintext!r}")
            print(f"密钥     : {ctx.key_bytes.hex()}")
            print(f"密文     : {ctx.ciphertext.hex() if ctx.ciphertext else '(尚未加密)'}")
            print(f"已运行步骤: {sorted(ctx.steps_done) if ctx.steps_done else '无'}")
            print("─" * 40)
            continue

        if cmd in ("1", "2", "3", "4", "5", "6"):
            n = int(cmd)
            try:
                print(f"\n>>> 正在运行步骤 {n} ...")
                run_step(ctx, n)
            except Exception as e:
                F.err(str(e))
            continue

        F.warn("非法输入！请输入 1-6、a、s 或 q")

		
if __name__ == "__main__":
    main()
