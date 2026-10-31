# AES 教学项目

纯 Python AES-128 教学实现，仅标准库，明确声明**不用于生产**。

## 项目定位

交互式 Python AES 教学项目。运行时先输入明文、自动生成密钥，然后按步骤跟踪“填充 → 密钥扩展 → 加密逐轮 → 解密逐轮 → 分组模式对比 → 篡改检测”全过程，控制台输出关键可视化，运行结束后自动生成 `AES_DEMO_GUIDE.md`（含全部讲解与真实样本）。

## 目录结构

```text
project-aes/
├── main.py
├── context.py
├── README.md
├── AES_DEMO_GUIDE.md          # 运行后自动生成，不手写
├── steps/
│   ├── __init__.py
│   ├── step1_padding.py
│   ├── step2_key_expansion.py
│   ├── step3_encrypt_round.py
│   ├── step4_decrypt_round.py
│   ├── step5_modes.py
│   └── step6_tamper.py
├── aes/
│   ├── __init__.py
│   ├── sbox.py
│   ├── gf.py
│   ├── padding.py
│   ├── key_expansion.py
│   └── cipher.py
├── utils/
│   ├── __init__.py
│   ├── formatting.py
│   └── markdown.py
└── tests/
    ├── __init__.py
    ├── test_aes.py
    ├── test_gf.py
    └── test_guide.py
```

## 运行方式

```bash
# 交互运行
python main.py

# 指定明文并运行全部
python main.py --text "Hello AES" --run-all --no-pause

# 指定密钥
python main.py --key hex:000102030405060708090a0b0c0d0e0f --text "test" --run-all --no-pause

# 运行测试
python -m unittest discover -s tests
```

## 6 步说明表

| 步骤 | 名称 | 说明 |
|------|------|------|
| 1 | 明文分组与 PKCS#7 填充 | UTF-8 编码、PKCS#7 填充（恒填充）、16 字节分组 |
| 2 | 密钥扩展 | AES-128 密钥扩展，生成 11 个 Round Key，展示 RotWord/SubWord/Rcon |
| 3 | 加密过程 | 逐轮跟踪 SubBytes/ShiftRows/MixColumns/AddRoundKey，输出第 1 轮矩阵 |
| 4 | 解密过程 | 逆序解密，展示操作顺序与加密相反，去填充后比对明文 |
| 5 | 分组模式对比 | ECB / CBC / GCM 对比，ECB 图案泄露、CBC 不同 IV 密文不同 |
| 6 | 篡改检测 | CBC 翻转密文不报错但明文错乱；GCM 认证失败 |

## 安全声明

本项目为纯 Python 教学实现，存在以下安全局限：
- 无侧信道防护（非常量时间，易受时序/缓存攻击）
- 无认证加密（ECB/CBC 均易受篡改与重放攻击）
- 密钥管理缺失

生产环境请使用 `cryptography` 库的 `AESGCM`，配合随机 nonce 和 KDF 派生密钥。
