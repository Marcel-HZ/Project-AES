# AES 教学项目

纯 Python AES-128 教学实现，仅标准库，明确声明**不用于生产**。

## 项目定位

交互式 Python AES 教学项目。运行时先输入明文、自动生成（或指定）密钥，然后按步骤跟踪“填充 → 密钥扩展 → 加密逐轮 → 解密逐轮 → 分组模式对比 → 篡改检测”全过程，控制台输出关键可视化，运行结束后自动生成 `AES_DEMO_GUIDE.md`（含全部讲解与真实样本）。

## AES 加密原理

### 1. 数学定义与基本逻辑

AES（Advanced Encryption Standard）是一种**对称分组密码**，将固定长度的明文分组映射为相同长度的密文分组。对于本项目采用的 AES-128，可以形式化表示为：

```text
E: {0,1}^128 × {0,1}^128  →  {0,1}^128 ,    c = E(k, m)
D: {0,1}^128 × {0,1}^128  →  {0,1}^128 ,    m = D(k, c)
```

其中 `m` 为 128 bit 明文分组，`k` 为 128 bit 密钥，`c` 为 128 bit 密文分组。加密与解密使用同一密钥，且互为逆运算。

AES 属于**代换-置换网络（SPN）**结构，通过多轮非线性代换与线性扩散实现混淆与扩散。理想对称分组密码应满足：

- **确定性**：相同密钥与相同明文始终产生相同密文。
- **可逆性**：持有正确密钥时可完整还原明文。
- **混淆（Confusion）**：密文与密钥之间的统计关系尽可能复杂（主要由 SubBytes 提供）。
- **扩散（Diffusion）**：明文或密钥的微小变化应导致密文大幅变化（主要由 ShiftRows + MixColumns 提供）。
- **雪崩效应**：改变明文或密钥的 1 bit，理想情况下约一半密文比特发生变化。

AES 只负责**保密性**。若需要完整性/防篡改，必须配合消息认证码（MAC）或直接使用认证加密模式（如 GCM）。

### 2. AES-128 的组成部分

本项目实现 AES-128（密钥 128 bit，10 轮）。主要组成部分如下：

1. **明文填充与分块**：明文先按 UTF-8 编码为字节序列，再使用 PKCS#7 填充至 16 字节的整数倍，最后切分为若干 16 字节（128 bit）分组。每个分组按列优先排列成 4×4 字节状态矩阵（State）。
2. **密钥扩展（Key Expansion）**：将 16 字节原始密钥扩展为 11 个 16 字节轮密钥（RoundKey[0] … RoundKey[10]）。扩展过程使用 RotWord、SubWord 与轮常量 Rcon。
3. **初始轮密钥加（AddRoundKey）**：状态矩阵与 RoundKey[0] 按字节异或。
4. **轮函数（9 轮完整轮）**：每轮依次执行  
   - **SubBytes**：字节级 S-box 非线性代换  
   - **ShiftRows**：行循环左移（扩散）  
   - **MixColumns**：列混合（有限域 GF(2⁸) 上的矩阵乘法）  
   - **AddRoundKey**：与当前轮密钥异或
5. **最终轮（第 10 轮）**：仅执行 SubBytes → ShiftRows → AddRoundKey（**无 MixColumns**）。
6. **输出**：最终状态矩阵按列优先重新排列为 16 字节密文。

解密过程使用对应的逆变换（InvSubBytes、InvShiftRows、InvMixColumns），并按相反顺序应用轮密钥。

### 3. 核心数学运算

AES 在字节（GF(2⁸)）与状态矩阵两个层面运算。

**有限域 GF(2⁸)**  
字节乘法以不可约多项式 \(x^8 + x^4 + x^3 + x + 1\)（即 `0x11b`）为模。常用运算包括：

- 字节异或（加法）
- xtime（乘以 \(x\)，即左移 1 位，若最高位为 1 则再异或 `0x1b`）
- 任意系数乘法通过 xtime 组合实现

**SubBytes**  
每个字节独立通过固定的 8×8 S-box 查表替换。S-box 由有限域求逆再经过仿射变换得到，提供非线性混淆。

**ShiftRows**  
状态矩阵的第 \(r\) 行循环左移 \(r\) 个字节（\(r = 0,1,2,3\)），使同一列的数据扩散到不同列。

**MixColumns**  
将每一列视为 GF(2⁸) 上的 4 维向量，左乘固定矩阵：

```math
\begin{bmatrix}
02 & 03 & 01 & 01 \\
01 & 02 & 03 & 01 \\
01 & 01 & 02 & 03 \\
03 & 01 & 01 & 02
\end{bmatrix}
```

实现列内充分混合。

**AddRoundKey**  
状态与轮密钥按字节异或，是唯一直接引入密钥信息的步骤。

**密钥扩展核心**（当 \(i \bmod 4 = 0\) 时）：

```text
temp = SubWord(RotWord(w[i-1])) ⊕ Rcon[i/4]
w[i] = w[i-4] ⊕ temp
```

其余位置仅做简单异或：`w[i] = w[i-4] ⊕ w[i-1]`。

### 4. 完整运算流程

从程序执行角度看，AES-128 加密可概括为：

1. **输入与编码**：接收明文字符串，使用 UTF-8 转为字节序列。
2. **PKCS#7 填充**：计算需要填充的字节数 \(n\)（\(1 \le n \le 16\)），每个填充字节的值均为 \(n\)；若已是 16 的倍数则再补一整块。
3. **分组**：将填充后的数据切分为 16 字节块，每块形成 4×4 状态矩阵。
4. **密钥扩展**：由 16 字节密钥生成 11 个轮密钥。
5. **初始 AddRoundKey**：状态 ⊕ RoundKey[0]。
6. **9 轮完整轮函数**：SubBytes → ShiftRows → MixColumns → AddRoundKey。
7. **最终轮**：SubBytes → ShiftRows → AddRoundKey（无 MixColumns）。
8. **输出密文**：状态矩阵转为 16 字节密文；多块时按模式（ECB/CBC 等）组合。

解密流程严格逆序，使用逆变换与逆序轮密钥，最后去除 PKCS#7 填充并验证填充合法性。

本项目所有核心运算均用纯 Python 实现（S-box、GF 乘法、矩阵操作等），便于逐步可视化；生产环境请使用经过充分审计的库。

### 5. 与项目中其他步骤的关系

AES 分组加密是本项目后续演示的基础，但需要区分不同层次的概念：

- **步骤 1（填充）**：解决任意长度明文与固定分组长度的匹配问题，PKCS#7 是最常用的标准填充。
- **步骤 2（密钥扩展）**：从用户密钥派生出每轮使用的轮密钥，是 AES 安全性的重要组成部分。
- **步骤 3/4（加/解密逐轮）**：完整展示 SPN 结构中的混淆与扩散，以及加解密的互逆关系。
- **步骤 5（模式对比）**：ECB 会泄露数据图案；CBC 需要随机 IV 且相同明文块在不同 IV 下密文不同；GCM 额外提供认证。
- **步骤 6（篡改检测）**：演示 CBC 静默出错（可被比特翻转攻击）与 GCM 认证失败（主动拒绝篡改数据）的本质区别。

单纯 AES（即使正确实现）只提供保密性；现代应用几乎总是使用 **AEAD**（Authenticated Encryption with Associated Data）模式。

### 6. 现实应用场景

1. **数据传输加密**：TLS/HTTPS、VPN、即时通讯等广泛使用 AES-GCM 或 AES-CBC + HMAC。
2. **磁盘与文件加密**：BitLocker、FileVault、VeraCrypt 等使用 AES 保护静态数据。
3. **数据库字段加密**：对敏感字段（身份证、银行卡号）进行加密存储。
4. **密钥包装与令牌**：用 AES 包装其他密钥或生成安全令牌。
5. **物联网与嵌入式**：许多资源受限设备采用 AES 硬件加速指令。

实际部署时必须注意：

- 使用经过验证的实现（如 `cryptography` 库的 `AESGCM`），避免自己实现。
- Nonce/IV 必须唯一且不可预测（GCM 严禁 nonce 复用）。
- 密钥应由密码学安全的随机数生成器产生，或通过 PBKDF2/HKDF/Argon2 等从口令派生。
- 优先选择带认证的模式（GCM、CCM、ChaCha20-Poly1305），而非裸 ECB/CBC。

综上，AES 通过固定分组、多轮 SPN 变换与密钥扩展实现高效对称加密。本项目完整展示了从填充到模式与完整性保护的全链路，帮助理解“为什么生产环境必须使用 AEAD，以及为什么绝不能自己实现 AES”。

## 目录结构

```text
project-aes/
├── main.py                      # 入口：输入明文 + 菜单循环 + 步骤调度
├── context.py                   # 全局上下文：存储明文、密钥与各步骤运行时样本
├── README.md
├── AES_DEMO_GUIDE.md            # 运行后自动生成（含全部讲解与真实样本）
├── steps/
│   ├── __init__.py
│   ├── step1_padding.py         # 明文分组与 PKCS#7 填充
│   ├── step2_key_expansion.py   # AES-128 密钥扩展
│   ├── step3_encrypt_round.py   # 加密过程逐轮跟踪
│   ├── step4_decrypt_round.py   # 解密过程逆序跟踪
│   ├── step5_modes.py           # ECB / CBC / GCM 模式对比
│   └── step6_tamper.py          # CBC 静默出错 vs GCM 认证失败
├── aes/
│   ├── __init__.py
│   ├── sbox.py                  # S-box / InvS-box
│   ├── gf.py                    # GF(2⁸) 运算
│   ├── padding.py               # PKCS#7 填充与去填充
│   ├── key_expansion.py         # 密钥扩展
│   └── cipher.py                # 加解密核心
├── utils/
│   ├── __init__.py
│   ├── formatting.py            # 统一输出与暂停
│   └── markdown.py              # Markdown 文档生成器
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

交互流程：
1. 输入明文（可直接回车使用默认值）
2. 菜单选择：
   - `1-6` 单步运行
   - `a` 全部运行
   - `s` 查看当前状态
   - `q` 退出并保存 Markdown 指南
3. 运行结束后自动在项目目录下生成 `AES_DEMO_GUIDE.md`

## 运行过程

| 步骤 | 名称 | 说明 |
|------|------|------|
| 1 | 明文分组与 PKCS#7 填充 | UTF-8 编码、PKCS#7 填充（恒填充）、16 字节分组 |
| 2 | 密钥扩展 | AES-128 密钥扩展，生成 11 个 Round Key，展示 RotWord/SubWord/Rcon |
| 3 | 加密过程 | 逐轮跟踪 SubBytes/ShiftRows/MixColumns/AddRoundKey，输出第 1 轮矩阵 |
| 4 | 解密过程 | 逆序解密，展示操作顺序与加密相反，去填充后比对明文 |
| 5 | 分组模式对比 | ECB / CBC / GCM 对比，ECB 图案泄露、CBC 不同 IV 密文不同 |
| 6 | 篡改检测 | CBC 翻转密文不报错但明文错乱；GCM 认证失败 |

## 技术规格

- Python 3.10+
- 仅标准库
- 原理讲解与真实样本全部写入 `AES_DEMO_GUIDE.md`，控制台只输出关键数据
- MD 文档固定保存在项目目录下，与运行目录无关

## 安全声明

本项目为纯 Python 教学实现，存在以下安全局限：

- 无侧信道防护（非常量时间，易受时序/缓存攻击）
- 无认证加密（ECB/CBC 均易受篡改与重放攻击）
- 密钥管理缺失（密钥由 `os.urandom` 生成，未持久化或派生）

生产环境请使用 `cryptography` 库的 `AESGCM`，配合随机 nonce 和 KDF（PBKDF2 / HKDF / Argon2）派生密钥，并严格保证 nonce 永不复用。