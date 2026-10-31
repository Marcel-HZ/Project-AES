# PROJECT_SPEC.md — AES 加密原理与实战教学项目

## 0. 项目定位

交互式 Python AES 教学项目。运行时先输入明文、自动生成密钥，然后按步骤跟踪“填充 → 密钥扩展 → 加密逐轮 → 解密逐轮 → 分组模式对比 → 篡改检测”全过程，控制台输出关键可视化，运行结束后自动生成 `AES_DEMO_GUIDE.md`（含全部讲解与真实样本）。

**核心约束：**

- 纯 Python 实现 AES-128（纯标准库），用于教学可视化，**明确声明不用于生产**。
- 控制台只输出关键数据与第 1 轮完整矩阵；完整逐轮数据全部写入 MD。
- 控制台输出与 MD 文档使用**同一份 `Context.samples`**，保证数据一致。
- 仅标准库；`tqdm` 可选，用 `try/except` 优雅降级。
- Python 3.10+。

---

## 1. 目录结构（必须严格按此创建）

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
└── utils/
    ├── __init__.py
    ├── formatting.py
    └── markdown.py
```

职责边界（硬性要求）：

- `aes/` 只负责计算，**不允许任何 `print`**，不允许依赖 `utils/`。
- `steps/` 只负责调用 `aes/`、用 `utils/formatting.py` 渲染、把关键数据写入 `ctx.samples`。
- `utils/` 不依赖 `steps/` 和 `aes/`（`formatting` 只接收 bytes/str）。
- `main.py` 只做输入、菜单、调度、收尾生成 MD。

---

## 2. 模块详细要求

### 2.1 `aes/sbox.py`

- 提供 `S_BOX: list[int]`（256）、`INV_S_BOX: list[int]`（256）。
- 提供 `sub_byte(b: int) -> int`、`inv_sub_byte(b: int) -> int`。
- 模块加载时用断言自检：`INV_S_BOX[S_BOX[i]] == i` 对所有 i 成立。
- 文件头注释写安全声明。

### 2.2 `aes/gf.py`

- `gf_mul(a: int, b: int) -> int`：GF(2^8)，不可约多项式 `0x11B`。
- `mix_column(col: list[int]) -> list[int]`、`inv_mix_column(col: list[int]) -> list[int]`。
- 提供常量 `MIX_MATRIX`、`INV_MIX_MATRIX`（4x4）。
- 单元自检：`gf_mul(0x57, 0x83) == 0xC1`（FIPS-197 示例）。

### 2.3 `aes/padding.py`

- `pad(data: bytes) -> bytes`：PKCS#7，恒填充，16 倍数也追加整块 `0x10`。
- `unpad(data: bytes) -> bytes`：校验填充合法，非法抛 `ValueError`。
- `split_blocks(data: bytes) -> list[bytes]`：按 16 字节分组，非法长度抛异常。

### 2.4 `aes/key_expansion.py`

- `expand_key(key: bytes) -> list[bytes]`：AES-128，返回 11 个 16 字节 round key。
- `expand_key_trace(key: bytes) -> dict`：额外返回 `w`（44 个 word）、`rcon` 使用记录、以及 `rot_sub_xor_steps`（只记录 i % 4 == 0 的 word 的 RotWord/SubWord/Rcon 中间值），供 step2 可视化。
- key 长度必须为 16 字节，否则抛 `ValueError`。

### 2.5 `aes/cipher.py`

- `encrypt_block(block: bytes, round_keys: list[bytes], record: bool = False) -> bytes | tuple`
- `decrypt_block(block: bytes, round_keys: list[bytes], record: bool = False) -> bytes | tuple`
- `record=True` 时返回 `(result, trace)`，trace 结构：

```python
{
  "initial_add_round_key": {"before": bytes, "after": bytes, "round_key_index": 0},
  "rounds": [
     {
       "round_no": 1,
       "sub_bytes":   {"before": bytes, "after": bytes},
       "shift_rows":  {"before": bytes, "after": bytes},
       "mix_columns": {"before": bytes, "after": bytes, "column0_detail": dict},
       "add_round_key": {"before": bytes, "after": bytes, "round_key_index": 1},
     },
     ...
  ],
  "final_round": {...},   # 第 10 轮，无 mix_columns
}
```

- 解密 trace 结构对称，键名为 `inv_shift_rows / inv_sub_bytes / inv_mix_columns`，且**顺序体现与加密相反**。
- 状态矩阵映射必须用列主序：`state[r][c] = block[r + 4*c]`，在 docstring 中写明。
- `mix_columns` 的 `column0_detail` 只需记录第 0 列的 4 个输入、4 个输出、以及 4 行 GF 计算式字符串（如 `"02*32 ⊕ 03*88 ⊕ 01*31 ⊕ 01*e0 = 23"`）。
- 自检：模块级 `if __name__ == "__main__"` 用 FIPS-197 向量验证（见第 7 节）。

### 2.6 `context.py`

```python
@dataclass
class Context:
    plaintext: str
    key_bytes: bytes                       # 16 字节
    plaintext_bytes: bytes = b""
    padded: bytes = b""
    padding_len: int = 0
    blocks: list[bytes] = field(default_factory=list)
    round_keys: list[bytes] = field(default_factory=list)
    key_expansion_trace: dict = field(default_factory=dict)
    ciphertext: bytes = b""
    encrypt_trace: dict = field(default_factory=dict)   # 仅第一块详细 trace
    round_snapshots: list[bytes] = field(default_factory=list)  # 每轮状态快照
    decrypted_padded: bytes = b""
    decrypted: bytes = b""
    decrypt_trace: dict = field(default_factory=dict)
    modes: dict = field(default_factory=dict)           # step5 结果
    tamper: dict = field(default_factory=dict)          # step6 结果
    samples: dict = field(default_factory=dict)         # 每步写入 MD 的键值
    steps_done: list[int] = field(default_factory=list) # 已运行的步骤号
```

要求：

- 提供 `reset_derived()`：清空派生字段但保留 `plaintext / key_bytes`，供重跑。
- `samples` 的键统一为字符串，如 `"step1.padding"`、`"step3.round1"`，值与结构由各 step 自行约定，但必须在 step 文件顶部注释中列出本步写入的键。

### 2.7 `utils/formatting.py`

必须提供（函数名固定，供 steps 调用）：

```python
def hr(char="─", width=64) -> str
def render_hex(b: bytes, sep=" ") -> str                       # "32 88 31 e0"
def render_matrix(b: bytes, title: str = "") -> str            # 4x4 框线矩阵
def render_before_after(before: bytes, after: bytes, title: str) -> str
def render_step_header(no: int, title: str) -> str             # "┌─ Step 3 · 加密过程 ─..."
def render_table(headers: list[str], rows: list[list[str]]) -> str
def progress(iterable, desc: str = "")                          # tqdm 可用则用，否则透传
def info(msg: str) -> None                                     # 统一前缀 "[i]"
def ok(msg: str) -> None                                       # "[✓]"
def warn(msg: str) -> None                                     # "[!]"
def err(msg: str) -> None                                      # "[x]"
def pause() -> None                                            # input("按 Enter 继续...")，非 TTY 自动跳过
```

约束：

- 矩阵渲染必须支持中文对齐（用等宽字符宽度计算，或矩阵内只用 ASCII）。
- 不引入第三方库；`tqdm` 仅在此文件内 `try/except`。
- 所有输出走 `sys.stdout`，便于测试时重定向。

### 2.8 `utils/markdown.py`

- `build_guide(ctx: Context) -> str`：根据 `ctx.samples` 与 ctx 字段生成完整 Markdown。
- `save_guide(ctx: Context, path: str = "AES_DEMO_GUIDE.md") -> str`：写到**项目根目录**（用 `Path(__file__).resolve().parent.parent` 定位，与运行目录无关），返回绝对路径。
- 文档结构固定为：

```text
# AES 加密原理与实战教学

## 0. 本次样本
## 1. 明文分组与 PKCS#7 填充
## 2. 密钥扩展
## 3. 加密过程（第 1 轮详解 + 第 2–10 轮快照）
## 4. 解密过程（逆序详解 + 明文比对）
## 5. 分组模式对比（ECB / CBC / GCM）
## 6. 篡改检测（CBC 静默出错 vs GCM 认证失败）
## 7. 安全说明与结论
```

- 只渲染 `steps_done` 里已完成的步骤章节；未运行的步骤写一行“未运行”。
- 代码块语言标注为 `text`。

### 2.9 `main.py`

流程：

```text
1. 打印项目标题 + 安全声明（教学用，非生产）
2. 输入明文：input("请输入明文：")，空输入则用默认 "Hello AES 教学!"
3. 生成密钥：os.urandom(16)，打印 hex
4. 菜单循环：
     1-6  运行单步（已运行过则重置该步相关 ctx 字段后重跑）
     a    依次运行 1-6
     s    显示当前 ctx 摘要（明文/密钥/密文/已运行步骤）
     q    退出（退出前若 steps_done 非空则生成 MD）
5. 每次运行后调用 save_guide()（覆盖写）
6. 捕获步骤内异常：打印 err 信息，不崩溃，回到菜单
```

要求：

- 菜单解析大小写不敏感；非法输入提示后重试。
- `a` 运行全部时，步骤间调用 `pause()`（非 TTY 自动跳过）。
- 支持命令行参数（`argparse`，可选但推荐）：`--text`、`--key hex:...`、`--no-pause`、`--run-all`，便于测试与 CI。
- `main.py` 内不得出现 AES 算法逻辑。

---

## 3. 六个步骤的详细规格

每个 step 模块必须暴露 `def run(ctx: Context) -> None`，并在文件头注释写明：本步讲解目标、写入 `ctx.samples` 的键列表。

### step1_padding.py — 明文分组与 PKCS#7 填充

- 将 `ctx.plaintext` 编码为 UTF-8，写入 `ctx.plaintext_bytes`。
- 调用 `aes.padding.pad`，写入 `ctx.padded / ctx.padding_len / ctx.blocks`。
- 控制台输出：明文字节 hex 与长度、填充字节数与值、填充前后对照、每个分组 hex。
- 特别提示：明文恰为 16 倍数时必须追加整块 `0x10`，并当场演示一句 16 字节明文的例子。
- 写入 samples：`step1.plaintext_hex`、`step1.padding`、`step1.blocks`。

### step2_key_expansion.py — 密钥扩展

- 调用 `expand_key_trace`，写入 `ctx.round_keys / ctx.key_expansion_trace`。
- 控制台输出：原始密钥 4 个 word；用表格展示每个 `i % 4 == 0` 的 word 的 `RotWord → SubWord → Rcon → XOR` 中间值（只详细展开 `w[4]` 和 `w[8]` 各一个作示例，其余给一行摘要）；11 个 Round Key 的 hex 列表。
- samples：`step2.words`、`step2.rcon_examples`、`step2.round_keys`。

### step3_encrypt_round.py — 加密过程

- 取 `ctx.blocks[0]`，调用 `encrypt_block(record=True)`。
- 其余块用 `record=False` 依次加密，拼成 `ctx.ciphertext`；`ctx.round_snapshots` 取第一块每轮 AddRoundKey 后的状态。
- 控制台输出：
  - 初始 AddRoundKey 的 before/after 矩阵。
  - **第 1 轮**四个操作各一组 before/after 矩阵，SubBytes 标注一个典型映射（`0x00 → 0x63`），ShiftRows 标注每行位移，MixColumns 展开第 0 列计算式。
  - 第 2–10 轮每轮一行摘要：轮号 + 该轮 round key 前 4 字节 + 状态前 4 字节；末轮标注“无 MixColumns”。
  - 最终密文 hex 与 base64。
- samples：`step3.round1`（完整 trace）、`step3.round_snapshots`、`step3.ciphertext`。

### step4_decrypt_round.py — 解密过程

- 对 `ctx.blocks[0]` 的密文调用 `decrypt_block(record=True)`，其余块无 record 解密并拼接。
- 调用 `unpad`，与 `ctx.plaintext_bytes` 逐字节比对，输出 ✅/❌。
- 控制台输出：解密**操作顺序**说明（初始 AddRoundKey[10] → InvShiftRows → InvSubBytes → AddRoundKey[9] → InvMixColumns → … → AddRoundKey[0]）；第 1 个解密轮的四组 before/after 矩阵；去填充前后 hex；比对结果。
- samples：`step4.decrypt_round1`、`step4.unpad`、`step4.compare`。

### step5_modes.py — 分组模式对比

用标准库 `cryptography` **不可用**（项目要求纯标准库），因此：

- ECB / CBC 用本项目 `aes/cipher.py` 手工实现（CBC 需实现 XOR IV 与链式，写在 step5 内部，不进 `aes/`，避免污染教学核心）。
- GCM：**不实现**，改为“说明 + 概念对比”，在控制台与 MD 中用表格说明 GCM 提供认证、nonce 不可复用，并注明“生产请用 `cryptography` 库的 AESGCM”。
- 对比数据用两段相同的 16 字节块（如 `b"A"*16 + b"A"*16`）：
  - ECB：两块密文相同 → 图案泄露。
  - CBC：两个不同 IV 各跑一次 → 相同明文块密文不同。
  - GCM：只输出概念表格行，无实际密文。
- 控制台输出一张对比表：`模式 / 是否需要 IV / 相同块是否泄露 / 是否提供认证 / 本演示结果`。
- samples：`step5.ecb`、`step5.cbc`、`step5.gcm_note`、`step5.table`。

### step6_tamper.py — 篡改检测

- CBC 演示（复用 step5 的 CBC 实现）：
  - 正常解密得到原文。
  - 翻转密文第 1 块第 0 字节，再次解密：**不报错**，但第 1 块明文错乱、第 2 块对应字节也受影响（CBC 错误传播），输出对比。
- GCM：不实现算法，仅用文字 + 表格说明“翻转 1 字节 → 认证失败抛异常”。
- 输出对比表：`模式 / 改动位置 / 解密是否报错 / 明文是否正确 / 结论`。
- samples：`step6.cbc_tamper`、`step6.gcm_note`、`step6.table`。

---

## 4. 控制台输出规范

- 每步开始打印 `render_step_header(n, title)`，结束打印一行 `ok("Step n 完成")`。
- 矩阵框宽度固定，单行不超过 80 列。
- 所有 hex 小写、空格分隔。
- 不打印完整 44 个 word 的展开（只进 MD），控制台只给摘要。
- 中文提示统一用 `info/ok/warn/err` 前缀。

---

## 5. MD 文档生成规范

- 由 `save_guide` 在每次步骤运行后覆盖生成，路径固定为项目根目录。
- 未运行的步骤章节保留标题，正文写 `> 未运行`。
- 所有矩阵用 ```text 代码块``` 包裹，保证 GitHub 渲染对齐。
- 第 7 节固定写：教学实现的安全局限（无侧信道防护、无认证、密钥管理缺失）、生产建议（`cryptography` 的 AESGCM、随机 nonce、KDF 派生密钥）。

---

## 6. 异常与边界

- 明文允许为空字符串：按空 bytes 处理，仍走完整填充（得到一块 `0x10*16`）。
- 明文超长（> 1024 字节）：控制台只详细展开第一块，其余块仅计数，MD 同样只展开第一块。
- 非 UTF-8 输入不在本版范围（输入为 str，统一 UTF-8 编码）。
- `unpad` 失败必须抛 `ValueError`，由 step4 捕获并输出 `err`，不崩溃。
- 所有 `aes/` 函数对非法长度输入抛 `ValueError`，错误信息用英文。

---

## 7. 测试与自检要求

在 `aes/cipher.py` 的 `__main__` 中必须包含 FIPS-197 向量自检：

```text
key        = 000102030405060708090a0b0c0d0e0f
plaintext  = 00112233445566778899aabbccddeeff
ciphertext = 69c4e0d86a7b0430d8cdb78070b4c55a
```

要求：加密得到上述密文，解密还原明文，断言通过后打印 `FIPS-197 vector OK`。

另需提供 `tests/`（可选但推荐，用 `unittest`，不引入 pytest）：

- `test_aes.py`：FIPS-197 向量、`expand_key` 返回 11 个 key、`pad/unpad` 往返、`unpad` 非法输入抛异常。
- `test_gf.py`：`gf_mul(0x57, 0x83) == 0xC1`、`gf_mul(a, 1) == a`。
- `test_guide.py`：构造空 Context，`build_guide` 不抛异常且包含 7 个二级标题。

---

## 8. 验收标准（Kilo Code 完成后逐条核对）

1. `python main.py` 可交互运行，输入明文后能依次运行 1–6 步，无崩溃。
2. 控制台出现第 1 轮 SubBytes / ShiftRows / MixColumns / AddRoundKey 的 before/after 矩阵。
3. 第 1 轮 MixColumns 有第 0 列的 GF 计算式。
4. 解密步骤明确展示“操作顺序与加密相反”，且最终比对输出 ✅。
5. step5 输出 ECB 两块密文相同、CBC 不同 IV 密文不同的对比表。
6. step6 输出 CBC 篡改后“解密不报错但明文错乱”的对比表。
7. 项目根目录生成 `AES_DEMO_GUIDE.md`，含 7 个二级标题，未运行步骤显示“未运行”。
8. `python -m aes.cipher` 输出 `FIPS-197 vector OK`。
9. 全项目 `grep -r "print(" aes/` 无结果（`aes/` 目录零打印）。
10. 除 `tqdm` 外无第三方依赖，`tqdm` 缺失时程序正常运行。
11. `README.md` 含：项目定位、目录结构、运行方式、6 步说明表、安全声明。
12. 所有 `steps/stepN_*.py` 文件头注释列出本步写入 `ctx.samples` 的键。

---

## 9. 实现顺序建议（给 Kilo Code 的任务切分）

1. `aes/sbox.py` → `aes/gf.py` → `aes/padding.py` → `aes/key_expansion.py` → `aes/cipher.py`，每完成一个跑自检。
2. `context.py` + `utils/formatting.py`（先用假数据验证矩阵渲染）。
3. `main.py` 菜单框架 + `utils/markdown.py` 空壳（7 个标题 + “未运行”）。
4. `steps/step1_padding.py` → `step2` → `step3` → `step4`，每步跑通控制台与 MD。
5. `steps/step5_modes.py` → `step6_tamper.py`。
6. `tests/` + `README.md`。
7. 按第 8 节逐条验收。