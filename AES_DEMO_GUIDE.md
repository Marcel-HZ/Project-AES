# AES 加密原理与实战教学

## 0. 本次样本

- 明文: 'ecupl-2025 for a single chance'
- 明文字节长度: 30
- 密钥 (hex): f6baf2898aabf48e5fc269c21d2824f4
- 填充后总块数: 2
- 密文 (hex): 534a37bf13a9305c73f9f28c70e26ca663c99545d3a8aac2eca32c9dfac34e24

## 1. 明文分组与 PKCS#7 填充

### 明文与填充

```text
明文: 'ecupl-2025 for a single chance'
明文字节 (hex): 65 63 75 70 6c 2d 32 30 32 35 20 66 6f 72 20 61 20 73 69 6e 67 6c 65 20 63 68 61 6e 63 65
明文长度: 30 字节
填充长度: 2 字节 (每个字节值 0x02)
填充前后对照:
  填充前: 65 63 75 70 6c 2d 32 30 32 35 20 66 6f 72 20 61 20 73 69 6e 67 6c 65 20 63 68 61 6e 63 65
  填充后: 65 63 75 70 6c 2d 32 30 32 35 20 66 6f 72 20 61 20 73 69 6e 67 6c 65 20 63 68 61 6e 63 65 02 02
分组 (每块 16 字节):
  块 0: 65 63 75 70 6c 2d 32 30 32 35 20 66 6f 72 20 61
  块 1: 20 73 69 6e 67 6c 65 20 63 68 61 6e 63 65 02 02
```

## 2. 密钥扩展

### 密钥扩展 (AES-128)

原始密钥 (hex): f6 ba f2 89 8a ab f4 8e 5f c2 69 c2 1d 28 24 f4

44 个扩展字 (w[0]..w[43]):
```text
  w[ 0]: f6 ba f2 89
  w[ 1]: 8a ab f4 8e
  w[ 2]: 5f c2 69 c2
  w[ 3]: 1d 28 24 f4
  w[ 4]: c3 8c 4d 2d
  w[ 5]: 49 27 b9 a3
  w[ 6]: 16 e5 d0 61
  w[ 7]: 0b cd f4 95
  w[ 8]: 7c 33 67 06
  w[ 9]: 35 14 de a5
  w[10]: 23 f1 0e c4
  w[11]: 28 3c fa 51
  w[12]: 93 1e b6 32
  w[13]: a6 0a 68 97
  w[14]: 85 fb 66 53
  w[15]: ad c7 9c 02
  w[16]: 5d c0 c1 a7
  w[17]: fb ca a9 30
  w[18]: 7e 31 cf 63
  w[19]: d3 f6 53 61
  w[20]: 0f 2d 2e c1
  w[21]: f4 e7 87 f1
  w[22]: 8a d6 48 92
  w[23]: 59 20 1b f3
  w[24]: 98 82 23 0a
  w[25]: 6c 65 a4 fb
  w[26]: e6 b3 ec 69
  w[27]: bf 93 f7 9a
  w[28]: 04 ea 9b 02
  w[29]: 68 8f 3f f9
  w[30]: 8e 3c d3 90
  w[31]: 31 af 24 0a
  w[32]: fd dc fc c5
  w[33]: 95 53 c3 3c
  w[34]: 1b 6f 10 ac
  w[35]: 2a c0 34 a6
  w[36]: 5c c4 d8 20
  w[37]: c9 97 1b 1c
  w[38]: d2 f8 0b b0
  w[39]: f8 38 3f 16
  w[40]: 6d b1 9f 61
  w[41]: a4 26 84 7d
  w[42]: 76 de 8f cd
  w[43]: 8e e6 b0 db
```

Rcon 使用记录 (i % 4 == 0 的字):
```text
  i=4: rcon=01
  i=8: rcon=02
  i=12: rcon=04
  i=16: rcon=08
  i=20: rcon=10
  i=24: rcon=20
  i=28: rcon=40
  i=32: rcon=80
  i=36: rcon=1b
  i=40: rcon=36
```

11 个 Round Key:
```text
  RoundKey[0]: f6baf2898aabf48e5fc269c21d2824f4
  RoundKey[1]: c38c4d2d4927b9a316e5d0610bcdf495
  RoundKey[2]: 7c3367063514dea523f10ec4283cfa51
  RoundKey[3]: 931eb632a60a689785fb6653adc79c02
  RoundKey[4]: 5dc0c1a7fbcaa9307e31cf63d3f65361
  RoundKey[5]: 0f2d2ec1f4e787f18ad6489259201bf3
  RoundKey[6]: 9882230a6c65a4fbe6b3ec69bf93f79a
  RoundKey[7]: 04ea9b02688f3ff98e3cd39031af240a
  RoundKey[8]: fddcfcc59553c33c1b6f10ac2ac034a6
  RoundKey[9]: 5cc4d820c9971b1cd2f80bb0f8383f16
  RoundKey[10]: 6db19f61a426847d76de8fcd8ee6b0db
```

## 3. 加密过程（第 1 轮详解 + 第 2–10 轮快照）

### 加密过程 (第一块)

初始 AddRoundKey (RoundKey[0]):
```text
before:
│ 65 6c 32 6f │
│ 63 2d 35 72 │
│ 75 32 20 20 │
│ 70 30 66 61 │
after:
│ 93 e6 6d 72 │
│ d9 86 f7 5a │
│ 87 c6 49 04 │
│ f9 be a4 95 │
```

第 1 轮详解:

SubBytes:
```text
before:
│ 93 e6 6d 72 │
│ d9 86 f7 5a │
│ 87 c6 49 04 │
│ f9 be a4 95 │
after:
│ dc 8e 3c 40 │
│ 35 44 68 be │
│ 17 b4 3b f2 │
│ 99 ae 49 2a │
典型映射: 0x00 → 0x63
```

ShiftRows:
```text
before:
│ dc 8e 3c 40 │
│ 35 44 68 be │
│ 17 b4 3b f2 │
│ 99 ae 49 2a │
after:
│ dc 8e 3c 40 │
│ 44 68 be 35 │
│ 3b f2 17 b4 │
│ 2a 99 ae 49 │
每行左循环位移: 第0行0、第1行1、第2行2、第3行3
```

MixColumns:
```text
before:
│ dc 8e 3c 40 │
│ 44 68 be 35 │
│ 3b f2 17 b4 │
│ 2a 99 ae 49 │
after:
│ 7e d4 18 22 │
│ 33 ca cc a4 │
│ 90 a9 45 dd │
│ 54 3a aa d3 │
  第 0 列输入: dc 44 3b 2a
  第 0 列输出: 7e 33 90 54
  02*dc ⊕ 03*44 ⊕ 01*3b ⊕ 01*2a = 7e
  01*dc ⊕ 02*44 ⊕ 03*3b ⊕ 01*2a = 33
  01*dc ⊕ 01*44 ⊕ 02*3b ⊕ 03*2a = 90
  03*dc ⊕ 01*44 ⊕ 01*3b ⊕ 02*2a = 54
```

AddRoundKey (RoundKey[1]):
```text
before:
│ 7e d4 18 22 │
│ 33 ca cc a4 │
│ 90 a9 45 dd │
│ 54 3a aa d3 │
after:
│ bd 9d 0e 29 │
│ bf ed 29 69 │
│ dd 10 95 29 │
│ 79 99 cb 46 │
```

第 2–10 轮快照:
```text
  Round 2: round_key前4字节=07c7f243, 状态前4字节=07c7f243
  Round 3: round_key前4字节=41d479ee, 状态前4字节=41d479ee
  Round 4: round_key前4字节=d855c190, 状态前4字节=d855c190
  Round 5: round_key前4字节=3d64c79d, 状态前4字节=3d64c79d
  Round 6: round_key前4字节=f0dac364, 状态前4字节=f0dac364
  Round 7: round_key前4字节=a577af43, 状态前4字节=a577af43
  Round 8: round_key前4字节=1c395e58, 状态前4字节=1c395e58
  Round 9: round_key前4字节=d130137b, 状态前4字节=d130137b
```

最终密文 (hex): 534a37bf13a9305c73f9f28c70e26ca663c99545d3a8aac2eca32c9dfac34e24
最终密文 (base64): U0o3vxOpMFxz+fKMcOJspmPJlUXTqKrC7KMsnfrDTiQ=

## 4. 解密过程（逆序详解 + 明文比对）

### 解密过程 (第一块)

操作顺序 (与加密相反):
初始 AddRoundKey[10] → InvShiftRows → InvSubBytes → AddRoundKey[9] → InvMixColumns → … → AddRoundKey[0]

初始 AddRoundKey (RoundKey[10]):
```text
before:
│ 53 13 73 70 │
│ 4a a9 f9 e2 │
│ 37 30 f2 6c │
│ bf 5c 8c a6 │
after:
│ 3e b7 05 fe │
│ fb 8f 27 04 │
│ a8 b4 7d dc │
│ de 21 41 7d │
```

第 1 个解密轮 (round 9):

InvShiftRows:
```text
before:
│ 3e b7 05 fe │
│ fb 8f 27 04 │
│ a8 b4 7d dc │
│ de 21 41 7d │
after:
│ 3e b7 05 fe │
│ 04 fb 8f 27 │
│ 7d dc a8 b4 │
│ 21 41 7d de │
```

InvSubBytes:
```text
before:
│ 3e b7 05 fe │
│ 04 fb 8f 27 │
│ 7d dc a8 b4 │
│ 21 41 7d de │
after:
│ d1 20 36 0c │
│ 30 63 73 3d │
│ 13 93 6f c6 │
│ 7b f8 13 9c │
```

AddRoundKey (RoundKey[9]):
```text
before:
│ d1 20 36 0c │
│ 30 63 73 3d │
│ 13 93 6f c6 │
│ 7b f8 13 9c │
after:
│ 8d e9 e4 f4 │
│ f4 f4 8b 05 │
│ cb 88 64 f9 │
│ 5b e4 a3 8a │
```

InvMixColumns:
```text
before:
│ 8d e9 e4 f4 │
│ f4 f4 8b 05 │
│ cb 88 64 f9 │
│ 5b e4 a3 8a │
after:
│ 9c 98 93 c7 │
│ e0 98 71 12 │
│ 13 1b 58 d5 │
│ 86 6a 12 82 │
```

去填充前后对照:
```text
  去填充前: 65 63 75 70 6c 2d 32 30 32 35 20 66 6f 72 20 61 20 73 69 6e 67 6c 65 20 63 68 61 6e 63 65 02 02
  去填充后: 65 63 75 70 6c 2d 32 30 32 35 20 66 6f 72 20 61 20 73 69 6e 67 6c 65 20 63 68 61 6e 63 65
```

明文比对: ✅ 一致

## 5. 分组模式对比（ECB / CBC / GCM）

### 分组模式对比

```text
模式 | 是否需要 IV | 相同块是否泄露 | 是否提供认证 | 本演示结果
ECB | 否 | 是 | 否 | 两块密文相同 → 图案泄露
CBC | 是 | 否 | 否 | 不同 IV 密文不同
GCM | 是 (nonce) | 否 | 是 | 概念说明，生产请用 cryptography AESGCM
```

ECB 结果:
```text
  明文: 4141414141414141414141414141414141414141414141414141414141414141
  密文块0: 1da6741ff67b9c4eda67beb89a10614f
  密文块1: 1da6741ff67b9c4eda67beb89a10614f
  两块相同: True
```
CBC 结果:
```text
  IV0: 00000000000000000000000000000000
  IV1: 01010101010101010101010101010101
  密文块0 (IV0): 1da6741ff67b9c4eda67beb89a10614f
  密文块0 (IV1): 7eddb530ca6009d9f0c70c1454e86258
  相同明文块在不同 IV 下密文不同
```
GCM 概念:
```text
  说明: GCM 提供认证加密，nonce 不可复用
  建议: 生产请用 cryptography 库的 AESGCM
```

## 6. 篡改检测（CBC 静默出错 vs GCM 认证失败）

### 篡改检测

```text
模式 | 改动位置 | 解密是否报错 | 明文是否正确 | 结论
CBC | 密文第1块第0字节 | 否 | 否 | 静默出错，明文错乱并传播至下一块
GCM | 任意密文 1 字节 | 是 | 否 | 认证失败抛异常
```

CBC 篡改演示:
```text
  正常解密: 4141414141414141414141414141414141414141414141414141414141414141
  篡改后解密: 4ea2f186086d403948c085783904761740414141414141414141414141414141
  解密是否报错: False
  明文是否正确: True
  结论: CBC 翻转密文字节导致对应明文块错乱，且影响下一块对应字节，但不抛异常
```
GCM 篡改检测:
```text
  说明: GCM 翻转 1 字节导致认证标签不匹配，抛认证失败异常
  结论: GCM 提供完整性保护
  结论: GCM 翻转 1 字节导致认证标签不匹配，抛认证失败异常
```

## 7. 安全说明与结论

### 安全说明与结论

本项目为纯 Python 教学实现，存在以下安全局限：
- 无侧信道防护（非常量时间，易受时序/缓存攻击）
- 无认证加密（ECB/CBC 均易受篡改与重放攻击）
- 密钥管理缺失（密钥由 os.urandom 生成，未持久化或派生）

生产环境建议：
- 使用 `cryptography` 库的 `AESGCM` 提供认证加密
- 使用随机 nonce，严禁 nonce 复用
- 使用 KDF（如 PBKDF2 / HKDF）从口令派生密钥

额外提醒：
- 永远不要自己实现生产级 AES（即使逻辑正确，也极易出现时序泄漏）
- 密文传输必须配合认证（AEAD），单纯 CBC/ECB 无法防御主动攻击
- 密钥长度建议至少 128 bit，优先 256 bit
