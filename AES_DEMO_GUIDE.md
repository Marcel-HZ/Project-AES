# AES 加密原理与实战教学

## 0. 本次样本

- 明文: 'ecupl-2025'
- 明文字节长度: 10
- 密钥 (hex): 30f32d02aaca8987e1c155f2a4c4fe1f
- 填充后总块数: 1
- 密文 (hex): ef630f1b29010a8b536a8be1e48ccf70

## 1. 明文分组与 PKCS#7 填充

### 明文与填充

```text
明文: 'ecupl-2025'
明文字节 (hex): 65 63 75 70 6c 2d 32 30 32 35
明文长度: 10 字节
填充长度: 6 字节 (每个字节值 0x06)
填充前后对照:
  填充前: 65 63 75 70 6c 2d 32 30 32 35
  填充后: 65 63 75 70 6c 2d 32 30 32 35 06 06 06 06 06 06
分组 (每块 16 字节):
  块 0: 65 63 75 70 6c 2d 32 30 32 35 06 06 06 06 06 06
```

## 2. 密钥扩展

### 密钥扩展 (AES-128)

原始密钥 (hex): 30 f3 2d 02 aa ca 89 87 e1 c1 55 f2 a4 c4 fe 1f

44 个扩展字 (w[0]..w[43]):
```text
  w[ 0]: 30 f3 2d 02
  w[ 1]: aa ca 89 87
  w[ 2]: e1 c1 55 f2
  w[ 3]: a4 c4 fe 1f
  w[ 4]: 2d 48 ed 4b
  w[ 5]: 87 82 64 cc
  w[ 6]: 66 43 31 3e
  w[ 7]: c2 87 cf 21
  w[ 8]: 38 c2 10 6e
  w[ 9]: bf 40 74 a2
  w[10]: d9 03 45 9c
  w[11]: 1b 84 8a bd
  w[12]: 63 bc 6a c1
  w[13]: dc fc 1e 63
  w[14]: 05 ff 5b ff
  w[15]: 1e 7b d1 42
  w[16]: 4a 82 46 b3
  w[17]: 96 7e 58 d0
  w[18]: 93 81 03 2f
  w[19]: 8d fa d2 6d
  w[20]: 77 37 7a ee
  w[21]: e1 49 22 3e
  w[22]: 72 c8 21 11
  w[23]: ff 32 f3 7c
  w[24]: 74 3a 6a f8
  w[25]: 95 73 48 c6
  w[26]: e7 bb 69 d7
  w[27]: 18 89 9a ab
  w[28]: 93 82 08 55
  w[29]: 06 f1 40 93
  w[30]: e1 4a 29 44
  w[31]: f9 c3 b3 ef
  w[32]: 3d ef d7 cc
  w[33]: 3b 1e 97 5f
  w[34]: da 54 be 1b
  w[35]: 23 97 0d f4
  w[36]: ae 38 68 ea
  w[37]: 95 26 ff b5
  w[38]: 4f 72 41 ae
  w[39]: 6c e5 4c 5a
  w[40]: 41 11 d6 ba
  w[41]: d4 37 29 0f
  w[42]: 9b 45 68 a1
  w[43]: f7 a0 24 fb
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
  RoundKey[0]: 30f32d02aaca8987e1c155f2a4c4fe1f
  RoundKey[1]: 2d48ed4b878264cc6643313ec287cf21
  RoundKey[2]: 38c2106ebf4074a2d903459c1b848abd
  RoundKey[3]: 63bc6ac1dcfc1e6305ff5bff1e7bd142
  RoundKey[4]: 4a8246b3967e58d09381032f8dfad26d
  RoundKey[5]: 77377aeee149223e72c82111ff32f37c
  RoundKey[6]: 743a6af8957348c6e7bb69d718899aab
  RoundKey[7]: 9382085506f14093e14a2944f9c3b3ef
  RoundKey[8]: 3defd7cc3b1e975fda54be1b23970df4
  RoundKey[9]: ae3868ea9526ffb54f7241ae6ce54c5a
  RoundKey[10]: 4111d6bad437290f9b4568a1f7a024fb
```

## 3. 加密过程（第 1 轮详解 + 第 2–10 轮快照）

### 加密过程 (第一块)

初始 AddRoundKey (RoundKey[0]):
```text
before:
│ 65 6c 32 06 │
│ 63 2d 35 06 │
│ 75 32 06 06 │
│ 70 30 06 06 │
after:
│ 55 c6 d3 a2 │
│ 90 e7 f4 c2 │
│ 58 bb 53 f8 │
│ 72 b7 f4 19 │
```

第 1 轮详解:

SubBytes:
```text
before:
│ 55 c6 d3 a2 │
│ 90 e7 f4 c2 │
│ 58 bb 53 f8 │
│ 72 b7 f4 19 │
after:
│ fc b4 66 3a │
│ 60 94 bf 25 │
│ 6a ea ed 41 │
│ 40 a9 bf d4 │
典型映射: 0x00 → 0x63
```

ShiftRows:
```text
before:
│ fc b4 66 3a │
│ 60 94 bf 25 │
│ 6a ea ed 41 │
│ 40 a9 bf d4 │
after:
│ fc b4 66 3a │
│ 94 bf 25 60 │
│ ed 41 6a ea │
│ d4 40 a9 bf │
每行左循环位移: 第0行0、第1行1、第2行2、第3行3
```

MixColumns:
```text
before:
│ fc b4 66 3a │
│ 94 bf 25 60 │
│ ed 41 6a ea │
│ d4 40 a9 bf │
after:
│ 7d a8 60 81 │
│ 37 52 3b 60 │
│ ce 49 77 4f │
│ d5 b9 ac a1 │
  第 0 列输入: fc 94 ed d4
  第 0 列输出: 7d 37 ce d5
  02*fc ⊕ 03*94 ⊕ 01*ed ⊕ 01*d4 = 7d
  01*fc ⊕ 02*94 ⊕ 03*ed ⊕ 01*d4 = 37
  01*fc ⊕ 01*94 ⊕ 02*ed ⊕ 03*d4 = ce
  03*fc ⊕ 01*94 ⊕ 01*ed ⊕ 02*d4 = d5
```

AddRoundKey (RoundKey[1]):
```text
before:
│ 7d a8 60 81 │
│ 37 52 3b 60 │
│ ce 49 77 4f │
│ d5 b9 ac a1 │
after:
│ 50 2f 06 43 │
│ 7f d0 78 e7 │
│ 23 2d 46 80 │
│ 9e 75 92 80 │
```

第 2–10 轮快照:
```text
  Round 2: round_key前4字节=9952cb30, 状态前4字节=9952cb30
  Round 3: round_key前4字节=b0bb2df5, 状态前4字节=b0bb2df5
  Round 4: round_key前4字节=0e205af1, 状态前4字节=0e205af1
  Round 5: round_key前4字节=1734b41e, 状态前4字节=1734b41e
  Round 6: round_key前4字节=ea839259, 状态前4字节=ea839259
  Round 7: round_key前4字节=c02f152a, 状态前4字节=c02f152a
  Round 8: round_key前4字节=3cd3bcfd, 状态前4字节=3cd3bcfd
  Round 9: round_key前4字节=be424d4f, 状态前4字节=be424d4f
```

最终密文 (hex): ef630f1b29010a8b536a8be1e48ccf70
最终密文 (base64): 72MPGykBCotTaovh5IzPcA==

## 4. 解密过程（逆序详解 + 明文比对）

### 解密过程 (第一块)

操作顺序 (与加密相反):
初始 AddRoundKey[10] → InvShiftRows → InvSubBytes → AddRoundKey[9] → InvMixColumns → … → AddRoundKey[0]

初始 AddRoundKey (RoundKey[10]):
```text
before:
│ ef 29 53 e4 │
│ 63 01 6a 8c │
│ 0f 0a 8b cf │
│ 1b 8b e1 70 │
after:
│ ae fd c8 13 │
│ 72 36 2f 2c │
│ d9 23 e3 eb │
│ a1 84 40 8b │
```

第 1 个解密轮 (round 9):

InvShiftRows:
```text
before:
│ ae fd c8 13 │
│ 72 36 2f 2c │
│ d9 23 e3 eb │
│ a1 84 40 8b │
after:
│ ae fd c8 13 │
│ 2c 72 36 2f │
│ e3 eb d9 23 │
│ 84 40 8b a1 │
```

InvSubBytes:
```text
before:
│ ae fd c8 13 │
│ 2c 72 36 2f │
│ e3 eb d9 23 │
│ 84 40 8b a1 │
after:
│ be 21 b1 82 │
│ 42 1e 24 4e │
│ 4d 3c e5 32 │
│ 4f 72 ce f1 │
```

AddRoundKey (RoundKey[9]):
```text
before:
│ be 21 b1 82 │
│ 42 1e 24 4e │
│ 4d 3c e5 32 │
│ 4f 72 ce f1 │
after:
│ 10 b4 fe ee │
│ 7a 38 56 ab │
│ 25 c3 a4 7e │
│ a5 c7 60 ab │
```

InvMixColumns:
```text
before:
│ 10 b4 fe ee │
│ 7a 38 56 ab │
│ 25 c3 a4 7e │
│ a5 c7 60 ab │
after:
│ eb d4 e7 6e │
│ 6e a0 50 66 │
│ 11 a8 65 c5 │
│ 7e 54 be 5d │
```

去填充前后对照:
```text
  去填充前: 65 63 75 70 6c 2d 32 30 32 35 06 06 06 06 06 06
  去填充后: 65 63 75 70 6c 2d 32 30 32 35
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
  密文块0: 2ec0bed7c96c0a73ac89fe891c0ff530
  密文块1: 2ec0bed7c96c0a73ac89fe891c0ff530
  两块相同: True
```
CBC 结果:
```text
  IV0: 00000000000000000000000000000000
  IV1: 01010101010101010101010101010101
  密文块0 (IV0): 2ec0bed7c96c0a73ac89fe891c0ff530
  密文块0 (IV1): b5b708aec01014c4083fc06e433c6aec
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
  篡改后解密: cc98a19593bbd41b32a30d3f3dca30db40414141414141414141414141414141
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
