# AES 加密原理与实战教学

## 0. 本次样本

- 明文: 'nku-2021'
- 明文字节长度: 8
- 密钥 (hex): 4448b289e1214457a1e18b4174749e29
- 填充后总块数: 1
- 密文 (hex): 8985adbb014b06dc9e04f50c9fc96481

## 1. 明文分组与 PKCS#7 填充

### 明文与填充

```text
明文: 'nku-2021'
明文字节 (hex): 6e 6b 75 2d 32 30 32 31
明文长度: 8 字节
填充长度: 8 字节 (每个字节值 0x08)
填充前后对照:
  填充前: 6e 6b 75 2d 32 30 32 31
  填充后: 6e 6b 75 2d 32 30 32 31 08 08 08 08 08 08 08 08
分组 (每块 16 字节):
  块 0: 6e 6b 75 2d 32 30 32 31 08 08 08 08 08 08 08 08
```

## 2. 密钥扩展

### 密钥扩展 (AES-128)

原始密钥 (hex): 44 48 b2 89 e1 21 44 57 a1 e1 8b 41 74 74 9e 29

44 个扩展字 (w[0]..w[43]):
```text
  w[ 0]: 44 48 b2 89
  w[ 1]: e1 21 44 57
  w[ 2]: a1 e1 8b 41
  w[ 3]: 74 74 9e 29
  w[ 4]: d7 43 17 1b
  w[ 5]: 36 62 53 4c
  w[ 6]: 97 83 d8 0d
  w[ 7]: e3 f7 46 24
  w[ 8]: bd 19 21 0a
  w[ 9]: 8b 7b 72 46
  w[10]: 1c f8 aa 4b
  w[11]: ff 0f ec 6f
  w[12]: cf d7 89 1c
  w[13]: 44 ac fb 5a
  w[14]: 58 54 51 11
  w[15]: a7 5b bd 7e
  w[16]: fe ad 7a 40
  w[17]: ba 01 81 1a
  w[18]: e2 55 d0 0b
  w[19]: 45 0e 6d 75
  w[20]: 45 91 e7 2e
  w[21]: ff 90 66 34
  w[22]: 1d c5 b6 3f
  w[23]: 58 cb db 4a
  w[24]: 7a 28 31 44
  w[25]: 85 b8 57 70
  w[26]: 98 7d e1 4f
  w[27]: c0 b6 3a 05
  w[28]: 74 a8 5a fe
  w[29]: f1 10 0d 8e
  w[30]: 69 6d ec c1
  w[31]: a9 db d6 c4
  w[32]: 4d 5e 46 2d
  w[33]: bc 4e 4b a3
  w[34]: d5 23 a7 62
  w[35]: 7c f8 71 a6
  w[36]: 17 fd 62 3d
  w[37]: ab b3 29 9e
  w[38]: 7e 90 8e fc
  w[39]: 02 68 ff 5a
  w[40]: 64 eb dc 4a
  w[41]: cf 58 f5 d4
  w[42]: b1 c8 7b 28
  w[43]: b3 a0 84 72
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
  RoundKey[0]: 4448b289e1214457a1e18b4174749e29
  RoundKey[1]: d743171b3662534c9783d80de3f74624
  RoundKey[2]: bd19210a8b7b72461cf8aa4bff0fec6f
  RoundKey[3]: cfd7891c44acfb5a58545111a75bbd7e
  RoundKey[4]: fead7a40ba01811ae255d00b450e6d75
  RoundKey[5]: 4591e72eff9066341dc5b63f58cbdb4a
  RoundKey[6]: 7a28314485b85770987de14fc0b63a05
  RoundKey[7]: 74a85afef1100d8e696decc1a9dbd6c4
  RoundKey[8]: 4d5e462dbc4e4ba3d523a7627cf871a6
  RoundKey[9]: 17fd623dabb3299e7e908efc0268ff5a
  RoundKey[10]: 64ebdc4acf58f5d4b1c87b28b3a08472
```

## 3. 加密过程（第 1 轮详解 + 第 2–10 轮快照）

### 加密过程 (第一块)

初始 AddRoundKey (RoundKey[0]):
```text
before:
│ 6e 32 08 08 │
│ 6b 30 08 08 │
│ 75 32 08 08 │
│ 2d 31 08 08 │
after:
│ 2a d3 a9 7c │
│ 23 11 e9 7c │
│ c7 76 83 96 │
│ a4 66 49 21 │
```

第 1 轮详解:

SubBytes:
```text
before:
│ 2a d3 a9 7c │
│ 23 11 e9 7c │
│ c7 76 83 96 │
│ a4 66 49 21 │
after:
│ e5 66 d3 10 │
│ 26 82 1e 10 │
│ c6 38 ec 90 │
│ 49 33 3b fd │
典型映射: 0x00 → 0x63
```

ShiftRows:
```text
before:
│ e5 66 d3 10 │
│ 26 82 1e 10 │
│ c6 38 ec 90 │
│ 49 33 3b fd │
after:
│ e5 66 d3 10 │
│ 82 1e 10 26 │
│ ec 90 c6 38 │
│ fd 49 33 3b │
每行左循环位移: 第0行0、第1行1、第2行2、第3行3
```

MixColumns:
```text
before:
│ e5 66 d3 10 │
│ 82 1e 10 26 │
│ ec 90 c6 38 │
│ fd 49 33 3b │
after:
│ 5d 37 78 49 │
│ 28 b8 91 2f │
│ b8 98 01 0b │
│ bb b6 de 58 │
  第 0 列输入: e5 82 ec fd
  第 0 列输出: 5d 28 b8 bb
  02*e5 ⊕ 03*82 ⊕ 01*ec ⊕ 01*fd = 5d
  01*e5 ⊕ 02*82 ⊕ 03*ec ⊕ 01*fd = 28
  01*e5 ⊕ 01*82 ⊕ 02*ec ⊕ 03*fd = b8
  03*e5 ⊕ 01*82 ⊕ 01*ec ⊕ 02*fd = bb
```

AddRoundKey (RoundKey[1]):
```text
before:
│ 5d 37 78 49 │
│ 28 b8 91 2f │
│ b8 98 01 0b │
│ bb b6 de 58 │
after:
│ 8a 01 ef aa │
│ 6b da 12 d8 │
│ af cb d9 4d │
│ a0 fa d3 7c │
```

第 2–10 轮快照:
```text
  Round 2: round_key前4字节=9d8652ca, 状态前4字节=9d8652ca
  Round 3: round_key前4字节=76c60ece, 状态前4字节=76c60ece
  Round 4: round_key前4字节=33213191, 状态前4字节=33213191
  Round 5: round_key前4字节=b88113fe, 状态前4字节=b88113fe
  Round 6: round_key前4字节=54de4528, 状态前4字节=54de4528
  Round 7: round_key前4字节=e3d1d425, 状态前4字节=e3d1d425
  Round 8: round_key前4字节=d30fe6a9, 状态前4字节=d30fe6a9
  Round 9: round_key前4字节=53e4e6bf, 状态前4字节=53e4e6bf
```

最终密文 (hex): 8985adbb014b06dc9e04f50c9fc96481
最终密文 (base64): iYWtuwFLBtyeBPUMn8lkgQ==

## 4. 解密过程（逆序详解 + 明文比对）

### 解密过程 (第一块)

操作顺序 (与加密相反):
初始 AddRoundKey[10] → InvShiftRows → InvSubBytes → AddRoundKey[9] → InvMixColumns → … → AddRoundKey[0]

初始 AddRoundKey (RoundKey[10]):
```text
before:
│ 89 01 9e 9f │
│ 85 4b 04 c9 │
│ ad 06 f5 64 │
│ bb dc 0c 81 │
after:
│ ed ce 2f 2c │
│ 6e 13 cc 69 │
│ 71 f3 8e e0 │
│ f1 08 24 f3 │
```

第 1 个解密轮 (round 9):

InvShiftRows:
```text
before:
│ ed ce 2f 2c │
│ 6e 13 cc 69 │
│ 71 f3 8e e0 │
│ f1 08 24 f3 │
after:
│ ed ce 2f 2c │
│ 69 6e 13 cc │
│ 8e e0 71 f3 │
│ 08 24 f3 f1 │
```

InvSubBytes:
```text
before:
│ ed ce 2f 2c │
│ 69 6e 13 cc │
│ 8e e0 71 f3 │
│ 08 24 f3 f1 │
after:
│ 53 ec 4e 42 │
│ e4 45 82 27 │
│ e6 a0 2c 7e │
│ bf a6 7e 2b │
```

AddRoundKey (RoundKey[9]):
```text
before:
│ 53 ec 4e 42 │
│ e4 45 82 27 │
│ e6 a0 2c 7e │
│ bf a6 7e 2b │
after:
│ 44 47 30 40 │
│ 19 f6 12 4f │
│ 84 89 a2 81 │
│ 82 38 82 71 │
```

InvMixColumns:
```text
before:
│ 44 47 30 40 │
│ 19 f6 12 4f │
│ 84 89 a2 81 │
│ 82 38 82 71 │
after:
│ 66 2b 18 31 │
│ d7 1d 0d 76 │
│ 10 e5 8e 15 │
│ fa d3 99 ad │
```

去填充前后对照:
```text
  去填充前: 6e 6b 75 2d 32 30 32 31 08 08 08 08 08 08 08 08
  去填充后: 6e 6b 75 2d 32 30 32 31
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
  密文块0: 4f18a2cee92d63810f60921ac71ecd2d
  密文块1: 4f18a2cee92d63810f60921ac71ecd2d
  两块相同: True
```
CBC 结果:
```text
  IV0: 00000000000000000000000000000000
  IV1: 01010101010101010101010101010101
  密文块0 (IV0): 4f18a2cee92d63810f60921ac71ecd2d
  密文块0 (IV1): 7cbb4cd077bc636775dcc637606756c8
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
  篡改后解密: ec5a8e55d14e0d9341847a485500565e40414141414141414141414141414141
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

> 未运行
