"""GF(2^8) arithmetic for AES. Pure stdlib. Teaching only, not for production."""

MIX_MATRIX = [
    [2, 3, 1, 1],
    [1, 2, 3, 1],
    [1, 1, 2, 3],
    [3, 1, 1, 2],
]
INV_MIX_MATRIX = [
    [14, 11, 13, 9],
    [9, 14, 11, 13],
    [13, 9, 14, 11],
    [11, 13, 9, 14],
]


def gf_mul(a: int, b: int) -> int:
    a &= 0xFF
    b &= 0xFF
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p & 0xFF


def _mul_col(col, mat):
    out = [0, 0, 0, 0]
    for r in range(4):
        acc = 0
        for c in range(4):
            acc ^= gf_mul(col[c], mat[r][c])
        out[r] = acc
    return out


def mix_column(col: list[int]) -> list[int]:
    return _mul_col(col, MIX_MATRIX)


def inv_mix_column(col: list[int]) -> list[int]:
    return _mul_col(col, INV_MIX_MATRIX)


assert gf_mul(0x57, 0x83) == 0xC1
