"""PKCS#7 padding helpers. Pure stdlib. Teaching only, not for production."""


def pad(data: bytes) -> bytes:
    n = 16 - (len(data) % 16)
    if n == 0:
        n = 16
    return data + bytes([n] * n)


def unpad(data: bytes) -> bytes:
    if not data or len(data) % 16 != 0:
        raise ValueError("invalid padded data length")
    n = data[-1]
    if n < 1 or n > 16:
        raise ValueError("invalid padding value")
    if data[-n:] != bytes([n] * n):
        raise ValueError("invalid padding bytes")
    return data[:-n]


def split_blocks(data: bytes) -> list[bytes]:
    if len(data) % 16 != 0:
        raise ValueError("data length must be multiple of 16")
    return [data[i:i + 16] for i in range(0, len(data), 16)]
