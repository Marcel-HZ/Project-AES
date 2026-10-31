"""AES-128 key expansion. Pure stdlib. Teaching only, not for production."""
from .sbox import sub_byte

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _to_words(key):
    return [int.from_bytes(key[i:i + 4], "big") for i in range(0, 16, 4)]


def expand_key(key: bytes) -> list[bytes]:
    if len(key) != 16:
        raise ValueError("key must be 16 bytes")
    w = [0] * 44
    for i in range(4):
        w[i] = int.from_bytes(key[i * 4:(i + 1) * 4], "big")
    for i in range(4, 44):
        temp = w[i - 1]
        if i % 4 == 0:
            # RotWord
            temp = ((temp << 8) | (temp >> 24)) & 0xFFFFFFFF
            # SubWord
            temp = (sub_byte((temp >> 24) & 0xFF) << 24) | \
                   (sub_byte((temp >> 16) & 0xFF) << 16) | \
                   (sub_byte((temp >> 8) & 0xFF) << 8) | \
                   sub_byte(temp & 0xFF)
            # Rcon
            temp ^= (RCON[i // 4 - 1] << 24)
        w[i] = w[i - 4] ^ temp
    round_keys = []
    for r in range(11):
        rk = b"".join(w[r * 4 + j].to_bytes(4, "big") for j in range(4))
        round_keys.append(rk)
    return round_keys


def expand_key_trace(key: bytes) -> dict:
    if len(key) != 16:
        raise ValueError("key must be 16 bytes")
    w = [0] * 44
    for i in range(4):
        w[i] = int.from_bytes(key[i * 4:(i + 1) * 4], "big")
    steps = []
    rcon_used = []
    for i in range(4, 44):
        temp = w[i - 1]
        rot_sub_xor = None
        if i % 4 == 0:
            rot = ((temp << 8) | (temp >> 24)) & 0xFFFFFFFF
            sub = (sub_byte((rot >> 24) & 0xFF) << 24) | \
                  (sub_byte((rot >> 16) & 0xFF) << 16) | \
                  (sub_byte((rot >> 8) & 0xFF) << 8) | \
                  sub_byte(rot & 0xFF)
            rcon_val = RCON[i // 4 - 1]
            xored = sub ^ (rcon_val << 24)
            rot_sub_xor = {
                "i": i,
                "before": temp,
                "rotword": rot,
                "subword": sub,
                "rcon": rcon_val,
                "after_xor": xored,
            }
            rcon_used.append({"i": i, "rcon": rcon_val})
            temp = xored
        w[i] = w[i - 4] ^ temp
        if rot_sub_xor is not None:
            steps.append(rot_sub_xor)
    round_keys = []
    for r in range(11):
        rk = b"".join(w[r * 4 + j].to_bytes(4, "big") for j in range(4))
        round_keys.append(rk)
    return {
        "w": [x.to_bytes(4, "big") for x in w],
        "rcon_used": rcon_used,
        "rot_sub_xor_steps": steps,
        "round_keys": round_keys,
    }
