"""AES-128 block cipher. Pure stdlib. Teaching only, not for production."""
from .sbox import S_BOX, INV_S_BOX, sub_byte, inv_sub_byte
from .gf import mix_column, inv_mix_column


def _bytes_to_state(b):
    return [[b[r + 4 * c] for c in range(4)] for r in range(4)]


def _state_to_bytes(s):
    out = bytearray(16)
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = s[r][c]
    return bytes(out)


def _add_round_key(state, rk):
    for r in range(4):
        for c in range(4):
            state[r][c] ^= rk[r + 4 * c]


def _sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = sub_byte(state[r][c])


def _inv_sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = inv_sub_byte(state[r][c])


def _shift_rows(state):
    # row r shifted left by r
    for r in range(4):
        row = [state[r][(c + r) % 4] for c in range(4)]
        for c in range(4):
            state[r][c] = row[c]


def _inv_shift_rows(state):
    for r in range(4):
        row = [state[r][(c - r) % 4] for c in range(4)]
        for c in range(4):
            state[r][c] = row[c]


def _mix_columns(state):
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        new = mix_column(col)
        for r in range(4):
            state[r][c] = new[r]


def _inv_mix_columns(state):
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        new = inv_mix_column(col)
        for r in range(4):
            state[r][c] = new[r]


def _column0_detail(before_state, after_state):
    col_in = [before_state[r][0] for r in range(4)]
    col_out = [after_state[r][0] for r in range(4)]
    # build calc strings using MIX_MATRIX
    from .gf import MIX_MATRIX
    strs = []
    for r in range(4):
        terms = []
        for c in range(4):
            a = MIX_MATRIX[r][c]
            b = col_in[c]
            terms.append(f"{a:02x}*{b:02x}")
        # compute result
        res = col_out[r]
        strs.append(" ⊕ ".join(terms) + f" = {res:02x}")
    return {"inputs": col_in, "outputs": col_out, "calc": strs}


def encrypt_block(block, round_keys, record=False):
    if len(block) != 16:
        raise ValueError("block must be 16 bytes")
    if len(round_keys) != 11:
        raise ValueError("need 11 round keys")
    state = _bytes_to_state(block)
    # initial add round key
    before = _state_to_bytes(state)
    _add_round_key(state, round_keys[0])
    after = _state_to_bytes(state)
    trace = None
    if record:
        trace = {
            "initial_add_round_key": {"before": before, "after": after, "round_key_index": 0},
            "rounds": [],
            "final_round": None,
        }
    # rounds 1..9
    for rn in range(1, 10):
        sb_before = _state_to_bytes(state)
        _sub_bytes(state)
        sb_after = _state_to_bytes(state)
        sr_before = sb_after
        _shift_rows(state)
        sr_after = _state_to_bytes(state)
        mc_before = sr_after
        _mix_columns(state)
        mc_after = _state_to_bytes(state)
        ar_before = mc_after
        _add_round_key(state, round_keys[rn])
        ar_after = _state_to_bytes(state)
        if record:
            detail = _column0_detail(_bytes_to_state(mc_before), _bytes_to_state(mc_after))
            trace["rounds"].append({
                "round_no": rn,
                "sub_bytes": {"before": sb_before, "after": sb_after},
                "shift_rows": {"before": sr_before, "after": sr_after},
                "mix_columns": {"before": mc_before, "after": mc_after, "column0_detail": detail},
                "add_round_key": {"before": ar_before, "after": ar_after, "round_key_index": rn},
            })
    # final round 10: no mix columns
    rn = 10
    sb_before = _state_to_bytes(state)
    _sub_bytes(state)
    sb_after = _state_to_bytes(state)
    sr_before = sb_after
    _shift_rows(state)
    sr_after = _state_to_bytes(state)
    ar_before = sr_after
    _add_round_key(state, round_keys[rn])
    ar_after = _state_to_bytes(state)
    if record:
        trace["final_round"] = {
            "round_no": rn,
            "sub_bytes": {"before": sb_before, "after": sb_after},
            "shift_rows": {"before": sr_before, "after": sr_after},
            "add_round_key": {"before": ar_before, "after": ar_after, "round_key_index": rn},
        }
    result = _state_to_bytes(state)
    if record:
        return result, trace
    return result


def decrypt_block(block, round_keys, record=False):
    if len(block) != 16:
        raise ValueError("block must be 16 bytes")
    if len(round_keys) != 11:
        raise ValueError("need 11 round keys")
    state = _bytes_to_state(block)
    # initial add round key [10]
    before = _state_to_bytes(state)
    _add_round_key(state, round_keys[10])
    after = _state_to_bytes(state)
    trace = None
    if record:
        trace = {
            "initial_add_round_key": {"before": before, "after": after, "round_key_index": 10},
            "rounds": [],
            "final_round": None,
        }
    # rounds 9..1
    for idx, rn in enumerate(range(9, 0, -1)):
        # inv shift rows
        isr_before = _state_to_bytes(state)
        _inv_shift_rows(state)
        isr_after = _state_to_bytes(state)
        # inv sub bytes
        isb_before = isr_after
        _inv_sub_bytes(state)
        isb_after = _state_to_bytes(state)
        # add round key [rn]
        ark_before = isb_after
        _add_round_key(state, round_keys[rn])
        ark_after = _state_to_bytes(state)
        # inv mix columns
        imc_before = ark_after
        _inv_mix_columns(state)
        imc_after = _state_to_bytes(state)
        if record:
            trace["rounds"].append({
                "round_no": rn,
                "inv_shift_rows": {"before": isr_before, "after": isr_after},
                "inv_sub_bytes": {"before": isb_before, "after": isb_after},
                "add_round_key": {"before": ark_before, "after": ark_after, "round_key_index": rn},
                "inv_mix_columns": {"before": imc_before, "after": imc_after, "column0_detail": None},
            })
    # final round: inv shift rows, inv sub bytes, add round key 0 (no inv mix)
    isr_before = _state_to_bytes(state)
    _inv_shift_rows(state)
    isr_after = _state_to_bytes(state)
    isb_before = isr_after
    _inv_sub_bytes(state)
    isb_after = _state_to_bytes(state)
    ark_before = isb_after
    _add_round_key(state, round_keys[0])
    ark_after = _state_to_bytes(state)
    if record:
        trace["final_round"] = {
            "round_no": 0,
            "inv_shift_rows": {"before": isr_before, "after": isr_after},
            "inv_sub_bytes": {"before": isb_before, "after": isb_after},
            "add_round_key": {"before": ark_before, "after": ark_after, "round_key_index": 0},
        }
    result = _state_to_bytes(state)
    if record:
        return result, trace
    return result


if __name__ == "__main__":
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    from .key_expansion import expand_key
    rks = expand_key(key)
    ct = encrypt_block(pt, rks)
    assert ct.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a", ct.hex()
    dec = decrypt_block(ct, rks)
    assert dec == pt
    print("FIPS-197 vector OK")
