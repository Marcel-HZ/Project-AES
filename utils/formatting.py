"""Formatting helpers. Pure stdlib. Teaching only."""
import sys

try:
    from tqdm import tqdm as _tqdm
    _HAS_TQDM = True
except Exception:
    _HAS_TQDM = False


def hr(char="─", width=64):
    return char * width


def render_hex(b, sep=" "):
    return sep.join(f"{x:02x}" for x in b)


def render_matrix(b, title=""):
    lines = []
    if title:
        lines.append(title)
    for r in range(4):
        row = " ".join(f"{b[r + 4 * c]:02x}" for c in range(4))
        lines.append(f"│ {row} │")
    return "\n".join(lines)


def render_before_after(before, after, title):
    return f"{title}\nbefore:\n{render_matrix(before)}\nafter:\n{render_matrix(after)}"


def render_step_header(no, title):
    return f"┌─ Step {no} · {title} " + "─" * 20


def render_table(headers, rows):
    out = [" | ".join(headers)]
    for row in rows:
        out.append(" | ".join(str(x) for x in row))
    return "\n".join(out)


def progress(iterable, desc=""):
    if _HAS_TQDM:
        return _tqdm(iterable, desc=desc)
    return iterable


def info(msg):
    print(f"[i] {msg}")


def ok(msg):
    print(f"[✓] {msg}")


def warn(msg):
    print(f"[!] {msg}")


def err(msg):
    print(f"[x] {msg}")


def pause():
    try:
        if sys.stdin.isatty():
            input("按 Enter 继续...")
    except EOFError:
        pass
