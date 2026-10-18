"""Unified diff parser: yields only ADDED lines with their new-file line numbers."""
import re

H_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class DiffError(Exception):
    pass


def parse_diff(text: str):
    """Return {path: [(lineno, text), ...]} for added lines. Hunk counts decide where a hunk ends,
    so an added line whose content starts with '++ ' is not mistaken for a file header."""
    out: dict = {}
    path = None
    new_no = old_left = new_left = 0
    saw_header = False
    for raw in text.splitlines():
        if old_left > 0 or new_left > 0:
            c = raw[:1]
            if c == "+":
                if path is not None:
                    out.setdefault(path, []).append((new_no, raw[1:]))
                new_no += 1
                new_left -= 1
            elif c == "-":
                old_left -= 1
            elif c == " " or raw == "":
                new_no += 1
                new_left -= 1
                old_left -= 1
            elif c == "\\":
                pass
            else:
                raise DiffError(f"unexpected line inside hunk: {raw[:30]!r}")
            continue
        if raw.startswith("+++ "):
            saw_header = True
            p = raw[4:].split("\t")[0].strip()
            path = None if p == "/dev/null" else (p[2:] if p.startswith("b/") else p)
            continue
        m = H_RE.match(raw)
        if m:
            saw_header = True
            old_left = int(m.group(2)) if m.group(2) is not None else 1
            new_left = int(m.group(4)) if m.group(4) is not None else 1
            new_no = int(m.group(3))
    if text.strip() and not saw_header:
        raise DiffError("input does not look like a unified diff")
    return out
