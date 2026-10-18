"""Shannon entropy per character class, length thresholds, and hard-negative shape filters."""
import math
import re
from collections import Counter

# Candidate tokens: runs of base64/url-safe characters, optional trailing '=' padding.
TOKEN_RE = re.compile(r"[A-Za-z0-9+/_\-]{12,}={0,2}")
HEX_RE = re.compile(r"[0-9a-fA-F]+")
_H = "[0-9a-fA-F]"
UUID_RE = re.compile(rf"{_H}{{8}}-{_H}{{4}}-{_H}{{4}}-{_H}{{4}}-{_H}{{12}}")
_SEG = r"(?:[A-Za-z][a-z]{2,}\d{0,2}|v\d{1,2})"
IDENT_RE = re.compile(rf"(?:{_SEG}[_\-./]?){{2,}}")  # snake/kebab/camel words
CONST_RE = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+")  # ALL_CAPS_CONSTANT
INTEGRITY_RE = re.compile(r"sha(?:1|256|384|512)-")  # lockfile integrity strings


def shannon(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def char_class(tok: str) -> str:
    if tok.isdigit():
        return "digits"
    return "hex" if HEX_RE.fullmatch(tok) else "b64"


def passes(tok: str, cfg) -> bool:
    """Length and per-class entropy thresholds (both inclusive)."""
    if len(tok) < cfg.min_len:
        return False
    cls = char_class(tok)
    if cls == "digits":
        return False
    thr = cfg.ent_hex if cls == "hex" else cfg.ent_b64
    return round(shannon(tok), 9) >= thr


def shape_negative(tok: str, line: str):
    """Return the name of a known benign shape, or None."""
    if UUID_RE.fullmatch(tok):
        return "uuid"
    if INTEGRITY_RE.match(tok):
        return "integrity"
    if IDENT_RE.fullmatch(tok) or CONST_RE.fullmatch(tok):
        return "identifier"
    if "base64," in line and len(tok) > 100:
        return "data-uri"
    return None


def is_minified(line: str) -> bool:
    return len(line) > 400 and (line.count(";") + line.count("{")) > 15
