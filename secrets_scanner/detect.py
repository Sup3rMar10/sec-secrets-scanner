"""Line-level detection: pattern layer, entropy layer, context scoring, suppressions."""
import base64
import re
from dataclasses import dataclass

from .entropy import TOKEN_RE, is_minified, passes, shannon, shape_negative
from .patterns import RULES

MODES = ("patterns", "entropy", "context", "combined")


@dataclass(frozen=True)
class Config:
    """mode: patterns = provider patterns only; entropy = raw entropy only (no filters, no context);
    context = entropy + shape filters + context scoring; combined = patterns + context layer."""
    mode: str = "combined"
    # Defaults = grid-search optimum on the DEV split for mode=combined (tests/test_eval.py keeps them in sync).
    min_len: int = 16
    ent_hex: float = 2.8
    ent_b64: float = 3.2
    ctx: float = 0.6


@dataclass
class Match:
    rule: str
    value: str
    col: int
    score: float
    rejected: bool = False  # inline suppression present but without a reason


SENS = r"(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|auth|credential|private[_-]?key|access[_-]?key|bearer)"
SENS_RE = re.compile(SENS + r"[\w\-.]*[\"']?\s*(?::=|=>|[:=])\s*[^=:]{0,40}$", re.I)
SHAPE_RE = re.compile(r"(?::=|=>|[:=])\s*[\[(]?\s*[\"'`]?$")
PLACEHOLDER_RE = re.compile(r"example|placeholder|dummy|sample|fake|changeme|redacted|xxxx|your[_-]|\btests?\b", re.I)
HASHWORD_RE = re.compile(r"(?<![A-Za-z])(?:sha\d*|commit|checksum|digest|md5|etag|uuid|guid|integrity)(?![A-Za-z])|hash(?![a-z])", re.I)
NOSECRET_RE = re.compile(r"(?:#|//|--|/\*|<!--)\s*nosecret\b(?:\s*:\s*(.*))?", re.I)
CONCAT_RE = re.compile(r"[\"'`]\s*\+\s*[\"'`]")
KV_RE = re.compile(r"[\w.\-]*" + SENS + r"[\w.\-]*\s*[:=]\s*(\S{6,})", re.I)
BASIC_RE = re.compile(r"[\w.@\-]{2,}:(\S{6,})")

PATTERN_BASE = 0.95
BASE = 0.2
W_NAME = 0.5
W_SHAPE = 0.1
PLACEHOLDER_PENALTY = 0.4
HASH_PENALTY = 0.4
B64_SCORE = 0.9


def context_score(line: str, prev: str, start: int, end: int, bonus: float) -> float:
    """Score an entropy candidate from its surroundings. line[start:end] is the candidate."""
    prefix = line[:start]
    near = line[:start] + " " + line[end:] + " " + prev
    s = BASE + bonus
    if SENS_RE.search(prefix):
        s += W_NAME
    if SHAPE_RE.search(prefix):
        s += W_SHAPE
    if PLACEHOLDER_RE.search(near):
        s -= PLACEHOLDER_PENALTY
    if HASHWORD_RE.search(near):
        s -= HASH_PENALTY
    return s


def try_b64(tok: str):
    t = tok.rstrip("=")
    if len(t) < 24 or not re.fullmatch(r"[A-Za-z0-9+/]+", t):
        return None
    try:
        s = base64.b64decode(t + "=" * (-len(t) % 4), validate=True).decode("ascii")
    except ValueError:
        return None
    return s if s.isprintable() else None


def decode_matches(tok: str, prefix: str):
    dec = try_b64(tok)
    if dec is None:
        return []
    out = []
    for r in RULES:
        m = r.regex.search(dec)
        if m:
            out.append(("base64-wrapped", m.group(1) if r.regex.groups else m.group(0)))
    m = KV_RE.fullmatch(dec)
    if m:
        out.append(("base64-wrapped", m.group(1)))
    else:
        m = BASIC_RE.fullmatch(dec)
        if m and SENS_RE.search(prefix):
            out.append(("base64-basic-auth", m.group(1)))
    return out


def scan_line(text: str, prev: str, cfg: Config):
    found: dict = {}

    def add(rule, value, col, score):
        old = found.get(value)
        if old is None or score > old.score:
            found[value] = Match(rule, value, col, score)

    views = [text]
    joined = CONCAT_RE.sub("", text)
    if joined != text:
        views.append(joined)
    use_pat = cfg.mode in ("patterns", "combined")
    use_ctx = cfg.mode in ("context", "combined")
    minified = is_minified(text)
    for v in views:
        if use_pat:
            for r in RULES:
                for m in r.regex.finditer(v):
                    val = m.group(1) if r.regex.groups else m.group(0)
                    score = PATTERN_BASE
                    if cfg.mode == "combined":
                        if r.id == "url-credentials" and val[0] in "${<%":
                            continue  # templated, not a literal password
                        if PLACEHOLDER_RE.search(v[: m.start()] + " " + v[m.end():] + " " + prev):
                            score -= PLACEHOLDER_PENALTY
                        if score < cfg.ctx:
                            continue
                    add(r.id, val, m.start(), score)
        if cfg.mode == "entropy":
            for m in TOKEN_RE.finditer(v):
                core = m.group(0).rstrip("=")
                if passes(core, cfg):
                    add("high-entropy", core, m.start(), 0.5)
        elif use_ctx and not minified:
            for m in TOKEN_RE.finditer(v):
                core = m.group(0).rstrip("=")
                if shape_negative(core, v):
                    continue
                for rid, val in decode_matches(core, v[: m.start()]):
                    sc = B64_SCORE - (PLACEHOLDER_PENALTY if PLACEHOLDER_RE.search(v[: m.start()] + " " + prev) else 0)
                    if sc >= cfg.ctx:
                        add(rid, val, m.start(), sc)
                if not passes(core, cfg):
                    continue
                thr = cfg.ent_hex if re.fullmatch(r"[0-9a-fA-F]+", core) else cfg.ent_b64
                bonus = min(0.1, max(0.0, shannon(core) - thr) * 0.1)
                sc = context_score(v, prev, m.start(), m.end(), bonus)
                if sc >= cfg.ctx:
                    add("high-entropy-string", core, m.start(), sc)
    vals = list(found)
    return [m for m in found.values() if not any(m.value != o and m.value in o for o in vals)]


def scan_lines(lines, cfg: Config):
    """lines: iterable of (lineno, text). Returns [(lineno, Match)]. Honors inline `nosecret: reason`."""
    out = []
    prev_no, prev = None, ""
    for no, text in lines:
        ms = scan_line(text, prev if prev_no == no - 1 else "", cfg)
        prev_no, prev = no, text
        if not ms:
            continue
        ns = NOSECRET_RE.search(text)
        if ns:
            reason = (ns.group(1) or "").replace("*/", "").replace("-->", "").strip()
            if reason:
                continue  # valid suppression
            for m in ms:
                m.rejected = True
        out.extend((no, m) for m in ms)
    return out
