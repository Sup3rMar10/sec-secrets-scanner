"""Allowlist / baseline file with mandatory reason and expiry date.

Format: {"entries": [{"fingerprint": "<12 hex>", "reason": "...", "expires": "YYYY-MM-DD", "path": "optional glob"}]}
An entry suppresses a finding through its expiry date (inclusive). After that the finding is reported again.
"""
import datetime as dt
import fnmatch
import json
import re
from dataclasses import dataclass


class BaselineError(Exception):
    pass


@dataclass(frozen=True)
class Entry:
    fingerprint: str
    reason: str
    expires: dt.date
    path: str = ""


def load_baseline(path: str):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as e:
        raise BaselineError(f"cannot read baseline {path}: {e}")
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
        raise BaselineError("baseline must be an object with an 'entries' list")
    out = []
    for i, e in enumerate(data["entries"]):
        if not isinstance(e, dict):
            raise BaselineError(f"entry {i}: not an object")
        fp, reason, exp = e.get("fingerprint"), e.get("reason"), e.get("expires")
        if not isinstance(fp, str) or not re.fullmatch(r"[0-9a-f]{12}", fp):
            raise BaselineError(f"entry {i}: fingerprint must be 12 lowercase hex chars")
        if not isinstance(reason, str) or not reason.strip():
            raise BaselineError(f"entry {i}: a non-empty reason is required")
        try:
            expires = dt.date.fromisoformat(exp)
        except (TypeError, ValueError):
            raise BaselineError(f"entry {i}: expires must be YYYY-MM-DD")
        out.append(Entry(fp, reason.strip(), expires, str(e.get("path", ""))))
    return out


def apply_baseline(findings, entries, today: dt.date):
    """Return (kept, n_suppressed, expired_entries_that_matched)."""
    kept, suppressed, expired = [], 0, []
    for f in findings:
        hit = None
        for e in entries:
            if e.fingerprint == f.fingerprint and (not e.path or fnmatch.fnmatch(f.path, e.path)):
                hit = e
                break
        if hit is None:
            kept.append(f)
        elif today <= hit.expires:
            suppressed += 1
        else:
            expired.append(hit)
            kept.append(f)
    return kept, suppressed, expired


def write_baseline(findings, path: str, expires: dt.date, reason: str):
    seen, entries = set(), []
    for f in findings:
        if (f.fingerprint, f.path) in seen:
            continue
        seen.add((f.fingerprint, f.path))
        entries.append({"fingerprint": f.fingerprint, "path": f.path, "reason": reason, "expires": expires.isoformat()})
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"entries": entries}, fh, indent=2)
        fh.write("\n")
