"""Findings, redaction, and JSON / SARIF 2.1.0 / text output. No output ever contains a raw value."""
import hashlib
from dataclasses import dataclass, field

from . import __version__
from .patterns import all_rule_descs

REDACT_PREFIX = 4


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def redact(value: str) -> str:
    """Short prefix (at most a quarter of the value, max 4 chars) + hash fingerprint."""
    pre = value[: min(REDACT_PREFIX, len(value) // 4)]
    return f"{pre}****[{fingerprint(value)}]"


@dataclass
class Finding:
    path: str
    line: int
    rule: str
    score: float
    redacted: str
    fingerprint: str
    suppression_rejected: bool = False
    baseline_expired: bool = False
    value: str = field(default="", repr=False)  # kept in memory only; never serialized

    @classmethod
    def make(cls, path, line, match):
        return cls(path, line, match.rule, round(match.score, 2), redact(match.value), fingerprint(match.value),
                   match.rejected, False, match.value)


def to_json(findings, summary: dict) -> dict:
    return {
        "tool": "sec-secrets-scanner", "version": __version__, "summary": summary,
        "findings": [{"path": f.path, "line": f.line, "rule": f.rule, "score": f.score, "redacted": f.redacted,
                      "fingerprint": f.fingerprint, "suppression_rejected": f.suppression_rejected,
                      "baseline_expired": f.baseline_expired} for f in findings],
    }


def to_sarif(findings) -> dict:
    descs = all_rule_descs()
    ids = list(descs)
    rules = [{"id": i, "shortDescription": {"text": descs[i]}} for i in ids]
    results = []
    for f in findings:
        results.append({
            "ruleId": f.rule, "ruleIndex": ids.index(f.rule), "level": "error",
            "message": {"text": f"Possible secret ({f.rule}), score {f.score}: {f.redacted}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path},
                                                "region": {"startLine": f.line}}}],
            "partialFingerprints": {"secretFingerprint/v1": f.fingerprint},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "sec-secrets-scanner", "version": __version__,
                                      "rules": rules}}, "results": results}],
    }


def to_text(findings) -> str:
    return "\n".join(f"{f.path}:{f.line}: {f.rule} score={f.score} {f.redacted}"
                     + (" [nosecret ignored: no reason]" if f.suppression_rejected else "")
                     + (" [baseline entry expired]" if f.baseline_expired else "") for f in findings)
