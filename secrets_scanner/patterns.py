"""Provider-style token patterns. Deliberately small: generic shapes (known prefix + fixed-length body).

None of these regexes contains a complete token; real-looking test tokens are assembled at runtime
by secrets_scanner.corpus from fragments.
"""
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    regex: "re.Pattern[str]"
    desc: str


RULES = (
    Rule("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "4-letter prefix + 16 upper/digits"),
    Rule("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"), "gh[pousr]_ prefix + 36 alphanumerics"),
    Rule("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,48}(?![A-Za-z0-9-])"), "xox[abprs]- prefix + 10-48 chars"),
    Rule("stripe-live-key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{24,}\b"), "[sr]k_live_ prefix + 24+ alphanumerics"),
    Rule("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])"), "AIza prefix + 35 url-safe chars"),
    Rule("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "three dot-separated base64url parts"),
    Rule("private-key-header", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"), "PEM private key header"),
    Rule("url-credentials", re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s:/@\"']+:([^\s@/\"']{6,})@"), "scheme://user:<secret>@host"),
)

# Rule ids produced by the other layers (used for SARIF rule metadata).
OTHER_RULES = {
    "high-entropy": "raw high-entropy token (entropy-only layer, no context)",
    "high-entropy-string": "high-entropy token that passed shape filters and context scoring",
    "base64-wrapped": "base64 payload that decodes to a secret assignment or provider token",
    "base64-basic-auth": "base64 user:password after an auth-like name",
}


def all_rule_descs() -> dict:
    d = {r.id: r.desc for r in RULES}
    d.update(OTHER_RULES)
    return d
