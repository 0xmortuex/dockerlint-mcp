"""Secret detection and redaction.

Findings and displayed instructions must never echo a secret value. Everything
that prints user text goes through `redact_line`, and rules that report a secret
use only the variable name (or a kind such as "GitHub token").
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_SEGMENT = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")

_STRONG_SEGMENTS = {
    "PASSWORD", "PASSWD", "PASS", "PASSPHRASE", "SECRET", "SECRETS", "TOKEN", "TOKENS",
    "APIKEY", "CREDENTIAL", "CREDENTIALS",
}
_STRONG_SUBSTRINGS = ("PASSWORD", "PASSWD", "APIKEY", "PRIVATEKEY", "ACCESSKEY", "SECRET")
_PAIRS = {("API", "KEY"), ("PRIVATE", "KEY"), ("ACCESS", "KEY"), ("AUTH", "TOKEN")}
# A name that ends in one of these holds a location or an identifier, not the secret itself.
_SAFE_SUFFIX = {
    "FILE", "PATH", "DIR", "URL", "URI", "NAME", "ID", "ENABLED", "LENGTH", "TTL", "EXPIRY",
    "HEADER", "USER", "USERNAME", "TYPE", "MODE", "PORT", "HOST", "CONFIG", "ENDPOINT", "FROM",
}


def is_secret_name(name: str) -> bool:
    """True if a variable name looks like it holds a credential."""
    segs: list[str] = []
    for part in re.split(r"[^A-Za-z0-9]+", name):
        segs.extend(s.upper() for s in _SEGMENT.findall(part))
    if not segs or segs[-1] in _SAFE_SUFFIX:
        return False
    if any(s in _STRONG_SEGMENTS for s in segs):
        return True
    if any((segs[i], segs[i + 1]) in _PAIRS for i in range(len(segs) - 1)):
        return True
    joined = "".join(segs)
    return any(sub in joined for sub in _STRONG_SUBSTRINGS)


def has_literal(value: str) -> bool:
    """True if the value is a hard-coded literal (not empty, not a variable reference)."""
    v = value.strip().strip("\"'").strip()
    return bool(v) and not v.startswith("$")


_TOKEN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("API key (sk-...)", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]

_ASSIGN = re.compile(r"""(?<![\w.-])([A-Za-z_][\w.-]*)=("[^"\n]*"|'[^'\n]*'|[^\s"'&|;\\]+)""")
_LEGACY = re.compile(r"^(\s*(?:ENV|ARG)\s+)([A-Za-z_][\w.-]*)([ \t]+)(\S.*)$", re.I)
_FLAG = re.compile(
    r"(--(?:password|passwd|pass|token|secret|api-key|apikey|auth-token))(?:=|[ \t]+)([^\s]+)", re.I
)
_URL = re.compile(r"(://[^/\s:@]+:)([^/\s@]+)(@)")
_AUTH_HEADER = re.compile(r"(Authorization:[ \t]*(?:Bearer|Basic|token)[ \t]+)([^\s\"']+)", re.I)
_CURL_USER = re.compile(r"(\b(?:curl|wget)\b[^|;&\n]{0,300}?[ \t](?:-u|--user)[ \t]+[^\s:]+:)([^\s\"']+)")


@dataclass(frozen=True)
class SecretHit:
    kind: str  # human description, never contains the value
    start: int  # span of the value to redact
    end: int


def scan(text: str) -> list[SecretHit]:
    """Find secret values in free text. Spans cover only the value."""
    hits: list[SecretHit] = []
    for m in _ASSIGN.finditer(text):
        if is_secret_name(m.group(1)) and has_literal(m.group(2)):
            hits.append(SecretHit(f"assignment to {m.group(1)}", m.start(2), m.end(2)))
    lm = _LEGACY.match(text)
    if lm and is_secret_name(lm.group(2)) and has_literal(lm.group(4)):
        hits.append(SecretHit(f"assignment to {lm.group(2)}", lm.start(4), lm.end(4)))
    for m in _FLAG.finditer(text):
        if has_literal(m.group(2)):
            hits.append(SecretHit(f"{m.group(1)} flag", m.start(2), m.end(2)))
    for m in _URL.finditer(text):
        if has_literal(m.group(2)):
            hits.append(SecretHit("password inside a URL", m.start(2), m.end(2)))
    for m in _AUTH_HEADER.finditer(text):
        if has_literal(m.group(2)):
            hits.append(SecretHit("Authorization header", m.start(2), m.end(2)))
    for m in _CURL_USER.finditer(text):
        if has_literal(m.group(2)):
            hits.append(SecretHit("user:password argument", m.start(2), m.end(2)))
    for kind, pat in _TOKEN_PATTERNS:
        for m in pat.finditer(text):
            hits.append(SecretHit(kind, m.start(), m.end()))
    hits.sort(key=lambda h: (h.start, -h.end))
    merged: list[SecretHit] = []
    for h in hits:
        if merged and h.start < merged[-1].end:
            continue
        merged.append(h)
    return merged


def redact_line(text: str) -> str:
    """Replace secret values in `text` with <redacted>."""
    out = text
    for h in reversed(scan(text)):
        out = out[: h.start] + "<redacted>" + out[h.end :]
    return out
