"""Text formatting shared by all tools."""

from __future__ import annotations

from .rules import Finding

MAX_OUTPUT = 60_000


def format_findings(label: str, findings: list[Finding], note: str = "") -> str:
    counts = {"error": 0, "warning": 0, "info": 0}
    for f in findings:
        counts[f.severity] += 1
    head = (
        f"{label}: {len(findings)} finding(s) "
        f"({counts['error']} error, {counts['warning']} warning, {counts['info']} info)"
    )
    if not findings:
        return head + ". Nothing to fix." + (f"\n{note}" if note else "")
    lines = [head, ""]
    for f in findings:
        where = f"line {f.line}" if f.line > 0 else "(whole file)"
        lines.append(f"[{f.rule}] {f.severity} {where}: {f.message}")
        lines.append(f"    fix: {f.fix}")
    if note:
        lines += ["", note]
    lines += [
        "",
        "Suppress one finding with a `# dockerlint-ignore: <RULE-ID>` comment on the line above it "
        "(above a compose service name to cover the whole service).",
    ]
    return clip("\n".join(lines))


def clip(text: str, limit: int = MAX_OUTPUT) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [{len(text) - limit} more characters truncated]"
