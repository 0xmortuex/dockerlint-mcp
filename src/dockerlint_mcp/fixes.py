"""fix_preview: apply the safe, mechanical fixes in memory and show a unified diff.

Only fixes that cannot change what the image does are applied. Nothing is written.
Every fix keeps the line count unchanged, so line numbers in findings stay valid.
"""

from __future__ import annotations

import difflib
import json
import os
import re

from .files import LoadedDockerfile
from .parser import Dockerfile, Instruction, parse
from .report import clip
from .rules import Ctx, Finding, lint
from .secrets import redact_line
from .shell import split_words

_SAFE_WORD = re.compile(r"^[\w./:=@%+,-]+$")
_PHYSICAL = re.compile(r"[^\r\n]*(?:\r\n|\n|\r)|[^\r\n]+")


class _Doc:
    def __init__(self, text: str) -> None:
        parts = _PHYSICAL.findall(text)
        self.body = [re.sub(r"(\r\n|\n|\r)$", "", p) for p in parts]
        self.ends = [p[len(b):] for p, b in zip(parts, self.body, strict=True)]
        self.original = list(parts)

    def rendered(self) -> list[str]:
        return [b + e for b, e in zip(self.body, self.ends, strict=True)]


def _segment(ins: Instruction) -> range:
    return range(ins.line - 1, ins.end_line)


def _fix_apt_install(doc: _Doc, ins: Instruction, rules: set[str]) -> str | None:
    add = []
    if "DL1024" in rules:
        add.append("-y")
    if "DL1004" in rules:
        add.append("--no-install-recommends")
    if not add:
        return None
    changed = False
    for i in _segment(ins):
        new = re.sub(r"\bapt-get(\s+)install\b", lambda m: "apt-get install " + " ".join(add), doc.body[i])
        if new != doc.body[i]:
            doc.body[i], changed = new, True
    return f"added {' '.join(add)} to apt-get install" if changed else None


def _fix_pip(doc: _Doc, ins: Instruction, rules: set[str]) -> str | None:
    pat = re.compile(r"\b(pip[0-9.]*\s+install|python[0-9.]*\s+-m\s+pip\s+install)\b(?!\s+--no-cache-dir)")
    changed = False
    for i in _segment(ins):
        new = pat.sub(r"\1 --no-cache-dir", doc.body[i])
        if new != doc.body[i]:
            doc.body[i], changed = new, True
    return "added --no-cache-dir to pip install" if changed else None


def _fix_apk(doc: _Doc, ins: Instruction, rules: set[str]) -> str | None:
    changed = False
    for i in _segment(ins):
        new = re.sub(r"\bapk(\s+)add\b(?!\s+--no-cache)", "apk add --no-cache", doc.body[i])
        if new != doc.body[i]:
            doc.body[i], changed = new, True
    return "added --no-cache to apk add" if changed else None


def _fix_add(doc: _Doc, ins: Instruction, rules: set[str]) -> str | None:
    srcs, _ = ins.sources_and_dest()
    if ins.heredocs or any(re.match(r"^(https?|git)://|^git@", s) for s in srcs) or ins.flag("checksum") is not None:
        return None
    i = ins.line - 1
    new = re.sub(r"^(\s*)ADD\b", r"\1COPY", doc.body[i], count=1, flags=re.I)
    if new == doc.body[i]:
        return None
    doc.body[i] = new
    return "replaced ADD with COPY"


def _fix_exec_form(doc: _Doc, ins: Instruction, rules: set[str], has_cmd: bool) -> str | None:
    if ins.line != ins.end_line or ins.json_form or ins.args.startswith("["):
        return None
    if ins.cmd == "ENTRYPOINT" and has_cmd:
        return None  # shell-form ENTRYPOINT ignores CMD; exec form would append it
    words = split_words(ins.args)
    if not words or not all(_SAFE_WORD.match(w) for w in words):
        return None
    i = ins.line - 1
    m = re.match(r"^(\s*)(\S+)(\s+)", doc.body[i])
    if not m:
        return None
    doc.body[i] = f"{m.group(1)}{m.group(2)} {json.dumps(words)}"
    return f"converted {ins.cmd} to exec form"


def _fix_lists(doc: _Doc, ins: Instruction, rules: set[str]) -> str | None:
    if ins.heredocs or ins.json_form:
        return None
    last = ins.end_line - 1
    text = doc.body[last].rstrip()
    whole = " ".join(doc.body[i] for i in _segment(ins))
    if not text or text.endswith(("\\", "&&", "||", ";", "|")) or "||" in whole or ";" in whole or "#" in text:
        return None
    doc.body[last] = text + " && rm -rf /var/lib/apt/lists/*"
    return "appended `&& rm -rf /var/lib/apt/lists/*`"


def _fix_apt_cli(doc: _Doc, ins: Instruction, rules: set[str]) -> str | None:
    pat = re.compile(r"\bapt(\s+)(install|update|upgrade|remove|purge|autoremove)\b")
    changed = False
    for i in _segment(ins):
        new = pat.sub(r"apt-get \2", doc.body[i])
        if new != doc.body[i]:
            doc.body[i], changed = new, True
    return "replaced `apt` with `apt-get`" if changed else None


def _fix_maintainer(doc: _Doc, ins: Instruction, rules: set[str]) -> str | None:
    if ins.line != ins.end_line or not ins.args:
        return None
    val = json.dumps(ins.args.strip().strip("\"'"), ensure_ascii=False)
    m = re.match(r"^(\s*)", doc.body[ins.line - 1])
    doc.body[ins.line - 1] = f"{m.group(1) if m else ''}LABEL org.opencontainers.image.authors={val}"
    return "replaced MAINTAINER with an OCI authors LABEL"


def fix_preview(ld: LoadedDockerfile, disabled: frozenset[str]) -> str:
    df = ld.df
    findings = lint(ld.ctx, disabled)
    doc = _Doc(ld.text)
    if len(doc.body) != len(df.lines) and not (len(doc.body) + 1 == len(df.lines) and df.lines[-1] == ""):
        raise AssertionError("line bookkeeping mismatch between parser and fixer")

    by_instr: dict[int, tuple[Instruction, set[str]]] = {}
    for f in findings:
        ins = df.instr_at(f.line)
        if ins is None:
            continue
        by_instr.setdefault(ins.line, (ins, set()))[1].add(f.rule)

    applied: list[tuple[int, str, str]] = []
    handled: set[tuple[str, int]] = set()

    def record(ins: Instruction, rules: list[str], what: str | None) -> None:
        if what:
            applied.append((ins.line, "/".join(rules), what))
            for r in rules:
                handled.add((r, ins.line))

    for ins, rules in by_instr.values():
        if rules & {"DL1004", "DL1024"} and ins.cmd == "RUN":
            # DL1024 may also come from yum/dnf, which this fixer does not touch.
            record(ins, sorted(rules & {"DL1004", "DL1024"}), _fix_apt_install(doc, ins, rules))
        if "DL1006" in rules:
            record(ins, ["DL1006"], _fix_pip(doc, ins, rules))
        if "DL1020" in rules:
            record(ins, ["DL1020"], _fix_apk(doc, ins, rules))
        if "DL1026" in rules:
            record(ins, ["DL1026"], _fix_apt_cli(doc, ins, rules))
        if "DL1008" in rules and ins.cmd == "ADD":
            record(ins, ["DL1008"], _fix_add(doc, ins, rules))
        if "DL1014" in rules:
            has_cmd = any(i.cmd == "CMD" and i.stage == ins.stage and not i.onbuild for i in df.instructions)
            record(ins, ["DL1014"], _fix_exec_form(doc, ins, rules, has_cmd))
        if "DL1027" in rules:
            record(ins, ["DL1027"], _fix_maintainer(doc, ins, rules))
        if "DL1005" in rules:
            record(ins, ["DL1005"], _fix_lists(doc, ins, rules))

    name = os.path.basename(ld.path)
    before = doc.original
    after = doc.rendered()
    manual = [f for f in findings if (f.rule, _instr_start(df, f.line)) not in handled]
    out: list[str] = []
    if not applied:
        out.append(f"fix_preview for {ld.path}: no automatic fix applies. Nothing was written.")
    else:
        remaining = lint(Ctx(parse("".join(after)), ld.ctx.context_dir, ld.ctx.ignore), disabled)
        out.append(
            f"fix_preview for {ld.path}: {len(applied)} automatic fix(es) in the preview "
            f"(nothing was written). Findings: {len(findings)} before, {len(remaining)} after."
        )
        out.append("")
        out.append("Applied in the preview:")
        for line, rules_s, what in sorted(applied):
            out.append(f"  L{line} [{rules_s}] {what}")
        diff = list(difflib.unified_diff(
            [redact_line(x.rstrip("\r\n")) for x in before],
            [redact_line(x.rstrip("\r\n")) for x in after],
            fromfile=f"a/{name}", tofile=f"b/{name}", lineterm="",
        ))
        out += ["", "```diff", *diff, "```"]
        out.append("")
        out.append("Secret values are redacted in this diff; apply the fixes to the file itself, "
                   "not by pasting the diff.")
    if manual:
        out += ["", "Needs a manual change (no safe automatic fix):"]
        out += [_manual_line(f) for f in manual]
    return clip("\n".join(out))


def _instr_start(df: Dockerfile, line: int) -> int:
    ins = df.instr_at(line)
    return ins.line if ins is not None else line


def _manual_line(f: Finding) -> str:
    return f"  L{f.line} [{f.rule}] {f.fix}"
