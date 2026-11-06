"""A hand-written Dockerfile parser.

Handles parser directives (`# syntax=`, `# escape=`), line continuations (with
comments and blank lines inside them), heredocs, JSON vs shell form, flags such
as `--mount` / `--chown` / `--from`, ONBUILD, multi-stage structure, and
ARG / ENV expansion. Never raises on odd input: problems are collected in
`Dockerfile.errors` and surfaced as findings.
"""

from __future__ import annotations

import bisect
import json
import re
from dataclasses import dataclass, field

from .shell import Command, split_commands, split_words

KNOWN_INSTRUCTIONS = {
    "FROM", "RUN", "CMD", "LABEL", "MAINTAINER", "EXPOSE", "ENV", "ADD", "COPY", "ENTRYPOINT",
    "VOLUME", "USER", "WORKDIR", "ARG", "ONBUILD", "STOPSIGNAL", "HEALTHCHECK", "SHELL",
}
_FLAG_CMDS = {"FROM", "RUN", "COPY", "ADD", "HEALTHCHECK"}

IGNORE_RE = re.compile(r"^\s*#\s*dockerlint-ignore\s*:\s*(.+?)\s*$", re.I)
DIRECTIVE_RE = re.compile(r"^\s*#\s*(syntax|escape|check)\s*=\s*(.*?)\s*$", re.I)
HEREDOC_RE = re.compile(r"(?<!<)<<(-?)([\"']?)([A-Za-z_]\w*)\2(?!<)")
FLAG_RE = re.compile(r"--([A-Za-z][\w-]*)(?:=(\S*))?(?=\s|$)")
ID_RE = re.compile(r"[A-Za-z]{2}\d{4}")


def split_lines(text: str) -> list[str]:
    return re.split(r"\r\n|\r|\n", text)


def parse_ignore_ids(comment: str) -> set[str]:
    m = IGNORE_RE.match(comment)
    if not m:
        return set()
    return {i.upper() for i in ID_RE.findall(m.group(1))}


@dataclass(frozen=True)
class ImageRef:
    raw: str
    name: str
    tag: str | None
    digest: str | None


def parse_image(ref: str) -> ImageRef:
    digest = None
    base = ref
    if "@" in base:
        base, digest = base.split("@", 1)
    slash = base.rfind("/")
    colon = base.rfind(":")
    tag = None
    name = base
    if colon > slash:
        name, tag = base[:colon], base[colon + 1 :]
    return ImageRef(ref, name, tag, digest)


_VAR = re.compile(r"\\\$|\$\{([A-Za-z_]\w*)(?:(:?[-+])([^}]*))?\}|\$([A-Za-z_]\w*)")


def expand(s: str, env: dict[str, str]) -> tuple[str, bool]:
    """Expand $VAR / ${VAR} / ${VAR:-d} / ${VAR:+a}. Returns (text, fully_resolved)."""
    unresolved = False

    def sub(m: re.Match[str]) -> str:
        nonlocal unresolved
        if m.group(0) == "\\$":
            return "$"
        name = m.group(1) or m.group(4)
        op = m.group(2)
        word = m.group(3) or ""
        val = env.get(name)
        if op:
            colon = op.startswith(":")
            is_set = val is not None and (val != "" or not colon)
            if op[-1] == "-":
                if is_set:
                    return val or ""
                text, ok = expand(word, env)
                unresolved = unresolved or not ok
                return text
            if is_set:
                text, ok = expand(word, env)
                unresolved = unresolved or not ok
                return text
            return ""
        if val is None:
            unresolved = True
            return m.group(0)
        return val

    return _VAR.sub(sub, s), not unresolved


@dataclass
class Heredoc:
    delimiter: str
    body: str
    line: int  # first body line (1-based)


@dataclass
class Instruction:
    cmd: str  # upper-case keyword; for ONBUILD the inner keyword
    args: str  # argument text after flags, continuations joined
    line: int  # first physical line (1-based)
    end_line: int  # last physical line, including heredoc bodies
    flags: list[tuple[str, str | None]] = field(default_factory=list)
    json_form: bool = False
    argv: list[str] = field(default_factory=list)  # JSON-form elements
    heredocs: list[Heredoc] = field(default_factory=list)
    ignores: set[str] = field(default_factory=set)
    onbuild: bool = False
    stage: int = -1
    pairs: list[tuple[str, str | None]] = field(default_factory=list)  # ENV/ARG/LABEL
    expanded: str | None = None  # WORKDIR/USER/EXPOSE/FROM after ARG/ENV expansion
    resolved: bool = True
    env: dict[str, str] = field(default_factory=dict)  # ENV/ARG values known at this point
    raw_keyword: str = ""
    _commands: list[Command] | None = None

    def flag(self, name: str) -> str | None:
        for n, v in self.flags:
            if n == name:
                return v if v is not None else ""
        return None

    def flag_values(self, name: str) -> list[str]:
        return [v or "" for n, v in self.flags if n == name]

    @property
    def shell_text(self) -> str:
        """The script a RUN executes: args (heredoc markers removed) plus heredoc bodies."""
        if self.json_form:
            return " ".join(self.argv)
        text = HEREDOC_RE.sub("", self.args) if self.heredocs else self.args
        if self.heredocs:
            return text + "\n" + "\n".join(h.body for h in self.heredocs)
        return text

    def commands(self) -> list[Command]:
        if self._commands is None:
            if self.json_form:
                self._commands = [Command(argv=list(self.argv))] if self.argv else []
            else:
                self._commands = split_commands(self.shell_text)
        return self._commands

    def sources_and_dest(self) -> tuple[list[str], str]:
        """COPY/ADD: (sources, destination). Heredoc sources are excluded."""
        words = [w for w in (self.argv if self.json_form else split_words(HEREDOC_RE.sub("", self.args)))]
        if len(words) < 2:
            return [], words[0] if words else ""
        return words[:-1], words[-1]


@dataclass
class Stage:
    index: int
    name: str | None
    line: int
    base_raw: str
    base: str
    resolved: bool
    image: ImageRef | None
    internal_from: int | None = None  # index of the earlier stage this one builds on
    platform: str | None = None
    instructions: list[Instruction] = field(default_factory=list)  # excluding the FROM
    from_instr: Instruction | None = None
    final_env: dict[str, str] = field(default_factory=dict)


@dataclass
class Dockerfile:
    lines: list[str]
    instructions: list[Instruction]
    stages: list[Stage]
    global_args: dict[str, str | None]
    directives: dict[str, str]
    errors: list[tuple[int, str]]
    escape: str
    _starts: list[int] | None = None

    def instr_at(self, line: int) -> Instruction | None:
        if self._starts is None:
            self._starts = [i.line for i in self.instructions]
        k = bisect.bisect_right(self._starts, line) - 1
        if k >= 0 and self.instructions[k].line <= line <= self.instructions[k].end_line:
            return self.instructions[k]
        return None


def _parse_flags(cmd: str, args: str) -> tuple[list[tuple[str, str | None]], str]:
    flags: list[tuple[str, str | None]] = []
    rest = args.lstrip()
    if cmd not in _FLAG_CMDS:
        return flags, args
    while rest.startswith("--"):
        m = FLAG_RE.match(rest)
        if not m:
            break
        flags.append((m.group(1), m.group(2)))
        rest = rest[m.end() :].lstrip()
    return flags, rest


def _parse_pairs(cmd: str, args: str) -> list[tuple[str, str | None]]:
    words = split_words(args)
    if not words:
        return []
    if cmd == "ARG":
        out: list[tuple[str, str | None]] = []
        for w in words:
            k, eq, v = w.partition("=")
            out.append((k, v if eq else None))
        return out
    if "=" not in words[0] and cmd in ("ENV", "LABEL"):
        # legacy `ENV key value with spaces`
        m = re.match(r"\s*(\S+)\s+(.*)$", args, re.S)
        if m:
            val = m.group(2).strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
                val = val[1:-1]
            return [(m.group(1), val)]
        return [(words[0], "")]
    return [(w.partition("=")[0], w.partition("=")[2]) for w in words if "=" in w]


def parse(text: str) -> Dockerfile:
    lines = split_lines(text)
    n = len(lines)
    directives: dict[str, str] = {}
    i = 0
    while i < n:
        m = DIRECTIVE_RE.match(lines[i])
        if not m:
            break
        directives[m.group(1).lower()] = m.group(2)
        i += 1
    escape = directives.get("escape", "\\")
    if escape not in ("\\", "`"):
        escape = "\\"
    cont_re = re.compile(re.escape(escape) + r"[ \t]*$")

    instructions: list[Instruction] = []
    errors: list[tuple[int, str]] = []
    pending: set[str] = set()
    i = 0
    while i < n:
        raw = lines[i]
        stripped = raw.strip()
        if not stripped:
            i += 1
            continue
        if stripped.startswith("#"):
            pending |= parse_ignore_ids(stripped)
            i += 1
            continue
        start = i
        ignores = set(pending)
        pending = set()
        piece = raw
        parts: list[str] = []
        while True:
            m = cont_re.search(piece)
            if not m:
                parts.append(piece)
                break
            parts.append(piece[: m.start()])
            i += 1
            while i < n and (not lines[i].strip() or lines[i].lstrip().startswith("#")):
                ignores |= parse_ignore_ids(lines[i].strip())
                i += 1
            if i >= n:
                break
            piece = lines[i]
        joined = "".join(parts)
        end = min(i, n - 1)
        i += 1

        km = re.match(r"\s*(\S+)\s*(.*)$", joined, re.S)
        if not km:
            continue
        keyword = km.group(1)
        rest = km.group(2).strip()
        onbuild = False
        if keyword.upper() == "ONBUILD":
            onbuild = True
            km2 = re.match(r"(\S+)\s*(.*)$", rest, re.S)
            if not km2:
                errors.append((start + 1, "ONBUILD needs an instruction after it"))
                continue
            keyword, rest = km2.group(1), km2.group(2).strip()
        cmd = keyword.upper()
        if cmd not in KNOWN_INSTRUCTIONS:
            errors.append((start + 1, f"unknown instruction '{keyword}'"))
            continue
        flags, body = _parse_flags(cmd, rest)
        ins = Instruction(
            cmd=cmd, args=body.strip(), line=start + 1, end_line=end + 1, flags=flags,
            ignores=ignores, onbuild=onbuild, raw_keyword=keyword,
        )
        if cmd in ("RUN", "CMD", "ENTRYPOINT", "SHELL", "VOLUME", "COPY", "ADD", "HEALTHCHECK"):
            _try_json(ins)
        if cmd in ("RUN", "COPY", "ADD") and not ins.json_form:
            # Heredoc bodies follow the instruction line verbatim.
            for hm in HEREDOC_RE.finditer(ins.args):
                dash, delim = hm.group(1), hm.group(3)
                body_lines: list[str] = []
                body_start = i + 1
                closed = False
                while i < n:
                    ln = lines[i]
                    i += 1
                    check = ln.lstrip("\t") if dash else ln
                    if check == delim:
                        closed = True
                        break
                    body_lines.append(ln)
                if not closed:
                    errors.append((start + 1, f"heredoc <<{delim} is never closed"))
                ins.heredocs.append(Heredoc(delim, "\n".join(body_lines), body_start))
                ins.end_line = max(ins.end_line, i)
        instructions.append(ins)

    return _structure(lines, instructions, directives, errors, escape)


def _try_json(ins: Instruction) -> None:
    a = ins.args
    if ins.cmd == "HEALTHCHECK":
        m = re.match(r"(?i)CMD\s+(\[.*)$", a, re.S)
        if not m:
            return
        a = m.group(1)
    if not a.startswith("["):
        return
    try:
        val = json.loads(a)
    except (ValueError, RecursionError):
        return
    if isinstance(val, list) and all(isinstance(x, str) for x in val):
        ins.json_form = True
        ins.argv = list(val)


def _structure(
    lines: list[str],
    instructions: list[Instruction],
    directives: dict[str, str],
    errors: list[tuple[int, str]],
    escape: str,
) -> Dockerfile:
    global_args: dict[str, str | None] = {}
    global_env: dict[str, str] = {}
    stages: list[Stage] = []
    names: dict[str, int] = {}
    cur: Stage | None = None
    env: dict[str, str] = {}
    for ins in instructions:
        if ins.cmd == "FROM":
            m = re.match(r"(\S+)(?:\s+(?i:as)\s+(\S+))?\s*$", ins.args)
            if not m:
                errors.append((ins.line, "FROM needs an image: FROM <image>[:tag] [AS <name>]"))
                continue
            base_raw = m.group(1)
            base, ok = expand(base_raw, global_env)
            name = m.group(2).lower() if m.group(2) else None
            internal = names.get(base.lower()) if ok else None
            stage = Stage(
                index=len(stages), name=name, line=ins.line, base_raw=base_raw, base=base,
                resolved=ok, image=None if (internal is not None or not ok) else parse_image(base),
                internal_from=internal, platform=ins.flag("platform"), from_instr=ins,
            )
            if name and name not in names:
                names[name] = stage.index
            stages.append(stage)
            cur = stage
            env = dict(stages[internal].final_env) if internal is not None else {}
            ins.stage = stage.index
            ins.expanded = base
            ins.resolved = ok
            continue
        if cur is None:
            if ins.cmd == "ARG" and not ins.onbuild:
                ins.pairs = _parse_pairs("ARG", ins.args)
                for k, v in ins.pairs:
                    if v is None:
                        global_args[k] = None
                    else:
                        ev, _ = expand(v, global_env)
                        global_args[k] = ev
                        global_env[k] = ev
                continue
            errors.append((ins.line, f"{ins.cmd} appears before the first FROM"))
            continue
        ins.stage = cur.index
        cur.instructions.append(ins)
        if ins.cmd in ("ENV", "ARG", "LABEL"):
            ins.pairs = _parse_pairs(ins.cmd, ins.args)
        if not ins.onbuild:
            if ins.cmd == "ENV":
                for k, v in ins.pairs:
                    ev, _ = expand(v or "", env)
                    env[k] = ev
            elif ins.cmd == "ARG":
                for k, v in ins.pairs:
                    if v is not None:
                        env[k], _ = expand(v, env)
                    elif global_env.get(k) is not None:
                        env[k] = global_env[k]
            elif ins.cmd in ("WORKDIR", "USER", "EXPOSE"):
                ins.expanded, ins.resolved = expand(ins.args, env)
        ins.env = dict(env)
        cur.final_env = dict(env)
    return Dockerfile(
        lines=lines, instructions=instructions, stages=stages, global_args=global_args,
        directives=directives, errors=errors, escape=escape,
    )
