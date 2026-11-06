"""A small shell tokenizer: split a RUN body into commands.

This is not a shell. It is just enough to answer "is there an `apt-get install`
in this RUN" without being fooled by quoting, `&&`, `;`, pipes or newlines.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

_SEPARATORS = {"&&", "||", ";", "|", "&", ";;", "|&", "&;"}
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_PIP = re.compile(r"^pip[0-9.]*$")
_PYTHON = re.compile(r"^python[0-9.]*$")


def _basename(p: str) -> str:
    return p.replace("\\", "/").rsplit("/", 1)[-1]


@dataclass
class Command:
    argv: list[str]  # after env assignments and sudo are stripped
    depth: int = 0  # parenthesis depth: > 0 means inside ( ... ) or $( ... )
    sudo: bool = False
    env: dict[str, str] = field(default_factory=dict)  # leading VAR=value words
    sep_after: str = ""  # operator that follows this command

    @property
    def name(self) -> str:
        return _basename(self.argv[0]) if self.argv else ""

    @property
    def args(self) -> list[str]:
        return self.argv[1:]

    def has_arg(self, *names: str) -> bool:
        return any(a in names for a in self.args)

    def has_flag(self, long: str, short: str = "") -> bool:
        """True if `--long`, `--long=...` or a short flag (alone or combined) is present."""
        for a in self.args:
            if a == long or a.startswith(long + "="):
                return True
            if short and a.startswith("-") and not a.startswith("--") and short in a[1:]:
                return True
        return False

    def positionals(self) -> list[str]:
        return [a for a in self.args if not a.startswith("-")]

    def text(self) -> str:
        return " ".join(self.argv)


def _clean_script(text: str) -> str:
    lines = [ln for ln in text.replace("\r\n", "\n").split("\n") if not ln.lstrip().startswith("#")]
    s = "\n".join(lines)
    s = re.sub(r"\\\n", " ", s)
    return s.replace("\n", " ; ")


def tokenize(text: str) -> list[str]:
    lex = shlex.shlex(_clean_script(text), posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    lex.commenters = ""
    toks: list[str] = []
    try:
        for t in lex:
            toks.append(t)
    except ValueError:
        # Unbalanced quotes: keep what was tokenized; Docker itself would fail the build.
        pass
    return toks


def _normalize(argv: list[str]) -> list[str]:
    """`python -m pip install` and `pip3 install` both become `pip install`."""
    if len(argv) >= 3 and _PYTHON.match(_basename(argv[0])) and argv[1] == "-m" and _PIP.match(argv[2]):
        return ["pip", *argv[3:]]
    if argv and _PIP.match(_basename(argv[0])):
        return ["pip", *argv[1:]]
    return argv


def split_commands(text: str) -> list[Command]:
    cmds: list[Command] = []
    cur: list[str] = []
    depth = 0

    def flush(sep: str) -> None:
        nonlocal cur
        if not cur:
            return
        env: dict[str, str] = {}
        n_env = 0
        while n_env < len(cur) and _ASSIGNMENT.match(cur[n_env]):
            k, _, v = cur[n_env].partition("=")
            env[k] = v
            n_env += 1
        argv = cur[n_env:]
        cur = []
        sudo = False
        if argv and argv[0] == "sudo":
            sudo = True
            skip = 1
            while skip < len(argv) and argv[skip].startswith("-"):
                skip += 1
            rest = argv[skip:]
            if not rest:
                cmds.append(Command(argv=["sudo"], depth=depth, sudo=True, env=env, sep_after=sep))
                return
            argv = rest
        if argv:
            cmds.append(
                Command(argv=_normalize(list(argv)), depth=depth, sudo=sudo, env=env, sep_after=sep)
            )

    for t in tokenize(text):
        if t in _SEPARATORS:
            flush(t)
        elif t == "(":
            flush("(")
            depth += 1
        elif t == ")":
            flush(")")
            depth = max(0, depth - 1)
        elif t == "$":
            continue
        else:
            cur.append(t)
    flush("")
    return cmds


def split_words(text: str) -> list[str]:
    """POSIX word split used for ENV/ARG/COPY arguments."""
    try:
        return shlex.split(text, posix=True)
    except ValueError:
        return text.split()
