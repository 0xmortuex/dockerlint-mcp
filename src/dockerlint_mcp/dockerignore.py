"""`.dockerignore` matching, following the Docker (moby patternmatcher) rules.

Differences from .gitignore that matter in practice:
  * patterns are anchored at the context root: `node_modules` does NOT match
    `packages/app/node_modules` (use `**/node_modules`);
  * a pattern that matches a directory excludes everything under it;
  * the LAST matching pattern wins, and `!` re-includes;
  * `*` and `?` never cross `/`, `**` does.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass

from .errors import UserError


@dataclass
class Pattern:
    raw: str
    line: int
    negate: bool
    regex: re.Pattern[str]


def _compile(pattern: str) -> re.Pattern[str]:
    out = ["^"]
    i = 0
    n = len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            if i + 1 < n and pattern[i + 1] == "*":
                while i + 1 < n and pattern[i + 1] == "*":
                    i += 1
                if i + 1 < n and pattern[i + 1] == "/":
                    i += 1
                    out.append("(?:.*/)?")
                else:
                    out.append(".*")
            else:
                out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            j = i + 1
            if j < n and pattern[j] in "^!":
                j += 1
            if j < n and pattern[j] == "]":
                j += 1
            while j < n and pattern[j] != "]":
                j += 1
            if j >= n:
                out.append(re.escape(c))
            else:
                body = pattern[i + 1 : j]
                if body[:1] in ("^", "!"):
                    body = "^" + body[1:]
                body = body.replace("\\", "\\\\")
                out.append("[" + body + "]")
                i = j
        elif c == "\\" and i + 1 < n:
            i += 1
            out.append(re.escape(pattern[i]))
        else:
            out.append(re.escape(c))
        i += 1
    out.append("$")
    try:
        return re.compile("".join(out), re.S)
    except re.error:
        return re.compile("(?!)")  # an invalid class never matches, like Go's ErrBadPattern


class IgnoreMatcher:
    def __init__(self, text: str) -> None:
        self.patterns: list[Pattern] = []
        for no, raw in enumerate(re.split(r"\r\n|\r|\n", text), start=1):
            p = raw.strip()
            if not p or p.startswith("#"):
                continue
            negate = p.startswith("!")
            if negate:
                p = p[1:].strip()
                if not p:
                    continue
            p = posixpath.normpath(p.replace("\\", "/")) if "\\" not in p else p
            if len(p) > 1 and p.startswith("/"):
                p = p[1:]
            if len(p) > 1000 or p.count("*") + p.count("?") > 16:
                raise UserError(
                    f".dockerignore line {no} is too long or has too many wildcards to match "
                    "safely; split it into simpler patterns"
                )
            self.patterns.append(Pattern(raw.strip(), no, negate, _compile(p)))

    def match(self, path: str) -> tuple[bool, Pattern | None]:
        """Is `path` (relative, forward slashes) excluded? Also returns the deciding pattern."""
        path = posixpath.normpath(path.replace("\\", "/"))
        parent = posixpath.dirname(path)
        parts = parent.split("/") if parent else []
        excluded = False
        decider: Pattern | None = None
        for pat in self.patterns:
            hit = bool(pat.regex.match(path))
            if not hit:
                for k in range(len(parts)):
                    if pat.regex.match("/".join(parts[: k + 1])):
                        hit = True
                        break
            if hit:
                excluded = not pat.negate
                decider = pat
        return excluded, decider

    def excludes(self, path: str) -> bool:
        return self.match(path)[0]
