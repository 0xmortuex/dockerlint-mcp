"""check_dockerignore: is the build context protected, and does the ignore file break COPY?"""

from __future__ import annotations

import glob
import os
import posixpath
import re

from .dockerignore import IgnoreMatcher
from .errors import UserError, shorten
from .files import Sandbox, find_ignore_file
from .parser import parse, parse_ignore_ids
from .rules import RULES, Finding

_WALK_LIMIT = 4000


def check_dockerignore(
    sb: Sandbox, path: str, disabled: frozenset[str] = frozenset()
) -> tuple[str, list[Finding]]:
    real = sb.resolve(path)
    if not os.path.exists(real):
        raise UserError(f"{shorten(path)!r} not found. Relative paths are resolved against {sb.root}.")
    dockerfile: str | None
    if os.path.isdir(real):
        ctx_dir = real
        cand = os.path.join(real, "Dockerfile")
        dockerfile = cand if os.path.isfile(cand) else None
    else:
        ctx_dir = os.path.dirname(real)
        dockerfile = real
    ignore_path = find_ignore_file(dockerfile) if dockerfile else None
    if ignore_path is None:
        plain = os.path.join(ctx_dir, ".dockerignore")
        ignore_path = plain if os.path.isfile(plain) else None

    out: list[Finding] = []

    def add(rule: str, line: int, message: str, fix: str) -> None:
        if rule not in disabled:
            out.append(Finding(rule, RULES[rule].severity, line, message, fix))

    has_pkg = os.path.isfile(os.path.join(ctx_dir, "package.json")) or os.path.isdir(
        os.path.join(ctx_dir, "node_modules")
    )
    if ignore_path is None:
        add(
            "DI3001", 0,
            f"No .dockerignore in {ctx_dir}. `docker build` sends the whole directory (including "
            ".git, node_modules and any .env file) to the daemon, and `COPY . .` puts it in the image.",
            "Create .dockerignore with at least:\n        .git\n        **/node_modules\n        .env\n"
            "        .env.*\n        !.env.example",
        )
        return ctx_dir, out

    _, text = sb.read_text(ignore_path)
    m = IgnoreMatcher(text)
    for ln in text.splitlines():
        disabled = disabled | parse_ignore_ids(ln.strip())
    ig_label = os.path.basename(ignore_path)

    if not (m.excludes(".git") and m.excludes(".git/config")):
        add("DI3002", 0, f"{ig_label} does not exclude .git, so the repository history is sent to the "
            "daemon and copied by `COPY . .`.", "Add the line `.git`.")
    if has_pkg and not (m.excludes("node_modules") and m.excludes("node_modules/x/index.js")):
        add("DI3003", 0, f"{ig_label} does not exclude node_modules; host modules (possibly for another "
            "OS) end up in the image or slow the context upload.",
            "Add `**/node_modules` (a bare `node_modules` only matches the context root).")
    if not (m.excludes(".env") and m.excludes(".env.production") and m.excludes(".env.local")):
        add("DI3004", 0, f"{ig_label} does not exclude every .env file; secrets can be copied into an "
            "image layer.", "Add `.env` and `.env.*` (and `!.env.example` to keep a template).")

    # Files the Dockerfile copies that the ignore file would remove.
    if dockerfile is not None:
        _, dtext = sb.read_text(dockerfile)
        df = parse(dtext)
        if len(m.patterns) > 5000 or sum(1 for i in df.instructions if i.cmd in ("COPY", "ADD")) > 2000:
            raise UserError(
                "Too many .dockerignore patterns (limit 5000) or COPY/ADD instructions (limit 2000) "
                "to check against each other."
            )
        for ins in df.instructions:
            if ins.cmd not in ("COPY", "ADD") or ins.onbuild or ins.flag("from") is not None:
                continue
            sources, _ = ins.sources_and_dest()
            for src in sources:
                if not src or src.startswith("<<") or "$" in src or re.match(r"^[a-z]+://", src):
                    continue
                norm = posixpath.normpath(src.replace("\\", "/")).lstrip("/")
                if norm in (".", "") or norm.startswith("..") or norm in ("Dockerfile", ".dockerignore"):
                    continue
                if any(ch in norm for ch in "*?["):
                    matches = glob.glob(os.path.join(ctx_dir, norm), recursive=True)[:200]
                    rels = [os.path.relpath(p, ctx_dir).replace("\\", "/") for p in matches]
                else:
                    rels = [norm] if os.path.exists(os.path.join(ctx_dir, norm)) else []
                for rel in rels:
                    excluded, pat = m.match(rel)
                    if excluded and pat is not None:
                        add(
                            "DI3005", pat.line,
                            f"Dockerfile line {ins.line}: `{ins.cmd} {src}` needs '{rel}', but "
                            f"{ig_label} line {pat.line} (`{pat.raw}`) excludes it from the build context, "
                            "so the build fails or the file is silently missing.",
                            f"Remove or narrow `{pat.raw}`, or re-include the file with `!{rel}` after it.",
                        )
                        break

    # Nested node_modules / .git the root-anchored patterns miss.
    seen = 0
    nested: list[str] = []
    stack = [""]
    while stack and seen < _WALK_LIMIT and len(nested) < 3:
        rel_dir = stack.pop()
        try:
            entries = list(os.scandir(os.path.join(ctx_dir, rel_dir)))
        except OSError:
            continue
        for e in entries:
            seen += 1
            if not e.is_dir(follow_symlinks=False):
                continue
            rel = f"{rel_dir}/{e.name}" if rel_dir else e.name
            if e.name in ("node_modules", ".git") and rel_dir:
                if not m.excludes(rel):
                    nested.append(rel)
                continue
            if e.name in ("node_modules", ".git") or m.excludes(rel):
                continue
            stack.append(rel)
    for rel in nested:
        add("DI3006", 0, f"{rel} exists in the build context and is not excluded: root-anchored patterns "
            f"like `{rel.rsplit('/', 1)[-1]}` only match the top level.",
            f"Use `**/{rel.rsplit('/', 1)[-1]}` in {ig_label}.")
    out.sort(key=lambda f: (f.rule, f.line))
    return ctx_dir, out
