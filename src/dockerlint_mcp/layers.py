"""dockerfile_overview and explain_layers: structure, layers, size hints, cache order."""

from __future__ import annotations

import re

from .files import LoadedDockerfile
from .parser import Dockerfile, Instruction, Stage
from .report import clip
from .rules import Finding, effective_user, install_commands, lint

from .secrets import is_secret_name, redact_line
from .shell import Command

LAYER_CMDS = {"RUN", "COPY", "ADD"}
_VOLATILE = re.compile(
    r"^(BUILD_?(DATE|TIME|NUMBER|ID|TIMESTAMP)|GIT_?(SHA|COMMIT|REV|HASH)|VCS_?REF|COMMIT_?(SHA|HASH)?|"
    r"SOURCE_?DATE|TIMESTAMP|CI_PIPELINE_ID|CI_JOB_ID|GITHUB_(SHA|RUN_ID))$",
    re.I,
)
_MANIFESTS = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt",
    "pyproject.toml", "poetry.lock", "uv.lock", "go.mod", "go.sum", "cargo.toml", "cargo.lock",
    "gemfile", "gemfile.lock", "composer.json", "composer.lock", "pom.xml", "build.gradle",
}


def _short(ins: Instruction, width: int = 90) -> str:
    text = ins.shell_text if ins.cmd == "RUN" else ins.args
    flags = "".join(f"--{n}{'=' + v if v is not None else ''} " for n, v in ins.flags)
    text = redact_line(" ".join((flags + text).split()))
    return text if len(text) <= width else text[: width - 3] + "..."


def _heavy(ins: Instruction) -> bool:
    return ins.cmd == "RUN" and (bool(install_commands(ins)) or any(_installs_os_pkgs(c) for c in ins.commands()))


def _installs_os_pkgs(c: Command) -> bool:
    return (c.name in ("apt-get", "apt", "yum", "dnf", "microdnf", "apk")) and c.has_arg("install", "add")


def size_hint(ins: Instruction) -> str:
    if ins.cmd in ("COPY", "ADD"):
        if ins.flag("from") is not None:
            return "only the copied artifacts"
        srcs, _ = ins.sources_and_dest()
        if any(s in (".", "./", "*", "./*") for s in srcs):
            return "large: the whole build context (minus .dockerignore)"
        if srcs and all(s.rsplit("/", 1)[-1].lower() in _MANIFESTS for s in srcs):
            return "tiny: dependency manifests"
        if any(re.match(r"^(https?|git)://", s) for s in srcs):
            return "size of the downloaded file"
        return "depends on the copied files"
    if ins.cmd != "RUN":
        return "metadata only (no size)"
    cmds = ins.commands()
    if any(_installs_os_pkgs(c) for c in cmds):
        return "large: OS packages, typically 20-300 MB"
    if install_commands(ins) or any(c.name == "pip" and c.has_arg("install") for c in cmds):
        return "large: dependencies, often 50-500 MB"
    if any(c.name in ("apt-get", "apt") and c.has_arg("update") for c in cmds):
        return "medium: package index, about 30-50 MB"
    if any(c.name in ("chown", "chmod") and c.has_flag("--recursive", "R") for c in cmds):
        return "duplicates every file it touches (the whole tree is copied into this layer)"
    if any(c.name in ("go", "cargo", "mvn", "gradle", "make", "tsc", "dotnet") for c in cmds) or any(
        c.name in ("npm", "yarn", "pnpm") and c.has_arg("run", "build") for c in cmds
    ):
        return "medium to large: build outputs and intermediate files"
    if any(c.name in ("curl", "wget") for c in cmds):
        return "size of the downloaded files"
    if cmds and all(c.name in ("rm", "mkdir", "ln", "echo", "useradd", "adduser", "groupadd", "addgroup",
                              "touch", "chmod", "chown", "mv", "cp") for c in cmds):
        return "small"
    return "small to medium (unknown)"


def _stage_label(st: Stage) -> str:
    return f"stage {st.index}" + (f" '{st.name}'" if st.name else "")


def _big_recursive(c: Command, before: list[Instruction]) -> bool:
    """chown/chmod -R over the whole application tree (not a few small subdirectories)."""
    if c.name not in ("chown", "chmod") or not c.has_flag("--recursive", "R"):
        return False
    targets = c.positionals()[1:]
    workdir = "/"
    dests: set[str] = set()
    for p in before:
        if p.cmd == "WORKDIR":
            workdir = (p.expanded or p.args).strip()
        elif p.cmd in ("COPY", "ADD"):
            _, dest = p.sources_and_dest()
            if dest.startswith("/"):
                dests.add(dest.rstrip("/") or "/")
    for t in targets:
        t = t.rstrip("/") or "/"
        if t in (".", "*", workdir.rstrip("/") or "/") or t in dests:
            return True
    return False


def cache_problems(df: Dockerfile, findings: list[Finding]) -> list[tuple[int, str, str]]:
    """(line, problem, fix) for build-cache and layer-size ordering issues."""
    out: list[tuple[int, str, str]] = []
    for f in findings:
        if f.rule in ("DL1009", "DL1003", "DL1021"):
            out.append((f.line, f"{f.rule}: {f.message}", f.fix))
    for st in df.stages:
        body = [i for i in st.instructions if not i.onbuild]
        # cleanup in a later layer does not shrink earlier layers
        for k, ins in enumerate(body):
            if ins.cmd != "RUN":
                continue
            cmds = ins.commands()
            if cmds and all(c.name == "rm" for c in cmds) and k > 0:
                prev = next((p for p in reversed(body[:k]) if p.cmd in LAYER_CMDS), None)
                if prev is not None and prev.cmd == "RUN":
                    out.append((
                        ins.line,
                        "rm in its own layer: files deleted here are still stored in the earlier layer "
                        f"(line {prev.line}), so the image does not get smaller.",
                        "Delete in the same RUN that created the files: `RUN <install> && rm -rf <cache>`.",
                    ))
            if any(_big_recursive(c, body[:k]) for c in cmds):
                prev_copy = next((p for p in reversed(body[:k]) if p.cmd in ("COPY", "ADD")), None)
                if prev_copy is not None:
                    out.append((
                        ins.line,
                        f"Recursive chown/chmod after the COPY on line {prev_copy.line} writes a second "
                        "copy of every file into a new layer.",
                        "Set ownership while copying: `COPY --chown=app:app ...` / `COPY --chmod=755 ...`.",
                    ))
        # volatile build args/env before expensive layers
        analysed = 0
        for k, ins in enumerate(body):
            if ins.cmd not in ("ARG", "ENV"):
                continue
            for name, _ in ins.pairs:
                if not _VOLATILE.match(name):
                    continue
                analysed += 1
                if analysed > 100:
                    if analysed == 101:
                        out.append((
                            ins.line,
                            "More than 100 volatile ARG/ENV declarations in one stage; the rest were not analyzed.",
                            "Declare build metadata once, at the end of the stage.",
                        ))
                    continue
                later = body[k + 1 :]
                if ins.cmd == "ENV":
                    heavy = next((r for r in later if _heavy(r)), None)
                else:
                    ref = re.compile(r"\$\{?" + re.escape(name) + r"\b")
                    first = next((r for r in later if r.cmd == "RUN" and ref.search(r.shell_text)), None)
                    heavy = None
                    if first is not None:
                        heavy = first if _heavy(first) else next(
                            (r for r in later if r.line > first.line and _heavy(r)), None
                        )
                if heavy is not None:
                    out.append((
                        ins.line,
                        f"{ins.cmd} {name} changes on every build and sits before the expensive step on "
                        f"line {heavy.line}; every layer after it is rebuilt each time.",
                        f"Move `{ins.cmd} {name}` (and any LABEL that uses it) to the end of the stage.",
                    ))
        # runs of consecutive RUN instructions
        streak: list[Instruction] = []
        for ins in body + [Instruction(cmd="END", args="", line=0, end_line=0)]:
            if ins.cmd == "RUN" and not ins.heredocs and not ins.flags:
                streak.append(ins)
                continue
            if len(streak) >= 4:
                out.append((
                    streak[0].line,
                    f"{len(streak)} consecutive RUN instructions (lines {streak[0].line}-{streak[-1].line}) "
                    "create one layer each.",
                    "Merge steps that belong together with `&&` (keep slow, rarely-changing steps in "
                    "their own RUN so they stay cached).",
                ))
            streak = []
    out.sort(key=lambda t: t[0])
    return out


def explain_layers(ld: LoadedDockerfile, disabled: frozenset[str]) -> str:
    df = ld.df
    findings = lint(ld.ctx, disabled)
    lines: list[str] = []
    total = 0
    lines.append(f"Layer analysis of {ld.path}")
    lines.append("")
    for st in df.stages:
        layers = [i for i in st.instructions if i.cmd in LAYER_CMDS and not i.onbuild]
        total += len(layers)
        base = st.base if st.resolved else st.base_raw
        lines.append(
            f"{_stage_label(st)} (line {st.line}): FROM {redact_line(base)}"
            + (" [builds on an earlier stage]" if st.internal_from is not None else "")
            + f" - {len(layers)} filesystem layer(s) of its own"
            + (" (only this stage ships)" if st.index == len(df.stages) - 1 else " (build-only unless copied from)")
        )
        for ins in st.instructions:
            kind = "layer" if ins.cmd in LAYER_CMDS else "meta "
            tag = "ONBUILD " if ins.onbuild else ""
            lines.append(
                f"  L{ins.line:<4} {tag}{ins.cmd:<11} {kind}  {size_hint(ins)}\n"
                f"        {_short(ins)}"
            )
        lines.append("")
    problems = cache_problems(df, findings)
    if problems:
        lines.append(f"Order / cache problems ({len(problems)}):")
        for line, msg, fix in problems:
            lines.append(f"  L{line}: {msg}")
            lines.append(f"      fix: {fix}")
    else:
        lines.append("Order / cache problems: none found.")
    lines.append("")
    lines.append(
        f"Total: {total} RUN/COPY/ADD layer(s) across {len(df.stages)} stage(s). "
        "Sizes are heuristics from the commands, not measurements (nothing is built)."
    )
    return clip("\n".join(lines))


def _ports(df: Dockerfile, st: Stage) -> list[str]:
    ports: list[str] = []
    cur: Stage | None = st
    chain: list[Stage] = []
    while cur is not None:
        chain.append(cur)
        cur = df.stages[cur.internal_from] if cur.internal_from is not None else None
    for s in reversed(chain):
        for ins in s.instructions:
            if ins.cmd == "EXPOSE" and not ins.onbuild:
                for tok in (ins.expanded or ins.args).split():
                    p = tok if "/" in tok else tok + "/tcp"
                    if p not in ports:
                        ports.append(p)
    return ports


def _form(ins: Instruction | None) -> str:
    if ins is None:
        return "not set"
    if ins.json_form:
        import json

        return "exec form " + redact_line(json.dumps(ins.argv))
    return "shell form `" + redact_line(ins.args) + "`"


def overview(ld: LoadedDockerfile) -> str:
    df = ld.df
    out: list[str] = [f"Dockerfile: {ld.path}", f"{len(df.lines)} lines, {len(df.instructions)} instructions"]
    if df.directives:
        out.append("Parser directives: " + ", ".join(f"{k}={v}" for k, v in df.directives.items()))
    if df.global_args:
        parts = []
        for k, v in df.global_args.items():
            parts.append(k if v is None else (f"{k}=<redacted>" if is_secret_name(k) else f"{k}={v}"))
        out.append("ARGs before FROM: " + ", ".join(parts))
    out.append("")
    if not df.stages:
        out.append("No FROM instruction found - this is not a buildable Dockerfile.")
        return "\n".join(out)
    out.append(f"Stages ({len(df.stages)}):")
    total = 0
    for st in df.stages:
        n = sum(1 for i in st.instructions if i.cmd in LAYER_CMDS and not i.onbuild)
        total += n
        if st.internal_from is not None:
            base = f"stage '{df.stages[st.internal_from].name}'"
        elif st.image is not None:
            im = st.image
            pin = f"tag {im.tag}" if im.tag else "no tag (implicit :latest)"
            if im.digest:
                pin += f", digest {im.digest[:19]}..."
            base = f"{im.name} ({pin})"
        else:
            base = f"{st.base_raw} (unresolved variable)"
        extra = f" platform={st.platform}" if st.platform else ""
        out.append(f"  {st.index}: {st.name or '(unnamed)'} - line {st.line}, base {base}{extra}, {n} layer(s)")
    final = df.stages[-1]
    out.append("")
    out.append(f"Final stage: {_stage_label(final)} (this is what `docker build` produces)")
    user, uins, safe = effective_user(df, final)
    if user is None:
        user_text = "non-root base image (nonroot/unprivileged tag)" if safe else "root (no USER instruction)"
    else:
        user_text = f"{user} (line {uins.line if uins else '?'})"
    out.append(f"  user: {user_text}")
    wd = [i for i in final.instructions if i.cmd == "WORKDIR" and not i.onbuild]
    out.append(f"  workdir: {(wd[-1].expanded or wd[-1].args) if wd else '(not set; /)'}")
    ports = _ports(df, final)
    out.append("  exposed ports: " + (", ".join(ports) if ports else "none"))
    ep = [i for i in final.instructions if i.cmd == "ENTRYPOINT" and not i.onbuild]
    cmd = [i for i in final.instructions if i.cmd == "CMD" and not i.onbuild]
    out.append(f"  entrypoint: {_form(ep[-1] if ep else None)}")
    out.append(f"  cmd: {_form(cmd[-1] if cmd else None)}")
    hc = [i for i in final.instructions if i.cmd == "HEALTHCHECK" and not i.onbuild]
    out.append("  healthcheck: " + ("disabled (NONE)" if hc and hc[-1].args.upper() == "NONE" else "yes" if hc else "none defined"))
    out.append(f"  layers in this stage: {sum(1 for i in final.instructions if i.cmd in LAYER_CMDS and not i.onbuild)}; "
               f"{total} across all stages")
    edges = []
    for st in df.stages:
        for ins in st.instructions:
            if ins.cmd == "COPY" and ins.flag("from") and not ins.onbuild:
                edges.append(f"stage {st.index} line {ins.line} <- {ins.flag('from')}")
    if edges:
        out.append("  COPY --from edges: " + "; ".join(edges))
    return clip("\n".join(out))
