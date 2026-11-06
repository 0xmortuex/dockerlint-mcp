"""The rule engine and every Dockerfile rule.

A rule is a function `(Ctx) -> Iterable[Hit]` registered with `@rule(id, severity, title)`.
`lint_dockerfile` runs all enabled rules, applies `# dockerlint-ignore:` comments, and
returns Findings sorted by line. Non-Dockerfile rule ids (compose, dockerignore) are
declared in RULES too so `--disable` can validate them.
"""

from __future__ import annotations

import difflib
import os
import posixpath
import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from typing import NamedTuple

from .dockerignore import IgnoreMatcher
from .parser import Dockerfile, Instruction, Stage
from .secrets import has_literal, is_secret_name, scan
from .shell import Command

SEVERITIES = ("error", "warning", "info")
_SEV_RANK = {"error": 0, "warning": 1, "info": 2}


@dataclass(frozen=True)
class RuleInfo:
    id: str
    severity: str
    title: str


RULES: dict[str, RuleInfo] = {}


@dataclass
class Finding:
    rule: str
    severity: str
    line: int
    message: str
    fix: str


class Hit(NamedTuple):
    line: int
    message: str
    fix: str
    severity: str | None = None


@dataclass
class Ctx:
    df: Dockerfile
    context_dir: str | None = None  # directory of the Dockerfile (assumed build context)
    ignore: IgnoreMatcher | None = None  # parsed .dockerignore, if one exists


Check = Callable[[Ctx], Iterable[Hit]]
_CHECKS: list[tuple[str, Check]] = []


def declare(rule_id: str, severity: str, title: str) -> None:
    RULES[rule_id] = RuleInfo(rule_id, severity, title)


def rule(rule_id: str, severity: str, title: str) -> Callable[[Check], Check]:
    declare(rule_id, severity, title)

    def deco(fn: Check) -> Check:
        _CHECKS.append((rule_id, fn))
        return fn

    return deco


def lint(ctx: Ctx, disabled: frozenset[str] = frozenset()) -> list[Finding]:
    out: list[Finding] = []
    for rid, fn in _CHECKS:
        if rid in disabled:
            continue
        info = RULES[rid]
        for h in fn(ctx):
            ins = ctx.df.instr_at(h.line)
            if ins is not None and rid in ins.ignores:
                continue
            out.append(Finding(rid, h.severity or info.severity, h.line, h.message, h.fix))
    out.sort(key=lambda f: (f.line, _SEV_RANK[f.severity], f.rule))
    return out


# ---------------------------------------------------------------- helpers


def runs(df: Dockerfile) -> Iterator[Instruction]:
    for ins in df.instructions:
        if ins.cmd == "RUN" and not ins.onbuild:
            yield ins


def active(df: Dockerfile, *cmds: str) -> Iterator[Instruction]:
    for ins in df.instructions:
        if ins.cmd in cmds and not ins.onbuild:
            yield ins


def _is_apt_get(c: Command, sub: str) -> bool:
    return c.name == "apt-get" and c.has_arg(sub)


def _is_apt(c: Command, sub: str) -> bool:
    return c.name == "apt" and c.has_arg(sub)


def _cache_mounts(ins: Instruction) -> list[str]:
    return [v for v in ins.flag_values("mount") if "type=cache" in v]


def _env_truthy(env: dict[str, str], name: str) -> bool:
    v = env.get(name)
    return v is not None and v.strip().lower() not in ("", "0", "false", "no", "off")


_PIP_POSITIONAL_OK = re.compile(r"^(\.|\./|\.\.|\.\[.*\])$")


def is_dep_install(c: Command) -> bool:
    """Does this command install the project's dependencies (the cache-friendly step)?"""
    n, a = c.name, c.args
    pos = c.positionals()
    if n == "pip" and c.has_arg("install"):
        if c.has_flag("--requirement", "r"):
            return True
        pk = [p for p in pos if p != "install" and not _PIP_POSITIONAL_OK.match(p)]
        return bool(pk) and not set(pk) <= {"pip", "setuptools", "wheel"}
    if n in ("npm", "pnpm", "bun") and any(x in a for x in ("ci", "install", "i", "add")):
        return not c.has_flag("--global", "g")
    if n == "yarn":
        return not a or a[0] in ("install", "add") or a[0].startswith("--")
    if n == "bundle" and c.has_arg("install"):
        return True
    if n == "composer" and c.has_arg("install", "require"):
        return True
    if n == "go" and a[:2] == ["mod", "download"]:
        return True
    if n == "poetry" and c.has_arg("install"):
        return True
    if n == "uv" and (c.has_arg("sync") or (c.has_arg("pip") and c.has_arg("install"))):
        return True
    if n == "pipenv" and c.has_arg("install", "sync"):
        return True
    if n == "cargo" and c.has_arg("fetch"):
        return True
    if n == "dotnet" and c.has_arg("restore"):
        return True
    if n in ("mvn", "mvnw", "./mvnw") and any("dependency:" in x for x in a):
        return True
    if n == "mix" and c.has_arg("deps.get"):
        return True
    return False


def install_commands(ins: Instruction) -> list[Command]:
    return [c for c in ins.commands() if is_dep_install(c)]


# ---------------------------------------------------------------- FROM


@rule("DL1001", "warning", "base image has no version tag or digest")
def _unpinned(ctx: Ctx) -> Iterator[Hit]:
    for st in ctx.df.stages:
        if st.internal_from is not None or not st.resolved or st.image is None:
            continue
        img = st.image
        if img.name.lower() == "scratch" or img.tag or img.digest:
            continue
        yield Hit(
            st.line,
            f"FROM {img.name} has no tag, so it means ':latest' and changes under you.",
            f"Pin a version, e.g. `FROM {img.name}:<version>` (or an @sha256 digest for "
            "reproducible builds).",
        )


@rule("DL1002", "warning", "base image uses the :latest tag")
def _latest(ctx: Ctx) -> Iterator[Hit]:
    for st in ctx.df.stages:
        img = st.image
        if img is None or not st.resolved or img.digest:
            continue
        if (img.tag or "").lower() == "latest":
            yield Hit(
                st.line,
                f"FROM {img.name}:latest is not reproducible; the build changes when upstream does.",
                f"Replace `:latest` with a specific version of {img.name}, e.g. "
                f"`FROM {img.name}:<major.minor>`.",
            )


# ---------------------------------------------------------------- apt / package managers


@rule("DL1003", "warning", "apt-get update without install in the same RUN")
def _apt_update_alone(ctx: Ctx) -> Iterator[Hit]:
    for ins in runs(ctx.df):
        cmds = ins.commands()
        upd = any(_is_apt_get(c, "update") or _is_apt(c, "update") for c in cmds)
        inst = any(_is_apt_get(c, "install") or _is_apt(c, "install") for c in cmds)
        if upd and not inst:
            yield Hit(
                ins.line,
                "`apt-get update` is in a different layer than the install, so Docker can cache "
                "a stale package index and the install later fails or installs old packages.",
                "Combine them: `RUN apt-get update && apt-get install -y --no-install-recommends "
                "<pkgs> && rm -rf /var/lib/apt/lists/*`.",
            )


@rule("DL1004", "warning", "apt-get install without --no-install-recommends")
def _apt_recommends(ctx: Ctx) -> Iterator[Hit]:
    for ins in runs(ctx.df):
        for c in ins.commands():
            if not _is_apt_get(c, "install"):
                continue
            if c.has_flag("--no-install-recommends") or c.has_flag("--only-upgrade") or any(
                "Install-Recommends" in a for a in c.args
            ):
                continue
            yield Hit(
                ins.line,
                "`apt-get install` also pulls 'recommended' packages, which bloats the image.",
                "Add `--no-install-recommends`: `apt-get install -y --no-install-recommends <pkgs>`.",
            )
            break


@rule("DL1005", "warning", "apt package lists are left in the layer")
def _apt_lists(ctx: Ctx) -> Iterator[Hit]:
    for ins in runs(ctx.df):
        cmds = ins.commands()
        if not any(_is_apt_get(c, "install") or _is_apt(c, "install") for c in cmds):
            continue
        if any("/var/lib/apt" in v for v in _cache_mounts(ins)):
            continue
        if any(c.name == "rm" and any("/var/lib/apt/lists" in a for a in c.args) for c in cmds):
            continue
        yield Hit(
            ins.line,
            "/var/lib/apt/lists is not removed in the same RUN, so the package index (tens of MB) "
            "stays in the image layer.",
            "End the RUN with `&& rm -rf /var/lib/apt/lists/*` (it must be in the same RUN to shrink "
            "the layer).",
        )


@rule("DL1006", "warning", "pip install without --no-cache-dir")
def _pip_cache(ctx: Ctx) -> Iterator[Hit]:
    for ins in runs(ctx.df):
        if _env_truthy(ins.env, "PIP_NO_CACHE_DIR") or _cache_mounts(ins):
            continue
        for c in ins.commands():
            if c.name != "pip" or not c.has_arg("install"):
                continue
            if c.has_flag("--no-cache-dir") or c.has_flag("--no-cache") or _env_truthy(
                c.env, "PIP_NO_CACHE_DIR"
            ):
                continue
            yield Hit(
                ins.line,
                "pip keeps downloaded wheels in ~/.cache/pip, which stays in the layer.",
                "Use `pip install --no-cache-dir ...` or set `ENV PIP_NO_CACHE_DIR=1` once.",
            )
            break


@rule("DL1020", "warning", "package manager cache is left in the layer")
def _pkg_cache(ctx: Ctx) -> Iterator[Hit]:
    for ins in runs(ctx.df):
        cmds = ins.commands()
        if _cache_mounts(ins):
            continue
        for c in cmds:
            if c.name == "apk" and c.has_arg("add"):
                if c.has_flag("--no-cache") or any(
                    x.name == "rm" and any("/var/cache/apk" in a for a in x.args) for x in cmds
                ):
                    continue
                yield Hit(
                    ins.line,
                    "`apk add` caches the index under /var/cache/apk.",
                    "Use `apk add --no-cache <pkgs>` (no separate `apk update` needed).",
                )
                break
            if c.name in ("yum", "dnf", "microdnf") and c.has_arg("install"):
                cleaned = any(
                    (x.name in ("yum", "dnf", "microdnf") and x.has_arg("clean"))
                    or (x.name == "rm" and any("/var/cache/" in a for a in x.args))
                    for x in cmds
                )
                if cleaned:
                    continue
                yield Hit(
                    ins.line,
                    f"`{c.name} install` leaves its metadata cache in the layer.",
                    f"End the RUN with `&& {c.name} clean all` "
                    + ("&& rm -rf /var/cache/yum" if c.name == "yum" else "&& rm -rf /var/cache/dnf"),
                )
                break


@rule("DL1024", "error", "package install without a non-interactive flag")
def _install_yes(ctx: Ctx) -> Iterator[Hit]:
    for ins in runs(ctx.df):
        for c in ins.commands():
            if _is_apt_get(c, "install") or (c.name in ("yum", "dnf", "microdnf") and c.has_arg("install")):
                quiet2 = sum(1 for a in c.args if a == "-qq") or any(
                    a.startswith("-") and not a.startswith("--") and a.count("q") >= 2 for a in c.args
                )
                if c.has_flag("--yes", "y") or c.has_flag("--assume-yes") or c.has_flag("--assumeyes") or (
                    c.name == "apt-get" and quiet2
                ):
                    continue
                yield Hit(
                    ins.line,
                    f"`{c.name} install` will wait for a confirmation prompt and the build fails.",
                    f"Add `-y`: `{c.name} install -y ...`.",
                )
                break


@rule("DL1025", "warning", "apt-get upgrade makes the build non-reproducible")
def _apt_upgrade(ctx: Ctx) -> Iterator[Hit]:
    for ins in runs(ctx.df):
        for c in ins.commands():
            if c.name == "apt-get" and c.has_arg("upgrade", "dist-upgrade", "full-upgrade"):
                yield Hit(
                    ins.line,
                    "Upgrading all packages makes the image depend on the day it was built.",
                    "Remove it; pick a newer base image tag instead and install only what you need.",
                )
                break


@rule("DL1026", "warning", "apt CLI used in a script; use apt-get")
def _apt_cli(ctx: Ctx) -> Iterator[Hit]:
    for ins in runs(ctx.df):
        for c in ins.commands():
            if c.name == "apt" and c.has_arg("install", "update", "upgrade", "remove", "purge", "autoremove"):
                yield Hit(
                    ins.line,
                    "`apt` has an unstable CLI meant for interactive use and prints a warning in scripts.",
                    "Use `apt-get` (same subcommands) in Dockerfiles.",
                )
                break


# ---------------------------------------------------------------- user, security


def effective_user(df: Dockerfile, st: Stage) -> tuple[str | None, Instruction | None, bool]:
    """(last USER value, its instruction, base known to run unprivileged)."""
    for ins in reversed(st.instructions):
        if ins.cmd == "USER" and not ins.onbuild:
            return (ins.expanded or ins.args).strip(), ins, False
    if st.internal_from is not None:
        return effective_user(df, df.stages[st.internal_from])
    if st.image is not None:
        full = (st.image.name + ":" + (st.image.tag or "")).lower()
        if (
            "nonroot" in full
            or "unprivileged" in full
            or st.image.name.lower().startswith("cgr.dev/chainguard/")
        ):
            return None, None, True
    return None, None, False


def _is_root(user: str) -> bool:
    u = user.split(":", 1)[0].strip().lower()
    return u in ("root", "0")


@rule("DL1007", "warning", "container runs as root")
def _root_user(ctx: Ctx) -> Iterator[Hit]:
    df = ctx.df
    if not df.stages:
        return
    st = df.stages[-1]
    user, ins, safe_base = effective_user(df, st)
    if safe_base:
        return
    if user is None:
        yield Hit(
            st.line,
            "The final stage never sets USER, so the app runs as root inside the container.",
            "Create and switch to an unprivileged user before CMD/ENTRYPOINT, e.g. "
            "`RUN useradd --system --uid 10001 app` then `USER app` (or `USER 10001`).",
        )
    elif _is_root(user) and ins is not None:
        yield Hit(
            ins.line,
            "The last USER in the final stage is root.",
            "Switch to an unprivileged user at the end: `USER app` (or a numeric UID such as 10001).",
        )


@rule("DL1008", "warning", "ADD used where COPY would do")
def _add(ctx: Ctx) -> Iterator[Hit]:
    arch = re.compile(r"\.(tar|tar\.gz|tgz|tar\.bz2|tbz2?|tar\.xz|txz|tar\.zst)$", re.I)
    for ins in active(ctx.df, "ADD"):
        srcs, _ = ins.sources_and_dest()
        urls = [s for s in srcs if re.match(r"^(https?|git)://|^git@", s)]
        local = [s for s in srcs if s not in urls and not s.startswith("<<")]
        if urls and ins.flag("checksum") is None:
            yield Hit(
                ins.line,
                "ADD from a URL is unverified and its layer cannot be cleaned up.",
                "Use `RUN curl -fsSLO <url>` and verify with `sha256sum -c`, or add "
                "`--checksum=sha256:<hash>` to ADD.",
                "info",
            )
        if local and not all(arch.search(s) for s in local) and ins.flag("keep-git-dir") is None:
            yield Hit(
                ins.line,
                "ADD has extra magic (auto-extracts archives, fetches URLs); for plain files it is "
                "surprising.",
                "Use `COPY` instead (keep ADD only to auto-extract a local tar archive).",
            )


@rule("DL1010", "error", "secret stored in ENV or ARG")
def _secret_env(ctx: Ctx) -> Iterator[Hit]:
    for ins in ctx.df.instructions:
        if ins.cmd not in ("ENV", "ARG"):
            continue
        for name, value in ins.pairs:
            if is_secret_name(name):
                if value is not None and has_literal(value):
                    yield Hit(
                        ins.line,
                        f"{ins.cmd} {name} sets a hard-coded secret (value redacted); it is baked "
                        "into the image and visible in `docker history`.",
                        f"Remove the value. Mount it at build time with `RUN --mount=type=secret,id={name.lower()} ...` "
                        "or pass it at runtime (`docker run -e` / orchestrator secrets).",
                    )
                elif ins.cmd == "ARG" and value is None:
                    yield Hit(
                        ins.line,
                        f"ARG {name} looks like a credential; build args are stored in image history.",
                        f"Use a BuildKit secret instead: `RUN --mount=type=secret,id={name.lower()} ...`.",
                        "warning",
                    )
            elif value is not None:
                for h in scan(value):
                    if not h.kind.startswith("assignment"):
                        yield Hit(
                            ins.line,
                            f"{ins.cmd} {name} contains what looks like a {h.kind} (value redacted).",
                            "Remove it and supply it at runtime or via `--mount=type=secret`.",
                        )
                        break


@rule("DL1011", "error", "secret in a RUN / COPY / other instruction")
def _secret_run(ctx: Ctx) -> Iterator[Hit]:
    for ins in ctx.df.instructions:
        if ins.cmd in ("ENV", "ARG", "FROM", "LABEL"):
            continue
        text = ins.shell_text if ins.cmd == "RUN" else ins.args
        kinds: list[str] = []
        for ln in text.split("\n"):
            for h in scan(ln):
                if h.kind not in kinds:
                    kinds.append(h.kind)
        if kinds:
            yield Hit(
                ins.line,
                f"{ins.cmd} contains a hard-coded secret ({'; '.join(kinds)}; value redacted). "
                "It is stored in the layer and in `docker history`.",
                "Use `RUN --mount=type=secret,id=<name> ...` (read /run/secrets/<name>) or fetch it "
                "at runtime. Rotate the exposed credential.",
            )


_SHELLISH = {"sh", "bash", "zsh", "dash", "ksh", "python", "python3", "perl", "ruby"}
_CURL_SUBST = re.compile(
    r"\b(?:ba|z)?sh\s+-c\s+[\"']?\$\(\s*(?:curl|wget)\b|\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b"
)


@rule("DL1012", "warning", "piping curl/wget into a shell")
def _curl_sh(ctx: Ctx) -> Iterator[Hit]:
    for ins in runs(ctx.df):
        if ins.json_form:
            continue
        cmds = ins.commands()
        piped = any(
            c.name in ("curl", "wget") and c.sep_after in ("|", "|&") and k + 1 < len(cmds)
            and cmds[k + 1].name in _SHELLISH
            for k, c in enumerate(cmds)
        )
        if piped or _CURL_SUBST.search(ins.shell_text):
            yield Hit(
                ins.line,
                "Running a downloaded script directly is unverifiable and breaks silently on a "
                "partial download.",
                "Download to a file, verify a pinned checksum (`sha256sum -c`), then run it; or use "
                "the distribution's package.",
            )


@rule("DL1018", "warning", "sudo inside a Dockerfile")
def _sudo(ctx: Ctx) -> Iterator[Hit]:
    for ins in runs(ctx.df):
        if any(c.sudo for c in ins.commands()):
            yield Hit(
                ins.line,
                "RUN already runs as the current USER (root by default); sudo is unnecessary and "
                "often not installed.",
                "Drop `sudo`. If you need root for one step, put `USER root` before it and switch back.",
            )


@rule("DL1019", "warning", "world-writable permissions (chmod 777)")
def _chmod(ctx: Ctx) -> Iterator[Hit]:
    bad = re.compile(r"^(0?777|[ugoa]*\+rwx|a=rwx|o\+w|a\+w|[ugo]*=rwx)$")
    for ins in list(runs(ctx.df)) + list(active(ctx.df, "COPY", "ADD")):
        if ins.cmd in ("COPY", "ADD"):
            hit = any(bad.match(v) for v in ins.flag_values("chmod"))
        else:
            hit = any(c.name == "chmod" and any(bad.match(a) for a in c.args) for c in ins.commands())
        if hit:
            yield Hit(
                ins.line,
                "Anyone in the container can modify these files.",
                "Grant only what is needed: `chmod 755` for executables/directories, `644` for data, "
                "or `chown` to the runtime user.",
            )


# ---------------------------------------------------------------- structure


@rule("DL1013", "info", "no HEALTHCHECK")
def _healthcheck(ctx: Ctx) -> Iterator[Hit]:
    df = ctx.df
    if not df.stages:
        return
    st: Stage | None = df.stages[-1]
    while st is not None:
        if any(i.cmd == "HEALTHCHECK" and not i.onbuild for i in st.instructions):
            return
        st = df.stages[st.internal_from] if st.internal_from is not None else None
    yield Hit(
        df.stages[-1].line,
        "The image defines no HEALTHCHECK, so orchestrators cannot tell a hung app from a healthy one.",
        "Add e.g. `HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:8080/health || "
        "exit 1`, or `HEALTHCHECK NONE` to opt out explicitly.",
    )


@rule("DL1014", "warning", "shell-form ENTRYPOINT/CMD (signals are not forwarded)")
def _shell_form(ctx: Ctx) -> Iterator[Hit]:
    for ins in active(ctx.df, "ENTRYPOINT", "CMD"):
        if ins.json_form or not ins.args:
            continue
        if re.match(r"exec\s", ins.args):
            continue
        extra = " (it starts with '[' but is not valid JSON, so Docker treats it as a shell command)" \
            if ins.args.startswith("[") else ""
        yield Hit(
            ins.line,
            f"Shell-form {ins.cmd} runs as `/bin/sh -c ...`; the shell is PID 1 and does not forward "
            f"SIGTERM, so `docker stop` waits 10s and kills the app{extra}.",
            f'Use exec form: `{ins.cmd} ["executable", "arg1"]` (JSON with double quotes), or prefix '
            "the shell command with `exec`.",
        )


@rule("DL1015", "warning", "multiple CMD / ENTRYPOINT / HEALTHCHECK in one stage")
def _multi_cmd(ctx: Ctx) -> Iterator[Hit]:
    for st in ctx.df.stages:
        for kw in ("CMD", "ENTRYPOINT", "HEALTHCHECK"):
            xs = [i for i in st.instructions if i.cmd == kw and not i.onbuild]
            for earlier, later in zip(xs, xs[1:], strict=False):
                yield Hit(
                    earlier.line,
                    f"This {kw} is overridden by the one on line {later.line}; only the last takes effect.",
                    f"Delete the unused {kw} (line {earlier.line}).",
                )


@rule("DL1016", "warning", "WORKDIR is not an absolute path")
def _workdir(ctx: Ctx) -> Iterator[Hit]:
    for ins in active(ctx.df, "WORKDIR"):
        if not ins.resolved:
            continue
        p = (ins.expanded or ins.args).strip().strip("\"'")
        if p.startswith(("/", "\\", "$")) or re.match(r"^[A-Za-z]:", p) or not p:
            continue
        yield Hit(
            ins.line,
            f"WORKDIR '{p}' is relative, so it depends on whatever the previous WORKDIR was.",
            f"Use an absolute path: `WORKDIR /{p}`.",
        )


@rule("DL1017", "warning", "cd inside RUN")
def _cd(ctx: Ctx) -> Iterator[Hit]:
    for ins in runs(ctx.df):
        if any(c.name == "cd" and c.depth == 0 for c in ins.commands()):
            yield Hit(
                ins.line,
                "`cd` in RUN only lasts for that command line and makes the Dockerfile hard to follow.",
                "Use `WORKDIR /path` (or `(cd /path && cmd)` in a subshell if you need it once).",
            )


@rule("DL1009", "warning", "COPY . before installing dependencies busts the build cache")
def _copy_before_install(ctx: Ctx) -> Iterator[Hit]:
    for st in ctx.df.stages:
        installed_before = False
        copy_all: Instruction | None = None
        for ins in st.instructions:
            if ins.onbuild:
                continue
            if ins.cmd in ("COPY", "ADD") and ins.flag("from") is None and copy_all is None:
                srcs, _ = ins.sources_and_dest()
                if any(s in (".", "./", "*", "./*") for s in srcs):
                    copy_all = ins if not installed_before else None
                    if installed_before:
                        break
            elif ins.cmd == "RUN":
                if install_commands(ins):
                    if copy_all is not None:
                        yield Hit(
                            copy_all.line,
                            "Everything is copied before dependencies are installed (line "
                            f"{ins.line}), so any source edit re-runs the dependency install.",
                            "Copy only the manifest first (requirements.txt / package*.json / go.mod ...), "
                            "run the install, THEN `COPY . .`.",
                        )
                        break
                    installed_before = True


@rule("DL1021", "warning", "COPY would send node_modules or .git into the image")
def _big_copy(ctx: Ctx) -> Iterator[Hit]:
    if ctx.context_dir is None:
        return
    heavy = ("node_modules", ".git")
    for ins in active(ctx.df, "COPY", "ADD"):
        if ins.flag("from") is not None:
            continue
        srcs, _ = ins.sources_and_dest()
        found: list[str] = []
        for s in srcs:
            norm = posixpath.normpath(s) if s else s
            if norm in heavy or norm.startswith(tuple(h + "/" for h in heavy)):
                if not (ctx.ignore and ctx.ignore.excludes(norm)):
                    found.append(norm.split("/")[0])
            elif s in (".", "./", "*", "./*"):
                for h in heavy:
                    if os.path.isdir(os.path.join(ctx.context_dir, h)) and not (
                        ctx.ignore and ctx.ignore.excludes(h)
                    ):
                        found.append(h)
        if found:
            names = " and ".join(dict.fromkeys(found))
            yield Hit(
                ins.line,
                f"This COPY sends {names} from the build context into the image"
                + " and no .dockerignore excludes it.",
                f"Create a .dockerignore next to the Dockerfile containing `{chr(10).join(dict.fromkeys(found))}` "
                "(use `**/node_modules` to also cover nested packages).",
            )


@rule("DL1022", "error", "COPY --from refers to an unknown or later stage")
def _copy_from(ctx: Ctx) -> Iterator[Hit]:
    df = ctx.df
    names = {s.name: s.index for s in df.stages if s.name}
    common = {"build", "builder", "base", "deps", "dist", "final", "runtime", "prod", "production",
              "compile", "release", "dev", "test", "app"}
    for ins in active(df, "COPY"):
        val = ins.flag("from")
        if not val or "$" in val:
            continue
        low = val.lower()
        if low.isdigit():
            if int(low) >= ins.stage:
                yield Hit(
                    ins.line,
                    f"COPY --from={val} refers to stage {val}, which is not an earlier stage "
                    f"(this is stage {ins.stage}).",
                    "Stage numbers start at 0 and must point to a stage defined above this line.",
                )
            continue
        if low in names:
            if names[low] >= ins.stage:
                yield Hit(
                    ins.line,
                    f"COPY --from={val} refers to a stage that is defined later (or is this stage); "
                    "Docker would pull an image with that name instead.",
                    "Reorder the stages so the source stage comes first.",
                )
            continue
        if re.search(r"[:/.@]", low):
            continue  # an external image
        close = difflib.get_close_matches(low, list(names), n=1, cutoff=0.7)
        if close or (low in common):
            hint = f" Did you mean '{close[0]}'?" if close else ""
            yield Hit(
                ins.line,
                f"COPY --from={val} does not match any stage name; Docker will try to pull an image "
                f"called '{val}'.{hint}",
                "Name the stage with `FROM ... AS <name>` or fix the name in --from.",
            )


@rule("DL1023", "error", "duplicate stage name")
def _dup_stage(ctx: Ctx) -> Iterator[Hit]:
    seen: dict[str, int] = {}
    for st in ctx.df.stages:
        if not st.name:
            continue
        if st.name in seen:
            yield Hit(
                st.line,
                f"Stage name '{st.name}' is already used on line {seen[st.name]}.",
                "Give every stage a unique `AS <name>`.",
            )
        else:
            seen[st.name] = st.line


@rule("DL1027", "info", "MAINTAINER is deprecated")
def _maintainer(ctx: Ctx) -> Iterator[Hit]:
    for ins in active(ctx.df, "MAINTAINER"):
        yield Hit(
            ins.line,
            "MAINTAINER is deprecated.",
            'Use `LABEL org.opencontainers.image.authors="Name <email>"`.',
        )


@rule("DL1028", "error", "Dockerfile syntax problem")
def _syntax(ctx: Ctx) -> Iterator[Hit]:
    for line, msg in ctx.df.errors:
        yield Hit(line, f"{msg[0].upper()}{msg[1:]}.", "Fix the instruction so Docker can parse it.")


# ---- ids implemented outside this module (compose, dockerignore)

declare("DC2001", "warning", "compose image has no version tag")
declare("DC2002", "warning", "compose image uses :latest")
declare("DC2003", "error", "privileged container")
declare("DC2004", "warning", "host network mode")
declare("DC2005", "error", "docker.sock mounted into a container")
declare("DC2006", "error", "secret in environment")
declare("DC2007", "info", "published port binds all interfaces")
declare("DC2008", "info", "no restart policy")
declare("DC2009", "info", "no healthcheck")
declare("DC2010", "info", "depends_on without a health condition")
declare("DC2012", "warning", "broad host directory bind mount")
declare("DC2013", "info", "obsolete top-level `version:` key")
declare("DC2014", "error", "env_file does not exist")
declare("DI3001", "warning", "no .dockerignore")
declare("DI3002", "warning", ".dockerignore does not exclude .git")
declare("DI3003", "warning", ".dockerignore does not exclude node_modules")
declare("DI3004", "warning", ".dockerignore does not exclude .env files")
declare("DI3005", "error", ".dockerignore excludes a file the Dockerfile copies")
declare("DI3006", "info", "node_modules/.git in a subdirectory is not excluded")

__all__ = ["Ctx", "Finding", "Hit", "RULES", "SEVERITIES", "lint"]
