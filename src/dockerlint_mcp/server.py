"""dockerlint-mcp: static Dockerfile / compose linting for AI agents (no Docker needed)."""

from __future__ import annotations

import argparse
import functools
import os
import sys
from collections.abc import Callable, Sequence
from typing import Any, TypeVar

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import __version__
from .compose import lint_compose as _lint_compose
from .errors import UserError
from .files import Sandbox, load_dockerfile
from .fixes import fix_preview as _fix_preview
from .ignorecheck import check_dockerignore as _check_dockerignore
from .layers import explain_layers as _explain_layers
from .layers import overview as _overview
from .multistage import suggest as _suggest
from .report import format_findings
from .rules import RULES, lint

mcp = MCPServer(
    "dockerlint",
    instructions=(
        "Statically lint and explain Dockerfiles and docker-compose files. Nothing is built or run "
        "and no Docker daemon is needed. Pass a file path (relative to the server's --dir, or "
        "absolute inside it). Typical flow: dockerfile_overview to understand the file, "
        "lint_dockerfile for rule IDs + line numbers + concrete fixes, explain_layers for cache "
        "order and size, check_dockerignore for the build context, fix_preview for a diff of the "
        "safe automatic fixes, suggest_multistage for a rewrite proposal, lint_compose for compose "
        "files. Silence a finding with a `# dockerlint-ignore: DL1003` comment above the instruction."
    ),
)

_sandbox: Sandbox | None = None
_disabled: frozenset[str] = frozenset()

F = TypeVar("F", bound=Callable[..., Any])

# Failures an agent can act on. MCPServer only forwards a ToolError's message; anything
# else arrives as a bare "Error executing tool", so these are re-raised as ToolError.
_EXPECTED = (UserError, OSError, RecursionError)


def tool(fn: F) -> F:
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except RecursionError as e:
            raise ToolError("The file is nested too deeply to analyze.") from e
        except _EXPECTED as e:
            raise ToolError(str(e)) from e

    mcp.tool()(wrapper)
    return fn


def configure(directory: str | None, disable: Sequence[str] = ()) -> None:
    global _sandbox, _disabled
    _sandbox = Sandbox(directory or os.getcwd())
    unknown = sorted(d for d in disable if d not in RULES)
    if unknown:
        raise UserError(f"unknown rule id(s): {', '.join(unknown)}. Known: {', '.join(sorted(RULES))}")
    _disabled = frozenset(disable)


def _sb() -> Sandbox:
    global _sandbox
    if _sandbox is None:
        _sandbox = Sandbox(os.getcwd())
    return _sandbox


@tool
def dockerfile_overview(path: str) -> str:
    """Summarize a Dockerfile: stages with base images (tag/digest), layer count, exposed ports,
    final user, workdir, and ENTRYPOINT/CMD (exec vs shell form). Start here to understand a file
    before linting it. `path` is a Dockerfile or a directory containing one."""
    return _overview(load_dockerfile(_sb(), path))


@tool
def lint_dockerfile(path: str) -> str:
    """Lint a Dockerfile with 28 rules (IDs DL1001-DL1028). Each finding has a rule ID, severity
    (error/warning/info), the line of the instruction, an explanation, and a concrete fix.
    Covers unpinned/latest tags, apt/pip/apk/yum hygiene, root user, ADD vs COPY, COPY-before-install
    cache busting, secrets in ENV/ARG/RUN (values are never echoed), curl|sh, HEALTHCHECK,
    shell-form CMD/ENTRYPOINT, WORKDIR, sudo, chmod 777 and COPY of node_modules/.git.
    Suppress with `# dockerlint-ignore: DL1003` above an instruction. Never builds anything."""
    ld = load_dockerfile(_sb(), path)
    found = lint(ld.ctx, _disabled)
    note = (
        f"Build context assumed to be {ld.ctx.context_dir}; "
        + (f"{os.path.basename(ld.ignore_path)} was read." if ld.ignore_path else "no .dockerignore found there.")
        + " Line numbers are the first line of each instruction."
    )
    return format_findings(f"Dockerfile {ld.path}", found, note)


@tool
def explain_layers(path: str) -> str:
    """Explain which Dockerfile instructions create image layers, with heuristic size hints
    (small/large and why), and list ORDER problems that invalidate the build cache or bloat the
    image (COPY . before dependency install, cleanup in a later layer, recursive chown after COPY,
    volatile build args before expensive steps). Sizes are estimates; nothing is built."""
    return _explain_layers(load_dockerfile(_sb(), path), _disabled)


@tool
def lint_compose(path: str) -> str:
    """Lint a docker-compose / compose.yaml file (rule IDs DC2001-DC2014): unpinned or :latest
    images, privileged, host network, docker.sock mounts, secrets in environment (values never
    echoed), ports published on all interfaces, missing restart/healthcheck, depends_on without a
    condition, broad bind mounts (/, home), obsolete `version:` key, and env_file paths that do not
    exist. Uses yaml.safe_load only. Suppress with `# dockerlint-ignore: DC2008` above a line or service."""
    real, found = _lint_compose(_sb(), path, _disabled)
    return format_findings(f"Compose file {real}", found)


@tool
def check_dockerignore(path: str) -> str:
    """Check the .dockerignore for a Dockerfile (or a directory): missing file, patterns that do
    not exclude .git, node_modules or .env files, nested node_modules the root-anchored patterns
    miss, and patterns that exclude files the Dockerfile COPYs (the build would fail or silently
    omit them). Uses Docker's matching rules (root-anchored, last match wins, ** crosses dirs)."""
    ctx_dir, found = _check_dockerignore(_sb(), path, _disabled)
    return format_findings(f"Build context {ctx_dir}", found)


@tool
def suggest_multistage(path: str) -> str:
    """Propose a multi-stage rewrite of a single-stage Dockerfile as TEXT (never writes a file).
    Recognizes common Python, Node, Go and Rust patterns and reuses your base image version,
    workdir, ports and CMD/ENTRYPOINT. Explains what moves to the build stage and why the final
    image shrinks."""
    return _suggest(load_dockerfile(_sb(), path))


@tool
def fix_preview(path: str) -> str:
    """Show a unified diff of the safe automatic fixes for a Dockerfile (add -y and
    --no-install-recommends to apt-get install, --no-cache-dir to pip, --no-cache to apk, apt ->
    apt-get, ADD -> COPY, shell-form CMD -> exec form, MAINTAINER -> LABEL, apt lists cleanup).
    Never writes the file: apply the diff yourself. Lists the findings that need manual changes."""
    return _fix_preview(load_dockerfile(_sb(), path), _disabled)


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="dockerlint-mcp",
        description="MCP server that statically lints Dockerfiles and compose files.",
    )
    p.add_argument("--dir", default=None, help="Only files inside this directory can be read "
                   "(default: the current directory).")
    p.add_argument("--disable", action="append", default=[], metavar="IDS",
                   help="Comma-separated rule ids to turn off, e.g. DL1013,DC2008 (repeatable).")
    p.add_argument("--version", action="version", version=f"dockerlint-mcp {__version__}")
    return p.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> None:
    args = _parse_args(argv)
    ids = [i.strip().upper() for chunk in args.disable for i in chunk.split(",") if i.strip()]
    try:
        configure(args.dir, ids)
    except UserError as e:
        print(f"dockerlint-mcp: {e}", file=sys.stderr)
        raise SystemExit(2) from e
    mcp.run()


if __name__ == "__main__":
    main()
