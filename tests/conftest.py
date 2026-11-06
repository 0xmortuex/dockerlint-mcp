"""Shared helpers: write real files to a temp dir and lint them through the real code path."""

from __future__ import annotations

import os
from collections.abc import Callable

import pytest

from dockerlint_mcp.files import Sandbox, load_dockerfile
from dockerlint_mcp.rules import Finding, lint


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


@pytest.fixture
def lint_text(tmp_path) -> Callable[..., list[Finding]]:
    """lint_text(dockerfile_text, extra={relative path: content}, disabled=...) -> findings"""
    counter = {"n": 0}

    def run(
        text: str,
        extra: dict[str, str] | None = None,
        disabled: frozenset[str] = frozenset(),
    ) -> list[Finding]:
        counter["n"] += 1
        d = tmp_path / f"case{counter['n']}"
        d.mkdir()
        write(str(d / "Dockerfile"), text)
        for rel, content in (extra or {}).items():
            write(str(d / rel), content)
        sb = Sandbox(str(d))
        ld = load_dockerfile(sb, "Dockerfile")
        return lint(ld.ctx, disabled)

    return run
