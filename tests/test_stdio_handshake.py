"""MCP stdio smoke test: spawns the real server over stdio, checks the tool list, calls every
tool against real files, and checks that instructive errors survive the trip to the agent
(MCPServer hides any exception that isn't a ToolError)."""

import os
import sys

import pytest

pytest.importorskip("mcp")

from mcp import ClientSession  # noqa: E402
from mcp.client.stdio import StdioServerParameters, stdio_client  # noqa: E402

EXPECTED_TOOLS = {
    "dockerfile_overview",
    "lint_dockerfile",
    "explain_layers",
    "lint_compose",
    "check_dockerignore",
    "suggest_multistage",
    "fix_preview",
}

DOCKERFILE = (
    "FROM python\nCOPY . .\nRUN apt-get update && apt-get install curl\n"
    "ENV DB_PASSWORD=hunter2\nCMD python app.py\n"
)
COMPOSE = "version: '3'\nservices:\n  web:\n    image: nginx:latest\n    privileged: true\n"


def _write(path, text):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def _params(root, *extra):
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "dockerlint_mcp", "--dir", str(root), *extra],
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )


@pytest.mark.anyio
async def test_tools_and_a_session_over_stdio(tmp_path):
    _write(tmp_path / "Dockerfile", DOCKERFILE)
    _write(tmp_path / "docker-compose.yml", COMPOSE)
    async with stdio_client(_params(tmp_path)) as (read, write), ClientSession(read, write) as session:
        init = await session.initialize()
        assert init.server_info.name == "dockerlint"
        names = {t.name for t in (await session.list_tools()).tools}
        assert names == EXPECTED_TOOLS, (names - EXPECTED_TOOLS, EXPECTED_TOOLS - names)

        res = await session.call_tool("lint_dockerfile", {"path": "Dockerfile"})
        text = res.content[0].text
        assert not res.is_error
        assert "[DL1001] warning line 1" in text and "[DL1024] error line 3" in text
        assert "[DL1010] error line 4" in text and "DB_PASSWORD" in text
        assert "hunter2" not in text
        assert "fix:" in text

        res = await session.call_tool("dockerfile_overview", {"path": "Dockerfile"})
        assert "shell form `python app.py`" in res.content[0].text
        res = await session.call_tool("explain_layers", {"path": "."})
        assert "Order / cache problems" in res.content[0].text
        res = await session.call_tool("fix_preview", {"path": "Dockerfile"})
        assert "--no-install-recommends" in res.content[0].text and "hunter2" not in res.content[0].text
        res = await session.call_tool("suggest_multistage", {"path": "Dockerfile"})
        assert "AS builder" in res.content[0].text
        res = await session.call_tool("check_dockerignore", {"path": "Dockerfile"})
        assert "DI3001" in res.content[0].text
        res = await session.call_tool("lint_compose", {"path": "docker-compose.yml"})
        assert "[DC2003] error line 5" in res.content[0].text and "[DC2013]" in res.content[0].text


@pytest.mark.anyio
async def test_disable_flag_over_stdio(tmp_path):
    _write(tmp_path / "Dockerfile", DOCKERFILE)
    async with stdio_client(_params(tmp_path, "--disable", "DL1001,DL1013", "--disable", "dl1007")) as (r, w), \
            ClientSession(r, w) as session:
        await session.initialize()
        text = (await session.call_tool("lint_dockerfile", {"path": "Dockerfile"})).content[0].text
        assert "DL1001" not in text and "DL1013" not in text and "DL1007" not in text
        assert "DL1024" in text


@pytest.mark.anyio
async def test_instructive_errors_reach_the_agent(tmp_path):
    outside = tmp_path / "outside"
    root = tmp_path / "proj"
    outside.mkdir()
    root.mkdir()
    _write(outside / "Dockerfile", "FROM alpine:3.20\n")
    _write(root / "bad.yml", "services: [oops\n")
    async with stdio_client(_params(root)) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        res = await session.call_tool("lint_dockerfile", {"path": "nope/Dockerfile"})
        assert res.is_error and "File not found" in res.content[0].text
        res = await session.call_tool("lint_dockerfile", {"path": str(outside / "Dockerfile")})
        assert res.is_error and "outside the directory this server is allowed to read" in res.content[0].text
        res = await session.call_tool("lint_dockerfile", {"path": "../outside/Dockerfile"})
        assert res.is_error and "outside the directory" in res.content[0].text
        res = await session.call_tool("lint_compose", {"path": "bad.yml"})
        assert res.is_error and "not valid YAML" in res.content[0].text


def test_cli_rejects_unknown_rule_id(tmp_path):
    import subprocess

    p = subprocess.run(
        [sys.executable, "-m", "dockerlint_mcp", "--dir", str(tmp_path), "--disable", "DL9999"],
        capture_output=True, text=True, timeout=60,
    )
    assert p.returncode == 2 and "unknown rule id" in p.stderr


def test_cli_rejects_missing_dir(tmp_path):
    import subprocess

    p = subprocess.run(
        [sys.executable, "-m", "dockerlint_mcp", "--dir", str(tmp_path / "nope")],
        capture_output=True, text=True, timeout=60,
    )
    assert p.returncode == 2 and "not a directory" in p.stderr
