"""Hostile inputs: traversal, symlinks, binary/huge files, pathological text."""

from __future__ import annotations

import os
import time

import pytest

from conftest import write
from dockerlint_mcp.compose import lint_compose
from dockerlint_mcp.errors import UserError
from dockerlint_mcp.files import MAX_BYTES, Sandbox, load_dockerfile
from dockerlint_mcp.fixes import fix_preview
from dockerlint_mcp.ignorecheck import check_dockerignore
from dockerlint_mcp.layers import explain_layers, overview
from dockerlint_mcp.multistage import suggest
from dockerlint_mcp.rules import lint


@pytest.fixture
def sb(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    write(str(tmp_path / "outside.txt"), "FROM alpine:3.20\n")
    write(str(root / "Dockerfile"), "FROM alpine:3.20\n")
    return Sandbox(str(root))


@pytest.mark.parametrize("bad", ["../outside.txt", "..\\outside.txt", "sub/../../outside.txt", ""])
def test_traversal_is_refused(sb, bad) -> None:
    with pytest.raises(UserError):
        load_dockerfile(sb, bad)
    with pytest.raises(UserError):
        check_dockerignore(sb, bad)
    with pytest.raises(UserError):
        lint_compose(sb, bad)


def test_absolute_path_outside_is_refused(sb, tmp_path) -> None:
    with pytest.raises(UserError, match="outside the directory"):
        load_dockerfile(sb, str(tmp_path / "outside.txt"))


def test_nul_byte_path(sb) -> None:
    with pytest.raises(UserError):
        load_dockerfile(sb, "Dockerfile\x00.txt")


def test_symlink_escape_is_refused(sb, tmp_path) -> None:
    link = os.path.join(sb.root, "link")
    try:
        os.symlink(str(tmp_path / "outside.txt"), link)
    except (OSError, NotImplementedError):
        pytest.skip("cannot create symlinks on this runner (needs privileges on Windows)")
    with pytest.raises(UserError, match="outside the directory"):
        load_dockerfile(sb, "link")


def test_symlinked_dockerignore_escape_is_refused(sb, tmp_path) -> None:
    write(str(tmp_path / "outside.dockerignore"), ".git\n")
    link = os.path.join(sb.root, ".dockerignore")
    try:
        os.symlink(str(tmp_path / "outside.dockerignore"), link)
    except (OSError, NotImplementedError):
        pytest.skip("cannot create symlinks on this runner (needs privileges on Windows)")
    with pytest.raises(UserError, match="outside the directory"):
        load_dockerfile(sb, "Dockerfile")


def test_sandbox_prefix_sibling_is_not_inside(tmp_path) -> None:
    (tmp_path / "proj").mkdir()
    (tmp_path / "proj-evil").mkdir()
    write(str(tmp_path / "proj-evil" / "Dockerfile"), "FROM a:1\n")
    with pytest.raises(UserError, match="outside the directory"):
        load_dockerfile(Sandbox(str(tmp_path / "proj")), "../proj-evil/Dockerfile")


def test_binary_directory_and_huge_files(sb) -> None:
    with open(os.path.join(sb.root, "bin"), "wb") as fh:
        fh.write(b"\xff\xfe\x00\x01FROM")
    with pytest.raises(UserError, match="not valid UTF-8"):
        load_dockerfile(sb, "bin")
    os.mkdir(os.path.join(sb.root, "adir"))
    with pytest.raises(UserError):
        sb.read_text("adir")
    with open(os.path.join(sb.root, "big"), "wb") as fh:
        fh.write(b"#" * (MAX_BYTES + 1))
    with pytest.raises(UserError, match="limit"):
        load_dockerfile(sb, "big")


def test_utf8_bom_is_accepted(sb) -> None:
    with open(os.path.join(sb.root, "bom"), "wb") as fh:
        fh.write(b"\xef\xbb\xbfFROM alpine:3.20\n")
    assert load_dockerfile(sb, "bom").df.stages[0].image.name == "alpine"  # type: ignore[union-attr]


def _all_tools(ld) -> None:
    lint(ld.ctx)
    overview(ld)
    explain_layers(ld, frozenset())
    fix_preview(ld, frozenset())
    suggest(ld)


def _timed(text, root, limit=30.0) -> None:
    write(os.path.join(root, "Dockerfile"), text)
    ld = load_dockerfile(Sandbox(root), "Dockerfile")
    t = time.time()
    _all_tools(ld)
    assert time.time() - t < limit


def test_one_megabyte_line_of_repeated_tokens(tmp_path) -> None:
    root = str(tmp_path)
    _timed("FROM a:1\nRUN " + "curl -u x " * 30000 + "\n", root)
    _timed("FROM a:1\nRUN " + "a=b " * 200000 + "\n", root)
    _timed("FROM a:1\nENV " + "A=" * 200000 + "\n", root)


def test_many_instructions(tmp_path) -> None:
    root = str(tmp_path)
    _timed("FROM a:1 AS s\n" + "ARG BUILD_DATE\nENV GIT_SHA=1\nRUN pip install x\nCOPY . .\n" * 3000, root)
    _timed("FROM a:1\n" + "RUN apt-get install x\n" * 8000, root)


def test_pathological_nesting_and_backslashes(tmp_path) -> None:
    root = str(tmp_path)
    _timed("FROM a:1\nCMD " + "[" * 100000 + "\n", root)
    _timed("FROM a:1\nRUN " + "\\ " * 100000 + "x\n", root)
    _timed("FROM a:1\nRUN echo " + "$(" * 50000 + "\n", root)
    _timed("FROM a:1\nRUN " + "'" * 100001 + "\n", root)
    _timed("FROM a:1\nRUN <<A\n" * 5000, root)
    _timed("FROM a:1\nENV X=" + "${A:-" * 5000 + "}" * 5000 + "\nWORKDIR $X\n", root)


def test_expansion_cycles_terminate(tmp_path) -> None:
    _timed("ARG A=$B\nARG B=$A\nFROM x:${A}\nENV C=$C\nWORKDIR $C\n", str(tmp_path))


def test_dockerignore_pathological(tmp_path) -> None:
    write(str(tmp_path / "Dockerfile"), "FROM a:1\nCOPY " + "a" * 5000 + " /x\n")
    write(str(tmp_path / ".dockerignore"), "\n".join(f"**/dir{i}/*.tmp" for i in range(3000)) + "\n")
    t = time.time()
    check_dockerignore(Sandbox(str(tmp_path)), "Dockerfile")
    assert time.time() - t < 30
    write(str(tmp_path / ".dockerignore"), "[" * 500 + "\n" + "\\" * 10 + "\n[]\n[!]\n")
    check_dockerignore(Sandbox(str(tmp_path)), "Dockerfile")


def test_compose_yaml_bomb_and_odd_types(tmp_path) -> None:
    bomb = "a: &a [x, x, x, x, x, x, x, x, x]\n"
    prev = "a"
    for i in range(b := 9):
        cur = chr(ord("b") + i)
        bomb += f"{cur}: &{cur} [*{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}]\n"
        prev = cur
    bomb += f"services:\n  web:\n    image: x:1\n    environment: *{prev}\n    ports: *{prev}\n    volumes: *{prev}\n"
    del b
    write(str(tmp_path / "c.yaml"), bomb)
    t = time.time()
    lint_compose(Sandbox(str(tmp_path)), "c.yaml")
    assert time.time() - t < 30
    odd = "services:\n  a: null\n  b:\n    image: 5\n    ports: [1, {target: x}, [], null]\n    environment: [1, 2, {a: b}]\n    volumes: [1, null]\n    depends_on: 7\n    env_file: [3, {path: 4}]\n  c: [1]\n  42:\n    image: x:1\n"
    write(str(tmp_path / "o.yaml"), odd)
    lint_compose(Sandbox(str(tmp_path)), "o.yaml")
    write(str(tmp_path / "t.yaml"), "services:\n  a: !!python/object/apply:os.system ['echo pwned']\n")
    with pytest.raises(UserError, match="not valid YAML"):
        lint_compose(Sandbox(str(tmp_path)), "t.yaml")


def test_huge_path_is_not_echoed_in_full(sb) -> None:
    with pytest.raises(UserError) as exc:
        load_dockerfile(sb, "A" * 100000)
    assert len(str(exc.value)) < 1000
