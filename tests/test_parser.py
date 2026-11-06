from __future__ import annotations

import pytest

from dockerlint_mcp.parser import expand, parse, parse_image
from dockerlint_mcp.secrets import is_secret_name, redact_line
from dockerlint_mcp.shell import split_commands


def test_continuations_comments_and_blank_lines_inside() -> None:
    df = parse("FROM a:1\nRUN apt-get update \\\n  # a comment\n\n  && apt-get install -y x\nCMD [\"x\"]\n")
    run = df.instructions[1]
    assert (run.line, run.end_line) == (2, 5)
    assert "apt-get install -y x" in run.args and "comment" not in run.args
    assert df.instructions[2].line == 6


def test_parser_directives_and_custom_escape() -> None:
    df = parse("# syntax=docker/dockerfile:1\n# escape=`\nFROM mcr.microsoft.com/windows/servercore:ltsc2022\n"
               "RUN echo a `\n    && echo b\n")
    assert df.directives == {"syntax": "docker/dockerfile:1", "escape": "`"}
    assert (df.instructions[1].line, df.instructions[1].end_line) == (4, 5)


def test_directive_only_valid_at_top() -> None:
    df = parse("FROM a:1\n# escape=`\nRUN echo a \\\n b\n")
    assert df.directives == {} and df.instructions[1].end_line == 4


def test_heredocs_plain_dash_and_quoted() -> None:
    df = parse(
        "FROM a:1\nRUN <<EOF\nline 1\n# not a comment to the parser\nEOF\n"
        "COPY <<-'END' /etc/x.conf\n\tbody\n\tEND\nRUN echo done\n"
    )
    r1, c, r2 = df.instructions[1], df.instructions[2], df.instructions[3]
    assert r1.heredocs[0].body == "line 1\n# not a comment to the parser" and r1.end_line == 5
    assert c.heredocs[0].delimiter == "END" and c.heredocs[0].body == "\tbody" and c.end_line == 8
    assert r2.line == 9 and not df.errors


def test_here_string_is_not_a_heredoc() -> None:
    df = parse("FROM a:1\nRUN cat <<< hello\nRUN true\n")
    assert not df.instructions[1].heredocs and df.instructions[2].line == 3


def test_json_vs_shell_form() -> None:
    df = parse('FROM a:1\nCMD ["a", "b c"]\nENTRYPOINT ["x"]\nCMD a b\nRUN ["sh", "-c", "true"]\nCMD [bad json]\n')
    cmd1, ep, cmd2, run, bad = df.instructions[1:]
    assert cmd1.json_form and cmd1.argv == ["a", "b c"] and ep.json_form
    assert not cmd2.json_form and run.json_form and not bad.json_form


def test_flags_mount_chown_from() -> None:
    df = parse(
        "FROM --platform=$BUILDPLATFORM golang:1.23 AS b\nRUN --mount=type=cache,target=/go/pkg --network=none go build\n"
        "FROM alpine:3.20\nCOPY --from=b --chown=1:1 /a /b\n"
    )
    assert df.stages[0].platform == "$BUILDPLATFORM"
    assert df.instructions[1].flag("mount") == "type=cache,target=/go/pkg"
    assert df.instructions[1].args == "go build"
    cp = df.instructions[3]
    assert cp.flag("from") == "b" and cp.flag("chown") == "1:1" and cp.sources_and_dest() == (["/a"], "/b")


def test_onbuild_instructions_are_marked() -> None:
    df = parse("FROM a:1\nONBUILD ADD . /app\nONBUILD RUN pip install x\n")
    assert [(i.cmd, i.onbuild) for i in df.instructions[1:]] == [("ADD", True), ("RUN", True)]


def test_multistage_names_and_internal_base() -> None:
    df = parse("FROM node:22 AS Build\nFROM build AS test\nFROM nginx:1.27\n")
    assert [s.name for s in df.stages] == ["build", "test", None]
    assert df.stages[1].internal_from == 0 and df.stages[1].image is None


def test_arg_env_expansion() -> None:
    df = parse("ARG V=3.12\nARG REG=docker.io\nFROM ${REG}/python:${V}-slim\nENV HOME_DIR=/srv\nWORKDIR $HOME_DIR/app\n")
    assert df.stages[0].base == "docker.io/python:3.12-slim" and df.stages[0].image is not None
    assert df.stages[0].image.tag == "3.12-slim"
    assert df.instructions[-1].expanded == "/srv/app"
    assert df.global_args == {"V": "3.12", "REG": "docker.io"}


def test_expand_forms() -> None:
    env = {"A": "1", "E": ""}
    assert expand("${A:-x}${B:-y}${E:-z}${E-w}", env) == ("1yz", True)
    assert expand("${A:+set}${B:+set}", env) == ("set", True)
    assert expand("$MISSING \\$A", env) == ("$MISSING $A", False)


def test_legacy_env_and_multiple_pairs() -> None:
    df = parse('FROM a:1\nENV key some value\nENV A=1 B="two words" C=3\nARG X\nARG Y=2\n')
    assert df.instructions[1].pairs == [("key", "some value")]
    assert df.instructions[2].pairs == [("A", "1"), ("B", "two words"), ("C", "3")]
    assert df.instructions[3].pairs == [("X", None)] and df.instructions[4].pairs == [("Y", "2")]


def test_image_refs() -> None:
    assert parse_image("localhost:5000/team/app:1.2").tag == "1.2"
    assert parse_image("localhost:5000/team/app").tag is None
    d = parse_image("nginx:1.27@sha256:" + "a" * 64)
    assert d.tag == "1.27" and d.digest is not None and d.name == "nginx"


@pytest.mark.parametrize("text", ["", "\n\n", "# only a comment\n", "FROM", "RUN", "FROM a:1\nRUN \\\n", "\x00\x01"])
def test_degenerate_inputs_do_not_crash(text: str) -> None:
    parse(text)


def test_crlf_and_utf8_bom_lines() -> None:
    df = parse("FROM a:1\r\nRUN echo a \\\r\n  && echo b\r\nCMD [\"x\"]\r\n")
    assert df.instructions[1].end_line == 3 and df.instructions[2].line == 4


def test_shell_splitting() -> None:
    cmds = split_commands("sudo apt-get update && (cd /x && make) ; FOO=1 pip3 install -r r.txt | tee log")
    names = [(c.name, c.depth) for c in cmds]
    assert names == [("apt-get", 0), ("cd", 1), ("make", 1), ("pip", 0), ("tee", 0)]
    assert cmds[0].sudo and cmds[3].env == {"FOO": "1"}
    assert split_commands("python3 -m pip install x")[0].name == "pip"
    assert split_commands("echo 'a && b'")[0].args == ["a && b"]


def test_secret_names_and_redaction() -> None:
    for name in ("DB_PASSWORD", "githubToken", "AWS_SECRET_ACCESS_KEY", "API_KEY", "apiKey", "NPM_TOKEN"):
        assert is_secret_name(name), name
    for name in ("TOKENIZERS_PARALLELISM", "PASSWORD_FILE", "SECRET_NAME", "PATH", "GPG_KEY", "AUTH_URL", "KEYBOARD"):
        assert not is_secret_name(name), name
    out = redact_line("RUN login --password hunter2 https://u:pw123@h.io TOKEN=abc && echo $TOKEN")
    assert "hunter2" not in out and "pw123" not in out and "abc" not in out and "$TOKEN" in out
    assert redact_line("ENV DB_PASSWORD hunter2") == "ENV DB_PASSWORD <redacted>"
    assert redact_line("ENV TZ=UTC") == "ENV TZ=UTC"
