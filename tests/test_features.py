from __future__ import annotations

import os
import re

import pytest

from conftest import write
from dockerlint_mcp.dockerignore import IgnoreMatcher
from dockerlint_mcp.errors import UserError
from dockerlint_mcp.files import Sandbox, load_dockerfile
from dockerlint_mcp.fixes import fix_preview
from dockerlint_mcp.ignorecheck import check_dockerignore
from dockerlint_mcp.layers import explain_layers, overview
from dockerlint_mcp.multistage import suggest
from dockerlint_mcp.parser import parse
from dockerlint_mcp.rules import Ctx, lint


def ld_of(tmp_path, text, extra=None):
    write(str(tmp_path / "Dockerfile"), text)
    for rel, content in (extra or {}).items():
        write(str(tmp_path / rel), content)
    return load_dockerfile(Sandbox(str(tmp_path)), "Dockerfile")


# ------------------------------------------------------------------ ignore comments / disable


def test_ignore_comment_applies_to_next_instruction_only(lint_text) -> None:
    text = (
        "FROM alpine:3.20\n# dockerlint-ignore: DL1018\nRUN sudo true\nRUN sudo true\n"
        "# dockerlint-ignore: DL1017, DL1018\n# another comment\nRUN cd /x && sudo true\n"
    )
    got = [(f.rule, f.line) for f in lint_text(text)]
    assert ("DL1018", 3) not in got and ("DL1018", 4) in got
    assert ("DL1017", 7) not in got and ("DL1018", 7) not in got


def test_ignore_comment_inside_continuation_and_on_from(lint_text) -> None:
    text = (
        "# dockerlint-ignore: DL1001, DL1007, DL1013\nFROM python\n"
        "RUN apt-get update \\\n  # dockerlint-ignore: DL1005, DL1004\n  && apt-get install -y curl\n"
    )
    got = {f.rule for f in lint_text(text)}
    assert not got & {"DL1001", "DL1007", "DL1013", "DL1005", "DL1004"}


def test_disable_flag_turns_rules_off(lint_text) -> None:
    text = "FROM python\nRUN sudo true\n"
    assert {f.rule for f in lint_text(text, disabled=frozenset({"DL1001", "DL1013", "DL1007"}))} == {"DL1018"}


def test_onbuild_is_not_linted_as_active(lint_text) -> None:
    got = {f.rule for f in lint_text("FROM alpine:3.20\nUSER app\nHEALTHCHECK NONE\nONBUILD ADD . /app\nONBUILD RUN cd /a\n")}
    assert got == set()


def test_inherited_user_from_earlier_stage(lint_text) -> None:
    text = "FROM alpine:3.20 AS base\nUSER 1000\nHEALTHCHECK NONE\nFROM base\nCMD [\"x\"]\n"
    assert lint_text(text) == []


def test_findings_never_contain_secret_values_via_tools(tmp_path) -> None:
    ld = ld_of(tmp_path, "FROM alpine:3.20\nENV DB_PASSWORD=hunter2\nRUN curl -u a:s3cretpw http://x\nCMD python x\n")
    outputs = [explain_layers(ld, frozenset()), overview(ld), fix_preview(ld, frozenset())]
    outputs.append("\n".join(f.message + f.fix for f in lint(ld.ctx)))
    for o in outputs:
        assert "hunter2" not in o and "s3cretpw" not in o


# ------------------------------------------------------------------ .dockerignore matching


def test_dockerignore_matching_follows_docker_rules() -> None:
    m = IgnoreMatcher("# c\nnode_modules\n*.md\n!README.md\n**/*.log\ntmp/\n/build\nsrc/?.txt\n!tmp/keep\n")
    assert m.excludes("node_modules") and m.excludes("node_modules/a/b.js")
    assert not m.excludes("packages/app/node_modules")  # root-anchored, unlike .gitignore
    assert m.excludes("NOTES.md") and not m.excludes("README.md") and not m.excludes("docs/NOTES.md")
    assert m.excludes("a/b/c.log") and m.excludes("c.log")
    assert m.excludes("tmp") and m.excludes("tmp/x") and not m.excludes("tmp/keep")
    assert m.excludes("build/out.bin") and m.excludes("src/a.txt") and not m.excludes("src/ab.txt")


def test_dockerignore_last_match_wins_and_negation_of_parent() -> None:
    m = IgnoreMatcher("docs\n!docs/api.md\n")
    assert m.excludes("docs/other.md")  # a matching parent excludes its children
    assert not m.excludes("docs/api.md")
    m2 = IgnoreMatcher("*\n!src\n!src/**\n")
    assert m2.excludes("README.md") and not m2.excludes("src/main.py")


def test_dockerignore_double_star_forms() -> None:
    m = IgnoreMatcher("**/node_modules\na/**/z\n**/.env*\n")
    assert m.excludes("node_modules") and m.excludes("x/y/node_modules/q")
    assert m.excludes("a/z") and m.excludes("a/b/c/z") and not m.excludes("b/z")
    assert m.excludes(".env.local") and m.excludes("svc/.env")


def test_dockerignore_rejects_pathological_pattern() -> None:
    with pytest.raises(UserError, match="too many wildcards"):
        IgnoreMatcher("*a" * 40 + "b\n")


# ------------------------------------------------------------------ check_dockerignore


def check(tmp_path, dockerfile, ignore=None, extra=None):
    write(str(tmp_path / "Dockerfile"), dockerfile)
    if ignore is not None:
        write(str(tmp_path / ".dockerignore"), ignore)
    for rel, content in (extra or {}).items():
        write(str(tmp_path / rel), content)
    _, f = check_dockerignore(Sandbox(str(tmp_path)), "Dockerfile")
    return [(x.rule, x.line) for x in f], f


def test_missing_dockerignore(tmp_path) -> None:
    got, _ = check(tmp_path, "FROM alpine:3.20\nCOPY . .\n")
    assert got == [("DI3001", 0)]


def test_dockerignore_missing_git_node_modules_env(tmp_path) -> None:
    got, _ = check(tmp_path, "FROM node:22\nCOPY . .\n", "dist\n", {"package.json": "{}"})
    assert {r for r, _ in got} == {"DI3002", "DI3003", "DI3004"}


def test_dockerignore_root_anchored_pattern_misses_nested(tmp_path) -> None:
    got, f = check(
        tmp_path, "FROM node:22\nCOPY . .\n", ".git\nnode_modules\n.env\n.env.*\n",
        {"package.json": "{}", "packages/app/node_modules/x.js": "x"},
    )
    assert got == [("DI3006", 0)] and "**/node_modules" in f[0].fix


def test_dockerignore_excludes_copied_file(tmp_path) -> None:
    got, f = check(
        tmp_path, "FROM python:3.12\nCOPY requirements.txt .\nCOPY src/app.py /app/\nCOPY *.cfg /etc/\n",
        ".git\n.env\n.env.*\n*.txt\nsrc\n!src/other\n*.cfg\n",
        {"requirements.txt": "x", "src/app.py": "x", "a.cfg": "x"},
    )
    assert ("DI3005", 4) in got and ("DI3005", 5) in got and ("DI3005", 7) in got
    assert any("Dockerfile line 2" in x.message for x in f)


def test_dockerignore_negation_reincludes_copied_file(tmp_path) -> None:
    got, _ = check(
        tmp_path, "FROM python:3.12\nCOPY requirements.txt .\n", ".git\n.env\n.env.*\n*.txt\n!requirements.txt\n",
        {"requirements.txt": "x"},
    )
    assert got == []


def test_dockerignore_for_named_dockerfile_and_directory_input(tmp_path) -> None:
    write(str(tmp_path / "Dockerfile.prod"), "FROM alpine:3.20\nCOPY a.txt /\n")
    write(str(tmp_path / "Dockerfile.prod.dockerignore"), ".git\n.env\n.env.*\na.txt\n")
    write(str(tmp_path / "a.txt"), "x")
    sb = Sandbox(str(tmp_path))
    _, f = check_dockerignore(sb, "Dockerfile.prod")
    assert [x.rule for x in f] == ["DI3005"]
    _, f2 = check_dockerignore(sb, ".")
    assert [x.rule for x in f2] == ["DI3001"]  # no plain Dockerfile / .dockerignore in the directory


def test_dockerignore_ignore_comment(tmp_path) -> None:
    got, _ = check(tmp_path, "FROM alpine:3.20\n", "# dockerlint-ignore: DI3002, DI3004\n")
    assert got == []


# ------------------------------------------------------------------ layers


def test_explain_layers_flags_order_problems(tmp_path) -> None:
    text = (
        "FROM python:3.12-slim\nARG BUILD_DATE\nENV BUILD=$BUILD_DATE\nCOPY . /app\nWORKDIR /app\n"
        "RUN pip install --no-cache-dir -r requirements.txt\n"
        "RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*\n"
        "RUN rm -rf /var/cache/x\nRUN chown -R app:app /app\nRUN a\nRUN b\nRUN c\nRUN d\n"
    )
    out = explain_layers(ld_of(tmp_path, text), frozenset())
    assert "DL1009" in out and "L4:" in out
    assert "rm in its own layer" in out
    assert "Recursive chown/chmod" in out
    assert "consecutive RUN" in out
    assert "BUILD_DATE" in out or "BUILD " in out
    assert "large:" in out and "metadata only" in out


def test_explain_layers_volatile_arg_before_install(tmp_path) -> None:
    text = "FROM node:22\nENV GIT_SHA=abc\nCOPY package.json .\nRUN npm ci\n"
    out = explain_layers(ld_of(tmp_path, text), frozenset())
    assert "GIT_SHA" in out and "Move" in out


def test_overview_content(tmp_path) -> None:
    text = (
        "ARG V=3.12\nFROM python:${V} AS b\nRUN true\nFROM gcr.io/distroless/python3-debian12:nonroot@sha256:" + "b" * 64
        + "\nCOPY --from=b /x /x\nEXPOSE 80 443/udp\nWORKDIR /srv\nENTRYPOINT [\"python\"]\nCMD app.py\n"
    )
    out = overview(ld_of(tmp_path, text))
    assert "tag 3.12" in out and "digest sha256:" in out and "80/tcp, 443/udp" in out
    assert 'entrypoint: exec form ["python"]' in out and "shell form `app.py`" in out
    assert "non-root base image" in out and "workdir: /srv" in out and "COPY --from edges" in out


# ------------------------------------------------------------------ fix_preview


def test_fix_preview_diff_is_correct_and_nothing_is_written(tmp_path) -> None:
    text = (
        "FROM debian:12\nRUN apt-get update \\\n    && apt-get install curl\nRUN pip install flask\n"
        "ADD app.py /app/\nCMD python app.py\nMAINTAINER Jane <j@x.io>\nRUN apk add curl\n"
    )
    ld = ld_of(tmp_path, text)
    before = open(ld.path, "rb").read()
    out = fix_preview(ld, frozenset())
    assert open(ld.path, "rb").read() == before
    assert "-    && apt-get install curl" in out
    assert "+    && apt-get install -y --no-install-recommends curl" in out
    assert "+RUN pip install --no-cache-dir flask" in out
    assert "+COPY app.py /app/" in out
    assert '+CMD ["python", "app.py"]' in out
    assert '+LABEL org.opencontainers.image.authors="Jane <j@x.io>"' in out
    assert "+RUN apk add --no-cache curl" in out
    assert "Needs a manual change" in out and "DL1001" not in out.split("Needs a manual change")[0]


def test_fix_preview_result_has_fewer_findings_and_never_adds_new_ones(tmp_path) -> None:
    text = (
        "FROM debian:12\nRUN apt update && apt install curl && apt-get install git\n"
        "RUN apt-get update && apt-get install -y wget\nENTRYPOINT ./run.sh\nCMD [\"a\"]\n"
    )
    ld = ld_of(tmp_path, text)
    before = len(lint(ld.ctx))
    out = fix_preview(ld, frozenset())
    m = re.search(r"Findings: (\d+) before, (\d+) after", out)
    assert m and int(m.group(1)) == before and int(m.group(2)) < before
    added = [ln for ln in out.splitlines() if ln.startswith("+") and not ln.startswith("+++")]
    assert not any(ln.startswith("+ENTRYPOINT") for ln in added)  # CMD exists: shell ENTRYPOINT is not converted
    assert any("apt-get install -y --no-install-recommends git" in ln for ln in added)


def test_fix_preview_keeps_crlf_line_count_and_skips_unsafe(tmp_path) -> None:
    text = "FROM debian:12\r\nRUN apt-get install curl\r\nCMD echo $HOME\r\n"
    ld = ld_of(tmp_path, text)
    out = fix_preview(ld, frozenset())
    assert "+RUN apt-get install -y --no-install-recommends curl" in out
    assert "CMD" in out.split("Needs a manual change")[1]  # $HOME: shell semantics, not auto-converted


def test_fix_preview_nothing_to_do(tmp_path) -> None:
    out = fix_preview(ld_of(tmp_path, "FROM alpine:3.20\nUSER app\nHEALTHCHECK NONE\nCMD [\"x\"]\n"), frozenset())
    assert "no automatic fix applies" in out


def test_fix_apt_lists_cleanup(tmp_path) -> None:
    out = fix_preview(ld_of(tmp_path, "FROM debian:12\nRUN apt-get update && apt-get install -y --no-install-recommends curl\n"), frozenset())
    assert "+RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*" in out


# ------------------------------------------------------------------ suggest_multistage


@pytest.mark.parametrize(
    ("text", "needles"),
    [
        (
            "FROM python:3.11\nWORKDIR /srv\nCOPY requirements.txt .\nRUN pip install -r requirements.txt\nCOPY . .\n"
            "EXPOSE 5000\nCMD [\"python\", \"app.py\"]\n",
            ["FROM python:3.11-slim AS builder", "AS runtime", "COPY --from=builder /opt/venv", "WORKDIR /srv",
             "EXPOSE 5000", 'CMD ["python", "app.py"]', "USER app"],
        ),
        (
            "FROM node:20\nWORKDIR /app\nCOPY package*.json ./\nRUN npm install\nCOPY . .\nRUN npm run build\n"
            "EXPOSE 3000\nCMD [\"node\", \"dist/main.js\"]\n",
            ["FROM node:20-alpine AS build", "RUN npm ci", "npm run build", "COPY --from=build --chown=node:node /app/dist",
             "USER node", 'CMD ["node", "dist/main.js"]'],
        ),
        (
            "FROM golang:1.22\nWORKDIR /go/src/app\nCOPY . .\nRUN go build -o /app ./cmd/api\nCMD [\"/app\"]\n",
            ["FROM golang:1.22 AS build", "go build", "./cmd/api", "gcr.io/distroless/static-debian12:nonroot",
             "COPY --from=build /out/app /app"],
        ),
        (
            "FROM rust:1.80\nWORKDIR /app\nCOPY . .\nRUN cargo build --release\nCMD [\"./target/release/mysvc\"]\n",
            ["FROM rust:1.80 AS build", "distroless/cc-debian12:nonroot", "target/release/mysvc", "touch src/main.rs"],
        ),
    ],
    ids=["python", "node", "go", "rust"],
)
def test_suggest_multistage(tmp_path, text, needles) -> None:
    ld = ld_of(tmp_path, text)
    before = os.listdir(tmp_path)
    out = suggest(ld)
    assert os.listdir(tmp_path) == before  # never writes
    for n in needles:
        assert n in out, n


@pytest.mark.parametrize("lang", ["python", "node", "go", "rust"])
def test_suggested_dockerfiles_lint_clean(tmp_path, lang) -> None:
    sources = {
        "python": "FROM python:3.12\nCOPY requirements.txt .\nRUN pip install -r requirements.txt\nCOPY . .\nCMD [\"python\", \"app.py\"]\n",
        "node": "FROM node:22\nCOPY package.json .\nRUN npm install\nCOPY . .\nRUN npm run build\nCMD [\"node\", \"dist/i.js\"]\n",
        "go": "FROM golang:1.23\nCOPY . .\nRUN go build -o /app .\n",
        "rust": "FROM rust:1.83\nCOPY . .\nRUN cargo build --release\n",
    }
    out = suggest(ld_of(tmp_path, sources[lang]))
    body = out.split("```dockerfile\n")[1].split("```")[0]
    write(str(tmp_path / "suggested" / "Dockerfile"), body)
    ld2 = load_dockerfile(Sandbox(str(tmp_path)), "suggested/Dockerfile")
    findings = [f for f in lint(ld2.ctx) if f.rule != "DL1013"]
    assert findings == [], [(f.rule, f.line, f.message) for f in findings]


def test_suggest_already_multistage_and_unknown(tmp_path) -> None:
    assert "already multi-stage" in suggest(ld_of(tmp_path, "FROM a:1 AS x\nFROM b:1\n"))
    assert "Could not recognise" in suggest(ld_of(tmp_path, "FROM ubuntu:24.04\nRUN echo hi\n"))


def test_parse_then_lint_empty_file_reports_syntax_not_crash(tmp_path) -> None:
    ld = ld_of(tmp_path, "")
    assert lint(Ctx(parse(""))) == []
    assert "No FROM instruction" in overview(ld)


def test_only_upgrade_is_not_flagged_for_recommends(lint_text) -> None:
    got = {f.rule for f in lint_text("FROM debian:12\nRUN apt-get install -y --only-upgrade openssl && rm -rf /var/lib/apt/lists/*\n")}
    assert "DL1004" not in got and "DL1024" not in got
