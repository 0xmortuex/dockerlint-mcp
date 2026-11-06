"""Bad Dockerfiles: each case must raise the expected rule id on the expected line."""

from __future__ import annotations

import pytest

# (case id, Dockerfile text, expected rule, expected line, extra files)
CASES: list[tuple[str, str, str, int, dict[str, str]]] = [
    ("untagged", "FROM python\n", "DL1001", 1, {}),
    ("untagged-2nd-stage", "FROM node:22 AS b\nRUN true\nFROM nginx\n", "DL1001", 3, {}),
    ("untagged-via-arg", "ARG IMG=ubuntu\nFROM ${IMG}\n", "DL1001", 2, {}),
    ("latest", "FROM node:latest\n", "DL1002", 1, {}),
    ("latest-via-arg", "ARG TAG=latest\nFROM alpine:${TAG}\n", "DL1002", 2, {}),
    ("latest-uppercase", "FROM debian:Latest\n", "DL1002", 1, {}),
    ("apt-update-alone", "FROM debian:12\nRUN apt-get update\n", "DL1003", 2, {}),
    ("apt-update-then-echo", "FROM debian:12\nRUN apt-get update && echo done\n", "DL1003", 2, {}),
    (
        "no-recommends",
        "FROM debian:12\nRUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*\n",
        "DL1004", 2, {},
    ),
    (
        "no-recommends-multiline",
        "FROM debian:12\nENV A=1\nRUN apt-get update \\\n    && apt-get install -y curl \\\n"
        "    && rm -rf /var/lib/apt/lists/*\n",
        "DL1004", 3, {},
    ),
    (
        "apt-lists-left",
        "FROM debian:12\nRUN apt-get update && apt-get install -y --no-install-recommends curl\n",
        "DL1005", 2, {},
    ),
    (
        "apt-clean-is-not-lists",
        "FROM debian:12\nRUN apt-get update && apt-get install -y --no-install-recommends curl && apt-get clean\n",
        "DL1005", 2, {},
    ),
    ("pip-cache", "FROM python:3.12\nRUN pip install flask\n", "DL1006", 2, {}),
    ("pip-module-cache", "FROM python:3.12\nRUN python -m pip install -r r.txt\n", "DL1006", 2, {}),
    ("no-user", "FROM python:3.12\nCMD [\"python\"]\n", "DL1007", 1, {}),
    ("user-root", "FROM python:3.12\nRUN true\nUSER root\nCMD [\"python\"]\n", "DL1007", 3, {}),
    (
        "final-stage-no-user",
        "FROM golang:1.23 AS build\nUSER nobody\nRUN true\nFROM alpine:3.20\nCOPY --from=build /a /a\n",
        "DL1007", 4, {},
    ),
    ("add-local", "FROM alpine:3.20\nADD app.py /app/\n", "DL1008", 2, {}),
    ("add-dot", "FROM alpine:3.20\nADD . /app\n", "DL1008", 2, {}),
    (
        "copy-all-before-pip",
        "FROM python:3.12\nCOPY . .\nRUN pip install --no-cache-dir -r requirements.txt\n",
        "DL1009", 2, {},
    ),
    ("copy-all-before-npm", "FROM node:22\nWORKDIR /a\nCOPY . .\nRUN npm ci\n", "DL1009", 3, {}),
    ("copy-all-before-gomod", "FROM golang:1.23\nCOPY . .\nRUN go mod download\n", "DL1009", 2, {}),
    (
        "copy-all-in-second-stage",
        "FROM node:22 AS a\nRUN true\nFROM node:22 AS b\nCOPY . /app\nRUN yarn install\n",
        "DL1009", 4, {},
    ),
    ("env-password", "FROM alpine:3.20\nENV DB_PASSWORD=hunter2\n", "DL1010", 2, {}),
    ("env-legacy-token", "FROM alpine:3.20\nENV API_TOKEN abc123\n", "DL1010", 2, {}),
    ("arg-default-token", "FROM alpine:3.20\nARG GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123\n", "DL1010", 2, {}),
    ("arg-no-default", "FROM alpine:3.20\nARG NPM_TOKEN\n", "DL1010", 2, {}),
    ("env-known-token-prefix", "FROM alpine:3.20\nENV GREETING=AKIAABCDEFGHIJKLMNOP\n", "DL1010", 2, {}),
    ("run-curl-user", "FROM alpine:3.20\nRUN curl -u admin:s3cretpw https://x.example/a\n", "DL1011", 2, {}),
    (
        "run-url-password",
        "FROM alpine:3.20\nRUN git clone https://bob:pa55w0rd@github.com/x/y.git\n",
        "DL1011", 2, {},
    ),
    (
        "run-export-secret",
        "FROM alpine:3.20\nRUN export AWS_SECRET_ACCESS_KEY=abcd1234 && aws s3 ls\n",
        "DL1011", 2, {},
    ),
    (
        "heredoc-secret",
        "FROM alpine:3.20\nRUN <<EOF\necho start\nPASSWORD=abc123 ./setup\nEOF\n",
        "DL1011", 2, {},
    ),
    ("curl-pipe-sh", "FROM alpine:3.20\nRUN curl -sSL https://get.example.sh | sh\n", "DL1012", 2, {}),
    ("wget-pipe-bash", "FROM alpine:3.20\nRUN wget -qO- https://x.example | bash -s -- --yes\n", "DL1012", 2, {}),
    ("no-healthcheck", "FROM alpine:3.20\nUSER nobody\nCMD [\"x\"]\n", "DL1013", 1, {}),
    ("shell-cmd", "FROM alpine:3.20\nCMD python app.py\n", "DL1014", 2, {}),
    ("shell-entrypoint", "FROM alpine:3.20\nENTRYPOINT ./run.sh\n", "DL1014", 2, {}),
    ("json-single-quotes", "FROM alpine:3.20\nCMD ['python', 'app.py']\n", "DL1014", 2, {}),
    ("two-cmd", "FROM alpine:3.20\nCMD [\"a\"]\nRUN true\nCMD [\"b\"]\n", "DL1015", 2, {}),
    ("two-entrypoint", "FROM alpine:3.20\nENTRYPOINT [\"a\"]\nENTRYPOINT [\"b\"]\n", "DL1015", 2, {}),
    ("relative-workdir", "FROM alpine:3.20\nWORKDIR app\n", "DL1016", 2, {}),
    ("relative-workdir-var", "FROM alpine:3.20\nENV DIR=src\nWORKDIR $DIR\n", "DL1016", 3, {}),
    ("cd-in-run", "FROM alpine:3.20\nRUN cd /app && make\n", "DL1017", 2, {}),
    ("sudo", "FROM alpine:3.20\nRUN sudo apk add --no-cache curl\n", "DL1018", 2, {}),
    ("chmod-777", "FROM alpine:3.20\nRUN chmod 777 /data\n", "DL1019", 2, {}),
    ("chmod-rwx", "FROM alpine:3.20\nRUN chmod -R a+rwx /app\n", "DL1019", 2, {}),
    ("copy-chmod-777", "FROM alpine:3.20\nCOPY --chmod=777 a /a\n", "DL1019", 2, {}),
    ("apk-cache", "FROM alpine:3.20\nRUN apk add curl\n", "DL1020", 2, {}),
    ("yum-cache", "FROM centos:7\nRUN yum install -y curl\n", "DL1020", 2, {}),
    (
        "copy-node-modules-dir",
        "FROM node:22\nCOPY . /app\n",
        "DL1021", 2, {"node_modules/x/index.js": "x"},
    ),
    ("copy-git-dir", "FROM node:22\nCOPY . /app\n", "DL1021", 2, {".git/HEAD": "ref: refs/heads/main\n"}),
    ("copy-node-modules-explicit", "FROM node:22\nCOPY node_modules ./node_modules\n", "DL1021", 2, {}),
    ("from-typo", "FROM golang:1.23 AS builder\nRUN true\nFROM alpine:3.20\nCOPY --from=buidler /a /a\n", "DL1022", 4, {}),
    ("from-forward-number", "FROM alpine:3.20\nCOPY --from=1 /a /a\nFROM alpine:3.20\n", "DL1022", 2, {}),
    ("from-later-name", "FROM alpine:3.20\nCOPY --from=later /a /a\nFROM alpine:3.20 AS later\n", "DL1022", 2, {}),
    ("dup-stage", "FROM alpine:3.20 AS x\nFROM alpine:3.20 AS X\n", "DL1023", 2, {}),
    ("apt-no-yes", "FROM debian:12\nRUN apt-get update && apt-get install curl\n", "DL1024", 2, {}),
    ("dnf-no-yes", "FROM fedora:40\nRUN dnf install curl && dnf clean all\n", "DL1024", 2, {}),
    ("apt-upgrade", "FROM debian:12\nRUN apt-get update && apt-get upgrade -y\n", "DL1025", 2, {}),
    ("apt-cli", "FROM debian:12\nRUN apt update && apt install -y curl\n", "DL1026", 2, {}),
    ("maintainer", "FROM alpine:3.20\nMAINTAINER me@example.com\n", "DL1027", 2, {}),
    ("unknown-instruction", "FROM alpine:3.20\nINSTALL curl\n", "DL1028", 2, {}),
    ("instruction-before-from", "RUN echo hi\nFROM alpine:3.20\n", "DL1028", 1, {}),
    ("unclosed-heredoc", "FROM alpine:3.20\nRUN <<EOF\necho hi\n", "DL1028", 2, {}),
    ("from-without-image", "FROM\n", "DL1028", 1, {}),
]


def test_at_least_forty_bad_cases() -> None:
    assert len(CASES) >= 40


@pytest.mark.parametrize("case", CASES, ids=[c[0] for c in CASES])
def test_bad_dockerfile_reports_rule_on_line(lint_text, case) -> None:
    _, text, rule, line, extra = case
    findings = lint_text(text, extra)
    got = [(f.rule, f.line) for f in findings]
    assert (rule, line) in got, f"expected {(rule, line)}, got {got}"


@pytest.mark.parametrize("case", CASES, ids=[c[0] for c in CASES])
def test_every_finding_has_a_concrete_fix_and_no_secret_values(lint_text, case) -> None:
    _, text, _, _, extra = case
    for f in lint_text(text, extra):
        assert f.fix.strip() and f.message.strip()
        for secret in ("hunter2", "abc123", "s3cretpw", "pa55w0rd", "abcd1234", "ghp_abcdefghijkl", "AKIAABCDEFG"):
            assert secret not in f.message and secret not in f.fix
