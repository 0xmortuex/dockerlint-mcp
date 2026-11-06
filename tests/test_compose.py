from __future__ import annotations

import pytest

from conftest import write
from dockerlint_mcp.compose import lint_compose
from dockerlint_mcp.errors import UserError
from dockerlint_mcp.files import Sandbox

GOOD_SERVICE = """    restart: unless-stopped
    healthcheck:
      test: ["CMD", "true"]
"""


def run(tmp_path, text, extra=None, disabled=frozenset()):
    write(str(tmp_path / "compose.yaml"), text)
    for rel, content in (extra or {}).items():
        write(str(tmp_path / rel), content)
    _, findings = lint_compose(Sandbox(str(tmp_path)), "compose.yaml", disabled)
    return [(f.rule, f.line) for f in findings], findings


CASES = [
    ("untagged", "services:\n  web:\n    image: nginx\n" + GOOD_SERVICE, "DC2001", 3),
    ("latest", "services:\n  web:\n    image: redis:latest\n" + GOOD_SERVICE, "DC2002", 3),
    ("latest-default-var", "services:\n  web:\n    image: app:${TAG:-latest}\n" + GOOD_SERVICE, "DC2002", 3),
    ("privileged", "services:\n  web:\n    image: a:1\n    privileged: true\n" + GOOD_SERVICE, "DC2003", 4),
    ("host-network", "services:\n  web:\n    image: a:1\n    network_mode: host\n" + GOOD_SERVICE, "DC2004", 4),
    (
        "docker-sock",
        "services:\n  web:\n    image: a:1\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"
        + GOOD_SERVICE,
        "DC2005", 5,
    ),
    (
        "docker-sock-long-syntax",
        "services:\n  web:\n    image: a:1\n    volumes:\n      - type: bind\n        source: /var/run/docker.sock\n"
        "        target: /s\n" + GOOD_SERVICE,
        "DC2005", 6,
    ),
    (
        "secret-map",
        "services:\n  db:\n    image: postgres:16\n    environment:\n      POSTGRES_PASSWORD: hunter2\n" + GOOD_SERVICE,
        "DC2006", 5,
    ),
    (
        "secret-list",
        "services:\n  db:\n    image: postgres:16\n    environment:\n      - TZ=UTC\n      - API_TOKEN=abc123\n"
        + GOOD_SERVICE,
        "DC2006", 6,
    ),
    (
        "ports-all-interfaces",
        "services:\n  web:\n    image: a:1\n    ports:\n      - \"8080:80\"\n" + GOOD_SERVICE,
        "DC2007", 5,
    ),
    (
        "ports-datastore-explicit",
        "services:\n  db:\n    image: postgres:16\n    ports:\n      - \"0.0.0.0:5432:5432\"\n" + GOOD_SERVICE,
        "DC2007", 5,
    ),
    (
        "ports-long-syntax",
        "services:\n  web:\n    image: a:1\n    ports:\n      - target: 80\n        published: 8080\n"
        + GOOD_SERVICE,
        "DC2007", 5,
    ),
    ("no-restart", "services:\n  web:\n    image: a:1\n    healthcheck:\n      test: [\"CMD\", \"true\"]\n", "DC2008", 2),
    ("no-healthcheck", "services:\n  web:\n    image: a:1\n    restart: always\n", "DC2009", 2),
    (
        "depends-list",
        "services:\n  web:\n    image: a:1\n    depends_on:\n      - db\n" + GOOD_SERVICE
        + "  db:\n    image: b:1\n" + GOOD_SERVICE,
        "DC2010", 4,
    ),
    (
        "depends-no-condition",
        "services:\n  web:\n    image: a:1\n    depends_on:\n      db:\n        restart: true\n" + GOOD_SERVICE
        + "  db:\n    image: b:1\n" + GOOD_SERVICE,
        "DC2010", 5,
    ),
    (
        "bind-root",
        "services:\n  web:\n    image: a:1\n    volumes:\n      - /:/host\n" + GOOD_SERVICE,
        "DC2012", 5,
    ),
    (
        "bind-home",
        "services:\n  web:\n    image: a:1\n    volumes:\n      - ~:/data\n" + GOOD_SERVICE,
        "DC2012", 5,
    ),
    (
        "bind-home-user-dir",
        "services:\n  web:\n    image: a:1\n    volumes:\n      - /home/bob:/data:ro\n" + GOOD_SERVICE,
        "DC2012", 5,
    ),
    ("version-key", "version: \"3.8\"\nservices:\n  web:\n    image: a:1\n" + GOOD_SERVICE, "DC2013", 1),
    (
        "env-file-missing",
        "services:\n  web:\n    image: a:1\n    env_file: .env.prod\n" + GOOD_SERVICE,
        "DC2014", 4,
    ),
    (
        "env-file-list-missing",
        "services:\n  web:\n    image: a:1\n    env_file:\n      - .env\n      - ./missing.env\n" + GOOD_SERVICE,
        "DC2014", 6,
    ),
]


@pytest.mark.parametrize("case", CASES, ids=[c[0] for c in CASES])
def test_bad_compose(tmp_path, case) -> None:
    _, text, rule, line = case
    extra = {".env": "A=1\n"} if "env_file:\n" in text else None
    got, _ = run(tmp_path, text, extra)
    assert (rule, line) in got, got


def test_good_compose_has_zero_findings(tmp_path) -> None:
    text = """name: shop
services:
  web:
    image: ghcr.io/acme/web:1.4.2
    ports:
      - "127.0.0.1:8080:8080"
    environment:
      DATABASE_URL: ${DATABASE_URL}
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
      LOG_LEVEL: info
    env_file:
      - .env
    depends_on:
      db:
        condition: service_healthy
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
    volumes:
      - ./data:/data
      - cache:/cache
  db:
    image: postgres@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready"]
    secrets:
      - db_password
secrets:
  db_password:
    file: ./db_password.txt
volumes:
  cache: {}
"""
    got, _ = run(tmp_path, text, {".env": "DATABASE_URL=x\n"})
    assert got == []


def test_loopback_port_and_optional_env_file_not_flagged(tmp_path) -> None:
    text = (
        "services:\n  web:\n    image: a:1\n    ports:\n      - \"127.0.0.1:8080:80\"\n      - \"[::1]:8081:81\"\n"
        "    env_file:\n      - path: ./nope.env\n        required: false\n" + GOOD_SERVICE
    )
    got, _ = run(tmp_path, text)
    assert got == []


def test_ignore_comment_on_line_and_on_service(tmp_path) -> None:
    text = (
        "services:\n  web:\n    image: nginx\n    # dockerlint-ignore: DC2003\n    privileged: true\n"
        + GOOD_SERVICE
        + "  # dockerlint-ignore: DC2001, DC2008, DC2009\n  other:\n    image: nginx\n"
    )
    got, _ = run(tmp_path, text)
    assert ("DC2003", 5) not in got
    assert ("DC2001", 3) in got  # not ignored: the comment was for a different line
    assert not [g for g in got if g[1] >= 8]  # whole 'other' service suppressed


def test_disable_flag(tmp_path) -> None:
    text = "services:\n  web:\n    image: nginx\n"
    got, _ = run(tmp_path, text, disabled=frozenset({"DC2001", "DC2008", "DC2009"}))
    assert got == []


def test_secret_values_are_never_echoed(tmp_path) -> None:
    text = (
        "services:\n  db:\n    image: postgres:16\n    environment:\n      POSTGRES_PASSWORD: hunter2\n"
        "      OTHER: ghp_abcdefghijklmnopqrstuvwxyz0123\n" + GOOD_SERVICE
    )
    _, findings = run(tmp_path, text)
    assert len([f for f in findings if f.rule == "DC2006"]) == 2
    blob = " ".join(f.message + f.fix for f in findings)
    assert "hunter2" not in blob and "ghp_abcdef" not in blob and "POSTGRES_PASSWORD" in blob


def test_errors_are_actionable(tmp_path) -> None:
    write(str(tmp_path / "bad.yaml"), "services: [unclosed\n")
    sb = Sandbox(str(tmp_path))
    with pytest.raises(UserError, match="not valid YAML"):
        lint_compose(sb, "bad.yaml")
    write(str(tmp_path / "nosvc.yaml"), "foo: bar\n")
    with pytest.raises(UserError, match="no top-level `services:`"):
        lint_compose(sb, "nosvc.yaml")
    with pytest.raises(UserError, match="File not found"):
        lint_compose(sb, "missing.yaml")


def test_env_file_outside_sandbox_is_not_probed(tmp_path) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    write(str(tmp_path / "secret.env"), "A=1\n")
    write(str(root / "compose.yaml"), "services:\n  web:\n    image: a:1\n    env_file: ../secret.env\n" + GOOD_SERVICE)
    _, findings = lint_compose(Sandbox(str(root)), "compose.yaml")
    f = [x for x in findings if x.rule == "DC2014"]
    assert len(f) == 1 and "outside the allowed directory" in f[0].message


def test_yaml_anchors_and_merge_keys(tmp_path) -> None:
    text = (
        "x-common: &common\n  restart: unless-stopped\n  healthcheck:\n    test: [\"CMD\", \"true\"]\n"
        "services:\n  a:\n    <<: *common\n    image: nginx\n  b:\n    <<: *common\n    image: b:1\n"
    )
    got, _ = run(tmp_path, text)
    assert got == [("DC2001", 8)]


def test_deeply_nested_yaml_is_rejected_cleanly(tmp_path) -> None:
    write(str(tmp_path / "deep.yaml"), "services: " + "[" * 20000 + "]" * 20000 + "\n")
    with pytest.raises(UserError):
        lint_compose(Sandbox(str(tmp_path)), "deep.yaml")
