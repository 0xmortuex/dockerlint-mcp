"""False-positive guard: realistic, well-written Dockerfiles must produce ZERO findings."""

from __future__ import annotations

import glob
import os

import pytest

from dockerlint_mcp.files import Sandbox, load_dockerfile
from dockerlint_mcp.ignorecheck import check_dockerignore
from dockerlint_mcp.layers import explain_layers, overview
from dockerlint_mcp.rules import lint

CORPUS = os.path.join(os.path.dirname(__file__), "corpus", "good")
DIRS = sorted(os.path.basename(p) for p in glob.glob(os.path.join(CORPUS, "*")) if os.path.isdir(p))


def test_corpus_has_at_least_fifteen_files() -> None:
    assert len(DIRS) >= 15


@pytest.mark.parametrize("name", DIRS)
def test_good_dockerfile_has_zero_findings(name: str) -> None:
    sb = Sandbox(CORPUS)
    ld = load_dockerfile(sb, os.path.join(name, "Dockerfile"))
    assert ld.ignore_path is not None
    findings = lint(ld.ctx)
    assert findings == [], [(f.rule, f.line, f.message) for f in findings]


@pytest.mark.parametrize("name", DIRS)
def test_good_dockerfile_dockerignore_and_analysis_are_clean(name: str) -> None:
    sb = Sandbox(CORPUS)
    _, di = check_dockerignore(sb, os.path.join(name, "Dockerfile"))
    assert di == [], [(f.rule, f.message) for f in di]
    ld = load_dockerfile(sb, os.path.join(name, "Dockerfile"))
    assert "Order / cache problems: none found." in explain_layers(ld, frozenset())
    assert "Stages (" in overview(ld)
