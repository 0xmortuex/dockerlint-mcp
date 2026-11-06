"""Sandboxed file access and loading.

Every path an agent supplies is resolved (symlinks included) and must stay inside
the --dir root. Files are size-capped and must be UTF-8.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from .dockerignore import IgnoreMatcher
from .errors import UserError, shorten
from .parser import Dockerfile, parse
from .rules import Ctx

MAX_BYTES = 2_000_000


def _inside(root: str, path: str) -> bool:
    r, p = os.path.normcase(root), os.path.normcase(path)
    if p == r:
        return True
    try:
        return os.path.commonpath([r, p]) == r
    except ValueError:  # different drives on Windows
        return False


def real_path(path: str) -> str:
    """os.path.realpath, but a path the OS cannot resolve is a UserError. Python 3.10 on Windows raises a bare
    ValueError ("path too long") where newer versions raise OSError or return the path."""
    try:
        return os.path.realpath(path)
    except (OSError, ValueError) as e:
        raise UserError(f"{shorten(path)!r} cannot be resolved as a path ({type(e).__name__}: {shorten(str(e))})") from e


class Sandbox:
    def __init__(self, root: str) -> None:
        self.root = real_path(root)
        if not os.path.isdir(self.root):
            raise UserError(f"--dir {root!r} is not a directory")

    def resolve(self, path: str) -> str:
        if not path or "\x00" in path:
            raise UserError("path is empty or contains a NUL byte")
        cand = path if os.path.isabs(path) else os.path.join(self.root, path)
        real = real_path(cand)
        if not _inside(self.root, real):
            raise UserError(
                f"{shorten(path)!r} is outside the directory this server is allowed to read ({self.root}). "
                "Start the server with --dir pointing at your project."
            )
        return real

    def contains(self, candidate: str) -> bool:
        return _inside(self.root, real_path(candidate))

    def read_text(self, path: str) -> tuple[str, str]:
        real = self.resolve(path)
        if not os.path.exists(real):
            raise UserError(
                f"File not found: {shorten(path)!r}. Relative paths are resolved against {self.root}."
            )
        if os.path.isdir(real):
            raise UserError(f"{shorten(path)!r} is a directory, not a file.")
        size = os.path.getsize(real)
        if size > MAX_BYTES:
            raise UserError(f"{shorten(path)!r} is {size} bytes; the limit is {MAX_BYTES}.")
        with open(real, "rb") as fh:
            raw = fh.read(MAX_BYTES + 1)
        try:
            return real, raw.decode("utf-8-sig")
        except UnicodeDecodeError as e:
            raise UserError(f"{shorten(path)!r} is not valid UTF-8 text ({e.reason} at byte {e.start}).") from e


@dataclass
class LoadedDockerfile:
    path: str  # real path
    text: str
    df: Dockerfile
    ctx: Ctx
    ignore_path: str | None


def find_ignore_file(dockerfile_real: str) -> str | None:
    d, name = os.path.split(dockerfile_real)
    for cand in (os.path.join(d, name + ".dockerignore"), os.path.join(d, ".dockerignore")):
        if os.path.isfile(cand):
            return cand
    return None


def load_dockerfile(sb: Sandbox, path: str) -> LoadedDockerfile:
    real = sb.resolve(path)
    if os.path.isdir(real):
        real = sb.resolve(os.path.join(real, "Dockerfile"))
    real, text = sb.read_text(real)
    df = parse(text)
    ignore: IgnoreMatcher | None = None
    ignore_path = find_ignore_file(real)
    if ignore_path is not None:
        _, itext = sb.read_text(ignore_path)
        ignore = IgnoreMatcher(itext)
    ctx = Ctx(df=df, context_dir=os.path.dirname(real), ignore=ignore)
    return LoadedDockerfile(real, text, df, ctx, ignore_path)
