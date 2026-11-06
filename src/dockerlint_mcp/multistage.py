"""suggest_multistage: propose a multi-stage Dockerfile as text. Never writes files."""

from __future__ import annotations

import json
import re

from .files import LoadedDockerfile
from .parser import Dockerfile, Instruction
from .secrets import redact_line
from .shell import split_words

_DEFAULT_VERSIONS = {"python": "3.12", "node": "22", "go": "1.23", "rust": "1.83"}
_SAFE_WORD = re.compile(r"^[\w./:=@%+,-]+$")


def _tag_version(df: Dockerfile, image_names: tuple[str, ...]) -> str | None:
    for st in df.stages:
        if st.image is not None and st.image.name.rsplit("/", 1)[-1] in image_names and st.image.tag:
            m = re.match(r"^v?(\d+(?:\.\d+){0,2})", st.image.tag)
            if m:
                return m.group(1)
    return None


def _all_commands(df: Dockerfile) -> list[tuple[Instruction, str, list[str]]]:
    out = []
    for ins in df.instructions:
        if ins.cmd == "RUN" and not ins.onbuild:
            for c in ins.commands():
                out.append((ins, c.name, c.args))
    return out


def detect(df: Dockerfile) -> str | None:
    bases = {st.image.name.rsplit("/", 1)[-1] for st in df.stages if st.image}
    cmds = {n for _, n, _ in _all_commands(df)}
    if bases & {"python", "pypy"} or cmds & {"pip", "poetry", "uv", "pipenv"}:
        return "python"
    if bases & {"node", "bun"} or cmds & {"npm", "yarn", "pnpm"}:
        return "node"
    if "golang" in bases or "go" in cmds:
        return "go"
    if "rust" in bases or "cargo" in cmds:
        return "rust"
    return None


def _start_cmd(df: Dockerfile, key: str) -> Instruction | None:
    last = None
    for ins in df.stages[-1].instructions:
        if ins.cmd == key and not ins.onbuild:
            last = ins
    return last


def _render_cmd(ins: Instruction | None, kind: str, default: list[str]) -> list[str]:
    """Render CMD/ENTRYPOINT in exec form where that is safe."""
    if ins is None:
        return [f"{kind} {json.dumps(default)}"]
    if ins.json_form:
        return [f"{kind} {json.dumps(ins.argv)}"]
    words = split_words(ins.args)
    if words and all(_SAFE_WORD.match(w) for w in words):
        return [f"{kind} {json.dumps(words)}"]
    return [
        f"# The original {kind} uses shell features; kept as is. Prefer exec form (see DL1014).",
        f"{kind} {ins.args}",
    ]


def _ports(df: Dockerfile) -> list[str]:
    ports: list[str] = []
    for ins in df.instructions:
        if ins.cmd == "EXPOSE" and not ins.onbuild:
            ports += (ins.expanded or ins.args).split()
    return ports


def _workdir(df: Dockerfile) -> str:
    for ins in reversed(df.instructions):
        if ins.cmd == "WORKDIR" and not ins.onbuild:
            p = (ins.expanded or ins.args).strip()
            if p.startswith("/") and "$" not in p:
                return p
    return "/app"


def _python(df: Dockerfile, ld: LoadedDockerfile) -> tuple[str, list[str]]:
    ver = _tag_version(df, ("python",)) or _DEFAULT_VERSIONS["python"]
    alpine = any(st.image and "alpine" in (st.image.tag or "") for st in df.stages)
    variant = "alpine" if alpine else "slim"
    img = f"python:{ver}-{variant}"
    wd = _workdir(df)
    text = df.stages and "\n".join(i.args for i in df.instructions)
    uses_req = "requirements" in (text or "") or not re.search(r"poetry|pyproject|pip install \.", text or "")
    user_cmd = (
        "RUN adduser -S -u 10001 app" if alpine
        else "RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app"
    )
    lines = [
        "# syntax=docker/dockerfile:1",
        f"FROM {img} AS builder",
        "ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1",
        f"WORKDIR {wd}",
        "RUN python -m venv /opt/venv",
        'ENV PATH="/opt/venv/bin:$PATH"',
    ]
    if uses_req:
        lines += ["COPY requirements.txt ./", "RUN pip install -r requirements.txt"]
    else:
        lines += ["COPY . .", "RUN pip install ."]
    lines += [
        "",
        f"FROM {img} AS runtime",
        'ENV PATH="/opt/venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1',
        f"WORKDIR {wd}",
        user_cmd,
        "COPY --from=builder /opt/venv /opt/venv",
    ]
    if uses_req:
        lines.append("COPY --chown=app:app . .")
    lines.append("USER app")
    for p in _ports(df):
        lines.append(f"EXPOSE {p}")
    lines.append("# Add a HEALTHCHECK for your service here (or HEALTHCHECK NONE).")
    lines += _render_cmd(_start_cmd(df, "ENTRYPOINT"), "ENTRYPOINT", []) if _start_cmd(df, "ENTRYPOINT") else []
    lines += _render_cmd(_start_cmd(df, "CMD"), "CMD", ["python", "app.py"])
    notes = [
        "The builder stage holds pip, build tools and caches; only the finished virtualenv "
        "(/opt/venv) is copied into the runtime stage.",
        "If a package needs compilers or system libraries, install them in the builder stage "
        "(`apt-get install -y --no-install-recommends build-essential`) and only the runtime "
        "libraries (e.g. libpq5) in the runtime stage.",
    ]
    if not uses_req:
        notes.append("This template installs the project itself with `pip install .`; the runtime "
                     "stage then needs only the virtualenv.")
    return "\n".join(lines), notes


def _node(df: Dockerfile, ld: LoadedDockerfile) -> tuple[str, list[str]]:
    ver = _tag_version(df, ("node",)) or _DEFAULT_VERSIONS["node"]
    major = ver.split(".")[0]
    img = f"node:{major}-alpine"
    names = {n for _, n, _ in _all_commands(df)}
    text = "\n".join(i.args for i in df.instructions)
    if "pnpm" in names:
        pm = "pnpm"
    elif "yarn" in names or "yarn.lock" in text:
        pm = "yarn"
    else:
        pm = "npm"
    has_build = bool(re.search(r"\b(npm run build|yarn build|pnpm (run )?build|tsc|next build|vite build)\b", text))
    ports = _ports(df)
    manifests = {"npm": "package.json package-lock.json", "yarn": "package.json yarn.lock",
                 "pnpm": "package.json pnpm-lock.yaml"}[pm]
    full_install = {"npm": "npm ci", "yarn": "yarn install --frozen-lockfile",
                    "pnpm": "corepack enable && pnpm install --frozen-lockfile"}[pm]
    prod_install = {"npm": "npm ci --omit=dev && npm cache clean --force",
                    "yarn": "yarn install --frozen-lockfile --production && yarn cache clean",
                    "pnpm": "corepack enable && pnpm install --frozen-lockfile --prod"}[pm]
    build_cmd = {"npm": "npm run build", "yarn": "yarn build", "pnpm": "pnpm run build"}[pm]
    wd = _workdir(df)
    lines = ["# syntax=docker/dockerfile:1", f"FROM {img} AS build", f"WORKDIR {wd}", f"COPY {manifests} ./"]
    notes: list[str] = []
    if has_build:
        lines += [f"RUN {full_install}", "COPY . .", f"RUN {build_cmd}", "",
                  f"FROM {img} AS runtime", "ENV NODE_ENV=production", f"WORKDIR {wd}",
                  f"COPY {manifests} ./", f"RUN {prod_install}",
                  f"COPY --from=build --chown=node:node {wd}/dist ./dist"]
        notes.append("Dev dependencies and sources stay in the build stage; the runtime stage has "
                     "production dependencies and the built output only. Change `dist` if your build "
                     "writes elsewhere (build/, .next/, out/).")
        default = ["node", "dist/index.js"]
    else:
        lines += [f"RUN {prod_install}", "", f"FROM {img} AS runtime", "ENV NODE_ENV=production",
                  f"WORKDIR {wd}", f"COPY --from=build {wd}/node_modules ./node_modules",
                  "COPY --chown=node:node . ."]
        notes.append("No build step was detected, so the build stage only installs production "
                     "dependencies and the runtime stage adds your sources. The gain is smaller here; "
                     "multi-stage pays off most when there is a compile/bundle step.")
        default = ["node", "server.js"]
    if pm == "npm":
        notes.append("`npm ci` needs a package-lock.json; use `npm install` instead if the project has none.")
    lines.append("USER node")
    for p in ports:
        lines.append(f"EXPOSE {p}")
    lines.append("# Add a HEALTHCHECK for your service here (or HEALTHCHECK NONE).")
    lines += _render_cmd(_start_cmd(df, "CMD"), "CMD", default)
    return "\n".join(lines), notes


def _go(df: Dockerfile, ld: LoadedDockerfile) -> tuple[str, list[str]]:
    ver = _tag_version(df, ("golang",)) or _DEFAULT_VERSIONS["go"]
    text = "\n".join(i.args for i in df.instructions)
    m = re.search(r"go build[^\n&|;]*?(\./[\w./-]+)\s*$|go build[^\n&|;]*?\s(\./cmd/[\w./-]+)", text, re.M)
    pkg = (m.group(1) or m.group(2)) if m else "."
    lines = [
        "# syntax=docker/dockerfile:1",
        f"FROM golang:{ver} AS build",
        "WORKDIR /src",
        "COPY go.mod go.sum ./",
        "RUN go mod download",
        "COPY . .",
        f'RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/app {pkg}',
        "",
        "FROM gcr.io/distroless/static-debian12:nonroot",
        "COPY --from=build /out/app /app",
        "USER nonroot:nonroot",
    ]
    for p in _ports(df):
        lines.append(f"EXPOSE {p}")
    lines.append("# Distroless has no shell or curl: use HEALTHCHECK NONE or a health flag in your binary.")
    lines += _render_cmd(_start_cmd(df, "ENTRYPOINT"), "ENTRYPOINT", ["/app"])
    notes = [
        "The Go toolchain (~800 MB) stays in the build stage; the runtime image is a static binary "
        "on distroless (a few MB, no shell, runs as non-root).",
        "CGO_ENABLED=0 makes a fully static binary. If you need cgo, use "
        "`gcr.io/distroless/cc-debian12:nonroot` and drop CGO_ENABLED=0.",
    ]
    return "\n".join(lines), notes


def _rust(df: Dockerfile, ld: LoadedDockerfile) -> tuple[str, list[str]]:
    ver = _tag_version(df, ("rust",)) or _DEFAULT_VERSIONS["rust"]
    text = "\n".join(i.args for i in df.instructions)
    m = re.search(r"target/release/([A-Za-z0-9_-]+)", text) or re.search(r"--bin\s+([A-Za-z0-9_-]+)", text)
    binary = m.group(1) if m else "app"
    lines = [
        "# syntax=docker/dockerfile:1",
        f"FROM rust:{ver} AS build",
        "WORKDIR /src",
        "COPY Cargo.toml Cargo.lock ./",
        "# Build the dependencies once against a dummy main so they stay cached.",
        'RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src',
        "COPY src ./src",
        "RUN touch src/main.rs && cargo build --release",
        "",
        "FROM gcr.io/distroless/cc-debian12:nonroot",
        f"COPY --from=build /src/target/release/{binary} /app",
        "USER nonroot:nonroot",
    ]
    for p in _ports(df):
        lines.append(f"EXPOSE {p}")
    lines.append("# Distroless has no shell or curl: use HEALTHCHECK NONE or a health flag in your binary.")
    lines += _render_cmd(_start_cmd(df, "ENTRYPOINT"), "ENTRYPOINT", ["/app"])
    notes = [
        "The Rust toolchain and target/ directory (gigabytes) stay in the build stage.",
        "Dependencies are compiled in their own layer, so editing src/ does not rebuild them."
        + ("" if m else " The binary name was not found in your Dockerfile; replace `app` with the "
           "[[bin]] / package name."),
        "For a fully static binary use the musl target with `gcr.io/distroless/static-debian12:nonroot`.",
    ]
    return "\n".join(lines), notes


def suggest(ld: LoadedDockerfile) -> str:
    df = ld.df
    if not df.stages:
        return "No FROM instruction found; there is nothing to restructure."
    if len(df.stages) > 1:
        names = ", ".join(s.name or str(s.index) for s in df.stages)
        return (
            f"This Dockerfile is already multi-stage ({len(df.stages)} stages: {names}). "
            "Run lint_dockerfile and explain_layers for improvements within the stages."
        )
    lang = detect(df)
    if lang is None:
        return (
            "Could not recognise a Python, Node, Go or Rust build in this Dockerfile (looked at the "
            "base image and the RUN commands), so no rewrite is proposed. The general pattern: do "
            "compilation and dependency installation in a `FROM <full image> AS build` stage and "
            "`COPY --from=build` only the results into a small final stage."
        )
    builders = {"python": _python, "node": _node, "go": _go, "rust": _rust}
    body, notes = builders[lang](df, ld)
    head = redact_line(" ".join(df.stages[0].base.split()))
    out = [
        f"Detected a {lang} project (single stage, base {head}). Proposed multi-stage Dockerfile "
        "(text only; nothing was written):",
        "",
        "```dockerfile",
        body,
        "```",
        "",
        "Why this is better:",
    ]
    out += [f"- {n}" for n in notes]
    out.append("- Versions come from your base image tag when it had one; otherwise a current default "
               "was used. Pin the exact version you test with.")
    out.append("- Check the result with lint_dockerfile after you save it.")
    return "\n".join(out)
