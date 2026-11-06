# dockerlint-mcp

An MCP server that lets an AI **lint and explain Dockerfiles and docker-compose files statically**:
rule IDs, severities, line numbers and a concrete fix for every finding. It never builds or runs
anything, needs no Docker daemon and no external binary.

**How it differs from what exists.** The Dockerfile-lint MCP servers I could find
([Docker CI Lint MCP](https://mcpize.com/mcp/docker-ci-lint-mcp), and hosted linters on
[Apify](https://apify.com/perryay/dockerfile-linter-checker/api/mcp)) wrap a single linter or a
hosted service, and Hadolint-based setups need the `hadolint` binary. This server is pure Python (`mcp` +
`pyyaml`), runs fully offline, and covers the whole build context in one place: Dockerfile rules,
compose rules, `.dockerignore` matching that follows Docker's real rules (and checks it against what your
`COPY` lines need), layer/cache-order analysis, multi-stage rewrite proposals, and a unified-diff
preview of the safe automatic fixes. Secret values are never echoed back to the model, and file access
is sandboxed to one directory.

## Install

Claude Code:

```bash
claude mcp add dockerlint -- uvx dockerlint-mcp --dir .
```

Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "dockerlint": {
      "command": "uvx",
      "args": ["dockerlint-mcp", "--dir", "C:\\path\\to\\your\\project"]
    }
  }
}
```

Without uv: `pip install dockerlint-mcp`, then run `dockerlint-mcp --dir /path/to/project`.

| Flag | Meaning |
|------|---------|
| `--dir PATH` | Only files inside this directory can be read (default: the current directory). |
| `--disable IDS` | Comma-separated rule ids to turn off, e.g. `--disable DL1013,DC2008`. Repeatable. |

You can also silence a single finding in the file itself with a comment on the line above:

```dockerfile
# dockerlint-ignore: DL1003, DL1005
RUN apt-get update
```

In compose files, put the comment above a line, or above a service name to cover the whole service.
In a `.dockerignore`, `# dockerlint-ignore: DI3002` anywhere turns that rule off for the file.

## Tools

| Tool | What it does |
|------|--------------|
| `dockerfile_overview(path)` | Stages with base image tag/digest, layer count, exposed ports, final user, workdir, ENTRYPOINT/CMD (exec vs shell form), COPY --from edges. |
| `lint_dockerfile(path)` | 28 rules (DL1001-DL1028). Each finding: rule id, severity, instruction line, explanation, concrete fix. |
| `explain_layers(path)` | Which instructions create layers, heuristic size hints, and ORDER problems that bust the cache or bloat the image. |
| `lint_compose(path)` | 13 compose rules (DC2001-DC2014) with line numbers. |
| `check_dockerignore(path)` | Missing file, patterns that do not exclude `.git` / `node_modules` / `.env`, nested directories the root-anchored patterns miss, and patterns that exclude files your `COPY` needs. |
| `suggest_multistage(path)` | A multi-stage rewrite as text for common Python, Node, Go and Rust patterns. Never writes a file. |
| `fix_preview(path)` | Unified diff of the safe automatic fixes. Never writes a file; lists what needs a manual change. |

`path` is a file (or a directory containing a `Dockerfile`), relative to `--dir` or absolute inside it.
The line number of a Dockerfile finding is the first line of the instruction.

## Try asking

- "Lint the Dockerfile and fix everything that is safe, then show me what is left."
- "Why does my Docker build re-install dependencies on every code change?" (explain_layers)
- "Is my .dockerignore protecting me? Does it exclude anything my COPY lines need?"
- "Review docker-compose.yml for anything dangerous before I deploy it."
- "Turn this single-stage Python Dockerfile into a multi-stage one."
- "Which layers make my image big?"

## Rules

| ID | Severity | Rule |
|----|----------|------|
| DL1001 | warning | base image has no version tag or digest |
| DL1002 | warning | base image uses the :latest tag |
| DL1003 | warning | apt-get update without install in the same RUN |
| DL1004 | warning | apt-get install without --no-install-recommends |
| DL1005 | warning | apt package lists are left in the layer |
| DL1006 | warning | pip install without --no-cache-dir |
| DL1007 | warning | container runs as root |
| DL1008 | warning | ADD used where COPY would do |
| DL1009 | warning | COPY . before installing dependencies busts the build cache |
| DL1010 | error | secret stored in ENV or ARG |
| DL1011 | error | secret in a RUN / COPY / other instruction |
| DL1012 | warning | piping curl/wget into a shell |
| DL1013 | info | no HEALTHCHECK |
| DL1014 | warning | shell-form ENTRYPOINT/CMD (signals are not forwarded) |
| DL1015 | warning | multiple CMD / ENTRYPOINT / HEALTHCHECK in one stage |
| DL1016 | warning | WORKDIR is not an absolute path |
| DL1017 | warning | cd inside RUN |
| DL1018 | warning | sudo inside a Dockerfile |
| DL1019 | warning | world-writable permissions (chmod 777) |
| DL1020 | warning | package manager cache is left in the layer (apk, yum, dnf) |
| DL1021 | warning | COPY would send node_modules or .git into the image |
| DL1022 | error | COPY --from refers to an unknown or later stage |
| DL1023 | error | duplicate stage name |
| DL1024 | error | package install without a non-interactive flag (-y) |
| DL1025 | warning | apt-get upgrade makes the build non-reproducible |
| DL1026 | warning | apt CLI used in a script; use apt-get |
| DL1027 | info | MAINTAINER is deprecated |
| DL1028 | error | Dockerfile syntax problem |
| DC2001 | warning | compose image has no version tag |
| DC2002 | warning | compose image uses :latest |
| DC2003 | error | privileged container |
| DC2004 | warning | host network mode |
| DC2005 | error | docker.sock mounted into a container |
| DC2006 | error | secret in environment |
| DC2007 | info / warning | published port binds all interfaces (warning for databases and caches) |
| DC2008 | info | no restart policy |
| DC2009 | info | no healthcheck |
| DC2010 | info | depends_on without a health condition |
| DC2012 | warning / error | broad host directory bind mount (`/` is an error) |
| DC2013 | info | obsolete top-level `version:` key |
| DC2014 | error | env_file does not exist |
| DI3001 | warning | no .dockerignore |
| DI3002 | warning | .dockerignore does not exclude .git |
| DI3003 | warning | .dockerignore does not exclude node_modules |
| DI3004 | warning | .dockerignore does not exclude .env files |
| DI3005 | error | .dockerignore excludes a file the Dockerfile copies |
| DI3006 | info | node_modules/.git in a subdirectory is not excluded |

## How it works and what it cannot know

- The Dockerfile parser is hand-written: parser directives, line continuations (with comments and
  blank lines inside), heredocs, JSON vs shell form, `--mount`/`--chown`/`--from` flags, `ONBUILD`,
  multi-stage names, and `ARG`/`ENV` expansion in `FROM`/`WORKDIR`.
- Rules look at parsed commands, not raw text, so `echo "apt-get update"` is not a finding.
- The build context is assumed to be the Dockerfile's directory. If you build with a different context
  (`docker build -f docker/Dockerfile .`) the context-dependent checks (DL1021, `check_dockerignore`) are
  looking at the wrong directory.
- Sizes in `explain_layers` are heuristics from the commands, not measurements.
- A base image that already runs unprivileged (for example a custom image) looks like root to DL1007;
  silence it with `# dockerlint-ignore: DL1007`.
- Compose findings are located by scanning the YAML text; if a key cannot be found the finding points at
  the service line. Only a single file is read (no `extends`, `include`, or `-f` merging, no `.env`
  interpolation).

## Security

- **Read-only and static.** Nothing is built, run, pulled or written. `suggest_multistage` and
  `fix_preview` return text; applying it is up to you.
- **Directory sandbox.** Every path is resolved (symlinks included) and must stay inside `--dir`; `..`
  traversal, absolute paths outside it and symlink escapes are refused. `env_file` paths that point
  outside it are reported without being probed.
- **Secrets are never echoed.** Findings name the variable (`DB_PASSWORD`) or the kind of secret
  ("GitHub token"), not its value. Instruction text shown by `dockerfile_overview`, `explain_layers` and
  `fix_preview` is redacted the same way. (The file on disk is of course unchanged.)
- **Safe parsing.** Compose files are loaded with `yaml.safe_load` only; files over 2 MB are refused;
  nested or alias-heavy YAML cannot make the server expand data without bound.
- The server makes no network requests.

## Development

```bash
uv sync --extra test
uv run --python 3.12 pytest
uv run ruff check src tests
uv run mypy --strict src
```

The tests use real files in temporary directories and launch the installed server over stdio. The
corpus in `tests/corpus/good` holds 16 realistic Dockerfiles that must produce zero findings.

There is a build-it-yourself tutorial in
[dockerlint-mcp-the-hard-way](https://github.com/0xmortuex/dockerlint-mcp-the-hard-way).

MIT licensed.
