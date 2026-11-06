# Changelog

## 0.1.0

First release.

- Seven tools: `dockerfile_overview`, `lint_dockerfile`, `explain_layers`, `lint_compose`,
  `check_dockerignore`, `suggest_multistage`, `fix_preview`.
- 28 Dockerfile rules (DL1001-DL1028), 13 compose rules (DC2001-DC2014), 6 `.dockerignore` rules
  (DI3001-DI3006).
- Hand-written Dockerfile parser: directives, continuations, heredocs, JSON/shell form, flags,
  ONBUILD, multi-stage, ARG/ENV expansion.
- `# dockerlint-ignore:` comments and `--disable` flag; `--dir` sandbox.
- Secret values are redacted in every output.
