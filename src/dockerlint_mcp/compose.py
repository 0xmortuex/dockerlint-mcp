"""lint_compose: static checks on docker-compose files.

The YAML is loaded with `yaml.safe_load` (no object construction). safe_load drops
line numbers, so findings are located by scanning the text for the service block and
the key inside it; if a key cannot be found the finding points at the service line.
"""

from __future__ import annotations

import os
import re
from typing import Any

import yaml

from .errors import UserError, shorten
from .files import Sandbox, real_path
from .parser import parse_ignore_ids, parse_image, split_lines
from .rules import RULES, Finding
from .secrets import has_literal, is_secret_name, scan

_DATASTORE_PORTS = {5432, 3306, 6379, 27017, 9200, 11211, 1433, 5984, 9042, 2379}
_BROAD = {"", "/etc", "/root", "/home", "/usr", "/var", "/boot", "/sys", "/proc", "/dev", "/bin",
          "/sbin", "/lib"}
_SEV = {c: RULES[c].severity for c in RULES}


class _Locator:
    def __init__(self, lines: list[str]) -> None:
        self.lines = lines
        self.top: dict[str, int] = {}
        self.services: dict[str, tuple[int, int]] = {}
        for i, ln in enumerate(lines):
            m = re.match(r"^([A-Za-z_][\w.-]*|\"[^\"]+\"|'[^']+')\s*:", ln)
            if m:
                self.top.setdefault(m.group(1).strip("\"'"), i)
        if "services" in self.top:
            self._index_services(self.top["services"])

    def _index_services(self, start: int) -> None:
        indent: int | None = None
        cur: str | None = None
        cur_start = 0
        for i in range(start + 1, len(self.lines)):
            ln = self.lines[i]
            if not ln.strip() or ln.lstrip().startswith("#"):
                continue
            ind = len(ln) - len(ln.lstrip())
            if ind == 0:
                break
            if indent is None:
                indent = ind
            if ind == indent:
                m = re.match(r"^\s*([\"']?)([^\s:\"']+)\1\s*:", ln)
                if m:
                    if cur is not None:
                        self.services[cur] = (cur_start, i - 1)
                    cur, cur_start = m.group(2), i
        if cur is not None:
            end = len(self.lines) - 1
            for j in range(cur_start + 1, len(self.lines)):
                if self.lines[j].strip() and not self.lines[j].startswith((" ", "\t", "#")):
                    end = j - 1
                    break
            self.services[cur] = (cur_start, end)

    def service_line(self, name: str) -> int:
        return self.services.get(name, (self.top.get("services", 0), 0))[0] + 1

    def find(self, service: str, pattern: str) -> int:
        """1-based line of the first match of `pattern` inside the service block."""
        if service not in self.services:
            return self.service_line(service)
        a, b = self.services[service]
        rx = re.compile(pattern)
        for i in range(a, b + 1):
            if rx.search(self.lines[i]):
                return i + 1
        return a + 1

    def key(self, service: str, key: str) -> int:
        return self.find(service, r"^\s*[\"']?" + re.escape(key) + r"[\"']?\s*:")


def _txt(v: Any) -> str:
    """str() of a YAML scalar only. Aliases can share huge nested structures, and str() of those
    would expand them, so containers become the empty string."""
    return str(v) if isinstance(v, (str, int, float)) and not isinstance(v, bool) else ""


def _is_true(v: Any) -> bool:
    return v is True or (isinstance(v, str) and v.strip().lower() in ("true", "yes", "1"))


def _split_port(spec: str) -> tuple[str | None, str | None, str]:
    """-> (host_ip, published, target) for short syntax; target keeps no protocol."""
    s = spec.split("/", 1)[0]
    ip: str | None = None
    if s.startswith("["):
        end = s.index("]") if "]" in s else -1
        if end > 0:
            ip, s = s[1:end], s[end + 1 :].lstrip(":")
    parts = s.split(":")
    if ip is None and len(parts) == 3:
        ip, parts = parts[0], parts[1:]
    if len(parts) == 2:
        return ip, parts[0], parts[1]
    return ip, None, parts[0]


def _first_int(s: str | None) -> int | None:
    if not s:
        return None
    m = re.match(r"\d+", s)
    return int(m.group(0)) if m else None


def _volume_source(v: Any) -> tuple[str | None, bool]:
    """-> (host source, is_bind)."""
    if isinstance(v, dict):
        if v.get("type") == "bind" or (v.get("type") is None and "source" in v):
            src = v.get("source")
            return (_txt(src) if src is not None else None), v.get("type") == "bind"
        return None, False
    if not isinstance(v, str):
        return None, False
    s = v
    if re.match(r"^[A-Za-z]:[\\/]", s):  # Windows drive letter: C:\x:/y
        drive, rest = s[:2], s[2:]
        src = drive + rest.split(":", 1)[0]
        return src, True
    src = s.split(":", 1)[0] if ":" in s else None
    if src is None:
        return None, False
    return src, src.startswith(("/", ".", "~", "$"))


def lint_compose(
    sb: Sandbox, path: str, disabled: frozenset[str] = frozenset()
) -> tuple[str, list[Finding]]:
    real, text = sb.read_text(path)
    if len(text) > 1_000_000:
        raise UserError("compose file is too large to analyze (limit 1 MB)")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise UserError(f"{shorten(path)!r} is not valid YAML: {shorten(str(e), 500)}") from e
    except RecursionError as e:
        raise UserError(f"{shorten(path)!r} is nested too deeply to analyze") from e
    if not isinstance(data, dict) or not isinstance(data.get("services"), dict):
        raise UserError(
            f"{shorten(path)!r} has no top-level `services:` mapping, so it does not look like a compose file."
        )
    lines = split_lines(text)
    loc = _Locator(lines)
    base_dir = os.path.dirname(real)
    out: list[Finding] = []

    def add(rule: str, line: int, message: str, fix: str, severity: str | None = None) -> None:
        if rule in disabled:
            return
        out.append(Finding(rule, severity or _SEV[rule], line, message, fix))

    if "version" in data:
        add("DC2013", loc.top.get("version", 0) + 1,
            "The top-level `version:` key is obsolete; Compose v2 ignores it and warns.",
            "Delete the `version:` line.")

    for name, svc in data["services"].items():
        name = _txt(name)
        if not name:
            continue
        if not isinstance(svc, dict):
            continue
        sline = loc.service_line(name)
        image = svc.get("image")
        if isinstance(image, str) and image.strip():
            img = parse_image(image.strip())
            tag = img.tag or ""
            if "${" in image or image.strip().startswith("$"):
                if re.search(r":-?latest\}|:latest$", image) or "-latest}" in image:
                    add("DC2002", loc.key(name, "image"),
                        f"Service '{name}' defaults its image tag to latest.",
                        "Use a pinned default, e.g. `${TAG:-1.2.3}`.")
            elif not img.tag and not img.digest:
                add("DC2001", loc.key(name, "image"),
                    f"Service '{name}' uses image '{img.name}' with no tag (means :latest).",
                    f"Pin a version: `image: {img.name}:<version>`.")
            elif tag.lower() == "latest" and not img.digest:
                add("DC2002", loc.key(name, "image"),
                    f"Service '{name}' uses {img.name}:latest, which changes without notice.",
                    f"Pin a version: `image: {img.name}:<version>`.")
        if _is_true(svc.get("privileged")):
            add("DC2003", loc.key(name, "privileged"),
                f"Service '{name}' runs privileged: full access to host devices, no isolation.",
                "Remove `privileged: true`; grant only the needed `cap_add:` / `devices:` entries.")
        if _txt(svc.get("network_mode", "")).strip().lower() == "host":
            add("DC2004", loc.key(name, "network_mode"),
                f"Service '{name}' uses the host network: no port isolation, `ports:` is ignored.",
                "Remove `network_mode: host` and publish only the needed ports with `ports:`.")

        # volumes
        vols = svc.get("volumes")
        for v in vols if isinstance(vols, list) else []:
            raw_text = v if isinstance(v, str) else _txt(v.get("source", "")) if isinstance(v, dict) else ""
            src, is_bind = _volume_source(v)
            vline = loc.find(name, re.escape(raw_text.split(":")[0]) if raw_text else r"^\s*volumes\s*:")
            if "docker.sock" in raw_text or "podman.sock" in raw_text or (src and "docker.sock" in src):
                add("DC2005", vline,
                    f"Service '{name}' mounts the container runtime socket: anyone who controls the "
                    "container controls the host.",
                    "Remove the socket mount, or put a restricted socket proxy in front of it "
                    "(read-only, only the API calls needed).")
                continue
            if not is_bind or not src:
                continue
            norm = src.replace("\\", "/").rstrip("/")
            home = re.match(r"^(~|\$\{?HOME\}?)$", norm) or re.match(r"^/(home|Users)/[^/]+$", norm) \
                or norm == "/root"
            if norm == "":
                add("DC2012", vline, f"Service '{name}' bind-mounts the host root `/`.",
                    "Mount only the specific directory the service needs, read-only (`:ro`) if possible.",
                    "error")
            elif norm in _BROAD or home or re.match(r"^[A-Za-z]:$", norm):
                add("DC2012", vline,
                    f"Service '{name}' bind-mounts a broad host directory ({src}).",
                    "Mount a project subdirectory instead, and add `:ro` when the container only reads.")

        # environment
        env = svc.get("environment")
        items: list[tuple[str, Any]] = []
        if isinstance(env, dict):
            items = [(_txt(k), v) for k, v in env.items() if _txt(k)]
        elif isinstance(env, list):
            for entry in env:
                if isinstance(entry, str):
                    k, eq, val = entry.partition("=")
                    items.append((k, val if eq else None))
        for k, val in items:
            if val is None or isinstance(val, bool):
                continue
            sval = _txt(val)
            kind = None
            if is_secret_name(k) and has_literal(sval):
                kind = "hard-coded value"
            else:
                tok = [h.kind for h in scan(sval) if not h.kind.startswith("assignment")]
                if tok:
                    kind = tok[0]
            if kind:
                add("DC2006", loc.find(name, r"^\s*-?\s*[\"']?" + re.escape(k) + r"[\"']?\s*[:=]"),
                    f"Service '{name}' sets {k} to a {kind} in the compose file (value redacted); "
                    "it will be committed and shows up in `docker inspect`.",
                    f"Use `{k}: ${{{k}}}` with a git-ignored .env file, or compose `secrets:` and "
                    f"`{k}_FILE`.")

        # ports
        ports = svc.get("ports")
        for p in ports if isinstance(ports, list) else []:
            ip: str | None
            published: str | None
            if isinstance(p, dict):
                ip = p.get("host_ip")
                published = _txt(p.get("published", "")) or None
                target = _txt(p.get("target", ""))
                shown = f"{published or ''}:{target}"
            else:
                spec = _txt(p)
                if not spec:
                    continue
                ip, published, target = _split_port(spec)
                shown = spec
            if ip and ip not in ("0.0.0.0", "::", ""):
                continue
            port = _first_int(target)
            if isinstance(p, dict):
                pline = loc.find(name, r"target:\s*[\"']?" + re.escape(target) + r"(?!\d)")
            else:
                pline = loc.find(name, re.escape(shown.split("/")[0]))
            store = port in _DATASTORE_PORTS or _first_int(published) in _DATASTORE_PORTS
            where = "explicitly to 0.0.0.0" if ip else "to all interfaces (no host IP given)"
            add("DC2007", pline,
                f"Service '{name}' publishes {shown} {where}; it is reachable from the whole network.",
                f"Bind to loopback unless it must be public: `\"127.0.0.1:{published or port}:{port}\"`.",
                "warning" if store else "info")

        has_restart = "restart" in svc or (
            isinstance(svc.get("deploy"), dict) and "restart_policy" in svc["deploy"]
        )
        if not has_restart and "profiles" not in svc:
            add("DC2008", sline, f"Service '{name}' has no restart policy; it stays down after a crash or reboot.",
                "Add `restart: unless-stopped` (or `restart: \"no\"` to say it is deliberate).")
        hc = svc.get("healthcheck")
        if (hc is None or (isinstance(hc, dict) and not hc.get("disable") and not hc.get("test"))) and (
            "image" in svc or "build" in svc
        ):
            add("DC2009", sline, f"Service '{name}' has no healthcheck.",
                "Add `healthcheck: {test: [\"CMD\", \"curl\", \"-f\", \"http://localhost:8080/health\"], "
                "interval: 30s, timeout: 3s, retries: 3}` or rely on one baked into the image.")

        dep = svc.get("depends_on")
        if isinstance(dep, list) and dep:
            add("DC2010", loc.key(name, "depends_on"),
                f"Service '{name}' uses list-form depends_on, which waits only for the container to "
                "start, not to be ready.",
                "Use the map form: `depends_on: {db: {condition: service_healthy}}` and give `db` a healthcheck.")
        elif isinstance(dep, dict):
            for dname, dval in dep.items():
                if not isinstance(dval, dict) or "condition" not in dval:
                    add("DC2010", loc.find(name, r"^\s*[\"']?" + re.escape(_txt(dname)) + r"[\"']?\s*:"),
                        f"Service '{name}' depends on '{dname}' without a condition (waits for start only).",
                        f"Add `condition: service_healthy` (and a healthcheck on '{dname}').")

        # env_file
        ef = svc.get("env_file")
        entries: list[tuple[str, bool]] = []
        if isinstance(ef, str):
            entries = [(ef, True)]
        elif isinstance(ef, list):
            for item in ef:
                if isinstance(item, str):
                    entries.append((item, True))
                elif isinstance(item, dict) and isinstance(item.get("path"), str):
                    entries.append((item["path"], item.get("required", True) is not False))
        for rel, required in entries:
            if not required or "$" in rel:
                continue
            target_path = real_path(os.path.join(base_dir, rel))
            eline = loc.find(name, re.escape(rel))
            if not sb.contains(target_path):
                add("DC2014", eline,
                    f"Service '{name}' env_file '{rel}' points outside the allowed directory, so it "
                    "was not checked.",
                    "Keep env files inside the project, or start the server with a wider --dir.")
            elif not os.path.isfile(target_path):
                add("DC2014", eline,
                    f"Service '{name}' env_file '{rel}' does not exist (looked in {base_dir}); "
                    "`docker compose up` will fail.",
                    f"Create the file (e.g. copy it from an example) or mark it optional: "
                    f"`- path: {rel}` with `required: false`.")

    # ignore comments: a comment above/at a line suppresses findings there; above a
    # service header it suppresses the whole service.
    line_ign: dict[int, set[str]] = {}
    range_ign: list[tuple[int, int, set[str]]] = []
    pending: set[str] = set()
    for i, ln in enumerate(lines):
        st = ln.strip()
        if st.startswith("#"):
            pending |= parse_ignore_ids(st)
            continue
        if not st:
            continue
        ids = set(pending)
        if " #" in ln:
            ids |= parse_ignore_ids("#" + ln.split(" #", 1)[1])
        pending = set()
        if ids:
            line_ign.setdefault(i + 1, set()).update(ids)
            for a, b in loc.services.values():
                if a == i:
                    range_ign.append((a + 1, b + 1, ids))
                    break
    kept: list[Finding] = []
    for f in out:
        if f.rule in line_ign.get(f.line, set()):
            continue
        if any(a <= f.line <= b and f.rule in ids for a, b, ids in range_ign):
            continue
        kept.append(f)
    order = {"error": 0, "warning": 1, "info": 2}
    kept.sort(key=lambda f: (f.line, order[f.severity], f.rule))
    return real, kept
