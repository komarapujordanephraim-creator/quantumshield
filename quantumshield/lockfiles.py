"""Lockfile discovery: resolved versions and transitive dependencies.

Manifests (see ``deps.py``) only list the packages a project asks for
directly. Lockfiles list everything that actually gets installed, including
packages pulled in by other packages, with exact versions. That closes the
two gaps of manifest scanning:

* **Transitive dependencies**: a project can depend on ``elliptic`` or
  ``pycrypto`` without ever naming it.
* **Versions**: each finding says which version is locked.

Supported lockfiles: package-lock.json, npm-shrinkwrap.json, yarn.lock
(classic and Berry), pnpm-lock.yaml, poetry.lock, uv.lock, pdm.lock,
Pipfile.lock, Cargo.lock, go.sum, composer.lock, Gemfile.lock and
gradle.lockfile.

Parsing is line based and dependency free, so it works offline and never
executes anything from the project.
"""

from __future__ import annotations

import json
import re
from pathlib import PurePosixPath
from typing import Dict, Iterator, List, Optional, Tuple

from .deps import DEP_RULES, DepRule

# Lockfile name (lower case) -> ecosystem
LOCKFILES: Dict[str, str] = {
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "poetry.lock": "pypi",
    "uv.lock": "pypi",
    "pdm.lock": "pypi",
    "pipfile.lock": "pypi",
    "cargo.lock": "cargo",
    "go.sum": "go",
    "composer.lock": "composer",
    "gemfile.lock": "rubygems",
    "gradle.lockfile": "maven",
}

# Lockfiles are often large; allow more than normal source files.
MAX_LOCKFILE_BYTES = 20_000_000

TRANSITIVE_NOTE = (
    " Found only in the lockfile, so another package pulls it in: "
    "the project never names it directly."
)

Entry = Tuple[str, str, int]  # (package, version, line number)


def is_lockfile(name: str) -> bool:
    return name.lower() in LOCKFILES


def _norm(eco: str, name: str) -> str:
    name = name.strip().lower()
    if eco == "pypi":
        return re.sub(r"[-_.]+", "-", name)
    return name


def _matches(rule: DepRule, eco: str, name: str) -> bool:
    if rule.ecosystem != eco:
        return False
    pkg = _norm(eco, rule.package)
    if eco == "go":
        # module paths: allow /vN and sub-packages
        return name == pkg or name.startswith(pkg + "/")
    if eco == "maven":
        # gradle.lockfile gives artifact ids such as bcprov-jdk18on
        return name.startswith(pkg)
    return name == pkg


# ---------------------------------------------------------------- parsers

def _line_of(lines: List[str], needle: str, start: int = 0) -> int:
    for i in range(start, len(lines)):
        if needle in lines[i]:
            return i + 1
    return 1


def _toml_packages(lines: List[str]) -> Iterator[Entry]:
    """poetry.lock, uv.lock, pdm.lock, Cargo.lock: [[package]] blocks."""
    name, ver, at = None, "", 0
    for i, line in enumerate(lines, start=1):
        s = line.strip()
        if s == "[[package]]":
            if name:
                yield name, ver, at
            name, ver, at = None, "", 0
            continue
        m = re.match(r'name\s*=\s*"([^"]+)"', s)
        if m and name is None:
            name, at = m.group(1), i
            continue
        m = re.match(r'version\s*=\s*"([^"]+)"', s)
        if m and name is not None and not ver:
            ver = m.group(1)
    if name:
        yield name, ver, at


def _npm_lock(lines: List[str]) -> Iterator[Entry]:
    """package-lock.json v1/v2/v3: a key line followed by a "version" line."""
    key_re = re.compile(r'^\s*"((?:[^"]*node_modules/)?(@[^/"]+/)?[^/"]+)"\s*:\s*\{')
    ver_re = re.compile(r'^\s*"version"\s*:\s*"([^"]+)"')
    for i, line in enumerate(lines):
        m = key_re.match(line)
        if not m:
            continue
        key = m.group(1)
        if key in ("packages", "dependencies", "devDependencies", "requires",
                   "optionalDependencies", "peerDependencies", "engines", "bin", "funding"):
            continue
        nxt = lines[i + 1] if i + 1 < len(lines) else ""
        v = ver_re.match(nxt)
        if not v:
            continue
        name = key.rsplit("node_modules/", 1)[-1]
        if name:
            yield name, v.group(1), i + 1


def _yarn_lock(lines: List[str]) -> Iterator[Entry]:
    head_re = re.compile(r'^"?((?:@[^@/"\s]+/)?[^@"\s,]+)@')
    ver_re = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?')
    current: Optional[Tuple[str, int]] = None
    for i, line in enumerate(lines, start=1):
        if line and not line[0].isspace() and line.rstrip().endswith(":"):
            m = head_re.match(line)
            current = (m.group(1), i) if m else None
            continue
        if current:
            v = ver_re.match(line)
            if v:
                yield current[0], v.group(1), current[1]
                current = None


def _pnpm_lock(lines: List[str]) -> Iterator[Entry]:
    pat = re.compile(r"^\s{2}['\"]?/?((?:@[^/@\s'\"]+/)?[^/@\s'\"]+)[@/](\d[^:'\"(\s]*)")
    in_packages = False
    for i, line in enumerate(lines, start=1):
        if re.match(r"^(packages|snapshots):\s*$", line):
            in_packages = True
            continue
        if line and not line[0].isspace():
            in_packages = False
            continue
        if in_packages:
            m = pat.match(line)
            if m:
                yield m.group(1), m.group(2), i


def _pipfile_lock(text: str, lines: List[str]) -> Iterator[Entry]:
    data = json.loads(text)
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            ver = str((meta or {}).get("version", "")).lstrip("=")
            yield name, ver, _line_of(lines, f'"{name}"')


def _composer_lock(text: str, lines: List[str]) -> Iterator[Entry]:
    data = json.loads(text)
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section) or []:
            name = pkg.get("name", "")
            if name:
                yield name, str(pkg.get("version", "")), _line_of(lines, f'"name": "{name}"')


def _go_sum(lines: List[str]) -> Iterator[Entry]:
    seen = set()
    for i, line in enumerate(lines, start=1):
        parts = line.split()
        if len(parts) < 2:
            continue
        mod, ver = parts[0], parts[1].split("/")[0]
        if mod not in seen:
            seen.add(mod)
            yield mod, ver, i


def _gemfile_lock(lines: List[str]) -> Iterator[Entry]:
    pat = re.compile(r"^ {4}([A-Za-z0-9_.-]+) \(([^)]+)\)\s*$")
    for i, line in enumerate(lines, start=1):
        m = pat.match(line)
        if m:
            yield m.group(1), m.group(2), i


def _gradle_lock(lines: List[str]) -> Iterator[Entry]:
    for i, line in enumerate(lines, start=1):
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        coord = s.split("=", 1)[0].split(":")
        if len(coord) == 3:
            yield coord[1], coord[2], i


def parse_lockfile(text: str, filename: str) -> List[Entry]:
    """Return (package, version, line) entries for a lockfile."""
    name = filename.lower()
    lines = text.splitlines()
    try:
        if name in ("package-lock.json", "npm-shrinkwrap.json"):
            return list(_npm_lock(lines))
        if name == "yarn.lock":
            return list(_yarn_lock(lines))
        if name == "pnpm-lock.yaml":
            return list(_pnpm_lock(lines))
        if name in ("poetry.lock", "uv.lock", "pdm.lock", "cargo.lock"):
            return list(_toml_packages(lines))
        if name == "pipfile.lock":
            return list(_pipfile_lock(text, lines))
        if name == "composer.lock":
            return list(_composer_lock(text, lines))
        if name == "go.sum":
            return list(_go_sum(lines))
        if name == "gemfile.lock":
            return list(_gemfile_lock(lines))
        if name == "gradle.lockfile":
            return list(_gradle_lock(lines))
    except (ValueError, AttributeError, TypeError):
        return []  # malformed lockfile: skip rather than crash the scan
    return []


def scan_lockfile(text: str, display_name: str, finding_cls) -> list:
    """Return one finding per crypto package found in a lockfile.

    Titles end with "(locked)". ``mark_transitive`` later changes that to
    "(transitive)" for packages the project's manifest does not name.
    """
    fname = PurePosixPath(display_name).name
    eco = LOCKFILES.get(fname.lower())
    if not eco:
        return []
    out = []
    seen = set()
    for pkg, ver, lineno in parse_lockfile(text, fname):
        norm = _norm(eco, pkg)
        for rule in DEP_RULES:
            if rule.rule_id in seen or not _matches(rule, eco, norm):
                continue
            seen.add(rule.rule_id)
            snippet = f"{pkg} {ver}".strip()
            out.append(finding_cls(
                rule_id=rule.rule_id, title=f"{rule.title} (locked)",
                severity=rule.severity, category=rule.category,
                file=display_name, line=lineno, snippet=snippet,
                why=rule.why, fix=rule.fix,
            ))
    return out


def mark_transitive(findings: list) -> None:
    """Label lockfile findings whose package the sibling manifest never names."""
    direct = set()
    for f in findings:
        p = PurePosixPath(f.file)
        if f.rule_id.startswith("QSD") and not is_lockfile(p.name):
            direct.add((str(p.parent), f.rule_id))
    for f in findings:
        p = PurePosixPath(f.file)
        if is_lockfile(p.name) and f.title.endswith(" (locked)"):
            if (str(p.parent), f.rule_id) not in direct:
                f.title = f.title[: -len(" (locked)")] + " (transitive)"
                f.why = f.why + TRANSITIVE_NOTE
