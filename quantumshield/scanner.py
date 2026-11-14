"""File walking and rule matching."""

from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable, List

from .rules import RULES, SEVERITY_ORDER
from .deps import is_manifest, scan_manifest
from .lockfiles import MAX_LOCKFILE_BYTES, is_lockfile, mark_transitive, scan_lockfile

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "env",
    "__pycache__", "dist", "build", ".tox", ".mypy_cache", ".pytest_cache",
    "site-packages", ".idea", ".vscode", "vendor", "target",
}

TEXT_EXTENSIONS = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".java", ".kt",
    ".go", ".rb", ".php", ".cs", ".c", ".h", ".cpp", ".hpp", ".rs", ".swift",
    ".sh", ".bash", ".yml", ".yaml", ".json", ".toml", ".ini", ".conf",
    ".cfg", ".env", ".tf", ".pem", ".key", ".txt", ".properties", ".xml",
    ".gradle", ".dockerfile",
}

TEXT_FILENAMES = {
    "dockerfile", "makefile", ".env", "nginx.conf",
    "authorized_keys", "known_hosts", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
}

MAX_FILE_BYTES = 1_000_000
IGNORE_MARKER = "quantumshield: ignore"
SNIPPET_LIMIT = 160


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    file: str
    line: int
    snippet: str
    why: str
    fix: str


@dataclass
class ScanResult:
    root: str
    files_scanned: int = 0
    files_skipped: int = 0
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "findings": [asdict(f) for f in self.findings],
        }


def _is_candidate(path: Path) -> bool:
    name = path.name.lower()
    return (path.suffix.lower() in TEXT_EXTENSIONS or name in TEXT_FILENAMES
            or is_manifest(name) or is_lockfile(name))


def _looks_binary(sample: bytes) -> bool:
    return b"\x00" in sample


def _excluded(rel_posix: str, parts: Iterable[str], exclude: Iterable[str]) -> bool:
    parts = set(parts)
    for item in exclude:
        item = item.strip("/").replace("\\", "/")
        if not item:
            continue
        if item in parts or rel_posix == item or rel_posix.startswith(item + "/"):
            return True
    return False


def _iter_files(root: Path, exclude: Iterable[str]):
    if root.is_file():
        yield root, root.name
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for filename in sorted(filenames):
            full = Path(dirpath) / filename
            rel = full.relative_to(root)
            rel_posix = rel.as_posix()
            if _excluded(rel_posix, rel.parts, exclude):
                continue
            yield full, rel_posix


def scan_text(text: str, display_name: str) -> List[Finding]:
    """Scan a block of text and return findings."""
    findings: List[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if IGNORE_MARKER in line.lower():
            continue
        for rule in RULES:
            if rule.pattern.search(line):
                snippet = line.strip()
                if len(snippet) > SNIPPET_LIMIT:
                    snippet = snippet[: SNIPPET_LIMIT - 3] + "..."
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        severity=rule.severity,
                        category=rule.category,
                        file=display_name,
                        line=lineno,
                        snippet=snippet,
                        why=rule.why,
                        fix=rule.fix,
                    )
                )
    return findings


def scan_path(path: str, exclude: Iterable[str] = ()) -> ScanResult:
    root = Path(path).resolve()
    result = ScanResult(root=str(root))
    for full, display in _iter_files(root, list(exclude)):
        if not _is_candidate(full):
            result.files_skipped += 1
            continue
        try:
            lockfile = is_lockfile(full.name)
            limit = MAX_LOCKFILE_BYTES if lockfile else MAX_FILE_BYTES
            if full.stat().st_size > limit:
                result.files_skipped += 1
                continue
            data = full.read_bytes()
        except OSError:
            result.files_skipped += 1
            continue
        if _looks_binary(data[:4096]):
            result.files_skipped += 1
            continue
        result.files_scanned += 1
        text = data.decode("utf-8", errors="replace")
        if lockfile:
            # Lockfiles hold names, versions and hashes, not code: skip the
            # source rules (hashes cause false matches) and read packages.
            result.findings.extend(scan_lockfile(text, display, Finding))
            continue
        result.findings.extend(scan_text(text, display))
        if is_manifest(full.name):
            result.findings.extend(scan_manifest(text, display, Finding))
    mark_transitive(result.findings)
    result.findings.sort(
        key=lambda f: (-SEVERITY_ORDER[f.severity], f.file, f.line, f.rule_id)
    )
    return result
