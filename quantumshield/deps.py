"""Dependency-level discovery.

Source code rules find cryptography that a project calls directly. Many
projects never call RSA or ECC themselves: a library does it for them. This
module reads dependency manifests (requirements.txt, pyproject.toml, Pipfile,
package.json, go.mod, Cargo.toml, pom.xml, build.gradle, Gemfile,
composer.json) and lists the cryptography libraries a project depends on.

The goal is an inventory signal, not a vulnerability verdict:

* ``dependency`` findings say "this project pulls in a crypto library; check
  which algorithms it is used for".
* Libraries that are unmaintained or documented as unsafe get a higher
  severity.
* Post-quantum libraries are reported as ``pqc`` (informational), so teams
  can see where migration work has already started.

Only package names are matched. Versions are not checked.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Dict, List, Tuple

# Manifest file name -> ecosystem
MANIFESTS: Dict[str, str] = {
    "requirements.txt": "pypi",
    "requirements-dev.txt": "pypi",
    "requirements_dev.txt": "pypi",
    "pyproject.toml": "pypi",
    "pipfile": "pypi",
    "setup.cfg": "pypi",
    "package.json": "npm",
    "go.mod": "go",
    "cargo.toml": "cargo",
    "pom.xml": "maven",
    "build.gradle": "maven",
    "build.gradle.kts": "maven",
    "gemfile": "rubygems",
    "composer.json": "composer",
}

MANIFEST_FILENAMES = set(MANIFESTS)


@dataclass(frozen=True)
class DepRule:
    rule_id: str
    ecosystem: str
    package: str
    title: str
    severity: str
    category: str
    why: str
    fix: str


_GENERAL_WHY = (
    "This library provides general-purpose cryptography. It usually includes RSA, "
    "ECC and Diffie-Hellman, which a large quantum computer is expected to break."
)
_GENERAL_FIX = (
    "Record which algorithms the project uses through this library and add them to "
    "your cryptographic inventory. Plan a move to ML-KEM / ML-DSA where public-key "
    "crypto is used."
)
_RSA_WHY = "This library exists to provide RSA, which Shor's algorithm breaks on a large quantum computer."
_ECC_WHY = "This library provides elliptic-curve cryptography (ECDSA/ECDH), which Shor's algorithm breaks."
_PQC_WHY = "This library provides post-quantum algorithms. Good sign: migration work has started here."
_PQC_FIX = "Check that it implements the final NIST standards (FIPS 203/204/205) and is kept up to date."


def _d(rule_id, eco, pkg, title, sev, cat, why, fix=_GENERAL_FIX):
    return DepRule(rule_id, eco, pkg, title, sev, cat, why, fix)


DEP_RULES: List[DepRule] = [
    # ---- Python -------------------------------------------------------
    _d("QSD001", "pypi", "pycrypto", "Unmaintained crypto library: pycrypto", "high", "classical",
       "PyCrypto has not been maintained since 2013 and has known security issues that will not be fixed.",
       "Replace it with pycryptodome or cryptography, then review which algorithms are used."),
    _d("QSD002", "pypi", "rsa", "RSA-only library: python-rsa", "medium", "quantum", _RSA_WHY),
    _d("QSD003", "pypi", "ecdsa", "ECC library: python-ecdsa", "medium", "quantum",
       _ECC_WHY + " Its own documentation also warns it is not protected against side-channel attacks.",
       "Prefer the cryptography package for ECC today, and plan a move to ML-DSA for signatures."),
    _d("QSD004", "pypi", "cryptography", "Crypto library: cryptography", "low", "dependency", _GENERAL_WHY),
    _d("QSD005", "pypi", "pycryptodome", "Crypto library: pycryptodome", "low", "dependency", _GENERAL_WHY),
    _d("QSD006", "pypi", "pycryptodomex", "Crypto library: pycryptodomex", "low", "dependency", _GENERAL_WHY),
    _d("QSD007", "pypi", "pyopenssl", "Crypto library: pyOpenSSL", "low", "dependency", _GENERAL_WHY),
    _d("QSD008", "pypi", "paramiko", "SSH library: paramiko", "low", "dependency",
       "SSH key exchange and host keys commonly use RSA, ECDSA or (EC)DH."),
    _d("QSD009", "pypi", "pyjwt", "JWT library: PyJWT", "low", "dependency",
       "JWTs signed with RS256/ES256 use RSA or ECDSA signatures."),
    _d("QSD010", "pypi", "python-jose", "JWT library: python-jose", "low", "dependency",
       "JWTs signed with RS256/ES256 use RSA or ECDSA signatures."),
    _d("QSD011", "pypi", "liboqs-python", "Post-quantum library: liboqs-python", "info", "pqc", _PQC_WHY, _PQC_FIX),
    _d("QSD012", "pypi", "pqcrypto", "Post-quantum library: pqcrypto", "info", "pqc", _PQC_WHY, _PQC_FIX),
    # ---- npm ----------------------------------------------------------
    _d("QSD101", "npm", "crypto-js", "Discontinued crypto library: crypto-js", "medium", "classical",
       "crypto-js development has been discontinued by its maintainers, so new issues will not be fixed.",
       "Use the platform Web Crypto API or Node's built-in crypto module instead."),
    _d("QSD102", "npm", "node-rsa", "RSA-only library: node-rsa", "medium", "quantum", _RSA_WHY),
    _d("QSD103", "npm", "elliptic", "ECC library: elliptic", "medium", "quantum", _ECC_WHY),
    _d("QSD104", "npm", "jsrsasign", "RSA/ECC library: jsrsasign", "medium", "quantum",
       "jsrsasign provides RSA and ECDSA signatures, which Shor's algorithm breaks."),
    _d("QSD105", "npm", "node-forge", "Crypto library: node-forge", "low", "dependency", _GENERAL_WHY),
    _d("QSD106", "npm", "jsonwebtoken", "JWT library: jsonwebtoken", "low", "dependency",
       "JWTs signed with RS256/ES256 use RSA or ECDSA signatures."),
    _d("QSD107", "npm", "jose", "JWT/JOSE library: jose", "low", "dependency",
       "JOSE tokens signed with RS256/ES256 use RSA or ECDSA signatures."),
    _d("QSD108", "npm", "@noble/curves", "ECC library: @noble/curves", "low", "quantum", _ECC_WHY),
    _d("QSD109", "npm", "@noble/post-quantum", "Post-quantum library: @noble/post-quantum", "info", "pqc", _PQC_WHY, _PQC_FIX),
    # ---- Go -----------------------------------------------------------
    _d("QSD201", "go", "golang.org/x/crypto", "Crypto module: golang.org/x/crypto", "low", "dependency", _GENERAL_WHY),
    _d("QSD202", "go", "github.com/golang-jwt/jwt", "JWT module: golang-jwt", "low", "dependency",
       "JWTs signed with RS256/ES256 use RSA or ECDSA signatures."),
    _d("QSD203", "go", "github.com/cloudflare/circl", "Post-quantum module: cloudflare/circl", "info", "pqc", _PQC_WHY, _PQC_FIX),
    _d("QSD204", "go", "github.com/open-quantum-safe/liboqs-go", "Post-quantum module: liboqs-go", "info", "pqc", _PQC_WHY, _PQC_FIX),
    # ---- Rust ---------------------------------------------------------
    _d("QSD301", "cargo", "rsa", "RSA crate: rsa", "medium", "quantum", _RSA_WHY),
    _d("QSD302", "cargo", "openssl", "Crypto crate: openssl", "low", "dependency", _GENERAL_WHY),
    _d("QSD303", "cargo", "ring", "Crypto crate: ring", "low", "dependency", _GENERAL_WHY),
    _d("QSD304", "cargo", "p256", "ECC crate: p256", "medium", "quantum", _ECC_WHY),
    _d("QSD305", "cargo", "pqcrypto", "Post-quantum crate: pqcrypto", "info", "pqc", _PQC_WHY, _PQC_FIX),
    _d("QSD306", "cargo", "oqs", "Post-quantum crate: oqs", "info", "pqc", _PQC_WHY, _PQC_FIX),
    # ---- Java ---------------------------------------------------------
    _d("QSD401", "maven", "bcprov", "Crypto library: Bouncy Castle", "low", "dependency",
       _GENERAL_WHY + " Bouncy Castle also ships post-quantum algorithms, so migration can often stay in the same library."),
    _d("QSD402", "maven", "jjwt", "JWT library: jjwt", "low", "dependency",
       "JWTs signed with RS256/ES256 use RSA or ECDSA signatures."),
    _d("QSD403", "maven", "nimbus-jose-jwt", "JOSE library: nimbus-jose-jwt", "low", "dependency",
       "JOSE tokens signed with RS256/ES256 use RSA or ECDSA signatures."),
    # ---- Ruby / PHP ---------------------------------------------------
    _d("QSD501", "rubygems", "jwt", "JWT gem: jwt", "low", "dependency",
       "JWTs signed with RS256/ES256 use RSA or ECDSA signatures."),
    _d("QSD502", "rubygems", "rbnacl", "Crypto gem: rbnacl", "low", "dependency",
       "libsodium bindings: Curve25519 key exchange and Ed25519 signatures are both broken by Shor's algorithm."),
    _d("QSD601", "composer", "phpseclib/phpseclib", "Crypto library: phpseclib", "low", "dependency", _GENERAL_WHY),
    _d("QSD602", "composer", "firebase/php-jwt", "JWT library: firebase/php-jwt", "low", "dependency",
       "JWTs signed with RS256/ES256 use RSA or ECDSA signatures."),
]


def _compile(rule: DepRule) -> "re.Pattern[str]":
    name = re.escape(rule.package)
    if rule.ecosystem == "pypi":
        # requirements line start, or a quoted/listed name in pyproject/Pipfile/setup.cfg
        pat = rf"(?i)(?:^\s*|[\"'\s,\[])({name})(?=\s*(?:[<>=!~;\[\]\"',@]|$))"
    elif rule.ecosystem in ("npm", "composer"):
        pat = rf"\"({name})\"\s*:"
    elif rule.ecosystem == "go":
        pat = rf"(?:^|\s)({name})(?:/v\d+)?(?:/[\w./-]+)?\s+v\d"
    elif rule.ecosystem == "cargo":
        pat = rf"^\s*({name})\s*=|\[dependencies\.({name})\]"
    elif rule.ecosystem == "maven":
        pat = rf"(?i)({name})[\w.-]*(?=[<:'\"])"
    else:  # rubygems
        pat = rf"^\s*gem\s+[\"']({name})[\"']"
    return re.compile(pat, re.MULTILINE)


_COMPILED: List[Tuple[DepRule, "re.Pattern[str]"]] = [(r, _compile(r)) for r in DEP_RULES]


def is_manifest(name: str) -> bool:
    n = name.lower()
    return n in MANIFEST_FILENAMES or (n.startswith("requirements") and n.endswith(".txt"))


def ecosystem_for(name: str) -> str:
    n = name.lower()
    if n in MANIFESTS:
        return MANIFESTS[n]
    if n.startswith("requirements") and n.endswith(".txt"):
        return "pypi"
    return ""


def scan_manifest(text: str, display_name: str, finding_cls) -> list:
    """Return findings for crypto libraries declared in a dependency manifest."""
    eco = ecosystem_for(PurePosixPath(display_name).name)
    if not eco:
        return []
    out = []
    seen = set()
    lines = text.splitlines()
    for rule, pattern in _COMPILED:
        if rule.ecosystem != eco:
            continue
        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            if "quantumshield: ignore" in line.lower():
                continue
            if pattern.search(line) and (rule.rule_id, lineno) not in seen:
                seen.add((rule.rule_id, lineno))
                snippet = stripped[:157] + "..." if len(stripped) > 160 else stripped
                out.append(finding_cls(
                    rule_id=rule.rule_id, title=rule.title, severity=rule.severity,
                    category=rule.category, file=display_name, line=lineno,
                    snippet=snippet, why=rule.why, fix=rule.fix,
                ))
                break  # one finding per package per manifest
    return out
