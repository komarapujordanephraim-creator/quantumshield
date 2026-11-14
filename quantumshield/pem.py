"""Read the algorithm inside PEM blocks.

Generic PEM labels ("PRIVATE KEY", "PUBLIC KEY", "CERTIFICATE") do not say which
algorithm the key uses. A scanner that only matches labels such as
"RSA PRIVATE KEY" misses them, and the inventory looks cleaner than it is.

This module base64-decodes each block and looks for the DER-encoded OID of the
key algorithm. For certificates the subject public key OID is reported, not the
signature algorithm. Encrypted private keys cannot be read and are skipped.
Standard library only.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import List, Tuple

_BEGIN = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----")

# DER encodings (tag 06, length, value) of key-algorithm OIDs -> family
_KEY_OIDS = [
    (bytes.fromhex("06092a864886f70d010101"), "RSA"),        # rsaEncryption 1.2.840.113549.1.1.1
    (bytes.fromhex("06092a864886f70d01010a"), "RSA"),        # RSASSA-PSS 1.2.840.113549.1.1.10
    (bytes.fromhex("06072a8648ce3d0201"), "EC"),             # id-ecPublicKey 1.2.840.10045.2.1
    (bytes.fromhex("06072a8648ce380401"), "DSA"),            # id-dsa 1.2.840.10040.4.1
    (bytes.fromhex("06092a864886f70d010301"), "DH"),         # dhKeyAgreement 1.2.840.113549.1.3.1
    (bytes.fromhex("06072a8648ce3e0201"), "DH"),             # dhpublicnumber 1.2.840.10046.2.1
    (bytes.fromhex("06032b6570"), "EdDSA"),                  # Ed25519 1.3.101.112
    (bytes.fromhex("06032b6571"), "EdDSA"),                  # Ed448 1.3.101.113
    (bytes.fromhex("06032b656e"), "X25519"),                 # 1.3.101.110
    (bytes.fromhex("06032b656f"), "X448"),                   # 1.3.101.111
]


def _pqc_family(der: bytes) -> str:
    i = der.find(bytes.fromhex("0609608648016503"))
    while i != -1:
        arc, last = der[i + 9], der[i + 10]
        if arc == 4 and last in (1, 2, 3):
            return "ML-KEM"
        if arc == 3 and 17 <= last <= 19:
            return "ML-DSA"
        if arc == 3 and 20 <= last <= 31:
            return "SLH-DSA"
        i = der.find(bytes.fromhex("0609608648016503"), i + 1)
    return ""


# Certificate signature-algorithm OIDs (DER prefix) -> family
_SIG_OIDS = [
    (bytes.fromhex("06082a8648ce3d0403"), "ECDSA"),          # ecdsa-with-SHA2 1.2.840.10045.4.3.x
    (bytes.fromhex("06072a8648ce3d0401"), "ECDSA"),          # ecdsa-with-SHA1
    (bytes.fromhex("06092a864886f70d0101"), "RSA"),          # sha*WithRSAEncryption, RSASSA-PSS
    (bytes.fromhex("06072a8648ce380403"), "DSA"),            # dsa-with-sha1
    (bytes.fromhex("0609608648016503040301"), "DSA"),        # dsa-with-sha224 2.16.840.1.101.3.4.3.1
    (bytes.fromhex("0609608648016503040302"), "DSA"),        # dsa-with-sha256 2.16.840.1.101.3.4.3.2
    (bytes.fromhex("06032b6570"), "EdDSA"),
    (bytes.fromhex("06032b6571"), "EdDSA"),
]


def _cert_family(der: bytes) -> str:
    """Family of the certificate's signature algorithm (the first algorithm identifier)."""
    pq = [(der.find(bytes.fromhex("0609608648016503040311")), "ML-DSA"),
          (der.find(bytes.fromhex("0609608648016503040312")), "ML-DSA"),
          (der.find(bytes.fromhex("0609608648016503040313")), "ML-DSA")]
    hits = [(der.find(oid), fam) for oid, fam in _SIG_OIDS if der.find(oid) != -1]
    hits += [h for h in pq if h[0] != -1]
    return min(hits)[1] if hits else ""


def _family(der: bytes, label: str) -> str:
    if "CERTIFICATE" in label:
        sig = _cert_family(der)
        if sig:
            return sig
        # skip to the SubjectPublicKeyInfo: the last key OID before the public key bits
        hits = [(der.rfind(oid), fam) for oid, fam in _KEY_OIDS if der.rfind(oid) != -1]
        pq = _pqc_family(der)
        if hits:
            return max(hits)[1]
        return pq
    pq = _pqc_family(der)
    if pq:
        return pq
    hits = [(der.find(oid), fam) for oid, fam in _KEY_OIDS if der.find(oid) != -1]
    return min(hits)[1] if hits else ""


def pem_blocks(text: str) -> List[Tuple[int, str, str]]:
    """Return (line number of BEGIN, label, family) for each readable PEM block."""
    out = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = _BEGIN.search(lines[i])
        if not m:
            i += 1
            continue
        label, start = m.group(1), i + 1
        body = []
        j = i + 1
        while j < len(lines) and f"-----END {label}-----" not in lines[j]:
            if ":" not in lines[j]:  # skip RFC 1421 headers
                body.append(lines[j].strip())
            j += 1
        i = j + 1
        if "ENCRYPTED" in label:
            continue
        try:
            der = base64.b64decode("".join(body), validate=False)
        except (binascii.Error, ValueError):
            continue
        fam = _family(der, label)
        if fam:
            out.append((start, label, fam))
    return out
