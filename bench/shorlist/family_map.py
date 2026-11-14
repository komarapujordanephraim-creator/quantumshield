"""QuantumShield rule -> ShorList family (schema/families.yaml). Used only by score.py."""
import re

def _ec_family(text: str) -> str:
    t = text.upper()
    if "ED25519" in t or "ED448" in t or "EDDSA" in t:
        return "EdDSA"
    if "X25519" in t:
        return "X25519"
    if re.search(r"\bX448\b", t):
        return "X448"
    if re.search(r"TLS_ECDHE?_|ECDHE?[-_]|GROUP|KE_METHOD|CURVES|KEX|DH-GROUPS|AGREE", t):
        return "ECDH"
    if re.search(r"EC_SIGN|ES256K|SIGN", t):
        return "ECDSA"
    if "ECDSA" in t:
        return "ECDSA"
    if "ECDH" in t:
        return "ECDH"
    return "EC"


def _pqc_family(text: str) -> str:
    t = text.upper()
    if re.search(r"ML[-_]?KEM|KYBER|-PQ-20|0X04,\s*0X04", t):
        return "ML-KEM"
    if re.search(r"ML[-_]?DSA|DILITHIUM|0X04,\s*0X03", t):
        return "ML-DSA"
    if re.search(r"SLH[-_]?DSA|SPHINCS", t):
        return "SLH-DSA"
    return "PQC"


DEP_FAMILY = {"QSD002": "RSA", "QSD102": "RSA", "QSD301": "RSA", "QSD003": "ECDSA",
              "QSD103": "EC", "QSD108": "EC", "QSD304": "EC", "QSD104": "RSA"}


def to_family(rid, s):
    fam, size = None, None
    if rid == "QS001":
        fam = "RSA"
    elif rid == "QS002":
        fam = _ec_family(s)
    elif rid == "QS003":
        fam = "DH"
    elif rid == "QS004":
        fam = "DSA"
    elif rid == "QS005":
        m = re.search(r"['\"](RS|PS|ES)(256|384|512)['\"]", s)
        fam = ("ECDSA" if m.group(1) == "ES" else "RSA") if m else "EdDSA"
    elif rid == "QS006":
        fam = "DSA" if "ssh-dss" in s else "RSA"
    elif rid == "QS007":
        fam = "AES-128"  # not a vocabulary family; ignored by the scorer
    elif rid == "QS008":
        fam = "MD5" if re.search(r"md5", s, re.I) else "SHA-1"
    elif rid == "QS009":
        fam = "RSA"
        m = re.search(r"\b(512|768|1024)\b", s)
        size = int(m.group(1)) if m else None
    elif rid == "QS010":
        fam = "TLS"
    elif rid == "QS011":
        m = re.search(r"BEGIN (RSA|EC|DSA) PRIVATE KEY", s)
        fam = m.group(1) if m else "PRIVATE-KEY"
    elif rid == "QS100":
        fam = _pqc_family(s)
    elif rid == "QS012":
        fam = "RSA"
    elif rid == "QS013":
        fam = "DH"
    elif rid == "QS014":
        fam = "DSA"
    elif rid == "QS015":
        fam = "ECDSA" if re.search(r"1\.2\.840\.10045\.4", s) else _ec_family(s)
    elif rid == "QS016":
        m = re.search(r"1\.3\.101\.(11[0-3])", s)
        fam = {"110": "X25519", "111": "X448", "112": "EdDSA", "113": "EdDSA"}[m.group(1)]
    elif rid == "QS017":
        t = s.upper()
        fam = ("3DES" if re.search(r"3DES|DES[-_]?EDE|TRIPLEDES|DESEDE", t) else "RC4" if re.search(r"RC4|ARCFOUR", t)
               else "RC2" if "RC2" in t else "MD4" if "MD4" in t else "MD5" if "MD5" in t else "DES" if re.search(r"DES[-_](CBC|ECB)", t) else "SHA-1")
    elif rid == "QS018":
        m = re.search(r"\(([A-Za-z0-9-]+)\)\s*$", s)
        fam = m.group(1) if m else "PEM"
    elif rid == "QS101":
        t = s.upper()
        fam = _pqc_family(s)
        if fam == "PQC":
            fam = ("ML-KEM" if re.search(r"MLKEM|4\.4\.[1-3]", t) else "ML-DSA" if re.search(r"MLDSA|4\.3\.1[7-9]", t)
                   else "SLH-DSA" if re.search(r"SLH|4\.3\.(2\d|3[01])", t) else "XMSS" if "XMSS" in t else "LMS")
    elif rid.startswith("QSD"):
        fam = DEP_FAMILY.get(rid, rid)
    return fam


