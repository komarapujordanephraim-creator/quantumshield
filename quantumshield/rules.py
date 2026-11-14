"""Detection rules.

Each rule is a regular expression applied line by line. Rules are grouped into
two categories:

* ``quantum``   - algorithms a large quantum computer is expected to break or
                  weaken (Shor's / Grover's algorithms).
* ``classical`` - cryptographic hygiene problems that are weak today, with no
                  quantum computer required.
* ``pqc``       - references to post-quantum algorithms (informational).

Patterns are heuristics. They can produce false positives and false negatives.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

NIST_NOTE = (
    "NIST finalized the first post-quantum standards in August 2024: "
    "FIPS 203 (ML-KEM, key establishment), FIPS 204 (ML-DSA, signatures) and "
    "FIPS 205 (SLH-DSA, hash-based signatures)."
)


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    category: str
    pattern: "re.Pattern[str]"
    why: str
    fix: str


def _rule(rule_id, title, severity, category, pattern, why, fix):
    return Rule(
        rule_id=rule_id,
        title=title,
        severity=severity,
        category=category,
        pattern=re.compile(pattern, re.IGNORECASE),
        why=why,
        fix=fix,
    )


RULES = [
    _rule(
        "QS001",
        "RSA usage",
        "high",
        "quantum",
        r"rsa\.generate_private_key|\bRSA\.(generate|importKey|import_key)\b"
        r"|generateKeyPair(Sync)?\(\s*['\"]rsa|getInstance\(\s*['\"]RSA"
        r"|rsa\.GenerateKey|\bgenrsa\b|-newkey\s+rsa|RSA_generate_key",
        "RSA relies on integer factoring, which Shor's algorithm solves on a "
        "large quantum computer. Data encrypted today can be stored and "
        "decrypted later (harvest now, decrypt later).",
        "Plan migration to ML-KEM (FIPS 203) for key establishment and "
        "ML-DSA (FIPS 204) for signatures. Use a hybrid (classical + "
        "post-quantum) approach during transition. " + NIST_NOTE,
    ),
    _rule(
        "QS002",
        "Elliptic-curve cryptography (ECC, ECDSA, ECDH, Ed25519, X25519)",
        "high",
        "quantum",
        r"ec\.generate_private_key|ec\.SECP\d+R1|ECDSA|ECDH"
        r"|\bsecp(256|384|521)[rk]1\b|prime256v1|\bP-(256|384|521)\b"
        r"|Ed25519|X25519|Ed448|\bX448\b|elliptic\.P(256|384|521)"
        r"|generateKeyPair(Sync)?\(\s*['\"](ec|ed25519|x25519|ed448|x448)",
        "Elliptic-curve discrete logarithms are solved by Shor's algorithm. "
        "This includes Ed25519 and X25519.",
        "Migrate key exchange to ML-KEM (FIPS 203) and signatures to ML-DSA "
        "(FIPS 204) or SLH-DSA (FIPS 205). Hybrid schemes such as X25519 + "
        "ML-KEM are a common transition step.",
    ),
    _rule(
        "QS003",
        "Diffie-Hellman key exchange",
        "high",
        "quantum",
        r"dh\.generate_parameters|createDiffieHellman|DiffieHellman"
        r"|\bDHE?-|getInstance\(\s*['\"]DH['\"]|ssl_dhparam|\bdhparam\b",
        "Finite-field Diffie-Hellman depends on the discrete logarithm "
        "problem, which Shor's algorithm breaks.",
        "Replace with ML-KEM (FIPS 203), ideally in a hybrid construction.",
    ),
    _rule(
        "QS004",
        "DSA signatures",
        "high",
        "quantum",
        r"\bdsa\.generate_private_key|\bDSA\.generate\b"
        r"|getInstance\(\s*['\"]DSA['\"]",
        "DSA depends on the discrete logarithm problem (Shor's algorithm). "
        "DSA is also deprecated for new signatures in current NIST guidance.",
        "Use ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).",
    ),
    _rule(
        "QS005",
        "JWT/token signing with RSA, ECDSA or EdDSA",
        "medium",
        "quantum",
        r"['\"](RS|PS|ES)(256|384|512)['\"]|['\"]EdDSA['\"]",
        "These token-signing algorithms use RSA or elliptic curves, which are "
        "not quantum-safe. Short-lived tokens are lower risk than long-lived "
        "signatures.",
        "Track post-quantum signature support in your JWT/JOSE libraries and "
        "plan algorithm agility so the algorithm can be swapped by config.",
    ),
    _rule(
        "QS006",
        "ssh-rsa / ssh-dss key",
        "medium",
        "quantum",
        r"ssh-rsa\s+AAAA|ssh-dss\s+AAAA",
        "SSH keys based on RSA or DSA are not quantum-safe, and ssh-rsa "
        "(SHA-1) signatures are deprecated in OpenSSH.",
        "Rotate to a modern key type now and follow OpenSSH post-quantum "
        "key-exchange support for the longer term.",
    ),
    _rule(
        "QS007",
        "AES-128 (reduced margin against Grover's algorithm)",
        "low",
        "quantum",
        r"AES[-_]?128|aes128",
        "Grover's algorithm roughly halves symmetric key strength. NIST still "
        "treats AES-128 as acceptable, but AES-256 gives a larger margin for "
        "data that must stay secret for many years.",
        "Prefer AES-256 for long-lived sensitive data.",
    ),
    _rule(
        "QS008",
        "MD5 or SHA-1 hash",
        "medium",
        "classical",
        r"hashlib\.(md5|sha1)\b|createHash\(\s*['\"](md5|sha1)['\"]"
        r"|MessageDigest\.getInstance\(\s*['\"](MD5|SHA-?1)['\"]"
        r"|\bmd5\(|\bsha1\(|Digest::(MD5|SHA1)|crypto/(md5|sha1)",
        "MD5 and SHA-1 have practical collision attacks today. This is a "
        "classical weakness, not a quantum one.",
        "Use SHA-256 or SHA-3. For password storage use Argon2, scrypt or "
        "bcrypt.",
    ),
    _rule(
        "QS009",
        "Small key size (512, 768 or 1024 bits)",
        "high",
        "classical",
        r"(key_?size|keysize|key_?length|modulus_?length|rsa_keygen_bits)"
        r"\s*[=:(]\s*['\"]?(512|768|1024)\b|rsa:(512|768|1024)\b",
        "Keys of this size are considered breakable with classical computers.",
        "Use at least 3072-bit RSA or a modern curve today, and plan the "
        "post-quantum migration.",
    ),
    _rule(
        "QS010",
        "Legacy SSL/TLS protocol version",
        "medium",
        "classical",
        r"SSLv2|SSLv3|TLSv?1\.[01]\b|PROTOCOL_TLSv1(_1)?\b|\bTLSv1(_1)?_method|\bTLS[-_]1[-_][01]\b",
        "SSLv2, SSLv3, TLS 1.0 and TLS 1.1 are deprecated and have known "
        "weaknesses.",
        "Require TLS 1.2 or TLS 1.3 only.",
    ),
    _rule(
        "QS011",
        "Private key embedded in source",
        "critical",
        "classical",
        r"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
        "A private key is stored in the repository. Anyone with read access "
        "can impersonate the key owner.",
        "Remove the key from the repository and its git history, revoke and "
        "rotate it, and load keys from a secrets manager or environment.",
    ),
    _rule(
        "QS100",
        "Post-quantum algorithm referenced",
        "info",
        "pqc",
        r"ML-?KEM|ML-?DSA|SLH-?DSA|\bkyber\d*\b|\bdilithium\d*\b"
        r"|\bsphincs\+?|liboqs|\boqs\b",
        "Informational: the code references a post-quantum algorithm or "
        "library. Review that it is used correctly and in a hybrid setup "
        "where appropriate.",
        "No action required from this finding.",
    ),
    # ---- v0.4: rules derived from the forms catalogued by ShorList -------------
    _rule(
        "QS012",
        "RSA in TLS suites, signature schemes, key types or OIDs",
        "high",
        "quantum",
        r"\bTLS_(SRP_SHA_)?RSA_|_RSA_WITH_|\brsa_(pss|pkcs1)_|SHA\d+[-_]?with[-_]?RSA|\bRSA[_-]?(PSS|OAEP|SIGN|DECRYPT|ENCRYPT|KEM|\d{4})"
        r"|EVP_PKEY_RSA|\bCK[KM]_RSA|PSA_(ALG|KEY_TYPE)_RSA|\brsa_(bits|keygen)|key[-_]?type[=:\s]+['\"]?RSA"
        r"|-keyalg\s+RSA|\bkty['\"]?\s*[:=]\s*['\"]?RSA|rsaEncryption|\.rsa(Encryption|Signature)|\brsa::"
        r"|RSASSA|RSAES|rsa-sha2-\d+|KEYTYPE_RSA|1\.2\.840\.113549\.1\.1\.\d+|['\"]RSA['\"]|\b(pss|oaep|pkcs1_15|PKCS1_OAEP|PKCS1_v1_5)\.new\("
        r"|-----BEGIN RSA (PUBLIC|PRIVATE) KEY-----",
        "RSA relies on integer factoring, which Shor's algorithm solves on a large quantum computer.",
        "Plan migration to ML-KEM (FIPS 203) and ML-DSA (FIPS 204); use hybrid modes during transition. " + NIST_NOTE,
    ),
    _rule(
        "QS013",
        "Finite-field Diffie-Hellman (TLS suites, groups, IKE, SSH)",
        "high",
        "quantum",
        r"\bTLS_DHE?_|\bDHE?_(RSA|DSS|PSK|anon)_|ffdhe\d+|\bmodp\d+|MODP Group|diffie-hellman-group|\bdh[-_]group"
        r"|\bCK[KM]_(X9_42_)?DH|EVP_PKEY_DH\b|dhKeyAgreement|1\.2\.840\.113549\.1\.3\.1|1\.2\.840\.10046\.2\.1"
        r"|-----BEGIN (X9\.42 )?DH PARAMETERS-----|KEYTYPE_DH\b|DH::create|\bDH\.(generate|new)",
        "Finite-field Diffie-Hellman relies on discrete logarithms, which Shor's algorithm solves.",
        "Move key exchange to ML-KEM, or hybrid X25519MLKEM768 in TLS 1.3. " + NIST_NOTE,
    ),
    _rule(
        "QS014",
        "DSA / DSS",
        "high",
        "quantum",
        r"(?<!ML[-_])(?<!SLH[-_])(?<![A-Za-z0-9-])DSA(?![A-Za-z])|(?<![A-Za-z0-9])DSS(?![A-Za-z0-9])|\bCK[KM]_DSA|EVP_PKEY_DSA|dsa_paramgen"
        r"|dsaEncryption|\bdsa\.Generate|-----BEGIN DSA|KEYTYPE_DSA|1\.2\.840\.10040\.4\.[13]|1\.3\.14\.3\.2\.(12|27)|ssh-dss",
        "DSA relies on discrete logarithms, which Shor's algorithm solves. It is also disallowed for new signatures by FIPS 186-5.",
        "Replace with ML-DSA (FIPS 204) or SLH-DSA (FIPS 205). " + NIST_NOTE,
    ),
    _rule(
        "QS015",
        "Elliptic curve named by curve, key type or OID",
        "high",
        "quantum",
        r"brainpoolP\d+[rt]1|\bsec[pt]\d+[rk]\d\b|\bsect\d+|\bansi[px]\d+|(?<![A-Za-z0-9])[PKB]-(163|192|224|233|256|283|384|409|521|571)K?\b"
        r"|ECC_NIST_P\d+|ECC_SECG|EC_SIGN_P\d+|\bP(256|384|521)\b|\bES256K\b|\bprime(192|239|256)v\d|MBEDTLS_ECP_DP_|PSA_(KEY_TYPE|ECC_FAMILY)_|EVP_PKEY_EC\b|\bCK[KM]_EC"
        r"|key[-_]?type=ec\b|--?kty\s+EC|-keyalg\s+ec\b|\bkty['\"]?\s*[:=]\s*['\"]?EC|id-ecPublicKey|1\.2\.840\.10045\.|1\.3\.132\.0\.\d+"
        r"|(?<![A-Za-z0-9])SM2(?![A-Za-z0-9])|\bCurve\d{3,}|nistp\d{3}|KEYTYPE_EC\b|-----BEGIN EC (PRIVATE KEY|PARAMETERS)-----|\bcurve448|\bcurve25519",
        "Elliptic-curve cryptography relies on discrete logarithms over curves, which Shor's algorithm solves.",
        "Plan migration to ML-KEM (FIPS 203) / ML-DSA (FIPS 204); use hybrid modes during transition. " + NIST_NOTE,
    ),
    _rule(
        "QS016",
        "Edwards / Montgomery curve OID (Ed25519, Ed448, X25519, X448)",
        "high",
        "quantum",
        r"1\.3\.101\.11[0-3]\b",
        "These curves are broken by Shor's algorithm like any elliptic curve.",
        "Plan migration to ML-KEM / ML-DSA. " + NIST_NOTE,
    ),
    _rule(
        "QS017",
        "Weak cipher or hash (DES, 3DES, RC4, RC2, MD4, SHA-1 in suites)",
        "medium",
        "classical",
        r"\b3DES\b|DES[-_]?EDE|TripleDES|DESede|(?<![A-Za-z0-9])DES[-_](CBC|ECB)|\bRC4\b|ARCFOUR|(?<![A-Za-z0-9])RC2(?![A-Za-z0-9])|\bMD4\b"
        r"|\bSHA-?1\b|SHA1(?=with|_|\b)|_SHA\b|\bMD5\b|_MD5\b",
        "These algorithms are broken or disallowed today, without any quantum computer.",
        "Use AES-GCM or ChaCha20-Poly1305, and SHA-256 or stronger.",
    ),
    _rule(
        "QS101",
        "Post-quantum algorithm referenced (OID or stateful hash-based signature)",
        "info",
        "pqc",
        r"2\.16\.840\.1\.101\.3\.4\.(4\.[1-3]|3\.(1[7-9]|2\d|3[01]))\b|(?<![A-Za-z0-9])(LMS|HSS)(?![A-Za-z])|\bXMSS(MT)?\b|hss-lms|1\.2\.840\.113549\.1\.9\.16\.3\.17"
        r"|\bMLKEM\d*|\bMLDSA\d*|\bSLHDSA|slh-?dsa|ML_KEM|ML_DSA|SLH_DSA|-PQ-20\d\d|0x60,\s*0x86,\s*0x48,\s*0x01,\s*0x65,\s*0x03,\s*0x04,\s*0x0[34]",
        "Informational: the code references a post-quantum algorithm.",
        "No action required from this finding.",
    ),
    _rule(
        "QS018",
        "Public-key algorithm inside a PEM block",
        "high",
        "quantum",
        r"(?!x)x",  # produced by the PEM decoder in scanner.py, not by a line pattern
        "The PEM block holds a key or certificate for an algorithm that Shor's algorithm breaks. "
        "Generic labels (PRIVATE KEY, PUBLIC KEY, CERTIFICATE) hide the algorithm; QuantumShield reads the OID inside.",
        "Add the key or certificate to your cryptographic inventory and plan its replacement with ML-KEM / ML-DSA. " + NIST_NOTE,
    ),
]

RULES_BY_ID = {r.rule_id: r for r in RULES}
