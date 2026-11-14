import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from quantumshield.cli import main
from quantumshield.report import html_report, json_report
from quantumshield.scanner import scan_path, scan_text

SAMPLE = Path(__file__).parent / "sample_project"


def found(result):
    return {(f.file, f.line, f.rule_id) for f in result.findings}


def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class ScannerTests(unittest.TestCase):
    def test_sample_project_expected_findings(self):
        got = found(scan_path(str(SAMPLE)))
        expected = {
            ("app.py", 5, "QS001"),
            ("app.py", 6, "QS002"),
            ("app.py", 7, "QS008"),
            ("server.js", 3, "QS001"),
            ("server.js", 3, "QS009"),
            ("server.js", 4, "QS005"),
            ("server.js", 5, "QS008"),
            ("config.yml", 1, "QS010"),
            ("config.yml", 2, "QS007"),
            ("config.yml", 3, "QS006"),
            ("pqc_demo.py", 1, "QS100"),
        }
        self.assertEqual(got, expected)

    def test_ignore_marker_suppresses_line(self):
        findings = scan_text("x = hashlib.md5(b'')  # quantumshield: ignore\n", "f.py")
        self.assertEqual(findings, [])

    def test_clean_file_has_no_findings(self):
        self.assertEqual(scan_text('print("hello")\n', "clean.py"), [])

    def test_tls12_is_not_flagged(self):
        ids = {f.rule_id for f in scan_text("min_version: TLSv1.2\n", "c.yml")}
        self.assertNotIn("QS010", ids)

    def test_ecdsa_is_not_reported_as_dsa(self):
        ids = {f.rule_id for f in scan_text("ecdsa.generate_private_key()\n", "a.py")}
        self.assertIn("QS002", ids)
        self.assertNotIn("QS004", ids)

    def test_private_key_is_critical(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "key.pem").write_text(
                "-----BEGIN RSA PRIVATE KEY-----\nDEMO_NOT_A_REAL_KEY\n-----END RSA PRIVATE KEY-----\n"
            )
            result = scan_path(tmp)
        self.assertEqual([(f.rule_id, f.severity) for f in result.findings], [("QS011", "critical")])

    def test_exclude_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "keep").mkdir()
            Path(tmp, "skip").mkdir()
            Path(tmp, "keep", "a.py").write_text("hashlib.md5(b'')\n")
            Path(tmp, "skip", "b.py").write_text("hashlib.md5(b'')\n")
            result = scan_path(tmp, exclude=["skip"])
        self.assertEqual({f.file for f in result.findings}, {"keep/a.py"})

    def test_binary_file_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "blob.txt").write_bytes(b"\x00\x01hashlib.md5(")
            result = scan_path(tmp)
        self.assertEqual(result.files_scanned, 0)
        self.assertEqual(result.files_skipped, 1)


class ReportTests(unittest.TestCase):
    def test_json_is_valid(self):
        data = json.loads(json_report(scan_path(str(SAMPLE))))
        self.assertEqual(data["tool"], "quantumshield")
        self.assertEqual(len(data["findings"]), 11)
        self.assertEqual(data["summary"]["verdict"], "Action needed")

    def test_html_escapes_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "x.py").write_text('s = "<script>alert(1)</script>"; hashlib.md5(b"")\n')
            page = html_report(scan_path(tmp))
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)


class RegressionTests(unittest.TestCase):
    def test_authorized_keys_without_extension_is_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "authorized_keys").write_text("ssh-rsa AAAAB3NzaC1yc2E deploy@demo\n")
            ids = {f.rule_id for f in scan_path(tmp).findings}
        self.assertIn("QS006", ids)

    def test_terraform_tls_policy_name_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "main.tf").write_text('ssl_policy = "ELBSecurityPolicy-TLS-1-0-2015-04"\n')
            ids = {f.rule_id for f in scan_path(tmp).findings}
        self.assertIn("QS010", ids)


class CliTests(unittest.TestCase):
    def test_exit_code_fails_on_high(self):
        code, _, _ = run_cli(["scan", str(SAMPLE)])
        self.assertEqual(code, 1)

    def test_fail_on_none_returns_zero(self):
        code, _, _ = run_cli(["scan", str(SAMPLE), "--fail-on", "none"])
        self.assertEqual(code, 0)

    def test_missing_path_returns_two(self):
        code, _, err = run_cli(["scan", "/definitely/not/here"])
        self.assertEqual(code, 2)
        self.assertIn("not found", err)

    def test_clean_dir_returns_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "ok.py").write_text('print("ok")\n')
            code, out, _ = run_cli(["scan", tmp])
        self.assertEqual(code, 0)
        self.assertIn("No findings", out)

    def test_html_output_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp, "report.html")
            code, _, _ = run_cli(["scan", str(SAMPLE), "--html", str(target)])
            self.assertTrue(target.read_text().startswith("<!doctype html>"))


if __name__ == "__main__":
    unittest.main()


class DependencyTests(unittest.TestCase):
    def _scan(self, files):
        import tempfile, os
        from quantumshield.scanner import scan_path
        with tempfile.TemporaryDirectory() as d:
            for name, body in files.items():
                p = os.path.join(d, name)
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "w") as fh:
                    fh.write(body)
            return scan_path(d)

    def test_python_requirements(self):
        r = self._scan({"requirements.txt": "django==5.0\npycrypto==2.6.1\nrsa>=4.9\n# ecdsa\ncryptography\n"})
        ids = {f.rule_id for f in r.findings}
        self.assertIn("QSD001", ids)
        self.assertIn("QSD002", ids)
        self.assertIn("QSD004", ids)
        self.assertNotIn("QSD003", ids)  # commented out

    def test_python_no_false_match(self):
        r = self._scan({"requirements.txt": "rsa-tools==1.0\ncryptography-extras\n"})
        self.assertEqual([f.rule_id for f in r.findings if f.rule_id.startswith("QSD")], [])

    def test_npm_and_pqc(self):
        body = '{"dependencies": {"crypto-js": "^4.2.0", "@noble/post-quantum": "0.2.0", "express": "4"}}'
        r = self._scan({"package.json": body})
        cats = {f.rule_id: f.category for f in r.findings}
        self.assertEqual(cats.get("QSD101"), "classical")
        self.assertEqual(cats.get("QSD109"), "pqc")

    def test_go_maven_cargo(self):
        r = self._scan({
            "go.mod": "module x\n\nrequire (\n\tgolang.org/x/crypto v0.21.0\n)\n",
            "pom.xml": "<artifactId>bcprov-jdk18on</artifactId>",
            "Cargo.toml": "[dependencies]\nrsa = \"0.9\"\n",
        })
        ids = {f.rule_id for f in r.findings}
        self.assertTrue({"QSD201", "QSD401", "QSD301"} <= ids)


class LockfileTests(unittest.TestCase):
    """v0.3: lockfiles give versions and transitive dependencies."""

    def _scan(self, files):
        with tempfile.TemporaryDirectory() as d:
            for name, body in files.items():
                p = os.path.join(d, name)
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "w") as fh:
                    fh.write(body)
            return scan_path(d)

    def _by_id(self, result):
        return {f.rule_id: f for f in result.findings if f.rule_id.startswith("QSD")}

    NPM_LOCK_V3 = (
        '{\n  "name": "app",\n  "lockfileVersion": 3,\n  "packages": {\n'
        '    "": {\n      "name": "app",\n      "dependencies": {\n        "jsonwebtoken": "^9.0.0"\n      }\n    },\n'
        '    "node_modules/jsonwebtoken": {\n      "version": "9.0.2",\n      "dependencies": {\n        "jws": "^3.2.2"\n      }\n    },\n'
        '    "node_modules/browserify-sign/node_modules/elliptic": {\n      "version": "6.5.4"\n    }\n  }\n}\n'
    )

    def test_npm_lock_transitive_and_locked(self):
        r = self._scan({
            "package.json": '{"dependencies": {"jsonwebtoken": "^9.0.0"}}',
            "package-lock.json": self.NPM_LOCK_V3,
        })
        lock = {f.rule_id: f for f in r.findings if f.file == "package-lock.json"}
        self.assertIn("QSD103", lock)  # elliptic, nested
        self.assertTrue(lock["QSD103"].title.endswith("(transitive)"))
        self.assertEqual(lock["QSD103"].snippet, "elliptic 6.5.4")
        self.assertTrue(lock["QSD106"].title.endswith("(locked)"))  # also in package.json
        self.assertEqual(lock["QSD106"].snippet, "jsonwebtoken 9.0.2")

    def test_npm_lock_ignores_dependency_ranges(self):
        # "requires"/"dependencies" maps inside a package are ranges, not installs
        r = self._scan({"package-lock.json": self.NPM_LOCK_V3.replace('"jws"', '"node-rsa"')})
        self.assertNotIn("QSD102", self._by_id(r))

    def test_yarn_classic_and_berry(self):
        classic = (
            '# yarn lockfile v1\n\n'
            '"@noble/curves@^1.2.0", "@noble/curves@~1.2.0":\n  version "1.2.0"\n  resolved "x"\n\n'
            'crypto-js@^4.1.1:\n  version "4.2.0"\n'
        )
        berry = '__metadata:\n  version: 6\n\n"node-rsa@npm:^1.1.1":\n  version: 1.1.1\n  resolution: "node-rsa@npm:1.1.1"\n'
        ids = set(self._by_id(self._scan({"a/yarn.lock": classic, "b/yarn.lock": berry})))
        self.assertTrue({"QSD108", "QSD101", "QSD102"} <= ids)

    def test_pnpm_lock(self):
        body = (
            "lockfileVersion: '9.0'\n\npackages:\n\n"
            "  '@noble/post-quantum@0.2.1':\n    resolution: {integrity: sha512-x}\n\n"
            "  elliptic@6.5.7:\n    resolution: {integrity: sha512-y}\n"
        )
        f = self._by_id(self._scan({"pnpm-lock.yaml": body}))
        self.assertEqual(f["QSD109"].category, "pqc")
        self.assertEqual(f["QSD103"].snippet, "elliptic 6.5.7")

    def test_poetry_and_uv_normalise_names(self):
        poetry = '[[package]]\nname = "PyCrypto"\nversion = "2.6.1"\n\n[[package]]\nname = "liboqs_python"\nversion = "0.10.0"\n'
        f = self._by_id(self._scan({"poetry.lock": poetry}))
        self.assertEqual(f["QSD001"].severity, "high")
        self.assertTrue(f["QSD001"].title.endswith("(transitive)"))
        self.assertIn("QSD011", f)

    def test_pipfile_and_composer_lock(self):
        pipfile = '{"default": {"ecdsa": {"hashes": ["sha256:abc"], "version": "==0.18.0"}}, "develop": {}}'
        composer = '{"packages": [{"name": "phpseclib/phpseclib", "version": "3.0.37"}], "packages-dev": []}'
        f = self._by_id(self._scan({"Pipfile.lock": pipfile, "composer.lock": composer}))
        self.assertEqual(f["QSD003"].snippet, "ecdsa 0.18.0")
        self.assertEqual(f["QSD601"].snippet, "phpseclib/phpseclib 3.0.37")

    def test_cargo_go_gem_gradle(self):
        f = self._by_id(self._scan({
            "Cargo.lock": 'version = 3\n\n[[package]]\nname = "p256"\nversion = "0.13.2"\n',
            "go.sum": "github.com/golang-jwt/jwt/v5 v5.2.1 h1:abc=\ngithub.com/golang-jwt/jwt/v5 v5.2.1/go.mod h1:def=\n",
            "Gemfile.lock": "GEM\n  specs:\n    jwt (2.8.1)\n      base64\n\nPLATFORMS\n  ruby\n",
            "gradle.lockfile": "org.bouncycastle:bcprov-jdk18on:1.78=runtimeClasspath\nempty=\n",
        }))
        self.assertEqual(f["QSD304"].snippet, "p256 0.13.2")
        self.assertEqual(f["QSD202"].snippet, "github.com/golang-jwt/jwt/v5 v5.2.1")
        self.assertEqual(f["QSD501"].snippet, "jwt 2.8.1")
        self.assertIn("QSD401", f)

    def test_lockfile_hashes_do_not_trigger_source_rules(self):
        body = '{\n  "packages": {\n    "node_modules/left-pad": {\n      "version": "1.3.0",\n      "integrity": "sha1-md5RSA-DSA"\n    }\n  }\n}\n'
        r = self._scan({"package-lock.json": body})
        self.assertEqual(r.findings, [])

    def test_malformed_lockfile_is_skipped(self):
        r = self._scan({"Pipfile.lock": "{not json", "composer.lock": "[]"})
        self.assertEqual(r.findings, [])


class V04RuleTests(unittest.TestCase):
    """v0.4: rules derived from the ShorList catalogue, PEM decoding, not-a-use filter."""

    def ids(self, text, name="x.txt"):
        return {f.rule_id for f in scan_text(text, name)}

    def test_tls_suites_and_groups(self):
        self.assertIn("QS012", self.ids('CIPHER_SUITE = "TLS_RSA_WITH_AES_256_GCM_SHA384"\n'))
        self.assertIn("QS013", self.ids('CIPHER_SUITE = "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"\n'))
        self.assertIn("QS013", self.ids('TLS_GROUP = "ffdhe2048"\n'))
        self.assertIn("QS015", self.ids('TLS_GROUP = "brainpoolP256r1"\n'))

    def test_oids(self):
        self.assertIn("QS012", self.ids('RSA_PSS = "1.2.840.113549.1.1.10"\n'))
        self.assertIn("QS015", self.ids('CURVE = "1.3.132.0.34"\n'))
        self.assertIn("QS016", self.ids('ED25519 = "1.3.101.112"\n'))
        self.assertIn("QS101", self.ids('ML_KEM_768 = "2.16.840.1.101.3.4.4.2"\n'))

    def test_ml_dsa_is_not_dsa(self):
        ids = self.ids("CK_KEY_TYPE keyType = CKK_ML_DSA;\n")
        self.assertNotIn("QS014", ids)
        self.assertTrue({"QS100", "QS101"} & ids)
        self.assertIn("QS014", self.ids("CK_KEY_TYPE keyType = CKK_DSA;\n"))

    def test_weak_ciphers(self):
        self.assertIn("QS017", self.ids('cipher = "DES-EDE3-CBC"\n'))
        self.assertIn("QS017", self.ids("ssl_ciphers RC4-SHA;\n"))

    def test_comments_and_removals_are_not_uses(self):
        self.assertEqual(self.ids("# Removed in v3: rsa.generate_private_key(key_size=2048)\n"), set())
        self.assertEqual(self.ids('ENABLED = {"Ed448": False}\n'), set())
        self.assertEqual(self.ids('logging.warning("peer offered ecdsa_secp256r1_sha256; rejected by policy")\n'), set())
        self.assertEqual(self.ids('SSL_CTX_set1_groups_list(ctx, "DEFAULT:-X25519MLKEM768");\n'), set())
        # C preprocessor directives are uses, not comments
        self.assertIn("QS015", self.ids("#define MBEDTLS_ECP_DP_SECP256R1_ENABLED\n"))

    def test_committed_key_still_reported_in_comment_context(self):
        self.assertIn("QS011", self.ids("# -----BEGIN RSA PRIVATE KEY-----\n"))

    PEM_ED25519 = '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA4ozyO8CexJ40WkpGIRUhiMsSEKwBQKotGPsOJo7Gvr0=\n-----END PUBLIC KEY-----\n'
    PEM_EC_CERT = '-----BEGIN CERTIFICATE-----\nMIIBdDCCARmgAwIBAgIUTYzowLc309oes1kMfmpVcr0xEPowCgYIKoZIzj0EAwIw\nDzENMAsGA1UEAwwEdGVzdDAeFw0yNjExMTQwNDA1MDZaFw0yNjExMTUwNDA1MDZa\nMA8xDTALBgNVBAMMBHRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQB0p9q\nB9lLStHbITO9eA3fb8PxGZaoBVAnva5ZMMBzs+mzTeVKwZCtJP6vcUPBk/dcHr/3\nDQhSV1QMORMy/Bnso1MwUTAdBgNVHQ4EFgQUwW3jY/n6iujMqWff/knh1wjuUggw\nHwYDVR0jBBgwFoAUwW3jY/n6iujMqWff/knh1wjuUggwDwYDVR0TAQH/BAUwAwEB\n/zAKBggqhkjOPQQDAgNJADBGAiEAvBRGznKMTsoHqHs68z80fBQG0/qyF0nntR20\nvsBkkjMCIQCISBnE//nUfHcvWNBBH0zEUWFjVESBRNGI//7g0kQkBA==\n-----END CERTIFICATE-----\n'
    PEM_RSA_PUB = '-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDyv0e7Py8ZN4oSDjW41Bs5cAP4\nKQfxO1U60HG8PtkvxmkCbdCQhX8hPsHCBjUv/8jJuJGIaXF3mj9AQLgaprqZpPdd\nJhCWyXWDZhaONx2JEjTFf2eSS7dIKZwEVKxgAfc/E5A6kQLmX2BB1NEfHHN15O6+\nwBUSA85etGXfSs0VKwIDAQAB\n-----END PUBLIC KEY-----\n'

    def _pem(self, text):
        return [(f.line, f.title) for f in scan_text(text, "k.pem") if f.rule_id == "QS018"]

    def test_generic_pem_labels_are_decoded(self):
        self.assertEqual(self._pem(self.PEM_ED25519), [(1, "EdDSA key inside PEM block (PUBLIC KEY)")])
        self.assertEqual(self._pem(self.PEM_RSA_PUB), [(1, "RSA key inside PEM block (PUBLIC KEY)")])
        # certificates report the signature algorithm and the subject key separately
        self.assertEqual(self._pem(self.PEM_EC_CERT), [(1, "ECDSA certificate signature inside PEM block (CERTIFICATE)"),
                                                       (1, "EC certificate subject key inside PEM block (CERTIFICATE)")])

    def test_pem_line_number_inside_file(self):
        text = "config:\n  key: |\n" + self.PEM_ED25519
        self.assertEqual(self._pem(text)[0][0], 3)
