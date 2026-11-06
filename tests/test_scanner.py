import contextlib
import io
import json
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
