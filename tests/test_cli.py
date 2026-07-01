"""CLI integration tests for ShareClean v0.2.0."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from io import StringIO
from unittest.mock import patch


def run_cli(*args: str, stdin_text: str | None = None) -> tuple[int, str, str]:
    argv = ["shareclean"] + list(args)
    stdin = StringIO(stdin_text or "")
    stdout = StringIO()
    stderr = StringIO()

    with (
        patch("sys.argv", argv),
        patch("sys.stdin", stdin),
        patch("sys.stdout", stdout),
        patch("sys.stderr", stderr),
    ):
        from shareclean.cli import main  # noqa: PLC0415

        exit_code = main()

    return exit_code, stdout.getvalue(), stderr.getvalue()


def _write_tempfile(content: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)
    return path


class TestVersionFlag(unittest.TestCase):
    def test_version_flag_prints_version(self) -> None:
        stdout = StringIO()
        stderr = StringIO()
        with (
            patch("sys.argv", ["shareclean", "--version"]),
            patch("sys.stdout", stdout),
            patch("sys.stderr", stderr),
        ):
            from shareclean.cli import main  # noqa: PLC0415

            with self.assertRaises(SystemExit) as ctx:
                main()
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("shareclean 0.2.0", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")


class TestNormalMode(unittest.TestCase):
    def test_sanitized_text_written_to_stdout(self) -> None:
        path = _write_tempfile("password=fake-secret-value\n")
        try:
            code, out, err = run_cli(path)
            self.assertEqual(code, 0)
            self.assertIn("password=[REDACTED]", out)
            self.assertNotIn("fake-secret-value", out)
            self.assertIn("replacement(s) made", err)
        finally:
            os.unlink(path)

    def test_output_writes_sanitized_content_to_new_file(self) -> None:
        input_path = _write_tempfile("api_key=fake-api-key\n")
        fd, output_path = tempfile.mkstemp(suffix=".txt")
        os.close(fd)
        try:
            code, out, _err = run_cli("--output", output_path, input_path)
            self.assertEqual(code, 0)
            self.assertEqual(out, "")
            with open(output_path, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "api_key=[REDACTED]\n")
        finally:
            os.unlink(input_path)
            os.unlink(output_path)

    def test_missing_file_exits_2(self) -> None:
        code, out, err = run_cli("/nonexistent/path/to/missing_file.txt")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("File not found", err)


class TestRedactionFlags(unittest.TestCase):
    def test_no_email_alias_disables_email_detection(self) -> None:
        path = _write_tempfile("Contact: user@example.com\n")
        try:
            code, out, _err = run_cli("--no-email", path)
            self.assertEqual(code, 0)
            self.assertIn("user@example.com", out)
        finally:
            os.unlink(path)

    def test_redact_email_reenables_after_config_or_env(self) -> None:
        path = _write_tempfile("Contact: user@example.com\n")
        try:
            with patch.dict(os.environ, {"SHARECLEAN_REDACT_EMAIL": "false"}):
                code, out, _err = run_cli("--redact-email", path)
            self.assertEqual(code, 0)
            self.assertIn("[EMAIL REDACTED]", out)
        finally:
            os.unlink(path)

    def test_redact_private_ip_flag(self) -> None:
        path = _write_tempfile("Server: 192.168.1.50\n")
        try:
            code, out, _err = run_cli("--redact-private-ip", path)
            self.assertEqual(code, 0)
            self.assertIn("[PRIVATE-IP]", out)
        finally:
            os.unlink(path)

    def test_custom_redaction_label_in_json_report(self) -> None:
        path = _write_tempfile("api_key=fake-api-key-value\n")
        try:
            code, _out, err = run_cli(
                "--redaction-label",
                "[REMOVED]",
                "--report",
                "--report-format",
                "json",
                path,
            )
            self.assertEqual(code, 0)
            data = json.loads(err)
            self.assertEqual(data["findings"][0]["replacement"], "[REMOVED]")
        finally:
            os.unlink(path)


class TestJsonReport(unittest.TestCase):
    def test_json_report_uses_v1_schema_and_safe_source(self) -> None:
        path = _write_tempfile("password=fake-secret-value\n")
        try:
            code, _out, err = run_cli("--report", "--report-format", "json", path)
            self.assertEqual(code, 0)
            data = json.loads(err)
            self.assertEqual(data["schema_version"], "1.0")
            self.assertEqual(data["source"], "file")
            self.assertEqual(data["summary"]["findings"], 1)
            self.assertEqual(data["findings"][0]["rule_id"], "SC001")
            self.assertIn("location", data["findings"][0])
            self.assertNotIn(os.path.basename(path), err)
            self.assertNotIn("fake-secret-value", err)
        finally:
            os.unlink(path)


class TestCheckMode(unittest.TestCase):
    def test_default_check_exits_1_for_any_finding(self) -> None:
        path = _write_tempfile("email=user@example.com\n")
        try:
            code, out, err = run_cli("--check", path)
            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertIn("check-failing", err)
        finally:
            os.unlink(path)

    def test_fail_on_severity_high_ignores_medium_email(self) -> None:
        path = _write_tempfile("email=user@example.com\n")
        try:
            code, out, _err = run_cli("--check", "--fail-on", "severity:high", path)
            self.assertEqual(code, 0)
            self.assertEqual(out, "")
        finally:
            os.unlink(path)

    def test_fail_on_category_token_fails_for_bearer(self) -> None:
        path = _write_tempfile("Authorization: Bearer fake-token\n")
        try:
            code, _out, _err = run_cli("--check", "--fail-on", "category:token", path)
            self.assertEqual(code, 1)
        finally:
            os.unlink(path)

    def test_ignore_for_check_does_not_disable_redaction_decision_only(self) -> None:
        path = _write_tempfile("email=user@example.com\n")
        try:
            code, _out, _err = run_cli(
                "--check",
                "--ignore-for-check",
                "category:pii_email",
                path,
            )
            self.assertEqual(code, 0)
        finally:
            os.unlink(path)

    def test_invalid_selector_exits_2(self) -> None:
        path = _write_tempfile("password=fake\n")
        try:
            code, _out, err = run_cli("--check", "--fail-on", "category:nope", path)
            self.assertEqual(code, 2)
            self.assertIn("Unknown category", err)
        finally:
            os.unlink(path)

    def test_selector_flags_require_check(self) -> None:
        path = _write_tempfile("password=fake\n")
        try:
            code, _out, err = run_cli("--fail-on", "severity:high", path)
            self.assertEqual(code, 2)
            self.assertIn("require --check", err)
        finally:
            os.unlink(path)


class TestConfigShow(unittest.TestCase):
    def test_config_show_reads_no_input_and_requires_no_file(self) -> None:
        code, out, err = run_cli("config", "show", stdin_text="password=fake\n")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertTrue(data["redact_email"])
        self.assertEqual(data["profile"], "default")
        self.assertEqual(err, "")


if __name__ == "__main__":
    unittest.main()
