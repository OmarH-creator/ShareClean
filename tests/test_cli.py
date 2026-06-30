"""CLI integration tests for ShareClean.

Tests the full pipeline by calling main() directly with patched sys.argv,
sys.stdin, sys.stdout, and sys.stderr.  All test inputs use clearly fake /
synthetic values.

Coverage:
- --check exits 1 with findings, 0 without findings, no stdout in either case
- --output writes sanitized content to new file, leaves original unmodified
- --no-email disables email detection (email passes through unchanged)
- --redact-private-ip enables private IP redaction
- Missing input file → exit code 2 + error on stderr
- --report-format json --report → valid JSON on stderr
- Normal mode → sanitized text on stdout, brief count on stderr

Requirements: 11.1, 11.2, 11.3, 15.4, 15.5
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from io import StringIO
from unittest.mock import patch

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def run_cli(*args: str, stdin_text: str | None = None) -> tuple[int, str, str]:
    """Invoke shareclean.cli.main() with the given CLI arguments.

    Returns (exit_code, stdout_content, stderr_content).
    Patches sys.argv, sys.stdin, sys.stdout, and sys.stderr for isolation.
    """
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
        # Import inside the context so the module picks up the patched streams
        # on every call (the module is already cached after first import, but
        # main() reads sys.stdout / sys.stderr at call time, not import time).
        from shareclean.cli import main  # noqa: PLC0415

        exit_code = main()

    return exit_code, stdout.getvalue(), stderr.getvalue()


def _write_tempfile(content: str) -> str:
    """Write *content* to a temporary file and return its path.

    The caller is responsible for deleting the file when done.
    """
    fd, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


# ---------------------------------------------------------------------------
# --version flag
# ---------------------------------------------------------------------------

class TestVersionFlag(unittest.TestCase):
    """--version prints the installed ShareClean version and exits cleanly."""

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
        self.assertIn("shareclean 0.1.0", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")


# ---------------------------------------------------------------------------
# --check mode
# ---------------------------------------------------------------------------

class TestCheckMode(unittest.TestCase):
    """--check flag: exit codes and stdout suppression (Req 11.1, 11.2, 11.3)."""

    def test_check_exits_1_when_finding_present(self) -> None:
        """--check must exit 1 when sensitive content is detected."""
        path = _write_tempfile("password=fake-secret-value\n")
        try:
            code, _out, _err = run_cli("--check", path)
            self.assertEqual(code, 1)
        finally:
            os.unlink(path)

    def test_check_exits_0_when_no_findings(self) -> None:
        """--check must exit 0 when no sensitive content is found."""
        path = _write_tempfile("This log line contains nothing sensitive.\n")
        try:
            code, _out, _err = run_cli("--check", path)
            self.assertEqual(code, 0)
        finally:
            os.unlink(path)

    def test_check_does_not_write_sanitized_text_to_stdout_with_findings(self) -> None:
        """Sanitized text must NOT appear on stdout in --check mode (finding present)."""
        path = _write_tempfile("api_key=fake-api-key-abc123\n")
        try:
            _code, out, _err = run_cli("--check", path)
            self.assertEqual(out, "", msg="stdout must be empty in --check mode")
        finally:
            os.unlink(path)

    def test_check_does_not_write_sanitized_text_to_stdout_when_clean(self) -> None:
        """stdout must remain empty in --check mode even when input is clean."""
        path = _write_tempfile("Just a normal log line.\n")
        try:
            _code, out, _err = run_cli("--check", path)
            self.assertEqual(out, "", msg="stdout must be empty in --check mode")
        finally:
            os.unlink(path)

    def test_check_prints_summary_to_stderr(self) -> None:
        """--check must print a concise finding summary to stderr."""
        path = _write_tempfile("token=fake-token-xyz\n")
        try:
            _code, _out, err = run_cli("--check", path)
            self.assertTrue(err.strip(), msg="stderr must not be empty in --check mode")
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# --output flag
# ---------------------------------------------------------------------------

class TestOutputFlag(unittest.TestCase):
    """--output writes to a new file; original file is left unmodified (Req 15.5)."""

    def test_output_writes_sanitized_content_to_new_file(self) -> None:
        """Sanitized content must be written to the --output file."""
        original_content = "password=fake-secret-value\n"
        input_path = _write_tempfile(original_content)
        fd, output_path = tempfile.mkstemp(suffix=".txt")
        os.close(fd)
        # Pre-clear the output file so we know the tool wrote to it
        open(output_path, "w").close()  # noqa: WPS515

        try:
            code, _out, _err = run_cli("--output", output_path, input_path)
            self.assertEqual(code, 0)

            with open(output_path, encoding="utf-8") as fh:
                sanitized = fh.read()

            # The password value must have been redacted
            self.assertNotIn("fake-secret-value", sanitized)
            self.assertIn("[REDACTED]", sanitized)
        finally:
            os.unlink(input_path)
            os.unlink(output_path)

    def test_output_leaves_original_file_unmodified(self) -> None:
        """The original input file must not be altered when --output is used."""
        original_content = "password=fake-secret-value\n"
        input_path = _write_tempfile(original_content)
        fd, output_path = tempfile.mkstemp(suffix=".txt")
        os.close(fd)

        try:
            run_cli("--output", output_path, input_path)

            with open(input_path, encoding="utf-8") as fh:
                after = fh.read()

            self.assertEqual(
                after,
                original_content,
                msg="Original file must not be modified when --output is used.",
            )
        finally:
            os.unlink(input_path)
            os.unlink(output_path)

    def test_output_exits_0_on_success(self) -> None:
        """Normal --output run must exit 0."""
        input_path = _write_tempfile("no secrets here\n")
        fd, output_path = tempfile.mkstemp(suffix=".txt")
        os.close(fd)

        try:
            code, _out, _err = run_cli("--output", output_path, input_path)
            self.assertEqual(code, 0)
        finally:
            os.unlink(input_path)
            os.unlink(output_path)

    def test_output_does_not_write_sanitized_text_to_stdout(self) -> None:
        """When --output is used, sanitized text must not go to stdout."""
        input_path = _write_tempfile("password=fake-pass\n")
        fd, output_path = tempfile.mkstemp(suffix=".txt")
        os.close(fd)

        try:
            _code, out, _err = run_cli("--output", output_path, input_path)
            self.assertEqual(out, "", msg="stdout must be empty when --output is used")
        finally:
            os.unlink(input_path)
            os.unlink(output_path)


# ---------------------------------------------------------------------------
# --no-email flag
# ---------------------------------------------------------------------------

class TestNoEmailFlag(unittest.TestCase):
    """--no-email disables email detection (Req 5.3, 11.3)."""

    def test_no_email_does_not_redact_email_address(self) -> None:
        """With --no-email, email addresses must pass through unchanged."""
        email = "user@example.com"
        path = _write_tempfile(f"Contact: {email}\n")
        try:
            _code, out, _err = run_cli("--no-email", path)
            self.assertIn(email, out, msg="Email should NOT be redacted with --no-email")
        finally:
            os.unlink(path)

    def test_no_email_produces_no_email_finding(self) -> None:
        """--no-email run on email-only input must exit 0 (no findings)."""
        path = _write_tempfile("Contact: user@example.com\n")
        try:
            code, _out, _err = run_cli("--check", "--no-email", path)
            self.assertEqual(code, 0, msg="--no-email should suppress email findings")
        finally:
            os.unlink(path)

    def test_without_no_email_email_is_redacted(self) -> None:
        """Without --no-email, email addresses are redacted by default."""
        path = _write_tempfile("Contact: user@example.com\n")
        try:
            _code, out, _err = run_cli(path)
            self.assertNotIn(
                "user@example.com",
                out,
                msg="Email should be redacted by default",
            )
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# --redact-private-ip flag
# ---------------------------------------------------------------------------

class TestRedactPrivateIpFlag(unittest.TestCase):
    """--redact-private-ip enables RFC 1918 address detection (Req 7.1, 7.3)."""

    def test_redact_private_ip_redacts_address(self) -> None:
        """With --redact-private-ip, private IP addresses must be redacted."""
        path = _write_tempfile("Server address: 192.168.1.50\n")
        try:
            _code, out, _err = run_cli("--redact-private-ip", path)
            self.assertNotIn(
                "192.168.1.50",
                out,
                msg="Private IP must be redacted with --redact-private-ip",
            )
            self.assertIn("[PRIVATE-IP]", out)
        finally:
            os.unlink(path)

    def test_without_redact_private_ip_address_passes_through(self) -> None:
        """Without --redact-private-ip, private IP addresses are left unchanged."""
        path = _write_tempfile("Server address: 10.0.0.1\n")
        try:
            _code, out, _err = run_cli(path)
            self.assertIn(
                "10.0.0.1",
                out,
                msg="Private IP must NOT be redacted unless --redact-private-ip is set",
            )
        finally:
            os.unlink(path)

    def test_redact_private_ip_exits_0(self) -> None:
        """--redact-private-ip run should still exit 0 after sanitizing."""
        path = _write_tempfile("addr: 172.16.0.5\n")
        try:
            code, _out, _err = run_cli("--redact-private-ip", path)
            self.assertEqual(code, 0)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Missing file → exit code 2
# ---------------------------------------------------------------------------

class TestMissingFileError(unittest.TestCase):
    """Missing input file must produce exit code 2 with an error on stderr."""

    def test_missing_file_exits_2(self) -> None:
        """A file path that does not exist must yield exit code 2."""
        code, _out, _err = run_cli("/nonexistent/path/to/missing_file.txt")
        self.assertEqual(code, 2)

    def test_missing_file_prints_error_to_stderr(self) -> None:
        """Error message about the missing file must appear on stderr."""
        _code, _out, err = run_cli("/nonexistent/path/to/missing_file.txt")
        self.assertTrue(
            err.strip(),
            msg="An error message must be printed to stderr for missing file",
        )

    def test_missing_file_no_stdout_output(self) -> None:
        """No content must be written to stdout when the input file is missing."""
        _code, out, _err = run_cli("/nonexistent/path/to/missing_file.txt")
        self.assertEqual(out, "")


# ---------------------------------------------------------------------------
# --report-format json
# ---------------------------------------------------------------------------

class TestJsonReport(unittest.TestCase):
    """--report-format json --report must emit valid JSON to stderr (Req 10.5)."""

    def test_json_report_is_valid_json(self) -> None:
        """stderr must contain parseable JSON when --report-format json is used."""
        path = _write_tempfile("password=fake-secret-value\n")
        try:
            _code, _out, err = run_cli("--report", "--report-format", "json", path)
            # There may be a brief-count line too; find the JSON object
            parsed = json.loads(err)
            self.assertIsInstance(parsed, dict)
        finally:
            os.unlink(path)

    def test_json_report_has_required_fields(self) -> None:
        """JSON report must contain input_name, finding_count, and findings."""
        path = _write_tempfile("api_key=fake-api-key-xyz\n")
        try:
            _code, _out, err = run_cli("--report", "--report-format", "json", path)
            data = json.loads(err)
            self.assertIn("input_name", data)
            self.assertIn("finding_count", data)
            self.assertIn("findings", data)
            self.assertIsInstance(data["findings"], list)
        finally:
            os.unlink(path)

    def test_json_report_finding_count_is_accurate(self) -> None:
        """finding_count in JSON must equal the number of findings."""
        path = _write_tempfile("token=fake-token-abc\n")
        try:
            _code, _out, err = run_cli("--report", "--report-format", "json", path)
            data = json.loads(err)
            self.assertEqual(data["finding_count"], len(data["findings"]))
        finally:
            os.unlink(path)

    def test_json_report_does_not_contain_raw_secret(self) -> None:
        """JSON report must never include the original sensitive value."""
        secret = "fake-secret-value-for-json-test"
        path = _write_tempfile(f"password={secret}\n")
        try:
            _code, _out, err = run_cli("--report", "--report-format", "json", path)
            self.assertNotIn(secret, err)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Normal mode (no special flags)
# ---------------------------------------------------------------------------

class TestNormalMode(unittest.TestCase):
    """Without special flags: sanitized text on stdout, brief count on stderr."""

    def test_sanitized_text_written_to_stdout(self) -> None:
        """Normal mode must write the full sanitized text to stdout."""
        path = _write_tempfile("password=fake-secret-value\n")
        try:
            _code, out, _err = run_cli(path)
            self.assertTrue(out, msg="stdout must not be empty in normal mode")
        finally:
            os.unlink(path)

    def test_sensitive_value_not_in_stdout(self) -> None:
        """The raw sensitive value must not appear in stdout after sanitization."""
        path = _write_tempfile("api_key=fake-api-key-normal-mode\n")
        try:
            _code, out, _err = run_cli(path)
            self.assertNotIn("fake-api-key-normal-mode", out)
            self.assertIn("[REDACTED]", out)
        finally:
            os.unlink(path)

    def test_brief_count_written_to_stderr(self) -> None:
        """Normal mode must print the brief replacement count to stderr."""
        path = _write_tempfile("password=fake-pass\n")
        try:
            _code, _out, err = run_cli(path)
            self.assertIn("replacement(s) made", err)
        finally:
            os.unlink(path)

    def test_clean_input_passes_through_verbatim(self) -> None:
        """Input with no sensitive content must be written to stdout unchanged.

        We compare the text content after normalising line endings, because
        tempfile on Windows may write \\r\\n while the in-memory string uses \\n.
        The important guarantee is that no characters are added or removed by
        the sanitizer — not the specific line-ending byte sequence.
        """
        content = "This is a perfectly normal log line.\n"
        path = _write_tempfile(content)
        try:
            _code, out, _err = run_cli(path)
            # Normalise line endings for cross-platform comparison
            self.assertEqual(
                out.replace("\r\n", "\n"),
                content,
                msg="Clean input must pass through unchanged (line-endings normalised)",
            )
        finally:
            os.unlink(path)

    def test_normal_mode_exits_0(self) -> None:
        """Normal mode must exit 0 regardless of whether findings are present."""
        path = _write_tempfile("password=fake-pass\n")
        try:
            code, _out, _err = run_cli(path)
            self.assertEqual(code, 0)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
