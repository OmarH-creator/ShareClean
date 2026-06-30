"""Unit tests for shareclean/redactor.py.

Tests the sanitize() function for multiline inputs, empty inputs, and
replacement_count accuracy. All test values are clearly fake.
"""

from pathlib import Path
import unittest

from shareclean.detectors import get_rules
from shareclean.models import Finding, SanitizeResult
from shareclean.redactor import sanitize


FIXTURE_DIR = Path(__file__).parent / "fixtures"


class TestSanitizeEmptyInput(unittest.TestCase):
    """Empty string input produces an empty SanitizeResult."""

    def test_empty_string_returns_empty_result(self):
        rules = get_rules()
        result = sanitize("", rules)
        self.assertEqual(result.cleaned_text, "")
        self.assertEqual(result.findings, [])

    def test_empty_string_replacement_count_is_zero(self):
        rules = get_rules()
        result = sanitize("", rules)
        self.assertEqual(result.replacement_count, 0)


class TestSanitizeMultilineInput(unittest.TestCase):
    """Only sensitive lines are modified; surrounding lines are preserved verbatim."""

    def _get_rules(self):
        return get_rules(redact_email=True, redact_private_ip=False)

    def test_only_sensitive_line_is_modified(self):
        text = (
            "INFO: Server starting\n"
            "password=fake-secret-value\n"
            "INFO: Server started on port 8000\n"
        )
        rules = self._get_rules()
        result = sanitize(text, rules)

        lines = result.cleaned_text.splitlines()
        self.assertEqual(lines[0], "INFO: Server starting")
        self.assertIn("password=", lines[1])
        self.assertIn("[REDACTED]", lines[1])
        self.assertNotIn("fake-secret-value", lines[1])
        self.assertEqual(lines[2], "INFO: Server started on port 8000")

    def test_surrounding_lines_preserved_verbatim(self):
        prefix = "DEBUG: initializing connection pool\n"
        secret = "api_key: fake-api-key-12345\n"
        suffix = "DEBUG: pool ready\n"
        text = prefix + secret + suffix
        rules = self._get_rules()
        result = sanitize(text, rules)

        # Split on newlines, stripping to compare content
        lines = result.cleaned_text.split("\n")
        self.assertEqual(lines[0], "DEBUG: initializing connection pool")
        self.assertEqual(lines[2], "DEBUG: pool ready")

    def test_multiple_sensitive_lines_each_redacted(self):
        text = (
            "password=fake-pass-abc\n"
            "clean line here\n"
            "token=fake-token-xyz\n"
        )
        rules = self._get_rules()
        result = sanitize(text, rules)

        self.assertNotIn("fake-pass-abc", result.cleaned_text)
        self.assertNotIn("fake-token-xyz", result.cleaned_text)
        self.assertIn("clean line here", result.cleaned_text)

    def test_no_sensitive_content_returns_verbatim(self):
        text = "Just a normal log line\nNothing to see here\n"
        rules = self._get_rules()
        result = sanitize(text, rules)

        self.assertEqual(result.cleaned_text, text)
        self.assertEqual(result.findings, [])

    def test_line_endings_preserved_crlf(self):
        text = "safe line\r\npassword=fake-pass\r\nanother safe line\r\n"
        rules = self._get_rules()
        result = sanitize(text, rules)

        self.assertIn("\r\n", result.cleaned_text)
        clean_lines = result.cleaned_text.splitlines(keepends=True)
        for line in clean_lines:
            self.assertTrue(line.endswith("\r\n"),
                            f"Expected CRLF endings, got: {line!r}")

    def test_line_numbers_accurate(self):
        text = (
            "INFO: boot sequence\n"
            "INFO: loading config\n"
            "secret=fake-secret-value\n"
            "INFO: config loaded\n"
        )
        rules = self._get_rules()
        result = sanitize(text, rules)

        kv = [f for f in result.findings if f.rule_id == "KEY_VALUE_SECRET"]
        self.assertEqual(len(kv), 1)
        self.assertEqual(kv[0].line_number, 3)


class TestFixtureIntegration(unittest.TestCase):
    """Fixture-based end-to-end coverage for the default redaction rules."""

    def test_sample_log_matches_expected_cleaned_output(self):
        with open(FIXTURE_DIR / "sample_log.txt", encoding="utf-8", newline="") as fh:
            sample = fh.read()
        with open(
            FIXTURE_DIR / "expected_cleaned_log.txt",
            encoding="utf-8",
            newline="",
        ) as fh:
            expected = fh.read()

        result = sanitize(sample, get_rules())

        self.assertEqual(result.cleaned_text, expected)
        self.assertEqual(result.replacement_count, 6)


class TestReplacementCount(unittest.TestCase):
    """replacement_count always equals len(findings)."""

    def test_no_findings(self):
        rules = get_rules()
        result = sanitize("nothing sensitive here", rules)
        self.assertEqual(result.replacement_count, len(result.findings))
        self.assertEqual(result.replacement_count, 0)

    def test_single_finding(self):
        rules = get_rules()
        result = sanitize("password=fake-secret-value", rules)
        self.assertEqual(result.replacement_count, len(result.findings))
        self.assertEqual(result.replacement_count, 1)

    def test_multiple_findings_on_multiple_lines(self):
        text = (
            "password=fake-pass-1\n"
            "api_key=fake-api-key-2\n"
            "token=fake-token-3\n"
        )
        rules = get_rules()
        result = sanitize(text, rules)
        self.assertEqual(result.replacement_count, len(result.findings))
        self.assertEqual(result.replacement_count, 3)

    def test_multiple_findings_on_same_line(self):
        # Two separate key=value patterns on the same line separated by a comma
        text = "password=fake-pass, token=fake-token"
        rules = get_rules()
        result = sanitize(text, rules)
        self.assertEqual(result.replacement_count, len(result.findings))
        self.assertGreaterEqual(result.replacement_count, 2)

    def test_email_and_key_value_both_counted(self):
        text = "email=fake@example.com\npassword=fake-pass"
        rules = get_rules(redact_email=True)
        result = sanitize(text, rules)
        self.assertEqual(result.replacement_count, len(result.findings))

    def test_connection_string_counts_as_one_finding(self):
        text = "postgresql://fakeuser:fake-pass@db.example.com/mydb"
        rules = get_rules()
        result = sanitize(text, rules)
        conn_findings = [f for f in result.findings if f.rule_id == "CONNECTION_STRING"]
        self.assertEqual(len(conn_findings), 1)
        self.assertEqual(result.replacement_count, len(result.findings))


class TestFindingMetadata(unittest.TestCase):
    """Findings carry correct metadata and never expose the raw secret."""

    def test_finding_never_stores_original_value(self):
        secret = "fake-super-secret-value"
        text = f"password={secret}"
        rules = get_rules()
        result = sanitize(text, rules)

        for finding in result.findings:
            self.assertNotIn(secret, finding.rule_id)
            self.assertNotIn(secret, finding.category)
            self.assertNotIn(secret, finding.replacement)

    def test_key_value_finding_metadata(self):
        text = "password=fake-secret-value"
        rules = get_rules()
        result = sanitize(text, rules)

        self.assertEqual(len(result.findings), 1)
        f = result.findings[0]
        self.assertEqual(f.rule_id, "KEY_VALUE_SECRET")
        self.assertEqual(f.line_number, 1)
        # The callable replacement returns key+separator+[REDACTED],
        # so the finding's replacement field is the full replacement string.
        self.assertIn("[REDACTED]", f.replacement)

    def test_connection_string_finding_metadata(self):
        text = "postgresql://fakeuser:fake-pass@db.example.com/mydb"
        rules = get_rules()
        result = sanitize(text, rules)

        conn = [f for f in result.findings if f.rule_id == "CONNECTION_STRING"]
        self.assertEqual(len(conn), 1)
        self.assertEqual(conn[0].line_number, 1)
        self.assertIn("[REDACTED]", conn[0].replacement)


if __name__ == "__main__":
    unittest.main()
