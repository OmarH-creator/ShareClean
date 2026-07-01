"""Redactor tests for ShareClean v0.2.0."""

from __future__ import annotations

from pathlib import Path
import unittest

from shareclean.detectors import get_rules
from shareclean.redactor import sanitize

FIXTURE_DIR = Path(__file__).parent / "fixtures"


class TestSanitizeBasics(unittest.TestCase):
    def test_empty_input(self) -> None:
        result = sanitize("", get_rules())
        self.assertEqual(result.cleaned_text, "")
        self.assertEqual(result.findings, [])

    def test_line_endings_are_preserved(self) -> None:
        text = "safe\r\npassword=fake-pass\r\n"
        result = sanitize(text, get_rules())
        self.assertIn("\r\n", result.cleaned_text)
        self.assertEqual(result.cleaned_text, "safe\r\npassword=[REDACTED]\r\n")

    def test_sample_log_matches_expected_cleaned_output(self) -> None:
        sample = (FIXTURE_DIR / "sample_log.txt").read_text(encoding="utf-8")
        expected = (FIXTURE_DIR / "expected_cleaned_log.txt").read_text(
            encoding="utf-8",
        )
        result = sanitize(sample, get_rules())
        self.assertEqual(result.cleaned_text, expected)
        self.assertEqual(result.replacement_count, 6)


class TestFindingMetadata(unittest.TestCase):
    def test_key_value_finding_metadata(self) -> None:
        result = sanitize("password=fake-secret-value", get_rules())
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.rule_id, "SC001")
        self.assertEqual(finding.category, "credential")
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.location.start.line, 1)
        self.assertEqual(finding.location.start.column, 10)
        self.assertEqual(finding.location.end.column, 27)
        self.assertEqual(finding.replacement, "[REDACTED]")

    def test_connection_string_finding_metadata(self) -> None:
        text = "postgresql://fakeuser:fake-pass@db.example.com/mydb"
        result = sanitize(text, get_rules())
        finding = result.findings[0]
        self.assertEqual(finding.rule_id, "SC004")
        self.assertEqual(finding.category, "connection_string")
        self.assertEqual(finding.severity, "critical")
        self.assertEqual(finding.replacement, "[REDACTED]")

    def test_findings_never_store_original_value(self) -> None:
        secret = "fake-super-secret-value"
        result = sanitize(f"password={secret}", get_rules())
        for finding in result.findings:
            self.assertNotIn(secret, repr(finding))


class TestLocationConventions(unittest.TestCase):
    def test_locations_are_one_based_and_end_exclusive(self) -> None:
        result = sanitize("xx password=fake", get_rules())
        finding = result.findings[0]
        self.assertEqual(finding.location.start.line, 1)
        self.assertEqual(finding.location.start.column, 13)
        self.assertEqual(finding.location.end.column, 17)

    def test_crlf_counts_as_one_newline_for_locations(self) -> None:
        result = sanitize("safe\r\npassword=fake", get_rules())
        finding = result.findings[0]
        self.assertEqual(finding.location.start.line, 2)
        self.assertEqual(finding.location.start.column, 10)
        self.assertEqual(finding.location.end.line, 2)
        self.assertEqual(finding.location.end.column, 14)


class TestOverlapHandling(unittest.TestCase):
    def test_bearer_jwt_overlap_uses_bearer_rule(self) -> None:
        jwt = "eyFAKEHEADER1234.eyFAKEPAYLOAD5678.fakeSIGNATURE90"
        result = sanitize(f"Authorization: Bearer {jwt}", get_rules())
        self.assertEqual(result.cleaned_text, "Authorization: Bearer [REDACTED]")
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].rule_id, "SC002")

    def test_jwt_inside_token_value_uses_more_specific_jwt_rule(self) -> None:
        jwt = "eyFAKEHEADER1234.eyFAKEPAYLOAD5678.fakeSIGNATURE90"
        result = sanitize(f"token={jwt}", get_rules())
        self.assertEqual(result.cleaned_text, "token=[JWT REDACTED]")
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].rule_id, "SC003")

    def test_connection_string_password_beats_key_value_overlap(self) -> None:
        text = "secret=postgresql://fakeuser:fake-pass@db.example.com/app"
        result = sanitize(text, get_rules())
        self.assertEqual(
            result.cleaned_text,
            "secret=postgresql://fakeuser:[REDACTED]@db.example.com/app",
        )
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].rule_id, "SC004")


if __name__ == "__main__":
    unittest.main()
