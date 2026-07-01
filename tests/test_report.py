"""Report formatting tests for ShareClean."""

from __future__ import annotations

import json
import unittest

from shareclean.detectors import get_rules
from shareclean.redactor import sanitize
from shareclean.report import format_brief_count, format_json_report, format_text_report


class TestJsonReportSchema(unittest.TestCase):
    def test_json_report_uses_versioned_schema(self) -> None:
        result = sanitize("password=fake-secret-value", get_rules())
        data = json.loads(format_json_report(result, "C:/Users/Fake/app.log"))
        self.assertEqual(data["schema_version"], "1.0")
        self.assertEqual(data["source"], "file")
        self.assertEqual(data["summary"]["findings"], 1)
        self.assertEqual(data["summary"]["by_category"], {"credential": 1})
        self.assertEqual(data["summary"]["by_severity"], {"high": 1})

    def test_json_finding_has_safe_metadata_and_location(self) -> None:
        result = sanitize("password=fake-secret-value", get_rules())
        data = json.loads(format_json_report(result, "stdin"))
        finding = data["findings"][0]
        self.assertEqual(finding["rule_id"], "SC001")
        self.assertEqual(finding["category"], "credential")
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["replacement"], "[REDACTED]")
        self.assertEqual(
            finding["location"],
            {
                "start": {"line": 1, "column": 10},
                "end": {"line": 1, "column": 27},
            },
        )

    def test_json_report_does_not_expose_source_names_or_secrets(self) -> None:
        secret = "fake-secret-value-for-json-test"
        path = "C:/Users/FakeUser/internal-project/app.log"
        result = sanitize(f"password={secret}", get_rules())
        report = format_json_report(result, path)
        self.assertNotIn(secret, report)
        self.assertNotIn("FakeUser", report)
        self.assertNotIn("internal-project", report)
        self.assertNotIn("app.log", report)

    def test_empty_json_report_schema(self) -> None:
        data = json.loads(format_json_report(sanitize("safe", get_rules()), "stdin"))
        self.assertEqual(data["source"], "stdin")
        self.assertEqual(data["summary"]["findings"], 0)
        self.assertEqual(data["findings"], [])


class TestTextReport(unittest.TestCase):
    def test_text_report_uses_safe_source_label(self) -> None:
        result = sanitize("email=user@example.com", get_rules())
        report = format_text_report(result, "C:/Users/Fake/app.log")
        self.assertIn("Source: file", report)
        self.assertNotIn("app.log", report)
        self.assertNotIn("user@example.com", report)
        self.assertIn("SC005 pii_email medium", report)

    def test_text_report_for_empty_result(self) -> None:
        report = format_text_report(sanitize("safe", get_rules()), "stdin")
        self.assertIn("Source: stdin", report)
        self.assertIn("Findings: 0", report)


class TestBriefCount(unittest.TestCase):
    def test_brief_count(self) -> None:
        self.assertEqual(
            format_brief_count(sanitize("password=fake", get_rules())),
            "1 replacement(s) made.",
        )


if __name__ == "__main__":
    unittest.main()
