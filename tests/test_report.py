"""Unit tests for report.py formatting functions.

Tests cover:
- format_text_report(): input name, finding count, category labels, line numbers, disclaimer,
  and absence of raw secret values.
- format_json_report(): valid JSON, correct schema fields, and absence of raw secret values.
- format_brief_count(): exact output format "N replacement(s) made."

All test values are clearly fake/synthetic.
"""

import json
import unittest

from shareclean.models import Finding, SanitizeResult
from shareclean.report import format_brief_count, format_json_report, format_text_report


def _make_result_with_findings() -> tuple[SanitizeResult, list[str]]:
    """Return a SanitizeResult with two synthetic findings and the raw secrets used."""
    raw_secrets = ["fake-api-key-value-xyz", "fake-bearer-token-abc"]
    findings = [
        Finding(
            rule_id="KEY_VALUE_SECRET",
            category="Key-value secret",
            line_number=3,
            replacement="[REDACTED]",
        ),
        Finding(
            rule_id="BEARER_TOKEN",
            category="Bearer token",
            line_number=7,
            replacement="[REDACTED]",
        ),
    ]
    result = SanitizeResult(
        cleaned_text="api_key = [REDACTED]\nAuthorization: Bearer [REDACTED]\n",
        findings=findings,
    )
    return result, raw_secrets


class TestFormatTextReport(unittest.TestCase):
    """Tests for format_text_report()."""

    def setUp(self) -> None:
        self.result, self.raw_secrets = _make_result_with_findings()
        self.input_name = "tests/fixtures/fake_log.txt"
        self.report = format_text_report(self.result, self.input_name)

    # --- required content ---

    def test_contains_input_name(self) -> None:
        """Report must include the input name."""
        self.assertIn(self.input_name, self.report)

    def test_contains_finding_count(self) -> None:
        """Report must state the total number of findings."""
        self.assertIn("2", self.report)

    def test_contains_category_labels(self) -> None:
        """Report must include each finding's category label."""
        self.assertIn("Key-value secret", self.report)
        self.assertIn("Bearer token", self.report)

    def test_contains_line_numbers(self) -> None:
        """Report must mention each finding's line number."""
        self.assertIn("3", self.report)
        self.assertIn("7", self.report)

    def test_ends_with_disclaimer(self) -> None:
        """Report must end with the disclaimer text."""
        self.assertTrue(
            self.report.strip().endswith(
                "The original sensitive values are never stored or displayed."
            ),
            msg=f"Report did not end with the expected disclaimer.\nActual tail:\n{self.report[-200:]}",
        )

    # --- privacy guarantee ---

    def test_does_not_contain_raw_secret_values(self) -> None:
        """Raw secret values must never appear in the text report."""
        for secret in self.raw_secrets:
            self.assertNotIn(
                secret,
                self.report,
                msg=f"Raw secret '{secret}' was found in the text report.",
            )

    # --- empty result ---

    def test_empty_result_still_contains_input_name_and_count(self) -> None:
        """Text report for zero findings still shows input name and count."""
        empty = SanitizeResult(cleaned_text="no secrets here\n", findings=[])
        report = format_text_report(empty, "stdin")
        self.assertIn("stdin", report)
        self.assertIn("0", report)

    def test_empty_result_still_ends_with_disclaimer(self) -> None:
        """Disclaimer is present even when there are no findings."""
        empty = SanitizeResult(cleaned_text="", findings=[])
        report = format_text_report(empty, "stdin")
        self.assertTrue(
            report.strip().endswith(
                "The original sensitive values are never stored or displayed."
            )
        )


class TestFormatJsonReport(unittest.TestCase):
    """Tests for format_json_report()."""

    def setUp(self) -> None:
        self.result, self.raw_secrets = _make_result_with_findings()
        self.input_name = "tests/fixtures/fake_log.txt"
        self.json_str = format_json_report(self.result, self.input_name)
        self.data = json.loads(self.json_str)  # will raise if not valid JSON

    # --- valid JSON ---

    def test_output_is_valid_json(self) -> None:
        """Output must be parseable as valid JSON."""
        # json.loads() in setUp would have raised; reaching here means success
        self.assertIsInstance(self.data, dict)

    # --- top-level schema fields ---

    def test_has_input_name_field(self) -> None:
        """JSON object must have 'input_name' matching the provided name."""
        self.assertIn("input_name", self.data)
        self.assertEqual(self.data["input_name"], self.input_name)

    def test_has_finding_count_field(self) -> None:
        """JSON object must have 'finding_count' equal to the number of findings."""
        self.assertIn("finding_count", self.data)
        self.assertEqual(self.data["finding_count"], 2)

    def test_has_findings_array(self) -> None:
        """JSON object must have a 'findings' array."""
        self.assertIn("findings", self.data)
        self.assertIsInstance(self.data["findings"], list)
        self.assertEqual(len(self.data["findings"]), 2)

    # --- per-finding schema fields ---

    def test_each_finding_has_rule_id(self) -> None:
        """Each entry in 'findings' must have a 'rule_id' field."""
        rule_ids = {f["rule_id"] for f in self.data["findings"]}
        self.assertIn("KEY_VALUE_SECRET", rule_ids)
        self.assertIn("BEARER_TOKEN", rule_ids)

    def test_each_finding_has_category(self) -> None:
        """Each entry in 'findings' must have a 'category' field."""
        for finding in self.data["findings"]:
            self.assertIn("category", finding)
            self.assertIsInstance(finding["category"], str)
            self.assertTrue(finding["category"])

    def test_each_finding_has_line_number(self) -> None:
        """Each entry in 'findings' must have a 'line_number' field."""
        line_numbers = {f["line_number"] for f in self.data["findings"]}
        self.assertIn(3, line_numbers)
        self.assertIn(7, line_numbers)

    def test_each_finding_has_replacement(self) -> None:
        """Each entry in 'findings' must have a 'replacement' field."""
        for finding in self.data["findings"]:
            self.assertIn("replacement", finding)
            self.assertEqual(finding["replacement"], "[REDACTED]")

    # --- privacy guarantee ---

    def test_does_not_contain_raw_secret_values(self) -> None:
        """Raw secret values must never appear anywhere in the JSON output."""
        for secret in self.raw_secrets:
            self.assertNotIn(
                secret,
                self.json_str,
                msg=f"Raw secret '{secret}' was found in the JSON report.",
            )

    # --- edge case: zero findings ---

    def test_empty_result_schema(self) -> None:
        """JSON for zero findings must still have all top-level fields."""
        empty = SanitizeResult(cleaned_text="", findings=[])
        data = json.loads(format_json_report(empty, "stdin"))
        self.assertEqual(data["input_name"], "stdin")
        self.assertEqual(data["finding_count"], 0)
        self.assertEqual(data["findings"], [])

    # --- finding_count consistency ---

    def test_finding_count_matches_findings_array_length(self) -> None:
        """'finding_count' must equal the length of the 'findings' array."""
        self.assertEqual(self.data["finding_count"], len(self.data["findings"]))


class TestFormatBriefCount(unittest.TestCase):
    """Tests for format_brief_count()."""

    def test_zero_replacements(self) -> None:
        """Brief count for zero findings must be '0 replacement(s) made.'"""
        empty = SanitizeResult(cleaned_text="nothing here", findings=[])
        self.assertEqual(format_brief_count(empty), "0 replacement(s) made.")

    def test_one_replacement(self) -> None:
        """Brief count for one finding must be '1 replacement(s) made.'"""
        result = SanitizeResult(
            cleaned_text="[REDACTED]",
            findings=[
                Finding(
                    rule_id="KEY_VALUE_SECRET",
                    category="Key-value secret",
                    line_number=1,
                    replacement="[REDACTED]",
                )
            ],
        )
        self.assertEqual(format_brief_count(result), "1 replacement(s) made.")

    def test_multiple_replacements(self) -> None:
        """Brief count must reflect the exact number of findings."""
        result, _ = _make_result_with_findings()
        self.assertEqual(format_brief_count(result), "2 replacement(s) made.")

    def test_exact_format(self) -> None:
        """Output must match exactly 'N replacement(s) made.' for various N."""
        for n in range(6):
            findings = [
                Finding(
                    rule_id="KEY_VALUE_SECRET",
                    category="Key-value secret",
                    line_number=i + 1,
                    replacement="[REDACTED]",
                )
                for i in range(n)
            ]
            result = SanitizeResult(cleaned_text="...", findings=findings)
            expected = f"{n} replacement(s) made."
            self.assertEqual(
                format_brief_count(result),
                expected,
                msg=f"Expected '{expected}' for n={n}",
            )


if __name__ == "__main__":
    unittest.main()
