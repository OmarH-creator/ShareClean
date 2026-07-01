"""Broad invariant tests for ShareClean."""

from __future__ import annotations

import json
import random
import unittest

from shareclean.detectors import get_rules
from shareclean.redactor import sanitize
from shareclean.report import format_json_report, format_text_report

SEED = 42
ITERATIONS = 100


class TestSanitizedOutputNeverContainsInjectedSecrets(unittest.TestCase):
    def test_key_value_secret_values_are_removed(self) -> None:
        rng = random.Random(SEED)
        keys = ["password", "api_key", "token", "client_secret"]
        values = [
            "fake-secret-value",
            "FakePass99",
            "test-only-token-value",
            "synthetic-secret-123",
        ]
        for _ in range(ITERATIONS):
            key = rng.choice(keys)
            value = rng.choice(values)
            result = sanitize(f"{key}={value}", get_rules())
            self.assertNotIn(value, result.cleaned_text)


class TestNonSensitiveInputPreserved(unittest.TestCase):
    def test_safe_text_is_unchanged(self) -> None:
        rng = random.Random(SEED)
        words = ["elapsed", "queue", "worker", "batch", "metric", "status"]
        for _ in range(ITERATIONS):
            text = " ".join(f"{rng.choice(words)}{rng.randint(1, 999)}" for _ in range(4))
            result = sanitize(text, get_rules(redact_private_ip=True))
            self.assertEqual(result.cleaned_text, text)
            self.assertEqual(result.findings, [])


class TestReportPrivacy(unittest.TestCase):
    def test_reports_do_not_contain_secrets_or_paths(self) -> None:
        secret = "fake-secret-value-for-report-test"
        path = "C:/Users/FakeUser/internal-project/app.log"
        result = sanitize(f"password={secret}", get_rules())
        text_report = format_text_report(result, path)
        json_report = format_json_report(result, path)
        for report in [text_report, json_report]:
            self.assertNotIn(secret, report)
            self.assertNotIn("FakeUser", report)
            self.assertNotIn("internal-project", report)
            self.assertNotIn("app.log", report)
        self.assertIsInstance(json.loads(json_report), dict)


if __name__ == "__main__":
    unittest.main()
