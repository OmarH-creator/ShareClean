"""Detector tests for ShareClean v0.2.0 metadata."""

from __future__ import annotations

import unittest

from shareclean.detectors import get_rules
from shareclean.redactor import sanitize


def _sanitize_with_rule(rule_id: str, text: str, **kwargs: object) -> str:
    rules = [rule for rule in get_rules(**kwargs) if rule.rule_id == rule_id]
    if not rules:
        raise KeyError(rule_id)
    return sanitize(text, rules).cleaned_text


class TestStableRuleMetadata(unittest.TestCase):
    def test_all_shipped_rules_have_stable_ids_categories_and_severity(self) -> None:
        rules = get_rules(redact_private_ip=True)
        metadata = {(rule.rule_id, rule.category, rule.severity) for rule in rules}
        self.assertIn(("SC001", "credential", "high"), metadata)
        self.assertIn(("SC002", "token", "high"), metadata)
        self.assertIn(("SC003", "token", "high"), metadata)
        self.assertIn(("SC004", "connection_string", "critical"), metadata)
        self.assertIn(("SC005", "pii_email", "medium"), metadata)
        self.assertIn(("SC006", "pii_path", "medium"), metadata)
        self.assertIn(("SC007", "internal_network", "medium"), metadata)
        self.assertIn(("SC008", "private_key", "critical"), metadata)

    def test_email_rule_can_be_disabled(self) -> None:
        ids = [rule.rule_id for rule in get_rules(redact_email=False)]
        self.assertNotIn("SC005", ids)

    def test_private_ip_rule_is_opt_in(self) -> None:
        self.assertNotIn("SC007", [rule.rule_id for rule in get_rules()])
        self.assertIn(
            "SC007",
            [rule.rule_id for rule in get_rules(redact_private_ip=True)],
        )


class TestDetectorRedaction(unittest.TestCase):
    def test_key_value_secret_redacts_only_value(self) -> None:
        self.assertEqual(
            _sanitize_with_rule("SC001", "password=fake-secret-value"),
            "password=[REDACTED]",
        )

    def test_key_value_custom_label(self) -> None:
        self.assertEqual(
            _sanitize_with_rule(
                "SC001",
                "api_key=fake-api-key",
                redaction_label="[HIDDEN]",
            ),
            "api_key=[HIDDEN]",
        )

    def test_bearer_token_preserves_prefix(self) -> None:
        self.assertEqual(
            _sanitize_with_rule("SC002", "Authorization: Bearer fake-token"),
            "Authorization: Bearer [REDACTED]",
        )

    def test_jwt_like_token_redacted(self) -> None:
        token = "eyFAKEHEADER1234.eyFAKEPAYLOAD5678.fakeSIGNATURE90"
        self.assertEqual(_sanitize_with_rule("SC003", token), "[JWT REDACTED]")

    def test_connection_string_password_redacted(self) -> None:
        text = "postgresql://admin:fake-pass@db.example.com:5432/mydb"
        self.assertEqual(
            _sanitize_with_rule("SC004", text),
            "postgresql://admin:[REDACTED]@db.example.com:5432/mydb",
        )

    def test_email_redacted(self) -> None:
        self.assertEqual(
            _sanitize_with_rule("SC005", "user@example.com"),
            "[EMAIL REDACTED]",
        )

    def test_windows_user_path_redacts_username(self) -> None:
        text = r"C:\Users\FakeUser\Desktop\project"
        self.assertEqual(
            _sanitize_with_rule("SC006", text),
            r"C:\Users\[USER]\Desktop\project",
        )

    def test_unix_user_path_redacts_username(self) -> None:
        self.assertEqual(
            _sanitize_with_rule("SC006", "/home/fakeuser/project"),
            "/home/[USER]/project",
        )

    def test_private_ip_redacted_when_enabled(self) -> None:
        self.assertEqual(
            _sanitize_with_rule(
                "SC007",
                "10.0.0.1",
                redact_private_ip=True,
            ),
            "[PRIVATE-IP]",
        )

    def test_private_key_block_redacted(self) -> None:
        text = (
            "-----BEGIN PRIVATE KEY-----\n"
            "FAKEKEYDATAFORTESTINGONLY\n"
            "-----END PRIVATE KEY-----"
        )
        self.assertEqual(
            _sanitize_with_rule("SC008", text),
            "[PRIVATE-KEY REDACTED]",
        )


if __name__ == "__main__":
    unittest.main()
