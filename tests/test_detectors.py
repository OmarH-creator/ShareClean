"""Unit tests for shareclean/detectors.py.

Covers positive (Task 2.2) and negative/boundary (Task 2.3) cases.
All test values are clearly fake.
"""

import re
import unittest

from shareclean.detectors import get_rules


def _apply_rule(rule_id: str, text: str, **get_rules_kwargs) -> str:
    """Helper: find the named rule and apply a single re.sub against text."""
    rules = get_rules(**get_rules_kwargs)
    for rule in rules:
        if rule.rule_id == rule_id:
            return re.sub(rule.pattern, rule.replacement, text)
    raise KeyError(f"Rule not found: {rule_id!r}")


# ---------------------------------------------------------------------------
# Task 2.2 — Positive (detector fires correctly)
# ---------------------------------------------------------------------------

class TestConnectionStringPositive(unittest.TestCase):
    """CONNECTION_STRING rule replaces the password and preserves context."""

    def test_postgresql_password_replaced(self):
        text = "postgresql://admin:fake-pass123@db.example.com:5432/mydb"
        result = _apply_rule("CONNECTION_STRING", text)
        self.assertIn("[REDACTED]", result)
        self.assertNotIn("fake-pass123", result)

    def test_scheme_preserved(self):
        text = "postgresql://admin:fake-pass123@db.example.com:5432/mydb"
        result = _apply_rule("CONNECTION_STRING", text)
        self.assertTrue(result.startswith("postgresql://"))

    def test_user_preserved(self):
        text = "postgresql://admin:fake-pass123@db.example.com:5432/mydb"
        result = _apply_rule("CONNECTION_STRING", text)
        self.assertIn("admin:", result)

    def test_host_preserved(self):
        text = "postgresql://admin:fake-pass123@db.example.com:5432/mydb"
        result = _apply_rule("CONNECTION_STRING", text)
        self.assertIn("@db.example.com:5432/mydb", result)

    def test_expected_output(self):
        text = "postgresql://admin:fake-pass123@db.example.com:5432/mydb"
        expected = "postgresql://admin:[REDACTED]@db.example.com:5432/mydb"
        result = _apply_rule("CONNECTION_STRING", text)
        self.assertEqual(result, expected)


class TestBearerTokenPositive(unittest.TestCase):
    """BEARER_TOKEN rule replaces the token value."""

    def test_token_replaced(self):
        text = "Authorization: Bearer fake-bearer-token-value"
        result = _apply_rule("BEARER_TOKEN", text)
        self.assertEqual(result, "Authorization: Bearer [REDACTED]")
        self.assertNotIn("fake-bearer-token-value", result)

    def test_prefix_preserved(self):
        text = "Authorization: Bearer fake-bearer-token-value"
        result = _apply_rule("BEARER_TOKEN", text)
        self.assertIn("Authorization: Bearer ", result)


class TestKeyValueSecretPositive(unittest.TestCase):
    """KEY_VALUE_SECRET rule replaces the value for various key names."""

    def test_password_equals(self):
        text = "password=fake-secret-value"
        result = _apply_rule("KEY_VALUE_SECRET", text)
        self.assertEqual(result, "password=[REDACTED]")

    def test_api_key_colon(self):
        text = "api_key: fake-api-key-value"
        result = _apply_rule("KEY_VALUE_SECRET", text)
        self.assertEqual(result, "api_key: [REDACTED]")

    def test_token_uppercase(self):
        # Case-insensitive: TOKEN= should match
        text = "TOKEN=fake-token-value"
        result = _apply_rule("KEY_VALUE_SECRET", text)
        self.assertEqual(result, "TOKEN=[REDACTED]")

    def test_key_name_preserved(self):
        text = "password=fake-secret-value"
        result = _apply_rule("KEY_VALUE_SECRET", text)
        self.assertIn("password=", result)

    def test_custom_redaction_label(self):
        text = "password=fake-secret-value"
        result = _apply_rule(
            "KEY_VALUE_SECRET",
            text,
            redaction_label="[HIDDEN]",
        )
        self.assertEqual(result, "password=[HIDDEN]")


class TestJwtLikePositive(unittest.TestCase):
    """JWT_LIKE rule replaces a three-segment Base64URL token."""

    def test_jwt_replaced(self):
        text = "eyFAKEHEADER1234.eyFAKEPAYLOAD5678.fakeSIGNATURE90"
        result = _apply_rule("JWT_LIKE", text)
        self.assertEqual(result, "[JWT REDACTED]")
        self.assertNotIn("eyFAKEHEADER1234", result)


class TestEmailPositive(unittest.TestCase):
    """EMAIL rule replaces the entire email address."""

    def test_email_replaced(self):
        text = "user@example.com"
        result = _apply_rule("EMAIL", text)
        self.assertEqual(result, "[EMAIL REDACTED]")
        self.assertNotIn("user@example.com", result)


class TestWindowsUserPathPositive(unittest.TestCase):
    """WINDOWS_USER_PATH rule replaces only the username segment."""

    def test_username_replaced(self):
        text = r"C:\Users\FakeUser\Desktop\project"
        result = _apply_rule("WINDOWS_USER_PATH", text)
        self.assertIn(r"C:\Users\[USER]", result)
        self.assertNotIn("FakeUser", result)

    def test_remaining_path_preserved(self):
        text = r"C:\Users\FakeUser\Desktop\project"
        result = _apply_rule("WINDOWS_USER_PATH", text)
        self.assertIn(r"\Desktop\project", result)


class TestUnixUserPathPositive(unittest.TestCase):
    """UNIX_USER_PATH rule replaces the username on /home/ and /Users/ paths."""

    def test_home_path(self):
        text = "/home/fakeuser/project"
        result = _apply_rule("UNIX_USER_PATH", text)
        self.assertEqual(result, "/home/[USER]/project")
        self.assertNotIn("fakeuser", result)

    def test_users_path(self):
        text = "/Users/fakeuser/project"
        result = _apply_rule("UNIX_USER_PATH", text)
        self.assertEqual(result, "/Users/[USER]/project")
        self.assertNotIn("fakeuser", result)


class TestPrivateIPPositive(unittest.TestCase):
    """PRIVATE_IP rule replaces RFC 1918 addresses (when enabled)."""

    def test_10_range(self):
        text = "server at 10.0.0.1 is healthy"
        result = _apply_rule("PRIVATE_IP", text, redact_private_ip=True)
        self.assertIn("[PRIVATE-IP]", result)
        self.assertNotIn("10.0.0.1", result)

    def test_192_168_range(self):
        text = "gateway is 192.168.1.100"
        result = _apply_rule("PRIVATE_IP", text, redact_private_ip=True)
        self.assertIn("[PRIVATE-IP]", result)
        self.assertNotIn("192.168.1.100", result)

    def test_172_16_range(self):
        text = "host 172.16.0.1 connected"
        result = _apply_rule("PRIVATE_IP", text, redact_private_ip=True)
        self.assertIn("[PRIVATE-IP]", result)
        self.assertNotIn("172.16.0.1", result)


# ---------------------------------------------------------------------------
# Task 2.3 — Negative / boundary cases
# ---------------------------------------------------------------------------

class TestJwtLikeNegative(unittest.TestCase):
    """Values with segments shorter than 10 chars must NOT match JWT_LIKE."""

    def test_short_segments_not_matched(self):
        # "1.2.3" — each segment is far too short
        text = "1.2.3"
        result = _apply_rule("JWT_LIKE", text)
        self.assertEqual(result, "1.2.3")  # unchanged

    def test_two_segment_value_not_matched(self):
        # Only two dot-separated segments
        text = "eyFAKEHEADER1234.eyFAKEPAYLOAD5678"
        result = _apply_rule("JWT_LIKE", text)
        self.assertEqual(result, text)  # unchanged


class TestConnectionStringNegative(unittest.TestCase):
    """URIs without a password component must NOT produce a finding."""

    def test_redis_no_password(self):
        # No user:password@ present
        text = "redis://host:6379"
        result = _apply_rule("CONNECTION_STRING", text)
        self.assertEqual(result, text)  # unchanged

    def test_postgres_no_password(self):
        text = "postgresql://host/mydb"
        result = _apply_rule("CONNECTION_STRING", text)
        self.assertEqual(result, text)  # unchanged


class TestNoSensitiveContentNegative(unittest.TestCase):
    """Plain text with no sensitive patterns should not be modified."""

    def test_plain_text_unchanged(self):
        text = "Server started on port 8000"
        # Apply all default rules; none should fire
        rules = get_rules()
        result = text
        for rule in rules:
            result = re.sub(rule.pattern, rule.replacement, result)
        self.assertEqual(result, text)


class TestGetRulesFlags(unittest.TestCase):
    """get_rules() respects redact_email and redact_private_ip flags."""

    def test_email_excluded_when_disabled(self):
        rules = get_rules(redact_email=False)
        ids = [r.rule_id for r in rules]
        self.assertNotIn("EMAIL", ids)

    def test_email_included_by_default(self):
        rules = get_rules()
        ids = [r.rule_id for r in rules]
        self.assertIn("EMAIL", ids)

    def test_private_ip_excluded_by_default(self):
        rules = get_rules(redact_private_ip=False)
        ids = [r.rule_id for r in rules]
        self.assertNotIn("PRIVATE_IP", ids)

    def test_private_ip_included_when_enabled(self):
        rules = get_rules(redact_private_ip=True)
        ids = [r.rule_id for r in rules]
        self.assertIn("PRIVATE_IP", ids)

    def test_custom_redaction_label_applies_to_connection_strings(self):
        result = _apply_rule(
            "CONNECTION_STRING",
            "postgresql://app:fake-pass@db.example.com/app",
            redaction_label="[MASKED]",
        )
        self.assertEqual(
            result,
            "postgresql://app:[MASKED]@db.example.com/app",
        )


if __name__ == "__main__":
    unittest.main()
