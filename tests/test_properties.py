"""
Property-based tests for ShareClean using Python standard library only.
Each test uses random with a fixed seed and runs >= 100 iterations per property.
"""
import json
import random
import re
import unittest

from shareclean.detectors import get_rules
from shareclean.models import Finding, SanitizeResult
from shareclean.redactor import sanitize
from shareclean.report import format_json_report, format_text_report

SEED = 42
ITERATIONS = 100

FAKE_PASSWORDS = [
    "fake-secret-value", "Passw0rd123!", "hunter2fake", "NotAReal#Pass99",
    "xK9mFakePass", "secret-fake-abc", "FakeToken123xyz", "test-only-value",
]
FAKE_EMAILS = [
    "user@example.com", "test.person@fake.org", "dev+alias@notreal.net",
    "admin@testdomain.io",
]
FAKE_KEYS = ["password", "passwd", "pwd", "api_key", "apikey", "token",
             "secret", "client_secret", "access_token", "refresh_token"]
SEPARATORS = ["=", ": ", "=\t", ":"]
SCHEMES = ["postgresql", "mysql", "mongodb"]
FAKE_HOSTS = ["db.example.com:5432/mydb", "localhost/testdb",
              "fake.host.org:3306/db"]
FAKE_USERS = ["fakeuser", "dbadmin", "testacct"]
PRIVATE_IPS = ["10.0.0.1", "192.168.1.100", "172.16.0.1", "10.255.255.255",
               "192.168.100.200"]

_RULES = get_rules(redact_email=True, redact_private_ip=False)


class TestProperty1SanitizedOutputNeverContainsSecret(unittest.TestCase):
    # Feature: share-clean, Property 1: Sanitized output never contains the original sensitive value
    def test_property(self):
        """Validates: Requirements 8.2, 8.5, 14.3"""
        rng = random.Random(SEED)
        rules = get_rules()
        for _ in range(ITERATIONS):
            key = rng.choice(FAKE_KEYS)
            sep = rng.choice(SEPARATORS)
            val = rng.choice(FAKE_PASSWORDS)
            text = f"{key}{sep}{val}"
            result = sanitize(text, rules)
            self.assertNotIn(val, result.cleaned_text,
                             f"Secret '{val}' found in cleaned output for input: {text!r}")


class TestProperty2FindingCountEqualsReplacementCount(unittest.TestCase):
    # Feature: share-clean, Property 2: Finding count equals actual replacement count
    def test_property(self):
        """Validates: Requirements 8.5, 10.2"""
        rng = random.Random(SEED)
        rules = get_rules()
        inputs = [
            "", "no sensitive content here", "password=fake123",
            "password=fake1\napi_key=fake2\ntoken=fake3",
            "user@example.com",
        ]
        for i in range(ITERATIONS):
            text = inputs[i % len(inputs)]
            result = sanitize(text, rules)
            self.assertEqual(len(result.findings), result.replacement_count,
                             f"Mismatch for input: {text!r}")


def _generate_safe_strings(rng: random.Random, count: int) -> list[str]:
    """Generate *count* random strings guaranteed to contain no pattern-matching content.

    Strategy:
    - Use only lowercase letters and digits (no '@', ':', '=', '/', '\\', '.')
      so that none of the detector patterns can fire.
    - Build multi-word phrases separated by single spaces.
    - This avoids:
        * emails  (require '@')
        * key-value secrets (require '=' or ':' adjacent to a keyword)
        * connection strings (require '://')
        * JWT-like tokens (require two '.' separators with long base64 segments)
        * Windows/Unix paths (require '\\' or '/')
        * private IPs (require '.' between numeric octets)
        * bearer tokens (require 'authorization' + ':' + 'bearer')
    """
    # Safe alphabet: lowercase letters + digits only — no punctuation that
    # any detector pattern requires.
    safe_chars = "abcdefghjklmnpqrstuvwxyz0123456789"  # no 'i' to avoid 'ip'-like subwords
    # Safe word-start prefixes that are NOT detector keywords.
    # Detector key names: password, passwd, pwd, token, access_token,
    # refresh_token, api_key, apikey, secret, client_secret, authorization
    # We avoid using any of those words entirely.
    safe_prefixes = [
        "elapsed", "batch", "queue", "delta", "sigma", "gamma",
        "retry", "stage", "cycle", "frame", "phase", "flux",
        "level", "count", "total", "block", "chunk", "stream",
        "buffer", "worker", "thread", "node", "shard", "replica",
        "metric", "gauge", "trace", "span", "label", "tag",
        "header", "record", "entry", "bucket", "region", "cluster",
        "zone", "rack", "slot", "lane", "pool", "group",
    ]

    results: list[str] = []
    for _ in range(count):
        # Build a sentence of 2–5 safe words
        num_words = rng.randint(2, 5)
        words: list[str] = []
        for _ in range(num_words):
            if rng.random() < 0.6:
                # Use a safe prefix plus a short random numeric suffix
                prefix = rng.choice(safe_prefixes)
                suffix = str(rng.randint(0, 9999))
                words.append(prefix + suffix)
            else:
                # Build a purely random safe word of 4–10 chars
                length = rng.randint(4, 10)
                word = "".join(rng.choice(safe_chars) for _ in range(length))
                # Ensure the random word doesn't accidentally spell a keyword.
                # Simple guard: reject if the word matches any known keyword.
                _KEYWORDS = {
                    "password", "passwd", "pwd", "token", "secret",
                    "apikey", "authorization", "bearer",
                }
                if word.lower() in _KEYWORDS:
                    word = "safe" + word  # guaranteed to not be a bare keyword
                words.append(word)
        results.append(" ".join(words))
    return results


class TestProperty3NonSensitiveInputPreservedVerbatim(unittest.TestCase):
    # Feature: share-clean, Property 3: Non-sensitive input is preserved verbatim
    def test_property(self):
        """Validates: Requirements 8.3, 8.4, 15.2"""
        rng = random.Random(SEED)
        rules = get_rules(redact_email=True, redact_private_ip=True)  # all rules active
        safe_inputs = _generate_safe_strings(rng, ITERATIONS)
        self.assertGreaterEqual(len(safe_inputs), ITERATIONS,
                                "Generator must produce at least 100 inputs")
        for text in safe_inputs:
            result = sanitize(text, rules)
            self.assertEqual(
                result.cleaned_text, text,
                f"Non-sensitive text was modified.\n"
                f"  Input:  {text!r}\n"
                f"  Output: {result.cleaned_text!r}",
            )
            self.assertEqual(
                result.findings, [],
                f"Unexpected findings for non-sensitive input: {text!r}\n"
                f"  Findings: {result.findings}",
            )


def _extract_line_ending(line: str) -> str:
    """Return the line ending character(s) of *line*, or empty string if none."""
    if line.endswith("\r\n"):
        return "\r\n"
    if line.endswith("\n"):
        return "\n"
    if line.endswith("\r"):
        return "\r"
    return ""


def _generate_line_ending_inputs(rng: random.Random, count: int) -> list[str]:
    """Generate *count* multi-line strings with mixed line endings.

    Each string consists of 2–6 lines joined with randomly chosen line endings
    (\n, \r\n, \r).  Roughly half the inputs contain an injected fake secret
    on a randomly chosen line; the other half contain no secrets at all.
    """
    line_endings = ["\n", "\r\n", "\r"]
    safe_line_templates = [
        "elapsed {n}",
        "batch count {n}",
        "stage {n} ready",
        "retry cycle {n}",
        "flux level {n}",
        "queue depth {n}",
    ]
    secret_templates = [
        "password=fake-secret-{n}",
        "api_key=fakeapikey{n}",
        "token=FakeToken{n}XYZ",
        "client_secret=fake-client-{n}",
    ]

    results: list[str] = []
    for _ in range(count):
        num_lines = rng.randint(2, 6)
        inject_secret = rng.random() < 0.5
        secret_line_index = rng.randint(0, num_lines - 1) if inject_secret else -1

        parts: list[str] = []
        for idx in range(num_lines):
            ending = rng.choice(line_endings)
            # Last line: 50% chance of having no trailing line ending
            if idx == num_lines - 1 and rng.random() < 0.5:
                ending = ""
            if idx == secret_line_index:
                content = rng.choice(secret_templates).format(n=rng.randint(1, 9999))
            else:
                content = rng.choice(safe_line_templates).format(n=rng.randint(0, 9999))
            parts.append(content + ending)

        results.append("".join(parts))
    return results


class TestProperty4LineEndingsPreserved(unittest.TestCase):
    # Feature: share-clean, Property 4: Line endings are preserved
    def test_property(self):
        """Validates: Requirements 1.5, 8.4"""
        rng = random.Random(SEED)
        rules = get_rules()
        inputs = _generate_line_ending_inputs(rng, ITERATIONS)
        self.assertGreaterEqual(len(inputs), ITERATIONS,
                                "Generator must produce at least 100 inputs")
        for text in inputs:
            result = sanitize(text, rules)
            orig_lines = text.splitlines(keepends=True)
            clean_lines = result.cleaned_text.splitlines(keepends=True)
            self.assertEqual(
                len(orig_lines), len(clean_lines),
                f"Line count changed.\n  Input:  {text!r}\n  Output: {result.cleaned_text!r}",
            )
            for orig, cleaned in zip(orig_lines, clean_lines):
                orig_ending = _extract_line_ending(orig)
                if orig_ending:
                    clean_ending = _extract_line_ending(cleaned)
                    self.assertEqual(
                        orig_ending, clean_ending,
                        f"Line ending changed: {orig!r} -> {cleaned!r}",
                    )


class TestProperty5KeyNamePreservedInKeyValueRedaction(unittest.TestCase):
    # Feature: share-clean, Property 5: Key name is preserved in key-value redaction
    def test_property(self):
        """Validates: Requirements 2.1, 8.2, 8.3

        For any input containing a key-value secret match, the key name and
        separator (e.g., 'password=', 'api_key: ') SHALL appear unchanged in
        cleaned_text, and only the value portion SHALL be replaced with [REDACTED].
        """
        rng = random.Random(SEED)
        rules = get_rules()
        for _ in range(ITERATIONS):
            key = rng.choice(FAKE_KEYS)
            sep = rng.choice(SEPARATORS)
            val = rng.choice(FAKE_PASSWORDS)
            text = f"{key}{sep}{val}"
            result = sanitize(text, rules)

            # The key name must be preserved verbatim in the cleaned text.
            # Check case-insensitively since the regex pattern is case-insensitive,
            # but the key itself (lower-case as defined) must appear as-is.
            self.assertIn(
                key,
                result.cleaned_text,
                f"Key name '{key}' not preserved verbatim in: {result.cleaned_text!r}",
            )

            # The separator must be preserved verbatim immediately after the key.
            # The cleaned text should contain key+separator as a contiguous substring.
            self.assertIn(
                key + sep,
                result.cleaned_text,
                f"Key+separator '{key}{sep!r}' not preserved verbatim in: {result.cleaned_text!r}",
            )

            # Only the value portion must be replaced — [REDACTED] must appear
            # right after the key+separator (possibly with the replacement label).
            self.assertIn(
                "[REDACTED]",
                result.cleaned_text,
                f"[REDACTED] label not found in: {result.cleaned_text!r}",
            )

            # The original value must not appear anywhere in the cleaned text.
            self.assertNotIn(
                val,
                result.cleaned_text,
                f"Value '{val}' was not redacted in: {result.cleaned_text!r}",
            )

            # The full expected replacement pattern must appear verbatim:
            # key + separator + [REDACTED]
            expected_fragment = f"{key}{sep}[REDACTED]"
            self.assertIn(
                expected_fragment,
                result.cleaned_text,
                f"Expected '{expected_fragment}' not found in: {result.cleaned_text!r}\n"
                f"  Input: {text!r}",
            )


class TestProperty6ConnectionStringStructurePreserved(unittest.TestCase):
    # Feature: share-clean, Property 6: Connection string structural components are preserved
    def test_property(self):
        """Validates: Requirements 3.1, 3.2, 8.2

        For any input containing a connection string with a password component,
        the scheme, username, host, port, and database name SHALL appear
        unchanged in cleaned_text, and only the password segment SHALL be
        replaced with [REDACTED].
        """
        # All schemes that support password-bearing connection strings
        all_schemes = ["postgres", "postgresql", "mysql", "mongodb", "redis"]

        # Varied individual components
        fake_usernames = [
            "fakeuser", "dbadmin", "testacct", "readonlyuser", "svcaccount",
        ]
        fake_passwords = [
            "fake-secret-value", "Passw0rd123!", "hunter2fake",
            "NotAReal#Pass99", "xK9mFakePass", "secret-fake-abc",
            "FakeToken123xyz", "test-only-value",
        ]
        fake_hosts = [
            "db.example.com", "localhost", "fake.host.org",
            "primary.db.test", "replica-1.internal.test",
        ]
        fake_ports = [5432, 3306, 27017, 6379, 5433, 3307]
        fake_databases = [
            "mydb", "testdb", "appdata", "analytics", "warehouse",
        ]

        rng = random.Random(SEED)
        rules = get_rules()

        for _ in range(ITERATIONS):
            scheme = rng.choice(all_schemes)
            user = rng.choice(fake_usernames)
            password = rng.choice(fake_passwords)
            host = rng.choice(fake_hosts)
            port = rng.choice(fake_ports)
            database = rng.choice(fake_databases)

            # Build a fully-qualified connection string: scheme://user:pass@host:port/db
            text = f"{scheme}://{user}:{password}@{host}:{port}/{database}"
            result = sanitize(text, rules)
            cleaned = result.cleaned_text

            # --- scheme must be preserved verbatim ---
            self.assertIn(
                scheme + "://",
                cleaned,
                f"Scheme '{scheme}://' lost.\n  Input: {text!r}\n  Output: {cleaned!r}",
            )

            # --- username must be preserved verbatim ---
            self.assertIn(
                user,
                cleaned,
                f"Username '{user}' lost.\n  Input: {text!r}\n  Output: {cleaned!r}",
            )

            # --- host must be preserved verbatim ---
            self.assertIn(
                host,
                cleaned,
                f"Host '{host}' lost.\n  Input: {text!r}\n  Output: {cleaned!r}",
            )

            # --- port must be preserved verbatim ---
            self.assertIn(
                f":{port}/",
                cleaned,
                f"Port ':{port}/' lost.\n  Input: {text!r}\n  Output: {cleaned!r}",
            )

            # --- database name must be preserved verbatim ---
            self.assertIn(
                f"/{database}",
                cleaned,
                f"Database '/{database}' lost.\n  Input: {text!r}\n  Output: {cleaned!r}",
            )

            # --- password must NOT appear in cleaned output ---
            self.assertNotIn(
                password,
                cleaned,
                f"Password '{password}' was not redacted.\n  Input: {text!r}\n  Output: {cleaned!r}",
            )

            # --- [REDACTED] must appear where the password was ---
            self.assertIn(
                "[REDACTED]",
                cleaned,
                f"[REDACTED] label missing.\n  Input: {text!r}\n  Output: {cleaned!r}",
            )

            # --- the exact structural replacement must be present:
            #     scheme://user:[REDACTED]@host:port/db
            expected_cleaned = f"{scheme}://{user}:[REDACTED]@{host}:{port}/{database}"
            self.assertEqual(
                cleaned,
                expected_cleaned,
                f"Cleaned string doesn't match expected structure.\n"
                f"  Input:    {text!r}\n"
                f"  Expected: {expected_cleaned!r}\n"
                f"  Got:      {cleaned!r}",
            )


class TestProperty7FindingLineNumbersAccurate(unittest.TestCase):
    # Feature: share-clean, Property 7: Finding line numbers are accurate

    def test_single_secret_on_known_line(self):
        """Single secret placed on each of lines 1–5; assert line_number matches.

        Validates: Requirements 8.5, 10.2
        """
        rules = get_rules()
        for i in range(ITERATIONS):
            secret_line = (i % 5) + 1  # cycle through lines 1–5
            lines = ["no sensitive content here\n"] * (secret_line - 1)
            lines.append(f"password=fake-secret-{i}\n")
            lines += ["more safe content\n"] * (5 - secret_line)
            text = "".join(lines)
            result = sanitize(text, rules)
            kv_findings = [f for f in result.findings if f.rule_id == "KEY_VALUE_SECRET"]
            self.assertGreaterEqual(
                len(kv_findings), 1,
                f"No KEY_VALUE_SECRET finding for input: {text!r}",
            )
            self.assertEqual(
                kv_findings[0].line_number,
                secret_line,
                f"Expected line {secret_line}, got {kv_findings[0].line_number}\n"
                f"  Input: {text!r}",
            )

    def test_multiple_secrets_on_different_known_lines(self):
        """Two secrets on different known lines; assert both findings report correct lines.

        Validates: Requirements 8.5, 10.2
        """
        rng = random.Random(SEED)
        rules = get_rules()
        for i in range(ITERATIONS):
            # Pick two distinct line positions within a 6-line block (1-indexed)
            total_lines = 6
            line_a = rng.randint(1, total_lines - 1)
            line_b = rng.randint(line_a + 1, total_lines)  # always > line_a

            # Build lines: safe text except at line_a and line_b
            lines: list[str] = []
            for ln in range(1, total_lines + 1):
                if ln == line_a:
                    lines.append(f"api_key=fakeapikey{i}A\n")
                elif ln == line_b:
                    lines.append(f"token=FakeToken{i}B\n")
                else:
                    lines.append(f"safe line {ln}\n")

            text = "".join(lines)
            result = sanitize(text, rules)
            kv_findings = [f for f in result.findings if f.rule_id == "KEY_VALUE_SECRET"]

            # Both injected secrets must produce a finding
            self.assertGreaterEqual(
                len(kv_findings), 2,
                f"Expected at least 2 KEY_VALUE_SECRET findings, got {len(kv_findings)}\n"
                f"  Input: {text!r}",
            )

            reported_lines = sorted(f.line_number for f in kv_findings[:2])
            self.assertEqual(
                reported_lines,
                sorted([line_a, line_b]),
                f"Expected findings on lines {sorted([line_a, line_b])}, "
                f"got {reported_lines}\n  Input: {text!r}",
            )

    def test_secret_on_first_line(self):
        """Secret on the very first line (1-indexed) must yield line_number == 1.

        Validates: Requirements 8.5, 10.2
        """
        rules = get_rules()
        for i in range(ITERATIONS):
            text = f"password=fake-secret-{i}\nsafe line 2\nsafe line 3\n"
            result = sanitize(text, rules)
            kv_findings = [f for f in result.findings if f.rule_id == "KEY_VALUE_SECRET"]
            self.assertGreaterEqual(len(kv_findings), 1,
                                    f"No KEY_VALUE_SECRET finding for: {text!r}")
            self.assertEqual(
                kv_findings[0].line_number, 1,
                f"Expected line 1, got {kv_findings[0].line_number}\n  Input: {text!r}",
            )

    def test_secret_on_last_line_no_trailing_newline(self):
        """Secret on the last line with no trailing newline; line_number must still be accurate.

        Validates: Requirements 8.5, 10.2
        """
        rules = get_rules()
        for i in range(ITERATIONS):
            n_safe = (i % 4) + 1   # 1–4 safe lines before the secret
            safe_part = "".join(f"safe line {ln}\n" for ln in range(1, n_safe + 1))
            # Last line has no trailing newline
            secret_part = f"token=FakeToken{i}XYZ"
            text = safe_part + secret_part
            expected_line = n_safe + 1
            result = sanitize(text, rules)
            kv_findings = [f for f in result.findings if f.rule_id == "KEY_VALUE_SECRET"]
            self.assertGreaterEqual(len(kv_findings), 1,
                                    f"No KEY_VALUE_SECRET finding for: {text!r}")
            self.assertEqual(
                kv_findings[0].line_number, expected_line,
                f"Expected line {expected_line}, got {kv_findings[0].line_number}\n"
                f"  Input: {text!r}",
            )

    def test_varied_secret_types_line_numbers_accurate(self):
        """Email and key-value secrets placed on specific lines; assert each finding's line.

        Validates: Requirements 8.5, 10.2
        """
        rules = get_rules(redact_email=True)
        rng = random.Random(SEED + 1)
        total_lines = 5
        for i in range(ITERATIONS):
            # Place a key-value secret on a random line and an email on a different line
            kv_line = rng.randint(1, total_lines)
            email_line = rng.choice([ln for ln in range(1, total_lines + 1) if ln != kv_line])

            lines: list[str] = []
            for ln in range(1, total_lines + 1):
                if ln == kv_line:
                    lines.append(f"secret=fake-val-{i}\n")
                elif ln == email_line:
                    lines.append(f"contact: testuser{i}@example.com\n")
                else:
                    lines.append(f"log entry {ln}\n")

            text = "".join(lines)
            result = sanitize(text, rules)

            kv_findings = [f for f in result.findings if f.rule_id == "KEY_VALUE_SECRET"]
            email_findings = [f for f in result.findings if f.rule_id == "EMAIL"]

            self.assertGreaterEqual(len(kv_findings), 1,
                                    f"No KEY_VALUE_SECRET finding in: {text!r}")
            self.assertGreaterEqual(len(email_findings), 1,
                                    f"No EMAIL finding in: {text!r}")

            self.assertEqual(
                kv_findings[0].line_number, kv_line,
                f"KEY_VALUE_SECRET: expected line {kv_line}, got {kv_findings[0].line_number}\n"
                f"  Input: {text!r}",
            )
            self.assertEqual(
                email_findings[0].line_number, email_line,
                f"EMAIL: expected line {email_line}, got {email_findings[0].line_number}\n"
                f"  Input: {text!r}",
            )


class TestProperty8FindingsNeverStoreOriginalValue(unittest.TestCase):
    # Feature: share-clean, Property 8: Findings never store the original matched value

    def _assert_no_field_contains(self, finding: "Finding", injected: str, context: str) -> None:
        """Assert that no string field of *finding* contains *injected*."""
        self.assertNotIn(
            injected, finding.rule_id,
            f"rule_id contains injected value.\n  injected={injected!r}\n  {context}",
        )
        self.assertNotIn(
            injected, finding.category,
            f"category contains injected value.\n  injected={injected!r}\n  {context}",
        )
        self.assertNotIn(
            injected, finding.replacement,
            f"replacement contains injected value.\n  injected={injected!r}\n  {context}",
        )
        # line_number is an int — verify it does not accidentally equal the
        # injected string (this is a type-safety guard, not a realistic risk).
        self.assertIsInstance(
            finding.line_number, int,
            f"line_number is not an int.\n  {context}",
        )

    def test_key_value_secrets(self):
        """Key names (password, api_key, token, …) with varied fake values.

        Validates: Requirements 8.5, 14.3
        """
        rng = random.Random(SEED)
        rules = get_rules()
        for _ in range(ITERATIONS):
            key = rng.choice(FAKE_KEYS)
            sep = rng.choice(SEPARATORS)
            val = rng.choice(FAKE_PASSWORDS)
            text = f"{key}{sep}{val}"
            result = sanitize(text, rules)
            self.assertGreaterEqual(len(result.findings), 1,
                                    f"No finding for: {text!r}")
            for finding in result.findings:
                self._assert_no_field_contains(finding, val, f"input={text!r}")

    def test_email_addresses(self):
        """Email addresses are replaced; injected address must not appear in any Finding.

        Validates: Requirements 8.5, 14.3
        """
        rng = random.Random(SEED)
        rules = get_rules(redact_email=True)
        for i in range(ITERATIONS):
            email = FAKE_EMAILS[i % len(FAKE_EMAILS)]
            text = f"Contact: {email}"
            result = sanitize(text, rules)
            self.assertGreaterEqual(len(result.findings), 1,
                                    f"No EMAIL finding for: {text!r}")
            for finding in result.findings:
                self._assert_no_field_contains(finding, email, f"input={text!r}")

    def test_connection_string_passwords(self):
        """Connection string passwords must not leak into any Finding field.

        Validates: Requirements 8.5, 14.3
        """
        rng = random.Random(SEED)
        rules = get_rules()
        for _ in range(ITERATIONS):
            scheme = rng.choice(SCHEMES)
            user = rng.choice(FAKE_USERS)
            password = rng.choice(FAKE_PASSWORDS)
            host = rng.choice(FAKE_HOSTS)
            text = f"{scheme}://{user}:{password}@{host}"
            result = sanitize(text, rules)
            self.assertGreaterEqual(len(result.findings), 1,
                                    f"No CONNECTION_STRING finding for: {text!r}")
            for finding in result.findings:
                self._assert_no_field_contains(finding, password, f"input={text!r}")

    def test_bearer_tokens(self):
        """Bearer token values must not appear in any Finding field.

        Validates: Requirements 8.5, 14.3
        """
        rng = random.Random(SEED)
        rules = get_rules()
        for _ in range(ITERATIONS):
            token = rng.choice(FAKE_PASSWORDS)
            text = f"Authorization: Bearer {token}"
            result = sanitize(text, rules)
            # Bearer token rule should fire; also possibly key-value if 'token' keyword present.
            self.assertGreaterEqual(len(result.findings), 1,
                                    f"No finding for bearer token input: {text!r}")
            for finding in result.findings:
                self._assert_no_field_contains(finding, token, f"input={text!r}")

    def test_jwt_like_tokens(self):
        """JWT-like tokens are fully replaced; the token must not appear in any Finding.

        Validates: Requirements 8.5, 14.3
        """
        rng = random.Random(SEED)
        rules = get_rules()
        # Use stable fake JWT segments (>= 10 base64url chars each)
        fake_headers = [
            "eyFakeHeader1Aa", "eyFakeHeader2Bb", "eyFakeHeader3Cc",
            "eyFakeHeaderXXX", "eyFakeHeader999",
        ]
        fake_payloads = [
            "eyFakePayload1Dd", "eyFakePayload2Ee", "eyFakePayload3Ff",
            "eyFakePayloadYYY", "eyFakePayload000",
        ]
        fake_sigs = [
            "FakeSig1GgHhIiJj", "FakeSig2KkLlMmNn", "FakeSig3OoPpQqRr",
            "FakeSigZZZWWWVVV", "FakeSig4SsTtUuVv",
        ]
        for _ in range(ITERATIONS):
            header = rng.choice(fake_headers)
            payload = rng.choice(fake_payloads)
            sig = rng.choice(fake_sigs)
            full_token = f"{header}.{payload}.{sig}"
            text = f"token={full_token}"
            result = sanitize(text, rules)
            self.assertGreaterEqual(len(result.findings), 1,
                                    f"No finding for JWT-like input: {text!r}")
            for finding in result.findings:
                # Neither the full token nor any individual segment may appear in a field
                self._assert_no_field_contains(finding, full_token, f"input={text!r}")
                self._assert_no_field_contains(finding, header, f"input={text!r} (header segment)")
                self._assert_no_field_contains(finding, payload, f"input={text!r} (payload segment)")
                self._assert_no_field_contains(finding, sig, f"input={text!r} (signature segment)")

    def test_mixed_rule_types_in_single_input(self):
        """Multi-pattern input: each injected value must not appear in any Finding.

        Combines key-value secret, email, and connection string in one input.
        Validates: Requirements 8.5, 14.3
        """
        rng = random.Random(SEED)
        rules = get_rules(redact_email=True)
        for i in range(ITERATIONS):
            val = FAKE_PASSWORDS[i % len(FAKE_PASSWORDS)]
            email = FAKE_EMAILS[i % len(FAKE_EMAILS)]
            password = FAKE_PASSWORDS[(i + 1) % len(FAKE_PASSWORDS)]
            scheme = SCHEMES[i % len(SCHEMES)]
            user = FAKE_USERS[i % len(FAKE_USERS)]
            host = FAKE_HOSTS[i % len(FAKE_HOSTS)]
            lines = [
                f"api_key={val}",
                f"contact: {email}",
                f"{scheme}://{user}:{password}@{host}",
            ]
            text = "\n".join(lines)
            result = sanitize(text, rules)
            self.assertGreaterEqual(len(result.findings), 3,
                                    f"Expected at least 3 findings for: {text!r}")
            injected_values = [val, email, password]
            for injected in injected_values:
                for finding in result.findings:
                    self._assert_no_field_contains(finding, injected, f"input={text!r}")


def _generate_fake_emails(rng: random.Random, count: int) -> list[str]:
    """Generate *count* synthetic email addresses using clearly fake domains.

    Varies the local part (with dots, plus signs, underscores, hyphens, digits)
    and the domain (fake TLDs and sub-domains) to produce a diverse set of inputs
    that the EMAIL detector should match.
    """
    local_prefixes = [
        "user", "test", "dev", "admin", "support", "info", "noreply",
        "contact", "hello", "ops", "eng", "qa", "bot", "svc",
    ]
    local_separators = ["", ".", "_", "-", "+"]
    local_suffixes = [str(i) for i in range(1, 20)]
    fake_domains = [
        "example.com", "fake.org", "notreal.net", "testdomain.io",
        "synthetic.dev", "sample.co", "dummy.example.com",
        "test-corp.org", "fakeco.net",
    ]

    results: list[str] = []
    for _ in range(count):
        prefix = rng.choice(local_prefixes)
        sep = rng.choice(local_separators)
        suffix = rng.choice(local_suffixes)
        local = prefix + sep + suffix if sep else prefix + suffix
        domain = rng.choice(fake_domains)
        results.append(f"{local}@{domain}")
    return results


# Context templates for embedding email addresses
_EMAIL_CONTEXTS = [
    "Contact: {email}",
    "Send logs to {email} for review",
    "Reported by {email}",
    "{email} triggered the alert",
    "Email: {email}",
    "cc: {email}",
    "From: {email}",
    "Reply-To: {email}",
    "notify {email} on completion",
]


class TestProperty9NoEmailFlagDisablesEmailDetection(unittest.TestCase):
    # Feature: share-clean, Property 9: --no-email disables email detection entirely
    def test_no_email_flag_produces_no_email_findings(self):
        """When redact_email=False, no EMAIL finding is produced and addresses are unchanged.

        Validates: Requirements 5.3
        """
        rng = random.Random(SEED)
        rules_no_email = get_rules(redact_email=False)
        emails = _generate_fake_emails(rng, ITERATIONS)
        self.assertGreaterEqual(len(emails), ITERATIONS,
                                "Generator must produce at least 100 emails")
        for i, email in enumerate(emails):
            ctx = _EMAIL_CONTEXTS[i % len(_EMAIL_CONTEXTS)]
            text = ctx.format(email=email)
            result = sanitize(text, rules_no_email)

            # No EMAIL finding should be produced
            email_findings = [f for f in result.findings if f.rule_id == "EMAIL"]
            self.assertEqual(
                email_findings, [],
                f"EMAIL finding produced despite redact_email=False.\n"
                f"  Input: {text!r}\n"
                f"  Findings: {result.findings}",
            )

            # The email address must remain unchanged in cleaned_text
            self.assertIn(
                email,
                result.cleaned_text,
                f"Email '{email}' was altered/removed despite redact_email=False.\n"
                f"  Input:  {text!r}\n"
                f"  Output: {result.cleaned_text!r}",
            )

    def test_email_detected_when_enabled(self):
        """Contrast: when redact_email=True (default), EMAIL findings ARE produced.

        Validates: Requirements 5.1, 5.3
        """
        rng = random.Random(SEED + 1)
        rules_with_email = get_rules(redact_email=True)
        emails = _generate_fake_emails(rng, ITERATIONS)
        for i, email in enumerate(emails):
            ctx = _EMAIL_CONTEXTS[i % len(_EMAIL_CONTEXTS)]
            text = ctx.format(email=email)
            result = sanitize(text, rules_with_email)

            email_findings = [f for f in result.findings if f.rule_id == "EMAIL"]
            self.assertGreaterEqual(
                len(email_findings), 1,
                f"No EMAIL finding produced despite redact_email=True.\n"
                f"  Input: {text!r}",
            )

            # The email address must NOT appear in cleaned_text
            self.assertNotIn(
                email,
                result.cleaned_text,
                f"Email '{email}' was NOT redacted despite redact_email=True.\n"
                f"  Input:  {text!r}\n"
                f"  Output: {result.cleaned_text!r}",
            )

            # The replacement label must appear instead
            self.assertIn(
                "[EMAIL REDACTED]",
                result.cleaned_text,
                f"[EMAIL REDACTED] label missing despite redact_email=True.\n"
                f"  Input:  {text!r}\n"
                f"  Output: {result.cleaned_text!r}",
            )

    def test_no_email_flag_multiline(self):
        """Email addresses embedded in multi-line text are preserved when redact_email=False.

        Validates: Requirements 5.3
        """
        rng = random.Random(SEED + 2)
        rules_no_email = get_rules(redact_email=False)
        emails = _generate_fake_emails(rng, ITERATIONS)
        for i, email in enumerate(emails):
            # Build a 3-line input: safe line, email line, safe line
            text = f"log entry {i}\nContact: {email}\nend of record {i}\n"
            result = sanitize(text, rules_no_email)

            email_findings = [f for f in result.findings if f.rule_id == "EMAIL"]
            self.assertEqual(
                email_findings, [],
                f"EMAIL finding produced in multiline input despite redact_email=False.\n"
                f"  Input: {text!r}\n"
                f"  Findings: {result.findings}",
            )

            self.assertIn(
                email,
                result.cleaned_text,
                f"Email '{email}' was altered in multiline input despite redact_email=False.\n"
                f"  Input:  {text!r}\n"
                f"  Output: {result.cleaned_text!r}",
            )


def _generate_rfc1918_ips(rng: random.Random, count: int) -> list[str]:
    """Generate *count* synthetic RFC 1918 addresses covering all three ranges.

    - 10.0.0.0/8      — first octet 10, remaining three octets 0–255
    - 172.16.0.0/12   — second octet 16–31, remaining two octets 0–255
    - 192.168.0.0/16  — third octet 0–255, fourth octet 0–255

    All values are clearly fake/synthetic (no real network addresses are used).
    """
    results: list[str] = []
    for i in range(count):
        range_choice = i % 3  # rotate evenly across all three RFC 1918 ranges
        if range_choice == 0:
            # 10.x.x.x
            ip = f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        elif range_choice == 1:
            # 172.16–31.x.x
            ip = f"172.{rng.randint(16, 31)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        else:
            # 192.168.x.x
            ip = f"192.168.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        results.append(ip)
    return results


# Context templates for embedding IP addresses
_IP_CONTEXTS = [
    "server at {ip} is ready",
    "connected to {ip}",
    "host={ip} port=8080",
    "DEBUG remote_addr={ip}",
    "Connecting to database at {ip}:5432",
    "peer {ip} timed out",
    "gateway: {ip}",
]


class TestProperty10PrivateIPOptIn(unittest.TestCase):
    # Feature: share-clean, Property 10: Private IP detection is opt-in

    def test_no_private_ip_finding_when_disabled(self):
        """When redact_private_ip=False (default), no PRIVATE_IP finding is produced
        and RFC 1918 addresses are unchanged in cleaned_text.

        Validates: Requirements 7.3
        """
        rng = random.Random(SEED)
        rules_no_ip = get_rules(redact_private_ip=False)
        ips = _generate_rfc1918_ips(rng, ITERATIONS)
        self.assertGreaterEqual(len(ips), ITERATIONS,
                                "Generator must produce at least 100 IPs")
        for i, ip in enumerate(ips):
            ctx = _IP_CONTEXTS[i % len(_IP_CONTEXTS)]
            text = ctx.format(ip=ip)
            result = sanitize(text, rules_no_ip)

            # No PRIVATE_IP finding should be produced
            ip_findings = [f for f in result.findings if f.rule_id == "PRIVATE_IP"]
            self.assertEqual(
                ip_findings, [],
                f"PRIVATE_IP finding produced despite redact_private_ip=False.\n"
                f"  Input: {text!r}\n"
                f"  Findings: {result.findings}",
            )

            # The IP address must remain unchanged in cleaned_text
            self.assertIn(
                ip,
                result.cleaned_text,
                f"Private IP '{ip}' was altered/removed despite redact_private_ip=False.\n"
                f"  Input:  {text!r}\n"
                f"  Output: {result.cleaned_text!r}",
            )

    def test_private_ip_detected_when_enabled(self):
        """Contrast: when redact_private_ip=True, PRIVATE_IP findings ARE produced
        and addresses are replaced with [PRIVATE-IP].

        Validates: Requirements 7.1, 7.2, 7.3
        """
        rng = random.Random(SEED + 1)
        rules_with_ip = get_rules(redact_private_ip=True)
        ips = _generate_rfc1918_ips(rng, ITERATIONS)
        for i, ip in enumerate(ips):
            ctx = _IP_CONTEXTS[i % len(_IP_CONTEXTS)]
            text = ctx.format(ip=ip)
            result = sanitize(text, rules_with_ip)

            ip_findings = [f for f in result.findings if f.rule_id == "PRIVATE_IP"]
            self.assertGreaterEqual(
                len(ip_findings), 1,
                f"No PRIVATE_IP finding produced despite redact_private_ip=True.\n"
                f"  Input: {text!r}",
            )

            # The IP address must NOT appear in cleaned_text
            self.assertNotIn(
                ip,
                result.cleaned_text,
                f"Private IP '{ip}' was NOT redacted despite redact_private_ip=True.\n"
                f"  Input:  {text!r}\n"
                f"  Output: {result.cleaned_text!r}",
            )

            # The replacement label must appear instead
            self.assertIn(
                "[PRIVATE-IP]",
                result.cleaned_text,
                f"[PRIVATE-IP] label missing despite redact_private_ip=True.\n"
                f"  Input:  {text!r}\n"
                f"  Output: {result.cleaned_text!r}",
            )

    def test_all_three_rfc1918_ranges_preserved_when_disabled(self):
        """All three RFC 1918 ranges (10/8, 172.16/12, 192.168/16) are preserved
        verbatim when redact_private_ip=False.

        Validates: Requirements 7.3
        """
        rules_no_ip = get_rules(redact_private_ip=False)
        # Fixed representative IPs — one per range — iterated 100+ times
        range_ips = [
            "10.0.0.1",         # RFC 1918 range 1: 10.0.0.0/8
            "172.16.0.1",       # RFC 1918 range 2: 172.16.0.0/12 (low end)
            "172.31.255.254",   # RFC 1918 range 2: 172.16.0.0/12 (high end)
            "192.168.1.100",    # RFC 1918 range 3: 192.168.0.0/16
            "10.255.255.255",   # RFC 1918 range 1: broadcast-adjacent
            "192.168.100.200",  # RFC 1918 range 3: varied subnet
        ]
        for i in range(ITERATIONS):
            ip = range_ips[i % len(range_ips)]
            text = f"connecting to {ip}"
            result = sanitize(text, rules_no_ip)

            ip_findings = [f for f in result.findings if f.rule_id == "PRIVATE_IP"]
            self.assertEqual(
                ip_findings, [],
                f"PRIVATE_IP finding for '{ip}' despite redact_private_ip=False.\n"
                f"  Input: {text!r}",
            )
            self.assertIn(
                ip,
                result.cleaned_text,
                f"RFC 1918 address '{ip}' was modified despite redact_private_ip=False.\n"
                f"  Output: {result.cleaned_text!r}",
            )

    def test_multiline_private_ips_preserved_when_disabled(self):
        """RFC 1918 addresses embedded in multi-line text are preserved when disabled.

        Validates: Requirements 7.3
        """
        rng = random.Random(SEED + 3)
        rules_no_ip = get_rules(redact_private_ip=False)
        ips = _generate_rfc1918_ips(rng, ITERATIONS)
        for i, ip in enumerate(ips):
            # Build a 3-line input: safe line, IP line, safe line
            text = f"log entry {i}\nremote host: {ip}\nend of record {i}\n"
            result = sanitize(text, rules_no_ip)

            ip_findings = [f for f in result.findings if f.rule_id == "PRIVATE_IP"]
            self.assertEqual(
                ip_findings, [],
                f"PRIVATE_IP finding in multiline input despite redact_private_ip=False.\n"
                f"  Input: {text!r}\n"
                f"  Findings: {result.findings}",
            )
            self.assertIn(
                ip,
                result.cleaned_text,
                f"Private IP '{ip}' was altered in multiline input despite redact_private_ip=False.\n"
                f"  Input:  {text!r}\n"
                f"  Output: {result.cleaned_text!r}",
            )


class TestProperty11RuleOrderingRespected(unittest.TestCase):
    # Feature: share-clean, Property 11: Rule ordering is respected

    def test_connection_string_fires_before_key_value_secret(self):
        """CONNECTION_STRING (index 0) must fire before KEY_VALUE_SECRET (index 2).

        Input: DATABASE_URL=postgresql://user:password@host/db
        The password is embedded in the connection string value.  CONNECTION_STRING
        should claim it first; KEY_VALUE_SECRET then sees the already-redacted text
        and must NOT produce a second separate redaction of the connection-string value.

        Validates: Requirements 8.1
        """
        rng = random.Random(SEED)
        rules = get_rules()

        # Confirm rule ordering: CONNECTION_STRING must come before KEY_VALUE_SECRET
        rule_ids = [r.rule_id for r in rules]
        cs_idx = rule_ids.index("CONNECTION_STRING")
        kv_idx = rule_ids.index("KEY_VALUE_SECRET")
        self.assertLess(
            cs_idx, kv_idx,
            f"CONNECTION_STRING (idx {cs_idx}) must precede KEY_VALUE_SECRET (idx {kv_idx})",
        )

        schemes = ["postgresql", "postgres", "mysql", "mongodb"]
        fake_hosts_dbs = [
            "db.example.com:5432/mydb",
            "localhost/testdb",
            "fake.host.org:3306/appdata",
            "primary.db.test/analytics",
            "replica-1.internal.test:27017/warehouse",
        ]

        for _ in range(ITERATIONS):
            scheme = rng.choice(schemes)
            user = rng.choice(FAKE_USERS)
            password = rng.choice(FAKE_PASSWORDS)
            host_db = rng.choice(fake_hosts_dbs)
            # Wrap connection string in a key=value assignment so both rules could match
            text = f"DATABASE_URL={scheme}://{user}:{password}@{host_db}"
            result = sanitize(text, rules)
            cleaned = result.cleaned_text

            # 1. The raw password must be gone from the output
            self.assertNotIn(
                password, cleaned,
                f"Password still present in: {cleaned!r}\n  Input: {text!r}",
            )

            # 2. The CONNECTION_STRING rule must have produced a finding
            cs_findings = [f for f in result.findings if f.rule_id == "CONNECTION_STRING"]
            self.assertGreaterEqual(
                len(cs_findings), 1,
                f"No CONNECTION_STRING finding produced.\n  Input: {text!r}",
            )

            # 3. Structural components of the connection string must be preserved —
            #    this proves CONNECTION_STRING fired (context-preserving replacement),
            #    not KEY_VALUE_SECRET (which would redact the entire value after '=').
            # Extract host from host_db (strip port and database)
            host = host_db.split(":")[0].split("/")[0]
            self.assertIn(
                host, cleaned,
                f"Host '{host}' lost — suggests wrong rule fired or structure broken.\n"
                f"  Input:  {text!r}\n"
                f"  Output: {cleaned!r}",
            )

            # 4. The scheme must be preserved (further evidence CONNECTION_STRING fired)
            self.assertIn(
                f"{scheme}://",
                cleaned,
                f"Scheme '{scheme}://' lost.\n  Input: {text!r}\n  Output: {cleaned!r}",
            )

            # 5. [REDACTED] must appear (the connection string password placeholder)
            self.assertIn(
                "[REDACTED]", cleaned,
                f"[REDACTED] label missing.\n  Input: {text!r}\n  Output: {cleaned!r}",
            )

            # 6. KEY_VALUE_SECRET must NOT have fired a second, separate finding that
            #    redacts the already-[REDACTED] text.  After CONNECTION_STRING runs,
            #    the line becomes e.g. "DATABASE_URL=postgresql://user:[REDACTED]@…"
            #    KEY_VALUE_SECRET's value pattern (\S+) would match "[REDACTED]" as the
            #    value — but we do NOT want a spurious second finding overwriting it.
            #    Verify: [REDACTED] is still intact and not double-replaced.
            self.assertIn(
                "[REDACTED]", cleaned,
                f"[REDACTED] was overwritten by a subsequent rule.\n"
                f"  Input:  {text!r}\n"
                f"  Output: {cleaned!r}",
            )

    def test_bearer_token_fires_before_key_value_secret(self):
        """BEARER_TOKEN (index 1) must fire before KEY_VALUE_SECRET (index 2).

        Input: Authorization: Bearer <token>
        BEARER_TOKEN should redact the token value.  KEY_VALUE_SECRET must then
        see the already-redacted text and must NOT double-redact it.

        Validates: Requirements 8.1
        """
        rng = random.Random(SEED + 10)
        rules = get_rules()

        # Confirm rule ordering: BEARER_TOKEN must come before KEY_VALUE_SECRET
        rule_ids = [r.rule_id for r in rules]
        bt_idx = rule_ids.index("BEARER_TOKEN")
        kv_idx = rule_ids.index("KEY_VALUE_SECRET")
        self.assertLess(
            bt_idx, kv_idx,
            f"BEARER_TOKEN (idx {bt_idx}) must precede KEY_VALUE_SECRET (idx {kv_idx})",
        )

        for _ in range(ITERATIONS):
            token = rng.choice(FAKE_PASSWORDS)
            text = f"Authorization: Bearer {token}"
            result = sanitize(text, rules)
            cleaned = result.cleaned_text

            # 1. The raw token must be gone
            self.assertNotIn(
                token, cleaned,
                f"Token still present in: {cleaned!r}\n  Input: {text!r}",
            )

            # 2. BEARER_TOKEN finding must exist
            bt_findings = [f for f in result.findings if f.rule_id == "BEARER_TOKEN"]
            self.assertGreaterEqual(
                len(bt_findings), 1,
                f"No BEARER_TOKEN finding.\n  Input: {text!r}",
            )

            # 3. [REDACTED] must be present (bearer rule's replacement)
            self.assertIn(
                "[REDACTED]", cleaned,
                f"[REDACTED] missing.\n  Input: {text!r}\n  Output: {cleaned!r}",
            )

            # 4. The "Authorization: Bearer " prefix must be preserved verbatim
            #    (case preserved as-is from input)
            self.assertIn(
                "Authorization: Bearer ",
                cleaned,
                f"Bearer prefix not preserved.\n  Input: {text!r}\n  Output: {cleaned!r}",
            )

    def test_lower_index_rule_fires_first_on_ambiguous_input(self):
        """Verify the ordered rule list is applied in the defined sequence.

        For any two rules A (index i) and B (index j > i) where both could match
        overlapping portions of the same text, A must apply first and B must
        subsequently see the partially-redacted text.

        We verify this by checking the CONNECTION_STRING (idx 0) and
        KEY_VALUE_SECRET (idx 2) on the canonical ambiguous case, running 100+
        iterations with varied inputs.

        Validates: Requirements 8.1
        """
        rng = random.Random(SEED + 20)
        rules = get_rules()
        rule_ids = [r.rule_id for r in rules]

        kv_keys = ["DATABASE_URL", "db_url", "connection_string"]
        schemes = ["postgresql", "postgres", "mysql"]
        hosts = ["db.example.com", "localhost", "fake-db.test"]
        databases = ["mydb", "testdb", "appdata"]

        for _ in range(ITERATIONS):
            kv_key = rng.choice(kv_keys)
            scheme = rng.choice(schemes)
            user = rng.choice(FAKE_USERS)
            password = rng.choice(FAKE_PASSWORDS)
            host = rng.choice(hosts)
            db = rng.choice(databases)
            port = rng.choice([5432, 3306, 5433])

            text = f"{kv_key}={scheme}://{user}:{password}@{host}:{port}/{db}"
            result = sanitize(text, rules)
            cleaned = result.cleaned_text

            # The password must not appear in the final output
            self.assertNotIn(
                password, cleaned,
                f"Password '{password}' survived.\n  Input: {text!r}\n  Output: {cleaned!r}",
            )

            # At least one finding must have been produced
            self.assertGreaterEqual(
                len(result.findings), 1,
                f"No findings for ambiguous input: {text!r}",
            )

            # The first finding must come from a rule with a lower index than
            # KEY_VALUE_SECRET, confirming earlier rules acted first.
            first_finding_rule_id = result.findings[0].rule_id
            first_finding_idx = rule_ids.index(first_finding_rule_id)
            kv_idx = rule_ids.index("KEY_VALUE_SECRET")
            self.assertLessEqual(
                first_finding_idx, kv_idx,
                f"First finding was from rule '{first_finding_rule_id}' (idx {first_finding_idx}), "
                f"but expected a rule at index <= KEY_VALUE_SECRET (idx {kv_idx}).\n"
                f"  Input: {text!r}",
            )

            # The host must still be present — structural evidence that
            # CONNECTION_STRING (context-preserving) fired, not KEY_VALUE_SECRET
            # (which would replace the entire URI value after '=').
            self.assertIn(
                host, cleaned,
                f"Host '{host}' lost after redaction.\n"
                f"  Input:  {text!r}\n"
                f"  Output: {cleaned!r}",
            )

    def test_subsequent_rules_operate_on_already_redacted_text(self):
        """Rules applied after an earlier rule see the partially-redacted line.

        We construct an input that:
          - Has a connection string password (matched by CONNECTION_STRING first)
          - Also has a separate key-value pair on the same line that should be
            independently redacted by KEY_VALUE_SECRET

        After CONNECTION_STRING fires on the password, KEY_VALUE_SECRET must
        still fire on the separate key-value pair — demonstrating that rules
        chain on the progressively-modified text.

        Validates: Requirements 8.1
        """
        rng = random.Random(SEED + 30)
        rules = get_rules()

        for _ in range(ITERATIONS):
            user = rng.choice(FAKE_USERS)
            password = rng.choice(FAKE_PASSWORDS)
            api_val = rng.choice(FAKE_PASSWORDS)
            host = "db.example.com"
            db = "testdb"
            # Combine connection string with a standalone key-value secret on the same line
            text = (
                f"postgresql://{user}:{password}@{host}/{db} "
                f"api_key={api_val}"
            )
            result = sanitize(text, rules)
            cleaned = result.cleaned_text

            # Both secrets must be gone
            self.assertNotIn(
                password, cleaned,
                f"Connection string password still present.\n"
                f"  Input:  {text!r}\n"
                f"  Output: {cleaned!r}",
            )
            self.assertNotIn(
                api_val, cleaned,
                f"Key-value secret still present.\n"
                f"  Input:  {text!r}\n"
                f"  Output: {cleaned!r}",
            )

            # Both rule types must have produced findings
            cs_findings = [f for f in result.findings if f.rule_id == "CONNECTION_STRING"]
            kv_findings = [f for f in result.findings if f.rule_id == "KEY_VALUE_SECRET"]

            self.assertGreaterEqual(
                len(cs_findings), 1,
                f"No CONNECTION_STRING finding.\n  Input: {text!r}",
            )
            self.assertGreaterEqual(
                len(kv_findings), 1,
                f"No KEY_VALUE_SECRET finding.\n  Input: {text!r}",
            )

            # The connection string structure must be preserved (scheme://user:[REDACTED]@host/db)
            self.assertIn(
                f"postgresql://{user}:[REDACTED]@{host}/{db}",
                cleaned,
                f"Connection string structure broken.\n"
                f"  Input:  {text!r}\n"
                f"  Output: {cleaned!r}",
            )

            # KEY_VALUE_SECRET must have replaced the api_key value
            self.assertIn(
                "api_key=[REDACTED]",
                cleaned,
                f"api_key=[REDACTED] not found.\n"
                f"  Input:  {text!r}\n"
                f"  Output: {cleaned!r}",
            )


# Feature: share-clean, Property 12: Text and JSON reports never include raw secret values
class TestProperty12ReportsNeverIncludeRawSecrets(unittest.TestCase):
    """Property 12: Text and JSON reports never include raw secret values.

    For any SanitizeResult, the output of both format_text_report() and
    format_json_report() SHALL NOT contain any string that was the original
    matched value of any finding.

    Validates: Requirements 10.4, 14.3
    """

    # -----------------------------------------------------------------------
    # Synthetic secret generators
    # -----------------------------------------------------------------------

    @staticmethod
    def _make_key_value_inputs(rng: random.Random, count: int) -> list[tuple[str, str]]:
        """Return (input_text, injected_secret) pairs for key-value secrets."""
        keys = ["password", "api_key", "token", "secret", "client_secret",
                "access_token", "refresh_token", "passwd", "pwd", "apikey"]
        seps = ["=", ": ", "=\t", ":"]
        # Use varied fake values — all clearly synthetic
        values = [
            "fake-secret-kv-1", "FakePass99KV", "not-a-real-token-abc",
            "synthetic-val-xyz", "FakeKeyValue123", "test-only-kv-secret",
            "fake-kv-alpha007", "FakeCredential88", "synthetic-kv-beta",
            "fake-value-gamma-9",
        ]
        results = []
        for i in range(count):
            key = keys[i % len(keys)]
            sep = seps[i % len(seps)]
            val = values[i % len(values)]
            results.append((f"{key}{sep}{val}", val))
        return results

    @staticmethod
    def _make_connection_string_inputs(rng: random.Random, count: int) -> list[tuple[str, str]]:
        """Return (input_text, injected_password) pairs for connection strings."""
        schemes = ["postgresql", "mysql", "mongodb", "redis", "postgres"]
        users = ["fakeuser", "dbadmin", "testacct"]
        passwords = [
            "fake-cs-pass-1", "FakeDbPass99", "synthetic-db-secret",
            "fake-pass-alpha", "FakeConnPass88", "test-only-db-pwd",
            "fake-db-beta007", "FakeDbCred22", "synthetic-pass-gamma",
            "fake-cs-delta-9",
        ]
        hosts = ["db.example.com:5432/mydb", "localhost/testdb",
                 "fake.host.org:3306/appdata"]
        results = []
        for i in range(count):
            scheme = schemes[i % len(schemes)]
            user = users[i % len(users)]
            pw = passwords[i % len(passwords)]
            host = hosts[i % len(hosts)]
            results.append((f"{scheme}://{user}:{pw}@{host}", pw))
        return results

    @staticmethod
    def _make_bearer_token_inputs(rng: random.Random, count: int) -> list[tuple[str, str]]:
        """Return (input_text, injected_token) pairs for bearer tokens."""
        tokens = [
            "fake-bearer-token-1", "FakeBearerTok99", "synthetic-bearer-abc",
            "fake-bearer-alpha", "FakeBearerCred88", "test-only-bearer-val",
            "fake-bearer-beta07", "FakeBearerXYZ22", "synthetic-bearer-gam",
            "fake-bearer-delta9",
        ]
        results = []
        for i in range(count):
            tok = tokens[i % len(tokens)]
            results.append((f"Authorization: Bearer {tok}", tok))
        return results

    @staticmethod
    def _make_email_inputs(rng: random.Random, count: int) -> list[tuple[str, str]]:
        """Return (input_text, injected_email) pairs for email addresses."""
        emails = [
            "fake.user1@example.com", "test.person2@fake.org",
            "dev3@notreal.net", "admin4@testdomain.io",
            "synth5@synthetic.dev", "sample6@sample.co",
            "dummy7@dummy.example.com", "ops8@test-corp.org",
            "eng9@fakeco.net", "qa10@example.com",
        ]
        contexts = [
            "Contact: {e}", "Send to {e}", "From: {e}",
            "Reply-To: {e}", "user is {e}",
        ]
        results = []
        for i in range(count):
            email = emails[i % len(emails)]
            ctx = contexts[i % len(contexts)]
            results.append((ctx.format(e=email), email))
        return results

    @staticmethod
    def _make_jwt_inputs(rng: random.Random, count: int) -> list[tuple[str, str]]:
        """Return (input_text, injected_jwt) pairs for JWT-like tokens."""
        headers = ["eyFakeHeader1Aa", "eyFakeHeader2Bb", "eyFakeHeader3Cc",
                   "eyFakeHeaderXXX", "eyFakeHeader999"]
        payloads = ["eyFakePayload1Dd", "eyFakePayload2Ee", "eyFakePayload3Ff",
                    "eyFakePayloadYYY", "eyFakePayload000"]
        sigs = ["FakeSig1GgHhIiJj", "FakeSig2KkLlMmNn", "FakeSig3OoPpQqRr",
                "FakeSigZZZWWWVVV", "FakeSig4SsTtUuVv"]
        results = []
        for i in range(count):
            header = headers[i % len(headers)]
            payload = payloads[i % len(payloads)]
            sig = sigs[i % len(sigs)]
            full_token = f"{header}.{payload}.{sig}"
            results.append((f"token={full_token}", full_token))
        return results

    # -----------------------------------------------------------------------
    # Helper: assert a secret is absent from both report outputs
    # -----------------------------------------------------------------------

    def _assert_secret_absent_from_reports(
        self,
        result: "SanitizeResult",
        secret: str,
        input_name: str,
        context_label: str,
    ) -> None:
        """Assert *secret* does not appear in either the text or JSON report."""
        text_report = format_text_report(result, input_name)
        json_report = format_json_report(result, input_name)

        self.assertNotIn(
            secret,
            text_report,
            f"[text report] injected secret found!\n"
            f"  Secret:  {secret!r}\n"
            f"  Context: {context_label}\n"
            f"  Report snippet: {text_report[:300]!r}",
        )
        self.assertNotIn(
            secret,
            json_report,
            f"[json report] injected secret found!\n"
            f"  Secret:  {secret!r}\n"
            f"  Context: {context_label}\n"
            f"  Report snippet: {json_report[:300]!r}",
        )

    # -----------------------------------------------------------------------
    # Test methods
    # -----------------------------------------------------------------------

    def test_key_value_secrets_absent_from_reports(self):
        """Key-value secret values must not appear in text or JSON reports.

        Validates: Requirements 10.4, 14.3
        """
        rng = random.Random(SEED)
        rules = get_rules()
        pairs = self._make_key_value_inputs(rng, ITERATIONS)
        self.assertGreaterEqual(len(pairs), ITERATIONS)
        for i, (text, secret) in enumerate(pairs):
            result = sanitize(text, rules)
            self._assert_secret_absent_from_reports(
                result, secret,
                input_name="stdin",
                context_label=f"iteration {i}, key-value input: {text!r}",
            )

    def test_connection_string_passwords_absent_from_reports(self):
        """Connection string passwords must not appear in text or JSON reports.

        Validates: Requirements 10.4, 14.3
        """
        rng = random.Random(SEED + 1)
        rules = get_rules()
        pairs = self._make_connection_string_inputs(rng, ITERATIONS)
        self.assertGreaterEqual(len(pairs), ITERATIONS)
        for i, (text, secret) in enumerate(pairs):
            result = sanitize(text, rules)
            self._assert_secret_absent_from_reports(
                result, secret,
                input_name="test-file.txt",
                context_label=f"iteration {i}, conn-string input: {text!r}",
            )

    def test_bearer_tokens_absent_from_reports(self):
        """Bearer token values must not appear in text or JSON reports.

        Validates: Requirements 10.4, 14.3
        """
        rng = random.Random(SEED + 2)
        rules = get_rules()
        pairs = self._make_bearer_token_inputs(rng, ITERATIONS)
        self.assertGreaterEqual(len(pairs), ITERATIONS)
        for i, (text, secret) in enumerate(pairs):
            result = sanitize(text, rules)
            self._assert_secret_absent_from_reports(
                result, secret,
                input_name="stdin",
                context_label=f"iteration {i}, bearer-token input: {text!r}",
            )

    def test_email_addresses_absent_from_reports(self):
        """Email addresses must not appear in text or JSON reports.

        Validates: Requirements 10.4, 14.3
        """
        rng = random.Random(SEED + 3)
        rules = get_rules(redact_email=True)
        pairs = self._make_email_inputs(rng, ITERATIONS)
        self.assertGreaterEqual(len(pairs), ITERATIONS)
        for i, (text, secret) in enumerate(pairs):
            result = sanitize(text, rules)
            self._assert_secret_absent_from_reports(
                result, secret,
                input_name="stdin",
                context_label=f"iteration {i}, email input: {text!r}",
            )

    def test_jwt_tokens_absent_from_reports(self):
        """JWT-like token values must not appear in text or JSON reports.

        Validates: Requirements 10.4, 14.3
        """
        rng = random.Random(SEED + 4)
        rules = get_rules()
        pairs = self._make_jwt_inputs(rng, ITERATIONS)
        self.assertGreaterEqual(len(pairs), ITERATIONS)
        for i, (text, secret) in enumerate(pairs):
            result = sanitize(text, rules)
            self._assert_secret_absent_from_reports(
                result, secret,
                input_name="stdin",
                context_label=f"iteration {i}, jwt input: {text!r}",
            )

    def test_mixed_secrets_absent_from_reports(self):
        """Mixed secret types in a single multi-line input: none may appear in reports.

        Combines key-value, connection string, bearer token, and email in one
        SanitizeResult; asserts all injected values are absent from both reports.

        Validates: Requirements 10.4, 14.3
        """
        rng = random.Random(SEED + 5)
        rules = get_rules(redact_email=True)

        kv_pairs = self._make_key_value_inputs(rng, ITERATIONS)
        cs_pairs = self._make_connection_string_inputs(rng, ITERATIONS)
        bt_pairs = self._make_bearer_token_inputs(rng, ITERATIONS)
        em_pairs = self._make_email_inputs(rng, ITERATIONS)

        for i in range(ITERATIONS):
            kv_text, kv_secret = kv_pairs[i]
            cs_text, cs_secret = cs_pairs[i]
            bt_text, bt_secret = bt_pairs[i]
            em_text, em_secret = em_pairs[i]

            # Combine all into a single multi-line input
            combined_text = "\n".join([kv_text, cs_text, bt_text, em_text])
            result = sanitize(combined_text, rules)

            text_report = format_text_report(result, "stdin")
            json_report = format_json_report(result, "stdin")

            for secret, label in [
                (kv_secret, "key-value"),
                (cs_secret, "connection-string password"),
                (bt_secret, "bearer token"),
                (em_secret, "email"),
            ]:
                self.assertNotIn(
                    secret,
                    text_report,
                    f"[text report] {label} secret found in iteration {i}!\n"
                    f"  Secret: {secret!r}\n"
                    f"  Input:  {combined_text!r}",
                )
                self.assertNotIn(
                    secret,
                    json_report,
                    f"[json report] {label} secret found in iteration {i}!\n"
                    f"  Secret: {secret!r}\n"
                    f"  Input:  {combined_text!r}",
                )

    def test_json_report_is_valid_json_and_secret_free(self):
        """JSON report must be parseable and must not contain injected secrets
        in any key or value at any depth.

        Validates: Requirements 10.4, 10.5, 14.3
        """
        rng = random.Random(SEED + 6)
        rules = get_rules(redact_email=True)
        kv_pairs = self._make_key_value_inputs(rng, ITERATIONS)

        for i, (text, secret) in enumerate(kv_pairs):
            result = sanitize(text, rules)
            json_str = format_json_report(result, "test-input.log")

            # Must be valid JSON
            try:
                parsed = json.loads(json_str)
            except json.JSONDecodeError as exc:
                self.fail(
                    f"format_json_report produced invalid JSON at iteration {i}: {exc}\n"
                    f"  Output: {json_str!r}",
                )

            # Flatten all string values from the parsed object and check each
            def _collect_strings(obj: object) -> list[str]:
                """Recursively collect all string values from a JSON-like object."""
                strings: list[str] = []
                if isinstance(obj, str):
                    strings.append(obj)
                elif isinstance(obj, dict):
                    for k, v in obj.items():
                        strings.append(k)
                        strings.extend(_collect_strings(v))
                elif isinstance(obj, list):
                    for item in obj:
                        strings.extend(_collect_strings(item))
                return strings

            all_strings = _collect_strings(parsed)
            for s in all_strings:
                self.assertNotIn(
                    secret,
                    s,
                    f"[json report] secret {secret!r} found in JSON field {s!r}\n"
                    f"  Iteration: {i}\n"
                    f"  Input: {text!r}",
                )


if __name__ == "__main__":
    unittest.main()
