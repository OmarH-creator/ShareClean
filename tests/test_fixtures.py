"""Fake-secret corpus regression tests."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import re
import unittest

from shareclean.detectors import get_rules
from shareclean.redactor import sanitize

FIXTURE_DIR = Path(__file__).parent / "fixtures"
MANIFEST = FIXTURE_DIR / "corpus_manifest.json"
FAKE_MARKERS = ("fake", "test", "testing", "example", "demo")
SENSITIVE_LOOKING_PATTERNS = (
    re.compile(r"ghp_[A-Za-z0-9_]+"),
    re.compile(r"AKIA[A-Z0-9]+"),
    re.compile(r"(?i)\bauthorization\s*:\s*bearer\s+\S+"),
    re.compile(
        r"(?i)\b(?:password|passwd|pwd|api[_-]?key|apikey|token|"
        r"access[_-]?token|refresh[_-]?token|secret|client[_-]?secret)"
        r"\s*[:=]\s*\S+"
    ),
    re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb|redis)://\S+"),
    re.compile(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
        r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
        r"192\.168\.\d{1,3}\.\d{1,3})\b"
    ),
)
PEM_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?"
    r"-----END [A-Z0-9 ]*PRIVATE KEY-----"
)


class TestFakeSecretCorpus(unittest.TestCase):
    def test_all_manifest_packs_match_expected_counts(self) -> None:
        entries = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(entries), 8)
        for entry in entries:
            with self.subTest(path=entry["path"]):
                text = (FIXTURE_DIR / entry["path"]).read_text(encoding="utf-8")
                result = sanitize(text, get_rules(redact_private_ip=True))
                counts = Counter(finding.category for finding in result.findings)
                self.assertEqual(dict(counts), entry["by_category"])

    def test_corpus_contains_only_obviously_fake_sensitive_values(self) -> None:
        entries = json.loads(MANIFEST.read_text(encoding="utf-8"))
        fixture_paths = {Path(entry["path"]) for entry in entries}
        fixture_paths.add(Path("sample_log.txt"))
        for relative_path in sorted(fixture_paths):
            path = FIXTURE_DIR / relative_path
            text = path.read_text(encoding="utf-8")
            for match in PEM_PRIVATE_KEY_PATTERN.finditer(text):
                lower_value = match.group(0).lower()
                self.assertTrue(
                    any(marker in lower_value for marker in FAKE_MARKERS),
                    f"{relative_path} has a private-key fixture without a fake marker",
                )
            relative_path = path.relative_to(FIXTURE_DIR)
            for line_number, line in enumerate(text.splitlines(), 1):
                lower_line = line.lower()
                for pattern in SENSITIVE_LOOKING_PATTERNS:
                    for match in pattern.finditer(line):
                        lower_value = match.group(0).lower()
                        self.assertTrue(
                            any(
                                marker in lower_value or marker in lower_line
                                for marker in FAKE_MARKERS
                            ),
                            (
                                f"{relative_path}:{line_number} has a sensitive-looking "
                                "fixture value without a fake/test/example/demo marker"
                            ),
                        )


if __name__ == "__main__":
    unittest.main()
