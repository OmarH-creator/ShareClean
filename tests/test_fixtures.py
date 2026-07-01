"""Fake-secret corpus regression tests."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import unittest

from shareclean.detectors import get_rules
from shareclean.redactor import sanitize

FIXTURE_DIR = Path(__file__).parent / "fixtures"
MANIFEST = FIXTURE_DIR / "corpus_manifest.json"


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
        corpus_text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in FIXTURE_DIR.glob("**/*")
            if path.is_file() and path.name not in {"corpus_manifest.json", ".gitkeep"}
        )
        lower = corpus_text.lower()
        self.assertNotIn("ghp_", lower.replace("ghp_fake", ""))
        self.assertNotIn("akia", lower.replace("akiafake", ""))
        for suspicious in ["password", "token", "secret", "private key"]:
            if suspicious in lower:
                self.assertTrue(
                    any(marker in lower for marker in ["fake", "test", "example", "demo"]),
                    f"corpus values mentioning {suspicious!r} must be visibly fake",
                )


if __name__ == "__main__":
    unittest.main()
