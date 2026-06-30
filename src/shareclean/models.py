"""Core data models for ShareClean.

Finding and SanitizeResult are the shared data types passed between
the redactor, report formatter, and CLI.
"""

from dataclasses import dataclass, field


@dataclass
class Finding:
    """A single detected instance of sensitive content.

    Stores only the metadata about a match - never the original matched value.
    """

    rule_id: str        # e.g. "KEY_VALUE_SECRET"
    category: str       # e.g. "Key-value secret"
    line_number: int    # 1-indexed line in the original input
    replacement: str    # the replacement label used, e.g. "[REDACTED]"
    # NOTE: the original matched value is intentionally NOT stored


@dataclass
class SanitizeResult:
    """The output of a redaction pass: cleaned text and list of findings."""

    cleaned_text: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def replacement_count(self) -> int:
        """Return the number of replacements made (equals len(findings))."""
        return len(self.findings)
