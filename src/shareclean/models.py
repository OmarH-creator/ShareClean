"""Core data models for ShareClean.

Finding and SanitizeResult are the shared data types passed between the
redactor, report formatter, and CLI. They intentionally store metadata only:
never matched values, hashes, snippets, or masked previews.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Position:
    """A 1-based position in normalized input text."""

    line: int
    column: int


@dataclass(frozen=True)
class Location:
    """A start/end location range.

    Locations are 1-based, and the end position is exclusive. Columns count
    Unicode code points after CRLF has been treated as a single LF newline for
    location purposes.
    """

    start: Position
    end: Position


@dataclass(frozen=True)
class Finding:
    """A single detected instance of sensitive content."""

    rule_id: str
    category: str
    severity: str
    location: Location
    replacement: str

    @property
    def line_number(self) -> int:
        """Backward-compatible access to the finding start line."""
        return self.location.start.line

    @property
    def column_number(self) -> int:
        """Backward-compatible access to the finding start column."""
        return self.location.start.column


@dataclass
class SanitizeResult:
    """The output of a redaction pass: cleaned text and safe findings."""

    cleaned_text: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def replacement_count(self) -> int:
        """Return the number of replacements made (equals len(findings))."""
        return len(self.findings)
