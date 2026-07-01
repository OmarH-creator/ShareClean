"""Core redaction engine for ShareClean."""

from __future__ import annotations

from dataclasses import dataclass

from shareclean.detectors import Rule, SEVERITY_RANK
from shareclean.models import Finding, Location, Position, SanitizeResult


@dataclass(frozen=True)
class _Candidate:
    rule: Rule
    start: int
    end: int

    @property
    def severity_rank(self) -> int:
        return SEVERITY_RANK[self.rule.severity]

    @property
    def span_length(self) -> int:
        return self.end - self.start


def _position_at(text: str, offset: int) -> Position:
    """Return the 1-based normalized position for a raw string offset."""
    line = 1
    column = 1
    index = 0

    while index < offset:
        if text.startswith("\r\n", index):
            line += 1
            column = 1
            index += 2
            continue
        if text[index] in {"\n", "\r"}:
            line += 1
            column = 1
        else:
            column += 1
        index += 1

    return Position(line=line, column=column)


def _location_for(text: str, start: int, end: int) -> Location:
    return Location(start=_position_at(text, start), end=_position_at(text, end))


def _overlaps(candidate: _Candidate, selected: list[_Candidate]) -> bool:
    return any(candidate.start < item.end and item.start < candidate.end for item in selected)


def _collect_candidates(text: str, rules: list[Rule]) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    for rule in rules:
        for match in rule.pattern.finditer(text):
            if not rule.is_valid(match):
                continue
            start, end = rule.redact_span(match)
            if start == end:
                continue
            candidates.append(_Candidate(rule=rule, start=start, end=end))
    return candidates


def _resolve_overlaps(candidates: list[_Candidate]) -> list[_Candidate]:
    """Choose one candidate for each overlapping character range."""
    ranked = sorted(
        candidates,
        key=lambda item: (
            -item.severity_rank,
            -item.rule.specificity,
            -item.span_length,
            item.start,
            item.end,
            item.rule.rule_id,
        ),
    )
    selected: list[_Candidate] = []
    for candidate in ranked:
        if not _overlaps(candidate, selected):
            selected.append(candidate)
    return sorted(selected, key=lambda item: (item.start, item.end, item.rule.rule_id))


def sanitize(text: str, rules: list[Rule]) -> SanitizeResult:
    """Apply *rules* to *text* without storing original matched values.

    Detectors run against the original input. When detector spans overlap,
    ShareClean emits one finding using the highest-severity rule; ties choose
    the most specific detector.
    """
    candidates = _resolve_overlaps(_collect_candidates(text, rules))
    findings = [
        Finding(
            rule_id=candidate.rule.rule_id,
            category=candidate.rule.category,
            severity=candidate.rule.severity,
            location=_location_for(text, candidate.start, candidate.end),
            replacement=candidate.rule.replacement,
        )
        for candidate in candidates
    ]

    cleaned = text
    for candidate in sorted(candidates, key=lambda item: item.start, reverse=True):
        cleaned = (
            cleaned[:candidate.start]
            + candidate.rule.replacement
            + cleaned[candidate.end:]
        )

    return SanitizeResult(cleaned_text=cleaned, findings=findings)
