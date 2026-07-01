"""Selector parsing for ShareClean check-mode decisions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from shareclean.detectors import SEVERITY_RANK, VALID_CATEGORIES, VALID_SEVERITIES
from shareclean.models import Finding

VALID_RULE_IDS = frozenset({
    "SC001",
    "SC002",
    "SC003",
    "SC004",
    "SC005",
    "SC006",
    "SC007",
    "SC008",
})


class SelectorError(ValueError):
    """Raised when a --fail-on or --ignore-for-check selector is invalid."""


@dataclass(frozen=True)
class Selector:
    kind: str
    value: str

    def matches(self, finding: Finding) -> bool:
        if self.kind == "rule":
            return finding.rule_id == self.value
        if self.kind == "category":
            return finding.category == self.value
        if self.kind == "severity":
            return SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[self.value]
        raise AssertionError(f"unsupported selector kind: {self.kind}")


def parse_selector_values(values: Iterable[str] | None) -> list[Selector]:
    """Parse comma-separated selector strings."""
    selectors: list[Selector] = []
    for raw_value in values or []:
        for part in raw_value.split(","):
            item = part.strip()
            if not item:
                continue
            try:
                kind, value = item.split(":", 1)
            except ValueError as exc:
                raise SelectorError(
                    f"Invalid selector {item!r}; expected kind:value."
                ) from exc
            kind = kind.strip().lower()
            value = value.strip()
            if kind == "rule":
                value = value.upper()
                if value not in VALID_RULE_IDS:
                    raise SelectorError(f"Unknown rule selector: {value}")
            elif kind == "category":
                value = value.lower()
                if value not in VALID_CATEGORIES:
                    raise SelectorError(f"Unknown category selector: {value}")
            elif kind == "severity":
                value = value.lower()
                if value not in VALID_SEVERITIES:
                    raise SelectorError(f"Unknown severity selector: {value}")
            else:
                raise SelectorError(f"Unknown selector kind: {kind}")
            selectors.append(Selector(kind=kind, value=value))
    return selectors


def matches_any(finding: Finding, selectors: list[Selector]) -> bool:
    return any(selector.matches(finding) for selector in selectors)


def findings_for_check(
    findings: list[Finding],
    *,
    fail_on: list[Selector],
    ignore_for_check: list[Selector],
) -> list[Finding]:
    """Return the findings that should make --check fail."""
    active = [
        finding
        for finding in findings
        if not matches_any(finding, ignore_for_check)
    ]
    if not fail_on:
        return active
    return [finding for finding in active if matches_any(finding, fail_on)]
