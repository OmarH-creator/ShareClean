"""Report formatting for ShareClean.

Reports never include original matched values, hashes, snippets, masked
previews, filenames, or full paths.
"""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from shareclean.models import Finding, SanitizeResult

SCHEMA_VERSION = "1.0"

_DISCLAIMER = (
    "NOTE: This report lists only safe metadata. Original sensitive values, "
    "hashes, snippets, filenames, and paths are never displayed."
)


def safe_source(input_name: str) -> str:
    """Return the privacy-preserving source label for report output."""
    return "stdin" if input_name == "stdin" else "file"


def _summary(result: SanitizeResult) -> dict[str, Any]:
    by_category = Counter(finding.category for finding in result.findings)
    by_severity = Counter(finding.severity for finding in result.findings)
    return {
        "findings": result.replacement_count,
        "by_category": dict(sorted(by_category.items())),
        "by_severity": dict(sorted(by_severity.items())),
    }


def _location_payload(finding: Finding) -> dict[str, dict[str, int]]:
    return {
        "start": {
            "line": finding.location.start.line,
            "column": finding.location.start.column,
        },
        "end": {
            "line": finding.location.end.line,
            "column": finding.location.end.column,
        },
    }


def format_text_report(result: SanitizeResult, input_name: str) -> str:
    """Return a human-readable report of all findings."""
    lines: list[str] = [
        "ShareClean Report",
        f"Source: {safe_source(input_name)}",
        f"Findings: {result.replacement_count}",
        "",
    ]
    if result.findings:
        lines.append("By category:")
        for category, count in _summary(result)["by_category"].items():
            lines.append(f"  {category}: {count}")
        lines.append("")
        lines.append("Findings:")

    for finding in result.findings:
        start = finding.location.start
        end = finding.location.end
        lines.append(
            f"  {finding.rule_id} {finding.category} {finding.severity} "
            f"line {start.line}, column {start.column} "
            f"to line {end.line}, column {end.column} -> {finding.replacement}"
        )
    if result.findings:
        lines.append("")
    lines.append(_DISCLAIMER)
    return "\n".join(lines)


def format_json_report(result: SanitizeResult, input_name: str) -> str:
    """Return a JSON-encoded report using schema version 1.0."""
    payload = {
        "schema_version": SCHEMA_VERSION,
        "source": safe_source(input_name),
        "summary": _summary(result),
        "findings": [
            {
                "rule_id": finding.rule_id,
                "category": finding.category,
                "severity": finding.severity,
                "location": _location_payload(finding),
                "replacement": finding.replacement,
            }
            for finding in result.findings
        ],
    }
    return json.dumps(payload, indent=2)


def format_brief_count(result: SanitizeResult) -> str:
    """Return a one-line summary of how many replacements were made."""
    return f"{result.replacement_count} replacement(s) made."
