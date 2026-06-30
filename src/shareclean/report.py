"""Report formatting for ShareClean.

Formats a SanitizeResult for human-readable or machine-readable output.
Neither function ever includes the original matched value.
"""

from __future__ import annotations

import json

from shareclean.models import SanitizeResult

_DISCLAIMER = (
    "NOTE: This report lists only what was redacted and where. "
    "The original sensitive values are never stored or displayed."
)


def format_text_report(result: SanitizeResult, input_name: str) -> str:
    """Return a human-readable report of all findings.

    Args:
        result:     The SanitizeResult from sanitize().
        input_name: The name of the input (file path or "stdin").

    Returns:
        A multi-line string suitable for printing to stderr.
    """
    lines: list[str] = [
        "ShareClean Report",
        f"Input: {input_name}",
        f"Replacements made: {result.replacement_count}",
        "",
    ]
    for finding in result.findings:
        lines.append(
            f"  Line {finding.line_number}: [{finding.rule_id}] "
            f"{finding.category} -> {finding.replacement}"
        )
    if result.findings:
        lines.append("")
    lines.append(_DISCLAIMER)
    return "\n".join(lines)


def format_json_report(result: SanitizeResult, input_name: str) -> str:
    """Return a JSON-encoded report of all findings.

    The JSON schema matches the design document specification.

    Args:
        result:     The SanitizeResult from sanitize().
        input_name: The name of the input (file path or "stdin").

    Returns:
        A JSON string.
    """
    payload = {
        "input_name": input_name,
        "finding_count": result.replacement_count,
        "findings": [
            {
                "rule_id": f.rule_id,
                "category": f.category,
                "line_number": f.line_number,
                "replacement": f.replacement,
            }
            for f in result.findings
        ],
    }
    return json.dumps(payload, indent=2)


def format_brief_count(result: SanitizeResult) -> str:
    """Return a one-line summary of how many replacements were made.

    Args:
        result: The SanitizeResult from sanitize().

    Returns:
        A string such as ``"4 replacement(s) made."``.
    """
    return f"{result.replacement_count} replacement(s) made."
