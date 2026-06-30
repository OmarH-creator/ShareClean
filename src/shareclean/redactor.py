"""Core redaction engine for ShareClean.

Applies an ordered list of Rules to input text, producing a SanitizeResult
that contains the cleaned text and a list of Findings.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from shareclean.detectors import Rule
from shareclean.models import Finding, SanitizeResult


def sanitize(text: str, rules: list[Rule]) -> SanitizeResult:
    """Apply *rules* to *text* in a single pass, line by line.

    For each line (1-indexed), each rule is applied in the order supplied.
    A Finding is recorded for every match.  The original matched value is
    never stored anywhere in the result.

    Args:
        text:  The raw input text to sanitize.
        rules: Ordered list of Rule objects to apply.

    Returns:
        A SanitizeResult containing the cleaned text and all findings.
    """
    findings: list[Finding] = []
    lines = text.splitlines(keepends=True)
    cleaned_lines: list[str] = []

    for line_number, line in enumerate(lines, start=1):
        cleaned_line = line
        for rule in rules:
            def make_callback(
                rule: Rule = rule,
                line_number: int = line_number,
            ) -> Callable[[re.Match[str]], str]:
                def callback(match: re.Match[str]) -> str:
                    # Compute replacement string exactly once - never store the
                    # original matched value.
                    if callable(rule.replacement):
                        repl_str = rule.replacement(match)
                    else:
                        repl_str = rule.replacement
                    findings.append(Finding(
                        rule_id=rule.rule_id,
                        category=rule.category,
                        line_number=line_number,
                        replacement=repl_str,
                    ))
                    return repl_str
                return callback

            cleaned_line = re.sub(rule.pattern, make_callback(), cleaned_line)
        cleaned_lines.append(cleaned_line)

    return SanitizeResult(cleaned_text="".join(cleaned_lines), findings=findings)
