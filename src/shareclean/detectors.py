"""Detector rules for ShareClean.

Rules expose stable detector IDs, categories, severities, and replacement
labels. They never hold or return original matched values.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

DEFAULT_REDACTION_LABEL = "[REDACTED]"

Severity = str
SpanGetter = Callable[[re.Match[str]], tuple[int, int]]

VALID_CATEGORIES = frozenset({
    "credential",
    "token",
    "connection_string",
    "pii_email",
    "pii_path",
    "internal_network",
    "private_key",
})

VALID_SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {severity: index for index, severity in enumerate(VALID_SEVERITIES)}


@dataclass(frozen=True)
class Rule:
    """A single detection rule.

    ``pattern`` may match surrounding context, while ``redact_span`` identifies
    the exact character range to replace in the original input.
    """

    rule_id: str
    name: str
    category: str
    severity: Severity
    pattern: re.Pattern[str]
    replacement: str
    specificity: int
    redact_span: SpanGetter = lambda m: m.span()


def _group_span(name: str) -> SpanGetter:
    return lambda match: match.span(name)


# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

_PEM_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?"
    r"-----END [A-Z0-9 ]*PRIVATE KEY-----"
)

_CONNECTION_STRING_PATTERN = re.compile(
    r"(?P<scheme>postgres(?:ql)?|mysql|mongodb|redis)://"
    r"(?P<userinfo>[^:@/\s]*):"
    r"(?P<password>[^@\s]+)"
    r"@(?P<hostdb>[^\s,;]+)",
    re.IGNORECASE,
)

_BEARER_TOKEN_PATTERN = re.compile(
    r"authorization\s*:\s*bearer\s+(?P<value>\S+)",
    re.IGNORECASE,
)

_KEY_VALUE_SECRET_PATTERN = re.compile(
    r"(?im)\b(?:password|passwd|pwd|api[_-]?key|apikey|token|"
    r"access[_-]?token|refresh[_-]?token|secret|client[_-]?secret)"
    r"\s*[:=]\s*(?P<value>[^\s,;]+)"
)

_JWT_LIKE_PATTERN = re.compile(
    r"\b(?:[A-Za-z0-9_-]{10,}\.){2}[A-Za-z0-9_-]{10,}\b"
)

_EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

_WINDOWS_USER_PATH_PATTERN = re.compile(
    r"(?i)[A-Za-z]:\\Users\\(?P<user>[^\\\s]+)"
)

_UNIX_USER_PATH_PATTERN = re.compile(
    r"/(?:home|Users)/(?P<user>[^/\s]+)"
)

_PRIVATE_IP_PATTERN = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})\b"
)


def _private_key_rule() -> Rule:
    return Rule(
        rule_id="SC008",
        name="PEM private-key block",
        category="private_key",
        severity="critical",
        pattern=_PEM_PRIVATE_KEY_PATTERN,
        replacement="[PRIVATE-KEY REDACTED]",
        specificity=100,
    )


def _connection_string_rule(redaction_label: str) -> Rule:
    return Rule(
        rule_id="SC004",
        name="Connection-string password",
        category="connection_string",
        severity="critical",
        pattern=_CONNECTION_STRING_PATTERN,
        replacement=redaction_label,
        specificity=90,
        redact_span=_group_span("password"),
    )


def _bearer_token_rule(redaction_label: str) -> Rule:
    return Rule(
        rule_id="SC002",
        name="Bearer token",
        category="token",
        severity="high",
        pattern=_BEARER_TOKEN_PATTERN,
        replacement=redaction_label,
        specificity=80,
        redact_span=_group_span("value"),
    )


def _jwt_like_rule() -> Rule:
    return Rule(
        rule_id="SC003",
        name="JWT-like token",
        category="token",
        severity="high",
        pattern=_JWT_LIKE_PATTERN,
        replacement="[JWT REDACTED]",
        specificity=70,
    )


def _key_value_secret_rule(redaction_label: str) -> Rule:
    return Rule(
        rule_id="SC001",
        name="Key-value secret",
        category="credential",
        severity="high",
        pattern=_KEY_VALUE_SECRET_PATTERN,
        replacement=redaction_label,
        specificity=60,
        redact_span=_group_span("value"),
    )


_EMAIL = Rule(
    rule_id="SC005",
    name="Email address",
    category="pii_email",
    severity="medium",
    pattern=_EMAIL_PATTERN,
    replacement="[EMAIL REDACTED]",
    specificity=50,
)

_WINDOWS_USER_PATH = Rule(
    rule_id="SC006",
    name="Windows local user path",
    category="pii_path",
    severity="medium",
    pattern=_WINDOWS_USER_PATH_PATTERN,
    replacement="[USER]",
    specificity=40,
    redact_span=_group_span("user"),
)

_UNIX_USER_PATH = Rule(
    rule_id="SC006",
    name="Unix local user path",
    category="pii_path",
    severity="medium",
    pattern=_UNIX_USER_PATH_PATTERN,
    replacement="[USER]",
    specificity=40,
    redact_span=_group_span("user"),
)

_PRIVATE_IP = Rule(
    rule_id="SC007",
    name="Private IP address",
    category="internal_network",
    severity="medium",
    pattern=_PRIVATE_IP_PATTERN,
    replacement="[PRIVATE-IP]",
    specificity=30,
)


def get_rules(
    *,
    redact_email: bool = True,
    redact_private_ip: bool = False,
    redaction_label: str = DEFAULT_REDACTION_LABEL,
) -> list[Rule]:
    """Return the ordered list of active detector rules."""
    rules: list[Rule] = [
        _private_key_rule(),
        _connection_string_rule(redaction_label),
        _bearer_token_rule(redaction_label),
        _jwt_like_rule(),
        _key_value_secret_rule(redaction_label),
    ]

    if redact_email:
        rules.append(_EMAIL)

    rules.extend([_WINDOWS_USER_PATH, _UNIX_USER_PATH])

    if redact_private_ip:
        rules.append(_PRIVATE_IP)

    return rules
