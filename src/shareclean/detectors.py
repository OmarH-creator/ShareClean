"""Detector rules for ShareClean.

Defines the Rule dataclass and all compiled regex patterns used to detect
and redact sensitive content from text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Rule:
    """A single detection rule: a compiled regex pattern plus replacement.

    The replacement can be a literal string (for whole-match redactions)
    or a callable(re.Match) -> str (for context-preserving redactions).
    """

    rule_id: str
    category: str
    pattern: re.Pattern[str]
    replacement: str | Callable[[re.Match[str]], str]


# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

_CONNECTION_STRING_PATTERN = re.compile(
    r"(?P<scheme>postgres(?:ql)?|mysql|mongodb|redis)://"
    r"(?P<userinfo>[^:@/]*):"
    r"(?P<password>[^@]+)"
    r"@(?P<hostdb>.+)"
)

_BEARER_TOKEN_PATTERN = re.compile(
    r"(?P<prefix>authorization\s*:\s*bearer\s+)(?P<value>\S+)",
    re.IGNORECASE,
)

_KEY_VALUE_SECRET_PATTERN = re.compile(
    r"(?im)(?P<key>\b(?:password|passwd|pwd|api[_-]?key|apikey|token|"
    r"access[_-]?token|refresh[_-]?token|secret|client[_-]?secret)\s*[:=]\s*)"
    r"(?P<value>[^\s,;]+)"
)

_JWT_LIKE_PATTERN = re.compile(
    r"\b(?:[A-Za-z0-9_-]{10,}\.){2}[A-Za-z0-9_-]{10,}\b"
)

_EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

_WINDOWS_USER_PATH_PATTERN = re.compile(
    r"(?i)(?P<prefix>[A-Za-z]:\\Users\\)(?P<user>[^\\\s]+)"
)

_UNIX_USER_PATH_PATTERN = re.compile(
    r"(?P<prefix>/(?:home|Users)/)(?P<user>[^/\s]+)"
)

_PRIVATE_IP_PATTERN = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})\b"
)


# ---------------------------------------------------------------------------
# Replacement callables
# ---------------------------------------------------------------------------

def _replace_connection_string(m: re.Match[str]) -> str:
    return f"{m.group('scheme')}://{m.group('userinfo')}:[REDACTED]@{m.group('hostdb')}"


def _replace_bearer_token(m: re.Match[str]) -> str:
    return f"{m.group('prefix')}[REDACTED]"


def _replace_key_value_secret(m: re.Match[str]) -> str:
    return f"{m.group('key')}[REDACTED]"


def _replace_windows_user_path(m: re.Match[str]) -> str:
    return f"{m.group('prefix')}[USER]"


def _replace_unix_user_path(m: re.Match[str]) -> str:
    return f"{m.group('prefix')}[USER]"


# ---------------------------------------------------------------------------
# Rule instances
# ---------------------------------------------------------------------------

_CONNECTION_STRING = Rule(
    rule_id="CONNECTION_STRING",
    category="Connection string password",
    pattern=_CONNECTION_STRING_PATTERN,
    replacement=_replace_connection_string,
)

_BEARER_TOKEN = Rule(
    rule_id="BEARER_TOKEN",
    category="Bearer token",
    pattern=_BEARER_TOKEN_PATTERN,
    replacement=_replace_bearer_token,
)

_KEY_VALUE_SECRET = Rule(
    rule_id="KEY_VALUE_SECRET",
    category="Key-value secret",
    pattern=_KEY_VALUE_SECRET_PATTERN,
    replacement=_replace_key_value_secret,
)

_JWT_LIKE = Rule(
    rule_id="JWT_LIKE",
    category="JWT-like token",
    pattern=_JWT_LIKE_PATTERN,
    replacement="[JWT REDACTED]",
)

_EMAIL = Rule(
    rule_id="EMAIL",
    category="Email address",
    pattern=_EMAIL_PATTERN,
    replacement="[EMAIL REDACTED]",
)

_WINDOWS_USER_PATH = Rule(
    rule_id="WINDOWS_USER_PATH",
    category="Windows user path",
    pattern=_WINDOWS_USER_PATH_PATTERN,
    replacement=_replace_windows_user_path,
)

_UNIX_USER_PATH = Rule(
    rule_id="UNIX_USER_PATH",
    category="Unix user path",
    pattern=_UNIX_USER_PATH_PATTERN,
    replacement=_replace_unix_user_path,
)

_PRIVATE_IP = Rule(
    rule_id="PRIVATE_IP",
    category="Private IP address",
    pattern=_PRIVATE_IP_PATTERN,
    replacement="[PRIVATE-IP]",
)


# ---------------------------------------------------------------------------
# Public factory
# ---------------------------------------------------------------------------

def get_rules(
    *,
    redact_email: bool = True,
    redact_private_ip: bool = False,
) -> list[Rule]:
    """Return the ordered list of active rules based on the supplied flags.

    Rule order (as required by design):
      1. CONNECTION_STRING
      2. BEARER_TOKEN
      3. KEY_VALUE_SECRET
      4. JWT_LIKE
      5. EMAIL          (only when redact_email=True)
      6. WINDOWS_USER_PATH
      7. UNIX_USER_PATH
      8. PRIVATE_IP     (only when redact_private_ip=True)
    """
    rules: list[Rule] = [
        _CONNECTION_STRING,
        _BEARER_TOKEN,
        _KEY_VALUE_SECRET,
        _JWT_LIKE,
    ]

    if redact_email:
        rules.append(_EMAIL)

    rules.extend([_WINDOWS_USER_PATH, _UNIX_USER_PATH])

    if redact_private_ip:
        rules.append(_PRIVATE_IP)

    return rules
