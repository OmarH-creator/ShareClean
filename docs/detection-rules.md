# Detection Rules

ShareClean uses stable detector IDs. Rule IDs are part of the public automation contract for CI policies, reports, allowlists, and future SARIF output.

Do not renumber or casually repurpose existing IDs. Add a new ID when a detector behavior becomes meaningfully different.

## Rule Table

| Rule ID | Detector | Category | Severity | Enabled by default | Replacement |
|---|---|---|---|---:|---|
| `SC001` | Key-value secret | `credential` | `high` | Yes | Generic redaction label |
| `SC002` | Bearer token | `token` | `high` | Yes | Generic redaction label |
| `SC003` | JWT-like token | `token` | `high` | Yes | `[JWT REDACTED]` |
| `SC004` | Connection-string password | `connection_string` | `critical` | Yes | Generic redaction label |
| `SC005` | Email address | `pii_email` | `medium` | Yes | `[EMAIL REDACTED]` |
| `SC006` | Local user path | `pii_path` | `medium` | Yes | `[USER]` |
| `SC007` | Private IP address | `internal_network` | `medium` | No | `[PRIVATE-IP]` |
| `SC008` | PEM private-key block | `private_key` | `critical` | Yes | `[PRIVATE-KEY REDACTED]` |

The generic redaction label defaults to `[REDACTED]` and can be changed with `--redaction-label TEXT` or config.

## Location Conventions

Findings report the exact redacted span where possible:

- Locations are 1-based.
- End positions are exclusive.
- Columns count Unicode code points.
- CRLF counts as one LF newline for location purposes.

## Overlap Handling

Detectors run against the original input. When detector spans overlap, ShareClean emits one finding:

1. Highest severity wins.
2. If severities match, the most specific detector wins.
3. Duplicate findings for the same character range are not emitted.

For example, a Bearer token that also looks like a JWT is reported as `SC002` because the Bearer detector is more context-specific.

## False Positives And False Negatives

ShareClean is pattern-based. It may redact values that are not sensitive and may miss secrets in unusual formats. When reporting issues, use fake examples and include whether the issue is:

- A false positive: ShareClean redacted something safe.
- A false negative: ShareClean missed something sensitive.
- A context-preservation issue: ShareClean redacted too much or too little.

Detection-changing bug reports should add or update a fake regression fixture under `tests/fixtures/`.
