# Detection Rules

ShareClean uses ordered regular-expression rules. Rules run line by line, and each rule sees the output of the rules that ran before it.

The goal is practical redaction of common accidental leaks while preserving enough surrounding context for debugging.

## Default Rules

| Rule ID | Enabled by default | Replacement | Notes |
|---|---:|---|---|
| `CONNECTION_STRING` | Yes | Password segment becomes `[REDACTED]` | Preserves scheme, username, host, port, path, and database name. |
| `BEARER_TOKEN` | Yes | Token becomes `[REDACTED]` | Matches `Authorization: Bearer ...`. |
| `KEY_VALUE_SECRET` | Yes | Value becomes `[REDACTED]` | Matches common keys such as `password`, `api_key`, `token`, and `client_secret`. |
| `JWT_LIKE` | Yes | Full token becomes `[JWT REDACTED]` | Matches three long base64url-like segments. |
| `EMAIL` | Yes | Full address becomes `[EMAIL REDACTED]` | Disable with `--no-email`. |
| `WINDOWS_USER_PATH` | Yes | Username becomes `[USER]` | Matches paths such as `C:\Users\Alice\project`. |
| `UNIX_USER_PATH` | Yes | Username becomes `[USER]` | Matches paths such as `/home/alice/project` and `/Users/alice/project`. |
| `PRIVATE_IP` | No | Address becomes `[PRIVATE-IP]` | Enable with `--redact-private-ip`. |

## Ordering

Rules are intentionally ordered from more specific to broader patterns:

1. Connection string passwords
2. Bearer tokens
3. Key-value secrets
4. JWT-like tokens
5. Email addresses
6. Windows user paths
7. Unix user paths
8. Private IP addresses, when enabled

This prevents broad rules from consuming text that a more context-preserving rule can redact more accurately.

## False Positives And False Negatives

ShareClean is pattern-based. It may redact values that are not sensitive and may miss secrets in unusual formats. When reporting issues, use fake examples and include whether the issue is:

- A false positive: ShareClean redacted something safe.
- A false negative: ShareClean missed something sensitive.
- A context-preservation issue: ShareClean redacted too much or too little of a matched value.
