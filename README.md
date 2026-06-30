# ShareClean

> Local-first Python CLI that sanitizes logs, stack traces, and text before you share them publicly.

ShareClean scans your text for common secrets and personal identifiers — passwords, API keys, emails, local paths, tokens — replaces only the sensitive parts, and reports exactly what it changed. Everything runs locally. Nothing is uploaded.

## Why

When debugging, it's easy to accidentally paste a `.env` value, a connection string with a password, or a file path containing your username into a GitHub issue, AI chat, or support ticket. ShareClean is the quick safety check you run before hitting send.

## Features

- Redacts key-value secrets (`password=`, `api_key:`, `token=`, etc.)
- Redacts connection string passwords (`postgresql://user:pass@host/db`)
- Redacts Bearer tokens and JWT-like strings
- Redacts email addresses
- Redacts local usernames from file paths (Windows & Unix)
- Optionally redacts private IP addresses
- Human-readable or JSON report of every change
- `--check` mode for CI pipelines and Git hooks
- Standard library only — no dependencies to install

## Usage

```bash
# Scan a file, print sanitized output
python -m shareclean app.log

# Pipe from stdin
type app.log | python -m shareclean

# Save sanitized output to a new file
python -m shareclean app.log --output app.cleaned.log

# Show a report of what was changed
python -m shareclean app.log --report

# Check mode — exit code 1 if findings detected
python -m shareclean app.log --check
```

## What it detects

| Pattern | Example input | Output |
|---|---|---|
| Key-value secret | `password=letmein` | `password=[REDACTED]` |
| API key | `api_key: abc123` | `api_key: [REDACTED]` |
| Connection string | `postgresql://user:pass@host/db` | `postgresql://user:[REDACTED]@host/db` |
| Bearer token | `Authorization: Bearer eyJ...` | `Authorization: Bearer [REDACTED]` |
| JWT-like token | `xxx.yyy.zzz` | `[JWT REDACTED]` |
| Email address | `user@example.com` | `[EMAIL REDACTED]` |
| Windows path | `C:\Users\Alice\work` | `C:\Users\[USER]\work` |
| Unix path | `/home/alice/project` | `/home/[USER]/project` |

## Limitations

ShareClean uses pattern-based detection. It may miss secrets in unusual formats and may redact text that is not sensitive. It does not upload your input, validate credentials against external services, or guarantee that output is safe to share. Always inspect the sanitized output before posting it publicly.

## Development

```bash
# Run tests
python -m unittest discover -s tests -v
```

Requires Python 3.10+. No third-party packages needed.

## Security

See [SECURITY.md](SECURITY.md) for the security policy and reporting instructions.

## License

MIT
