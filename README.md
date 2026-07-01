# ShareClean

[![CI](https://github.com/OmarH-creator/ShareClean/actions/workflows/ci.yml/badge.svg)](https://github.com/OmarH-creator/ShareClean/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
[![Release](https://img.shields.io/github/v/release/OmarH-creator/ShareClean)](https://github.com/OmarH-creator/ShareClean/releases)
[![Live demo](https://img.shields.io/badge/live-demo-4fd1c5)](https://omarh-creator.github.io/ShareClean/)

Local-first Python CLI for sanitizing logs, stack traces, config snippets, and terminal output before you paste them into GitHub issues, support tickets, Slack, or AI chats.

ShareClean detects common sensitive values, replaces only the risky portion, and reports what changed without storing or printing the original secret. It has no runtime dependencies, makes no network calls, and sends no telemetry.

[Try the interactive browser playground](https://omarh-creator.github.io/ShareClean/) to see the redaction rules before installing.

![ShareClean terminal demo](docs/assets/shareclean-demo.svg)

## 10-Second Demo

```bash
cat app.log | shareclean --report
```

Input:

```text
user=user@example.com
password=fake-secret-value
postgresql://app:fake-pass@db.example.com/app
```

Output:

```text
user=[EMAIL REDACTED]
password=[REDACTED]
postgresql://app:[REDACTED]@db.example.com/app
```

Report:

```text
3 replacement(s) made.
```

## Why ShareClean?

Debugging often means pasting logs into GitHub issues, support tickets, AI chats, and Slack threads. Those logs can accidentally contain passwords, API keys, connection strings, local usernames, email addresses, or tokens.

ShareClean is the quick local safety pass you run before posting.

## When To Use It

- Before sharing logs, traceback output, terminal transcripts, `.env` snippets, or config fragments.
- In a pre-share script, Git hook, or CI check where sanitized text should stay local.
- When you want context-preserving redaction instead of deleting whole lines.

## How It Is Different

ShareClean is not a repository secret scanner. Tools like dedicated repo scanners are better for finding committed credentials across source history.

ShareClean is for the smaller everyday moment: "I am about to paste this text somewhere public. Can I make it safer first?"

## Features

- Redacts key-value secrets such as `password=`, `api_key:`, `token=`, and `client_secret=`
- Redacts connection string passwords while preserving scheme, user, host, port, and database
- Redacts Bearer tokens and JWT-like values
- Redacts email addresses by default, with `--no-email` available when email context matters
- Redacts local usernames from Windows, Linux, and macOS-style paths
- Optionally redacts RFC 1918 private IP addresses with `--redact-private-ip`
- Emits human-readable or JSON reports
- Supports `--check` mode for CI, hooks, and pre-share workflows
- Uses only the Python standard library at runtime

## Install

With `pipx`:

```bash
pipx install git+https://github.com/OmarH-creator/ShareClean.git@v0.1.0
```

From a local checkout:

```bash
python -m pip install -e .
```

Directly from GitHub:

```bash
python -m pip install git+https://github.com/OmarH-creator/ShareClean.git@v0.1.0
```

You can also run it without installing from the repository root:

```bash
python -m shareclean --help
```

## Quick Start

Sanitize a file and print the cleaned text:

```bash
shareclean app.log
```

Pipe from stdin:

```bash
cat app.log | shareclean
```

On Windows PowerShell:

```powershell
Get-Content .\app.log -Raw | shareclean
```

Write sanitized output to a new file:

```bash
shareclean app.log --output app.cleaned.log
```

Print a full report to stderr:

```bash
shareclean app.log --report
```

Emit a machine-readable report:

```bash
shareclean app.log --report --report-format json
```

Use check mode for CI or hooks:

```bash
shareclean app.log --check
```

`--check` exits with code `1` when findings are detected and never writes sanitized text to stdout.

## What It Detects

| Pattern | Example input | Output |
|---|---|---|
| Key-value secret | `password=letmein` | `password=[REDACTED]` |
| API key | `api_key: abc123` | `api_key: [REDACTED]` |
| Connection string | `postgresql://user:pass@host/db` | `postgresql://user:[REDACTED]@host/db` |
| Bearer token | `Authorization: Bearer eyJ...` | `Authorization: Bearer [REDACTED]` |
| JWT-like token | `xxx.yyy.zzz` | `[JWT REDACTED]` |
| Email address | `user@example.com` | `[EMAIL REDACTED]` |
| Windows user path | `C:\Users\Alice\work` | `C:\Users\[USER]\work` |
| Unix user path | `/home/alice/project` | `/home/[USER]/project` |
| Private IP address | `192.168.1.20` | `[PRIVATE-IP]` when enabled |

See [docs/detection-rules.md](docs/detection-rules.md) for more detail.

## CLI Reference

```text
usage: shareclean [-h] [--check] [--output FILE] [--report]
                  [--report-format {text,json}] [--no-email]
                  [--redact-private-ip]
                  [FILE]
```

Exit codes:

| Code | Meaning |
|---:|---|
| `0` | Completed successfully |
| `1` | Findings detected in `--check` mode |
| `2` | User or I/O error |
| `3` | Unexpected internal error |

## Safety Model

ShareClean is intentionally local and transparent:

- No network calls
- No cloud processing
- No telemetry
- No account or API key required
- Original matched secret values are not stored in findings or reports
- Input files are never modified in place

ShareClean is pattern-based. It can miss unusual formats and can redact benign text that resembles a secret. Always inspect sanitized output before sharing it publicly.

## Development

Run the test suite:

```bash
python -m unittest discover -s tests -v
```

Run basic packaging and import checks:

```bash
python -m compileall -q src tests
python -m pip wheel . --no-deps --wheel-dir dist-check
```

The project uses only the Python standard library at runtime and for tests.

## Contributing

Bug reports, detector improvements, and documentation fixes are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md).

For security-sensitive issues, please read [SECURITY.md](SECURITY.md) before opening a public issue.

See [ROADMAP.md](ROADMAP.md) for planned next steps.

## License

ShareClean is released under the [MIT License](LICENSE).
