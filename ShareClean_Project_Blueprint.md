# ShareClean
## Full Project Blueprint — Local-First Log and Text Sanitizer for Safe Sharing

> **Project status:** planned MVP  
> **Language:** Python 3.10+  
> **Type:** command-line interface (CLI)  
> **Core promise:** ShareClean processes text locally and helps users remove common secrets and personal information **before** they paste logs into GitHub issues, AI chats, Discord, email, tickets, or public forums.

---

## 1. One-sentence pitch

**ShareClean is a local Python command-line tool that scans logs, terminal output, stack traces, configuration snippets, and plain text; redacts likely secrets and personal identifiers; then explains exactly what it changed.**

---

## 2. Why this project matters

When people debug a problem, they commonly copy terminal output, `.env` values, traceback text, URLs, configuration snippets, and database errors into public places. Those snippets can accidentally contain passwords, tokens, API keys, session identifiers, emails, connection strings, internal paths, or IP addresses.

ShareClean is intended to be a **pre-share safety layer**:

```text
Raw log / copied text
        ↓
   ShareClean scans locally
        ↓
Cleaned text + transparent report
        ↓
Safe(r) paste into an issue, chat, ticket, or forum
```

### Why it is not “just another secret scanner”

GitHub secret scanning is valuable, but it usually protects repositories after code is committed or pushed. ShareClean is designed for a different moment: the few seconds **before a person shares debugging text anywhere**.

The project should never claim “perfect security.” Pattern detection can miss unknown formats and can produce false positives. The honest promise is:

> “ShareClean reduces accidental exposure of common sensitive values. Always review the output before sharing.”

### Security motivation

OWASP recommends avoiding sensitive data in logs and specifically discusses the risks around credentials, personal data, and technical secrets. GitHub secret scanning and push protection also exist to help prevent credentials from reaching repositories. ShareClean complements these tools by operating locally before content is pasted or uploaded.

References:
- OWASP Logging Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html>
- OWASP Secrets Management Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html>
- GitHub Secret Scanning: <https://docs.github.com/en/code-security/concepts/secret-security/secret-scanning>
- GitHub Push Protection: <https://docs.github.com/en/code-security/concepts/secret-security/push-protection>

---

## 3. Target users

### Primary users
- Students posting error messages online.
- Developers opening GitHub issues.
- Engineers sharing logs in Slack, Discord, Teams, or email.
- People asking an AI assistant for debugging help.
- Anyone who wants a fast local sanitization check.

### Example scenario

A developer copies this:

```text
Connection failed.
DATABASE_URL=postgresql://admin:MyPassword123@10.10.2.18:5432/production
OPENAI_API_KEY=sk-live-example-not-real
File path: C:\Users\Hassan\Documents\work\project\.env
Contact: hassan@example.com
```

ShareClean returns this:

```text
Connection failed.
DATABASE_URL=postgresql://admin:[REDACTED]@10.10.2.18:5432/production
OPENAI_API_KEY=[REDACTED]
File path: C:\Users\[USER]\Documents\work\project\.env
Contact: [EMAIL REDACTED]
```

And reports:

```text
Redaction report
----------------
[1] database password   line 2
[2] API key/value       line 3
[3] local user path     line 4
[4] email address       line 5
Total replacements: 4
```

---

## 4. Project goals

### MVP goals — version 0.1.0

1. Accept text from:
   - a file path
   - standard input (pipe)
2. Detect a small set of common sensitive patterns.
3. Replace only the sensitive part where possible.
4. Preserve line breaks and surrounding debugging context.
5. Print clean text to standard output.
6. Optionally print a human-readable redaction report.
7. Use only Python’s standard library.
8. Include proper tests with fake data only.
9. Be easy to install and run.

### Non-goals for MVP

Do **not** build these at the beginning:

- No AI model or API integration.
- No web application.
- No user accounts.
- No cloud upload.
- No browser extension.
- No “guaranteed secret detection” claim.
- No direct modification of the user’s source file unless they explicitly request output to a new file.
- No attempt to imitate enterprise DLP/security products.

---

## 5. The first usable command set

The MVP should support these commands:

```bash
# Scan a file and print sanitized content
python -m shareclean app.log

# Read text from stdin
type app.log | python -m shareclean

# Save cleaned content to another file
python -m shareclean app.log --output app.cleaned.log

# Show what was changed
python -m shareclean app.log --report

# Only check; do not print the sanitized text
python -m shareclean app.log --check

# Request JSON report for automation later
python -m shareclean app.log --report-format json
```

### Expected exit codes

| Exit code | Meaning |
|---:|---|
| `0` | No findings, or sanitization completed normally |
| `1` | Sensitive-looking content was detected in `--check` mode |
| `2` | User or file error: missing file, unreadable file, invalid argument |
| `3` | Unexpected internal error |

This makes `--check` useful later in CI or Git hooks.

---

## 6. Core user experience

### Default behavior

Command:

```bash
python -m shareclean error.log
```

Result:
- print the sanitized text to the terminal;
- print the number of replacements to `stderr`;
- do not overwrite the original file.

### Report behavior

Command:

```bash
python -m shareclean error.log --report
```

Result:
- sanitized text goes to standard output;
- report goes to standard error;
- a user can safely redirect clean output:

```bash
python -m shareclean error.log --report > error.cleaned.log
```

### Check-only behavior

Command:

```bash
python -m shareclean error.log --check
```

Result:
- no sanitized text output;
- concise findings printed;
- exit code `1` if something suspicious was found.

---

## 7. Detection scope for version 0.1.0

The initial version must focus on a few understandable patterns.

### 7.1 Key-value secrets

Detect values after common key names:

```text
password=...
passwd: ...
pwd=...
token=...
access_token=...
refresh_token=...
api_key=...
apikey=...
secret=...
client_secret=...
authorization: Bearer ...
```

Desired replacement style:

```text
password=letmein
```

becomes:

```text
password=[REDACTED]
```

Keep the key name visible because it remains useful for debugging.

### 7.2 Connection strings

Examples to detect:

```text
postgres://user:password@host:5432/db
postgresql://user:password@host/db
mysql://user:password@host/db
mongodb://user:password@host/db
redis://:password@host:6379
```

Preferred behavior:
- preserve protocol, host, port, database name;
- redact password;
- redact the user too only when it looks personal or sensitive.

Example:

```text
postgresql://admin:MyPass123@db.internal:5432/prod
```

becomes:

```text
postgresql://admin:[REDACTED]@db.internal:5432/prod
```

### 7.3 Authorization headers

Input:

```text
Authorization: Bearer eyJhbGciOi...
```

Output:

```text
Authorization: Bearer [REDACTED]
```

### 7.4 JWT-like tokens

A JWT often resembles three Base64URL-like segments separated by dots:

```text
xxxxx.yyyyy.zzzzz
```

Do not label every three-part dotted string as a token without care. The detector should use:
- three segments;
- each segment has enough characters;
- allowed characters: letters, digits, `_`, `-`;
- no spaces.

Output:

```text
[JWT REDACTED]
```

### 7.5 Email addresses

Input:

```text
dev.name+test@company.example
```

Output:

```text
[EMAIL REDACTED]
```

### 7.6 Local paths containing usernames

Windows:

```text
C:\Users\Hassan\Desktop\project
```

becomes:

```text
C:\Users\[USER]\Desktop\project
```

Linux/macOS:

```text
/home/hassan/project
/Users/hassan/project
```

becomes:

```text
/home/[USER]/project
/Users/[USER]/project
```

### 7.7 Private IP addresses — optional, not required on day one

Potentially redact:
- `10.x.x.x`
- `172.16.x.x` through `172.31.x.x`
- `192.168.x.x`

Suggested replacement:

```text
[PRIVATE-IP]
```

Be conservative. Private IPs can be useful in debugging and are not always sensitive. Make this detector optional later using:

```bash
--redact-private-ip
```

---

## 8. Detection scope deliberately excluded at first

Do not implement these in version 0.1.0:

- Credit card detection
- National IDs/passports
- Source-code AST scanning
- Binary file scanning
- OCR from screenshots
- Secret validation by sending values to cloud services
- Full entropy-based secret scanning
- Support for every provider-specific API key format
- Automatic clipboard monitoring

These are interesting future extensions, but they will distract from making the first release useful.

---

## 9. Privacy and safety rules

ShareClean should follow these rules from the start:

1. **Local by default:** it must not upload input text anywhere.
2. **No telemetry in MVP:** do not collect logs, usage, files, or detected values.
3. **Never print raw secret values in reports.**
4. **Do not overwrite input files by default.**
5. **Document limitations honestly.**
6. **Use only fake tokens in tests and screenshots.**
7. **Keep reports descriptive, not revealing.**

Good report:

```text
API key value redacted at line 18
```

Bad report:

```text
Redacted key: sk-live-abc123...
```

---

## 10. Architecture

Keep the project small and modular.

```text
shareclean/
├── README.md
├── LICENSE
├── SECURITY.md
├── pyproject.toml
├── .gitignore
├── src/
│   └── shareclean/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli.py
│       ├── models.py
│       ├── detectors.py
│       ├── redactor.py
│       ├── report.py
│       └── io_utils.py
└── tests/
    ├── __init__.py
    ├── test_detectors.py
    ├── test_redactor.py
    ├── test_cli.py
    └── fixtures/
        ├── sample_log.txt
        └── expected_cleaned_log.txt
```

### Module responsibilities

| File | Responsibility |
|---|---|
| `__main__.py` | Allows `python -m shareclean` |
| `cli.py` | Defines CLI arguments and exit codes |
| `models.py` | Defines result objects using dataclasses |
| `detectors.py` | Holds detection rules and pattern definitions |
| `redactor.py` | Applies replacements and creates findings |
| `report.py` | Formats terminal and JSON reports |
| `io_utils.py` | Reads from file/stdin and writes output safely |
| `tests/` | Verifies every intended behavior |

---

## 11. Data model

Use a Python dataclass for every redaction finding.

```python
from dataclasses import dataclass

@dataclass
class Finding:
    rule_id: str
    category: str
    line_number: int
    start_column: int
    end_column: int
    replacement: str
```

Important:
- do **not** store the secret text in `Finding`;
- store only metadata necessary for the report;
- retain enough information to debug the sanitizer without leaking the actual value.

A higher-level result object:

```python
from dataclasses import dataclass, field

@dataclass
class SanitizeResult:
    cleaned_text: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def replacement_count(self) -> int:
        return len(self.findings)
```

---

## 12. Rule design

Each rule should be represented clearly.

```python
from dataclasses import dataclass
import re

@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    pattern: re.Pattern[str]
    replacement: str
```

### Important design rule

A general replacement string is not enough for every pattern.

For example:

```text
password=hello
```

should become:

```text
password=[REDACTED]
```

You need to preserve the matched key and replace only the value.

Use a replacement function:

```python
def redact_key_value(match: re.Match[str]) -> str:
    key = match.group("key")
    return f"{key}[REDACTED]"
```

This is more readable and safer than replacing the entire line.

---

## 13. Suggested initial regular expressions

These are starting points, not final truth. Test them carefully.

### 13.1 Key-value secret rule

```python
KEY_VALUE_SECRET = re.compile(
    r"(?im)"
    r"(?P<key>\b(?:api[_-]?key|apikey|password|passwd|pwd|token|"
    r"access[_-]?token|refresh[_-]?token|secret|client[_-]?secret)"
    r"\s*[:=]\s*)"
    r"(?P<value>[^\s,;]+)"
)
```

### 13.2 Bearer token rule

```python
BEARER_TOKEN = re.compile(
    r"(?im)(?P<prefix>\bauthorization\s*:\s*bearer\s+)(?P<value>[^\s]+)"
)
```

### 13.3 Email rule

```python
EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
```

### 13.4 Windows user path rule

```python
WINDOWS_USER_PATH = re.compile(
    r"(?i)\b(?P<prefix>[A-Z]:\\Users\\)(?P<user>[^\\\s]+)"
)
```

### 13.5 Linux/macOS user path rule

```python
UNIX_USER_PATH = re.compile(
    r"(?P<prefix>/(?:home|Users)/)(?P<user>[^/\s]+)"
)
```

### 13.6 JWT-like value rule

```python
JWT_LIKE = re.compile(
    r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
)
```

### Notes on regex quality

- The patterns will create false positives sometimes. That is normal.
- Avoid patterns that match too broadly.
- Do not hide the entire line unless necessary.
- Make each rule testable independently.
- Add rule IDs such as `KEY_VALUE_SECRET`, `EMAIL`, `JWT_LIKE`.

Python’s built-in `re` module is sufficient for this project, and `argparse` is designed for standard command-line argument handling. Python’s standard library documentation is the main source of truth for these modules:
- <https://docs.python.org/3/library/re.html>
- <https://docs.python.org/3/library/argparse.html>
- <https://docs.python.org/3/library/pathlib.html>

---

## 14. Redaction algorithm

For each line:

1. Start with the original line.
2. Run the detection rules in a carefully chosen order.
3. Apply replacements.
4. Record findings without recording secret values.
5. Return the cleaned line.
6. Join cleaned lines with original newline behavior preserved.

### Suggested rule order

1. Connection-string password
2. Authorization header
3. Key-value secrets
4. JWT-like strings
5. Email addresses
6. User path names
7. Optional private IP addresses

Why:
- more specific patterns should run before broad patterns;
- otherwise a generic key-value rule might alter text before the connection-string rule sees it.

### Overlap problem

This input contains both a key and a connection string:

```text
DATABASE_URL=postgresql://admin:password@host/db
```

A good implementation should ideally produce:

```text
DATABASE_URL=postgresql://admin:[REDACTED]@host/db
```

not:

```text
DATABASE_URL=[REDACTED]
```

Both are safer, but the first preserves more useful debugging context.

For the MVP, it is acceptable to redact the entire value after `DATABASE_URL=`. Document that connection-string precision can improve in version 0.2.0.

---

## 15. Output formats

### 15.1 Terminal report

```text
ShareClean report
=================
Input: error.log
Findings: 3

1. API key/value         line 4
2. Email address         line 7
3. Windows user path     line 9

Review the output before sharing. ShareClean cannot guarantee that all sensitive data was detected.
```

### 15.2 JSON report

```json
{
  "input_name": "error.log",
  "finding_count": 2,
  "findings": [
    {
      "rule_id": "KEY_VALUE_SECRET",
      "category": "API key/value",
      "line_number": 4,
      "replacement": "[REDACTED]"
    },
    {
      "rule_id": "EMAIL",
      "category": "Email address",
      "line_number": 7,
      "replacement": "[EMAIL REDACTED]"
    }
  ]
}
```

Never include the original matched value in JSON.

---

## 16. CLI contract

### Argument table

| Argument | Meaning |
|---|---|
| `input` | Optional path to input file. Omit to read standard input. |
| `-o`, `--output` | Save cleaned text to a new file. |
| `--report` | Print human-readable findings to standard error. |
| `--report-format {text,json}` | Choose report format. Default: `text`. |
| `--check` | Do not print cleaned text; exit with `1` when findings exist. |
| `--quiet` | Suppress normal status messages. |
| `--version` | Print the current version. |
| `--no-email` | Disable email redaction for this command. |
| `--redact-private-ip` | Enable optional private IP redaction. |

### Help text target

```text
usage: shareclean [-h] [-o OUTPUT] [--report]
                  [--report-format {text,json}] [--check]
                  [--quiet] [--no-email] [--redact-private-ip]
                  [input]

Sanitize logs and text before sharing them.

positional arguments:
  input                 Input file. Omit to read from stdin.

options:
  -h, --help            Show this help message and exit.
  -o OUTPUT, --output OUTPUT
                         Write sanitized content to this file.
  --report              Print a redaction report to stderr.
  --report-format {text,json}
                         Report format when --report is enabled.
  --check               Exit with code 1 if findings are detected.
  --quiet               Suppress normal status messages.
  --no-email            Do not redact email addresses.
  --redact-private-ip   Redact RFC1918 private IP addresses.
  --version             Show version information and exit.
```

---

## 17. Build plan

## Phase 0 — Create the repository today (15 minutes)

Create the folder:

```bash
mkdir shareclean
cd shareclean
git init
```

Create these files:

```text
README.md
LICENSE
.gitignore
pyproject.toml
src/shareclean/__init__.py
src/shareclean/__main__.py
src/shareclean/cli.py
src/shareclean/models.py
src/shareclean/detectors.py
src/shareclean/redactor.py
src/shareclean/report.py
tests/test_redactor.py
tests/test_detectors.py
```

Add `.gitignore`:

```gitignore
__pycache__/
*.py[cod]
.venv/
.pytest_cache/
.coverage
dist/
build/
*.egg-info/
```

Initial commit:

```bash
git add .
git commit -m "chore: initialize ShareClean project structure"
```

## Phase 1 — Working sanitizer (1–2 hours)

Build only:
- read a file;
- run email and `password=` redaction;
- print cleaned output;
- write two tests.

Definition of done:

```bash
python -m shareclean sample.log
```

works reliably.

Commit:

```bash
git commit -am "feat: redact emails and key-value secrets"
```

## Phase 2 — CLI polish (1–2 hours)

Add:
- `--report`;
- `--output`;
- `--check`;
- exit codes;
- input from stdin.

Commit:

```bash
git commit -am "feat: add reports output files and check mode"
```

## Phase 3 — More detectors and test suite (2–4 hours)

Add:
- bearer token;
- local user paths;
- JWT-like values;
- basic connection-string treatment;
- 20+ test cases.

Commit:

```bash
git commit -am "feat: add token path and connection string redaction"
```

## Phase 4 — Public GitHub readiness (1 hour)

Add:
- screenshots/GIF terminal demo;
- README usage examples;
- license;
- security policy;
- GitHub Actions test workflow.

Commit:

```bash
git commit -am "docs: prepare first public release"
git tag v0.1.0
```

---

## 18. Beginner-friendly daily checklist

### Day 1
- [ ] Create repository.
- [ ] Install Python 3.10+.
- [ ] Make `python -m shareclean --help` work.
- [ ] Redact `password=...`.
- [ ] Commit.

### Day 2
- [ ] Add email redaction.
- [ ] Add three tests.
- [ ] Add a sample log file with fake values.
- [ ] Commit.

### Day 3
- [ ] Add `--report`.
- [ ] Add `--output`.
- [ ] Test piping from terminal.
- [ ] Commit.

### Day 4
- [ ] Add local-path redaction.
- [ ] Add JWT-like redaction.
- [ ] Improve README.
- [ ] Commit.

### Day 5
- [ ] Add `--check`.
- [ ] Add GitHub Actions.
- [ ] Publish version `v0.1.0`.

---

## 19. Test strategy

Use Python’s built-in `unittest` module initially. No third-party testing library is required.

Run tests with:

```bash
python -m unittest discover -s tests -v
```

### Minimum test cases

| Test | Input | Expected |
|---|---|---|
| Password | `password=hello123` | `password=[REDACTED]` |
| API key | `api_key: abc` | `api_key: [REDACTED]` |
| Email | `a@b.com` | `[EMAIL REDACTED]` |
| Bearer header | `Authorization: Bearer abc` | `Authorization: Bearer [REDACTED]` |
| Windows path | `C:\Users\Alice\work` | `C:\Users\[USER]\work` |
| Unix path | `/home/alice/work` | `/home/[USER]/work` |
| No finding | `Server started on port 8000` | unchanged |
| Multiline input | three lines | only sensitive line changes |
| Output file | valid input | output created, input unchanged |
| Check mode | secret present | exit code `1` |

### Edge cases to test

```text
PASSWORD = "value with spaces"
password: value,
token=abc;next=value
email is user@example.com.
C:\Users\John Doe\file.txt
/home/user-name/project
```

Test what you support and document what you do not support yet.

---

## 20. Example implementation sketch

### `src/shareclean/__main__.py`

```python
from shareclean.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
```

### `src/shareclean/models.py`

```python
from dataclasses import dataclass, field


@dataclass
class Finding:
    rule_id: str
    category: str
    line_number: int
    replacement: str


@dataclass
class SanitizeResult:
    cleaned_text: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def replacement_count(self) -> int:
        return len(self.findings)
```

### `src/shareclean/redactor.py` — simple first idea

```python
import re
from shareclean.models import Finding, SanitizeResult


KEY_VALUE_SECRET = re.compile(
    r"(?im)(?P<key>\b(?:password|passwd|pwd|api[_-]?key|apikey|token|secret)"
    r"\s*[:=]\s*)(?P<value>[^\s,;]+)"
)

EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)


def sanitize_text(text: str) -> SanitizeResult:
    findings: list[Finding] = []
    lines = text.splitlines(keepends=True)
    cleaned_lines: list[str] = []

    for line_number, line in enumerate(lines, start=1):
        def redact_key_value(match: re.Match[str]) -> str:
            findings.append(
                Finding(
                    rule_id="KEY_VALUE_SECRET",
                    category="Key-value secret",
                    line_number=line_number,
                    replacement="[REDACTED]",
                )
            )
            return f"{match.group('key')}[REDACTED]"

        cleaned_line = KEY_VALUE_SECRET.sub(redact_key_value, line)

        def redact_email(match: re.Match[str]) -> str:
            findings.append(
                Finding(
                    rule_id="EMAIL",
                    category="Email address",
                    line_number=line_number,
                    replacement="[EMAIL REDACTED]",
                )
            )
            return "[EMAIL REDACTED]"

        cleaned_line = EMAIL.sub(redact_email, cleaned_line)
        cleaned_lines.append(cleaned_line)

    return SanitizeResult(
        cleaned_text="".join(cleaned_lines),
        findings=findings,
    )
```

This is intentionally not a complete final implementation. It is an understandable, testable starting point.

---

## 21. Example test

### `tests/test_redactor.py`

```python
import unittest

from shareclean.redactor import sanitize_text


class SanitizeTextTests(unittest.TestCase):
    def test_redacts_password_value(self):
        result = sanitize_text("password=hello123")

        self.assertEqual(result.cleaned_text, "password=[REDACTED]")
        self.assertEqual(result.replacement_count, 1)

    def test_redacts_email(self):
        result = sanitize_text("Contact me: person@example.com")

        self.assertEqual(
            result.cleaned_text,
            "Contact me: [EMAIL REDACTED]",
        )
        self.assertEqual(result.replacement_count, 1)

    def test_keeps_safe_text(self):
        result = sanitize_text("Server started on port 8000")

        self.assertEqual(result.cleaned_text, "Server started on port 8000")
        self.assertEqual(result.replacement_count, 0)


if __name__ == "__main__":
    unittest.main()
```

---

## 22. `pyproject.toml` for the first version

```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "shareclean"
version = "0.1.0"
description = "Local-first sanitizer for logs and text before sharing."
readme = "README.md"
requires-python = ">=3.10"
license = { text = "MIT" }
authors = [
  { name = "Your Name" }
]
keywords = ["security", "privacy", "logs", "sanitization", "cli"]

[project.scripts]
shareclean = "shareclean.cli:main"

[tool.setuptools.packages.find]
where = ["src"]
```

After packaging is added, users can eventually install it using:

```bash
pip install .
```

and run:

```bash
shareclean error.log --report
```

---

## 23. Suggested README structure

Your public `README.md` should be shorter than this blueprint.

```markdown
# ShareClean

[One-line description]

## Why
[The accidental log-sharing problem]

## Features
- Local-first
- Redacts common values
- Reports every change
- Does not overwrite input files by default

## Install
[Commands]

## Usage
[Three examples]

## What it detects
[Clear list]

## Limitations
[Not perfect. Review output.]

## Development
[Test commands]

## Security
[Link to SECURITY.md]

## License
MIT
```

### README opening paragraph suggestion

> ShareClean is a local-first Python CLI that sanitizes logs, stack traces, configuration snippets, and copied text before you share them. It redacts common secrets and personal identifiers while preserving useful debugging context, then reports what changed.

---

## 24. `SECURITY.md` suggestion

```markdown
# Security Policy

## Scope

ShareClean is a best-effort local sanitizer. It is not a replacement for an
organization’s security tooling, data-loss prevention policy, or code review.

## Reporting a vulnerability

Do not open a public issue for a potential vulnerability that could expose
sensitive user data. Contact the maintainer privately at:

[Your contact method]

## Important limitations

- Pattern-based detection can miss unknown secret formats.
- Pattern-based detection can produce false positives.
- Users must review sanitized output before sharing.
- ShareClean does not validate tokens with external services.
```

---

## 25. GitHub issue ideas

Create these issues after the first commit:

1. `feat: redact key-value secrets`
2. `feat: redact email addresses`
3. `feat: add readable redaction report`
4. `feat: add stdin support`
5. `feat: add --check mode`
6. `test: build detector test matrix`
7. `docs: add limitations and security policy`
8. `ci: run tests on GitHub Actions`
9. `feat: support custom user rules`
10. `feat: add connection-string aware redaction`

This makes your repository look organized and makes it easier to work one task at a time.

---

## 26. GitHub Actions workflow — add after tests work

Create:

```text
.github/workflows/tests.yml
```

```yaml
name: Tests

on:
  push:
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install package
        run: pip install .

      - name: Run tests
        run: python -m unittest discover -s tests -v
```

---

## 27. Future roadmap

### Version 0.2.0 — Custom rules

Allow a local configuration file:

```json
{
  "rules": [
    {
      "name": "Internal ticket ID",
      "pattern": "ACME-[0-9]{5}",
      "replacement": "[INTERNAL-TICKET]"
    }
  ]
}
```

Command:

```bash
shareclean app.log --config .shareclean.json
```

### Version 0.3.0 — Better connection strings

Parse common connection URLs more precisely and mask:
- password;
- user;
- query-string secrets;
- cloud credentials embedded in URLs.

### Version 0.4.0 — Clipboard mode

A manual command that sanitizes current clipboard text.

Important: do **not** silently monitor clipboard history. Make the user run the command explicitly.

### Version 0.5.0 — Git hook support

Add:

```bash
shareclean --install-pre-commit
```

The hook would scan only staged text files and warn before commit.

### Version 1.0.0 — Stable release

Only declare 1.0.0 when:
- CLI behavior is stable;
- rule configuration has a documented format;
- test coverage is strong;
- the project has clear privacy documentation;
- no major known destructive behavior exists.

---

## 28. What makes this original

The idea is not “invent regex.” The originality comes from product focus:

- **Pre-share**, not only pre-commit.
- **Human-readable report**, not silent filtering.
- **Debugging-context preservation**, not simply deleting full lines.
- **Local-first privacy**, no account and no upload.
- **Beginner-friendly and open-source**, so other students can understand the implementation.

You can also make it more unique later by adding “sharing profiles”:

```bash
shareclean error.log --profile github
shareclean error.log --profile ai-chat
shareclean error.log --profile support-ticket
```

For example:
- `github`: redact secrets and local paths;
- `ai-chat`: redact secrets, emails, local paths, and private IPs;
- `support-ticket`: redact secrets but leave internal host names if the user chooses.

---

## 29. Honest limitations section

Put this in the README exactly or almost exactly:

> ShareClean uses pattern-based detection. It may miss secrets in unusual formats and may redact text that is not sensitive. It does not upload your input, validate credentials against external services, or guarantee that output is safe to share. Always inspect the sanitized output before posting it publicly.

This statement is important. It makes the project more credible, not less.

---

## 30. First release checklist

- [ ] Repository has a clear name: `shareclean`
- [ ] Description is one sentence and understandable
- [ ] `python -m shareclean --help` works
- [ ] Reads from a file
- [ ] Reads from standard input
- [ ] Redacts key-value secrets
- [ ] Redacts emails
- [ ] Redacts local paths
- [ ] `--report` works
- [ ] `--check` returns correct exit code
- [ ] Original files are never overwritten by default
- [ ] Tests pass on a clean clone
- [ ] README includes an example
- [ ] README includes limitations
- [ ] `SECURITY.md` exists
- [ ] GitHub Actions tests run
- [ ] No real secret is in the repository
- [ ] Create release tag `v0.1.0`

---

## 31. A Kiro prompt for the first task

Paste this into Kiro after creating the empty repository:

```text
I am a beginner Python developer building a local CLI project named ShareClean.

Goal:
Create the smallest working version of a tool that reads a text file and redacts:
1. values after password= or password:
2. email addresses

Requirements:
- Use Python standard library only.
- Use a src/ layout.
- Create an installable package that runs with: python -m shareclean input.txt
- Do not overwrite the input file.
- Print sanitized text to standard output.
- Add unittest tests for password and email redaction.
- Explain every file before creating it.
- Make small changes only; do not add a web app, AI, databases, third-party packages, or extra features.
```

---

## 32. Final project statement for your portfolio/CV

> Built ShareClean, a privacy-focused Python CLI that sanitizes logs and debugging text before sharing. The tool detects and redacts common secrets and personal identifiers, preserves useful technical context, generates transparent redaction reports, supports standard input and file workflows, and is covered by automated tests.

---

## 33. Immediate next action

Create the repo and implement only this first behavior:

```text
password=hello123  →  password=[REDACTED]
person@example.com →  [EMAIL REDACTED]
```

Do not add more features until this works and has tests.

That first small success is the foundation of the whole project.
