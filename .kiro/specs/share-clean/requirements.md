# Requirements Document

## Introduction

ShareClean is a local-first Python CLI tool that sanitizes logs, terminal output, stack traces, configuration snippets, and plain text before users share them publicly (e.g., on GitHub, AI chat, Discord, or support tickets). It detects common sensitive patterns — secrets, tokens, emails, and local paths — replaces only the sensitive parts while preserving useful debugging context, and reports exactly what it changed. All processing is local; no data is uploaded anywhere.

## Glossary

- **ShareClean**: The CLI application being specified.
- **CLI**: Command-line interface; the user-facing entry point via `python -m shareclean`.
- **Detector**: A pattern-matching rule that identifies potentially sensitive content in input text.
- **Redactor**: The component that applies detectors to input text and produces sanitized output.
- **Finding**: A single detected instance of sensitive content, described by its rule, category, line number, and replacement label — never the raw secret value.
- **SanitizeResult**: The output of a redaction pass: the cleaned text and the list of Findings.
- **Rule**: A named detector with a pattern, a category label, and a replacement string or function.
- **Report**: A human-readable or JSON-formatted summary of all Findings produced during a run.
- **Check mode**: A run mode in which ShareClean exits with code 1 if any findings are detected, without printing sanitized output.
- **stdin**: Standard input stream; allows piped input to ShareClean.
- **stdout**: Standard output stream; the default destination for sanitized text.
- **stderr**: Standard error stream; the default destination for reports and status messages.
- **Key-value secret**: A sensitive value appearing after a recognized key name such as `password=`, `api_key:`, or `token=`.
- **Connection string**: A URI containing credentials in the form `scheme://user:password@host/db`.
- **Bearer token**: An HTTP Authorization header value of the form `Authorization: Bearer <token>`.
- **JWT-like token**: A value matching the pattern of three Base64URL segments separated by dots.
- **Private IP**: An RFC 1918 address in the `10.x.x.x`, `172.16–31.x.x`, or `192.168.x.x` ranges.

---

## Requirements

### Requirement 1: Accept Input from File or Standard Input

**User Story:** As a developer, I want to provide log content either as a file path or via a pipe, so that I can use ShareClean in both interactive and scripted workflows.

#### Acceptance Criteria

1. WHEN a file path is provided as a positional argument, THE CLI SHALL read the full text content of that file as input.
2. WHEN no file path argument is provided, THE CLI SHALL read input text from stdin.
3. IF a provided file path does not exist or cannot be read, THEN THE CLI SHALL print a descriptive error message to stderr and exit with code 2.
4. IF stdin is read and the stream is empty, THEN THE CLI SHALL treat the input as an empty string and produce no findings.
5. THE CLI SHALL preserve the original line endings of the input text in all output.

---

### Requirement 2: Detect Key-Value Secrets

**User Story:** As a developer, I want ShareClean to detect passwords, tokens, API keys, and other common key-value secrets in my text, so that I do not accidentally share credential values.

#### Acceptance Criteria

1. WHEN input text contains a key matching `password`, `passwd`, `pwd`, `token`, `access_token`, `refresh_token`, `api_key`, `apikey`, `secret`, or `client_secret` followed by `=` or `:` and a non-whitespace value, THE Detector SHALL identify the value portion as a Key-value secret Finding.
2. WHEN input text contains `authorization: bearer` followed by a non-whitespace token value (case-insensitive), THE Detector SHALL identify the token portion as a Bearer token Finding.
3. THE Detector SHALL match key names case-insensitively (e.g., `PASSWORD=`, `Api_Key:`, `TOKEN=` are all detected).
4. THE Detector SHALL match key-value pairs separated by `=` or `:` with optional surrounding whitespace.
5. THE Detector SHALL stop the value match at the first whitespace, comma, or semicolon character.

---

### Requirement 3: Detect Connection String Passwords

**User Story:** As a developer, I want ShareClean to detect passwords embedded in database and service connection strings, so that host and database name are preserved while the credential is redacted.

#### Acceptance Criteria

1. WHEN input text contains a URI beginning with `postgres://`, `postgresql://`, `mysql://`, `mongodb://`, or `redis://` and the URI contains a password component, THE Detector SHALL identify the password component as a Connection string Finding.
2. WHEN a connection string password is found, THE Redactor SHALL replace only the password segment with `[REDACTED]` while preserving the scheme, username, host, port, and database name.
3. IF a connection string contains no password component (e.g., `redis://host:6379`), THEN THE Detector SHALL produce no Finding for that URI.

---

### Requirement 4: Detect JWT-Like Tokens

**User Story:** As a developer, I want ShareClean to detect JWT-like token strings in my text, so that accidentally included session or authentication tokens are removed before sharing.

#### Acceptance Criteria

1. WHEN input text contains a value composed of exactly three segments of Base64URL characters (`[A-Za-z0-9_-]`), each at least 10 characters long, separated by dots, with no surrounding whitespace within the token, THE Detector SHALL identify it as a JWT-like token Finding.
2. WHEN a JWT-like token is found, THE Redactor SHALL replace the entire token with `[JWT REDACTED]`.
3. THE Detector SHALL NOT identify dotted version strings (e.g., `1.2.3`) or file names (e.g., `report.2024.final`) as JWT-like tokens, because each segment must meet the minimum character length of 10.

---

### Requirement 5: Detect Email Addresses

**User Story:** As a developer, I want ShareClean to detect email addresses in my text, so that personal contact information is not accidentally shared publicly.

#### Acceptance Criteria

1. WHEN input text contains a string matching the pattern `local-part@domain.tld` where the local part contains alphanumeric characters, dots, underscores, percent signs, plus signs, or hyphens, and the domain contains at least one dot and a TLD of at least two characters, THE Detector SHALL identify it as an Email address Finding.
2. WHEN an email address is found, THE Redactor SHALL replace the entire address with `[EMAIL REDACTED]`.
3. WHERE the `--no-email` flag is provided, THE CLI SHALL disable email detection for that run and produce no Email address Findings.

---

### Requirement 6: Detect Local User Paths

**User Story:** As a developer, I want ShareClean to detect local filesystem paths that contain my operating system username, so that my identity is not revealed when sharing paths from Windows, Linux, or macOS.

#### Acceptance Criteria

1. WHEN input text contains a Windows path matching `[A-Z]:\Users\<username>\...` (case-insensitive), THE Detector SHALL identify the username segment as a Local path Finding.
2. WHEN input text contains a Unix path matching `/home/<username>/...` or `/Users/<username>/...`, THE Detector SHALL identify the username segment as a Local path Finding.
3. WHEN a Local path Finding is detected, THE Redactor SHALL replace only the username segment with `[USER]`, preserving the drive letter, path prefix, and remaining path components.

---

### Requirement 7: Optionally Detect Private IP Addresses

**User Story:** As a developer, I want the option to redact RFC 1918 private IP addresses from my text, so that internal network topology is not exposed when I choose to share configuration or logs.

#### Acceptance Criteria

1. WHERE the `--redact-private-ip` flag is provided, THE Detector SHALL identify IPv4 addresses in the `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16` ranges as Private IP Findings.
2. WHERE the `--redact-private-ip` flag is provided and a Private IP is found, THE Redactor SHALL replace the address with `[PRIVATE-IP]`.
3. WHEN the `--redact-private-ip` flag is not provided, THE Detector SHALL NOT produce any Private IP Findings.

---

### Requirement 8: Apply Redactions and Preserve Debugging Context

**User Story:** As a developer, I want ShareClean to replace only the sensitive value while keeping surrounding text intact, so that I retain the debugging context I need after sanitizing.

#### Acceptance Criteria

1. THE Redactor SHALL apply detection rules in the following order: connection string passwords, authorization headers, key-value secrets, JWT-like tokens, email addresses, local user paths, private IP addresses (if enabled).
2. THE Redactor SHALL replace only the sensitive portion of a match (e.g., the value after `api_key=`, the password in a URI), not the entire line.
3. THE Redactor SHALL preserve all non-sensitive text on each line, including key names, formatting characters, and surrounding content.
4. THE Redactor SHALL preserve blank lines, indentation, and original line ending characters in the output.
5. WHEN a Finding is recorded, THE Redactor SHALL store the rule ID, category, line number, and replacement label — and SHALL NOT store the original matched value.

---

### Requirement 9: Print Sanitized Text to stdout

**User Story:** As a developer, I want the sanitized text written to stdout by default, so that I can easily copy it, redirect it, or pipe it to other tools.

#### Acceptance Criteria

1. WHEN sanitization completes normally with no `--check` flag, THE CLI SHALL write the full sanitized text to stdout.
2. WHEN the `--output` flag is provided with a file path, THE CLI SHALL write the sanitized text to that file instead of stdout.
3. IF the `--output` target path cannot be written, THEN THE CLI SHALL print a descriptive error message to stderr and exit with code 2.
4. THE CLI SHALL NOT modify the original input file under any circumstance.
5. WHEN the `--output` flag is used, THE CLI SHALL print a confirmation message to stderr indicating the output file path.

---

### Requirement 10: Display a Redaction Report

**User Story:** As a developer, I want to see a report of what was changed during sanitization, so that I can verify the output and understand what ShareClean detected.

#### Acceptance Criteria

1. WHEN the `--report` flag is provided, THE CLI SHALL print a redaction report to stderr after processing.
2. THE Report SHALL include the input name (file path or `stdin`), the total number of findings, and one entry per Finding showing the category label and line number.
3. THE Report SHALL end with a disclaimer stating that ShareClean cannot guarantee all sensitive data was detected.
4. THE Report SHALL NOT include the original matched value or any portion of the raw secret.
5. WHEN `--report-format json` is provided alongside `--report`, THE CLI SHALL emit the report as a JSON object to stderr, including `input_name`, `finding_count`, and a `findings` array with each Finding's `rule_id`, `category`, `line_number`, and `replacement` label.
6. WHEN no `--report` flag is provided, THE CLI SHALL print only the count of replacements to stderr (e.g., `4 replacement(s) made.`).

---

### Requirement 11: Support Check Mode

**User Story:** As a developer, I want a `--check` mode that exits with a non-zero code when findings are detected, so that I can use ShareClean in CI pipelines or Git hooks to prevent accidental exposure.

#### Acceptance Criteria

1. WHEN the `--check` flag is provided and findings are detected, THE CLI SHALL exit with code 1.
2. WHEN the `--check` flag is provided and no findings are detected, THE CLI SHALL exit with code 0.
3. WHEN the `--check` flag is provided, THE CLI SHALL NOT print sanitized text to stdout.
4. WHEN the `--check` flag is provided, THE CLI SHALL print a concise summary of findings to stderr.

---

### Requirement 12: Exit Codes

**User Story:** As a developer, I want ShareClean to return well-defined exit codes, so that scripts and CI pipelines can reliably detect success, findings, user errors, and internal errors.

#### Acceptance Criteria

1. WHEN processing completes with no findings or sanitization is applied normally, THE CLI SHALL exit with code 0.
2. WHEN `--check` mode is active and at least one Finding is detected, THE CLI SHALL exit with code 1.
3. WHEN a user or file error occurs — such as a missing input file, unreadable file, or invalid argument — THE CLI SHALL exit with code 2.
4. WHEN an unexpected internal error occurs that is not caused by user input, THE CLI SHALL exit with code 3 and print a descriptive error message to stderr.

---

### Requirement 13: Standard Library Only

**User Story:** As a developer, I want ShareClean to depend only on Python's standard library, so that I can install and run it without managing additional dependencies.

#### Acceptance Criteria

1. THE ShareClean package SHALL use only modules available in Python's standard library for all runtime functionality.
2. THE ShareClean package SHALL require Python 3.10 or later.
3. THE ShareClean package SHALL be runnable via `python -m shareclean` without any `pip install` of third-party packages.

---

### Requirement 14: Privacy and Safety Guarantees

**User Story:** As a developer, I want ShareClean to process my data locally and never transmit it, so that I can trust the tool itself does not create the exposure risk it is meant to prevent.

#### Acceptance Criteria

1. THE ShareClean application SHALL process all input text locally without making any network requests.
2. THE ShareClean application SHALL NOT collect, log, or transmit usage data, file contents, or detected values to any external service.
3. THE ShareClean application SHALL NOT print or log raw secret values at any verbosity level or in any report format.
4. THE ShareClean application SHALL display a disclaimer in the report and documentation stating that pattern-based detection may miss some sensitive values and may produce false positives.

---

### Requirement 15: Test Coverage with Fake Data

**User Story:** As a developer, I want the ShareClean test suite to cover all detectors and CLI behaviors using only fake data, so that the repository never contains real credentials or personal information.

#### Acceptance Criteria

1. THE Test_Suite SHALL include tests for each detector: key-value secrets, bearer tokens, connection string passwords, JWT-like tokens, email addresses, Windows user paths, and Unix user paths.
2. THE Test_Suite SHALL include a test verifying that input containing no sensitive patterns produces output identical to the input.
3. THE Test_Suite SHALL include tests for multiline input where only sensitive lines are modified.
4. THE Test_Suite SHALL include a test verifying that `--check` mode exits with code 1 when a finding is present and code 0 when no findings are present.
5. THE Test_Suite SHALL include a test verifying that `--output` writes sanitized content to a new file and leaves the original file unmodified.
6. THE Test_Suite SHALL use only synthetic, clearly fake values in all test inputs (e.g., `password=fake-secret-value`, `user@example.com`).
7. THE Test_Suite SHALL be executable with `python -m unittest discover -s tests -v` using no third-party packages.
