# Security Policy

ShareClean is a local-first redaction tool. It is designed to reduce the chance of accidentally sharing common secrets in logs and text, but it is not a complete data loss prevention system.

## Supported Versions

| Version | Supported |
|---|---|
| `0.1.x` | Yes |

## Reporting a Vulnerability

Please do not open a public issue containing real secrets, production logs, credentials, customer data, or exploit details.

If GitHub private vulnerability reporting is enabled for this repository, use the **Report a vulnerability** button on the repository Security page. If private reporting is not available, open a minimal public issue that says you have a security report to share and include no sensitive details.

When possible, use clearly fake examples such as `password=fake-secret-value` or `user@example.com`.

## What To Include

- A short description of the issue
- Steps to reproduce with fake input data
- Expected behavior
- Actual behavior
- ShareClean version or commit SHA
- Operating system and Python version

## Scope

Security reports may include:

- Sensitive values appearing in sanitized output when they should be redacted
- Sensitive values appearing in reports, findings, logs, exceptions, or error messages
- Input files being modified unexpectedly
- Unsafe filesystem behavior
- Denial-of-service style inputs that cause extreme runtime or memory use

Out of scope:

- Requests for comprehensive secret detection across every vendor-specific format
- Reports that require real credentials or production data to reproduce
- Issues caused by modifying the source code locally

## Disclosure Expectations

Please give the maintainer a reasonable opportunity to investigate and publish a fix before disclosing a confirmed vulnerability publicly.
