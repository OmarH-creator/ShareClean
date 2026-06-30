# Changelog

All notable changes to ShareClean will be documented in this file.

This project follows a simple release format inspired by Keep a Changelog and uses semantic versioning for public releases.

## 0.1.0 - Unreleased

### Added

- Standard-library-only `shareclean` CLI.
- Redaction rules for key-value secrets, connection string passwords, Bearer tokens, JWT-like tokens, email addresses, local user paths, and opt-in private IP addresses.
- Human-readable and JSON reports that exclude original secret values.
- `--check`, `--output`, `--report`, `--report-format`, `--no-email`, and `--redact-private-ip` CLI options.
- Unit, integration, fixture-based, and property-style tests.
- Cross-platform line-ending preservation for file, stdin, and stdout workflows.
- GitHub-ready documentation, CI, security policy, and contribution guide.
