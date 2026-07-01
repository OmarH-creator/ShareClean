# Changelog

All notable changes to ShareClean will be documented in this file.

This project follows a simple release format inspired by Keep a Changelog and uses semantic versioning for public releases.

## 0.2.0 - 2026-07-02

### Added

- Stable `SC###` detector IDs, categories, severities, and 1-based location ranges.
- Versioned JSON report schema `1.0` with privacy-preserving `source` labels.
- `--fail-on` and `--ignore-for-check` selectors for CI check policies.
- Project config support for `pyproject.toml` and `.shareclean.toml`, including profiles and environment variable overrides.
- `shareclean config show` for inspecting effective non-sensitive configuration.
- PEM private-key block detection.
- Fake-secret fixture corpus with manifest-driven regression tests.
- GitHub Release workflow for TestPyPI and PyPI Trusted Publishing without long-lived API tokens.

### Changed

- Bumped package and CLI version to `0.2.0`.
- `pipx install shareclean` is now the intended install path after PyPI publication.
- Reports no longer include filenames or full input paths by default.
- Overlapping detections now emit one finding by severity and detector specificity.
- `--no-email` is now a deprecated alias for `--no-redact-email`.

### Verified

- PyPI and TestPyPI package-name preflight returned 404 for `shareclean` on 2026-07-02, so the planned public package name appeared available before release workflow implementation.

## 0.1.1 - 2026-07-01

### Added

- `--redaction-label TEXT` for customizing the generic `[REDACTED]` label used by passwords, API keys, Bearer tokens, and connection string passwords.
- Interactive playground support for trying custom redaction labels in the browser demo.

## 0.1.0 - 2026-07-01

### Added

- Standard-library-only `shareclean` CLI.
- Redaction rules for key-value secrets, connection string passwords, Bearer tokens, JWT-like tokens, email addresses, local user paths, and opt-in private IP addresses.
- Human-readable and JSON reports that exclude original secret values.
- `--check`, `--output`, `--report`, `--report-format`, `--no-email`, and `--redact-private-ip` CLI options.
- Unit, integration, fixture-based, and property-style tests.
- Cross-platform line-ending preservation for file, stdin, and stdout workflows.
- GitHub-ready documentation, CI, security policy, and contribution guide.
