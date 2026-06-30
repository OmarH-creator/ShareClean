# Roadmap

ShareClean is intentionally small: local-first, standard-library-only, and focused on making text safer to share. These are the most likely next improvements.

## Near Term

- Add more targeted detectors for common cloud and SaaS token shapes while keeping examples fake.
- Add a `--fail-on {category}` option for stricter CI and pre-commit workflows.
- Add optional allowlist support for values users intentionally want to preserve.
- Improve JSON report ergonomics for automation.
- Publish to PyPI once the package name and release flow are ready.

## Maybe Later

- Optional SARIF output for code-scanning style integrations.
- Config file support for team defaults.
- More fixture packs for common log formats.

## Non-Goals

- No telemetry.
- No network scanning.
- No credential validation against external services.
- No claim that ShareClean replaces dedicated secret scanners such as repository scanners or data loss prevention systems.
