# Roadmap

ShareClean is intentionally small: local-first, standard-library-only, and focused on making text safer to share. These are the most likely next improvements.

## Near Term

- Add more targeted detectors for common cloud and SaaS token shapes while keeping examples fake.
- Add optional allowlist support for values users intentionally want to preserve.
- Add optional SARIF output for code-scanning style integrations.
- Add repository-relative source paths as an explicit opt-in report mode for CI.
- Add `--report-format jsonl` for batch and stream processing.

## Maybe Later

- More fixture packs for common log formats.

## Non-Goals

- No telemetry.
- No network scanning.
- No credential validation against external services.
- No claim that ShareClean replaces dedicated secret scanners such as repository scanners or data loss prevention systems.
