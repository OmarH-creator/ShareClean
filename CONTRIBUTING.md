# Contributing

Thanks for helping make ShareClean safer and more useful.

## Development Setup

```bash
git clone https://github.com/OmarH-creator/ShareClean.git
cd ShareClean
python -m pip install -e .
python -m unittest discover -s tests -v
```

No third-party runtime or test dependencies are required.

## Project Principles

- Keep ShareClean local-first: no network calls, accounts, telemetry, or remote scanning.
- Preserve debugging context wherever possible. Redact the sensitive value, not the whole line.
- Never store or print original matched secret values in `Finding`, reports, exceptions, or test output.
- Use clearly fake test values only.
- Prefer precise, readable standard-library code over broad dependencies.
- Add tests for every detector or behavior change.

## Adding Or Changing A Detector

1. Add or update the rule in `src/shareclean/detectors.py`.
2. Keep rule order intentional. More specific rules should run before broader rules.
3. Add positive and negative detector tests.
4. Add redactor or property-style tests when behavior spans multiple modules.
5. Confirm reports never include the raw matched value.

Run:

```bash
python -m unittest discover -s tests -v
python -m compileall -q src tests
```

## Pull Request Checklist

- Tests pass locally.
- New behavior is covered by tests.
- Documentation is updated when CLI behavior or detection behavior changes.
- Examples use fake values only.
- The PR does not add telemetry, network behavior, or unnecessary dependencies.

## Security Issues

Do not put real secrets or production logs in GitHub issues or pull requests. Read [SECURITY.md](SECURITY.md) first.
