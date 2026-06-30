# Release Process

This checklist keeps releases boring and repeatable.

## Before Release

1. Confirm `CHANGELOG.md` has an entry for the release.
2. Confirm `src/shareclean/__init__.py` and `pyproject.toml` use the same version.
3. Run the full test suite:

   ```bash
   python -m unittest discover -s tests -v
   ```

4. Run compile checks:

   ```bash
   python -m compileall -q src tests
   ```

5. Build a local wheel:

   ```bash
   python -m pip wheel . --no-deps --wheel-dir dist-check
   ```

6. Smoke test the installed CLI in a clean environment when possible:

   ```bash
   shareclean --help
   shareclean tests/fixtures/sample_log.txt --check
   ```

## Release

1. Commit the release changes.
2. Tag the release:

   ```bash
   git tag v0.1.0
   git push origin main --tags
   ```

3. Create a GitHub release from the tag.
4. Include the relevant `CHANGELOG.md` section in the release notes.

## After Release

- Verify the CI workflow passed on the release tag.
- Verify installation instructions in `README.md` still work.
- Open a follow-up issue for anything intentionally deferred.
