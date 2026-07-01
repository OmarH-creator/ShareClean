# Release Process

This checklist keeps releases boring and repeatable.

## One-Time PyPI Setup

1. Confirm the `shareclean` project name is available on PyPI and TestPyPI, or that you control it.
2. Configure pending Trusted Publishers for both PyPI and TestPyPI before the first upload.
3. Use separate GitHub environments:
   - `testpypi`
   - `pypi`
4. Protect the `pypi` environment with manual approval.
5. Do not store long-lived PyPI API tokens in GitHub secrets.

The release workflow uses `pypa/gh-action-pypi-publish@release/v1` with job-level `id-token: write`.

## Before Release

1. Confirm `CHANGELOG.md` has an entry for the release.
2. Confirm the Git tag, `pyproject.toml`, and `shareclean --version` normalize to the same version:

   ```text
   tag: v0.2.0
   package: 0.2.0
   CLI: 0.2.0
   ```

3. Run the full test suite:

   ```bash
   python -m unittest discover -s tests -v
   ```

4. Run compile checks:

   ```bash
   python -m compileall -q src tests
   ```

5. Build and validate distributions:

   ```bash
   python -m build
   python -m twine check dist/*
   python -m venv .venv-smoke
   . .venv-smoke/bin/activate
   python -m pip install dist/*.whl
   shareclean --version
   shareclean config show
   ```

6. Smoke test the CLI:

   ```bash
   shareclean --version
   shareclean tests/fixtures/sample_log.txt --check
   shareclean config show
   ```

## Release

1. Commit the release changes.
2. Tag the release:

   ```bash
   git tag vX.Y.Z
   git push origin main --tags
   ```

3. Publish a GitHub Release from the tag.
4. The release workflow will:
   - Checkout the release tag.
   - Run the test matrix.
   - Build exactly once with `python -m build`.
   - Run `twine check dist/*`.
   - Install the built wheel in a clean environment and run `shareclean --version` plus `shareclean config show`.
   - Upload the exact `dist/` files as an artifact.
   - Publish that artifact to TestPyPI.
   - Smoke install the exact version from TestPyPI with `pipx`.
   - Wait for protected `pypi` environment approval.
   - Publish the same artifact to production PyPI.

Production PyPI publishing is skipped for GitHub prereleases.

## After Release

- Verify `pipx install shareclean` works on Windows, macOS, and Linux.
- Verify `shareclean --version` matches the release tag.
- Verify the GitHub Release workflow published the expected artifacts.
- Do not rerun successful publish jobs for the same tag unless you expect PyPI to reject the already-published immutable version.
- Open follow-up issues for anything intentionally deferred.
