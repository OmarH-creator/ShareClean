"""Configuration tests for ShareClean."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from shareclean.config import ConfigError, load_config


class TestConfigDiscovery(unittest.TestCase):
    def test_missing_config_uses_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = load_config(environ={}, start=Path(tmp))
        self.assertTrue(config.redact_email)
        self.assertFalse(config.redact_private_ip)
        self.assertEqual(config.profile, "default")

    def test_nearest_config_wins_without_parent_merge(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            child = root / "child"
            child.mkdir()
            (root / ".shareclean.toml").write_text(
                "redact_private_ip = true\n",
                encoding="utf-8",
            )
            (child / ".shareclean.toml").write_text(
                "redact_email = false\n",
                encoding="utf-8",
            )
            config = load_config(environ={}, start=child)
        self.assertFalse(config.redact_email)
        self.assertFalse(config.redact_private_ip)

    def test_pyproject_counts_only_with_tool_shareclean(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pyproject.toml"
            path.write_text("[project]\nname = 'demo'\n", encoding="utf-8")
            config = load_config(environ={}, start=Path(tmp))
        self.assertEqual(config.profile, "default")

    def test_both_config_files_in_same_directory_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".shareclean.toml").write_text("redact_email = true\n", encoding="utf-8")
            (root / "pyproject.toml").write_text(
                "[tool.shareclean]\nredact_email = false\n",
                encoding="utf-8",
            )
            with self.assertRaises(ConfigError) as ctx:
                load_config(environ={}, start=root)
        self.assertIn(".shareclean.toml", str(ctx.exception))
        self.assertIn("pyproject.toml", str(ctx.exception))

    def test_malformed_toml_error_mentions_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".shareclean.toml"
            path.write_text("redact_email = \n", encoding="utf-8")
            with self.assertRaises(ConfigError) as ctx:
                load_config(environ={}, start=Path(tmp))
        self.assertIn(str(path.resolve()), str(ctx.exception))


class TestProfilesAndPrecedence(unittest.TestCase):
    def test_profile_overlays_base_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".shareclean.toml"
            path.write_text(
                "\n".join([
                    "redact_email = false",
                    "redact_private_ip = false",
                    "profile = 'ci'",
                    "",
                    "[profiles.ci]",
                    "redact_private_ip = true",
                    "fail_on = ['severity:high']",
                ]),
                encoding="utf-8",
            )
            config = load_config(environ={}, start=Path(tmp))
        self.assertFalse(config.redact_email)
        self.assertTrue(config.redact_private_ip)
        self.assertEqual(config.fail_on, ["severity:high"])

    def test_unknown_profile_exits_as_config_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".shareclean.toml"
            path.write_text("profile = 'ci'\n", encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(environ={}, start=Path(tmp))

    def test_cli_profile_overrides_environment_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".shareclean.toml"
            path.write_text(
                "\n".join([
                    "[profiles.ci]",
                    "redact_private_ip = true",
                    "",
                    "[profiles.support]",
                    "redact_private_ip = false",
                ]),
                encoding="utf-8",
            )
            config = load_config(
                cli_profile="support",
                environ={"SHARECLEAN_PROFILE": "ci"},
                start=Path(tmp),
            )
        self.assertEqual(config.profile, "support")
        self.assertFalse(config.redact_private_ip)

    def test_cli_values_override_environment_and_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".shareclean.toml"
            path.write_text(
                "[profiles.ci]\nredact_private_ip = true\n",
                encoding="utf-8",
            )
            config = load_config(
                cli_profile="ci",
                cli_values={"redact_private_ip": False},
                environ={"SHARECLEAN_REDACT_PRIVATE_IP": "true"},
                start=Path(tmp),
            )
        self.assertFalse(config.redact_private_ip)


class TestEnvironmentParsing(unittest.TestCase):
    def test_explicit_empty_environment_ignores_process_environment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(
                os.environ,
                {
                    "SHARECLEAN_REDACT_EMAIL": "false",
                    "SHARECLEAN_REDACT_PRIVATE_IP": "true",
                },
            ):
                config = load_config(environ={}, start=Path(tmp))
        self.assertTrue(config.redact_email)
        self.assertFalse(config.redact_private_ip)

    def test_boolean_environment_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = load_config(
                environ={
                    "SHARECLEAN_REDACT_EMAIL": "off",
                    "SHARECLEAN_REDACT_PRIVATE_IP": "yes",
                },
                start=Path(tmp),
            )
        self.assertFalse(config.redact_email)
        self.assertTrue(config.redact_private_ip)

    def test_invalid_boolean_environment_value_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ConfigError):
                load_config(
                    environ={"SHARECLEAN_REDACT_EMAIL": "sometimes"},
                    start=Path(tmp),
                )

    def test_selector_environment_variables(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = load_config(
                environ={
                    "SHARECLEAN_FAIL_ON": "severity:high",
                    "SHARECLEAN_IGNORE_FOR_CHECK": "category:pii_email",
                },
                start=Path(tmp),
            )
        self.assertEqual(config.fail_on, ["severity:high"])
        self.assertEqual(config.ignore_for_check, ["category:pii_email"])


if __name__ == "__main__":
    unittest.main()
