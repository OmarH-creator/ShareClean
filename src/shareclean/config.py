"""Configuration loading for ShareClean."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

from shareclean.detectors import DEFAULT_REDACTION_LABEL

try:  # pragma: no cover - exercised on Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]


BOOL_TRUE = frozenset({"true", "1", "yes", "on"})
BOOL_FALSE = frozenset({"false", "0", "no", "off"})

ENV_REDACT_EMAIL = "SHARECLEAN_REDACT_EMAIL"
ENV_REDACT_PRIVATE_IP = "SHARECLEAN_REDACT_PRIVATE_IP"
ENV_REDACTION_LABEL = "SHARECLEAN_REDACTION_LABEL"
ENV_PROFILE = "SHARECLEAN_PROFILE"
ENV_FAIL_ON = "SHARECLEAN_FAIL_ON"
ENV_IGNORE_FOR_CHECK = "SHARECLEAN_IGNORE_FOR_CHECK"

ROOT_KEYS = frozenset({
    "redact_email",
    "redact_private_ip",
    "redaction_label",
    "profile",
    "fail_on",
    "ignore_for_check",
    "profiles",
})
PROFILE_KEYS = frozenset({
    "redact_email",
    "redact_private_ip",
    "redaction_label",
    "fail_on",
    "ignore_for_check",
})


class ConfigError(ValueError):
    """Raised for user-facing configuration errors."""


@dataclass(frozen=True)
class ShareCleanConfig:
    redact_email: bool = True
    redact_private_ip: bool = False
    redaction_label: str = DEFAULT_REDACTION_LABEL
    profile: str = "default"
    fail_on: list[str] | None = None
    ignore_for_check: list[str] | None = None

    def with_lists(self) -> "ShareCleanConfig":
        return replace(
            self,
            fail_on=list(self.fail_on or []),
            ignore_for_check=list(self.ignore_for_check or []),
        )

    def to_public_dict(self) -> dict[str, Any]:
        data = asdict(self.with_lists())
        return data


def _config_error(path: Path, message: str) -> ConfigError:
    return ConfigError(f"Config error in {path}: {message}")


def _format_toml_error(path: Path, exc: tomllib.TOMLDecodeError) -> ConfigError:
    line = getattr(exc, "lineno", None)
    column = getattr(exc, "colno", None)
    if line is not None and column is not None:
        return ConfigError(f"Config error in {path}:{line}:{column}: {exc}")
    return ConfigError(f"Config error in {path}: {exc}")


def _load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise _format_toml_error(path, exc) from exc
    except OSError as exc:
        raise ConfigError(f"Config error in {path}: cannot read file") from exc
    if not isinstance(data, dict):
        raise _config_error(path, "top-level TOML value must be a table")
    return data


def _shareclean_table_from_pyproject(path: Path) -> dict[str, Any] | None:
    data = _load_toml(path)
    tool = data.get("tool")
    if not isinstance(tool, dict):
        return None
    table = tool.get("shareclean")
    if table is None:
        return None
    if not isinstance(table, dict):
        raise _config_error(path, "[tool.shareclean] must be a table")
    return table


def _find_config(start: Path | None = None) -> tuple[Path, dict[str, Any]] | None:
    current = (start or Path.cwd()).resolve()
    if current.is_file():
        current = current.parent

    while True:
        dotfile = current / ".shareclean.toml"
        pyproject = current / "pyproject.toml"
        dotfile_table = _load_toml(dotfile) if dotfile.exists() else None
        pyproject_table = (
            _shareclean_table_from_pyproject(pyproject)
            if pyproject.exists()
            else None
        )

        if dotfile_table is not None and pyproject_table is not None:
            raise ConfigError(
                "Config error: both ShareClean config files exist in the same "
                f"directory: {dotfile} and {pyproject}"
            )
        if dotfile_table is not None:
            return dotfile, dotfile_table
        if pyproject_table is not None:
            return pyproject, pyproject_table

        if (current / ".git").exists():
            return None
        parent = current.parent
        if parent == current:
            return None
        current = parent


def _load_explicit_config(path_value: str) -> tuple[Path, dict[str, Any]]:
    path = Path(path_value).expanduser().resolve()
    if not path.exists():
        raise ConfigError(f"Config error: config file not found: {path}")
    if path.name == "pyproject.toml":
        table = _shareclean_table_from_pyproject(path)
        if table is None:
            raise _config_error(path, "missing [tool.shareclean] table")
        return path, table
    return path, _load_toml(path)


def _validate_label(path: Path | None, value: object) -> str:
    if not isinstance(value, str):
        raise _value_error(path, "redaction_label must be a string")
    if value == "":
        raise _value_error(path, "redaction_label must not be empty")
    if "\n" in value or "\r" in value:
        raise _value_error(path, "redaction_label must stay on one line")
    return value


def _value_error(path: Path | None, message: str) -> ConfigError:
    if path is None:
        return ConfigError(f"Config error: {message}")
    return _config_error(path, message)


def _validate_bool(path: Path | None, key: str, value: object) -> bool:
    if not isinstance(value, bool):
        raise _value_error(path, f"{key} must be true or false")
    return value


def _validate_string(path: Path | None, key: str, value: object) -> str:
    if not isinstance(value, str) or not value:
        raise _value_error(path, f"{key} must be a non-empty string")
    return value


def _validate_selector_list(path: Path | None, key: str, value: object) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise _value_error(path, f"{key} must be a list of selector strings")
    return list(value)


def _validate_table(
    path: Path | None,
    table: dict[str, Any],
    *,
    profile_table: bool,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    allowed = PROFILE_KEYS if profile_table else ROOT_KEYS
    unknown = sorted(set(table) - allowed)
    if unknown:
        raise _value_error(path, f"unknown config key(s): {', '.join(unknown)}")

    values: dict[str, Any] = {}
    profiles: dict[str, dict[str, Any]] = {}
    for key, value in table.items():
        if key == "profiles":
            if not isinstance(value, dict):
                raise _value_error(path, "profiles must be a table")
            for profile_name, profile_values in value.items():
                if not isinstance(profile_name, str) or not profile_name:
                    raise _value_error(path, "profile names must be non-empty strings")
                if not isinstance(profile_values, dict):
                    raise _value_error(path, f"profile {profile_name!r} must be a table")
                profile_config, _ = _validate_table(
                    path,
                    profile_values,
                    profile_table=True,
                )
                profiles[profile_name] = profile_config
            continue
        if key in {"redact_email", "redact_private_ip"}:
            values[key] = _validate_bool(path, key, value)
        elif key == "redaction_label":
            values[key] = _validate_label(path, value)
        elif key == "profile":
            values[key] = _validate_string(path, key, value)
        elif key in {"fail_on", "ignore_for_check"}:
            values[key] = _validate_selector_list(path, key, value)
    return values, profiles


def _apply_values(config: ShareCleanConfig, values: dict[str, Any]) -> ShareCleanConfig:
    data = asdict(config)
    for key, value in values.items():
        data[key] = value
    return ShareCleanConfig(**data)


def _parse_env_bool(name: str, raw: str) -> bool:
    normalized = raw.strip().lower()
    if normalized in BOOL_TRUE:
        return True
    if normalized in BOOL_FALSE:
        return False
    raise ConfigError(
        f"Config error: {name} must be one of true, 1, yes, on, false, 0, no, off"
    )


def _env_values(environ: dict[str, str]) -> tuple[dict[str, Any], str | None]:
    values: dict[str, Any] = {}
    profile = None
    if ENV_REDACT_EMAIL in environ:
        values["redact_email"] = _parse_env_bool(
            ENV_REDACT_EMAIL,
            environ[ENV_REDACT_EMAIL],
        )
    if ENV_REDACT_PRIVATE_IP in environ:
        values["redact_private_ip"] = _parse_env_bool(
            ENV_REDACT_PRIVATE_IP,
            environ[ENV_REDACT_PRIVATE_IP],
        )
    if ENV_REDACTION_LABEL in environ:
        values["redaction_label"] = _validate_label(None, environ[ENV_REDACTION_LABEL])
    if ENV_PROFILE in environ:
        profile = _validate_string(None, ENV_PROFILE, environ[ENV_PROFILE])
    if ENV_FAIL_ON in environ:
        values["fail_on"] = [environ[ENV_FAIL_ON]]
    if ENV_IGNORE_FOR_CHECK in environ:
        values["ignore_for_check"] = [environ[ENV_IGNORE_FOR_CHECK]]
    return values, profile


def load_config(
    *,
    config_path: str | None = None,
    cli_profile: str | None = None,
    cli_values: dict[str, Any] | None = None,
    environ: dict[str, str] | None = None,
    start: Path | None = None,
) -> ShareCleanConfig:
    """Load ShareClean configuration using the documented precedence order."""
    path: Path | None = None
    table: dict[str, Any] = {}
    profiles: dict[str, dict[str, Any]] = {}

    if config_path is not None:
        path, table = _load_explicit_config(config_path)
    else:
        discovered = _find_config(start)
        if discovered is not None:
            path, table = discovered

    base_values, profiles = _validate_table(path, table, profile_table=False)
    config = _apply_values(ShareCleanConfig(), base_values)

    env_values, env_profile = _env_values(environ or dict(os.environ))
    selected_profile = config.profile
    if env_profile is not None:
        selected_profile = env_profile
    if cli_profile is not None:
        selected_profile = cli_profile

    if selected_profile != "default":
        if selected_profile not in profiles:
            raise _value_error(path, f"unknown profile: {selected_profile}")
        config = _apply_values(config, profiles[selected_profile])

    config = replace(config, profile=selected_profile)
    config = _apply_values(config, env_values)
    if cli_values:
        config = _apply_values(
            config,
            {key: value for key, value in cli_values.items() if value is not None},
        )
    return config.with_lists()
