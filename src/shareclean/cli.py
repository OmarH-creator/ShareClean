"""CLI entry point for ShareClean."""

from __future__ import annotations

import argparse
import json
import sys

from shareclean import __version__
from shareclean.config import ConfigError, ShareCleanConfig, load_config
from shareclean.detectors import DEFAULT_REDACTION_LABEL, get_rules
from shareclean.io_utils import ShareCleanIOError, read_input, write_output
from shareclean.redactor import sanitize
from shareclean.report import format_brief_count, format_json_report, format_text_report
from shareclean.selectors import (
    SelectorError,
    findings_for_check,
    parse_selector_values,
)

EXIT_OK = 0
EXIT_FINDING = 1
EXIT_USER = 2
EXIT_INTERNAL = 3


def _redaction_label(value: str) -> str:
    if value == "":
        raise argparse.ArgumentTypeError("must not be empty")
    if "\n" in value or "\r" in value:
        raise argparse.ArgumentTypeError("must stay on one line")
    return value


def _add_config_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--config",
        metavar="FILE",
        default=None,
        help="Load ShareClean config from FILE instead of auto-discovery.",
    )
    parser.add_argument(
        "--profile",
        metavar="NAME",
        default=None,
        help="Use a named ShareClean config profile.",
    )
    parser.add_argument(
        "--redact-email",
        dest="redact_email",
        action="store_true",
        default=None,
        help="Enable email address detection for this run.",
    )
    parser.add_argument(
        "--no-redact-email",
        "--no-email",
        dest="redact_email",
        action="store_false",
        default=None,
        help=(
            "Disable email address detection for this run. "
            "--no-email is deprecated; use --no-redact-email."
        ),
    )
    parser.add_argument(
        "--redact-private-ip",
        dest="redact_private_ip",
        action="store_true",
        default=None,
        help="Enable detection and redaction of RFC 1918 private IP addresses.",
    )
    parser.add_argument(
        "--no-redact-private-ip",
        dest="redact_private_ip",
        action="store_false",
        default=None,
        help="Disable detection and redaction of RFC 1918 private IP addresses.",
    )
    parser.add_argument(
        "--redaction-label",
        default=None,
        type=_redaction_label,
        metavar="TEXT",
        help=(
            "Replacement text for generic secrets such as passwords, API keys, "
            f"Bearer tokens, and connection string passwords. Default: "
            f"{DEFAULT_REDACTION_LABEL!r}."
        ),
    )
    parser.add_argument(
        "--fail-on",
        action="append",
        default=None,
        metavar="SELECTORS",
        help=(
            "In --check mode, fail on selectors such as severity:high, "
            "category:token, or rule:SC003."
        ),
    )
    parser.add_argument(
        "--ignore-for-check",
        action="append",
        default=None,
        metavar="SELECTORS",
        help=(
            "In --check mode, exclude matching findings from the exit decision "
            "without disabling detection or redaction."
        ),
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shareclean",
        description=(
            "Sanitize sensitive values in logs and text before sharing publicly. "
            "Reads from a file or stdin; writes sanitized text to stdout (or --output)."
        ),
    )
    parser.add_argument(
        "file",
        nargs="?",
        default=None,
        metavar="FILE",
        help="Input file to sanitize. Reads from stdin if omitted.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Print the ShareClean version and exit.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        default=False,
        help=(
            "Exit 1 if matching findings are detected; do not write sanitized "
            "output. Useful in CI pipelines and Git hooks."
        ),
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        default=None,
        help="Write sanitized text to FILE instead of stdout.",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        default=False,
        help="Print a full redaction report to stderr after processing.",
    )
    parser.add_argument(
        "--report-format",
        choices=["text", "json"],
        default="text",
        metavar="{text,json}",
        help="Format for --report output: 'text' (default) or 'json'.",
    )
    _add_config_options(parser)
    return parser


def _build_config_show_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shareclean config show",
        description="Print the effective ShareClean configuration.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Print the ShareClean version and exit.",
    )
    _add_config_options(parser)
    return parser


def _cli_config_values(args: argparse.Namespace) -> dict[str, object]:
    return {
        "redact_email": args.redact_email,
        "redact_private_ip": args.redact_private_ip,
        "redaction_label": args.redaction_label,
        "fail_on": args.fail_on,
        "ignore_for_check": args.ignore_for_check,
    }


def _load_effective_config(args: argparse.Namespace) -> ShareCleanConfig:
    return load_config(
        config_path=args.config,
        cli_profile=args.profile,
        cli_values=_cli_config_values(args),
    )


def _extract_config_show_args(argv: list[str]) -> list[str] | None:
    for index in range(len(argv) - 1):
        if argv[index] == "config" and argv[index + 1] == "show":
            return argv[:index] + argv[index + 2:]
    return None


def _print_check_summary(total: int, failing: int) -> None:
    if failing:
        print(
            f"Found {failing} check-failing sensitive item(s) "
            f"out of {total} total finding(s). No output written.",
            file=sys.stderr,
        )
    elif total:
        print(
            f"No check-failing sensitive items found. "
            f"{total} finding(s) still detected and no output written.",
            file=sys.stderr,
        )
    else:
        print("No sensitive items found. No output written.", file=sys.stderr)


def _run_config_show(argv: list[str]) -> int:
    parser = _build_config_show_parser()
    args = parser.parse_args(argv)
    try:
        config = _load_effective_config(args)
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_USER
    print(json.dumps(config.to_public_dict(), indent=2))
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    """Run ShareClean and return a process exit code."""
    raw_args = list(sys.argv[1:] if argv is None else argv)
    config_show_args = _extract_config_show_args(raw_args)
    if config_show_args is not None:
        return _run_config_show(config_show_args)

    parser = _build_parser()
    args = parser.parse_args(raw_args)

    try:
        if not args.check and (args.fail_on is not None or args.ignore_for_check is not None):
            print(
                "Error: --fail-on and --ignore-for-check require --check.",
                file=sys.stderr,
            )
            return EXIT_USER

        config = _load_effective_config(args)

        try:
            fail_on = parse_selector_values(config.fail_on)
            ignore_for_check = parse_selector_values(config.ignore_for_check)
        except SelectorError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return EXIT_USER

        try:
            text, input_name = read_input(args.file)
        except ShareCleanIOError as exc:
            print(str(exc), file=sys.stderr)
            return EXIT_USER

        rules = get_rules(
            redact_email=config.redact_email,
            redact_private_ip=config.redact_private_ip,
            redaction_label=config.redaction_label,
        )
        result = sanitize(text, rules)

        if args.check:
            failing = findings_for_check(
                result.findings,
                fail_on=fail_on,
                ignore_for_check=ignore_for_check,
            )
            _print_check_summary(result.replacement_count, len(failing))
            return EXIT_FINDING if failing else EXIT_OK

        try:
            write_output(result.cleaned_text, args.output, args.file)
        except ShareCleanIOError as exc:
            print(str(exc), file=sys.stderr)
            return EXIT_USER

        if args.output:
            print(f"Output written to: {args.output}", file=sys.stderr)

        if args.report:
            if args.report_format == "json":
                print(format_json_report(result, input_name), file=sys.stderr)
            else:
                print(format_text_report(result, input_name), file=sys.stderr)
        else:
            print(format_brief_count(result), file=sys.stderr)

        return EXIT_OK

    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_USER
    except Exception as exc:  # noqa: BLE001 - catch-all for internal errors
        print(f"Internal error: {exc}", file=sys.stderr)
        return EXIT_INTERNAL
