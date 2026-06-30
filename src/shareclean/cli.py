"""CLI entry point for ShareClean.

Orchestrates the full pipeline:
    read_input -> get_rules -> sanitize -> write_output / report -> exit code

Exit codes
----------
EXIT_OK       = 0  - completed normally (no findings, or sanitization applied)
EXIT_FINDING  = 1  - --check mode: at least one finding detected
EXIT_USER     = 2  - I/O / user error (ShareCleanIOError)
EXIT_INTERNAL = 3  - unexpected internal error
"""

from __future__ import annotations

import argparse
import sys

from shareclean import __version__
from shareclean.detectors import get_rules
from shareclean.io_utils import ShareCleanIOError, read_input, write_output
from shareclean.redactor import sanitize
from shareclean.report import format_brief_count, format_json_report, format_text_report

# ---------------------------------------------------------------------------
# Exit code constants
# ---------------------------------------------------------------------------

EXIT_OK = 0
EXIT_FINDING = 1
EXIT_USER = 2
EXIT_INTERNAL = 3


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

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
            "Exit 1 if any findings are detected; do not write sanitized output. "
            "Useful in CI pipelines and Git hooks."
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
    parser.add_argument(
        "--no-email",
        action="store_true",
        default=False,
        help="Disable email address detection for this run.",
    )
    parser.add_argument(
        "--redact-private-ip",
        action="store_true",
        default=False,
        help="Enable detection and redaction of RFC 1918 private IP addresses.",
    )

    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    """Run the ShareClean pipeline and return an exit code.

    Returns an int exit code; never calls sys.exit() directly except in the
    outermost catch-all handler.
    """
    parser = _build_parser()
    args = parser.parse_args()

    try:
        # ------------------------------------------------------------------
        # Step 1: Read input
        # ------------------------------------------------------------------
        try:
            text, input_name = read_input(args.file)
        except ShareCleanIOError as exc:
            print(str(exc), file=sys.stderr)
            return EXIT_USER

        # ------------------------------------------------------------------
        # Step 2: Build rules
        # ------------------------------------------------------------------
        rules = get_rules(
            redact_email=not args.no_email,
            redact_private_ip=args.redact_private_ip,
        )

        # ------------------------------------------------------------------
        # Step 3: Sanitize
        # ------------------------------------------------------------------
        result = sanitize(text, rules)

        # ------------------------------------------------------------------
        # Step 4a: --check mode - no output written
        # ------------------------------------------------------------------
        if args.check:
            count = result.replacement_count
            if count:
                print(
                    f"Found {count} sensitive item(s). No output written.",
                    file=sys.stderr,
                )
                return EXIT_FINDING
            else:
                print("No sensitive items found. No output written.", file=sys.stderr)
                return EXIT_OK

        # ------------------------------------------------------------------
        # Step 4b: Normal mode - write output and report
        # ------------------------------------------------------------------
        try:
            write_output(result.cleaned_text, args.output, args.file)
        except ShareCleanIOError as exc:
            print(str(exc), file=sys.stderr)
            return EXIT_USER

        # Confirmation when writing to a file
        if args.output:
            print(f"Output written to: {args.output}", file=sys.stderr)

        # Report or brief count
        if args.report:
            if args.report_format == "json":
                print(format_json_report(result, input_name), file=sys.stderr)
            else:
                print(format_text_report(result, input_name), file=sys.stderr)
        else:
            print(format_brief_count(result), file=sys.stderr)

        return EXIT_OK

    except Exception as exc:  # noqa: BLE001 - catch-all for internal errors
        print(f"Internal error: {exc}", file=sys.stderr)
        sys.exit(EXIT_INTERNAL)
