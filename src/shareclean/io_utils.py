"""I/O utilities for ShareClean.

Handles all filesystem and stream interaction outside the core pipeline.
This is the only module that touches sys.stdin, sys.stdout, or the
filesystem (apart from cli.py, which orchestrates everything).

Public interface:
    ShareCleanIOError  - custom exception for all I/O problems
    read_input()       - read text from a file path or stdin
    write_output()     - write text to a file path or stdout
"""

from __future__ import annotations

import sys


class ShareCleanIOError(Exception):
    """Raised for all I/O errors encountered by ShareClean.

    Caught by cli.py, which prints the message to stderr and exits with
    code 2.
    """


def _stream_encoding(stream: object) -> str:
    return getattr(stream, "encoding", None) or "utf-8"


def _stream_errors(stream: object) -> str:
    return getattr(stream, "errors", None) or "strict"


def read_input(path: str | None) -> tuple[str, str]:
    """Read the full input text from *path* or from stdin.

    Args:
        path: Path to the input file, or ``None`` to read from stdin.

    Returns:
        A ``(text, input_name)`` tuple where *input_name* is ``"stdin"``
        when reading from stdin, or the file path string otherwise.

    Raises:
        ShareCleanIOError: If *path* is given but the file does not exist,
            cannot be opened, or cannot be read.
    """
    if path is None:
        # Read the raw buffer when available so redirected stdin keeps its
        # original line endings instead of going through universal-newlines
        # translation. Fall back to the text stream for mocked/interactive use.
        try:
            stdin = sys.stdin
            buffer = getattr(stdin, "buffer", None)
            if buffer is None:
                text = stdin.read()
            else:
                data = buffer.read()
                if isinstance(data, str):
                    text = data
                else:
                    text = data.decode(
                        _stream_encoding(stdin),
                        errors=_stream_errors(stdin),
                    )
        except Exception as exc:
            raise ShareCleanIOError(f"Error: Cannot read from stdin: {exc}") from exc
        return text, "stdin"

    try:
        # newline="" disables universal-newlines translation so all original
        # line endings (\n, \r\n, \r) are preserved verbatim in the returned
        # string.
        with open(path, mode="r", encoding="utf-8", newline="") as fh:
            text = fh.read()
    except FileNotFoundError:
        raise ShareCleanIOError(f"Error: File not found: {path}")
    except OSError as exc:
        raise ShareCleanIOError(f"Error: Cannot read file: {path}") from exc

    return text, path


def write_output(text: str, path: str | None, input_path: str | None) -> None:
    """Write *text* to *path*, or to stdout when *path* is ``None``.

    Args:
        text:       The sanitized text to write.
        path:       Destination file path, or ``None`` to write to stdout.
        input_path: The path of the original input file (used to prevent
                    in-place overwriting).  Pass ``None`` when the input was
                    stdin.

    Raises:
        ShareCleanIOError: If *path* is the same as *input_path* (would
            overwrite the original), or if the file cannot be written.
    """
    if path is None:
        # Write through the raw buffer when available. On Windows, text-mode
        # stdout would translate "\n" and corrupt existing "\r\n" as "\r\r\n".
        try:
            stdout = sys.stdout
            buffer = getattr(stdout, "buffer", None)
            if buffer is None:
                stdout.write(text)
            else:
                buffer.write(text.encode(
                    _stream_encoding(stdout),
                    errors=_stream_errors(stdout),
                ))
        except Exception as exc:
            raise ShareCleanIOError(f"Error: Cannot write to stdout: {exc}") from exc
        return

    if path == input_path:
        raise ShareCleanIOError("Error: Output path must differ from input path.")

    try:
        # newline="" prevents Python from translating \n to the platform line
        # separator, preserving the original line endings from the input.
        with open(path, mode="w", encoding="utf-8", newline="") as fh:
            fh.write(text)
    except OSError as exc:
        raise ShareCleanIOError(f"Error: Cannot write to output file: {path}") from exc
