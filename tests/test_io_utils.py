"""Unit tests for shareclean/io_utils.py.

Tests read_input() and write_output() for correct I/O behaviour, error
handling, and line-ending preservation. All test content uses clearly
fake/synthetic values.

Covers:
  - Task 6.2: missing file → ShareCleanIOError
  - Task 6.2: empty stdin → ("", "stdin")
  - Task 6.2: stdin with content → (content, "stdin")
  - Task 6.2: existing file → (file_contents, file_path)
  - Task 6.2: write_output path == input_path → ShareCleanIOError
  - Task 6.2: write_output to new file; original untouched
  - Task 6.2: write_output(text, None, None) → stdout
  - Task 6.2: line endings (\r\n) preserved on round-trip

Requirements: 1.3, 1.4, 9.4, 15.5
"""

import io
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

from shareclean.io_utils import ShareCleanIOError, read_input, write_output


# ---------------------------------------------------------------------------
# read_input — file path given
# ---------------------------------------------------------------------------

class TestReadInputFromFile(unittest.TestCase):
    """read_input(path) reads from an existing file and returns (text, path)."""

    def test_existing_file_returns_contents(self):
        # Write in binary mode so \n is stored as \n (not translated to \r\n on Windows)
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".txt", delete=False
        ) as fh:
            fh.write(b"fake log content\nline two\n")
            tmp_path = fh.name

        try:
            text, input_name = read_input(tmp_path)
            self.assertEqual(text, "fake log content\nline two\n")
        finally:
            os.unlink(tmp_path)

    def test_existing_file_returns_path_as_input_name(self):
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=".txt", delete=False
        ) as fh:
            fh.write("some content")
            tmp_path = fh.name

        try:
            _, input_name = read_input(tmp_path)
            self.assertEqual(input_name, tmp_path)
        finally:
            os.unlink(tmp_path)

    def test_missing_file_raises_share_clean_io_error(self):
        missing = os.path.join(tempfile.gettempdir(), "no_such_file_fake_12345.txt")
        with self.assertRaises(ShareCleanIOError) as ctx:
            read_input(missing)
        self.assertIn("File not found", str(ctx.exception))

    def test_missing_file_error_mentions_path(self):
        missing = os.path.join(tempfile.gettempdir(), "no_such_file_fake_12345.txt")
        with self.assertRaises(ShareCleanIOError) as ctx:
            read_input(missing)
        self.assertIn(missing, str(ctx.exception))


# ---------------------------------------------------------------------------
# read_input — stdin (path=None)
# ---------------------------------------------------------------------------

class TestReadInputFromStdin(unittest.TestCase):
    """read_input(None) reads from sys.stdin and returns ("stdin") as input_name."""

    def test_empty_stdin_returns_empty_string(self):
        with patch("shareclean.io_utils.sys") as mock_sys:
            mock_sys.stdin = io.StringIO("")
            text, input_name = read_input(None)
        self.assertEqual(text, "")
        self.assertEqual(input_name, "stdin")

    def test_empty_stdin_produces_no_findings(self):
        """Empty stdin text fed through the redactor should yield no findings."""
        from shareclean.detectors import get_rules
        from shareclean.redactor import sanitize

        with patch("shareclean.io_utils.sys") as mock_sys:
            mock_sys.stdin = io.StringIO("")
            text, _ = read_input(None)

        rules = get_rules()
        result = sanitize(text, rules)
        self.assertEqual(result.findings, [])

    def test_stdin_with_content_returns_content(self):
        fake_content = "fake log line one\nfake log line two\n"
        with patch("shareclean.io_utils.sys") as mock_sys:
            mock_sys.stdin = io.StringIO(fake_content)
            text, input_name = read_input(None)
        self.assertEqual(text, fake_content)
        self.assertEqual(input_name, "stdin")

    def test_stdin_with_multiline_content(self):
        fake_content = "alpha\nbeta\ngamma\n"
        with patch("shareclean.io_utils.sys") as mock_sys:
            mock_sys.stdin = io.StringIO(fake_content)
            text, _ = read_input(None)
        self.assertEqual(text, fake_content)

    def test_stdin_buffer_preserves_crlf(self):
        class FakeStdin:
            encoding = "utf-8"
            errors = "strict"

            def __init__(self):
                self.buffer = io.BytesIO(b"alpha\r\nbeta\r\n")

            def read(self):
                raise AssertionError("text stream should not be used")

        with patch("shareclean.io_utils.sys") as mock_sys:
            mock_sys.stdin = FakeStdin()
            text, input_name = read_input(None)

        self.assertEqual(text, "alpha\r\nbeta\r\n")
        self.assertEqual(input_name, "stdin")


# ---------------------------------------------------------------------------
# write_output — path == input_path guard
# ---------------------------------------------------------------------------

class TestWriteOutputSamePathGuard(unittest.TestCase):
    """write_output raises ShareCleanIOError when path equals input_path."""

    def test_same_path_raises_error(self):
        tmp_path = os.path.join(tempfile.gettempdir(), "fake_input_file_abc.txt")
        with self.assertRaises(ShareCleanIOError) as ctx:
            write_output("sanitized content", tmp_path, tmp_path)
        self.assertIn("differ from input path", str(ctx.exception))

    def test_same_path_error_is_share_clean_io_error_subclass(self):
        tmp_path = "/fake/path/input.txt"
        with self.assertRaises(ShareCleanIOError):
            write_output("content", tmp_path, tmp_path)


# ---------------------------------------------------------------------------
# write_output — write to new file, original untouched
# ---------------------------------------------------------------------------

class TestWriteOutputToNewFile(unittest.TestCase):
    """write_output writes content to the output file and leaves input unchanged."""

    def test_writes_content_to_output_file(self):
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=".txt", delete=False
        ) as input_fh:
            input_fh.write("original fake content\n")
            input_path = input_fh.name

        output_path = input_path + ".out"
        try:
            write_output("sanitized fake content\n", output_path, input_path)
            with open(output_path, mode="r", encoding="utf-8", newline="") as fh:
                written = fh.read()
            self.assertEqual(written, "sanitized fake content\n")
        finally:
            os.unlink(input_path)
            if os.path.exists(output_path):
                os.unlink(output_path)

    def test_original_file_is_unmodified(self):
        original_content = b"original fake content - do not change\n"
        # Write in binary mode so line endings are stored exactly as-is
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".txt", delete=False
        ) as input_fh:
            input_fh.write(original_content)
            input_path = input_fh.name

        output_path = input_path + ".out"
        try:
            write_output("sanitized version\n", output_path, input_path)
            # Read back in binary to compare exact bytes stored
            with open(input_path, mode="rb") as fh:
                after = fh.read()
            self.assertEqual(after, original_content)
        finally:
            os.unlink(input_path)
            if os.path.exists(output_path):
                os.unlink(output_path)

    def test_output_file_differs_from_input(self):
        """Confirm the output file path is distinct from the input file path."""
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=".txt", delete=False
        ) as input_fh:
            input_fh.write("fake data\n")
            input_path = input_fh.name

        output_path = input_path + ".cleaned"
        try:
            write_output("cleaned fake data\n", output_path, input_path)
            self.assertTrue(os.path.exists(output_path))
            self.assertNotEqual(input_path, output_path)
        finally:
            os.unlink(input_path)
            if os.path.exists(output_path):
                os.unlink(output_path)


# ---------------------------------------------------------------------------
# write_output — write to stdout (path=None)
# ---------------------------------------------------------------------------

class TestWriteOutputToStdout(unittest.TestCase):
    """write_output(text, None, None) writes to sys.stdout."""

    def test_writes_to_stdout_when_path_is_none(self):
        fake_text = "sanitized output for stdout\n"
        with patch("shareclean.io_utils.sys") as mock_sys:
            captured = io.StringIO()
            mock_sys.stdout = captured
            write_output(fake_text, None, None)
        self.assertEqual(captured.getvalue(), fake_text)

    def test_stdout_write_called_with_correct_text(self):
        """Verify sys.stdout.write is called with the exact text."""
        fake_text = "another fake line\n"
        with patch("shareclean.io_utils.sys") as mock_sys:
            captured = io.StringIO()
            mock_sys.stdout = captured
            write_output(fake_text, None, None)
        self.assertEqual(captured.getvalue(), fake_text)

    def test_stdout_buffer_preserves_crlf_bytes(self):
        class FakeStdout:
            encoding = "utf-8"
            errors = "strict"

            def __init__(self):
                self.buffer = io.BytesIO()

            def write(self, text):
                raise AssertionError("text stream should not be used")

        fake_stdout = FakeStdout()
        with patch("shareclean.io_utils.sys") as mock_sys:
            mock_sys.stdout = fake_stdout
            write_output("alpha\r\nbeta\r\n", None, None)

        self.assertEqual(fake_stdout.buffer.getvalue(), b"alpha\r\nbeta\r\n")


# ---------------------------------------------------------------------------
# Line-ending preservation
# ---------------------------------------------------------------------------

class TestLineEndingPreservation(unittest.TestCase):
    """Line endings are never normalized during read or write."""

    def test_crlf_preserved_on_write_and_read_back(self):
        """Write text with \\r\\n endings and read back — no normalization."""
        crlf_text = "fake line one\r\nfake line two\r\nfake line three\r\n"

        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="", suffix=".txt", delete=False
        ) as input_fh:
            input_fh.write("original\r\n")
            input_path = input_fh.name

        output_path = input_path + ".out"
        try:
            write_output(crlf_text, output_path, input_path)
            # Read back with newline="" to prevent Python translating \r\n→\n
            with open(output_path, mode="r", encoding="utf-8", newline="") as fh:
                result = fh.read()
            self.assertEqual(result, crlf_text)
            self.assertIn("\r\n", result)
            self.assertNotIn("\r\n".replace("\r\n", "\n"), result.replace("\r\n", ""))
        finally:
            os.unlink(input_path)
            if os.path.exists(output_path):
                os.unlink(output_path)

    def test_read_input_preserves_crlf(self):
        """read_input preserves \\r\\n without translating to \\n."""
        crlf_text = "line one\r\nline two\r\n"

        # Write the file in binary mode to guarantee exact bytes on disk
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".txt", delete=False
        ) as fh:
            fh.write(crlf_text.encode("utf-8"))
            tmp_path = fh.name

        try:
            text, _ = read_input(tmp_path)
            self.assertEqual(text, crlf_text)
            self.assertIn("\r\n", text)
        finally:
            os.unlink(tmp_path)

    def test_lf_only_preserved_on_round_trip(self):
        """LF-only files are not altered by write_output."""
        lf_text = "line one\nline two\n"

        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".txt", delete=False
        ) as input_fh:
            input_fh.write(b"original\n")
            input_path = input_fh.name

        output_path = input_path + ".out"
        try:
            write_output(lf_text, output_path, input_path)
            with open(output_path, mode="r", encoding="utf-8", newline="") as fh:
                result = fh.read()
            self.assertEqual(result, lf_text)
        finally:
            os.unlink(input_path)
            if os.path.exists(output_path):
                os.unlink(output_path)


if __name__ == "__main__":
    unittest.main()
