"""Tests for report/check_pages.py: the page limit must be read correctly, or a
too-long report could be submitted without anyone noticing."""

import importlib.util
import unittest
from pathlib import Path

# report/ is not a package, so load the script from its path.
_PATH = Path(__file__).resolve().parent.parent / "report" / "check_pages.py"
_SPEC = importlib.util.spec_from_file_location("check_pages", _PATH)
check_pages = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(check_pages)


class PageCountTest(unittest.TestCase):
    def test_reads_plural_and_singular(self):
        self.assertEqual(check_pages.page_count("Output written on main.pdf (7 pages, 123 bytes)."), 7)
        self.assertEqual(check_pages.page_count("Output written on main.pdf (1 page, 9 bytes)."), 1)

    def test_unfinished_build_is_an_error(self):
        with self.assertRaises(ValueError):
            check_pages.page_count("! Undefined control sequence.")


class PendingCountTest(unittest.TestCase):
    def test_counts_markers_outside_comments(self):
        text = "Done.\n\\pending{intro}\n% \\pending{in a comment}\n50\\% \\pending{after escaped percent}\n"
        self.assertEqual(check_pages.pending_count([text]), 2)


if __name__ == "__main__":
    unittest.main()
