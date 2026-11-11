"""Check the built report: at most 10 pages, and how many \\pending markers remain.

Run after building (see report/README.md):  python report/check_pages.py
Reads LaTeX's own log instead of the PDF, so it needs no PDF library.
"""

import re
import sys
from pathlib import Path

# The course's limit for the report (report plan).
MAX_PAGES = 10
REPORT = Path(__file__).resolve().parent


def page_count(log_text: str) -> int:
    """The page count LaTeX prints at the end of a build: 'Output written on main.pdf (7 pages'."""
    match = re.search(r"Output written on \S+ \((\d+) pages?", log_text)
    if match is None:
        raise ValueError("no 'Output written' line: the build did not finish")
    return int(match.group(1))


def pending_count(tex_texts: list[str]) -> int:
    """How many \\pending{...} markers are left in the text, ignoring LaTeX comments."""
    total = 0
    for text in tex_texts:
        for line in text.splitlines():
            # A % starts a comment unless it is escaped as \%.
            code = re.split(r"(?<!\\)%", line, maxsplit=1)[0]
            total += len(re.findall(r"\\pending\{", code))
    return total


def main() -> int:
    pages = page_count((REPORT / "main.log").read_text(encoding="utf-8", errors="replace"))
    texts = [p.read_text(encoding="utf-8") for p in sorted(REPORT.rglob("*.tex"))]
    pending = pending_count(texts)
    print(f"{pages} pages (limit {MAX_PAGES}); {pending} to-do markers left")
    # Too many pages fails the check; to-do markers only fail it at submission time,
    # so drafts can merge while sections are still being written.
    return 1 if pages > MAX_PAGES else 0


if __name__ == "__main__":
    sys.exit(main())
