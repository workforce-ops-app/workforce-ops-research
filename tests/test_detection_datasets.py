"""Tests for the detection datasets (slice DS1): the selection rules, the split, and the
committed files. No network: the rules are tested on small made-up inputs, and the
committed files are checked as they are.

The committed test set is opened here only to check its checksum and that no near-copy
of a test entry is in the tuning set. Its content is never printed or compared by eye.
"""

import hashlib
import json
import unittest
from collections import Counter
from pathlib import Path

from scripts.build_detection_datasets import (
    DATASET,
    HARMLESS,
    Entry,
    demo_texts,
    near_key,
    read_lines,
    remove_duplicates,
    sample,
    split,
)
from scripts.vendor.backend_normalize import normalize

VENDOR = Path(__file__).resolve().parent.parent / "scripts" / "vendor" / "backend_normalize.py"
# SHA-256 of app/detection/normalize.py in workforce-ops-backend at commit
# 1ca970c4cf77765dae45a06e7d056067dfefc0d0 (where the detector, #134, merged). To check:
#   git show 1ca970c:app/detection/normalize.py | sha256sum
BACKEND_NORMALIZE_SHA256 = "0bcbb87de2216eaaed373d791a5576141db88e8b0006388aed4dcb6472b71336"
ATTACK_TYPES = {"sql_injection", "xss", "path_traversal", "command_injection", "format_string"}


def entry(label: str, text: str, source: str = "A", line: int = 1) -> Entry:
    return Entry(label, source, "file.txt", line, text)


class NormalizationIsTheBackendsTest(unittest.TestCase):
    """Rule 2 uses the detector's own normalization, so the copy must be exact."""

    def test_the_copy_is_byte_for_byte_the_backends(self) -> None:
        self.assertEqual(hashlib.sha256(VENDOR.read_bytes()).hexdigest(), BACKEND_NORMALIZE_SHA256)

    def test_the_five_steps(self) -> None:
        self.assertEqual(normalize("%2527"), "'")  # 1. URL-decoded twice
        self.assertEqual(normalize("&lt;script&gt;"), "<script>")  # 2. HTML entities
        self.assertEqual(normalize("＜script"), "<script")  # 3. NFKC (full-width <)
        self.assertEqual(normalize("UnIoN/**/SeLeCt"), "union select")  # 4 and 5


class ReadLinesTest(unittest.TestCase):
    def test_each_line_is_one_entry_exactly_as_written(self) -> None:
        lines = list(read_lines(b"|| \r\n' or 1=1\n"))
        self.assertEqual([(n, t) for n, t, _ in lines], [(1, "|| "), (2, "' or 1=1"), (3, None)])

    def test_comments_empty_lines_and_binary_data_are_left_out(self) -> None:
        data = b"# a comment\n\n   \n\xff\xfe\nbad\x01byte\n#{7*7}\n#Site.com:\nkept\n"
        found = {n: (t, why) for n, t, why in read_lines(data, comment=r"^#[A-Za-z0-9.]+:\s*$")}
        self.assertEqual(found[1], (None, "comment"))
        self.assertEqual(found[2], (None, "empty"))
        self.assertEqual(found[3], (None, "empty"))
        self.assertEqual(found[4], (None, "not UTF-8 text"))
        self.assertEqual(found[5], (None, "binary data"))
        # A payload that starts with # is not a comment: only "# " or the file's own form.
        self.assertEqual(found[6], ("#{7*7}", ""))
        self.assertEqual(found[7], (None, "comment"))
        self.assertEqual(found[8], ("kept", ""))


class DuplicatesTest(unittest.TestCase):
    def test_duplicates_after_normalization_are_removed_within_a_label(self) -> None:
        kept, dropped = remove_duplicates(
            [entry("sql_injection", "' OR 1=1", line=1), entry("sql_injection", "%27%20or%201=1", line=2)]
        )
        self.assertEqual([e.line for e in kept], [1])  # the first in canonical order stays
        self.assertEqual(dropped, 1)

    def test_the_same_text_under_two_labels_is_kept_under_both(self) -> None:
        kept, _ = remove_duplicates([entry("sql_injection", "|"), entry("command_injection", "|")])
        self.assertEqual(sorted(e.label for e in kept), ["command_injection", "sql_injection"])

    def test_text_that_normalizes_to_nothing_is_dropped(self) -> None:
        kept, dropped = remove_duplicates([entry("xss", "%20"), entry("xss", "/**/")])
        self.assertEqual((kept, dropped), ([], 2))

    def test_near_duplicates_differ_only_in_digits_and_whitespace(self) -> None:
        self.assertEqual(near_key(normalize("' or 1=1 --")), near_key(normalize("' OR 2=2--")))
        self.assertNotEqual(near_key(normalize("' or 1=1")), near_key(normalize("' and 1=1")))


class SampleTest(unittest.TestCase):
    def pool(self, label: str, count: int) -> list[Entry]:
        return [entry(label, f"value {n}", line=n) for n in range(count)]

    def test_a_large_type_is_cut_to_the_limit_and_harmless_input_never_is(self) -> None:
        chosen = sample(self.pool("xss", 50) + self.pool(HARMLESS, 50), 20, seed=1)
        self.assertEqual(Counter(e.label for e in chosen), {"xss": 20, HARMLESS: 50})

    def test_the_same_seed_gives_the_same_sample(self) -> None:
        first = [e.line for e in sample(self.pool("xss", 50), 20, seed=7)]
        self.assertEqual(first, [e.line for e in sample(self.pool("xss", 50), 20, seed=7)])
        self.assertNotEqual(first, [e.line for e in sample(self.pool("xss", 50), 20, seed=8)])

    def test_adding_a_type_does_not_change_another_types_sample(self) -> None:
        alone = [e.line for e in sample(self.pool("xss", 50), 20, seed=7)]
        together = sample(self.pool("xss", 50) + self.pool("sql_injection", 80), 20, seed=7)
        self.assertEqual(alone, [e.line for e in together if e.label == "xss"])


class SplitTest(unittest.TestCase):
    def entries(self) -> list[Entry]:
        made = []
        for label in ("xss", HARMLESS):
            for source in ("A", "B"):
                made.extend(entry(label, f"{label} {source} text {n}", source, n) for n in range(100))
        # Give every entry a distinct near-duplicate key (digits alone would be removed).
        for index, item in enumerate(made):
            item.norm = f"{item.label}-{item.source}-" + "".join(chr(97 + int(d)) for d in str(index))
        return made

    def test_the_same_seed_gives_the_same_split(self) -> None:
        self.assertEqual(split(self.entries(), 5, 0.4), split(self.entries(), 5, 0.4))
        self.assertNotEqual(split(self.entries(), 5, 0.4), split(self.entries(), 6, 0.4))

    def test_forty_percent_of_each_label_and_source_is_test(self) -> None:
        made = self.entries()
        sets = split(made, 5, 0.4)
        in_test = Counter((e.label, e.source) for i, e in enumerate(made) if sets[i] == "test")
        self.assertEqual(set(in_test.values()), {40})

    def test_near_duplicates_stay_in_one_set_even_across_labels(self) -> None:
        made = self.entries()
        # Three near-copies: two under xss in different sources, one harmless.
        for index in (0, 150, 250):
            made[index].norm = "' or = --"
        sets = split(made, 5, 0.4)
        self.assertEqual(len({sets[0], sets[150], sets[250]}), 1)


class DemoTextsTest(unittest.TestCase):
    def test_the_typed_fields_are_read_without_running_the_file(self) -> None:
        source = """
raise SystemExit("this file is never run")
DEPARTMENTS = {"Kitchen": ("Morning Prep",)}
COMPANIES = (CompanyPlan(name="Northwind Cafe", timezone="America/Chicago",
    email_domain="example.com", people=(Person("Ana Diaz", "Kitchen", (), "manager"),)),)
WEEK = (ShiftPlan(0, "Kitchen", "07:00", "15:00", 1, "Prep line", notes="Deliveries at 8"),)
"""
        self.assertEqual(
            demo_texts(source),
            [
                "Kitchen",
                "Morning Prep",
                "Northwind Cafe",
                "America/Chicago",
                "example.com",
                "Ana Diaz",
                "ana.diaz@example.com",
                "Prep line",
                "Deliveries at 8",
            ],
        )


class CommittedDatasetsTest(unittest.TestCase):
    """The files in datasets/detection/ as committed."""

    @classmethod
    def setUpClass(cls) -> None:
        def rows(name: str) -> list[dict]:
            return [json.loads(line) for line in (DATASET / name).read_text(encoding="ascii").splitlines()]

        cls.tuning = rows("tuning.jsonl")
        cls.test = rows("test.jsonl")
        cls.summary = json.loads((DATASET / "summary.json").read_text(encoding="utf-8"))

    def test_every_file_matches_its_checksum(self) -> None:
        for line in (DATASET / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
            digest, name = line.split("  ")
            with self.subTest(name=name):
                self.assertEqual(hashlib.sha256((DATASET / name).read_bytes()).hexdigest(), digest)

    def test_no_near_copy_of_a_test_entry_is_in_the_tuning_set(self) -> None:
        tuning = {near_key(normalize(r["text"])) for r in self.tuning}
        test = {near_key(normalize(r["text"])) for r in self.test}
        self.assertEqual(tuning & test, set())

    def test_the_sets_are_disjoint_and_labelled(self) -> None:
        ids = [r["id"] for r in self.tuning + self.test]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertLessEqual({r["label"] for r in self.tuning + self.test}, ATTACK_TYPES | {HARMLESS})

    def test_the_summary_counts_the_files(self) -> None:
        self.assertEqual(self.summary["test"], dict(sorted(Counter(r["label"] for r in self.test).items())))
        self.assertEqual(
            self.summary["tuning"], dict(sorted(Counter(r["label"] for r in self.tuning).items()))
        )

    def test_the_harmless_test_set_reaches_1000(self) -> None:
        self.assertGreaterEqual(self.summary["test"][HARMLESS], 1000)


if __name__ == "__main__":
    unittest.main()
