"""Tests for scripts/score_detection.py (slice DS2): every count and measure the report's
RQ1 answer rests on, and the rules that keep the test set scored only once.

No network and no real detector: a small fake detector flags entries by fixed rules, and
the datasets are a handful of made-up entries whose scores are worked out by hand below.
The committed test set is never opened here.
"""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import score_detection as sd

SQL, XSS = "sql_injection", "xss"
KINDS = (SQL, XSS)


def fake_detector(flags: dict[str, set[str]]) -> sd.Detector:
    """A detector that flags each text as `flags` says (nothing for any other text), with
    two "patterns" that check for a letter in the prepared text."""
    return sd.Detector(
        version="0123456789abcdef0123456789abcdef01234567",
        commit="0123456789abcdef0123456789abcdef01234567",
        clean=True,
        kinds=KINDS,
        flag=lambda text: set(flags.get(text, set())),
        prepare=lambda text: text.lower(),
        checks=(("SQLI-01", lambda forms: "s" in forms), ("XSS-01", lambda forms: "x" in forms)),
    )


def entry(id: str, label: str, source: str, text: str | None = None) -> dict:
    return {"id": id, "label": label, "source": source, "file": "f.txt", "line": 1, "text": text or id}


# The hand-worked example. What the fake detector flags, per entry:
#   s1 (sql)            -> sql          true positive for sql
#   s2 (sql)            -> sql, xss     true positive for sql, false positive for xss
#   s3 (sql)            -> nothing      false negative for sql
#   x1 (xss)            -> xss          true positive for xss
#   h1 (harmless, team) -> sql          false positive for sql, a tricky false alarm
#   h2 (harmless, team) -> nothing
#   c1 (harmless, census) -> nothing
# So sql: TP 2, FP 1, FN 1 (precision 2/3, recall 2/3, F1 2/3)
# and xss: TP 1, FP 1, FN 0 (precision 1/2, recall 1, F1 2/3).
ENTRIES = [
    entry("s1", SQL, "A"),
    entry("s2", SQL, "B"),
    entry("s3", SQL, "B"),
    entry("x1", XSS, "A"),
    entry("h1", "harmless", "team"),
    entry("h2", "harmless", "team"),
    entry("c1", "harmless", "census"),
]
FLAGGED = {"s1": {SQL}, "s2": {SQL, XSS}, "s3": set(), "x1": {XSS}, "h1": {SQL}, "h2": set(), "c1": set()}


class WilsonTest(unittest.TestCase):
    def test_known_values(self):
        # Worked out from the formula; the usual textbook example 8 of 10.
        low, high = sd.wilson(8, 10)
        self.assertAlmostEqual(low, 0.4902, places=4)
        self.assertAlmostEqual(high, 0.9433, places=4)

    def test_the_edges_stay_honest(self):
        # 0 of 10 still allows up to about 28%; 20 of 20 is not "certainly 100%".
        self.assertEqual(sd.wilson(0, 10)[0], 0.0)
        self.assertAlmostEqual(sd.wilson(0, 10)[1], 0.2775, places=4)
        self.assertAlmostEqual(sd.wilson(20, 20)[0], 0.8389, places=4)
        self.assertEqual(sd.wilson(20, 20)[1], 1.0)

    def test_nothing_to_measure_is_missing_not_zero(self):
        self.assertIsNone(sd.wilson(0, 0))
        self.assertIsNone(sd.ratio(0, 0))
        self.assertIsNone(sd.f1(None, 0.5))
        self.assertEqual(sd.f1(0.0, 0.0), 0.0)


class ScoreTest(unittest.TestCase):
    def setUp(self):
        self.scores = sd.score(ENTRIES, FLAGGED, KINDS)

    def test_counts_per_type(self):
        sql, xss = self.scores["per_type"][SQL], self.scores["per_type"][XSS]
        self.assertEqual((sql["true_positives"], sql["false_positives"], sql["false_negatives"]), (2, 1, 1))
        self.assertEqual((xss["true_positives"], xss["false_positives"], xss["false_negatives"]), (1, 1, 0))
        self.assertEqual(sql["entries"], 3)

    def test_measures_per_type(self):
        sql, xss = self.scores["per_type"][SQL], self.scores["per_type"][XSS]
        self.assertAlmostEqual(sql["precision"], 2 / 3)
        self.assertAlmostEqual(sql["recall"], 2 / 3)
        self.assertAlmostEqual(sql["f1"], 2 / 3)
        self.assertAlmostEqual(xss["precision"], 1 / 2)
        self.assertEqual(xss["recall"], 1.0)
        self.assertAlmostEqual(xss["f1"], 2 / 3)
        # The intervals are the Wilson ones for the same counts.
        self.assertEqual(sql["precision_ci"], sd.wilson(2, 3))
        self.assertEqual(xss["recall_ci"], sd.wilson(1, 1))

    def test_recall_by_source(self):
        by_source = self.scores["per_type"][SQL]["recall_by_source"]
        self.assertEqual(by_source["A"], {"flagged": 1, "total": 1, "recall": 1.0})
        self.assertEqual(by_source["B"], {"flagged": 1, "total": 2, "recall": 0.5})

    def test_confusion_matrix_counts_a_double_flag_in_both_columns(self):
        counts = self.scores["confusion"]["counts"]
        self.assertEqual(self.scores["confusion"]["rows"], [SQL, XSS, "harmless"])
        self.assertEqual(self.scores["confusion"]["columns"], [SQL, XSS, "none"])
        # s2 is in both the sql and the xss column; s3 in "none". 4 marks for 3 entries.
        self.assertEqual(counts[SQL], {SQL: 2, XSS: 1, "none": 1})
        self.assertEqual(counts[XSS], {SQL: 0, XSS: 1, "none": 0})
        self.assertEqual(counts["harmless"], {SQL: 1, XSS: 0, "none": 2})

    def test_false_alarms_tricky_and_ordinary_apart(self):
        alarms = self.scores["false_alarms"]
        self.assertEqual((alarms["tricky"]["flagged"], alarms["tricky"]["total"]), (1, 2))
        self.assertEqual(alarms["tricky"]["rate"], 0.5)
        self.assertEqual((alarms["ordinary"]["flagged"], alarms["ordinary"]["total"]), (0, 1))
        self.assertEqual(alarms["ordinary"]["ci"], sd.wilson(0, 1))
        self.assertEqual(set(alarms["by_source"]), {"team", "census"})

    def test_entry_counts(self):
        self.assertEqual(self.scores["entries"], {SQL: 3, XSS: 1, "harmless": 3})

    def test_a_type_never_flagged_has_no_precision(self):
        scores = sd.score(ENTRIES, {key: set() for key in FLAGGED}, KINDS)
        sql = scores["per_type"][SQL]
        self.assertIsNone(sql["precision"])
        self.assertEqual(sql["recall"], 0.0)
        self.assertIsNone(sql["f1"])
        self.assertEqual(sql["verdict"], "not reliable")

    def test_a_label_the_detector_has_no_type_for_is_refused(self):
        with self.assertRaises(SystemExit):
            sd.score([entry("p1", "path_traversal", "A")], {"p1": set()}, KINDS)


class VerdictTest(unittest.TestCase):
    def test_reliable_needs_both_lower_ends(self):
        self.assertEqual(sd.verdict(0.99, 0.99, (0.95, 1.0), (0.92, 1.0)), "reliable")

    def test_measured_high_but_too_few_entries_is_not_shown(self):
        # 20 of 20: measured 100%, but the interval reaches down to about 84%.
        ci = sd.wilson(20, 20)
        self.assertEqual(sd.verdict(1.0, 1.0, ci, ci), "not shown")

    def test_measured_below_the_threshold_is_not_reliable(self):
        self.assertEqual(sd.verdict(0.85, 0.99, (0.8, 0.9), (0.95, 1.0)), "not reliable")
        self.assertEqual(sd.verdict(None, 0.99, None, (0.95, 1.0)), "not reliable")


class TimingTest(unittest.TestCase):
    def test_percentile_is_nearest_rank(self):
        self.assertEqual(sd.percentile(list(range(1, 101)), 0.99), 99)
        self.assertEqual(sd.percentile([5], 0.99), 5)
        self.assertEqual(sd.percentile([2, 1], 0.99), 2)
        self.assertEqual(sd.percentile([3, 1, 2], 0.5), 2)

    def test_median_ns_keeps_the_median_run(self):
        # A fake clock: the runs take 5, 1, and 100 ns; the slow one does not move it.
        ticks = iter([0, 5, 10, 11, 20, 120])
        calls = []
        self.assertEqual(sd.median_ns(lambda: calls.append(1), 3, clock=lambda: next(ticks)), 5)
        self.assertEqual(len(calls), 3)

    def test_timing_covers_the_whole_detector_and_every_pattern(self):
        times = sd.timing(["s1", "x1", "h1"], fake_detector({}), repeats=2)
        self.assertEqual((times["repeats"], times["values"]), (2, 3))
        self.assertEqual(set(times["per_pattern"]), {"SQLI-01", "XSS-01"})
        for part in [times["detector"], *times["per_pattern"].values()]:
            self.assertGreaterEqual(part["p99_ns"], 0)
            self.assertGreaterEqual(part["p99_ns"], part["median_ns"])


class TestSplitRulesTest(unittest.TestCase):
    def setUp(self):
        self.out = Path(tempfile.mkdtemp())

    def test_tuning_takes_any_detector(self):
        sd.check_allowed("tuning", None, None, self.out)
        sd.check_allowed("tuning", "0" * 40, None, self.out)
        sd.check_allowed("tuning", None, Path("."), self.out)

    def test_test_split_only_with_a_tag(self):
        for ref, path in (
            (None, None),
            ("0" * 40, None),
            ("v1", None),
            ("detector-v1x", None),
            (None, Path(".")),
        ):
            with self.subTest(ref=ref, path=path), self.assertRaises(SystemExit):
                sd.check_allowed("test", ref, path, self.out)
        sd.check_allowed("test", "detector-v1", None, self.out)

    def test_a_tag_is_scored_on_the_test_set_once(self):
        (self.out / "test-detector-v1.json").write_text("{}", encoding="utf-8")
        with self.assertRaises(SystemExit):
            sd.check_allowed("test", "detector-v1", None, self.out)
        sd.check_allowed("test", "detector-v2", None, self.out)

    def test_result_names(self):
        detector = fake_detector({})
        self.assertEqual(sd.result_name("tuning", detector), "tuning-0123456789ab")
        tagged = sd.Detector(**{**detector.__dict__, "version": "detector-v1"})
        self.assertEqual(sd.result_name("test", tagged), "test-detector-v1")
        dirty = sd.Detector(**{**detector.__dict__, "version": "local", "clean": False})
        self.assertEqual(sd.result_name("tuning", dirty), "tuning-0123456789ab-dirty")


class ResolveTagTest(unittest.TestCase):
    def test_an_annotated_tag_resolves_to_its_commit(self):
        listing = "aaa\trefs/tags/detector-v1\nbbb\trefs/tags/detector-v1^{}"
        with mock.patch.object(sd, "_git_output", return_value=listing):
            self.assertEqual(sd.resolve_tag("url", "detector-v1"), "bbb")

    def test_a_lightweight_tag_is_its_commit(self):
        with mock.patch.object(sd, "_git_output", return_value="ccc\trefs/tags/detector-v1"):
            self.assertEqual(sd.resolve_tag("url", "detector-v1"), "ccc")

    def test_a_missing_tag_is_refused(self):
        with mock.patch.object(sd, "_git_output", return_value=""), self.assertRaises(SystemExit):
            sd.resolve_tag("url", "detector-v9")


class RunTest(unittest.TestCase):
    """The whole run on a made-up dataset folder, with its own SHA256SUMS."""

    def setUp(self):
        self.dataset = Path(tempfile.mkdtemp())
        lines = "".join(json.dumps(item, sort_keys=True) + "\n" for item in ENTRIES)
        # Bytes, not text: on Windows write_text() would turn each newline into CRLF.
        (self.dataset / "tuning.jsonl").write_bytes(lines.encode("ascii"))
        digest = hashlib.sha256(lines.encode("ascii")).hexdigest()
        (self.dataset / "SHA256SUMS").write_text(f"{digest}  tuning.jsonl\n", encoding="utf-8")
        self.detector = fake_detector({key: value for key, value in FLAGGED.items()})

    def test_scores_and_header(self):
        result = sd.run("tuning", self.detector, self.dataset, repeats=0)
        self.assertEqual(result["scores"], sd.score(ENTRIES, FLAGGED, KINDS))
        self.assertEqual(result["header"]["split"], "tuning")
        self.assertEqual(result["header"]["detector"]["commit"], self.detector.commit)
        self.assertIn("tuning.jsonl", result["header"]["dataset_sha256"])
        self.assertNotIn("timing", result)

    def test_timing_records_the_machine(self):
        result = sd.run("tuning", self.detector, self.dataset, repeats=2)
        self.assertEqual(result["timing"]["values"], len(ENTRIES))
        self.assertIn("python", result["header"]["machine"])

    def test_a_changed_dataset_file_is_refused(self):
        with (self.dataset / "tuning.jsonl").open("a", encoding="ascii", newline="\n") as file:
            file.write(json.dumps(entry("s9", SQL, "A")) + "\n")
        with self.assertRaises(SystemExit):
            sd.run("tuning", self.detector, self.dataset, repeats=0)

    def test_markdown_shows_every_table(self):
        result = sd.run("tuning", self.detector, self.dataset, repeats=2)
        result["header"].update(
            command="python -m scripts.score_detection --split tuning", research_commit="abc"
        )
        text = sd.markdown(result)
        for heading in (
            "Per attack type",
            "Recall by source",
            "Confusion matrix",
            "False alarms",
            "Time per value",
        ):
            self.assertIn(heading, text)
        # sql: precision 2/3 shown as 66.7%; the double flag shows in the matrix row.
        self.assertIn("| `sql_injection` | 3 | 66.7% |", text)
        self.assertIn("| `sql_injection` | 2 | 1 | 1 |", text)


if __name__ == "__main__":
    unittest.main()
