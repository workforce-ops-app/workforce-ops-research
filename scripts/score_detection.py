"""Score the backend's detector on one split of the detection datasets (slice DS2, RQ1).

    python -m scripts.score_detection --split tuning                      # the pinned commit
    python -m scripts.score_detection --split tuning --backend-ref <commit>
    python -m scripts.score_detection --split tuning --backend-path ../workforce-ops-backend
    python -m scripts.score_detection --split test --backend-ref detector-v1   # once (DS3)

What it does, in order (the measures are in the backend's docs/features/detection.md,
"Question and measures", and in report/sections/methodology.tex):

1. Check the dataset files against datasets/detection/SHA256SUMS, so the numbers always
   come from the committed split and never from a file changed by hand.
2. Load the detector: the backend's app/detection package, fetched at a pinned commit or
   tag (sparse, only that folder), or, while tuning, from a local backend checkout. The
   study scores exactly the code the API runs (rule DE10). The test split is refused
   unless the detector is a tag named detector-v<N>, fetched from GitHub, and a result
   for that tag does not exist yet: the test set is scored ONCE per version.
3. Ask the detector which attack types each entry looks like (`kinds(text)`).
4. Count, per attack type, the true positives, false positives, and false negatives, and
   turn them into precision, recall, F1, and Wilson 95% intervals; build the confusion
   matrix; and count false alarms on harmless input per source.
5. Time the detector: each value matched 100 times with time.perf_counter_ns, the median
   kept, then the median and 99th percentile over all values, per pattern and for the
   whole detector. The machine is recorded with the results.
6. Write results/detection/<split>-<version>.json and .md, each with a header naming the
   command, the dataset checksums, and both repositories' commits.

The entries are attack strings: DATA. They are read from JSON, passed to the detector as
Python strings, and counted. Nothing here runs, renders, or sends them anywhere.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import math
import os
import platform
import re
import statistics
import subprocess
import sys
import time
import tomllib
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from scripts.build_detection_datasets import CONFIG, DATASET, HARMLESS, fetch_repository

REPO = Path(__file__).resolve().parent.parent
RESULTS = REPO / "results" / "detection"
CACHE = REPO / ".cache" / "backend-detector"
BACKEND = "workforce-ops-backend"

# The only versions the test split may be scored with (see step 2 above).
TAG = re.compile(r"detector-v\d+")
# z for a two-sided 95% interval: the 97.5th percentile of the standard normal.
Z95 = 1.959963984540054
# How many times each value is matched for the timing (the median of these is kept).
REPEATS = 100
# "Reliably", fixed before the test set is scored (report/sections/methodology.tex): a
# type is detected reliably when the LOWER ends of the 95% intervals of both its
# precision and its recall are at least this. Judging the lower end, not the measured
# value, means a small set (format_string) cannot pass on luck.
RELIABLE = 0.90
# The harmless sources, in two groups reported separately (detection.md): the team's
# tricky text, where false alarms are expected, and ordinary text.
TRICKY_SOURCES = ("team",)
ORDINARY_SOURCES = ("demo", "census")


# --- The detector ------------------------------------------------------------------------


@dataclass(frozen=True)
class Detector:
    """What the scoring needs from the backend's detector, wrapped so the tests can pass in
    a small fake one instead of downloading the real one.

    kinds:   the attack types, in the backend's order (the confusion matrix uses it)
    flag:    the attack types one value is flagged as (the backend's kinds())
    prepare: one value turned into what each pattern looks at (its normalized forms)
    checks:  one (pattern ID, check) per pattern; a check takes what prepare() gave and
             says whether that pattern matches, exactly as the detector decides it
    """

    version: str  # the tag, the commit, or "local" (what --backend-* asked for)
    commit: str  # the backend commit the code came from
    clean: bool  # False when a local checkout had uncommitted changes
    kinds: tuple[str, ...]
    flag: Callable[[str], set[str]]
    prepare: Callable[[str], object]
    checks: tuple[tuple[str, Callable[[object], bool]], ...]


def _git_output(*args: str, cwd: Path | None = None) -> str:
    # Fixed arguments built here, no shell.
    done = subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)  # noqa: S603, S607
    return done.stdout.strip()


def resolve_tag(url: str, tag: str) -> str:
    """The commit a tag on the remote points at.

    An annotated tag is its own object; ls-remote then also lists "<tag>^{}", the commit it
    points to (the "peeled" tag), and that is the one to use.
    """
    lines = _git_output("ls-remote", url, f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}").splitlines()
    refs = dict(reversed(line.split("\t")) for line in lines if "\t" in line)
    commit = refs.get(f"refs/tags/{tag}^{{}}") or refs.get(f"refs/tags/{tag}")
    if not commit:
        raise SystemExit(f"{BACKEND} has no tag {tag}")
    return commit


def fetch_detector(ref: str, config: dict) -> tuple[Path, str]:
    """The backend checked out at `ref` (a commit or a tag), only app/detection, and the
    commit it is. Reuses the dataset build's sparse fetch, so it is cached in .cache/."""
    spec = dict(config["repositories"][BACKEND])
    # A tag is turned into its commit first: the cache is keyed by commit, so a moved tag
    # could never be scored from a stale copy.
    commit = resolve_tag(spec["url"], ref) if TAG.fullmatch(ref) else ref
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise SystemExit("--backend-ref must be a detector-v<N> tag or a full 40-character commit")
    spec["commit"] = commit
    return fetch_repository(BACKEND, spec, ["/app/detection/"], CACHE), commit


def load_detector(root: Path, version: str, commit: str, clean: bool = True) -> Detector:
    """Import app.detection from `root` (a backend checkout) and wrap it as a Detector."""
    # 1. Make `app` importable from that checkout only. If some other `app` was already
    #    imported, the study would score the wrong code, so that is refused.
    if "app" in sys.modules:
        raise SystemExit("another 'app' package is already imported; run the script on its own")
    sys.path.insert(0, str(root))
    detection = importlib.import_module("app.detection")
    detector = importlib.import_module("app.detection.detector")
    where = Path(detection.__file__).resolve()
    if root.resolve() not in where.parents:
        raise SystemExit(f"app.detection was imported from {where}, not from {root}")

    # 2. The per-pattern check repeats what the detector's _search() does for one pattern:
    #    search the URL-decoded form, and only if that finds nothing and the other form
    #    differs, the form without URL decoding. Values are cut to the 2,000-character cap
    #    first, as matches() does (DE4).
    cap = detector.MAX_VALUE_CHARS

    def prepare(value: str) -> tuple[str, str]:
        value = value[:cap]
        return detection.normalize(value), detection.normalize(value, url_decode=False)

    def check_for(regex: re.Pattern[str]) -> Callable[[object], bool]:
        def check(forms: object) -> bool:
            decoded, undecoded = forms  # type: ignore[misc]
            if regex.search(decoded) is not None:
                return True
            return undecoded != decoded and regex.search(undecoded) is not None

        return check

    checks = tuple((pattern.id, check_for(pattern.regex)) for pattern in detection.PATTERNS)
    return Detector(
        version=version,
        commit=commit,
        clean=clean,
        kinds=tuple(detection.KINDS),
        flag=detection.kinds,
        prepare=prepare,
        checks=checks,
    )


def local_detector(path: Path) -> Detector:
    """The detector in a local backend checkout, for tuning: its commit is recorded, and
    whether it had uncommitted changes (then the result is marked "-dirty")."""
    commit = _git_output("rev-parse", "HEAD", cwd=path)
    clean = _git_output("status", "--porcelain", "--", "app/detection", cwd=path) == ""
    return load_detector(path, "local", commit, clean)


# --- Reading the datasets ----------------------------------------------------------------


def checked_checksums(dataset: Path, names: Iterable[str]) -> dict[str, str]:
    """The SHA-256 of each named file, refused unless it is the one in SHA256SUMS."""
    expected = {}
    for line in (dataset / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, name = line.split(maxsplit=1)
        expected[name] = digest
    found = {}
    for name in names:
        digest = hashlib.sha256((dataset / name).read_bytes()).hexdigest()
        if expected.get(name) != digest:
            raise SystemExit(f"{name} does not match SHA256SUMS: rebuild it, never edit it by hand")
        found[name] = digest
    return found


def read_entries(path: Path) -> list[dict]:
    """The entries of one .jsonl split, in file order."""
    with path.open(encoding="ascii") as lines:
        return [json.loads(line) for line in lines if line.strip()]


# --- Measures ----------------------------------------------------------------------------


def ratio(part: int, whole: int) -> float | None:
    """part / whole, or None when there is nothing to divide by (an undefined measure is
    reported as missing, never as 0 or 1)."""
    return part / whole if whole else None


def wilson(successes: int, trials: int, z: float = Z95) -> tuple[float, float] | None:
    """The Wilson score interval for a proportion (95% by default).

    Unlike the usual "p plus or minus z times the standard error", it stays inside 0 to 1
    and is honest at the edges: 20 out of 20 gives about 0.84 to 1, not 1 to 1. So a
    small set is not reported as more certain than it is.
    """
    if trials == 0:
        return None
    p = successes / trials
    z2 = z * z
    centre = (p + z2 / (2 * trials)) / (1 + z2 / trials)
    half = z / (1 + z2 / trials) * math.sqrt(p * (1 - p) / trials + z2 / (4 * trials * trials))
    return (max(0.0, centre - half), min(1.0, centre + half))


def f1(precision: float | None, recall: float | None) -> float | None:
    """The harmonic mean of precision and recall (missing if either is)."""
    if precision is None or recall is None:
        return None
    return 2 * precision * recall / (precision + recall) if precision + recall else 0.0


def verdict(
    precision: float | None,
    recall: float | None,
    precision_ci: tuple[float, float] | None,
    recall_ci: tuple[float, float] | None,
) -> str:
    """The RQ1 answer for one type, by the threshold fixed beforehand (RELIABLE).

    reliable:      both intervals' lower ends reach the threshold
    not shown:     both measured values reach it, but an interval's lower end does not, so
                   this sample cannot show it (the set is too small or the result too close)
    not reliable:  a measured value is below the threshold, or missing (nothing flagged)
    """
    if precision is None or recall is None or precision < RELIABLE or recall < RELIABLE:
        return "not reliable"
    if precision_ci[0] >= RELIABLE and recall_ci[0] >= RELIABLE:  # type: ignore[index]
        return "reliable"
    return "not shown"


def score(entries: list[dict], flagged: dict[str, set[str]], kinds: tuple[str, ...]) -> dict:
    """Every RQ1 count and measure for one split.

    entries: the split's entries (id, label, source, ...)
    flagged: for each entry ID, the attack types the detector flagged it as
    kinds:   the attack types, in the order the tables use
    """
    labels = sorted({entry["label"] for entry in entries})
    unknown = set(labels) - set(kinds) - {HARMLESS}
    if unknown:
        raise SystemExit(f"labels the detector has no type for: {sorted(unknown)}")

    # 1. Per type: an entry flagged as this type is a true positive when its label is this
    #    type and a false positive otherwise; an entry of this type not flagged as it is a
    #    false negative. One entry can be flagged as several types and counts for each.
    per_type = {}
    for kind in kinds:
        of_kind = [entry for entry in entries if entry["label"] == kind]
        tp = sum(kind in flagged[entry["id"]] for entry in of_kind)
        fp = sum(kind in flagged[entry["id"]] for entry in entries if entry["label"] != kind)
        fn = len(of_kind) - tp
        precision, recall = ratio(tp, tp + fp), ratio(tp, tp + fn)
        precision_ci, recall_ci = wilson(tp, tp + fp), wilson(tp, tp + fn)
        # Recall per source: the collections differ (detection README, known limits), so
        # the report can say where a type's misses come from.
        by_source = {}
        for source in sorted({entry["source"] for entry in of_kind}):
            mine = [entry for entry in of_kind if entry["source"] == source]
            hits = sum(kind in flagged[entry["id"]] for entry in mine)
            by_source[source] = {"flagged": hits, "total": len(mine), "recall": ratio(hits, len(mine))}
        per_type[kind] = {
            "entries": len(of_kind),
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "precision": precision,
            "precision_ci": precision_ci,
            "recall": recall,
            "recall_ci": recall_ci,
            "f1": f1(precision, recall),
            "recall_by_source": by_source,
            "verdict": verdict(precision, recall, precision_ci, recall_ci),
        }

    # 2. The confusion matrix: rows are the true label, columns the types flagged, plus
    #    "none" for an entry flagged as nothing. An entry flagged as two types is counted
    #    in both columns, so a row can add up to more than its number of entries.
    rows = [*kinds, HARMLESS]
    columns = [*kinds, "none"]
    matrix = {row: dict.fromkeys(columns, 0) for row in rows}
    for entry in entries:
        types = flagged[entry["id"]]
        for kind in types:
            matrix[entry["label"]][kind] += 1
        if not types:
            matrix[entry["label"]]["none"] += 1

    # 3. False alarms: harmless entries flagged as anything, per source and in the two
    #    groups (tricky text written to be hard, ordinary text).
    harmless = [entry for entry in entries if entry["label"] == HARMLESS]

    def alarms(sources: Iterable[str]) -> dict:
        mine = [entry for entry in harmless if entry["source"] in set(sources)]
        hits = sum(bool(flagged[entry["id"]]) for entry in mine)
        return {
            "flagged": hits,
            "total": len(mine),
            "rate": ratio(hits, len(mine)),
            "ci": wilson(hits, len(mine)),
        }

    false_alarms = {
        "tricky": alarms(TRICKY_SOURCES),
        "ordinary": alarms(ORDINARY_SOURCES),
        "by_source": {source: alarms([source]) for source in sorted({e["source"] for e in harmless})},
    }
    return {
        "entries": {label: sum(entry["label"] == label for entry in entries) for label in labels},
        "per_type": per_type,
        "confusion": {"rows": rows, "columns": columns, "counts": matrix},
        "false_alarms": false_alarms,
    }


# --- Timing ------------------------------------------------------------------------------


def percentile(values: list[int], share: float) -> int:
    """The nearest-rank percentile: the smallest value at least `share` of the values are
    at or below (share 0.99 gives the 99th percentile). Always one of the measured values."""
    ordered = sorted(values)
    rank = max(1, math.ceil(share * len(ordered)))
    return ordered[rank - 1]


def median_ns(
    work: Callable[[], object], repeats: int, clock: Callable[[], int] = time.perf_counter_ns
) -> int:
    """The median time of `repeats` runs of `work`, in nanoseconds. The median, not the
    mean, so one run slowed by something else on the machine does not move it."""
    times = []
    for _ in range(repeats):
        start = clock()
        work()
        times.append(clock() - start)
    return int(statistics.median(times))


def timing(texts: list[str], detector: Detector, repeats: int = REPEATS) -> dict:
    """Median and 99th percentile time per value, for the whole detector and per pattern.

    Whole detector: kinds() on the original value (normalizing included). Per pattern: the
    pattern's own check on the value's already normalized forms, so a slow pattern shows
    as itself and not as the cost of normalizing, which every pattern shares.
    """
    whole = [median_ns(lambda text=text: detector.flag(text), repeats) for text in texts]
    prepared = [detector.prepare(text) for text in texts]
    per_pattern = {}
    for pattern_id, check in detector.checks:
        times = [median_ns(lambda forms=forms, check=check: check(forms), repeats) for forms in prepared]
        per_pattern[pattern_id] = {
            "median_ns": int(statistics.median(times)),
            "p99_ns": percentile(times, 0.99),
        }
    return {
        "repeats": repeats,
        "values": len(texts),
        "detector": {"median_ns": int(statistics.median(whole)), "p99_ns": percentile(whole, 0.99)},
        "per_pattern": per_pattern,
    }


def machine() -> dict:
    """The machine the times come from (times from different machines do not compare)."""
    return {
        "system": platform.platform(),
        "processor": platform.processor() or platform.machine(),
        "cpus": os.cpu_count(),
        "python": platform.python_version(),
    }


# --- Writing the results -----------------------------------------------------------------


def _percent(value: float | None) -> str:
    return "n/a" if value is None else f"{100 * value:.1f}%"


def _interval(ci: tuple[float, float] | None) -> str:
    return "n/a" if ci is None else f"{100 * ci[0]:.1f} to {100 * ci[1]:.1f}"


def _micro(ns: int) -> str:
    return f"{ns / 1000:.1f}"


def markdown(result: dict) -> str:
    """The result as Markdown tables, for reading on GitHub (the JSON is the record)."""
    head, scores = result["header"], result["scores"]
    lines = [
        f"# Detection scores: {head['split']} split, detector {head['detector']['version']}",
        "",
        f"Made by `{head['command']}` from research commit `{head['research_commit']}`"
        f" and backend commit `{head['detector']['commit']}`. Dataset checksums and the machine are in"
        " the JSON file next to this one.",
        "",
        f"A type is detected **reliably** when the lower ends of both 95% intervals are at least"
        f" {100 * RELIABLE:.0f}% (fixed before the test set is scored).",
        "",
        "## Per attack type",
        "",
        "| Type | Entries | Precision | 95% interval | Recall | 95% interval | F1 | Verdict |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for kind, row in scores["per_type"].items():
        lines.append(
            f"| `{kind}` | {row['entries']} | {_percent(row['precision'])} | {_interval(row['precision_ci'])}"
            f" | {_percent(row['recall'])} | {_interval(row['recall_ci'])} | {_percent(row['f1'])}"
            f" | {row['verdict']} |"
        )
    lines += [
        "",
        "## Recall by source",
        "",
        "| Type | Source | Flagged | Entries | Recall |",
        "|---|---|---|---|---|",
    ]
    for kind, row in scores["per_type"].items():
        for source, part in row["recall_by_source"].items():
            lines.append(
                f"| `{kind}` | {source} | {part['flagged']} | {part['total']} | {_percent(part['recall'])} |"
            )

    confusion = scores["confusion"]
    lines += [
        "",
        "## Confusion matrix",
        "",
        "Rows: the true label. Columns: the types flagged; an entry flagged as two types counts in both.",
        "",
        "| True label | " + " | ".join(f"`{c}`" for c in confusion["columns"]) + " |",
        "|---|" + "---|" * len(confusion["columns"]),
    ]
    for row in confusion["rows"]:
        counts = confusion["counts"][row]
        lines.append(f"| `{row}` | " + " | ".join(str(counts[c]) for c in confusion["columns"]) + " |")

    alarms = scores["false_alarms"]
    lines += [
        "",
        "## False alarms on harmless input",
        "",
        "| Input | Flagged | Entries | Rate | 95% interval |",
    ]
    lines.append("|---|---|---|---|---|")
    groups = [("tricky (team)", alarms["tricky"]), ("ordinary (demo, census)", alarms["ordinary"])]
    groups += [(f"source: {source}", part) for source, part in alarms["by_source"].items()]
    for name, part in groups:
        lines.append(
            f"| {name} | {part['flagged']} | {part['total']} | {_percent(part['rate'])}"
            f" | {_interval(part['ci'])} |"
        )

    times = result.get("timing")
    if times:
        lines += [
            "",
            "## Time per value",
            "",
            f"Each of the {times['values']} values matched {times['repeats']} times, median kept;"
            " then the median and 99th percentile over the values, in microseconds.",
            "",
            "| What | Median (µs) | 99th percentile (µs) |",
            "|---|---|---|",
            f"| whole detector (with normalizing) | {_micro(times['detector']['median_ns'])}"
            f" | {_micro(times['detector']['p99_ns'])} |",
        ]
        for pattern_id, part in times["per_pattern"].items():
            lines.append(f"| `{pattern_id}` | {_micro(part['median_ns'])} | {_micro(part['p99_ns'])} |")
    return "\n".join(lines) + "\n"


def research_commit() -> str:
    """This repository's commit, marked "-dirty" if the working tree had changes (then the
    result cannot be traced to a commit exactly)."""
    commit = _git_output("rev-parse", "HEAD", cwd=REPO)
    dirty = _git_output("status", "--porcelain", "--", "scripts", "datasets", cwd=REPO) != ""
    return commit + ("-dirty" if dirty else "")


def result_name(split: str, detector: Detector) -> str:
    """results/detection/<split>-<version>: the tag, or the commit's first 12 characters,
    marked "-dirty" for a local checkout with uncommitted changes."""
    version = detector.version if TAG.fullmatch(detector.version) else detector.commit[:12]
    return f"{split}-{version}" + ("" if detector.clean else "-dirty")


def check_allowed(split: str, ref: str | None, path: Path | None, out: Path) -> None:
    """Step 2's rules for the test split: a detector-v<N> tag from GitHub, scored once."""
    if split != "test":
        return
    if path is not None or ref is None or not TAG.fullmatch(ref):
        raise SystemExit("the test split is scored only with a tagged detector: --backend-ref detector-v<N>")
    if (out / f"test-{ref}.json").exists():
        raise SystemExit(
            f"test-{ref} is already scored; a changed detector is a new version with its own tag"
        )


# --- Main --------------------------------------------------------------------------------


def run(split: str, detector: Detector, dataset: Path, repeats: int | None) -> dict:
    """Steps 1 and 3 to 5 for one split: the whole result, header included."""
    name = f"{split}.jsonl"
    checksums = checked_checksums(dataset, [name])
    entries = read_entries(dataset / name)
    # Step 3: one call per entry. kinds() returns a fresh set, kept per entry ID.
    flagged = {entry["id"]: set(detector.flag(entry["text"])) for entry in entries}
    result = {
        "header": {
            "script": "scripts/score_detection.py",
            "split": split,
            "dataset_sha256": checksums,
            "detector": {"version": detector.version, "commit": detector.commit, "clean": detector.clean},
            "reliable_threshold": RELIABLE,
        },
        "scores": score(entries, flagged, detector.kinds),
    }
    if repeats:
        result["timing"] = timing([entry["text"] for entry in entries], detector, repeats)
        result["header"]["machine"] = machine()
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--split", choices=("tuning", "test"), required=True)
    where = parser.add_mutually_exclusive_group()
    where.add_argument("--backend-ref", help="a backend commit, or a detector-v<N> tag (test split)")
    where.add_argument("--backend-path", type=Path, help="a local backend checkout (tuning only)")
    parser.add_argument("--repeats", type=int, default=REPEATS, help="timing runs per value (0: no timing)")
    args = parser.parse_args(argv)

    # Step 2: the rules for the test split come before anything is loaded or read.
    check_allowed(args.split, args.backend_ref, args.backend_path, RESULTS)
    config = tomllib.loads(CONFIG.read_text(encoding="utf-8"))
    if args.backend_path is not None:
        detector = local_detector(args.backend_path)
    else:
        # Without a ref: the backend commit the datasets were built with (sources.toml).
        ref = args.backend_ref or config["repositories"][BACKEND]["commit"]
        root, commit = fetch_detector(ref, config)
        detector = load_detector(root, ref, commit)

    result = run(args.split, detector, DATASET, args.repeats)
    command = "python -m scripts.score_detection " + " ".join(argv if argv is not None else sys.argv[1:])
    result["header"]["command"] = command
    result["header"]["research_commit"] = research_commit()

    # Step 6: the JSON is the record (sorted keys, so two runs differ only where the
    # numbers do); the Markdown is for reading.
    RESULTS.mkdir(parents=True, exist_ok=True)
    name = result_name(args.split, detector)
    (RESULTS / f"{name}.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (RESULTS / f"{name}.md").write_text(markdown(result), encoding="utf-8")
    print(f"wrote results/detection/{name}.json and .md")
    print(f"to reproduce: {command}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
