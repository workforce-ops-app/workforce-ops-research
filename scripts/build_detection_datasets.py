"""Build the detection study's datasets and their fixed tuning/test split (slice DS1).

    python -m scripts.build_detection_datasets           # fetch, select, split, write
    python -m scripts.build_detection_datasets --check   # rebuild and compare with the repo

What it does, in order (the rules are in datasets/detection/README.md and in the
backend's docs/features/detection.md, "Data and how it is chosen"):

1. Fetch each source at the commit (or checksum) pinned in datasets/detection/sources.toml.
2. Read every line of every included file as one entry (rule 1), skipping the files'
   own comments, empty lines, and lines that are not text (binary data).
3. Remove duplicates within each label after the backend's normalization (rule 2).
4. Sample each attack type down to 1,000 entries with a fixed seed (rule 3).
5. Group near-duplicates (equal after removing digits and whitespace) and split the
   groups 60/40 into tuning and test, stratified by label and source, with a fixed seed.
   A group never crosses the two sets, so the test set is not copies of the tuning set.
6. Write tuning.jsonl, test.jsonl, summary.json, label-overlaps.jsonl, the licences, and
   SHA256SUMS.

The attack strings are DATA. Nothing here runs, imports, renders, or sends them: they are
read as bytes, decoded as text, and written as JSON strings. The backend's demo data file
is read with Python's ast module, never imported or run.
"""

from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import io
import json
import random
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import urllib.request
import zipfile
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

from scripts.vendor.backend_normalize import normalize

REPO = Path(__file__).resolve().parent.parent
DATASET = REPO / "datasets" / "detection"
CONFIG = DATASET / "sources.toml"
# Downloads are kept here between runs (ignored by git).
CACHE = REPO / ".cache" / "detection-sources"

HARMLESS = "harmless"
# The files the build writes, in the order SHA256SUMS lists them.
OUTPUTS = ("tuning.jsonl", "test.jsonl", "summary.json", "label-overlaps.jsonl")
# A raw control character (other than tab) means the line is binary data, which needs a
# different setting than a form field to be dangerous (rule 1).
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
# Rule 2: near-duplicates are equal after removing digits and whitespace.
_DIGITS_AND_SPACE = re.compile(r"[\d\s]+")


@dataclass
class Entry:
    """One input line: its label, where it came from, and its text exactly as written."""

    label: str  # an attack type, or "harmless"
    source: str  # the collection: PayloadsAllTheThings, SecLists, team, demo, census
    file: str  # the file inside the source
    line: int  # 1-based line number in that file
    text: str
    # Filled in by the build, never written out.
    norm: str = field(default="", repr=False)

    @property
    def order(self) -> tuple[str, str, str, int]:
        """The canonical order: by label, then source, file, and line."""
        return (self.label, self.source, self.file, self.line)


# --- Reading ------------------------------------------------------------------------------


def read_lines(data: bytes, comment: str | None = None) -> Iterator[tuple[int, str | None, str]]:
    """Each line of a file as (line number, text or None, why it was left out or "").

    Line endings (LF or CRLF) are removed; nothing else is, because a leading or trailing
    space can be part of an attack ("|| " in a command list). A line is left out when it
    is empty, is the file's own comment, or is not text.
    """
    comment_line = re.compile(comment) if comment else None
    for number, raw in enumerate(data.split(b"\n"), start=1):
        raw = raw.removesuffix(b"\r")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            yield number, None, "not UTF-8 text"
            continue
        if not text.strip():
            yield number, None, "empty"
        elif text.startswith("# ") or (comment_line and comment_line.match(text)):
            yield number, None, "comment"
        elif _CONTROL.search(text):
            yield number, None, "binary data"
        else:
            yield number, text, ""


def matching_files(root: Path, include: Iterable[str], excluded: Iterable[str]) -> list[Path]:
    """The files under root that an include pattern matches and no excluded pattern does,
    sorted by path so the order never depends on the file system."""
    found: set[Path] = set()
    for pattern in include:
        found.update(p for p in root.glob(pattern) if p.is_file())
    kept = [p for p in found if not any(fnmatch(p.relative_to(root).as_posix(), x) for x in excluded)]
    return sorted(kept, key=lambda p: p.relative_to(root).as_posix())


def demo_texts(source: str) -> list[str]:
    """The text fields of the backend's demo data (scripts/seed_demo.py), read with ast.

    The fields a person types into the application: company names, time zones, and email
    domains; people's names and their email addresses (built the way the seed builds
    them); department and team names; and each shift's details, notes, and event text.
    Role codes and times are left out: nobody types them as free text.
    """
    tree = ast.parse(source)
    texts: list[str] = []

    def text(node: ast.expr | None) -> str | None:
        return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None

    for node in ast.walk(tree):
        # DEPARTMENTS = {"Kitchen": ("Morning Prep", ...), ...}: departments and teams.
        if isinstance(node, ast.Assign | ast.AnnAssign) and isinstance(node.value, ast.Dict):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Name) and t.id == "DEPARTMENTS" for t in targets):
                for key, value in zip(node.value.keys, node.value.values, strict=True):
                    texts.extend(t for t in [text(key)] if t)
                    if isinstance(value, ast.Tuple):
                        texts.extend(t for t in map(text, value.elts) if t)
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
            continue
        keywords = {k.arg: k.value for k in node.keywords}
        if node.func.id == "CompanyPlan":
            domain = text(keywords.get("email_domain"))
            texts.extend(t for t in (text(keywords.get(k)) for k in ("name", "timezone")) if t)
            texts.extend([domain] if domain else [])
            people = keywords.get("people")
            for person in people.elts if isinstance(people, ast.Tuple) else []:
                name = text(person.args[0]) if isinstance(person, ast.Call) and person.args else None
                if name:
                    texts.append(name)
                    if domain:
                        texts.append(f"{name.lower().replace(' ', '.')}@{domain}")
        elif node.func.id == "ShiftPlan":
            # ShiftPlan(weekday, department, start, end, worker, details, ...)
            if len(node.args) > 5:
                texts.extend(t for t in [text(node.args[5])] if t)
            for name in ("notes", "event_name", "event_description"):
                texts.extend(t for t in [text(keywords.get(name))] if t)
    # Each text once, in the order first seen.
    return list(dict.fromkeys(texts))


def census_surnames(archive: bytes, member: str, take: int) -> list[str]:
    """The `take` most common surnames by rank, written as a person would (Smith)."""
    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
        rows = csv.DictReader(io.StringIO(zipped.read(member).decode("utf-8")))
        ranked = sorted((int(r["rank"]), r["name"]) for r in rows if r["rank"].isdigit())
    return [name.title() for rank, name in ranked if 1 <= rank <= take]


# --- Selection and split ------------------------------------------------------------------


def near_key(norm: str) -> str:
    """Rule 2's near-duplicate key: the normalized text without digits and whitespace."""
    return _DIGITS_AND_SPACE.sub("", norm)


def remove_duplicates(entries: list[Entry]) -> tuple[list[Entry], int]:
    """Rule 2: within each label, keep the first entry (canonical order) of each normalized
    text. Entries that normalize to nothing are dropped too. Returns (kept, dropped)."""
    seen: set[tuple[str, str]] = set()
    kept: list[Entry] = []
    for entry in sorted(entries, key=lambda e: e.order):
        entry.norm = normalize(entry.text)
        key = (entry.label, entry.norm)
        if not entry.norm.strip() or key in seen:
            continue
        seen.add(key)
        kept.append(entry)
    return kept, len(entries) - len(kept)


def sample(entries: list[Entry], limit: int, seed: int) -> list[Entry]:
    """Rule 3: an attack type with more than `limit` entries keeps a random `limit` of them.

    Each type has its own generator (seeded with the seed and the type), so adding a type
    never changes another type's sample. Harmless input is not sampled.
    """
    by_label: dict[str, list[Entry]] = defaultdict(list)
    for entry in sorted(entries, key=lambda e: e.order):
        by_label[entry.label].append(entry)
    chosen: list[Entry] = []
    for label, pool in sorted(by_label.items()):
        if label != HARMLESS and len(pool) > limit:
            # Not for security: a fixed, repeatable sample.
            rng = random.Random(f"{seed}:sample:{label}")  # noqa: S311
            picked = sorted(rng.sample(range(len(pool)), limit))
            pool = [pool[i] for i in picked]
        chosen.extend(pool)
    return chosen


def split(entries: list[Entry], seed: int, test_share: float) -> dict[int, str]:
    """The 60/40 split: for each entry (by position in `entries`), "tuning" or "test".

    Near-duplicate groups are formed across ALL labels and moved as one, so no near-copy
    of a test entry is ever in the tuning set, not even under another label. Each group
    belongs to the stratum (label, source) of its first entry. Strata are handled in a
    fixed order; within one, its groups are shuffled with a generator seeded by the seed
    and the stratum, and go to the test set until the stratum has its share there.
    """
    groups: dict[str, list[int]] = defaultdict(list)
    for index, entry in enumerate(entries):
        groups[near_key(entry.norm)].append(index)
    stratum_of = {key: (entries[m[0]].label, entries[m[0]].source) for key, m in groups.items()}
    size = Counter((e.label, e.source) for e in entries)
    in_test: Counter[tuple[str, str]] = Counter()
    assigned: dict[int, str] = {}
    for stratum in sorted(size):
        target = round(test_share * size[stratum])
        keys = sorted(k for k, s in stratum_of.items() if s == stratum)
        random.Random(f"{seed}:split:{stratum[0]}:{stratum[1]}").shuffle(keys)  # noqa: S311
        for key in keys:
            if any(m in assigned for m in groups[key]):
                continue
            chosen = "test" if in_test[stratum] < target else "tuning"
            for member in groups[key]:
                assigned[member] = chosen
                if chosen == "test":
                    in_test[(entries[member].label, entries[member].source)] += 1
    return assigned


# --- Fetching -----------------------------------------------------------------------------


def _git(*args: str, cwd: Path) -> None:
    # Fixed arguments from sources.toml, no shell.
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)  # noqa: S603, S607


def fetch_repository(name: str, spec: dict, paths: list[str], cache: Path) -> Path:
    """The repository checked out at its pinned commit, with only `paths` (sparse)."""
    target = cache / f"{name}-{spec['commit'][:12]}"
    if not (target / ".done").exists():
        shutil.rmtree(target, ignore_errors=True)
        target.mkdir(parents=True)
        _git("init", "-q", cwd=target)
        _git("remote", "add", "origin", spec["url"], cwd=target)
        _git("sparse-checkout", "set", "--no-cone", *paths, cwd=target)
        _git("fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", spec["commit"], cwd=target)
        _git("checkout", "-q", "FETCH_HEAD", cwd=target)
        (target / ".done").write_text(spec["commit"], encoding="utf-8")
    return target


def fetch_download(name: str, spec: dict, cache: Path) -> bytes:
    """The file at spec["url"], refused unless its SHA-256 is the pinned one."""
    target = cache / f"{name}-{spec['sha256'][:12]}"
    if not target.exists():
        cache.mkdir(parents=True, exist_ok=True)
        # A fixed https URL from sources.toml.
        with urllib.request.urlopen(spec["url"], timeout=120) as response:  # noqa: S310
            target.write_bytes(response.read())
    data = target.read_bytes()
    if hashlib.sha256(data).hexdigest() != spec["sha256"]:
        target.unlink()
        raise SystemExit(f"{name}: the download's checksum is not the pinned one")
    return data


# --- Building -----------------------------------------------------------------------------


def _top_folders(patterns: Iterable[str]) -> list[str]:
    """The sparse-checkout paths for some glob patterns: the part before the first *."""
    return sorted({"/" + p.split("*")[0].rstrip("/") + ("/" if "*" in p else "") for p in patterns})


def collect(config: dict, cache: Path) -> tuple[list[Entry], Counter[str], dict[str, Path]]:
    """Every entry before rule 2, the count of lines left out by reason, and each
    repository's checkout (for the licences)."""
    entries: list[Entry] = []
    left_out: Counter[str] = Counter()
    excluded = defaultdict(list)
    for item in config.get("excluded", []):
        excluded[item["repository"]].append(item["path"])
    wanted: dict[str, list[str]] = defaultdict(lambda: ["/LICENSE"])
    for item in config["attack"]:
        wanted[item["repository"]].extend(_top_folders(item["include"]))
    wanted["workforce-ops-backend"].append("/scripts/seed_demo.py")
    roots = {
        name: fetch_repository(name, spec, wanted[name], cache)
        for name, spec in config["repositories"].items()
    }

    for item in config["attack"]:
        root = roots[item["repository"]]
        for path in matching_files(root, item["include"], excluded[item["repository"]]):
            relative = path.relative_to(root).as_posix()
            for number, text, reason in read_lines(path.read_bytes(), item.get("comment")):
                if text is None:
                    left_out[reason] += 1
                else:
                    entries.append(Entry(item["type"], item["repository"], relative, number, text))

    tricky = config["harmless"]["tricky"]["file"]
    for number, text, reason in read_lines((REPO / tricky).read_bytes()):
        if text is None:
            left_out[reason] += 1
        else:
            entries.append(Entry(HARMLESS, "team", Path(tricky).name, number, text))
    seed_file = (roots["workforce-ops-backend"] / "scripts" / "seed_demo.py").read_text(encoding="utf-8")
    for number, text in enumerate(demo_texts(seed_file), start=1):
        entries.append(Entry(HARMLESS, "demo", "scripts/seed_demo.py", number, text))
    census = config["downloads"]["census-surnames"]
    names = census_surnames(
        fetch_download("census-surnames", census, cache), census["member"], census["take"]
    )
    for rank, name in enumerate(names, start=1):
        entries.append(Entry(HARMLESS, "census", census["member"], rank, name))
    return entries, left_out, roots


def build(config: dict, out: Path, cache: Path) -> dict:
    """Run every step and write the outputs into `out`. Returns the summary."""
    raw, left_out, roots = collect(config, cache)
    unique, duplicates = remove_duplicates(raw)
    chosen = sample(unique, config["max_per_type"], config["seed"])
    sets = split(chosen, config["seed"], config["test_share"])

    out.mkdir(parents=True, exist_ok=True)
    rows: dict[str, list[dict]] = {"tuning": [], "test": []}
    # IDs follow the canonical order, so they never depend on the split.
    ids: dict[int, str] = {}
    for number, (index, entry) in enumerate(sorted(enumerate(chosen), key=lambda p: p[1].order), 1):
        ids[index] = f"{entry.label}-{number:05d}"
        rows[sets[index]].append(
            {
                "id": ids[index],
                "label": entry.label,
                "source": entry.source,
                "file": entry.file,
                "line": entry.line,
                "text": entry.text,
            }
        )
    for name, items in rows.items():
        _write_jsonl(out / f"{name}.jsonl", items)

    # The same normalized text under two labels: recorded, not silently fixed.
    by_norm: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for index, entry in enumerate(chosen):
        by_norm[entry.norm].append((entry.label, ids[index]))
    overlaps = [
        {"labels": sorted({lab for lab, _ in found}), "ids": sorted(i for _, i in found)}
        for _, found in sorted(by_norm.items())
        if len({lab for lab, _ in found}) > 1
    ]
    _write_jsonl(out / "label-overlaps.jsonl", overlaps)

    def counts(items: Iterable[Entry | dict]) -> dict[str, int]:
        labels = Counter(i["label"] if isinstance(i, dict) else i.label for i in items)
        return dict(sorted(labels.items()))

    summary = {
        "seed": config["seed"],
        "max_per_type": config["max_per_type"],
        "test_share": config["test_share"],
        "commits": {n: s["commit"] for n, s in config["repositories"].items()},
        "downloads": {n: s["sha256"] for n, s in config["downloads"].items()},
        "lines_left_out": dict(sorted(left_out.items())),
        "entries_read": counts(raw),
        "duplicates_removed": duplicates,
        "after_duplicates": counts(unique),
        "after_sampling": counts(chosen),
        "tuning": counts(rows["tuning"]),
        "test": counts(rows["test"]),
        "test_by_source": dict(sorted(Counter(f"{r['label']}/{r['source']}" for r in rows["test"]).items())),
        "label_overlaps": len(overlaps),
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8", newline="\n")

    licences = out / "LICENSES"
    licences.mkdir(exist_ok=True)
    for name, spec in config["repositories"].items():
        if "license_file" in spec:
            shutil.copyfile(roots[name] / spec["license_file"], licences / f"{name}.LICENSE")

    sums = [f"{_sha256(out / name)}  {name}" for name in OUTPUTS]
    sums.append(f"{_sha256(REPO / config['harmless']['tricky']['file'])}  harmless/tricky.txt")
    (out / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8", newline="\n")
    return summary


def _write_jsonl(path: Path, items: Iterable[dict]) -> None:
    # ensure_ascii keeps every file plain ASCII: no look-alike or invisible characters
    # can hide in it, and any tool shows the escapes instead of rendering the text.
    lines = [json.dumps(item, ensure_ascii=True, sort_keys=True) for item in items]
    path.write_text("".join(line + "\n" for line in lines), encoding="ascii", newline="\n")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="rebuild and compare with the repo")
    args = parser.parse_args(argv)
    config = tomllib.loads(CONFIG.read_text(encoding="utf-8"))
    if not args.check:
        summary = build(config, DATASET, CACHE)
        print(json.dumps({"tuning": summary["tuning"], "test": summary["test"]}, indent=2))
        return 0
    with tempfile.TemporaryDirectory() as scratch:
        build(config, Path(scratch), CACHE)
        fresh = (Path(scratch) / "SHA256SUMS").read_text(encoding="utf-8")
    same = fresh == (DATASET / "SHA256SUMS").read_text(encoding="utf-8")
    print("the committed datasets match a fresh build" if same else "the datasets differ from a fresh build")
    return 0 if same else 1


if __name__ == "__main__":
    sys.exit(main())
