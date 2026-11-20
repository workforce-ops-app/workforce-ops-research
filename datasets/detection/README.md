# Detection datasets (RQ1)

**In short:** the attack and harmless input for the detection study, already split into a tuning set and a test set. The split was fixed and committed before any pattern was tuned. **Nobody reads `test.jsonl` while writing or tuning patterns.** The rules come from the backend's [detection design](https://github.com/workforce-ops-app/workforce-ops-backend/blob/main/docs/features/detection.md#data-and-how-it-is-chosen) (slice DS1, research #6).

## Files

| File | What it holds |
|---|---|
| `tuning.jsonl` | 60% of each label and source: the only data used to write and tune patterns |
| `test.jsonl` | the other 40%: scored once, with the tagged detector (DS3), never read before |
| `summary.json` | the seed, commits, and counts at every step (written by the build) |
| `label-overlaps.jsonl` | texts that are the same after normalization under two labels (recorded, not fixed) |
| `sources.toml` | every source, pinned commit, included file, and excluded file with its reason |
| `harmless/tricky.txt` | the tricky harmless input, written by the team |
| `LICENSES/` | the licences of the outside sources, kept with the data |
| `SHA256SUMS` | the SHA-256 checksum of each data file |

Each line of a `.jsonl` file is one entry: `id`, `label` (an attack type or `harmless`), `source`, `file` and `line` (where it came from), and `text` (exactly as written there). The files are JSON Lines with every non-ASCII character escaped, so no tool renders the text and nothing invisible can hide in it. They are not CSV on purpose: a spreadsheet would run entries that start with `=` as formulas.

## Sources

| Source | Version | Licence | Used for |
|---|---|---|---|
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | commit `08ea40e77db3f42ef8f20c65196f3936a19b6c86` (2026-10-30) | MIT (`LICENSES/PayloadsAllTheThings.LICENSE`) | attack input |
| [SecLists](https://github.com/danielmiessler/SecLists) | commit `dbfb830d95e4f3da4fb7d7d277ed597de0ed7a18` (2026-11-12) | MIT (`LICENSES/SecLists.LICENSE`) | attack input |
| [workforce-ops-backend](https://github.com/workforce-ops-app/workforce-ops-backend) | commit `1ca970c4cf77765dae45a06e7d056067dfefc0d0` (where the detector, #134, merged) | the team's own | demo data text, and the normalization |
| [2010 Census surnames](https://www.census.gov/topics/population/genealogy/data/2010_surnames.html) | `names.zip`, SHA-256 in `sources.toml` | public domain (`LICENSES/census-surnames.NOTICE`) | ordinary harmless input |

Both collections were agreed at the design review: they are widely used, public, and already labelled by attack type through their folders. The label of an entry is the type of the folder or file it came from, as listed in `sources.toml`.

## Labels and files used

| Label | PayloadsAllTheThings | SecLists |
|---|---|---|
| `sql_injection` | `SQL Injection/Intruder/` | `Fuzzing/Databases/SQLi/`, `Fuzzing/Databases/*.fuzzdb.txt`, `Fuzzing/login_bypass.txt` |
| `xss` | `XSS Injection/Intruders/` | `Fuzzing/XSS/robot-friendly/`, `Fuzzing/XSS/Polyglots/`, `Fuzzing/HTML5sec-Injections-Jhaddix.txt`, `Fuzzing/URI-XSS.fuzzdb.txt` |
| `path_traversal` | `Directory Traversal/Intruder/`, `File Inclusion/Intruders/` | `Fuzzing/LFI/` |
| `command_injection` | `Command Injection/Intruder/` | `Fuzzing/command-injection-commix.txt` |
| `format_string` | `Server Side Template Injection/Intruder/` | `Fuzzing/FormatString-Jhaddix.txt`, `Fuzzing/template-engines-expression.txt`, `Fuzzing/template-engines-identification.txt` |

Harmless input has three sources: `harmless/tricky.txt` (source `team`), the demo data's text fields (source `demo`, from the backend's `scripts/seed_demo.py`), and the 2,500 most common census surnames (source `census`). The demo data file is read with Python's `ast` module, never imported or run. Its fields are the ones a person types: company names, time zones, email domains, people's names and email addresses, department and team names, and each shift's details, notes, and event text.

## Excluded files (rule 1)

| File | Why |
|---|---|
| SecLists `Fuzzing/Databases/SQLi/NoSQL.txt` | NoSQL (MongoDB) injection: another query language, not one of the five types |
| SecLists `Fuzzing/Databases/OracleDB-SID.txt` | Oracle database names to guess, not injection input |
| PayloadsAllTheThings `XSS Injection/Files/` | whole files to upload (SVG, SWF, XML, notebooks): a different setting from a form field |
| SecLists `Fuzzing/XSS/human-friendly/` | the same payloads as `robot-friendly`, written for people (comments, XML wrappers) |
| PayloadsAllTheThings `File Inclusion/Intruders/php-filter-iconv.txt` | fragments of PHP filter chains, harmless on their own |
| PayloadsAllTheThings `File Inclusion/Files/` | exploit scripts, not input (never run) |
| SecLists `Fuzzing/template-engines-special-vars.txt` | variable names to try after a template injection is found, not attacks on their own |
| SecLists `Fuzzing/SSI-Injection-Jhaddix.txt` | server-side includes: another attack type |
| SecLists `Fuzzing/UnixAttacks.fuzzdb.txt`, `Windows-Attacks.fuzzdb.txt`, `Metacharacters.fuzzdb.txt` | mixed attack types in one file with no label per line |

Inside the files used, a line is left out when it is empty (145 lines), the file's own comment (42: lines starting with `# `, and the `#Site.com:` headings in `jsonp_endpoint.txt`), not UTF-8 text (2), or binary data with raw control characters (4). Every other line is kept exactly, including leading and trailing spaces, which can be part of an attack.

## How the entries were chosen

1. **Every entry** of the files above (rule 1).
2. **Duplicates removed after normalization** (rule 2): within each label, entries equal after the detector's normalization keep only the first (by source, file, and line). Entries that normalize to nothing (`%20`, `/**/`) are dropped. The normalization is the backend's own `app/detection/normalize.py`, copied byte for byte into `scripts/vendor/backend_normalize.py`; a test checks its checksum against the backend's file at the pinned commit.
3. **At most 1,000 per type** (rule 3): a larger type is sampled with a generator seeded by the seed and the type's name, so one type's sample never changes when another changes. Harmless input is not sampled.
4. **Near-duplicates stay together** (rule 2): entries equal after normalization and removing digits and whitespace form one group, across all labels, and a group goes wholly to tuning or wholly to test.
5. **The 60/40 split** is stratified by label and source: each group belongs to the label and source of its first entry, and each label and source gets 40% of its entries in the test set. Seed: `20261112`.

| Label | Read | After duplicates | After sampling | Tuning | Test | Test target (rule 4) |
|---|---|---|---|---|---|---|
| `sql_injection` | 3,190 | 2,505 | 1,000 | 600 | 400 | 300, met |
| `xss` | 19,392 | 9,503 | 1,000 | 600 | 400 | 300, met |
| `path_traversal` | 57,943 | 39,165 | 1,000 | 600 | 400 | 300, met |
| `command_injection` | 8,793 | 8,748 | 1,000 | 599 | 401 | 300, met |
| `format_string` | 217 | 201 | 201 | 117 | 84 | 300, **not met** |
| `harmless` | 2,873 | 2,869 | 2,869 | 1,722 | 1,147 | 1,000, met |

Test entries by source: `sql_injection` 216 from PayloadsAllTheThings and 184 from SecLists; `xss` 80 and 320; `path_traversal` 164 and 236; `command_injection` 22 and 379; `format_string` 43 and 41; `harmless` 124 team, 23 demo, and 1,000 census.

## Known limits (for the report)

- **`format_string` falls short of the target:** the pinned collections hold only 201 distinct entries, so its test set has 84 and its confidence intervals will be wider (about 10 percentage points). The report states this rather than adding entries from another source after the fact.
- **The sample follows the collections' sizes:** most `command_injection` entries come from the commix list in SecLists, and most `path_traversal` entries are plain file paths. The split keeps each source's share the same in both sets, and the report gives results per source where they differ.
- **Three texts appear under two labels** (`""`, `&`, `|`: in the team's harmless set and in SQL injection lists). They are listed in `label-overlaps.jsonl` and left as they are; each pair is in the same set.
- **Most harmless test entries are surnames.** The team's tricky set (124 test entries) is the hard part, so the report gives the false alarm rate for each harmless source.

## Rules for using these files

- **Do not read `test.jsonl` while writing or tuning patterns**, and do not run a pattern against it until the detector is tagged (for example `detector-v1`). It is scored once (DS3); a later change is a new version with its own score.
- **The tricky harmless set is fixed before tuning starts.** It is written by the team and reviewed by both teammates before any pattern is tuned; once tuning starts it is not changed.
- **The entries are attack strings: data only.** Never run them, paste them into a page, or serve them to a browser. Nothing in this repository publishes `datasets/` (there is no GitHub Pages site, and the report includes no dataset file).
- **The files are never edited by hand.** Change `sources.toml` or `harmless/tricky.txt`, run the build, and commit what it writes.

## Rebuilding

```
python -m scripts.build_detection_datasets           # fetch, select, split, write
python -m scripts.build_detection_datasets --check   # rebuild and compare with the committed files
```

The build needs Git and network access. It fetches each repository at its pinned commit (sparse, only the folders used) and the census file, which it refuses unless the checksum matches, into `.cache/` (ignored by Git). The same commits, seed, and rules always give the same files; `--check` confirms it through `SHA256SUMS`.

On Windows, antivirus software may block some attack files in `.cache/` while the build reads them. Building in a Linux container avoids that:

```
docker run --rm -v "$PWD:/src:ro" python:3.13 sh -c "cp -r /src /w && cd /w && python -m scripts.build_detection_datasets --check"
```
