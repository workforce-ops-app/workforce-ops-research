# Detection scores (RQ1)

**In short:** the detector's scores on the detection datasets, written by [`scripts/score_detection.py`](../../scripts/score_detection.py) (slice DS2, research #7). Never edited by hand.

## Files

Each run writes two files named `<split>-<version>`:

| File | What it holds |
|---|---|
| `<split>-<version>.json` | the record: the command, both repositories' commits, the dataset checksums, the machine, and every count, measure, and time |
| `<split>-<version>.md` | the same numbers as tables, for reading |

The version is the detector's tag (`detector-v1`) or the first 12 characters of the backend commit. A run from a local backend checkout with uncommitted changes ends in `-dirty` and is never cited.

## Rules

- **Tuning split:** scored as often as tuning needs, with any backend commit or a local checkout (`--backend-path`).
- **Test split:** scored only with a `detector-v<N>` tag fetched from GitHub, and **once per tag**: the script refuses when `test-<tag>.json` already exists. A changed detector is a new tag with its own score, and the first score stays in the report.
- **Detector copy:** a fetched detector is cached in `.cache/`. Before it is imported, the script checks that its HEAD is the recorded commit and that no file differs from that commit (no changed, untracked, or ignored file). A copy that fails is fetched again once, and the run is refused if it still fails, so the commit in the result always names the code that was scored.
- **F1** is computed from the counts as 2TP / (2TP + FP + FN). A type with entries but no flags has no precision (nothing flagged) but F1 = 0; F1 is missing only when there is nothing to count.
- **"Reliably"** was agreed by both of us and fixed before the test set was scored (report methodology): a type is detected reliably when the lower ends of the 95% Wilson intervals of both its precision and its recall are at least 90%.
- **Times** come from the machine named in the JSON file and are only compared within one run.

## What is here

| File | Detector | Notes |
|---|---|---|
| `tuning-1ca970c4cf77` | backend commit `1ca970c` (#134), before any tuning | the starting point tuning is measured against; timed on a laptop with Docker running, so the times are only a first look |
