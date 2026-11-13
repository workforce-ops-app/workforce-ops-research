# Scripts

**In short:** the analysis scripts that turn the datasets into the report's results.

## Conventions

- **One script per result.** A script reads from `datasets/`, writes to `results/`, and prints the command that reproduces it.
- **Repeatable.** The same input gives the same output: fixed random seeds, sorted output, no network access while scoring.
- **Commented step by step**, so either teammate can explain any line.
- **Tested.** Scoring code (precision, recall, F1, confusion matrix) has unit tests in `tests/`, because a counting mistake would change every number in the report.

## Scripts

| Script | What it does |
|---|---|
| [`build_detection_datasets.py`](build_detection_datasets.py) | fetches the attack collections at pinned commits, applies the selection rules, and writes the fixed tuning/test split with checksums ([datasets/detection](../datasets/detection/README.md)) |
| [`vendor/backend_normalize.py`](vendor/backend_normalize.py) | the backend detector's normalization, copied byte for byte at a pinned commit (a test checks its checksum); never edit it here |
