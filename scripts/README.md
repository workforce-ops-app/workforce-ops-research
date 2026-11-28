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
| [`score_detection.py`](score_detection.py) | scores the backend's detector on one split: precision, recall, F1 with Wilson 95% intervals, the confusion matrix, false alarms on harmless input, and time per value, written to [`results/detection/`](../results/detection/README.md). The test split only with a `detector-v<N>` tag, once per tag |
| [`vendor/backend_normalize.py`](vendor/backend_normalize.py) | the backend detector's normalization, copied byte for byte at a pinned commit (a test checks its checksum); never edit it here |
