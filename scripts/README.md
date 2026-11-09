# Scripts

**In short:** the analysis scripts that turn the datasets into the report's results.

## Conventions

- **One script per result.** A script reads from `datasets/`, writes to `results/`, and prints the command that reproduces it.
- **Repeatable.** The same input gives the same output: fixed random seeds, sorted output, no network access while scoring.
- **Commented step by step**, so either teammate can explain any line.
- **Tested.** Scoring code (precision, recall, F1, confusion matrix) has unit tests in `tests/`, because a counting mistake would change every number in the report.
