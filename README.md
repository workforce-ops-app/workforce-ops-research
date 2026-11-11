# Workforce Operations Research

**In short:** the replication package for the security research report on the [Workforce Operations Application](https://github.com/workforce-ops-app). It holds the datasets, analysis scripts, results, and notes behind every number in the report, so anyone can check or repeat the study. The method is set by [decision 0030](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0030-security-study-method.md) and the sections by the [report plan](https://github.com/workforce-ops-app/.github/blob/main/docs/project/report-plan.md).

## Research questions

| # | Question | Where the evidence is |
|---|---|---|
| RQ1 | What types of attacks can pattern-based (regular expression) inspection of input detect reliably? | `datasets/detection/`, `scripts/`, `results/detection/` |
| RQ2 | Are internal or external threats more common? | (a) published breach data in `notes/`; (b) audit findings by attacker profile in `results/findings/` |
| RQ3 | What part of the system is the most vulnerable? | `results/findings/`, grouped by component and severity |

## Layout

| Folder | What it holds |
|---|---|
| [`datasets/`](datasets/README.md) | Input data, each with where it came from, why it was chosen, its license, and a checksum |
| [`scripts/`](scripts/README.md) | Analysis scripts that turn datasets into results |
| [`results/`](results/README.md) | Outputs of the scripts and the audit findings, exactly as the report cites them |
| [`notes/`](notes/README.md) | Literature and published-data notes with citations |
| [`report/`](report/README.md) | The report itself, in LaTeX with the IEEE conference class; CI builds the PDF and checks the page limit |

## Repeating the study

Each results file names the script, the dataset, and the commit that produced it. To repeat a result, check out that commit and run the command in the results folder's README. Scripts use Python 3.13 and only the packages pinned in this repository.

## Rules for this repository

- **No real personal data.** Datasets are public attack collections, published reports, or synthetic input written by the team. Audit evidence comes from local test copies only (decision 0030).
- **No working exploits against anyone else's systems.** Attack strings are kept as test input for the detector, not as tools.
- **Selection is written down before scoring.** A dataset's README states how it was chosen and split before any result uses it, because selection bias is the most common criticism of studies like this one.
- **Results are never edited by hand.** If a number is wrong, fix the script or the data and run it again.

## Contributing

The [contributor guide](https://github.com/workforce-ops-app/.github/tree/main/docs/contributing) applies here as in the other repositories: work starts from an issue, every change goes through a pull request, and the other teammate approves it.
