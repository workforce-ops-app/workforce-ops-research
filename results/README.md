# Results

**In short:** the outputs the report cites, each traceable to the script, the dataset, and the commit that produced it.

## Planned results

| Folder | Contents | Research question |
|---|---|---|
| [`detection/`](detection/README.md) | precision, recall, and F1 per attack type with 95% intervals, confusion matrix, false alarms, timing | RQ1 |
| `audit/` | raw output of each audit tool run (`audit/`), one folder per run named by its start time, each with `run.json` naming the tool, times, and commits scanned | RQ2 (b), RQ3; the detection field set (RQ1) |
| `findings/` | the findings log exported from the audits: tool, vulnerability, fix, regression test, attacker profile, component, severity | RQ2 (b), RQ3 |
| `recovery/` | restore drill times from the backup and restore runbook | supporting evidence |

Each results file starts with a header naming the script, the dataset checksums, and the commit.
