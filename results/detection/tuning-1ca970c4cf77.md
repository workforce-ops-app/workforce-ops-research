# Detection scores: tuning split, detector 1ca970c4cf77765dae45a06e7d056067dfefc0d0

Made by `python -m scripts.score_detection --split tuning` from research commit `77a9dd1c626db49d3c320453634ab728eebb90c1` and backend commit `1ca970c4cf77765dae45a06e7d056067dfefc0d0`. Dataset checksums and the machine are in the JSON file next to this one.

A type is detected **reliably** when the lower ends of both 95% intervals are at least 90% (fixed before the test set is scored).

## Per attack type

| Type | Entries | Precision | 95% interval | Recall | 95% interval | F1 | Verdict |
|---|---|---|---|---|---|---|---|
| `sql_injection` | 600 | 98.8% | 96.9 to 99.5 | 53.5% | 49.5 to 57.5 | 69.4% | not reliable |
| `xss` | 600 | 99.4% | 98.3 to 99.8 | 87.7% | 84.8 to 90.1 | 93.2% | not reliable |
| `path_traversal` | 600 | 95.7% | 92.3 to 97.7 | 37.3% | 33.6 to 41.3 | 53.7% | not reliable |
| `command_injection` | 599 | 99.3% | 98.2 to 99.7 | 96.2% | 94.3 to 97.4 | 97.7% | reliable |
| `format_string` | 117 | 27.5% | 22.8 to 32.7 | 71.8% | 63.0 to 79.2 | 39.7% | not reliable |

## Recall by source

| Type | Source | Flagged | Entries | Recall |
|---|---|---|---|---|
| `sql_injection` | PayloadsAllTheThings | 213 | 323 | 65.9% |
| `sql_injection` | SecLists | 108 | 277 | 39.0% |
| `xss` | PayloadsAllTheThings | 87 | 120 | 72.5% |
| `xss` | SecLists | 439 | 480 | 91.5% |
| `path_traversal` | PayloadsAllTheThings | 53 | 245 | 21.6% |
| `path_traversal` | SecLists | 171 | 355 | 48.2% |
| `command_injection` | PayloadsAllTheThings | 9 | 32 | 28.1% |
| `command_injection` | SecLists | 567 | 567 | 100.0% |
| `format_string` | PayloadsAllTheThings | 55 | 64 | 85.9% |
| `format_string` | SecLists | 29 | 53 | 54.7% |

## Confusion matrix

Rows: the true label. Columns: the types flagged; an entry flagged as two types counts in both.

| True label | `sql_injection` | `xss` | `path_traversal` | `command_injection` | `format_string` | `none` |
|---|---|---|---|---|---|---|
| `sql_injection` | 321 | 0 | 1 | 2 | 0 | 277 |
| `xss` | 2 | 526 | 1 | 0 | 0 | 71 |
| `path_traversal` | 0 | 0 | 224 | 0 | 0 | 376 |
| `command_injection` | 1 | 2 | 4 | 576 | 217 | 16 |
| `format_string` | 0 | 0 | 3 | 2 | 84 | 32 |
| `harmless` | 1 | 1 | 1 | 0 | 5 | 1714 |

## False alarms on harmless input

| Input | Flagged | Entries | Rate | 95% interval |
|---|---|---|---|---|
| tricky (team) | 8 | 187 | 4.3% | 2.2 to 8.2 |
| ordinary (demo, census) | 0 | 1535 | 0.0% | 0.0 to 0.2 |
| source: census | 0 | 1500 | 0.0% | 0.0 to 0.3 |
| source: demo | 0 | 35 | 0.0% | 0.0 to 9.9 |
| source: team | 8 | 187 | 4.3% | 2.2 to 8.2 |

## Time per value

Each of the 4238 values matched 100 times, median kept; then the median and 99th percentile over the values, in microseconds.

| What | Median (µs) | 99th percentile (µs) |
|---|---|---|
| whole detector (with normalizing) | 36.0 | 399.1 |
| `SQLI-01` | 1.4 | 6.5 |
| `SQLI-02` | 2.0 | 21.3 |
| `SQLI-03` | 0.7 | 2.6 |
| `SQLI-04` | 1.4 | 6.7 |
| `SQLI-05` | 2.5 | 27.4 |
| `SQLI-06` | 2.5 | 26.9 |
| `XSS-01` | 0.7 | 2.4 |
| `XSS-02` | 1.0 | 4.9 |
| `XSS-03` | 2.3 | 22.7 |
| `XSS-04` | 0.7 | 2.2 |
| `XSS-05` | 2.5 | 22.2 |
| `PATH-01` | 2.3 | 17.8 |
| `PATH-02` | 4.1 | 59.1 |
| `PATH-03` | 0.7 | 4.1 |
| `CMD-01` | 1.2 | 4.8 |
| `CMD-02` | 4.1 | 46.5 |
| `CMD-03` | 0.7 | 2.5 |
| `FMT-01` | 0.7 | 2.2 |
| `FMT-02` | 0.7 | 13.8 |
| `FMT-03` | 0.7 | 1.9 |
| `FMT-04` | 1.3 | 6.4 |
