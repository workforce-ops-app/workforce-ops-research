# Datasets

**In short:** every input the study uses, with enough detail to fetch it again and to judge whether its selection was fair.

## What each dataset records

Each dataset gets its own folder with a `README.md` stating:

| Item | Why it is needed |
|---|---|
| Source and version (URL, commit or release, date downloaded) | so the same file can be fetched again |
| License | so it may be republished here |
| Why it was chosen, and what was left out | selection bias is the first thing a reviewer checks |
| Label scheme (attack type, or benign) | so precision and recall mean the same thing for every set |
| How it was split into tuning and test sets | patterns tuned on the test set would score unfairly well |
| SHA-256 checksum of each file | so a changed file is noticed |

## Planned datasets

Set by the detection study design (workforce-ops-app/workforce-ops-backend#115).

| Folder | Contents | Status |
|---|---|---|
| `detection/` | public attack collections and tricky benign input for RQ1 | waiting on the design |
