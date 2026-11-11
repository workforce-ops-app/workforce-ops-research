# Report

**In short:** the research report in LaTeX, using the official IEEE conference class (`IEEEtran`). CI builds the PDF on every pull request and fails if it is longer than 10 pages, so the page count is known all along, not only at the end. What each section must contain is set by the [report plan](https://github.com/workforce-ops-app/.github/blob/main/docs/project/report-plan.md).

## Layout

| File | What it holds |
|---|---|
| `main.tex` | title, authors, and the order of the sections |
| `sections/<name>.tex` | one file per section, so the two of us can edit different sections at the same time |
| `references.bib` | the references; only cited entries appear in the PDF |
| `check_pages.py` | after a build: the page count against the limit, and how many to-do markers remain |

## Writing

- Text still to be written is marked `\pending{what is missing}`. It prints in red, and `check_pages.py` counts what is left.
- Every number comes from a file in `results/` or `notes/`; never type one in from memory.
- Write only finished work in the past tense. Work that has not happened yet (audits, the detector, the test split) is written as planned, with a `\pending` marker to switch it to the past tense once it is done, so the draft never claims something we have not done.
- Cite with `\cite{key}`, using the keys in `references.bib`.
- Keep claims in proportion to the evidence, and answer each research question exactly as asked (report plan, quality check).

## Building

With Docker (the same image CI uses), from the repository root:

```sh
docker run --rm -v "$PWD/report:/doc" -w /doc texlive/texlive:latest@sha256:07e8062637249c4f780ca59f42cc2ed592bc2dc1db4320769406aee3f98aa70e latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex
python report/check_pages.py
```

On Windows Git Bash, put `MSYS_NO_PATHCONV=1` in front of `docker` so the paths are not rewritten. The first run downloads the TeX Live image (several gigabytes). The image is pinned by digest so CI and local builds use the same LaTeX; `ci.toml` says how to update it. Overleaf also opens this folder if you prefer an online editor: upload `report/` as a project.

## Before submitting

1. No `\pending` markers left (`check_pages.py` prints 0).
2. Each teammate has written a critique (summary, three strengths, three weaknesses) and its weaknesses are fixed.
3. The PDF is named `Secure Workforce Operations ProjReport.pdf`, and each teammate submits their own copy.
