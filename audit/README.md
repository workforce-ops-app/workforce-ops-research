# Audit tools

**In short:** the tools for the final audits, ready to run against a local copy: the outside-attacker audit (workforce-ops-app/workforce-ops-backend#119) and the frontend audit (workforce-ops-app/workforce-ops-frontend#62). They scan and record; both teammates judge the results and file the findings together ([decision 0030](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0030-security-study-method.md)).

The checklists for each audit are in the code repositories, next to the earlier audit: backend `docs/security/audit-external.md` (#119) and frontend `docs/security/audit-final.md` (#62).

## What is here

| File | What it does |
|---|---|
| [`check_signed_out.py`](check_signed_out.py) | sends every operation in the API's OpenAPI document once with no session and writes what each answered; anything but a 401 (outside the four public operations) is marked "look" |
| [`run_zap.sh`](run_zap.sh) | OWASP ZAP, pinned by digest: `baseline` (passive scan of the pages) or `api` (active scan of every operation from the OpenAPI document) |
| [`run_sqlmap.sh`](run_sqlmap.sh) | sqlmap, pinned in [`requirements.txt`](requirements.txt), on the endpoints that need no account: sign-in, redeeming a link, and (optionally) company sign-up |
| [`xss-inputs.txt`](xss-inputs.txt) | inputs to type into every text field of every screen, with their sources |

Burp Suite Community is used by hand (intercepting and changing requests); it has no script here. Save its project file and any notes in the same run folder as the other tools.

## 1. Start the local copy

Audit the combined code of every open pull request: the `review/integration` branch of both code repositories (it is rebuilt automatically from `main` and every open PR). Write down both commits; every result must name them.

```
cd workforce-ops-backend
git fetch && git switch --detach origin/review/integration
docker compose down --volumes            # deletes local data
docker compose up -d --build
docker compose run --rm migrate
DEMO_PASSWORD='<choose one>' python -m scripts.seed_demo

cd ../workforce-ops-frontend
git fetch && git switch --detach origin/review/integration
docker compose up -d --build             # the pages and /api at http://localhost:8080
```

- The backend must run with `APP_ENV=development` (the default in `.env.example`), so `/api/openapi.json` exists. The audit is about the code, not the hosting; the hosting items stay deferred as in the midterm audit.
- **Security events:** the detection layer records what the tools send. Leave it on. The field set of the detection study (research #8) is built from these events, matched to each run's times in its `run.json`.
- **Origin:** with `APP_ORIGIN` unset (as in `.env.example`), the API accepts the Origin of the address a request was sent to. ZAP runs in a container and reaches the copy at `host.docker.internal:8080`, so its `ORIGIN` is that address; the Python script and sqlmap run on this computer and use `localhost:8080`.
- **Rate limits are left on,** as an attacker meets them. The sqlmap script slows down to fit them; ZAP will see many 429 answers on sign-in, which is itself a result (threat D1).

## 2. Run the tools

From this repository, with the local copy running. Set `BACKEND_DIR` and `FRONTEND_DIR` to the two checkouts, so each `run.json` names the commits:

```
export BACKEND_DIR=../workforce-ops-backend FRONTEND_DIR=../workforce-ops-frontend
python audit/check_signed_out.py http://localhost:8080 results/audit/$(date -u +%Y%m%dT%H%M%SZ)-signed-out
audit/run_zap.sh baseline
audit/run_zap.sh api                                   # as an outsider meets it: POSTs stop at the Origin check
ORIGIN=http://host.docker.internal:8080 audit/run_zap.sh api   # past the Origin check, into the session and input checks
python -m pip install -r audit/requirements.txt
audit/run_sqlmap.sh
```

Each run writes a new folder under `results/audit/` named by its start time (UTC), with the tool's own reports and `run.json`. Commit them as they are (results are never edited by hand).

## 3. Judge and file

1. Go through each report together. For each alert or "look" row, decide: a finding, expected behavior (say why), or a false alarm (say why). Write the decision in the audit's checklist in the code repository, next to the threat or requirement it belongs to.
2. File each finding with the security-finding issue template. A finding that could reach another company's data or act without permission goes to a private security advisory first ([security policy](https://github.com/workforce-ops-app/.github/blob/main/SECURITY.md)).
3. Once fixed, the finding enters the findings log with its tool, vulnerability, fix, regression test, threat ID, and attacker profile; `results/findings/` holds the export the report cites (RQ2 b, RQ3).

## Rules

- **Local copies only.** Every script refuses any target other than this computer before sending anything.
- **No data-changing injection:** sqlmap runs at `--risk 1`.
- Never point these tools at anyone else's system, including the hosted services the project uses.
