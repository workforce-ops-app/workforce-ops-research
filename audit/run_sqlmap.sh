#!/usr/bin/env bash
# sqlmap against the endpoints an outside attacker can reach with no account (profile P1).
#
# Usage:  audit/run_sqlmap.sh [target]     (target defaults to the local frontend)
# Needs:  python -m pip install -r audit/requirements.txt   (sqlmap, pinned)
#
# Every other endpoint answers 401 without a session (audit/check_signed_out.py checks
# that), so it cannot be injected from outside; the signed-in attacker profiles are other
# audits.
#
# Output: results/audit/<UTC time>-sqlmap/ with sqlmap's own folders and run.json (times,
# version, the commits scanned) for the detection field set (research #8). Set BACKEND_DIR
# and FRONTEND_DIR to the checkouts that are running, so run.json names their commits.
set -euo pipefail

target="${1:-http://localhost:8080}"

# 1. Local copies only (decision 0030).
case "$target" in
  http://localhost:*|http://127.0.0.1:*) ;;
  *) echo "only a local copy may be scanned, not $target" >&2; exit 2 ;;
esac

here="$(cd "$(dirname "$0")/.." && pwd)"
out="$here/results/audit/$(date -u +%Y%m%dT%H%M%SZ)-sqlmap"
mkdir -p "$out"
started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# 2. Settings shared by every run:
#    - the Origin header of the application's own page, so requests get past the
#      forged-request check and reach the input handling;
#    - --risk 1 only (no statements that change data) and --level 3 (more places tried);
#    - --delay 3: sign-in and link redeeming share a limit of 20 a minute per address, so
#      one request every 3 seconds stays under it. Faster runs would mostly see 429s.
common=(--batch --level 3 --risk 1 --delay 3 --flush-session --output-dir "$out"
  --headers "Origin: $target" --headers "Content-Type: application/json")

# 3. One run per public endpoint. The * marks where sqlmap injects.
set +e
sqlmap "${common[@]}" -u "$target/api/sessions" --method POST \
  --data '{"email":"someone@example.com*","password":"a long wrong password*"}'
sqlmap "${common[@]}" -u "$target/api/password-links/redeem" --method POST \
  --data '{"token":"not-a-real-token*","password":"a long new password for this*"}'
# Company sign-up allows 5 requests an hour per address, so a sqlmap run there would only
# see 429s. SIGN_UP=1 runs it anyway (for example after restarting the API, which empties
# its counters), with a delay that fits the limit; expect it to take hours.
if [ -n "${SIGN_UP:-}" ]; then
  sqlmap --batch --level 1 --risk 1 --delay 720 --flush-session --output-dir "$out" \
    --headers "Origin: $target" --headers "Content-Type: application/json" \
    -u "$target/api/sign-up" --method POST \
    --data '{"company_name":"Audit Probe*","timezone":"UTC","display_name":"Probe*","email":"probe@audit.example*","password":"lanterns drift over quiet waters"}'
fi
set -e

# 4. What was run, when, and against which commits.
commit() { if [ -n "${1:-}" ]; then git -C "$1" rev-parse HEAD; else echo unknown; fi; }
cat > "$out/run.json" <<JSON
{
  "tool": "sqlmap",
  "version": "$(sqlmap --version 2>/dev/null | tail -1)",
  "target": "$target",
  "sign_up_included": "${SIGN_UP:-}",
  "started": "$started",
  "finished": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "backend_commit": "$(commit "${BACKEND_DIR:-}")",
  "frontend_commit": "$(commit "${FRONTEND_DIR:-}")"
}
JSON
echo "sqlmap finished; output in $out"
