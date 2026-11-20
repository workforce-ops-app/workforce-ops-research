#!/usr/bin/env bash
# OWASP ZAP against the local copy, as an outside attacker with no account (profile P1).
#
# Usage:  audit/run_zap.sh <baseline|api> [target]     (target defaults to the local frontend)
#
#   baseline  spiders the pages and reports what it sees without attacking (passive scan)
#   api       reads the API's OpenAPI document and attacks every operation (active scan)
#
# Output: results/audit/<UTC time>-zap-<mode>/ with ZAP's HTML, JSON, and Markdown reports
# and run.json (start and end time, image, the commits scanned) for the detection field
# set (research #8). Set BACKEND_DIR and FRONTEND_DIR to the checkouts that are running, so
# run.json names their commits.
set -euo pipefail

# The ZAP image, pinned by digest (zaproxy/zap-stable as of 2026-11-19), so every run uses
# the same scanner and its rules. To update: docker buildx imagetools inspect
# zaproxy/zap-stable, then change the digest here and in audit/README.md together.
IMAGE="zaproxy/zap-stable@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af"

mode="${1:-}"
# From inside the ZAP container, the computer running Docker is host.docker.internal.
target="${2:-http://host.docker.internal:8080}"

# 1. Local copies only (decision 0030): refuse any other host before anything runs.
case "$target" in
  http://localhost:*|http://127.0.0.1:*|http://host.docker.internal:*) ;;
  *) echo "only a local copy may be scanned, not $target" >&2; exit 2 ;;
esac
case "$mode" in
  baseline|api) ;;
  *) echo "usage: audit/run_zap.sh <baseline|api> [target]" >&2; exit 2 ;;
esac

here="$(cd "$(dirname "$0")/.." && pwd)"
out="$here/results/audit/$(date -u +%Y%m%dT%H%M%SZ)-zap-$mode"
mkdir -p "$out"
started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# 2. The API refuses changing requests whose Origin is not the application's own page
#    (forged-request check). ZAP sends none, so by default its POSTs stop there, which is
#    what a real outside attacker meets. ORIGIN=http://host.docker.internal:8080 (the
#    address ZAP sends to, which the API compares the Origin with when APP_ORIGIN is unset)
#    adds that header to every request, so the attacks also reach the checks behind it.
extra=()
if [ -n "${ORIGIN:-}" ]; then
  extra=(-z "-config replacer.full_list(0).description=origin \
-config replacer.full_list(0).enabled=true \
-config replacer.full_list(0).matchtype=REQ_HEADER \
-config replacer.full_list(0).matchstr=Origin \
-config replacer.full_list(0).regex=false \
-config replacer.full_list(0).replacement=$ORIGIN")
fi

# 3. Run. ZAP's exit code says whether it found warnings; the reports are what matter,
#    so a non-zero code does not stop the script before run.json is written.
set +e
if [ "$mode" = baseline ]; then
  docker run --rm -v "$out:/zap/wrk:rw" "$IMAGE" zap-baseline.py \
    -t "$target/pages/sign-in.html" -J zap.json -r zap.html -w zap.md "${extra[@]}"
else
  docker run --rm -v "$out:/zap/wrk:rw" "$IMAGE" zap-api-scan.py \
    -t "$target/api/openapi.json" -f openapi -J zap.json -r zap.html -w zap.md "${extra[@]}"
fi
code=$?
set -e

# 4. What was run, when, and against which commits.
commit() { if [ -n "${1:-}" ]; then git -C "$1" rev-parse HEAD; else echo unknown; fi; }
cat > "$out/run.json" <<JSON
{
  "tool": "zap-$mode",
  "image": "$IMAGE",
  "target": "$target",
  "origin_header": "${ORIGIN:-}",
  "started": "$started",
  "finished": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "zap_exit_code": $code,
  "backend_commit": "$(commit "${BACKEND_DIR:-}")",
  "frontend_commit": "$(commit "${FRONTEND_DIR:-}")"
}
JSON
echo "ZAP $mode finished (exit $code); reports in $out"
