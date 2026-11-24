"""Send every API operation once with no session, as an outside attacker (profile P1) would,
and write down what each one answered.

Usage (the local copy must be running in development mode, so /api/openapi.json exists):

    python audit/check_signed_out.py http://localhost:8080 results/audit/<run folder>

What it does, step by step:
1. Refuses any target that is not this computer (decision 0030: local copies only).
2. Reads the list of operations from the API's own OpenAPI document, so a new endpoint
   is checked without changing this script.
3. Sends each one with no cookie. Path parameters get a random UUID; bodies are an empty
   JSON object. The Origin header is the target's own, so the request gets past the
   forged-request check and reaches the session check (without it, every POST would stop
   at the Origin check and the session check would never be tried).
4. Sorts each answer: "refused" (401, as expected), "public" (the operations meant for
   visitors with no account), or "look" (anything else: a person decides whether it is a
   finding). Writes a Markdown table and the raw answers as JSON.

It only reads answers; it never decides what is a finding. Both teammates judge the "look"
rows together during the audit (backend #119).
"""

import json
import sys
import urllib.error
import urllib.request
import uuid
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

# The operations meant for visitors with no account (backend docs: authentication,
# organization). Their answers are recorded but not expected to be 401.
PUBLIC = {
    ("GET", "/api/health"),
    ("POST", "/api/sessions"),
    ("POST", "/api/sign-up"),
    ("POST", "/api/password-links/redeem"),
}

# Hosts that are this computer. Anything else is refused before a request is sent.
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "host.docker.internal"}


def check_target(target: str) -> str:
    """The target without a trailing slash, or ValueError if it is not this computer."""
    parts = urlsplit(target)
    if parts.scheme not in ("http", "https") or parts.hostname not in LOCAL_HOSTS:
        raise ValueError(f"only a local copy may be scanned, not {target!r}")
    return target.rstrip("/")


def fill_path(path: str, value: str) -> str:
    """The path with every {parameter} replaced by the given value."""
    out, inside = [], False
    for char in path:
        if char == "{":
            inside = True
            out.append(value)
        elif char == "}":
            inside = False
        elif not inside:
            out.append(char)
    return "".join(out)


def classify(method: str, path: str, status: int) -> str:
    """refused, public, or look (a person checks it)."""
    if (method, path) in PUBLIC:
        return "public"
    return "refused" if status == 401 else "look"


def operations(document: dict) -> list[tuple[str, str]]:
    """Every (METHOD, path) in an OpenAPI document, sorted, so runs compare line by line."""
    found = []
    for path, ops in document.get("paths", {}).items():
        for method in ops:
            if method.lower() in ("get", "post", "put", "patch", "delete"):
                found.append((method.upper(), path))
    return sorted(found)


def send(target: str, method: str, path: str) -> tuple[int, str]:
    """Send one request with no cookie; return the status and the start of the body."""
    body = None if method in ("GET", "DELETE") else b"{}"
    request = urllib.request.Request(  # noqa: S310 (the target was checked to be local)
        target + path,
        data=body,
        method=method,
        headers={"Origin": target, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as answer:  # noqa: S310
            return answer.status, answer.read(300).decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read(300).decode("utf-8", "replace")


def main(target: str, out_dir: str) -> int:
    target = check_target(target)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    started = datetime.now(UTC).isoformat(timespec="seconds")

    # 2. The list of operations, from the API itself.
    with urllib.request.urlopen(target + "/api/openapi.json", timeout=30) as answer:  # noqa: S310
        document = json.load(answer)

    # 3 and 4. One request each, in a fixed order.
    rows = []
    for method, path in operations(document):
        status, start = send(target, method, fill_path(path, str(uuid.uuid4())))
        rows.append(
            {
                "method": method,
                "path": path,
                "status": status,
                "result": classify(method, path, status),
                "body_start": start,
            }
        )

    finished = datetime.now(UTC).isoformat(timespec="seconds")
    (out / "signed-out.json").write_text(
        json.dumps({"target": target, "started": started, "finished": finished, "rows": rows}, indent=2),
        encoding="utf-8",
    )
    lines = [
        "# Signed-out check",
        "",
        f"Target {target}, {started} to {finished} (UTC). Written by `audit/check_signed_out.py`.",
        "",
        "| Result | Method | Path | Status |",
        "|---|---|---|---|",
    ]
    lines += [f"| {r['result']} | {r['method']} | `{r['path']}` | {r['status']} |" for r in rows]
    (out / "signed-out.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    looks = sum(r["result"] == "look" for r in rows)
    print(f"{len(rows)} operations, {looks} to look at; written to {out}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))
