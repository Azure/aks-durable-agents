#!/usr/bin/env python3
"""Safe artifact collectors and bot-owned failure trackers for kind and AKS e2e workflows."""
import argparse
import importlib.util
import json
import math
import os
import re
import stat
import sys
import urllib.error
import urllib.request
from pathlib import Path

MAX_TOTAL, MAX_FILES, MAX_LOG, MAX_PROOF = 16 * 1024 * 1024, 256, 2 * 1024 * 1024, 256 * 1024
TITLE = "Kind e2e regression"
MARKER = "<!-- kind-e2e-tracking -->"
START, END = "<!-- kind-e2e-status:start -->", "<!-- kind-e2e-status:end -->"
PROOFS = ("proof.json", "network-proof.json", "timings.json")
RUN_URL = re.compile(r"https://github\.com/[\w.-]+/[\w.-]+/actions/runs/[0-9]+(/attempts/[0-9]+)?")
EVIDENCE = re.compile(r"Evidence: (/\S*/\.build/demo/[0-9a-f]{32})\s*$", re.MULTILINE)
SAFE_PHASE = re.compile(r"[A-Za-z0-9 ._:/(),;'-]{1,160}")
SUMMARY_RESERVE = 16 * 1024
AKS_TITLE = "AKS e2e regression"
AKS_MARKER = "<!-- aks-e2e-tracking -->"
AKS_START, AKS_END = "<!-- aks-e2e-status:start -->", "<!-- aks-e2e-status:end -->"
AKS_STAGES = ("config", "preflight", "substrate-inputs", "create", "wait", "federate", "scenario", "teardown", "finalize")
SUBSTRATE_EVIDENCE_RECOVERY = (
    "For unavailable, expired or mismatched Substrate image evidence: "
    "Re-run the Images run for the source pinned in PUBLISHED_IMAGES within GitHub\'s 30-day re-run window "
    "and wait for Verified image pins only if its current-main stale-source check still accepts that source. "
    "If only verification is missing, dispatch Verified image pins with that publish_run_id, subject to the same check. "
    "For a stale source or evidence too old to restore, publish and verify a reviewed replacement, then refresh "
    "the chart image pins, PUBLISHED_IMAGES and matching backup-helper receipt."
)


class ApiError(Exception):
    pass


def _number(v):
    return type(v) in (int, float) and math.isfinite(v) and v >= 0


def valid_proof(p):
    ones = ("publicationCount", "receiptCount", "artifacts", "realModelCalls", "modelHTTPCalls")
    zeros = ("provider_calls", "executor_calls", "fakeModelCalls")
    return (isinstance(p, dict) and p.get("completed") is True
            and all(type(p.get(k)) is int and p[k] == 1 for k in ones)
            and all(type(p.get(k)) is int and p[k] == 0 for k in zeros)
            and type(p.get("headSeq")) is int and p["headSeq"] > 0
            and isinstance(p.get("headHash"), str) and re.fullmatch(r"[0-9a-f]{64}", p["headHash"]) is not None
            and isinstance(p.get("session"), str) and p["session"] != "")


def valid_network(records):
    if not isinstance(records, list) or len(records) != 4:
        return False
    seen = set()
    for r in records:
        if not isinstance(r, dict) or set(r) != {"case", "stage", "address", "allowed", "expect", "tcpOnly"}:
            return False
        control = r["stage"] == "control"
        m = re.fullmatch(r"([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}):9000", r["address"]) if isinstance(r["address"], str) else None
        if (r["case"] not in ("host-egress", "harness-ingress") or r["stage"] not in ("control", "denial")
                or not m or any(int(g) > 255 for g in m.groups()) or r["tcpOnly"] is not True
                or r["allowed"] is not control or r["expect"] != ("allowed" if control else "denied")):
            return False
        seen.add((r["case"], r["stage"]))
    return len(seen) == 4


def valid_timings(t):
    return (isinstance(t, dict) and set(t) == {"elapsedSeconds", "phases"} and _number(t["elapsedSeconds"])
            and isinstance(t["phases"], list)
            and all(isinstance(p, dict) and set(p) == {"name", "seconds"} and isinstance(p["name"], str) and _number(p["seconds"]) for p in t["phases"]))


VALIDATORS = {"proof.json": valid_proof, "network-proof.json": valid_network, "timings.json": valid_timings}


def read_file(path, limit):
    """Read a regular file without following symlinks; returns (last `limit` bytes, original size)."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise OSError("not a regular file")
        if info.st_size > limit:
            os.lseek(fd, info.st_size - limit, os.SEEK_SET)
        with os.fdopen(os.dup(fd), "rb") as f:
            return f.read(limit), info.st_size
    finally:
        os.close(fd)


def find_evidence(workspace, console_text):
    """Return the demo evidence directory only if it is the real workspace/.build/demo/<uuid> without symlinks."""
    found = EVIDENCE.findall(console_text)
    if not found:
        return None
    path = Path(found[-1])
    root = Path(workspace).resolve()
    if path.parent != root / ".build/demo":
        return None
    for part in (root / ".build", root / ".build/demo", path):
        try:
            if not stat.S_ISDIR(os.lstat(part).st_mode):  # lstat: a symlink is not a directory
                return None
        except OSError:
            return None
    return path


def collect_aks(workspace, destination, summary, result, run_url, sha, stage, profile="aks"):
    # The kind path deliberately retains logs. Never call it for real-model runs.
    schema = {"aks": "proof.py", "aks-substrate": "substrate_proof.py"}[profile]
    spec = importlib.util.spec_from_file_location("aks_public_proof", Path(__file__).resolve().parents[1] / "aks" / schema)
    assert spec is not None and spec.loader is not None
    proof = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(proof)

    if (not RUN_URL.fullmatch(run_url) or (sha and not re.fullmatch(r"[0-9a-f]{40}", sha))
            or stage not in AKS_STAGES or result not in ("success", "failure", "cancelled")):
        raise ValueError("invalid AKS reporting metadata")
    dest = Path(destination)
    dest.mkdir(parents=True)
    valid = True
    for name in PROOFS:
        try:
            value = proof.load_public(workspace, name)
        except (OSError, ValueError, RecursionError):
            valid = False
            continue
        # Reserialize closed, validated fields; never retain untrusted raw bytes.
        (dest / name).write_text(json.dumps(value, sort_keys=True, allow_nan=False) + "\n")
    status = {"result": "success" if result == "success" and valid else "failed",
              "stage": stage, "runURL": run_url, "commitSHA": sha}
    text = ("# AKS e2e summary\n\n" + f"- Result: {status['result']}\n"
            + f"- Stage: {stage}\n- Run: {run_url}\n- Commit: {sha}\n")
    if result in ("failure", "cancelled"):
        try:
            diagnostics = proof.load_public(workspace, "diagnostics.json")
        except (OSError, ValueError, RecursionError):
            text += "- Diagnostics: unavailable\n"
        else:
            (dest / "diagnostics.json").write_text(json.dumps(diagnostics, sort_keys=True, allow_nan=False) + "\n")
            text += (f"- Scenario phase: {diagnostics['phase']}\n- Operation: {diagnostics['operation']}\n"
                     + f"- Reason: {diagnostics['reason']}\n- Source fencing: {diagnostics['cleanup']}\n")
            if profile == "aks-substrate" and diagnostics["phase"] == "install":
                try:
                    install = proof.load_public(workspace, "install-status.json")
                except (OSError, ValueError, RecursionError):
                    text += "- Install status: unavailable\n"
                else:
                    (dest / "install-status.json").write_text(json.dumps(install, sort_keys=True, allow_nan=False) + "\n")
                    listed = {key: ", ".join(install[key]) or "none" for key in ("eventReasons", "containerReasons", "containerStates")}
                    text += (f"- Install step: {install['failedStep']}\n"
                             + f"- Install resource: {install['resourceKind']}/{install['resourceName']}\n"
                             + f"- Event reasons: {listed['eventReasons']}\n- Container reasons: {listed['containerReasons']}\n"
                             + f"- Container states: {listed['containerStates']}\n"
                             + "- Exit codes: " + (", ".join(map(str, install["exitCodes"])) or "none") + "\n"
                             + f"- Install rollout: {install['rolloutStatus']}\n")
            rollout_kind = {"profile-rollout": "DaemonSet", "deployment-rollout": "Deployment"}.get(diagnostics["operation"])
            if rollout_kind is not None:
                try:
                    rollout = proof.load_public(workspace, "rollout-status.json")
                    if rollout["controllerKind"] not in (rollout_kind, "other"):
                        raise ValueError("mismatched AKS rollout controller")
                except (OSError, ValueError, RecursionError):
                    text += "- Rollout status: unavailable\n"
                else:
                    (dest / "rollout-status.json").write_text(json.dumps(rollout, sort_keys=True, allow_nan=False) + "\n")
                    counts = [str(rollout[key]) if rollout[key] is not None else "unknown"
                              for key in ("readyNodes", "desiredNodes")]
                    text += (f"- Controller: {rollout['controllerKind']}/{rollout['controllerName']}\n"
                             + "- Pod reasons: " + ", ".join(rollout["podReasons"]) + "\n"
                             + "- Ready/desired nodes: " + "/".join(counts) + "\n")
        text += "- Underlying cause: not determined\n"
    (dest / "status.json").write_text(json.dumps(status, sort_keys=True) + "\n")
    (dest / "summary.md").write_text(text)
    Path(summary).parent.mkdir(parents=True, exist_ok=True)
    Path(summary).write_text(text)
    return 1 if result == "success" and not valid else 0


def collect(workspace, console, destination, summary, result, run_url, profile="kind", sha="", stage="scenario"):
    if profile in ("aks", "aks-substrate"):
        return collect_aks(workspace, destination, summary, result, run_url, sha, stage, profile)
    if profile != "kind":
        raise ValueError("unknown reporting profile")
    if not RUN_URL.fullmatch(run_url):
        raise ValueError("run URL is not a canonical GitHub Actions run URL")
    dest = Path(destination)
    dest.mkdir(parents=True)  # fresh destination only: FileExistsError refuses reuse
    state: dict[str, int] = {"files": 1, "bytes": 0}  # one file slot is reserved for the summary
    notes = {"unsafe": 0, "omitted": 0, "truncated": 0, "skipped": 0}

    def put(name, data):
        (dest / name).write_bytes(data)
        state["files"] += 1
        state["bytes"] += len(data)

    try:
        raw, console_size = read_file(console, MAX_LOG)
    except OSError:
        raw, console_size = b"", 0
    evidence = find_evidence(workspace, raw.decode("utf-8", "replace"))
    status, parsed = {}, {}
    entries = []
    if evidence:
        with os.scandir(evidence) as it:
            entries = sorted(it, key=lambda e: e.name)
    # Proofs first so they always survive the caps.
    for name in PROOFS:
        entry = next((e for e in entries if e.name == name), None)
        if entry is None:
            status[name] = "missing"
            continue
        try:
            data, size = read_file(entry.path, MAX_PROOF)
            if size > MAX_PROOF:
                raise ValueError
            value = json.loads(data)
        except (OSError, ValueError):
            notes["unsafe"] += 1
            status[name] = "invalid"
            continue
        put(name, data)
        parsed[name] = value
        status[name] = "valid" if VALIDATORS[name](value) else "invalid"
    if raw:
        put("console.log", raw)
        notes["truncated"] += console_size > len(raw)
    logs = []
    for entry in entries:
        m = re.fullmatch(r"command-([0-9]{3,})\.log", entry.name)
        if m:
            logs.append((int(m.group(1)), entry))
        elif entry.name not in PROOFS:
            notes["omitted"] += 1
    for _, entry in sorted(logs, key=lambda x: x[0], reverse=True):  # newest failure logs matter most
        room = MAX_TOTAL - SUMMARY_RESERVE - state["bytes"]
        if state["files"] >= MAX_FILES or room <= 0:
            notes["skipped"] += 1
            continue
        try:
            data, size = read_file(entry.path, min(MAX_LOG, room))
        except OSError:
            notes["unsafe"] += 1
            continue
        notes["truncated"] += size > len(data)
        put(entry.name, data)
    ok = all(status.get(n) == "valid" for n in PROOFS)
    collector = "success proof invalid" if result == "success" and not ok else "ok"
    timings = parsed.get("timings.json") if status.get("timings.json") == "valid" else None
    lines = ["# Kind e2e demo summary", "", f"- Result: {result}", f"- Run: {run_url}",
             f"- Evidence directory: {'found' if evidence else 'not found'}", f"- Collector: {collector}"]
    lines += [f"- {n}: {status.get(n, 'missing')}" for n in PROOFS]
    if status.get("proof.json") == "valid":
        lines += ["- Provider/executor callbacks: 0/0", "- Model HTTP requests/publications/receipts/artifacts: 1/1/1/1"]
    if status.get("network-proof.json") == "valid":
        lines.append("- TCP policy controls/denials: 2/2 (effective policy, not drop attribution)")
    lines += ["- Replay follows demo-only sealing; this is not AKS, real identity or hostile-tenant qualification.",
              "- Cleanup: " + ("confirmed by demo" if "PASS: demo complete and owned cluster removed." in raw.decode("utf-8", "replace") else "not confirmed; inspect logs")]
    if timings:
        lines.append(f"- Elapsed seconds: {timings['elapsedSeconds']:.1f}")
        lines += [f"- Phase {p['name']}: {p['seconds']:.1f}s" for p in timings["phases"][:30] if SAFE_PHASE.fullmatch(p["name"])]
    lines += [f"- Files copied: {state['files'] - 1}", f"- Bytes copied: {state['bytes']}",
              (f"- Notes: {notes['unsafe']} unsafe entries skipped, {notes['omitted']} other files omitted, "
               f"{notes['truncated']} files truncated, {notes['skipped']} older command logs skipped")]
    Path(summary).parent.mkdir(parents=True, exist_ok=True)
    Path(summary).write_text("\n".join(lines) + "\n")
    (dest / "summary.md").write_text("\n".join(lines) + "\n")
    return 1 if collector != "ok" else 0


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


class GitHubAPI:
    """Minimal REST client: one attempt per call, token only in the header, bodies never surfaced."""

    def __init__(self, token, base="https://api.github.com"):
        self._token, self.base = token, base
        self._opener = urllib.request.build_opener(_NoRedirect)

    def request(self, method, path, payload=None):
        if not path.startswith("/repos/"):
            raise ApiError("refusing non-repository API path")
        data = None if payload is None else json.dumps(payload).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method, headers={
            "Authorization": "Bearer " + self._token, "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "kind-e2e-tracker", "Content-Type": "application/json"})
        try:
            with self._opener.open(req, timeout=30) as resp:
                body = resp.read()
            return json.loads(body) if body else {}
        except urllib.error.HTTPError as exc:
            raise ApiError(f"GitHub API {method} {path.split('?')[0]} failed: HTTP {exc.code}") from None
        except (OSError, ValueError) as exc:
            raise ApiError(f"GitHub API {method} {path.split('?')[0]} failed: {type(exc).__name__}") from None


def render_block(run_url, sha):
    return f"{START}\nStatus: failing\nLatest failing run: {run_url}\nCommit: {sha}\n{END}"


def find_tracker(api, repo, title=TITLE, marker=MARKER):
    """Exactly one github-actions[bot] tracker, filtered by author before counting; refuse incomplete lookups."""
    matches = []
    for page in range(1, 101):
        items = api.request("GET", f"/repos/{repo}/issues?state=all&sort=created&direction=asc&per_page=100&page={page}")
        if not isinstance(items, list):
            raise ApiError("unexpected issue listing response")
        for item in items:
            user = item.get("user") or {}
            if ("pull_request" not in item and item.get("title") == title and marker in (item.get("body") or "")
                    and user.get("login") == "github-actions[bot]" and user.get("type") == "Bot"):
                matches.append(item)
        if len(items) < 100:
            if len(matches) > 1:
                raise ApiError("multiple bot-authored tracking issues found")
            return matches[0] if matches else None
    raise ApiError("issue lookup incomplete after 100 pages")


def update_body(body, block, start=START, end=END):
    starts, ends = body.count(start), body.count(end)
    if starts == 0 and ends == 0:
        return body.rstrip("\n") + "\n\n" + block + "\n"
    if starts != 1 or ends != 1 or body.index(start) > body.index(end):
        raise ApiError("tracking issue has a malformed managed status block; refusing to overwrite")
    return body[:body.index(start)] + block + body[body.index(end) + len(end):]


def track(api, repo, run_id, sha, run_url, test=False, profile="kind", stage="scenario"):
    if profile not in ("kind", "aks") or (profile == "aks" and (stage not in AKS_STAGES or test)):
        raise ValueError("invalid AKS tracker profile, stage or test mode")
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or not re.fullmatch(rf"https://github\.com/{re.escape(repo)}/actions/runs/{int(run_id)}(/attempts/[0-9]+)?", run_url):
        raise ValueError("sha or run URL is not canonical for this run")
    base = f"/repos/{repo}/issues"
    if profile == "aks":
        issue = find_tracker(api, repo, AKS_TITLE, AKS_MARKER)
        recovery = "\n" + SUBSTRATE_EVIDENCE_RECOVERY if stage == "substrate-inputs" else ""
        block = f"{AKS_START}\nStage: {stage}\nWorkflow: {run_url}\nCommit: {sha}{recovery}\n{AKS_END}"
        if issue is None:
            issue = api.request("POST", base, {"title": AKS_TITLE, "body": f"{AKS_MARKER}\n\n{block}\n"})
        else:
            body = update_body(issue.get("body") or "", block, AKS_START, AKS_END)
            api.request("PATCH", f"{base}/{issue['number']}", {"body": body, "state": "open"})
        return f"https://github.com/{repo}/issues/{int(issue['number'])}"
    issue = find_tracker(api, repo)
    if test:
        if issue is None:
            block = f"{START}\nStatus: reporting permission check; no demo was run\n{END}"
            issue = api.request("POST", base, {"title": TITLE, "body": f"{MARKER}\n\nBot-owned tracker for failing nightly kind e2e runs.\n\n{block}\n"})
        number = issue["number"]
        api.request("POST", f"{base}/{number}/comments", {"body": "Test run: reporting permission check. No demo was run. " + run_url})
        api.request("PATCH", f"{base}/{number}", {"state": "closed"})
    elif issue is None:
        body = f"{MARKER}\n\nBot-owned tracker for failing nightly kind e2e runs. Text outside the status block is preserved.\n\n{render_block(run_url, sha)}\n"
        issue = api.request("POST", base, {"title": TITLE, "body": body})
    else:
        body = update_body(issue.get("body") or "", render_block(run_url, sha))  # validate before any write
        api.request("PATCH", f"{base}/{issue['number']}", {"body": body, "state": "open"})
    return f"https://github.com/{repo}/issues/{int(issue['number'])}"


def main(argv=None, api=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    c = sub.add_parser("collect")
    for name in ("workspace", "console", "destination", "summary", "run-url"):
        c.add_argument("--" + name, required=True)
    c.add_argument("--result", required=True, choices=("success", "failure", "cancelled"))
    t = sub.add_parser("track")
    t.add_argument("--repo", required=True, choices=("Azure/aks-durable-agents",))
    t.add_argument("--run-id", required=True, type=int)
    t.add_argument("--sha", required=True)
    t.add_argument("--run-url", required=True)
    t.add_argument("--test", action="store_true")
    c.add_argument("--sha", default="")
    for command in (c, t):
        command.add_argument("--profile", choices=("kind", "aks", "aks-substrate") if command is c else ("kind", "aks"), default="kind")
        command.add_argument("--stage", default="scenario")
    args = parser.parse_args(argv)
    try:
        if args.command == "collect":
            code = collect(args.workspace, args.console, args.destination, args.summary, args.result, args.run_url,
                           args.profile, args.sha, args.stage)
            if code:
                print("collector: success claim has invalid or missing proof; see summary", file=sys.stderr)
            return code
        if api is None:
            token = os.environ.get("GITHUB_TOKEN")
            if not token:
                raise ValueError("GITHUB_TOKEN is required")
            api = GitHubAPI(token)
        print("Tracker:", track(api, args.repo, args.run_id, args.sha, args.run_url, args.test, args.profile, args.stage))
        return 0
    except (ApiError, ValueError, OSError) as exc:
        print(f"e2e {args.command} failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
