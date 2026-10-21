"""Report-only scans of checksum-pinned CI tools; own-code scans stay strict."""
import argparse
import hashlib
import json
import math
import os
import re
import selectors
import signal
import stat
import subprocess
import time
from pathlib import Path

PINS = {
    "kubectl": ("65691ff77eb6fa44c908b77a1082c9f092c3b9733b5cefabec0d1104890e21a8", "v1.26.8"),
    "kubelogin": ("5160d49d0fb0d5f6fd7923058000f5fde34627a640cb4b313026992586c20ff2", "v1.26.6"),
}
RELEASES = {"kubectl": "v1.37.1", "kubelogin": "v0.2.21"}
LIMIT = 32 * 1024 * 1024
TIMEOUT = 90
CONFIG = {"protocol_version": "v1.0.0", "scanner_name": "govulncheck", "scanner_version": "v1.9.0",
          "db": "https://vuln.go.dev", "scan_level": "symbol", "scan_mode": "binary"}


def require(condition):
    if not condition:
        raise ValueError("invalid scan")


def finite(token):
    value = float(token)
    require(math.isfinite(value))
    return value


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def decision(tool, status="scan-error", findings=()):
    return {"tool": tool if tool in PINS else "unknown", "status": status,
            "findings": sorted(findings)}


def evaluate(tool, binaryhash, raw, returncode):
    """Evaluate concatenated JSON objects, never scanner exit status alone."""
    findings = set()
    if tool not in PINS or binaryhash != PINS[tool][0]:
        return decision(tool, "integrity-error")
    try:
        require(len(raw) <= LIMIT)
        raw = raw.decode("utf-8") if isinstance(raw, bytes) else raw
        require(len(raw.encode("utf-8")) <= LIMIT)
        decoder = json.JSONDecoder(object_pairs_hook=unique, parse_float=finite,
                                   parse_constant=lambda _: require(False))
        offset, count, sboms = 0, 0, 0
        while offset < len(raw):
            if raw[offset] in " \r\n\t":
                offset += 1
                continue
            message, offset = decoder.raw_decode(raw, offset)
            require(isinstance(message, dict) and len(message) == 1)
            kind, value = next(iter(message.items()))
            require(isinstance(value, dict))
            require(count != 0 or kind == "config")
            if kind == "config":
                require(count == 0 and all(value.get(k) == v for k, v in CONFIG.items()))
            elif kind == "SBOM":
                sboms += 1
                require(sboms == 1 and value.get("go_version") == "go" + PINS[tool][1][1:])
                require(isinstance(value.get("modules"), list))
                for module in value["modules"]:
                    require(isinstance(module, dict) and isinstance(module.get("path"), str)
                            and isinstance(module.get("version"), str))
            elif kind == "progress":
                require(isinstance(value.get("message"), str))
            elif kind in ("osv", "finding"):
                advisory = value.get("id" if kind == "osv" else "osv")
                require(isinstance(advisory, str) and re.fullmatch(r"GO-\d{4}-\d{4,}", advisory))
                if kind == "finding":
                    trace = value.get("trace")
                    require(isinstance(trace, list) and len(trace) > 0)
                    for frame in trace:
                        require(isinstance(frame, dict) and bool(frame))
                        require(all(isinstance(frame[k], str) for k in
                                    ("module", "version", "package", "function", "receiver") if k in frame))
                    first = trace[0]
                    require(isinstance(first.get("module"), str) and bool(first["module"]))
                    findings.add(advisory)
            else:
                require(False)
            count += 1
        require(count > 0 and sboms == 1)
        require(returncode == 0)
        return decision(tool, "findings" if findings else "clean", findings)
    except (ValueError, TypeError, KeyError, RecursionError):
        # Preserve already parsed findings, but never call an incomplete scan clean.
        return decision(tool, "scan-error", findings)


def digest(path):
    # O_NONBLOCK avoids hanging on a FIFO substituted for a binary.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as binary:
        require(stat.S_ISREG(os.fstat(binary.fileno()).st_mode))
        return hashlib.file_digest(binary, "sha256").hexdigest()


def run_scan(path, timeout=None):
    """Bound both output and wall time, including descendants holding stdout."""
    seconds = TIMEOUT if timeout is None else timeout
    require(type(seconds) in (int, float) and math.isfinite(seconds) and seconds > 0)
    deadline, output = time.monotonic() + min(TIMEOUT, seconds), bytearray()
    scanner = Path(path).parent / "govulncheck"
    with subprocess.Popen([str(scanner), "-json", "-mode=binary", "-scan=symbol", str(path)],
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True) as process:
        try:
            assert process.stdout is not None  # Guaranteed by stdout=PIPE.
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise TimeoutError("scan timeout")
                    chunk = os.read(process.stdout.fileno(), 65536)
                    if not chunk:
                        break
                    output.extend(chunk)
                    require(len(output) <= LIMIT)
            code = process.wait(timeout=max(0, deadline - time.monotonic()))
            return bytes(output), code
        finally:
            # Kill the whole session even if its leader exited or was interrupted.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()


def scan_tool(tool, tools_dir, timeout=None):
    try:
        path = Path(tools_dir) / tool
        require(tool in PINS and path.is_absolute())
        before = digest(path)
        require(before == PINS[tool][0])
    except (OSError, ValueError):
        return decision(tool, "integrity-error")
    try:
        raw, code = run_scan(path) if timeout is None else run_scan(path, timeout=timeout)
        result = evaluate(tool, before, raw, code)
    except (TimeoutError, subprocess.TimeoutExpired):
        if timeout is not None and timeout < TIMEOUT:
            raise TimeoutError("scenario budget exhausted") from None
        result = decision(tool)
    except (OSError, ValueError):
        result = decision(tool)
    try:
        require(digest(path) == before)
    except (OSError, ValueError):
        return decision(tool, "integrity-error")
    return result


def audit_tools(tools_dir, remaining=lambda: TIMEOUT):
    results = []
    for tool in PINS:
        results.append(scan_tool(tool, tools_dir, timeout=remaining()))
        remaining()  # A report-only scanner cannot extend the scenario budget.
    return results


def write_report(results, directory, summary=None):
    directory = Path(directory)
    directory.mkdir(mode=0o700)
    lines = ["## CI runner binary scans (report-only)", "",
             "Findings do not gate execution. Scan errors are not evidence of zero vulnerabilities.", ""]
    records = []
    for result in results:
        tool, status = result["tool"], result["status"]
        checksum, go_version = PINS.get(tool, ("unknown", "unknown"))
        records.append(dict(result, release=RELEASES.get(tool, "unknown"), sha256=checksum, goVersion=go_version))
        lines.append(f"- {tool} {RELEASES.get(tool, 'unknown')}: **{status}**; advisories: " + (", ".join(result["findings"]) or "none reported"))
        if status != "clean":
            print(f"::warning::CI runner {tool} binary scan: {status}; see runner-tool report")
    text = "\n".join(lines) + "\n"
    (directory / "report.json").write_text(json.dumps(records, indent=2, sort_keys=True) + "\n")
    (directory / "summary.md").write_text(text)
    if summary:
        with Path(summary).open("a") as output:
            output.write(text)


def integrity_failed(results):
    return any(result["status"] == "integrity-error" for result in results)


def interrupt(_signal, _frame):
    raise KeyboardInterrupt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tools-dir", required=True, type=Path)
    parser.add_argument("--report-dir", required=True, type=Path)
    parser.add_argument("--summary", default=os.environ.get("GITHUB_STEP_SUMMARY"), type=Path)
    args = parser.parse_args(argv)
    previous = signal.signal(signal.SIGTERM, interrupt)
    cancelled = False
    try:
        results = audit_tools(args.tools_dir)
    except KeyboardInterrupt:
        cancelled = True
        results = [decision(tool) for tool in PINS]
    finally:
        signal.signal(signal.SIGTERM, previous)
    write_report(results, args.report_dir, args.summary)
    for result in results:
        print(json.dumps(result, sort_keys=True))
    return 130 if cancelled else int(integrity_failed(results))


if __name__ == "__main__":
    raise SystemExit(main())
