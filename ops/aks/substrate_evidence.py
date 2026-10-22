"""Private installer evidence. Stderr redaction is best effort, not publication clearance."""
import base64
import json
import os
import re
import stat
import uuid
from pathlib import Path
from urllib.parse import quote, quote_plus

import cleanup
import lifecycle

SENSITIVE = r"TOKEN|SECRET|PASSWORD|CREDENTIAL|KEY"
OPERATIONS = {
    "az": {"show", "list", "get-versions", "list-usage", "create", "delete", "stop", "get-credentials"},
    "kubectl": {"apply", "get", "wait", "exec", "delete", "rollout", "create", "config", "label"},
    "kubectl-ate": {"create", "get", "resume", "delete"},
    "ate-setup": {"create"},
    "go": {"version"},
    "git": {"rev-parse", "status"},
}


class Evidence:
    """Own one new private directory and serial command evidence; never adopt paths."""

    def __init__(self, directory, run=lifecycle.command):
        self.directory = Path(directory)
        if not self.directory.is_absolute():
            self.directory = Path.cwd() / self.directory
        self.run, self.fd = run, None
        self.cleanup_started, self.write_failed = False, False
        self.steps, self.secrets = [], set()
        for key, value in os.environ.items():
            if re.search(SENSITIVE, key, re.IGNORECASE):
                self._remember(value)
        parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for component in self.directory.parts[1:-1]:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                os.close(parent)
                parent = child
            os.mkdir(self.directory.name, mode=0o700, dir_fd=parent)
            self.fd = os.open(self.directory.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            info = os.fstat(self.fd)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError("evidence directory must be owned and private")
        except (OSError, ValueError):
            self.close()
            raise ValueError("evidence requires a new private directory without symlinks") from None
        finally:
            os.close(parent)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def _write(self, name, data):
        if self.fd is None:
            raise ValueError("evidence writer is closed")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name):
            raise ValueError("invalid evidence filename")
        temporary = ".evidence-" + uuid.uuid4().hex
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
            with os.fdopen(fd, "wb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
        finally:
            try:
                os.unlink(temporary, dir_fd=self.fd)
            except FileNotFoundError:
                pass

    def write_json(self, name, data):
        """Atomically save caller-selected safe proof fields; I/O errors propagate."""
        self._write(name, (json.dumps(data, indent=2, ensure_ascii=True) + "\n").encode())

    def _remember(self, value):
        if (not isinstance(value, str) or not 4 <= len(value) <= 65536
                or (value.isdecimal() and len(value) < 8)):
            return
        self.secrets.update((value, quote(value, safe=""), quote_plus(value),
                             base64.b64encode(value.encode()).decode(),
                             base64.urlsafe_b64encode(value.encode()).decode()))

    def _remember_input(self, raw):
        try:
            if not isinstance(raw, (bytes, str)) or len(raw) > 1024 * 1024:
                return
            data = json.loads(raw)
            if not isinstance(data, dict) or data.get("kind") != "Secret":
                return
            for section in ("stringData", "data"):
                values = data.get(section, {})
                if not isinstance(values, dict):
                    continue
                for value in values.values():
                    self._remember(value)
                    if section == "data" and isinstance(value, str):
                        try:
                            self._remember(base64.b64decode(value, validate=True).decode())
                        except (ValueError, UnicodeError):
                            pass
        except (ValueError, TypeError, RecursionError, UnicodeError):
            pass  # Untrusted stdin is never itself evidence.

    def _scrub(self, raw):
        text = raw.decode("utf-8", errors="replace")
        for secret in sorted(self.secrets, key=len, reverse=True):
            text = text.replace(secret, "[REDACTED]")
        text = re.sub(r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z0-9]+ )?PRIVATE KEY-----|\Z)",
                      "[REDACTED]", text)
        text = re.sub(r'''(?i)(?:\bauthorization\s*[:=]\s*(?:bearer|basic)|\bbearer)\s+[^\s"'<>]+''',
                      "Authorization [REDACTED]", text)
        text = re.sub(r"(?i)(https?://)[^\s/@]+@", r"\1[REDACTED]@", text)
        text = re.sub(r'''(?i)(\b(?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|password|(?:client[_-]?)?secret|credential|(?:api|access|private)[_-]?key)["']?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;}]+)''',
                      r"\1[REDACTED]", text)
        text = re.sub(r"\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "[REDACTED]", text)
        text = re.sub(r"\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{16,}\b", "[REDACTED]", text)
        text = re.sub(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))", "", text)
        text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", text).replace("::", ": :")
        # Redact the complete diagnostic before taking a bounded UTF-8 tail.
        return text.encode()[-65536:].decode("utf-8", errors="ignore").encode()

    def command(self, args, *, timeout, input=None):
        if self.write_failed and not self.cleanup_started:
            raise cleanup.CloudError("evidence writing failed")
        self._remember_input(input)
        captured, status = [], "passed"

        def collect(raw):
            try:
                if isinstance(raw, bytes):
                    captured.append(raw)
            except Exception:  # noqa: BLE001, S110 — the memory-only sink must not raise.
                pass

        try:
            return self.run(args, timeout=timeout, input=input, stderr_sink=collect)
        except BaseException as error:
            status = type(error).__name__
            raise
        finally:
            sequence = len(self.steps) + 1
            tool = Path(str(args[0])).name if args else "external"
            if tool not in OPERATIONS:
                tool = "external"
            operation = "other"
            arguments = iter(args[1:])
            for arg in arguments:
                if arg in ("--kubeconfig", "--context", "-C"):
                    next(arguments, None)
                elif isinstance(arg, str) and arg in OPERATIONS.get(tool, set()):
                    operation = arg
                    break
            self.steps.append({"sequence": sequence, "tool": tool, "operation": operation, "status": status})
            try:
                self._write(f"{sequence:04d}.stderr.txt", self._scrub(b"".join(captured)))
                self.write_json("steps.json", self.steps)
            except Exception:  # noqa: BLE001 — preserve primary failures and permit cleanup.
                self.write_failed = True  # Stop normal work next time, but never suppress cleanup.
