"""Closed, non-sensitive AKS public evidence schemas and bounded file reader."""
import json
import math
import os
import stat
from pathlib import Path

MAX_BYTES = 16 * 1024
PHASES = frozenset(("preflight", "install", "network-dormant", "network-live", "park",
                    "restart", "approve", "continue", "backup", "replay", "cleanup"))
OPERATIONS = frozenset(("phase", "profile-create", "profile-rollout", "profile-verify", "profile-remove",
                        "profile-node-check", "namespace-create", "volume-create", "chart-install", "policy-check",
                        "fixture-init-create", "fixture-init-wait", "fixture-init-remove"))
REASONS = frozenset(("deadline-exhausted", "command-timeout", "command-failed", "interrupted",
                     "invariant-failed", "io-failed", "unclassified-failure"))
CLEANUP = frozenset(("succeeded", "failed", "not-run"))
_FINAL = {
    "version": 1, "profile": "aks", "model": "real", "approval": "simulated", "entra": "not-run",
    "modelCalls": 1, "fakeModelCalls": 0, "published": 1, "receipts": 1, "artifacts": 1,
    "restartVerified": True, "markerVerified": True, "networkVerified": True,
}
_REPLAY = {"completed": True, "providerCalls": 0, "executorCalls": 0,
           "coverageComplete": True, "unchanged": True}


def _closed(value, keys):
    if type(value) is not dict or value.keys() != set(keys):
        raise ValueError("invalid AKS public evidence schema")


def _literals(value, expected):
    for key, wanted in expected.items():
        if type(value[key]) is not type(wanted) or value[key] != wanted:
            raise ValueError("invalid AKS public evidence value")


def validate(value):
    """Require every final invariant; return only the public fields."""
    _closed(value, (*_FINAL, "replay"))
    _literals(value, _FINAL)
    _closed(value["replay"], _REPLAY)
    _literals(value["replay"], _REPLAY)
    return {**_FINAL, "replay": dict(_REPLAY)}


def validate_network(records):
    """Require dormant/live x ingress/egress x control/denial exactly once."""
    if type(records) is not list or len(records) != 8:
        raise ValueError("invalid AKS network proof")
    seen, clean = set(), []
    for record in records:
        _closed(record, ("phase", "case", "stage", "passed"))
        for key, choices in (("phase", ("dormant", "live")),
                             ("case", ("untrusted-ingress", "host-egress")),
                             ("stage", ("control", "denial"))):
            if type(record[key]) is not str or record[key] not in choices:
                raise ValueError("invalid AKS network proof")
        if record["passed"] is not True:
            raise ValueError("invalid AKS network proof")
        identity = (record["phase"], record["case"], record["stage"])
        if identity in seen:
            raise ValueError("duplicate AKS network proof")
        seen.add(identity)
        clean.append({key: record[key] for key in ("phase", "case", "stage", "passed")})
    return clean


def _seconds(value):
    # Check bounds before isfinite: huge JSON integers must fail, not overflow.
    if type(value) not in (int, float) or not 0 <= value <= 2700 or not math.isfinite(value):
        raise ValueError("invalid AKS timing")


def validate_timings(value):
    _closed(value, ("version", "phases", "totalSeconds"))
    _literals(value, {"version": 1})
    if type(value["phases"]) is not dict or not value["phases"].keys() <= PHASES:
        raise ValueError("invalid AKS timing phases")
    _seconds(value["totalSeconds"])
    for seconds in value["phases"].values():
        _seconds(seconds)
    return {"version": 1, "phases": dict(value["phases"]), "totalSeconds": value["totalSeconds"]}


def validate_diagnostics(value):
    """Failure category only: never exception text or an underlying-cause claim."""
    _closed(value, ("version", "phase", "operation", "reason", "cleanup"))
    _literals(value, {"version": 1})
    for key, choices in (("phase", PHASES), ("operation", OPERATIONS), ("reason", REASONS), ("cleanup", CLEANUP)):
        if type(value[key]) is not str or value[key] not in choices:
            raise ValueError("invalid AKS diagnostics")
    return {key: value[key] for key in ("version", "phase", "operation", "reason", "cleanup")}


VALIDATORS = {"proof.json": validate, "network-proof.json": validate_network, "timings.json": validate_timings,
              "diagnostics.json": validate_diagnostics}


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate AKS public evidence key")
        value[key] = item
    return value


def _nonfinite(_value):
    raise ValueError("nonfinite AKS public evidence value")


def load_public(workspace, name):
    """Read only a fixed root file, with no symlink traversal, truncation or raw copying."""
    if name not in VALIDATORS:
        raise ValueError("unknown AKS public evidence file")
    # Walk by directory descriptors so ancestor symlinks and replacement races
    # cannot redirect a trusted workspace path into private evidence.
    path = Path(workspace).absolute()
    directory = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
                raise ValueError("unsafe AKS public evidence file")
            data = stream.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError("oversize AKS public evidence file")
    finally:
        os.close(directory)
    return VALIDATORS[name](json.loads(data, object_pairs_hook=_object, parse_constant=_nonfinite))
