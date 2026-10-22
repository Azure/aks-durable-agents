"""Closed actor-profile evidence; legacy marker proofs remain a different schema."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("actor_public_base", Path(__file__).with_name("proof.py"))
assert spec is not None and spec.loader is not None
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

FINAL = {"version": 1, "profile": "aks-substrate", "variant": "substrate-gvisor", "case": "simulated-explicit-continue", "model": "real", "approval": "simulated", "entra": "not-run", "modelCalls": 1, "fakeModelCalls": 0, "published": 1, "receipts": 1, "artifacts": 1, "restartVerified": True, "networkVerified": True, "actorBound": True, "runtime": "gvisor", "checkpointVolumes": True, "separateExecutor": True, "guestEgress": "not-qualified", "coldRestore": "not-run"}
REPLAY = {"completed": True, "providerCalls": 0, "executorCalls": 0, "coverageComplete": True, "unchanged": True}
CASES = ("untrusted-router", "untrusted-control", "executor-router", "executor-control", "executor-model", "host-egress")


def validate(value):
    base._closed(value, (*FINAL, "replay"))
    base._literals(value, FINAL)
    base._closed(value["replay"], REPLAY)
    base._literals(value["replay"], REPLAY)
    return {**FINAL, "replay": dict(REPLAY)}


def validate_network(records):
    if type(records) is not list or len(records) != 24:
        raise ValueError("incomplete actor caller-network proof")
    seen, clean = set(), []
    for record in records:
        base._closed(record, ("phase", "case", "stage", "passed"))
        if record["phase"] not in ("dormant", "live") or record["case"] not in CASES or record["stage"] not in ("control", "denial") or record["passed"] is not True:
            raise ValueError("invalid actor caller-network proof")
        identity = record["phase"], record["case"], record["stage"]
        if identity in seen:
            raise ValueError("duplicate actor caller-network proof")
        seen.add(identity)
        clean.append(dict(record))
    return clean


validate_timings = base.validate_timings
validate_diagnostics = base.validate_diagnostics
validate_rollout_status = base.validate_rollout_status
# Isolated base-module instance: only this profile replaces its two validators.
# The descriptor-anchored bounded file reader and legacy schema stay unchanged.
base.__dict__["VALIDATORS"] = {**base.VALIDATORS, "proof.json": validate, "network-proof.json": validate_network}
load_public = base.load_public
