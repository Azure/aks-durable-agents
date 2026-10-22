#!/usr/bin/env python3
"""Admission-only regression on the demo's owned kind cluster; never installs a runtime."""
import argparse
import copy
import json
import signal
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parents[1]), str(HERE), str(HERE.parent / "demo"), str(HERE.parent / "images")]
import substrate

from ops.demo import demo
from ops.images import substrate_images

WORKLOADS = {"Deployment", "DaemonSet", "StatefulSet", "Job", "WorkerPool"}


def test_images():
    # Schema-only synthetic digests: never pulled, published or used on AKS.
    return substrate_images.installer_map({
        "version": 1, "workflowCommit": "0" * 40,
        "substrateCommit": substrate_images.SUBSTRATE_COMMIT,
        "pauseCommit": substrate_images.PAUSE_COMMIT,
        "images": {role: substrate_images.PREFIX + role + "@sha256:" + "1" * 64
                   for role in substrate_images.ROLES},
    })


def check(source, directory):
    images = test_images()
    bundles = [substrate.render(source, images, nodes) for nodes in (
        ["approved-a"], ["approved-b", "approved-a"], ["approved-c", "approved-a", "approved-b"])]
    runner = demo.Runner(directory)

    def kube(*args, document=None):
        return runner.run(["kubectl", "--kubeconfig", runner.kubeconfig, "--context", runner.context, *args],
                          data=json.dumps(document).encode() if document is not None else None)

    def admit(document):
        kube("create", "--dry-run=server", "-f", "-", document=document)

    def interrupted(signum, frame):
        raise demo.DemoError("admission check interrupted; cleaning owned resources")

    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        demo.preflight(runner)
        runner.create_cluster()
        # Only namespaces and CRDs persist, in a newly owned disposable cluster.
        for doc in bundles[0]["manifests"]:
            if doc["kind"] in ("Namespace", "CustomResourceDefinition"):
                kube("create", "-f", "-", document=doc)
                if doc["kind"] == "CustomResourceDefinition":
                    kube("wait", "--for=condition=Established", "crd/" + doc["metadata"]["name"], "--timeout=60s")

        # Prove this is semantic API validation, not a permissive mock/schema check.
        broken = copy.deepcopy(next(d for d in bundles[0]["manifests"] if d["kind"] == "Deployment"))
        broken["spec"]["template"]["spec"]["affinity"]["nodeAffinity"] = {
            "requiredDuringSchedulingIgnoredDuringExecution": {"nodeSelectorTerms": [
                {"matchFields": [{"key": "metadata.name", "operator": "In", "values": ["approved-a", "approved-b"]}]}]}}
        try:
            admit(broken)
        except demo.DemoError as error:
            if "must be only one value" not in str(error):
                raise
        else:
            raise AssertionError("API accepted the invalid multi-value node field selector")

        count = 0
        for bundle in bundles:
            for doc in bundle["manifests"]:
                if doc["kind"] not in WORKLOADS:
                    continue
                admit(doc)
                count += 1
                if doc["kind"] == "WorkerPool":
                    # CRD admission checks its schema, not core Pod semantics.
                    # Validate the rendered worker's scheduling fields as a Pod too.
                    template = doc["spec"]["template"]
                    admit({"apiVersion": "v1", "kind": "Pod",
                           "metadata": {"name": "worker-scope-check", "namespace": doc["metadata"]["namespace"]},
                           "spec": {"nodeSelector": template["nodeSelector"],
                                    "affinity": {"nodeAffinity": template["nodeAffinity"]},
                                    "containers": [{"name": "worker", "image": doc["spec"]["workerImage"],
                                                    "resources": template["resources"]}]}})
        if count != 30:
            raise AssertionError("expected all ten pinned-source workloads in each of the three node cases")
        for namespace in ("ate-system", substrate.SMOKE):
            remaining = json.loads(kube("get", "deployments,daemonsets,statefulsets,jobs,workerpools,pods",
                                       "-n", namespace, "-o", "json"))
            if remaining["items"]:
                raise AssertionError("admission-only check persisted a workload")
        print(f"Validated {count} rendered workloads for 1/2/3 nodes, plus worker Pod scopes; invalid selector rejected.")
    finally:
        for sig in previous:
            signal.signal(sig, signal.SIG_IGN)
        try:
            runner.cleanup()
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--directory", required=True, type=Path)
    args = parser.parse_args()
    check(args.source, args.directory)
