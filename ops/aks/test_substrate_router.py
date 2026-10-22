"""Owned router overlay contracts; these are not network-enforcement receipts."""
import copy
import tempfile
import unittest
from pathlib import Path
from typing import Any

import substrate
import yaml
from test_substrate import fixture

HOST: dict[str, Any] = {"namespace": "agents", "labels": {"app.kubernetes.io/name": "aks-durable-agents", "app.kubernetes.io/instance": "kaimahi", "app.kubernetes.io/component": "host"}}


def upstream_policy():
    return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": "atenet-router", "namespace": "ate-system"}, "spec": {"podSelector": {"matchLabels": {"app": "atenet-router"}}, "policyTypes": ["Ingress"], "ingress": [{"ports": [{"protocol": "TCP", "port": p} for p in ("http", "https", "connect", "connect-tls")]}]}}


class RouterOverlayTests(unittest.TestCase):
    def bundle(self, root, host=None, policy=None):
        mapping = fixture(root)
        (root / "manifests/ate-install/ate-system-networkpolicies.yaml").write_text(yaml.safe_dump_all([upstream_policy() if policy is None else policy]))
        return substrate.render(root, mapping, ["node-a", "node-b"], verify=False, router_host=host)

    def test_router_overlay_is_owned_exact_and_reproducible(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            default = self.bundle(root / "default")
            changed = self.bundle(root / "variant", HOST)
            self.assertEqual(self.bundle(root / "again", HOST), changed)
            baseline = next(d for d in default["manifests"] if d["kind"] == "NetworkPolicy")
            policy = next(d for d in changed["manifests"] if d["kind"] == "NetworkPolicy")
            self.assertNotIn("from", baseline["spec"]["ingress"][0])
            self.assertEqual(policy["spec"]["ingress"], [{"ports": baseline["spec"]["ingress"][0]["ports"], "from": [
                {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "agents"}}, "podSelector": {"matchLabels": HOST["labels"]}},
                {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": substrate.SMOKE}}, "podSelector": {"matchLabels": {"substrate.aks/probe": "counter"}}},
            ]}])
            self.assertEqual([d for d in changed["manifests"] if d["kind"] != "NetworkPolicy"], [d for d in default["manifests"] if d["kind"] != "NetworkPolicy"])
            self.assertEqual(changed["actorTemplate"], default["actorTemplate"])
            probe = substrate.probe_pod({"probe": "registry.example/probe@sha256:" + "a" * 64}, ["node-a"])
            self.assertEqual(probe["metadata"]["labels"], {"substrate.aks/probe": "counter"})

    def test_refuses_unscoped_or_nonhost_selector(self):
        for change in ({"namespace": ""}, {"namespace": "ate-system"}, {"namespace": "*"}, {"namespace": "agents/other"}, {"labels": {}}, {"labels": {"app.kubernetes.io/component": "host"}}, {"extra": "ignored"}):
            host = copy.deepcopy(HOST)
            host.update(change)
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp, self.assertRaises(ValueError):
                self.bundle(Path(tmp), host)
        host = copy.deepcopy(HOST)
        host["labels"]["app.kubernetes.io/component"] = "executor"
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(ValueError):
            self.bundle(Path(tmp), host)

    def test_refuses_source_policy_shape_change(self):
        for change in ("missing-selector", "extra-rule", "unexpected-port"):
            policy = upstream_policy()
            if change == "missing-selector":
                policy["spec"]["podSelector"] = {}
            elif change == "extra-rule":
                policy["spec"]["ingress"].append({})
            else:
                policy["spec"]["ingress"][0]["ports"].append({"port": 1234})
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp, self.assertRaises(ValueError):
                self.bundle(Path(tmp), HOST, policy)


if __name__ == "__main__":
    unittest.main()
