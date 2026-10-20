"""Offline Helm contract tests. Goldens contain synthetic inputs, not image receipts."""
import copy
import difflib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

CHART = Path(__file__).resolve().parents[1]
UPDATE = "--update-goldens" in sys.argv
if UPDATE:
    sys.argv.remove("--update-goldens")


def helm(*args):
    return subprocess.run(
        ["helm", "--kube-context", "offline-only", *map(str, args)],
        text=True, capture_output=True, check=False,
    )


def render(values, release="test", namespace="agents"):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as f:
        json.dump(values, f)
        f.flush()
        return helm("template", release, CHART, "--namespace", namespace,
                    "--kube-version", "1.37.0", "-f", f.name)


class ChartTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert sys.version_info[:3] == (3, 14, 3), "use Python 3.14.3"
        assert yaml.__version__ == "6.0.3", "install tests/requirements.txt"
        version = helm("version", "--short")
        assert version.returncode == 0 and version.stdout.strip() == "v3.20.0+gb2e4314", version.stderr
        cls.defaults = json.loads((CHART / "tests/default-inputs.yaml").read_text())
        cls.proof = json.loads((CHART / "tests/proof-values.yaml").read_text())

    def documents(self, values, release="test", namespace="agents"):
        result = render(values, release, namespace)
        self.assertEqual(result.returncode, 0, result.stderr)
        return [doc for doc in yaml.safe_load_all(result.stdout) if doc]

    def test_lint_and_goldens(self):
        for fixture in ("default-inputs", "proof-values"):
            with self.subTest(fixture=fixture):
                result = helm("lint", CHART, "--strict", "--kube-version", "1.37.0", "-f", CHART / f"tests/{fixture}.yaml")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                docs = self.documents(json.loads((CHART / f"tests/{fixture}.yaml").read_text()))
                actual = yaml.safe_dump_all(docs, sort_keys=True)
                golden = CHART / f"tests/golden/{fixture}.yaml"
                if UPDATE:
                    golden.parent.mkdir(exist_ok=True)
                    golden.write_text(actual)
                self.assertTrue(golden.exists(), f"missing golden: {golden}")
                expected = golden.read_text()
                self.assertEqual(actual, expected, "".join(difflib.unified_diff(expected.splitlines(True), actual.splitlines(True))))

    def model_policy(self, values):
        docs = self.documents(values)
        config = next(d for d in docs if d["kind"] == "ConfigMap"
                      and "model-policy.json" in d.get("data", {}))
        self.assertTrue(config["immutable"])
        return json.loads(config["data"]["model-policy.json"])

    def test_model_policy_limits(self):
        baseline = {
            "version": 1, "runID": self.defaults["model"]["policy"]["runID"],
            "ledgerPath": "/data/real-attempts.db",
            "deployment": self.defaults["model"]["deployment"],
            "pricing": self.defaults["model"]["policy"]["pricing"],
        }
        for settings in ({}, {"maxAttempts": 2}, {"maxAttempts": 3},
                         {"maxInputTokens": 32768},
                         {"maxAttempts": 3, "maxInputTokens": 32768}):
            with self.subTest(settings=settings):
                values = copy.deepcopy(self.defaults)
                values["model"]["policy"].update(settings)
                expected = copy.deepcopy(baseline)
                if settings.get("maxAttempts") == 3:
                    expected.update(version=2, maxAttempts=3)
                if "maxInputTokens" in settings:
                    expected["maxInputTokens"] = 32768
                actual = self.model_policy(values)
                self.assertEqual(actual, expected)
                if settings == {"maxAttempts": 3, "maxInputTokens": 32768}:
                    # Go opens this same fixture, binding chart output to host parsing.
                    fixture = json.loads((CHART / "tests/model-policy-three-calls.json").read_text())
                    self.assertEqual(actual, fixture)

    def test_model_policy_null_uses_safe_defaults(self):
        baseline = self.model_policy(self.defaults)
        for settings in ({"maxAttempts": None}, {"maxInputTokens": None},
                         {"maxAttempts": None, "maxInputTokens": None}):
            with self.subTest(settings=settings):
                values = copy.deepcopy(self.defaults)
                values["model"]["policy"].update(settings)
                self.assertEqual(self.model_policy(values), baseline)

    def test_model_policy_limit_refusals(self):
        for key, invalid in (
            ("maxAttempts", (0, 1, 4, 3.5, "3", True)),
            ("maxInputTokens", (0, -1, 8192, 8193, 32769, 32768.5, "32768", True)),
        ):
            for value in invalid:
                with self.subTest(key=key, value=value):
                    values = copy.deepcopy(self.defaults)
                    values["model"]["policy"][key] = value
                    result = render(values)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn(key, result.stderr)

    def test_bare_defaults_refuse_missing_inputs(self):
        result = helm("template", "test", CHART)
        self.assertNotEqual(result.returncode, 0)
        # Published image pins do not supply the operator\'s identity inputs.
        self.assertIn("auth", result.stderr)

    def test_schema_refusals(self):
        cases = [
            (("image", "host", "digest"), "", "digest"),
            (("image", "harness", "digest"), "", "digest"),
            (("image", "host", "digest"), "sha256:abc", "digest"),
            (("image", "host", "repository"), "example.invalid/host:latest", "repository"),
            (("image", "harness", "repository"), "example.invalid/harness:v1", "repository"),
            (("image", "host", "includesHealthProbe"), False, "includesHealthProbe"),
            (("auth", "mode"), "off", "trustedNetwork"),
            (("auth", "allowedClientIDs"), [], "allowedClientIDs"),
            (("auth", "approvers"), [], "approvers"),
            (("auth", "tlsSecretName"), "", "tlsSecretName"),
            (("persistence", "subPath"), "../old", "subPath"),
        ]
        for path, value, error_field in cases:
            with self.subTest(path=path, value=value):
                values = copy.deepcopy(self.defaults)
                target = values
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                result = render(values)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(error_field, result.stderr)

    def test_approver_identity_refusals(self):
        # Approvers must match the verifier's issuer and subject form: a lowercase
        # GUID for oid, no ASCII whitespace or control characters for sub.
        issuer = self.defaults["auth"]["issuer"]
        tenant = self.defaults["auth"]["tenantID"]
        oid = "abcdef01-2345-6789-abcd-ef0123456789"
        for claim, approver, error_field in (
            ("oid", {"issuer": f"https://sts.windows.net/{tenant}/", "subject": oid}, "issuer"),
            ("oid", {"issuer": issuer + "/", "subject": oid}, "issuer"),
            ("oid", {"issuer": issuer, "subject": "user@contoso.example"}, "subject"),
            ("oid", {"issuer": issuer, "subject": "../x@y"}, "subject"),
            ("oid", {"issuer": issuer, "subject": oid.upper()}, "subject"),
            ("sub", {"issuer": issuer, "subject": "pairwise subject"}, "subject"),
            ("sub", {"issuer": issuer, "subject": "pairwise\x7fsubject"}, "subject"),
        ):
            with self.subTest(approver=approver, claim=claim):
                values = copy.deepcopy(self.defaults)
                values["auth"]["subjectClaim"] = claim
                values["auth"]["approvers"].append(approver)
                result = render(values)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(error_field, result.stderr)
        for claim, subject in (("oid", oid), ("sub", "pairwise-subject")):
            with self.subTest(claim=claim):
                values = copy.deepcopy(self.defaults)
                values["auth"]["subjectClaim"] = claim
                values["auth"]["approvers"].append({"issuer": issuer, "subject": subject})
                auth = next(d for d in self.documents(values) if d["kind"] == "ConfigMap" and d["metadata"]["name"].endswith("-auth"))
                self.assertEqual(json.loads(auth["data"]["auth.json"])["approvers"], values["auth"]["approvers"])

    def test_two_pods_security_placement_and_storage(self):
        docs = self.documents(self.defaults)
        deployments = [d for d in docs if d["kind"] == "Deployment"]
        self.assertEqual(len(deployments), 2)
        host = next(d for d in deployments if d["metadata"]["name"].endswith("-host"))
        harness = next(d for d in deployments if d["metadata"]["name"].endswith("-harness"))
        for dep in deployments:
            self.assertEqual(dep["spec"]["replicas"], 0)
            self.assertEqual(dep["spec"]["strategy"], {"type": "Recreate"})
            pod = dep["spec"]["template"]["spec"]
            self.assertFalse(pod["automountServiceAccountToken"])
            for flag in ("hostNetwork", "hostPID", "hostIPC"):
                self.assertFalse(pod[flag])
            self.assertNotIn("fsGroup", pod["securityContext"])
            self.assertEqual(pod["securityContext"]["runAsUser"], 65532)
            for c in pod["containers"]:
                self.assertTrue(c["securityContext"]["readOnlyRootFilesystem"])
                self.assertFalse(c["securityContext"]["allowPrivilegeEscalation"])
                self.assertEqual(c["securityContext"]["capabilities"]["drop"], ["ALL"])
                mounts = c["volumeMounts"]
                self.assertEqual(next(m for m in mounts if m["mountPath"] == "/data")["subPath"], "sessions-v1")
                self.assertEqual(next(m for m in mounts if m["mountPath"] == "/tmp")["subPath"], "sessions-v1/tmp-" + c["name"])
        template = host["spec"]["template"]
        self.assertEqual(template["metadata"]["labels"]["azure.workload.identity/use"], "true")
        self.assertNotIn("azure.workload.identity/use", harness["spec"]["template"]["metadata"]["labels"])
        affinity = template["spec"]["affinity"]["podAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"][0]
        self.assertEqual(affinity["labelSelector"]["matchLabels"], harness["spec"]["selector"]["matchLabels"])
        self.assertEqual(affinity["namespaces"], ["agents"])
        self.assertEqual(affinity["topologyKey"], "kubernetes.io/hostname")
        daemon = template["spec"]["containers"][0]
        self.assertEqual(daemon["readinessProbe"]["exec"]["command"], ["/session-fixture", "network-probe", "--address", "127.0.0.1:8081", "--expect", "allowed"])
        fixture = harness["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(fixture["readinessProbe"]["exec"]["command"], ["/session-fixture", "network-probe", "--address", "127.0.0.1:9000", "--expect", "allowed"])
        self.assertIn("-addr=127.0.0.1:8080", daemon["args"])
        self.assertIn("-health-addr=127.0.0.1:8081", daemon["args"])
        self.assertIn("-peer-node-file=/data/fixture-node.json", daemon["args"])
        self.assertTrue(any(v.get("secret", {}).get("secretName") == "test-tls" for v in template["spec"]["volumes"]))
        pvc = next(d for d in docs if d["kind"] == "PersistentVolumeClaim")
        self.assertEqual(pvc["metadata"]["annotations"]["helm.sh/resource-policy"], "keep")
        self.assertEqual(pvc["spec"]["accessModes"], ["ReadWriteOnce"])
        self.assertFalse(any(d["kind"] in ("Job", "Ingress", "Secret") for d in docs))
        self.assertFalse(any("helm.sh/hook" in d["metadata"].get("annotations", {}) for d in docs))
        self.assertEqual([d["metadata"]["name"] for d in docs if d["kind"] == "Service"], ["test-aks-durable-agents-harness"])

    def test_network_contract(self):
        docs = self.documents(self.defaults)
        policies = [d for d in docs if d["kind"] == "NetworkPolicy"]
        self.assertEqual(len(policies), 3)
        deny = next(d["spec"] for d in policies if d["metadata"]["name"].endswith("-deny"))
        self.assertEqual(deny["policyTypes"], ["Ingress", "Egress"])
        self.assertEqual(deny["ingress"], [])
        self.assertEqual(deny["egress"], [])
        egress = next(d["spec"]["egress"] for d in policies if d["metadata"]["name"].endswith("-host-egress"))
        self.assertEqual(egress[0]["ports"], [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}])
        block = egress[1]["to"][0]["ipBlock"]
        self.assertEqual(block["cidr"], "0.0.0.0/0")
        self.assertEqual(block["except"], ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4"])
        self.assertEqual(egress[1]["ports"], [{"protocol": "TCP", "port": 443}])
        ingress = next(d["spec"]["ingress"] for d in policies if d["metadata"]["name"].endswith("-harness-ingress"))
        for peer in (egress[2]["to"][0], ingress[0]["from"][0]):
            self.assertEqual(peer["namespaceSelector"]["matchLabels"], {"kubernetes.io/metadata.name": "agents"})
            self.assertIn("podSelector", peer)
        self.assertEqual(egress[2]["ports"], [{"protocol": "TCP", "port": 9000}])
        self.assertEqual(ingress[0]["ports"], [{"protocol": "TCP", "port": 9000}])

    def test_custom_namespace_existing_claim_and_release_isolation(self):
        values = copy.deepcopy(self.proof)
        values["persistence"]["existingClaim"] = "retained-data"
        first = self.documents(values, "one", "custom-ns")
        second = self.documents(values, "two", "custom-ns")
        self.assertFalse(any(d["kind"] == "PersistentVolumeClaim" for d in first))
        selectors = []
        for docs, release in ((first, "one"), (second, "two")):
            host = next(d for d in docs if d["kind"] == "Deployment" and d["metadata"]["name"].endswith("-host"))
            pod = host["spec"]["template"]["spec"]
            args = pod["containers"][0]["args"]
            fqdn = f"{release}-aks-durable-agents-harness.custom-ns.svc.cluster.local:9000"
            self.assertIn("-harness-service=" + fqdn, args)
            self.assertIn("-harness=release-notes=" + fqdn, args)
            self.assertEqual(host["spec"]["replicas"], 1)
            self.assertEqual(next(v["persistentVolumeClaim"]["claimName"] for v in pod["volumes"] if "persistentVolumeClaim" in v), "retained-data")
            self.assertFalse(any("secret" in v for v in pod["volumes"]))
            selectors.append(host["spec"]["selector"]["matchLabels"])
        self.assertNotEqual(*selectors)

    def test_long_release_names_do_not_collide(self):
        names = []
        for release in ("a" * 40 + "-one", "a" * 40 + "-two"):
            docs = self.documents(self.defaults, release)
            names.append({d["metadata"]["name"] for d in docs})
            self.assertTrue(all(len(name) <= 63 for name in names[-1]))
        self.assertFalse(names[0] & names[1], "distinct releases must not share resource names")

    def test_string_names_remain_yaml_strings(self):
        values = copy.deepcopy(self.defaults)
        values["persistence"]["existingClaim"] = "true"
        docs = self.documents(values, namespace="123")
        for doc in docs:
            self.assertEqual(doc["metadata"]["namespace"], "123")
            if doc["kind"] == "Deployment":
                volumes = doc["spec"]["template"]["spec"]["volumes"]
                self.assertEqual(next(v["persistentVolumeClaim"]["claimName"] for v in volumes if "persistentVolumeClaim" in v), "true")

    def native_values(self):
        values = copy.deepcopy(self.defaults)
        values["auth"]["mode"] = "off"
        values["auth"]["trustedNetwork"] = True
        values["persistence"]["subPath"] = "sessions-v1"
        values.setdefault("harness", {})["native"] = {
            "enabled": True,
            "entries": [
                {"id": "bundle-v4-" + "a" * 64, "port": 9000},
                {"id": "bundle-v4-" + "b" * 64, "port": 9001},
            ],
        }
        return values

    def test_native_inventory_routes_storage_probes_and_network(self):
        values = self.native_values()
        docs = self.documents(values)
        host = next(d["spec"]["template"]["spec"] for d in docs if d["kind"] == "Deployment" and d["metadata"]["name"].endswith("-host"))
        harness = next(d["spec"]["template"]["spec"] for d in docs if d["kind"] == "Deployment" and d["metadata"]["name"].endswith("-harness"))
        args = host["containers"][0]["args"]
        self.assertEqual(args, json.loads((CHART / "tests/native-host-args.json").read_text()))
        for entry in values["harness"]["native"]["entries"]:
            endpoint = f'test-aks-durable-agents-harness.agents.svc.cluster.local:{entry["port"]}'
            self.assertIn("-harness-service=" + endpoint, args)
            self.assertIn(f'-harness={entry["id"]}={endpoint}', args)
        self.assertEqual(sum(a.startswith("-harness-service=") for a in args), 2)
        self.assertFalse(any(a.startswith(("-peer-node-file", "-node-name", "-tool-executors")) for a in args))
        self.assertEqual(host["containers"][0]["readinessProbe"]["exec"]["command"], ["/host", "health-probe", "127.0.0.1:8081"])
        self.assertEqual([c["name"] for c in harness["containers"]], ["producer"])
        producer = harness["containers"][0]
        self.assertEqual(producer["command"], ["/usr/local/bin/canvas-harness"])
        self.assertEqual(producer["args"], ["serve", "-inventory", "/data/producers/inventory.json", "-ready-listen", "0.0.0.0:8081"])
        self.assertEqual(producer["readinessProbe"]["httpGet"], {"path": "/readyz", "port": 8081})
        self.assertTrue(producer["securityContext"]["readOnlyRootFilesystem"])
        self.assertEqual(producer["image"], values["image"]["harness"]["repository"] + "@" + values["image"]["harness"]["digest"])
        mounts = producer["volumeMounts"]
        self.assertNotIn("/data", [m["mountPath"] for m in mounts], "producer must not see host journal/ledger")
        self.assertEqual(next(m for m in mounts if m["mountPath"] == "/data/producers"), {"name": "data", "mountPath": "/data/producers", "subPath": "sessions-v1/producers", "readOnly": True})
        self.assertEqual(next(m for m in mounts if m["mountPath"] == "/tmp")["subPath"], "sessions-v1/tmp-producer")
        service = next(d for d in docs if d["kind"] == "Service")
        self.assertEqual(service["spec"]["ports"], [
            {"name": "grpc-0", "port": 9000, "targetPort": 9000, "protocol": "TCP"},
            {"name": "grpc-1", "port": 9001, "targetPort": 9001, "protocol": "TCP"},
        ])
        policies = [d for d in docs if d["kind"] == "NetworkPolicy"]
        egress = next(d["spec"]["egress"] for d in policies if d["metadata"]["name"].endswith("-host-egress"))
        ingress = next(d["spec"]["ingress"] for d in policies if d["metadata"]["name"].endswith("-harness-ingress"))
        ports = [{"protocol": "TCP", "port": 9000}, {"protocol": "TCP", "port": 9001}]
        self.assertEqual(egress[2]["ports"], ports)
        self.assertEqual(ingress[0]["ports"], ports)
        self.assertEqual(egress[1]["ports"], [{"protocol": "TCP", "port": 443}])
        self.assertIn("10.0.0.0/8", egress[1]["to"][0]["ipBlock"]["except"])
        affinity = host["affinity"]["podAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"][0]
        self.assertEqual(affinity["topologyKey"], "kubernetes.io/hostname")

    def test_operator_notes_follow_profile(self):
        # Helm does not emit NOTES.txt as a manifest. Render those same bytes as
        # a temporary ConfigMap block through the real engine, without a cluster.
        with tempfile.TemporaryDirectory() as temp:
            chart = Path(temp) / "chart"
            shutil.copytree(CHART, chart)
            notes = (chart / "templates/NOTES.txt").read_text()
            wrapper = "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: test-notes}\ndata:\n  notes: |\n"
            (chart / "templates/operator-notes.yaml").write_text(wrapper + "\n".join("    " + line for line in notes.splitlines()) + "\n")
            for native, values in ((False, self.defaults), (True, self.native_values())):
                with self.subTest(native=native), tempfile.NamedTemporaryFile(mode="w", suffix=".json") as source:
                    json.dump(values, source)
                    source.flush()
                    result = helm("template", "test", chart, "--namespace", "agents", "--kube-version", "1.37.0", "-f", source.name)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    rendered = next(doc["data"]["notes"] for doc in yaml.safe_load_all(result.stdout) if doc and doc.get("metadata", {}).get("name") == "test-notes")
                    if native:
                        self.assertIn("/host health-probe", rendered)
                        self.assertNotIn("/session-fixture", rendered)
                    else:
                        self.assertIn("/session-fixture", rendered)

    def test_native_inventory_refusals(self):
        for entries, fragment in (
            ([], "entries"),
            ([{"id": "bundle-v4-not-a-digest", "port": 9000}], "id"),
            ([{"id": "bundle-v4-" + "a" * 64, "port": 0}], "port"),
            ([{"id": "bundle-v4-" + "a" * 64, "port": 8081}], "port"),
            ([{"id": "bundle-v4-" + "a" * 64, "port": 65536}], "port"),
            ([{"id": "bundle-v4-" + "a" * 64, "port": 9000, "command": "extra"}], "command"),
            ([{"id": "bundle-v4-" + "a" * 64, "port": 9000}, {"id": "bundle-v4-" + "a" * 64, "port": 9001}], "unique"),
            ([{"id": "bundle-v4-" + "a" * 64, "port": 9000}, {"id": "bundle-v4-" + "b" * 64, "port": 9000}], "unique"),
        ):
            with self.subTest(entries=entries):
                values = self.native_values()
                values["harness"]["native"]["entries"] = entries
                result = render(values)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(fragment, result.stderr)
        values = self.native_values()
        values["harness"]["native"]["inventory"] = "/tmp/untrusted.json"
        result = render(values)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("inventory", result.stderr)
        values = self.native_values()
        values["auth"]["mode"] = "required"
        values["auth"]["tlsSecretName"] = ""
        result = render(values)
        self.assertNotEqual(result.returncode, 0, "native profile must not bypass TLS/identity gates")
        self.assertIn("tlsSecretName", result.stderr)

    def test_network_policy_opt_out(self):
        values = copy.deepcopy(self.defaults)
        values["networkPolicy"] = {"enabled": False}
        self.assertFalse(any(d["kind"] == "NetworkPolicy" for d in self.documents(values)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
