"""Receipt boundaries for the separately published production replay helper."""
import copy
import importlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

CLI = Path(__file__).with_name("backup_helper.py")
HOST = "ghcr.io/azure/aks-durable-agents/host"
HELPER = "ghcr.io/azure/aks-durable-agents/backup-helper"


def receipt():
    return {"version": 1, "sourceCommit": "a" * 40,
            "hostDigest": "sha256:" + "b" * 64,
            "image": HELPER + "@sha256:" + "c" * 64}


class BackupHelperTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(CLI.is_file(), "backup helper receipt implementation is missing")
        self.helper = importlib.import_module("backup_helper")

    def test_receipt_binds_helper_to_source_and_production_host(self):
        data = receipt()
        self.assertEqual(self.helper.create_receipt("a" * 40, "sha256:" + "b" * 64,
                                                  "sha256:" + "c" * 64), data)
        self.assertEqual(self.helper.validate_receipt(data), data)
        self.assertEqual(self.helper.validate_host(data, HOST + "@sha256:" + "b" * 64),
                         HELPER + "@sha256:" + "c" * 64)

    def test_closed_receipt_rejects_ambiguous_or_mutable_publication(self):
        cases = [None, [], {}, dict(receipt(), extra=True)]
        for field, values in {
            "version": [True, 0, 2, "1"],
            "sourceCommit": [None, "", "a" * 39, "A" * 40, "main", "a" * 40 + "\n"],
            "hostDigest": [None, "", "b" * 64, "sha256:" + "B" * 64, "sha256:" + "b" * 63],
            "image": [None, HELPER + ":main", HOST + "@sha256:" + "c" * 64,
                      HELPER + "@sha256:" + "c" * 63, HELPER + ":v1@sha256:" + "c" * 64],
        }.items():
            for value in values:
                data = copy.deepcopy(receipt())
                data[field] = value
                cases.append(data)
        for data in cases:
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.helper.validate_receipt(data)
        for field in receipt():
            data = receipt()
            del data[field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                self.helper.validate_receipt(data)

    def test_consumer_refuses_mismatch_or_unpinned_rendered_host_before_use(self):
        for image in [HOST + "@sha256:" + "d" * 64, HOST + ":main", "",
                      HELPER + "@sha256:" + "b" * 64,
                      HOST + ":main@sha256:" + "b" * 64, None]:
            with self.subTest(image=image), self.assertRaises(ValueError):
                self.helper.validate_host(receipt(), image)
        data = dict(receipt(), extra=True)
        with self.assertRaises(ValueError):
            self.helper.validate_host(data, HOST + "@sha256:" + "b" * 64)

    def test_cli_creates_and_validates_receipt_without_overwriting(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "backup-helper.json"
            command = [sys.executable, "-B", str(CLI), "create", "--source-commit", "a" * 40,
                       "--host-digest", "sha256:" + "b" * 64,
                       "--helper-digest", "sha256:" + "c" * 64, "--output", str(path)]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(path.read_text()), receipt())
            original = path.read_bytes()
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(path.read_bytes(), original)
            validate = [sys.executable, "-B", str(CLI), "validate", "--receipt", str(path),
                        "--host-image", HOST + "@sha256:" + "b" * 64]
            result = subprocess.run(validate, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), HELPER + "@sha256:" + "c" * 64)
            validate[-1] = HOST + "@sha256:" + "d" * 64
            result = subprocess.run(validate, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertIn("host digest", result.stderr)
            path.write_text(json.dumps(receipt()).replace('"version": 1', '"version": 2, "version": 1'))
            result = subprocess.run(validate, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("duplicate JSON key", result.stderr)

    def test_invalid_creation_leaves_no_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "backup-helper.json"
            result = subprocess.run([sys.executable, "-B", str(CLI), "create", "--source-commit", "main",
                                     "--host-digest", "sha256:" + "b" * 64,
                                     "--helper-digest", "sha256:" + "c" * 64, "--output", str(path)],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
