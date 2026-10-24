"""Exact-source lookup against fake GitHub responses; never a publication or deployment."""
import copy
import io
import json
import sys
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import substrate_schedule as schedule

ROOT = Path(__file__).resolve().parents[2]
original_path = sys.path[:]
try:
    sys.path[:0] = [str(ROOT), str(ROOT / "ops/images")]
    from ops.images import substrate_images as images
    from ops.images import update_pins
finally:
    sys.path[:] = original_path

SOURCE = "a" * 40


def run_metadata(identifier, verify=False):
    return {"id": identifier, "status": "completed", "conclusion": "success", "head_branch": "main", "head_sha": SOURCE,
            "event": "workflow_run" if verify else "push", "path": ".github/workflows/image-pins.yml" if verify else ".github/workflows/images.yml",
            "repository": {"full_name": schedule.REPO}, "head_repository": {"full_name": schedule.REPO}}


def artifact(identifier, run_id, name):
    return {"id": identifier, "name": name, "expired": False, "expires_at": "9999-12-31T23:59:59Z",
            "workflow_run": {"id": run_id, "head_sha": SOURCE, "head_branch": "main"}}


def archive(publication, mapping):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as output:
        output.writestr("substrate-publication.json", json.dumps(publication))
        output.writestr("substrate-images.json", json.dumps(mapping))
        output.writestr("ignored-sbom.json", "not read as input")
    return buffer.getvalue()


class FakeGitHub:
    def __init__(self):
        self.calls = []
        self.manifest = {"version": 1, "sourceCommit": SOURCE, "images": {role: {"repository": repo, "digest": "sha256:" + "d" * 64} for role, repo in update_pins.REPOSITORIES.items()}}
        self.pub = {"version": 1, "workflowCommit": SOURCE, "substrateCommit": images.SUBSTRATE_COMMIT, "pauseCommit": images.PAUSE_COMMIT,
                    "images": {role: images.PREFIX + role + "@sha256:" + "b" * 64 for role in images.ROLES}}
        self.mapping = images.installer_map(self.pub)
        self.runs = {123: run_metadata(123), 456: run_metadata(456, True)}
        self.publishers = [self.runs[123]]
        self.artifacts = [artifact(20, 456, "verified-substrate-images")]
        self.published = {123: [artifact(10, 123, "published-substrate-images")],
                          456: [artifact(20, 456, "verified-substrate-images")]}
        self.zips = {10: archive(self.pub, self.mapping), 20: archive(self.pub, self.mapping)}

    def command(self, args, *, limit=300):
        self.calls.append(args)
        assert args[:2] == ["gh", "api"] and 0 < limit <= 60, args
        path = args[2].split("?", 1)[0]
        if "/actions/workflows/images.yml/runs" in path:
            assert "head_sha=" + SOURCE in args[2] and "branch=main" in args[2]
            value = {"workflow_runs": self.publishers}
        elif path.endswith("/actions/artifacts"):
            value = {"artifacts": self.artifacts}
        elif path.endswith("/artifacts"):
            value = {"artifacts": self.published.get(int(path.split("/")[-2]), [])}
        elif path.endswith("/zip"):
            return self.zips[int(path.split("/")[-2])]
        else:
            value = self.runs[int(path.split("/")[-1])]
        return json.dumps(value).encode()

    def resolve(self):
        return schedule.resolve(self.manifest, self.command, time.monotonic() + 840)


class ScheduledEvidenceTests(unittest.TestCase):
    def test_retained_exact_source_pair_not_latest_source(self):
        api = FakeGitHub()
        other = artifact(99, 999, "verified-substrate-images")
        other["workflow_run"]["head_sha"] = "f" * 40
        api.artifacts.insert(0, other)
        self.assertEqual(api.resolve(), ("123", "456", SOURCE))
        self.assertFalse(any("runs/999" in c[2] for c in api.calls))

    def test_verifier_can_run_newer_main_but_verified_publication_must_match_pin(self):
        api = FakeGitHub()
        api.artifacts[0]["workflow_run"]["head_sha"] = "f" * 40
        api.runs[456]["head_sha"] = "f" * 40
        self.assertEqual(api.resolve(), ("123", "456", SOURCE))

    def refusal(self, api):
        with self.assertRaises(schedule.EvidenceError) as caught:
            api.resolve()
        text = str(caught.exception)
        self.assertIn("Re-run", text)
        self.assertIn("Images", text)
        self.assertIn("PUBLISHED_IMAGES", text)
        self.assertIn("30-day", text)
        self.assertIn("refresh", text)
        self.assertNotIn("PRIVATE_SENTINEL", text)

    def test_missing_expired_and_ambiguous_artifacts_fail_closed(self):
        for failure in ("missing verified", "expired verified", "date expired", "missing published", "expired published", "duplicate published", "duplicate verified", "duplicate outside prefix"):
            with self.subTest(failure=failure):
                api = FakeGitHub()
                if failure == "missing verified": api.artifacts = []
                if failure == "expired verified": api.artifacts[0]["expired"] = True
                if failure == "date expired": api.artifacts[0]["expires_at"] = "2000-01-01T00:00:00Z"
                if failure == "missing published": api.published[123] = []
                if failure == "expired published": api.published[123][0]["expired"] = True
                if failure == "duplicate published": api.published[123].append(artifact(11, 123, "published-substrate-images"))
                if failure == "duplicate verified": api.artifacts.append(artifact(21, 456, "verified-substrate-images"))
                if failure == "duplicate outside prefix": api.published[456].append(artifact(21, 456, "verified-substrate-images"))
                self.refusal(api)

    def test_wrong_producer_metadata_refuses_without_untrusted_archive_download(self):
        for identifier in (123, 456):
            for key, value in (("conclusion", "failure"), ("status", "in_progress"), ("head_branch", "untrusted"),
                               ("repository", {"full_name": "untrusted/fork"}), ("head_repository", {"full_name": "untrusted/fork"}),
                               ("path", "PRIVATE_SENTINEL"), ("event", "pull_request")):
                with self.subTest(identifier=identifier, key=key):
                    api = FakeGitHub()
                    api.runs[identifier][key] = value
                    self.refusal(api)
                    blocked = "/artifacts/10/zip" if identifier == 123 else "/artifacts/20/zip"
                    self.assertFalse(any(blocked in c[2] for c in api.calls))

    def test_source_map_and_receipts_cannot_be_swapped_or_mismatched(self):
        for failure in ("source", "native source", "map", "publication", "duplicate keys", "oversized"):
            with self.subTest(failure=failure):
                api = FakeGitHub()
                publication, mapping = copy.deepcopy(api.pub), copy.deepcopy(api.mapping)
                if failure == "source": publication["workflowCommit"] = images.SUBSTRATE_COMMIT
                if failure == "native source": mapping["sourceCommit"] = SOURCE
                if failure == "map": mapping["images"]["probe"] = "PRIVATE_SENTINEL"
                if failure == "publication": publication["images"]["ateapi"] = images.PREFIX + "ateapi@sha256:" + "c" * 64
                api.zips[20] = archive(publication, mapping)
                if failure in ("duplicate keys", "oversized"):
                    output = io.BytesIO()
                    with zipfile.ZipFile(output, "w") as z:
                        z.writestr("substrate-publication.json", '{"version":1,"version":2}' if failure == "duplicate keys" else " " * (256 * 1024 + 1))
                        z.writestr("substrate-images.json", json.dumps(mapping))
                    api.zips[20] = output.getvalue()
                self.refusal(api)

    def test_same_source_runs_must_pair_by_contents_not_newest_publisher(self):
        api = FakeGitHub()
        api.runs[124] = run_metadata(124)
        api.publishers.insert(0, api.runs[124])
        api.published[124] = [artifact(11, 124, "published-substrate-images")]
        other = copy.deepcopy(api.pub)
        other["images"]["ateapi"] = images.PREFIX + "ateapi@sha256:" + "c" * 64
        api.zips[11] = archive(other, images.installer_map(other))
        self.assertEqual(api.resolve(), ("123", "456", SOURCE))

    def test_full_page_bound_does_not_discard_an_available_exact_source_pair(self):
        api = FakeGitHub()
        original = api.command
        def full_pages(args, *, limit=300):
            if "/actions/artifacts?name=" in args[2]:
                api.calls.append(args)
                rows = [dict(api.artifacts[0], expired=True)] * 100
                if args[2].endswith("page=1"):
                    rows[0] = api.artifacts[0]
                return json.dumps({"artifacts": rows}).encode()
            return original(args, limit=limit)
        api.command = full_pages
        self.assertEqual(api.resolve(), ("123", "456", SOURCE))
        self.assertEqual(sum("/actions/artifacts?name=" in c[2] for c in api.calls), 5)

    def test_unrelated_artifact_without_workflow_provenance_is_not_a_candidate(self):
        api = FakeGitHub()
        api.artifacts.insert(0, dict(api.artifacts[0], id=99, workflow_run=None))
        self.assertEqual(api.resolve(), ("123", "456", SOURCE))

    def test_lookup_pagination_and_download_counts_are_bounded(self):
        api = FakeGitHub()
        original = api.command
        def full_pages(args, *, limit=300):
            if "/actions/artifacts?name=" in args[2]:
                api.calls.append(args)
                return json.dumps({"artifacts": [dict(api.artifacts[0], expired=True)] * 100}).encode()
            return original(args, limit=limit)
        api.command = full_pages
        self.refusal(api)
        self.assertEqual(sum("/actions/artifacts?name=" in c[2] for c in api.calls), 5)
        for kind in ("verified", "published"):
            with self.subTest(kind=kind):
                api = FakeGitHub()
                other = copy.deepcopy(api.pub)
                if kind == "verified":
                    other["workflowCommit"] = "f" * 40
                    api.artifacts = []
                    for n in range(21):
                        api.runs[1000+n] = run_metadata(1000+n, True)
                        api.artifacts.append(artifact(2000+n, 1000+n, "verified-substrate-images"))
                        api.published[1000+n] = [artifact(2000+n, 1000+n, "verified-substrate-images")]
                        api.zips[2000+n] = archive(other, api.mapping)
                else:
                    other["images"]["ateapi"] = images.PREFIX + "ateapi@sha256:" + "c" * 64
                    api.publishers = []
                    for n in range(21):
                        api.runs[1000+n] = run_metadata(1000+n)
                        api.publishers.append(api.runs[1000+n])
                        api.published[1000+n] = [artifact(2000+n, 1000+n, "published-substrate-images")]
                        api.zips[2000+n] = archive(other, images.installer_map(other))
                self.refusal(api)
                # Published lookup also reads one verified ZIP; neither kind exceeds20.
                self.assertEqual(sum(c[2].endswith("/zip") for c in api.calls), 20 if kind == "verified" else 21)

    def test_lookup_limits_fail_with_recovery_not_generic_deadline_or_raw_details(self):
        api = FakeGitHub()
        clock = [100.0]
        original = api.command
        def slow(args, *, limit=300):
            value = original(args, limit=limit)
            clock[0] += 61
            return value
        api.command = slow
        with patch.object(schedule.time, "monotonic", side_effect=lambda: clock[0]): self.refusal(api)
        api = FakeGitHub()
        def broken(args, *, limit=300): raise OSError("PRIVATE_SENTINEL")
        api.command = broken
        self.refusal(api)


if __name__ == "__main__": unittest.main()
