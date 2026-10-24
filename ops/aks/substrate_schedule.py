"""Bounded, read-only evidence lookup for the reviewed PUBLISHED_IMAGES source."""
import datetime
import io
import json
import subprocess
import time
import zipfile

REPO = "Azure/aks-durable-agents"


class EvidenceError(ValueError):
    def __init__(self):
        # Preparation installs the repository import root; selection never imports this.
        from ops.demo.e2e import SUBSTRATE_EVIDENCE_RECOVERY
        super().__init__("Substrate evidence lookup or revalidation failed. " + SUBSTRATE_EVIDENCE_RECOVERY)


def resolve(manifest, command, deadline):
    try:
        return _resolve(manifest, command, deadline)
    except (ValueError, KeyError, TypeError, AttributeError, OSError, RuntimeError, zipfile.BadZipFile, subprocess.SubprocessError):
        raise EvidenceError() from None


def _resolve(manifest, command, deadline):
    from substrate_inputs import verified_run

    from ops.images import substrate_images, update_pins

    update_pins.validate_manifest(manifest)
    source = manifest["sourceCommit"]
    end = min(deadline, time.monotonic() + 60)
    downloads = {"verified": 0, "published": 0}

    def request(path):
        left = end - time.monotonic()
        if left <= 0:
            raise EvidenceError()
        return command(["gh", "api", "repos/" + REPO + "/" + path], limit=min(30, left))

    def pages(path, key, *, allow_prefix=False):
        rows = []
        for page in range(1, 6):
            separator = "&" if "?" in path else "?"
            data = json.loads(request(path + separator + f"per_page=100&page={page}"))
            batch = data[key]
            if not isinstance(batch, list):
                raise EvidenceError()
            rows.extend(batch)
            if len(batch) < 100:
                return rows
        if allow_prefix:
            return rows
        raise EvidenceError()

    def identifier(value):
        if type(value) is not int or not 0 < value < 10**20:
            raise EvidenceError()
        return str(value)

    def retained(item):
        return (isinstance(item, dict) and item.get("expired") is False
                and datetime.datetime.fromisoformat(item["expires_at"]) > datetime.datetime.now(datetime.timezone.utc))

    def read_pair(item, kind):
        downloads[kind] += 1
        if downloads[kind] > 20:
            raise EvidenceError()
        raw = request("actions/artifacts/" + identifier(item["id"]) + "/zip")
        values = []
        # Read only two bounded JSON members; do not extract SBOMs or archive paths.
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = archive.infolist()
            if len(members) > 256:
                raise EvidenceError()
            for name in ("substrate-publication.json", "substrate-images.json"):
                matches = [entry for entry in members if entry.filename == name]
                if len(matches) != 1 or matches[0].file_size > 256 * 1024:
                    raise EvidenceError()
                with archive.open(matches[0]) as member:
                    data = member.read(256 * 1024 + 1)
                if len(data) > 256 * 1024:
                    raise EvidenceError()
                values.append(json.loads(data, object_pairs_hook=update_pins.unique_object))
        return tuple(values)

    publishers = []
    for run in pages("actions/workflows/images.yml/runs?branch=main&status=success&head_sha=" + source, "workflow_runs"):
        try:
            update_pins.validate_run(run, manifest)
        except (ValueError, AttributeError):
            continue
        if run.get("status") == "completed" and run.get("head_repository", {}).get("full_name") == REPO:
            publishers.append(run)
    candidates = [a for a in pages("actions/artifacts?name=verified-substrate-images", "artifacts", allow_prefix=True)
                  if a.get("name") == "verified-substrate-images" and isinstance(a.get("workflow_run"), dict) and retained(a)]
    # A verifier may execute on newer main. Its actual receipt, not this hint,
    # must bind the reviewed source. Never substitute another source's images.
    candidates.sort(key=lambda a: a["workflow_run"].get("head_sha") != source)
    published = {}
    for index, item in enumerate(candidates):
        if index >= 20:
            raise EvidenceError()
        verify_id = identifier(item["workflow_run"]["id"])
        if sum(a["workflow_run"]["id"] == int(verify_id) for a in candidates) != 1:
            raise EvidenceError()
        verification = json.loads(request("actions/runs/" + verify_id))
        try:
            verified_run(verification, verify_id)
        except (ValueError, AttributeError):
            continue
        # The repository prefix is a search bound, not a uniqueness proof.
        # Check the complete owning-run listing before selecting an artifact ID.
        run_artifacts = pages("actions/runs/" + verify_id + "/artifacts", "artifacts")
        matches = [a for a in run_artifacts if a.get("name") == "verified-substrate-images" and retained(a)]
        if len(matches) != 1 or matches[0]["id"] != item["id"]:
            raise EvidenceError()
        receipt, mapping = read_pair(item, "verified")
        substrate_images.validate_publication(receipt)
        if receipt["workflowCommit"] != source:
            continue
        substrate_images.refs(receipt, mapping)
        for run in publishers:
            publish_id = identifier(run["id"])
            if publish_id not in published:
                artifacts = pages("actions/runs/" + publish_id + "/artifacts", "artifacts")
                matches = [a for a in artifacts if a.get("name") == "published-substrate-images" and retained(a)]
                if len(matches) > 1:
                    raise EvidenceError()
                published[publish_id] = read_pair(matches[0], "published") if matches else None
            pair = published[publish_id]
            if pair is not None and pair == (receipt, mapping):
                substrate_images.validate_run(receipt, mapping, run)
                if time.monotonic() >= end:
                    raise EvidenceError()
                return publish_id, verify_id, source
    raise EvidenceError()
