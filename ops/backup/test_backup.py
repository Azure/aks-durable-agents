"""Safety boundaries: stopped snapshots, integrity and isolated recovery inputs."""
import importlib.util
import io
import json
import os
import socket
import sqlite3
import tarfile
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("backup", Path(__file__).with_name("backup.py"))
backup = importlib.util.module_from_spec(spec)
if spec.loader and spec.origin and Path(spec.origin).exists():
    spec.loader.exec_module(backup)


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir(mode=0o700)

    def database(self, name):
        db = sqlite3.connect(self.source / name)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("CREATE TABLE receipt (value TEXT)")
        db.execute("INSERT INTO receipt VALUES ('durable')")
        db.commit()
        os.chmod(self.source / name, 0o600)
        self.addCleanup(db.close)
        return db

    def archive(self):
        stream = io.BytesIO()
        backup.pack(self.source, stream)
        stream.seek(0)
        return stream

    def test_wal_checkpoint_changes_only_copy_and_preserves_receipts_and_ledger(self):
        # Leaving connections open deliberately keeps committed rows in WAL. The
        # caller's writer fence is tested on kind; pack must never open this DB.
        for name in ("journal.db", "publications.db", "real-attempts.db"):
            self.database(name)
        (self.source / "instructions.txt").write_text("recorded instructions")
        before = {p.name: p.read_bytes() for p in self.source.iterdir()}
        dest = self.root / "restored"
        dest.mkdir(mode=0o700)
        backup.unpack(dest, self.archive())
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.source.iterdir()})
        for name in ("journal.db", "publications.db", "real-attempts.db"):
            with sqlite3.connect(dest / name) as db:
                self.assertEqual(db.execute("SELECT value FROM receipt").fetchall(), [("durable",)])
            self.assertEqual((dest / name).stat().st_mode & 0o777, 0o600)
        self.assertEqual((dest / "instructions.txt").read_text(), "recorded instructions")
        backup.verify(dest)

    def test_runtime_sockets_and_tmp_trees_are_not_backed_up(self):
        self.database("journal.db")
        s = socket.socket(socket.AF_UNIX)
        self.addCleanup(s.close)
        s.bind(str(self.source / "publish.sock"))
        (self.source / "tmp-daemon").mkdir()
        (self.source / "tmp-daemon" / "stale").write_text("runtime")
        stream = self.archive()
        with tarfile.open(fileobj=stream, mode="r:gz") as tar:
            names = tar.getnames()
            self.assertNotIn("data/publish.sock", names)
            self.assertNotIn("data/tmp-daemon/stale", names)
            manifest = json.load(tar.extractfile("manifest.json"))
            self.assertIn("publish.sock", manifest["excluded"])
            self.assertIn("tmp-daemon", manifest["excluded"])

    def test_symlink_and_corrupt_database_refused(self):
        (self.source / "journal.db").write_bytes(b"SQLite format 3\x00broken")
        with self.assertRaises((ValueError, sqlite3.DatabaseError)):
            self.archive()
        (self.source / "journal.db").unlink()
        self.database("journal.db")
        (self.source / "instructions.txt").symlink_to("/etc/passwd")
        with self.assertRaisesRegex(ValueError, "symlink in data: instructions.txt"):
            self.archive()

    def test_corrupt_or_truncated_wal_refused_before_sqlite_can_discard_rows(self):
        db = self.database("journal.db")
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        db.execute("INSERT INTO receipt VALUES ('committed-in-wal')")
        db.commit()
        wal = self.source / "journal.db-wal"
        original = wal.read_bytes()
        self.assertGreater(len(original), 32)
        for offset in (0, 24, 40, 48, len(original) - 1, None):
            with self.subTest(offset=offset):
                damaged = bytearray(original)
                if offset is None:
                    damaged = damaged[:-1]
                else:
                    damaged[offset] ^= 0x01
                wal.write_bytes(damaged)
                with self.assertRaisesRegex(ValueError, "invalid WAL"):
                    self.archive()
                wal.write_bytes(original)

    def test_hot_rollback_journal_requires_separate_operator_recovery(self):
        self.database("journal.db")
        (self.source / "journal.db-journal").write_bytes(b"ambiguous rollback state")
        with self.assertRaisesRegex(ValueError, "nonempty rollback journal"):
            self.archive()

    def test_corrupt_receipt_store_cannot_hide_by_losing_sqlite_header(self):
        self.database("journal.db")
        (self.source / "publications.db").write_bytes(b"damaged header")
        with self.assertRaisesRegex(ValueError, "invalid SQLite header: .*publications.db"):
            self.archive()

    def test_source_root_symlink_and_unsafe_restored_modes_refused(self):
        self.database("journal.db")
        alias = self.root / "alias"
        alias.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(ValueError):
            backup.pack(alias, io.BytesIO())
        dest = self.root / "restored"
        dest.mkdir(mode=0o700)
        backup.unpack(dest, self.archive())
        (dest / "journal.db").chmod(0o644)
        with self.assertRaises(ValueError):
            backup.verify(dest)

    def test_tampering_and_unsafe_archive_paths_refused_without_overwrite(self):
        self.database("journal.db")
        stream = self.archive()
        members = []
        with tarfile.open(fileobj=stream, mode="r:gz") as tar:
            for item in tar.getmembers():
                if item.isfile():
                    members.append((item.name, tar.extractfile(item).read()))
        for name, data in [("../escape", b"bad"), ("data/journal.db", b"tampered")]:
            with self.subTest(name=name):
                bad = io.BytesIO()
                with tarfile.open(fileobj=bad, mode="w:gz") as tar:
                    for path, content in members:
                        if path == name:
                            content = data
                        item = tarfile.TarInfo(path)
                        item.size = len(content)
                        tar.addfile(item, io.BytesIO(content))
                    if name.startswith(".."):
                        item = tarfile.TarInfo(name)
                        item.size = len(data)
                        tar.addfile(item, io.BytesIO(data))
                bad.seek(0)
                dest = self.root / name.replace("/", "_")
                dest.mkdir()
                with self.assertRaises(ValueError):
                    backup.unpack(dest, bad)
                self.assertFalse((self.root / "escape").exists())
        dest = self.root / "not-empty"
        dest.mkdir()
        (dest / "keep").write_text("original")
        with self.assertRaises(ValueError):
            backup.unpack(dest, self.archive())
        self.assertEqual((dest / "keep").read_text(), "original")


class FenceTests(unittest.TestCase):
    def test_live_unlabelled_and_terminating_pvc_consumers_refused(self):
        for phase, deleting in [("Running", False), ("Pending", False), ("Unknown", False), ("Running", True)]:
            pod = {"metadata": {"name": "unlabelled-writer"}, "spec": {"volumes": [{"persistentVolumeClaim": {"claimName": "source"}}]}, "status": {"phase": phase}}
            if deleting:
                pod["metadata"]["deletionTimestamp"] = "2026-01-01T00:00:00Z"
            with self.subTest(phase=phase, deleting=deleting), self.assertRaisesRegex(ValueError, "PVC still has a possible writer: unlabelled-writer"):
                backup.assert_no_consumers([pod], "source")
        backup.assert_no_consumers([dict(pod, status={"phase": "Succeeded"})], "source")


if __name__ == "__main__":
    unittest.main()
