"""Offline preparation tests using a temporary local Git repository."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from tools import prepare_external_bridge as m


class PrepareBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        m.git("init", self.source)
        m.git("-C", self.source, "config", "user.name", "Offline Test")
        m.git("-C", self.source, "config", "user.email", "test@example.invalid")
        m.git("-C", self.source, "config", "core.autocrlf", "false")
        (self.source / "source.c").write_bytes(b"test source\n")
        m.git("-C", self.source, "add", ".")
        m.git("-C", self.source, "commit", "-m", "fixture")
        self.manifest = {"source": str(self.source), "commit": m.git("-C", self.source, "rev-parse", "HEAD"),
                         "license": "test fixture", "sha256": {"source.c": hashlib.sha256(b"test source\n").hexdigest()}}

    def test_fetches_exact_commit_even_when_default_branch_advances(self):
        (self.source / "source.c").write_bytes(b"later source\n")
        m.git("-C", self.source, "commit", "-am", "advance")
        target = self.root / "checkout"
        result = m.prepare(target, self.manifest)
        self.assertEqual((target / "source.c").read_bytes(), b"test source\n")
        self.assertEqual(json.loads((target / "stadia-research-provenance.json").read_text()), result)
        with self.assertRaises(subprocess.CalledProcessError):
            m.git("-C", target, "symbolic-ref", "-q", "HEAD")

    def test_nonempty_target_is_preserved(self):
        target = self.root / "checkout"
        target.mkdir()
        (target / "keep").write_text("untouched")
        with self.assertRaisesRegex(ValueError, "empty"):
            m.prepare(target, self.manifest)
        self.assertEqual((target / "keep").read_text(), "untouched")

    def test_tampered_selected_source_is_rejected(self):
        target = self.root / "checkout"
        m.prepare(target, self.manifest)
        (target / "source.c").write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            m.verify_checkout(target, self.manifest)

    def test_mismatched_commit_is_rejected(self):
        target = self.root / "checkout"
        m.prepare(target, self.manifest)
        self.manifest["commit"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "HEAD"):
            m.verify_checkout(target, self.manifest)


if __name__ == "__main__":
    unittest.main()
