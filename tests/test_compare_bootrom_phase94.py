"""Synthetic tests for offline, read-only phase94 comparator; NO real ROM or USB."""
import tempfile
from pathlib import Path
import unittest
from tools import compare_bootrom_phase94 as m

class CompareBootROMPhase94Tests(unittest.TestCase):
    def setUp(self):
        self.reference = bytes(i % 251 for i in range(m.ROM_SIZE))
        self.test_hash = m.digest(self.reference)

    def test_no_images_gives_no_verification(self):
        r = m.compare(None, None)
        self.assertEqual(r["status"], "REFERENCE_MISSING")
        self.assertFalse(r["actual_stadia_exploit_execution_verified"])
        self.assertFalse(r["stadia_rom_provenance_verified"])

    def test_reference_only_is_not_candidate(self):
        r = m.compare(self.reference, None, self.test_hash)
        self.assertEqual(r["status"], "CANDIDATE_MISSING")

    def test_reference_hash_must_match(self):
        r = m.compare(self.reference, self.reference)
        self.assertEqual(r["status"], "UNVERIFIED_REFERENCE_HASH")
        self.assertIsNone(r["exact_binary_match"])

    def test_matching_bytes_without_provenance(self):
        r = m.compare(self.reference, bytes(self.reference), self.test_hash)
        self.assertEqual(r["status"], "REFERENCE_IDENTICAL_BYTES_PROVENANCE_UNVERIFIED")
        self.assertTrue(r["exact_binary_match"])
        self.assertEqual(len(r["anchor_windows"]), 7)
        self.assertTrue(all(x["match"] for x in r["anchor_windows"].values()))
        self.assertFalse(r["actual_stadia_exploit_execution_verified"])

    def test_non_anchor_change_is_not_exact(self):
        altered = bytearray(self.reference)
        altered[0x100] ^= 1
        r = m.compare(self.reference, bytes(altered), self.test_hash)
        self.assertEqual(r["status"], "ONLY_SELECTED_REFERENCE_WINDOWS_MATCH")
        self.assertFalse(r["exact_binary_match"])

    def test_detects_hid_and_hab_mismatches(self):
        altered = bytearray(self.reference)
        altered[0x0020EA7E - m.ROM_BASE] ^= 1
        altered[0x002147F8 - m.ROM_BASE] ^= 1
        r = m.compare(self.reference, bytes(altered), self.test_hash)
        self.assertEqual(r["status"], "REFERENCE_ANCHOR_MISMATCH")
        self.assertFalse(r["anchor_windows"]["sdp_hid_callback"]["match"])
        self.assertFalse(r["anchor_windows"]["HAB_GET_CONFIG_FN"]["match"])

    def test_wrong_binary_size_fails(self):
        with self.assertRaises(ValueError):
            m.compare(b"short", None)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "wrong.bin"
            p.write_bytes(b"\xff" * 128)
            with self.assertRaises(ValueError):
                m.read_rom(p)

    def test_invalid_window_fails(self):
        for length in (0, 257):
            with self.assertRaises(ValueError):
                m.compare(None, None, window_bytes=length)

if __name__ == "__main__":
    unittest.main(verbosity=2)
