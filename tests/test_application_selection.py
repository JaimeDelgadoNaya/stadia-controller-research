"""Device-free regression tests for the recorded application selector."""
import copy
import json
import unittest
from pathlib import Path
from tools.audit_application_selection import audit, verified_instructions


class ApplicationSelectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads((Path(__file__).resolve().parents[1] /
                                   "evidence/bootloader-analysis.json").read_text(encoding="utf-8"))
        cls.report = audit(cls.evidence)

    def test_offline_verified_region(self):
        self.assertEqual(self.report["region"], "0x60801ef0")
        self.assertFalse(self.report["hardware_access"])
        self.assertEqual(len(self.report["scenarios"]), 6)

    def test_validation_and_slot_selection(self):
        rows = {(row["selected_id"], row["validation_success"]): row
                for row in self.report["scenarios"]}
        for slot, base, failure in ((2, "0x60040000", "0x10"),
                                    (3, "0x60840000", "0x20")):
            self.assertEqual(rows[slot, True]["application_base"], base)
            self.assertEqual(rows[slot, True]["action"], "prepare_vector_table_and_branch")
            self.assertEqual(rows[slot, True]["vtor"], "0xe000ed08")
            self.assertEqual(rows[slot, False]["action"], "write_boot_status_and_return")
            self.assertEqual(rows[slot, False]["status_register"], "0x400f8038")
            self.assertEqual(rows[slot, False]["status_value"], failure)

    def test_unknown_selector_does_not_dispatch(self):
        for row in self.report["scenarios"]:
            if row["selected_id"] not in (2, 3):
                self.assertEqual(row["action"], "return_without_dispatch")
                self.assertNotIn("status_register", row)

    def test_altered_machine_bytes_rejected(self):
        data = copy.deepcopy(self.evidence)
        region = next(r for r in data["functions"] if r["start"] == "0x60801ef0")
        ins = region["instructions"][0]
        changed = bytearray.fromhex(ins["bytes"])
        changed[0] ^= 1
        ins["bytes"] = changed.hex()
        with self.assertRaisesRegex(ValueError, "fingerprint mismatch"):
            verified_instructions(data)

    def test_altered_image_identity_rejected(self):
        data = copy.deepcopy(self.evidence)
        data["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "recorded bootloader"):
            audit(data)

    def test_untrusted_literal_rejected(self):
        data = copy.deepcopy(self.evidence)
        region = next(r for r in data["functions"] if r["start"] == "0x60801ef0")
        entry = next(x for x in region["instructions"] if x["address"] == "0x60801efa")
        entry["literal_uint32"] = "0x20000000"
        with self.assertRaisesRegex(ValueError, "Unexpected literals"):
            audit(data)


if __name__ == "__main__":
    unittest.main()
