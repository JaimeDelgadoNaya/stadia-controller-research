"""Offline phase-12 audit tests: synthetic fixtures plus recorded evidence."""
import json
import unittest
from pathlib import Path

from tools.trace_write_path import (ANCHORS, DIRECT_PATH, EXPECTED_BUILD,
                                    EXPECTED_IMAGE, SIZE, scan)


def fixture():
    """Small synthetic corpus with required callsites, not OEM firmware."""
    records = {at: {"address": hex(at), "bytes": "00", "mnemonic": mnemonic,
                    "operands": operands} for at, (mnemonic, operands) in ANCHORS.items()}
    for site, target in DIRECT_PATH:
        records[site] = {"address": hex(site), "bytes": "00", "mnemonic": "bl",
                         "operands": f"#{target:#x}", "direct_target": hex(target)}
    records[0x6080BD8E]["literal_uint32"] = "0x60815300"
    records[0x60801E38]["literal_uint32"] = "0x200029c8"
    plain = [0x6080AB4D, 0x6080AB11, 0x6080B0F1, 0x6080B037, 0x6080AFE5, 0x6080AA3D]
    physical = [0, 0, 0, 0, 0, 0, 0x60808E39, 0x60808A51]
    return {"sha256": EXPECTED_IMAGE, "bytes": SIZE, "build": EXPECTED_BUILD,
            "functions": [{"start": hex(at), "end_exclusive": hex(at+1),
                           "instructions": [instruction]}
                          for at, instruction in sorted(records.items())],
            "storage_vtables": [{"address": "0x60815300", "entries": [hex(x) for x in plain]},
                                {"address": "0x60815320", "entries": [hex(x) for x in physical]}]}


class TraceWritePathTests(unittest.TestCase):
    def test_synthetic_known_path_and_fixed_arguments(self):
        result = scan(fixture())
        self.assertEqual(len(result["path"]), 6)
        self.assertEqual(result["path"][-2]["to"], "0x6080b0f0")
        self.assertEqual(result["path"][-1]["to"], "0x60808e38")
        self.assertEqual(result["fixed_ivt_arguments"]["length"], "0x1000")
        self.assertEqual(result["external_input_to_path"], "NOT ESTABLISHED")
        self.assertFalse(result["hardware_access"])

    def test_unknown_direct_calls_are_not_silently_covered(self):
        data = fixture()
        data["functions"].append({"start": "0x60803000", "end_exclusive": "0x60803001",
                                  "instructions": [{"address": "0x60803000", "bytes": "00",
                                                    "mnemonic": "bl", "operands": "#0x60809000",
                                                    "direct_target": "0x60809000"}]})
        self.assertEqual(scan(data)["out_of_scope_direct_call_count"], 5)

    def test_changed_direct_target_rejected(self):
        data = fixture()
        ins = next(f["instructions"][0] for f in data["functions"] if f["start"] == "0x60801dc0")
        ins["direct_target"] = "0x60801ef0"
        with self.assertRaisesRegex(ValueError, "Direct-call mismatch"):
            scan(data)

    def test_modified_fixed_length_rejected(self):
        data = fixture()
        ins = next(f["instructions"][0] for f in data["functions"] if f["start"] == "0x60801d94")
        ins["operands"] = "r3, #0x2000"
        with self.assertRaisesRegex(ValueError, "Anchor mismatch"):
            scan(data)

    def test_replaced_plain_vtable_rejected(self):
        data = fixture()
        data["storage_vtables"][0]["entries"][2] = "0x6080ab11"
        with self.assertRaisesRegex(ValueError, "Unexpected virtual target"):
            scan(data)

    def test_missing_caller_evidence_rejected(self):
        data = fixture()
        data["functions"] = [f for f in data["functions"] if f["start"] != "0x60801ee4"]
        with self.assertRaisesRegex(ValueError, "Direct-call mismatch"):
            scan(data)

    def test_missing_literal_rejected(self):
        data = fixture()
        ins = next(f["instructions"][0] for f in data["functions"] if f["start"] == "0x6080bd8e")
        ins["literal_uint32"] = "0x12345678"
        with self.assertRaisesRegex(ValueError, "Plain vtable address"):
            scan(data)

    def test_bad_build_rejected(self):
        data = fixture()
        data["build"] = 1
        with self.assertRaisesRegex(ValueError, "Unsupported firmware"):
            scan(data)

    def test_bad_encoding_or_region_length_rejected(self):
        data = fixture()
        data["functions"][0]["instructions"][0]["bytes"] = "z00"
        with self.assertRaisesRegex(ValueError, "Invalid instruction bytes"):
            scan(data)
        data = fixture()
        data["functions"][0]["end_exclusive"] = hex(int(data["functions"][0]["end_exclusive"], 16) + 1)
        with self.assertRaisesRegex(ValueError, "length mismatch"):
            scan(data)

    def test_public_evidence_when_present(self):
        path = Path(__file__).resolve().parents[1] / "evidence/bootloader-analysis.json"
        if not path.exists():
            self.skipTest("Public evidence not installed in local fixture")
        result = scan(json.loads(path.read_text(encoding="utf-8")))
        self.assertEqual(result["image_sha256"], EXPECTED_IMAGE)
        self.assertEqual(result["build"], EXPECTED_BUILD)
        self.assertEqual(result["selected_regions"], 28)
        self.assertGreater(result["out_of_scope_direct_call_count"], 0)
        self.assertGreater(len(result["indirect_sites_not_resolved_generically"]), 0)
        self.assertEqual(result["custom_firmware_execution"], "NOT DEMONSTRATED")


if __name__ == "__main__":
    unittest.main()
