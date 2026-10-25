import json
from pathlib import Path
import unittest
from tools.audit_hid_report_contract import decode


class HidContractTests(unittest.TestCase):
    def test_independent_live_windows_caps_agree_with_raw_descriptor(self):
        root = Path(__file__).resolve().parents[1] / "evidence"
        source = json.loads((root / "stadia-hid-report-contract.json").read_text())
        parsed = decode(bytes.fromhex(source["descriptor_hex"]))
        live = json.loads((root / "stadia-hid-capabilities.json").read_text(encoding="utf-8-sig"))
        collection = live["collections"][0]
        report = next(r for r in collection["reports"] if r["type"] == "output")
        value = report["values"][0]
        field = next(f for f in parsed["fields"] if f["direction"] == "output")
        self.assertEqual((value["report_id"], value["bit_size"], value["report_count"]),
                         (field["report_id"], field["size"], field["count"]))
        self.assertEqual((value["usage_page"], value["usage_min"], value["logical_max"]),
                         (field["usage_page"], field["usages"][0], field["logical_max"]))
        self.assertEqual(collection["output_report_bytes"], 5)

    def test_measured_output_contract(self):
        source = json.loads((Path(__file__).resolve().parents[1] /
                             "evidence/stadia-hid-report-contract.json").read_text())
        result = decode(bytes.fromhex(source["descriptor_hex"]))
        output = [f for f in result["fields"] if f["direction"] == "output"]
        self.assertEqual(len(output), 1)
        field = output[0]
        self.assertEqual((field["report_id"], field["usage_page"], field["usages"]), (5, 15, [151]))
        self.assertEqual((field["size"], field["count"], field["logical_max"]), (16, 2, 65535))
        self.assertIn({"direction": "output", "report_id": 5, "payload_bits": 32, "wire_bytes": 5}, result["reports"])

    def test_global_push_pop_and_independent_report_offsets(self):
        result = decode(bytes.fromhex("7508950185018102a47510950285029102b48102"))
        self.assertEqual([f["payload_bit_offset"] for f in result["fields"]], [0, 0, 8])
        self.assertEqual([f["bits"] for f in result["fields"]], [8, 32, 8])
        self.assertEqual(result["reports"][0]["wire_bytes"], 3)

    def test_local_usage_cleared_by_collection(self):
        result = decode(bytes.fromhex("05010905a101750895018102c0"))
        self.assertEqual(result["fields"][0]["usages"], [])

    def test_malformed_items_rejected(self):
        for data in (b"\x77\x01", b"\xb4", b"\xa4", b"\x85\x00", b"\xfe"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                decode(data)


if __name__ == "__main__":
    unittest.main()
