import json
import unittest
from pathlib import Path
from tools.capture_hid_input_phase79 import summarize, capture

class LiveHid79Tests(unittest.TestCase):
    def test_empty_is_not_positive_contract_evidence(self):
        self.assertEqual(summarize([]), {"report_count": 0, "distinct_reports": [], "all_match_id3_length11": False})

    def test_aggregate_without_order_or_identifiers(self):
        report = bytes([3] + [0]*10)
        result = summarize([report, report])
        self.assertTrue(result["all_match_id3_length11"])
        self.assertEqual(result["distinct_reports"], [{"hex": report.hex(), "count": 2}])
        self.assertFalse(summarize([b"\x03"])["all_match_id3_length11"])
        self.assertFalse(summarize([bytes(11)])["all_match_id3_length11"])

    def test_bound_before_import_or_device_access(self):
        for seconds in (0, -1, 31):
            with self.assertRaises(ValueError):
                capture(seconds)

    def test_recorded_observation_is_empty_and_limited(self):
        result = json.loads((Path(__file__).resolve().parents[1]/"evidence/usb-live-hid-input-phase79.json").read_text())
        self.assertEqual(result["report_count"], 0)
        self.assertEqual(result["distinct_reports"], [])
        self.assertFalse(any(result["limits"].values()))
