import importlib.util
import json
import unittest
from pathlib import Path


@unittest.skipUnless(importlib.util.find_spec("unicorn"), "Optional Unicorn dependency is not installed")
class StorageEmulationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.emulate_storage import run
        evidence = json.loads((Path(__file__).resolve().parents[1] /
                               "evidence/bootloader-analysis.json").read_text())
        cls.results = {case["case"]: case for case in run(evidence)["results"]}

    def test_actual_ivt_arguments_stay_in_partition(self):
        call = self.results["actual_ivt_arguments"]["backend_calls"][0]
        self.assertEqual(call["flash_offset"], "0x1000")
        self.assertEqual(call["length"], "0x1000")

    def test_normal_bounds_errors_do_not_delegate(self):
        for name in ("past_partition", "oversized"):
            self.assertFalse(self.results[name]["backend_calls"])
            self.assertTrue(self.results[name]["stopped_at_bounds_error_path"])

    def test_synthetic_wrap_delegates_before_partition(self):
        case = self.results["synthetic_wrapped_offset"]
        self.assertEqual(case["backend_calls"][0]["flash_offset"], "0xff0")
        self.assertFalse(case["physical_backend_executed"])
