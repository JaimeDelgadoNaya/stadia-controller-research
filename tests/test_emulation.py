"""Optional machine-code checks: install requirements-emulation.txt to run."""
import copy
import importlib.util
import json
import unittest
from pathlib import Path

HAS_UNICORN = importlib.util.find_spec("unicorn") is not None


@unittest.skipUnless(HAS_UNICORN, "Optional Unicorn dependency is not installed")
class EmulationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads((Path(__file__).resolve().parents[1] /
                                   "evidence/bootloader-analysis.json").read_text())

    def test_recorded_instructions_agree_with_model_for_all_cases(self):
        from tools.emulate_range_check import run
        result = run(self.evidence)
        self.assertEqual(len(result["results"]), 8)
        witness = next(r for r in result["results"] if r["case"] == "wrapped_range")
        self.assertTrue(witness["arm_accepts"])
        self.assertFalse(witness["nonwrapping_accepts"])

    def test_modified_machine_code_is_rejected(self):
        from tools.emulate_range_check import helper_bytes
        data = copy.deepcopy(self.evidence)
        region = next(r for r in data["functions"] if r["start"] == "0x60801fe6")
        raw = bytearray.fromhex(region["instructions"][0]["bytes"])
        raw[0] ^= 1
        region["instructions"][0]["bytes"] = raw.hex()
        with self.assertRaisesRegex(ValueError, "bytes do not match"):
            helper_bytes(data)

    def test_values_outside_register_width_are_rejected(self):
        from tools.emulate_range_check import execute, helper_bytes
        with self.assertRaisesRegex(ValueError, "32-bit"):
            execute(helper_bytes(self.evidence), 0, 255, 0, 0x100000000)
