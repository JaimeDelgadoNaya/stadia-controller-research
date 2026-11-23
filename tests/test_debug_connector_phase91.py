"""Offline consistency checks for source-reported, NOT physically confirmed phase-91 mapping."""
import json
import unittest
from pathlib import Path

EVIDENCE = Path(__file__).resolve().parents[1] / "evidence" / "debug-connector-phase91.json"

class DebugConnectorPhase91Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads(EVIDENCE.read_text(encoding="utf-8"))

    def test_pin_labels_are_complete_and_unique(self):
        pads = self.report["connector"]["pads"]
        self.assertEqual(len(pads), 17)
        self.assertEqual(len({x["pad"] for x in pads}), 17)
        self.assertEqual({x["pad"] for x in pads}, set("123456789ABCDEFGH"))

    def test_documented_signals_consistent(self):
        signals = {p["pad"]: p["signal"] for p in self.report["connector"]["pads"]}
        self.assertEqual({k: signals[k] for k in ("4", "D", "5", "7")},
                         {"4": "TX", "D": "RX", "5": "SWCLK", "7": "SWDIO"})
        self.assertEqual({k for k, v in signals.items() if v == "GND"}, {"E", "G", "9"})
        self.assertEqual(signals["H"], "Vdd")
        self.assertEqual(signals["F"], "nRESET")

    def test_alternate_points_are_not_evidence_of_unlock(self):
        self.assertEqual(self.report["alternate_swd_points"]["top_to_bottom"],
                         ["SWDIO/TMS", "SWCLK/TCK", "SWO/TDO", "TDI"])
        self.assertFalse(self.report["alternate_swd_points"]["swd_uses_tdi"])
        self.assertFalse(any(self.report["independently_verified"].values()))
        self.assertFalse(self.report["hardware_actions_performed"])
        self.assertFalse(self.report["connector"]["numbering_is_official"])

if __name__ == "__main__":
    unittest.main()
