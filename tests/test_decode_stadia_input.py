import json
from pathlib import Path
import unittest

from tools.audit_hid_report_contract import decode
from tools.decode_stadia_input import decode_report, BUTTON_USAGES


class InputDecoderTests(unittest.TestCase):
    def test_contract_matches_descriptor(self):
        path = Path(__file__).resolve().parents[1] / "evidence/stadia-hid-report-contract.json"
        contract = decode(bytes.fromhex(json.loads(path.read_text())["descriptor_hex"]))
        fields = [f for f in contract["fields"] if f["direction"] == "input" and not f["flags"] & 1]
        self.assertEqual([(f["payload_bit_offset"], f["bits"]) for f in fields],
                         [(0, 4), (8, 15), (24, 16), (40, 16), (56, 16), (72, 3)])
        self.assertEqual(fields[1]["usages"], list(BUTTON_USAGES))
        self.assertEqual([f["usages"] for f in fields[2:]],
                         [[48, 49], [50, 53], [197, 196], [233, 234, 205]])

    def test_each_button_independently(self):
        for bit, usage in enumerate(BUTTON_USAGES):
            data = bytearray.fromhex("03 08 00 00 80 80 80 80 00 00 00")
            data[2:4] = (1 << bit).to_bytes(2, "little")
            self.assertEqual(decode_report(data)["pressed_button_usages"], [usage])

    def test_null_hat_and_padding(self):
        for hat in range(16):
            data = bytearray.fromhex("03 08 00 80 80 80 80 80 00 00 f8")
            data[1] = 0xf0 | hat
            result = decode_report(data)
            self.assertEqual(result["hat"], hat if hat < 8 else None)
            self.assertEqual(result["pressed_button_usages"], [])
            self.assertEqual(result["pressed_consumer_usages"], [])

    def test_distinct_axes_controls_and_consumer(self):
        result = decode_report(bytes.fromhex("03 08 00 00 01 7f 80 ff 12 e3 05"))
        self.assertEqual(result["axes_raw"], dict(x=1, y=127, z=128, rz=255))
        self.assertEqual(result["simulation_controls_raw"], {"0xc5": 18, "0xc4": 227})
        self.assertEqual(result["pressed_consumer_usages"], [233, 205])

    def test_invalid_axis_retained_and_flagged(self):
        result = decode_report(bytes.fromhex("03 08 00 00 00 80 00 80 00 00 00"))
        self.assertEqual(result["axes_outside_descriptor_range"], ["x", "z"])

    def test_framing(self):
        for data in (b"", bytes(10), bytes(12), bytes([5]) + bytes(10)):
            with self.assertRaises(ValueError):
                decode_report(data)
