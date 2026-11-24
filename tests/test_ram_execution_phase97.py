"""Synthetic unit tests for the RAM-only ARM Thumb teaching image.

The fixture is verified against the offline build from minimal_ram.S. These
tests require neither an ARM toolchain nor any physical hardware.
"""
import hashlib
import struct
import unittest

from research.phase97.simulate_ram import simulate

IMAGE = bytes.fromhex("00000120090000205a2001490860fee714000020")
EXPECTED_SHA256 = "68a75935017e47c373d2df0b9294c31781705894511bc62fea78b6a265806f38"


class RamExecutionPhase97Tests(unittest.TestCase):
    def test_01_fixture_matches_compiled_image(self):
        self.assertEqual(len(IMAGE), 20)
        self.assertEqual(hashlib.sha256(IMAGE).hexdigest(), EXPECTED_SHA256)

    def test_02_stack_and_thumb_reset_vector(self):
        self.assertEqual(struct.unpack_from("<II", IMAGE), (0x20010000, 0x20000009))

    def test_03_four_instructions_reach_self_loop(self):
        x = simulate(IMAGE)
        self.assertEqual(x["status"], "SYNTHETIC_RAM_CODE_EXECUTED")
        self.assertEqual(len(x["steps"]), 4)

    def test_04_single_ram_marker_write(self):
        self.assertEqual(simulate(IMAGE)["writes"],
                         [{"address": "0x20000014", "value": 0x5a}])

    def test_05_no_hardware_claim(self):
        x = simulate(IMAGE)
        for k in ("hardware_execution_proven", "hab_bypass_proven",
                  "flash_modified", "otp_modified", "real_usb_or_device_access"):
            self.assertIs(x[k], False, k)

    def test_06_invalid_reset_vector_is_rejected(self):
        b = bytearray(IMAGE)
        struct.pack_into("<I", b, 4, 0x20000008)
        with self.assertRaisesRegex(ValueError, "Thumb"):
            simulate(bytes(b))

    def test_07_wrong_stack_is_rejected(self):
        b = bytearray(IMAGE)
        struct.pack_into("<I", b, 0, 0x20200000)
        with self.assertRaisesRegex(ValueError, "stack"):
            simulate(bytes(b))

    def test_08_out_of_region_write_is_rejected(self):
        b = bytearray(IMAGE)
        struct.pack_into("<I", b, 16, 0x401f4000)
        with self.assertRaisesRegex(ValueError, "Forbidden write"):
            simulate(bytes(b))

    def test_09_unsupported_opcode_is_rejected(self):
        b = bytearray(IMAGE)
        struct.pack_into("<H", b, 8, 0xbe00)
        with self.assertRaisesRegex(ValueError, "Unsupported Thumb"):
            simulate(bytes(b))

    def test_10_branch_elsewhere_is_rejected(self):
        b = bytearray(IMAGE)
        struct.pack_into("<H", b, 14, 0xe7fd)
        with self.assertRaisesRegex(ValueError, "self-loop"):
            simulate(bytes(b))

    def test_11_wrong_marker_is_rejected(self):
        b = bytearray(IMAGE)
        struct.pack_into("<H", b, 8, 0x205b)
        with self.assertRaisesRegex(ValueError, "marker"):
            simulate(bytes(b))

    def test_12_short_and_long_buffers_rejected(self):
        for bad in (b"", IMAGE[:-1], IMAGE + b"\x00"):
            with self.subTest(n=len(bad)), self.assertRaises(ValueError):
                simulate(bad)


if __name__ == "__main__":
    unittest.main(verbosity=2)
