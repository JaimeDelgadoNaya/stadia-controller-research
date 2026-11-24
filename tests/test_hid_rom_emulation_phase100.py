"""Fail-closed tests for the phase 100 public BootROM HID excerpt emulator.

Tests synthesize invalid inputs. The CI additionally runs the actual public
SHA-pinned ROM in Unicorn; none of these tests connect any devices.
"""
import unittest
from research.phase100.emulate_hid_callback import (
    EXPECTED_SHA256, ROM_BASE, ROM_SIZE, FUNCTION, BEGIN, END_ACCEPT,
    END_REJECT, MAX_REPORT_BYTES, EXPECTED_REPORT_PTR, ANCHORS,
    validate_rom, emulate_report_registration,
)


class PublicROMGatePhase100Tests(unittest.TestCase):
    def test_01_sha_has_64_digits(self):
        self.assertEqual(len(EXPECTED_SHA256), 64)

    def test_02_bad_size_rejected(self):
        with self.assertRaisesRegex(ValueError, "128 KiB"):
            validate_rom(b"")

    def test_03_wrong_image_rejected(self):
        with self.assertRaisesRegex(ValueError, "SHA"):
            validate_rom(bytes(ROM_SIZE))

    def test_04_handler_in_internal_rom(self):
        self.assertTrue(ROM_BASE <= BEGIN <= END_REJECT < ROM_BASE + ROM_SIZE)

    def test_05_anchor_addresses_bounded(self):
        self.assertGreaterEqual(len(ANCHORS), 9)
        for a, seq in ANCHORS.items():
            self.assertTrue(ROM_BASE <= a <= ROM_BASE + ROM_SIZE - len(seq))

    def test_06_two_stop_points_different(self):
        self.assertLess(END_ACCEPT, END_REJECT)

    def test_07_threshold_and_known_pointer(self):
        self.assertEqual(MAX_REPORT_BYTES, 0x800)
        self.assertEqual(EXPECTED_REPORT_PTR, 0x2020723F)

    def test_08_invalid_report_length_rejected_before_unicorn(self):
        with self.assertRaisesRegex(ValueError, "uint16"):
            emulate_report_registration(b"", -1)

    def test_09_oversized_length_parameter_rejected(self):
        with self.assertRaisesRegex(ValueError, "uint16"):
            emulate_report_registration(b"", 65536)


if __name__ == "__main__":
    unittest.main(verbosity=2)
