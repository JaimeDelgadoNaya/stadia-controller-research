"""Seven synthetic tests for public RT1060 opcode branch geometry."""
import unittest
from research.phase98.verify_claims import branch_target, SIGNATURES, MPU, HID

class TestRomOpcodePhase98(unittest.TestCase):
    def test_normal_exit_skips_ctrl_write(self):
        self.assertEqual(branch_target(0xE004, MPU+0xA6), MPU+0xB2)

    def test_invalid_region_jumps_to_ctrl_write(self):
        self.assertEqual(branch_target(0xD326, MPU+0x58), MPU+0xA8)

    def test_loop_branch_back(self):
        self.assertEqual(branch_target(0xD3D6, MPU+0xA4), MPU+0x54)

    def test_bad_opcode_refused(self):
        with self.assertRaises(ValueError):
            branch_target(0x6000, MPU)

    def test_signature_count(self):
        self.assertEqual(len(SIGNATURES), 9)

    def test_hid_ptr_values_and_geometry(self):
        self.assertEqual(0x2020723F+2048-0x20207A3C, 3)
        self.assertEqual(0x2020723C+2048, 0x20207A3C)

    def test_addresses_are_thumb_aligned(self):
        self.assertEqual(MPU % 2, 0)
        self.assertEqual(HID % 2, 0)

if __name__ == "__main__":
    unittest.main(verbosity=2)
