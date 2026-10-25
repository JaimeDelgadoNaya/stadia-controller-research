"""Pure/synthetic verification tests; original signed image is never committed."""
import struct
import unittest

from tools import audit_fillmemory_verified as m


class FillMemoryVerifiedTests(unittest.TestCase):
    def test_fill_and_write_are_distinct_tables(self):
        self.assertEqual(len(m.FILL_EXPECTED), 5)
        self.assertEqual(len(m.WRITE_EXPECTED), 4)
        self.assertNotEqual(m.FILL_EXPECTED, m.WRITE_EXPECTED)

    def test_normal_fill_does_not_include_execution_enable_bytes(self):
        for address in (m.EXEC_ENABLE, m.CALL_ENABLE):
            self.assertFalse(m.ordinary_nonwrapping_allowed(m.FILL_EXPECTED, address, 4))

    def test_small_hardware_targets_are_in_fill_table(self):
        self.assertTrue(m.ordinary_nonwrapping_allowed(m.FILL_EXPECTED, 0x2000, 4))
        self.assertTrue(m.ordinary_nonwrapping_allowed(m.FILL_EXPECTED, 0x400F8030, 12))
        self.assertFalse(m.ordinary_nonwrapping_allowed(m.FILL_EXPECTED, 0x400F8030, 16))
        self.assertFalse(m.ordinary_nonwrapping_allowed(m.WRITE_EXPECTED, 0x400F8030, 4))

    def test_write_memory_has_separate_flash_permission(self):
        self.assertTrue(m.ordinary_nonwrapping_allowed(m.WRITE_EXPECTED, 0x60004000, 4))
        self.assertFalse(m.ordinary_nonwrapping_allowed(m.FILL_EXPECTED, 0x60004000, 4))

    def test_zero_negative_and_overflow_explicitly_excluded(self):
        for address, length in ((0x2000, 0), (0x2000, -1), (0x2000, 0xFFFFFFFF),
                                (0xFFFFFFFF, 4), (-1, 4)):
            with self.subTest(address=address, length=length):
                with self.assertRaises(ValueError):
                    m.ordinary_nonwrapping_allowed(m.FILL_EXPECTED, address, length)

    def test_region_parser_on_synthetic_bytes(self):
        buf = bytearray(80)
        for i, (lo, hi) in enumerate(m.FILL_EXPECTED):
            struct.pack_into("<2I", buf, i * 8, lo, hi)
        self.assertEqual(m.range_pairs(buf, 0, 5), m.FILL_EXPECTED)

    def test_original_verifier_rejects_synthetic_size_hash(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            m.verify_original(bytes(m.SIZE))


if __name__ == "__main__":
    unittest.main()
