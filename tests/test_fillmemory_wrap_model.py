"""Synthetic-only tests for bounded uint32 FillMemory interval model."""
import struct
import unittest

from tools import audit_fillmemory_wrap_model as m


class FillMemoryWrapTests(unittest.TestCase):
    def test_normal_flags_rejected(self):
        for field in m.CONTROL_FIELDS:
            self.assertFalse(m.policy_op_zero_precheck(field, 4))

    def test_wrap_can_fool_only_first_static_range_comparison(self):
        for field in m.CONTROL_FIELDS:
            size = m.wrap_length_for_end(field, 0x2003)
            self.assertGreater(field + size - 1, m.MASK)
            self.assertEqual(m.end32(field, size), 0x2003)
            self.assertTrue(m.policy_op_zero_precheck(field, size))
            self.assertGreater(size, m.byte_count_within_region(field, m.RAM_REGION_END))

    def test_map_comparison_also_exhibits_wrap(self):
        region = [(m.RAM_REGION_START, m.RAM_REGION_END, 0x11, 0x20015ea8)]
        for field in m.CONTROL_FIELDS:
            length = m.wrap_length_for_end(field, 0x2003)
            self.assertEqual(len(m.memory_map_precheck(field, length, region)), 1)

    def test_no_wrap_does_not_create_permissions(self):
        allowed = m.policy_op_zero_precheck(0x2000, 4)
        denied = m.policy_op_zero_precheck(m.CONTROL_FIELDS[0], 4)
        self.assertTrue(allowed)
        self.assertFalse(denied)

    def test_invalid_sizes_are_not_witnesses(self):
        with self.assertRaises(ValueError):
            m.end32(1, 0)
        with self.assertRaises(ValueError):
            m.wrap_length_for_end(0x2000, 0x2001)
        with self.assertRaises(ValueError):
            m.byte_count_within_region(m.RAM_REGION_END + 1, m.RAM_REGION_END)

    def test_region_exclusions(self):
        regions = [(0x20000000, 0x2001ffff, 0x11, 0x20015ea8)]
        self.assertEqual(m.memory_map_precheck(0x60000000, 4, regions), [])
        self.assertEqual(m.memory_map_precheck(0x20000000, 4, regions)[0]["start"], 0x20000000)

    def test_region_decode_synthetic(self):
        data = bytearray(64)
        struct.pack_into("<4I", data, 0, 0x10, 0x20, 1, 0x30)
        self.assertEqual(m.parse_memory_regions(data, 0, 1), ((0x10,0x20,1,0x30),))
        with self.assertRaises(ValueError):
            m.parse_memory_regions(data, 0, 5)

    def test_original_hash_gate_cannot_be_bypassed_by_synthetic_bytes(self):
        with self.assertRaisesRegex(ValueError, "exact original"):
            m.inspect_original(bytes(m.original.SIZE))


if __name__ == "__main__":
    unittest.main()
