"""Pure synthetic tests for Stadia FillMemory runtime-guard provenance model."""
import struct
import unittest

from tools import audit_fillmemory_dynamic_guard as m
from tools import audit_fillmemory_wrap_model as previous


class GuardProvenanceTests(unittest.TestCase):
    def test_context_addresses_and_startup_snapshot(self):
        self.assertEqual(m.DYNAMIC_ADDRESSES,
                         (0x20212D40, 0x20212D44, 0x20212D48, 0x20212D4C))
        self.assertGreater(m.PROVIDER_CONTEXT, m.STARTUP_COPY_DEST + m.STARTUP_COPY_LENGTH)

    def test_disjoint_intervals_are_not_rejected(self):
        start, size = 0x20015A00, 4
        # These values are synthetic and illustrative, NEVER physical readings.
        self.assertFalse(m.guard_symbolic_model(start,size,
            (0x20000000,0x20001000,0x20200000,0x20201FFF)))

    def test_first_protected_region_intersection_rejects(self):
        self.assertTrue(m.guard_symbolic_model(0x20000120,4,
                         (0x20000000,0x20000200,0x20200000,0x20201FFF)))

    def test_second_protected_region_intersection_rejects(self):
        self.assertTrue(m.guard_symbolic_model(0x20015A00,4,
                         (0x20000000,0x20001000,0x20015000,0x20016000)))

    def test_second_protected_region_end_before_start_precheck_can_skip(self):
        start = 0x200159E0
        length = previous.wrap_length_for_end(start,0x2003)
        # Both synthetic cases are possible under the branch comparisons,
        # depending on runtime limits. They are NOT measured Stadia values.
        accepting = (0x20000000,0x20001000,0x20004000,0x20008000)
        rejecting = (0x20000000,0x20001000,0x1000,0x20018000)
        self.assertFalse(m.guard_symbolic_model(start,length,accepting))
        self.assertTrue(m.guard_symbolic_model(start,length,rejecting))

    def test_first_suppressed_when_both_bounds_equal_map_first(self):
        self.assertFalse(m.guard_symbolic_model(0x20000100,4,
                         (0,0,0x20200000,0x20201fff)))
        self.assertTrue(m.guard_symbolic_model(0x20000100,4,
                         (0x20000000,0x20000200,0x20200000,0x20201fff)))

    def test_bad_limit_types_rejected(self):
        for value in [(), (1,2,3), (-1,2,3,4), (1,2,3,0x100000000)]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                m.guard_symbolic_model(0x20015000,4,value)

    def test_wont_accept_unverified_original(self):
        with self.assertRaisesRegex(ValueError, "hash/size"):
            m.analyze_original(bytes(m.original.SIZE))


if __name__ == "__main__":
    unittest.main()
