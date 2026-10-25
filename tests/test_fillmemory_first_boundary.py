"""Offline synthetic-only regression tests; no controller/hardware interaction."""
import unittest
from tools import audit_fillmemory_first_boundary as b
from tools import audit_fillmemory_init_flow as flow
from tools import audit_fillmemory_wrap_model as wrap


class FirstBoundaryTests(unittest.TestCase):
    def test_signed_uint32_interpretation(self):
        self.assertEqual(b.signed32(0),0)
        self.assertEqual(b.signed32(0x7fffffff),0x7fffffff)
        self.assertEqual(b.signed32(0x80000000),-0x80000000)
        self.assertEqual(b.signed32(0xffffffff),-1)

    def test_large_wrapped_fills_use_byte_tail_not_stm(self):
        for address in wrap.CONTROL_FIELDS:
            with self.subTest(address=hex(address)):
                count=wrap.wrap_length_for_end(address,0x2003)
                self.assertEqual(b.chosen_loop_route(address,count),"byte_tail_signed_blt")
                self.assertGreater(count,0x80000000)

    def test_first_declared_region_exit_has_no_device_side_effect(self):
        for address in wrap.CONTROL_FIELDS:
            count=wrap.wrap_length_for_end(address,0x2003)
            result=b.first_declared_boundary(address,count)
            self.assertEqual(result["writes_before_region_exit"],0x20020000-address)
            self.assertEqual(result["first_outside_this_region"],"0x20020000")
            self.assertIn("UNKNOWN",result["actual_bus_fault"])

    def test_ordinary_length_does_not_exit_region(self):
        result=b.first_declared_boundary(0x200159e0,4)
        self.assertIsNone(result["first_outside_this_region"])
        self.assertEqual(result["writes_before_region_exit"],4)
        self.assertEqual(result["route"],"bulk_or_short_tail_bounded_model")

    def test_preview_is_bounded_and_does_not_allocate_requested_size(self):
        result=b.small_mock_preview(0x200159e0,0xffffffff)
        self.assertEqual(result["disposable_buffer_bytes"],64)
        self.assertEqual(result["simulated_bytes"],64)
        self.assertFalse(result["actual_memory_touched"])
        with self.assertRaises(ValueError):
            b.small_mock_preview(0x200159e0,0xffffffff,1000)

    def test_alignment_and_empty_input_are_explicit(self):
        self.assertEqual(b.chosen_loop_route(0x200159e0,0),"zero_length_fast_return")
        self.assertEqual(b.chosen_loop_route(0x200159e1,0xffffffff),
                         "unaligned_prefix_needs_independent_emulation")

    def test_outside_region_is_not_asserted_bus_fault(self):
        x=b.first_declared_boundary(0x402a8080,4)
        self.assertEqual(x["writes_before_region_exit"],0)
        self.assertEqual(x["first_outside_this_region"],"0x402a8080")
        self.assertEqual(x["actual_bus_fault"],"UNKNOWN")

    def test_hash_verification_mandatory(self):
        for tool in (b.original_report,flow.audit):
            with self.subTest(tool=tool.__name__):
                with self.assertRaisesRegex(ValueError,"pinned|original"):
                    tool(bytes(100672))


if __name__=="__main__":
    unittest.main()
