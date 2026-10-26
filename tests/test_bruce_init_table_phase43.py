"""Synthetic-only tests for the signed function-pointer table-shape audit."""
import struct
import unittest
from tools import audit_bruce_init_table_phase43 as a

class CandidateTableTests(unittest.TestCase):
    def test_exact_static_entry_address(self):
        self.assertEqual(a.POINTER_FILE_OFFSET, 0xfd544)
        self.assertEqual(a.POINTER_VALUE, 0x600748ed)

    def test_bounded_contiguous_thumb_entries(self):
        buf=bytearray(0x100)
        for off,v in ((0x20,0x60071f01),(0x24,0x600748ed),(0x28,0x600719a1)):
            struct.pack_into("<I",buf,off,v)
        lo,hi=a.neighbor_candidate_range(bytes(buf),center=0x24)
        self.assertEqual((lo,hi),(0x20,0x2c))

    def test_non_thumb_and_unaligned_limits(self):
        buf=bytearray(0x40)
        struct.pack_into("<I",buf,0x10,0x600748ed)
        with self.assertRaisesRegex(ValueError,"word-aligned"):
            a.neighbor_candidate_range(bytes(buf),center=0x11)
        self.assertFalse(a.executable_thumb_value(0x600748ec))
        self.assertFalse(a.executable_thumb_value(0x20009ef8))

    def test_walker_instruction_mutation_is_detected(self):
        self.assertTrue(a.verify_walker_pins(dict(a.WALKER_PINS)))
        rows=dict(a.WALKER_PINS)
        rows[0x600CDBA6]=("bx","r3")
        with self.assertRaisesRegex(ValueError,"drift"):
            a.verify_walker_pins(rows)

    def test_not_accept_wrong_image(self):
        with self.assertRaisesRegex(ValueError,"pinned"):
            a.audit(b"no data")

if __name__=="__main__":
    unittest.main()
