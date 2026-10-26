"""Phase 59 signed pair reader survey unit tests (no OEM file needed)."""
import struct
import unittest
from tools import audit_bruce_pair_consumers_phase59 as a


class Phase59PairReaders(unittest.TestCase):
    def test_signed_pair_coordinates(self):
        self.assertEqual(a.PAIR_FIRST,0x2000FBF4)
        self.assertEqual(a.PAIR_SECOND,0x2000FBF8)
        self.assertEqual(a.PAIR_FIRST-a.PAIR_BASE,0x37C)
        self.assertEqual(a.PAIR_SECOND-a.PAIR_BASE,0x380)

    def test_little_endian_word_bounded_and_aligned(self):
        raw=bytearray(0x200)
        struct.pack_into("<I",raw,0x40,a.PAIR_BASE)
        self.assertEqual(a.unsigned_word(raw,0x40),a.PAIR_BASE)
        with self.assertRaisesRegex(ValueError,"aligned"):
            a.unsigned_word(raw,0x41)

    def test_aligned_literal_matches_only_target(self):
        raw=bytearray(0x100)
        for offset,value in [(0x20,a.PAIR_BASE),(0x24,a.PAIR_FIRST),
                             (0x28,a.PAIR_SECOND),(0x2C,0x20004000)]:
            struct.pack_into("<I",raw,offset,value)
        got=a.scan_aligned_literals(raw)
        self.assertEqual([row["value"] for row in got],
                         [hex(x) for x in a.POINTERS])

    def test_synthetic_PC_relative_literal_load(self):
        raw=bytearray(0x40)
        # 0x4800 is 16-bit LDR R0,[PC,#0]. PC=0x60000000 => literal +4
        struct.pack_into("<H",raw,0,0x4800)
        struct.pack_into("<I",raw,4,a.PAIR_FIRST)
        res=a.pc_ldr_candidate(raw,a.BASE,0,False)
        self.assertEqual(res["literal_pc"],hex(a.BASE+4))
        self.assertEqual(res["loaded_register"],"r0")

    def test_synthetic_thumb_literal_provenance_is_not_runtime(self):
        raw=bytearray(0x40)
        struct.pack_into("<H",raw,0x1C,0x4900)
        struct.pack_into("<I",raw,0x20,a.PAIR_FIRST)
        hits=a.scan_aligned_literals(raw)
        refs=a.recover_signed_literal_loads(raw,hits,back_bytes=0x30)
        self.assertTrue(any(q["pc"]==hex(a.BASE+0x1C) and
                            q["loaded_value"]==hex(a.PAIR_FIRST)
                            for q in refs))
        self.assertTrue(all(q["runtime_proven"]=="UNVERIFIED" for q in refs))

    def test_no_inferred_PC_literal_from_other_instruction(self):
        raw=b"\x00\xbf\x00\xbf\x00\x00\x00\x00"
        self.assertIsNone(a.pc_ldr_candidate(raw,a.BASE,0,False))

    def test_signed_pair_offset_pattern_matches_literal_memory(self):
        good=a.PAIR_MEM_REGEXP.search("r3, [r4, #0x37c]")
        self.assertIsNotNone(good)
        self.assertEqual(int(good.group(2),0),0x37C)
        self.assertEqual(good.group(1),"r4")
        self.assertIsNone(a.PAIR_MEM_REGEXP.search("r3, [r4, r2]"))

    def test_signed_writers_are_required_positive_controls(self):
        # The full original OEM run must find both 0x60063878 and
        # 0x6006387E: a linear stream scan alone missed both.
        self.assertEqual(a.PAIR_IMMEDIATES,{0x37C,0x380})

    def test_trampoline_original_bytes_required(self):
        with self.assertRaises((ValueError,IndexError)):
            a.resolve_itcm_trampoline(b"not original")

    def test_itcm_range_check(self):
        with self.assertRaisesRegex(ValueError,"outside startup copy"):
            a.itcm_code(b"small",a.ITCM_LENGTH-1,100)

    def test_lone_read_pc_relative_base_has_two_loads(self):
        self.assertEqual(a.LONE_READER_PINS[0x600BD136],
                         ("ldr","r3, [pc, #0x10]"))
        self.assertEqual(a.LONE_READER_PINS[0x600BD138],
                         ("ldrb.w","r3, [r3, #0x380]"))
        self.assertEqual(len(a.LONE_READER_PINS),4)

    def test_real_handler_is_distinct_from_ITCM_veneer(self):
        self.assertEqual(a.REAL_HANDLER_XIP,0x6007E6A0)
        self.assertEqual(a.CALLBACK_ITCM,0xB980)
        self.assertEqual(len(a.HANDLER_PINS),13)
        self.assertEqual(a.HANDLER_PINS[0x6007E6CE],("ldrex","r2, [r3]"))

    def test_unrelated_global_is_not_callback_pair_base(self):
        self.assertEqual(a.OTHER_RAM_GLOBAL,0x20025CE0)
        self.assertNotEqual(a.OTHER_RAM_GLOBAL,a.PAIR_BASE)

    def test_fails_closed_on_nonoriginal(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            a.audit(b"dummy")


if __name__=="__main__":
    unittest.main()
