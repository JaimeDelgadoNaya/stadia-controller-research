"""Phase56 targeted, conservative provenance and reader regressions."""
import unittest
from tools import audit_bruce_parent_r0_phase56 as a


class Phase56CallerOrigin(unittest.TestCase):
    def test_offset80_reader_is_typed_not_linked(self):
        self.assertEqual(a.offset_reader("ldr.w", "r3, [r4, #0x80]"),
                         {"output":"r3","base":"r4","width":"ldr"})

    def test_byte_reader(self):
        self.assertEqual(a.offset_reader("ldrb", "r0, [r8, #0x80]")["width"],"ldrb")

    def test_store_is_not_reader(self):
        self.assertIsNone(a.offset_reader("str.w","r2, [r4, #0x80]"))

    def test_wrong_field_and_register_index_rejected(self):
        self.assertIsNone(a.offset_reader("ldr","r0, [r4, #0x84]"))
        self.assertIsNone(a.offset_reader("ldr","r0, [r4, r2]"))

    def test_known_bl_clobbers_r0(self):
        rows=[{"pc":hex(a.CALLSITE-12),"m":"bl","op":"#0x60070000",
               "ins":"bl #0x60070000"},
              {"pc":hex(a.CALLSITE),"m":"bl","op":"#0x6007eb8c",
               "ins":"bl #0x6007eb8c"}]
        result=a.near_call_r0_writes(rows)
        self.assertEqual(len(result),1)
        self.assertEqual(result[0]["r0"],"UNTRUSTED_CALL_RETURN")

    def test_pinned_return_producer_is_not_numeric_pointer(self):
        self.assertEqual(a.R0_ORIGIN_PINS[0x60079D74], ("movs","r0, #0xa4"))
        self.assertEqual(a.R0_ORIGIN_PINS[0x60079D76], ("bl","#0x6013d378"))
        self.assertEqual(a.R0_ORIGIN_PINS[0x60079D7E], ("mov","r4, r0"))

    def test_oem_provenance_requires_signed_image(self):
        with self.assertRaises((ValueError, IndexError)):
            a.prove_r0_producer(b"synthetic")

    def test_pinned_itcm_wrapper_guards(self):
        self.assertEqual(a.ITCM_WRAPPER_PINS[0xB53E],("bl","#0x8832"))
        self.assertEqual(a.ITCM_WRAPPER_PINS[0xB542],("cbnz","r0, #0xb552"))
        self.assertEqual(a.ITCM_WRAPPER_PINS[0xB550],("b","#0xb53c"))
        self.assertEqual(len(a.ITCM_WRAPPER_PINS),14)

    def test_itcm_range_checks(self):
        with self.assertRaises(ValueError):
            a.itcm_rows(b"",a.ITCM_LENGTH-1,10)

    def test_startup_relocated_itcm_mapping(self):
        self.assertEqual(a.ITCM_SOURCE_OFFSET, 0x81C)
        self.assertTrue(0 <= 0xB532 < a.ITCM_LENGTH)
        self.assertEqual(a.ITCM_SOURCE_OFFSET + 0xB532, 0xBD4E)

    def test_initial_sha_gate(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            a.audit(b"synthetic")

    def test_known_anchor_distinguishes_r0_and_r2(self):
        self.assertEqual(a.OWNER,0x2000A2A8)
        self.assertEqual(a.CALLSITE,0x60079D84)
        self.assertEqual(a.TARGET,0x6007EB8C)


if __name__=="__main__":
    unittest.main()
