"""Synthetic tests for signed-only Bruce class selector table analysis."""
import unittest
import struct
from tools import audit_bruce_class_selector as x

class SelectorTests(unittest.TestCase):
    def test_wrong_signed_image_rejected(self):
        with self.assertRaisesRegex(ValueError,"exact OEM signed"):
            x.audit(bytes(x.IMAGE_SIZE))
    def test_selector_table_has_three_method_words(self):
        self.assertEqual([i[0] for i in x.RECORDS],[1,2,4])
        self.assertEqual(x.RECORD_START+2*16,0x60104B94)
        self.assertEqual(x.RECORDS[2][1][-1],0x600D0333)
        self.assertEqual(x.RECORDS[3][1][-1],0x600D0E59)
    def test_startup_copy_checks_reference_vs_execution(self):
        # This synthetic input can be inspected without a real controller.
        fake=bytearray(x.DATA_SOURCE_OFFSET+x.DATA_END-x.DATA_DESTINATION)
        at=x.DATA_SOURCE_OFFSET+4
        struct.pack_into("<I",fake,at,0x60104BA0)
        d=x.startup_copy_targets(fake)
        self.assertIn(hex(x.DATA_DESTINATION+4),d["matching_words_aligned"]["4"][hex(x.SEL4)])
        self.assertTrue(d["nonzero_word_is_not_runtime_registration"])
    def test_outside_original_image_literal_rejected(self):
        with self.assertRaises(ValueError):
            x.word(b"",x.REGION_LIMIT)
if __name__=="__main__":
    unittest.main()
