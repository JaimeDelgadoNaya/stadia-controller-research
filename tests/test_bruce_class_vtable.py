"""No-device tests for signed Bruce class vtable initialization evidence."""
import unittest
from tools import audit_bruce_class_vtable as a
class ClassVtableTests(unittest.TestCase):
    def test_sha_guard_rejects_fake_sample(self):
        with self.assertRaisesRegex(ValueError,"Exact original"):
            a.audit(bytes(a.IMAGE_SIZE))
    def test_vtable_pointer_store_and_class_handler_pinned(self):
        self.assertTrue(a.check_anchors(dict(a.ANCHORS)))
        self.assertEqual(a.ANCHORS[0x6005533A],("str","r6, [r4, #4]"))
        self.assertEqual(a.ANCHORS[0x600553C0],("str","r3, [r4, #4]"))
        self.assertEqual(a.ANCHORS[0x600D0EB8],("ldrb","r1, [r1, #1]"))
    def test_mutated_pointer_writer_fails(self):
        mutated=dict(a.ANCHORS)
        mutated[0x6005533A]=("str","r6, [r4, #8]")
        with self.assertRaisesRegex(ValueError,"semantic drift"):
            a.check_anchors(mutated)
    def test_literal_load_address_arithmetic(self):
        self.assertEqual(a.LITERAL_LOADS[0x600553BA][1],
                         ((0x600553BA+4)&~3)+0x40)
        self.assertEqual(a.LITERAL_LOADS[0x600553BE][1],
                         ((0x600553BE+4)&~3)+0x38)
    def test_rejects_bad_literal_ranges(self):
        with self.assertRaises(ValueError):
            a.literal_at(b"",0x600553FA)
if __name__=="__main__":
    unittest.main()
