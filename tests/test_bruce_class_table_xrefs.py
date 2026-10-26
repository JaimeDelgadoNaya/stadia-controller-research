import unittest
from tools import audit_bruce_class_table_xrefs as x

class TableReferences(unittest.TestCase):
    def test_rejects_unverified_image(self):
        with self.assertRaises(ValueError):
            x.audit(bytes(x.IMAGE_SIZE))
    def test_pc_alignment(self):
        self.assertEqual(x.pc_ldr_literal(0x60051002,"ldr","r2, [pc, #0x10]"),0x60051014)
    def test_non_literal_load(self):
        self.assertIsNone(x.pc_ldr_literal(0x60051000,"ldr","r1, [r3]"))
    def test_range(self):
        self.assertEqual(x.END-x.START,0x60)
if __name__=="__main__":
    unittest.main()
