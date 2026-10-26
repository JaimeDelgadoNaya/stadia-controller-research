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
    def test_neighbor_dispatch_has_distinct_stride(self):
        self.assertTrue(x.check_neighbor_dispatch_anchors(dict(x.ANCHORS)))
        self.assertEqual(x.ANCHORS[0x600567A2],
                         ("add.w","r2, r5, r3, lsl #3"))
        self.assertEqual(x.ANCHORS[0x600567B6],("blx","r2"))
    def test_bad_neighbor_anchor_fails(self):
        changed=dict(x.ANCHORS)
        changed[0x600567A2]=("add.w","r2, r5, r3, lsl #2")
        with self.assertRaisesRegex(ValueError,"instruction drift"):
            x.check_neighbor_dispatch_anchors(changed)
    def test_range(self):
        self.assertEqual(x.END-x.START,0x60)
if __name__=="__main__":
    unittest.main()
