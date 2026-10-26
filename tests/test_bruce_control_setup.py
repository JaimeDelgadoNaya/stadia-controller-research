"""Offline-only tests for control SETUP XIP provenance auditor."""
import unittest
from tools import audit_bruce_control_setup as a

class ControlSetupTests(unittest.TestCase):
    def test_hash_pin_rejects_wrong_input(self):
        with self.assertRaisesRegex(ValueError,"exact SHA"):
            a.audit(bytes(a.IMAGE_SIZE))
    def test_offsets_are_xip(self):
        for start,end in a.FOCUS.values():
            self.assertLessEqual(a.BASE,start)
            self.assertLess(end,a.BASE+0xFF000)
            self.assertLess(start,end)
    def test_literal_ref_on_synthetic_data(self):
        import struct
        raw=bytearray(0x200)
        raw[4:8]=struct.pack("<I",0x600D0C3D)
        raw[11:15]=struct.pack("<I",0x600D0C3D)
        result=a.exact_xip_pointer_matches(raw,{"parser":0x600D0C3C})
        self.assertEqual(result["parser"]["count"],2)
        self.assertEqual(result["parser"]["file_offsets"],["0x4","0xb"])
        self.assertEqual(result["parser"]["aligned_word_offsets"],["0x4"])
    def test_offset_one_load_is_candidate_not_proof(self):
        rows={"z":[{"pc":a.BASE+1,"m":"ldrb","op":"r1, [r2, #1]"}]}
        result=a.control_input_loads(rows)
        self.assertEqual(len(result),1)
        self.assertFalse(result[0]["setup_brequest_proven"])
    def test_indirect_event_not_brequest(self):
        self.assertNotIn("0x81",a.TARGETS)
        self.assertEqual(a.TARGETS["setup_parser"],0x600D0C3C)

if __name__=="__main__":
    unittest.main()
