"""Synthetic-only tests of phase43 direct Thumb branch/pointer census."""
import struct
import unittest
from tools import audit_bruce_init_inbound_phase43 as a

def enc_bl(pc, target):
    off = target - (pc + 4)
    if off & 1 or not -(1<<24) <= off < (1<<24):
        raise ValueError("bad thumb BL displacement")
    raw = off & ((1<<25)-1)
    s = (raw >> 24) & 1
    i1 = (raw >> 23) & 1
    i2 = (raw >> 22) & 1
    j1 = (1-i1)^s
    j2 = (1-i2)^s
    hw1 = 0xf000|(s<<10)|((raw>>12)&0x3ff)
    hw2 = 0xd000|(j1<<13)|(j2<<11)|((raw>>1)&0x7ff)
    return struct.pack("<HH",hw1,hw2)

class InboundPhase43Tests(unittest.TestCase):
    def test_thumb32_prefilter_includes_synthetic_bl(self):
        code = enc_bl(0x60080000, a.INIT)
        h1,h2=struct.unpack("<HH",code)
        self.assertTrue(a.candidate_thumb32_branch(h1,h2))
        result=a.decode_if_direct(a.decoder(),code,0,0x60080000)
        self.assertIsNotNone(result)
        self.assertEqual(int(result["target"],16),a.INIT)

    def test_thumb32_halfword_misaligned_source(self):
        p=0x60080002
        payload=b"\x00\xbf"+enc_bl(p,a.INIT)+b"\x00\xbf"
        result=a.decode_if_direct(a.decoder(),payload,2,p)
        self.assertEqual(int(result["target"],16),a.INIT)

    def test_cross_region_thumb_target_not_confused_with_caller(self):
        code=enc_bl(0x60081000,0x60070000)
        result=a.decode_if_direct(a.decoder(),code,0,0x60081000)
        self.assertNotEqual(int(result["target"],16),a.INIT)

    def test_raw_pointer_census_detects_unaligned_values(self):
        raw=struct.pack("<I",a.THUMB_TARGET)
        content=b"X"+raw+b"000"+raw
        report=a.all_byte_word_references(content,a.THUMB_TARGET)
        self.assertEqual(report["count"],2)
        self.assertEqual(report["file_offsets"],["0x1","0x8"])
        self.assertEqual(report["aligned4_count"],1)

    def test_register_indirect_excluded(self):
        class Fake:
            mnemonic="blx"
            op_str="r3"
        self.assertIsNone(a.parse_direct_target(Fake()))

    def test_hash_mismatch_rejected(self):
        with self.assertRaisesRegex(ValueError, "SHA256"):
            a.audit(b"wrong image")

if __name__=="__main__":
    unittest.main()
