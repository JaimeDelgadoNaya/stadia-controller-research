"""Pure synthetic regression for bounded, signed-data record-candidate census."""
import struct
import unittest
from tools import audit_bruce_class10_record_producer as p

class Class10ProducerCensus(unittest.TestCase):
    def test_raises_on_non_original_image(self):
        with self.assertRaisesRegex(ValueError,"Exact signed"):
            p.inspect(bytes(p.IMAGE_SIZE))
    def test_initialized_data_triplet_candidates(self):
        blob=bytearray(p.IMAGE_SIZE)
        off=p.DATA_SOURCE_OFFSET+0x20
        struct.pack_into("<III",blob,off,0x60055101,0,0x60104200)
        blob[0xC4200+4]=10
        item=p.record_candidate(blob,off,label="test")
        self.assertTrue(item["matches_class10_byte"])
        self.assertEqual(item["copied_to_ram"],hex(p.DATA_DESTINATION+0x20))
        self.assertEqual(item["candidate_callback_word"],"0x60055101")
    def test_shape_rejects_externally_unbounded_function_pointer(self):
        blob=bytearray(0x40)
        struct.pack_into("<III",blob,0,0x20003001,0,0x60104200)
        self.assertIsNone(p.record_candidate(blob,0,label="test"))
    def test_unknown_ram_descriptor_is_not_claimed_class10(self):
        blob=bytearray(0x40)
        struct.pack_into("<III",blob,0,0x60055101,0,0x2000A100)
        item=p.record_candidate(blob,0,label="test")
        self.assertFalse(item["matches_class10_byte"])
        self.assertIsNone(item["descriptor_byte_plus_4"])
    def test_scanner_respects_12_byte_record_boundary(self):
        blob=bytearray(0x48)
        struct.pack_into("<III",blob,0x10,0x60055101,0,0x60104200)
        r=p.scan_range(blob,0x0,0x1c,label="test")
        self.assertEqual(r["all_shape_matches"],1)
if __name__=="__main__":
    unittest.main()
