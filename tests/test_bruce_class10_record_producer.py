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
    def test_two_adjacent_original_layouts_in_synthetic_buffer(self):
        blob=bytearray(p.IMAGE_SIZE)
        import struct
        for off,func,desc,sel in p.SIGNED_BOOT_RECORDS:
            struct.pack_into("<III",blob,off,func,0,desc)
            source=p.DATA_SOURCE_OFFSET+(desc-p.DATA_DESTINATION)
            blob[source+4]=sel
        rows=p.confirmed_boot_records(blob)
        self.assertEqual([r["byte_at_descriptor_plus_4"] for r in rows],[2,10])
        self.assertEqual(rows[1]["callback_function_address"],"0x600613fc")
        self.assertEqual(rows[1]["destination_boot_RAM"],"0x200030f4")
        blob[0xFDF5C]=0x00
        with self.assertRaisesRegex(ValueError,"drift"):
            p.confirmed_boot_records(blob)

    def test_callback_guard_pin_drift_detected(self):
        self.assertTrue(p.check_pins(dict(p.HANDLER_PINS),p.HANDLER_PINS))
        altered=dict(p.HANDLER_PINS)
        altered[0x600613FC]=("cmp","r1, #0xff")
        with self.assertRaisesRegex(ValueError,"drift"):
            p.check_pins(altered,p.HANDLER_PINS)

    def test_scanner_respects_12_byte_record_boundary(self):
        blob=bytearray(0x48)
        struct.pack_into("<III",blob,0x10,0x60055101,0,0x60104200)
        r=p.scan_range(blob,0x0,0x18,label="test")
        self.assertEqual(r["all_shape_matches"],1)
if __name__=="__main__":
    unittest.main()
