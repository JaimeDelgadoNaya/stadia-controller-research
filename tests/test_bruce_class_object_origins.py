"""Offline synthetic tests for original signed Bruce class table origins."""
import struct
import unittest
from tools import audit_bruce_class_object_origins as a

class OriginTests(unittest.TestCase):
    def test_owner_sample_identity_required(self):
        with self.assertRaisesRegex(ValueError,"exact original"):
            a.inspect(bytes(a.IMAGE_SIZE))

    def test_word_parser_is_little_endian_data(self):
        fake=bytearray(0xC4C00)
        struct.pack_into("<I",fake,0xC4BA4,0x60055321)
        result=a.annotate_words(fake,0x60104BA4,0x60104BA8)
        self.assertEqual(result[0]["word"],"0x60055321")
        self.assertTrue(result[0]["is_xip_thumb_pointer"])

    def test_census_separates_table_entry_from_pointer_reference(self):
        fake=bytearray(0xFF030)
        struct.pack_into("<I",fake,0x40,0x60104BA4)
        struct.pack_into("<I",fake,0xC4BA4,0x60055321)
        found=a.pointer_literal_census(fake,{0x60104BA4,0x60104BA8})
        self.assertEqual(found[0]["source_file_offsets"],["0x40"])
        self.assertEqual(found[1]["count"],0)

    def test_invalid_data_range_rejected(self):
        with self.assertRaises(ValueError):
            a.annotate_words(b"",0x60104BA5,0x60104BB0)
        with self.assertRaises(ValueError):
            a._word(b"",0x60001000)
if __name__=="__main__":
    unittest.main()
