"""Synthetic phase-19 callback provenance regression tests; no OEM binaries."""
import hashlib
import struct
import unittest
from tools import audit_vendor_completion as m

def fixture():
    data=bytearray(b"\xff"*m.SIZE)
    for off, encoded in m.ANCHORS.items():
        raw=bytes.fromhex(encoded)
        data[off:off+len(raw)]=raw
    for off,val in ((0xBBAC,0x60814F34),(0xBBB4,m.SEND_THUMB),(0xBBB8,m.RECV_THUMB)):
        struct.pack_into("<I",data,off,val)
    struct.pack_into("<III",data,0x14F34,0x60809E25,0x6080A045,0x60809E2D)
    struct.pack_into("<II",data,0x14F24,0x60809E31,0x6080A06B)
    data[0x15296:0x1529D]=bytes.fromhex("07058702000200")
    data[0x1529D:0x152A4]=bytes.fromhex("07050702000200")
    return bytes(data)

def digests(data):
    return {(a,b):hashlib.sha256(data[a:b]).hexdigest() for a,b in m.FINGERPRINTS}

def audited(data, fingerprints=None):
    return m.audit(data,expected_sha256=hashlib.sha256(data).hexdigest(),
                   fingerprints=digests(data) if fingerprints is None else fingerprints)

class VendorCompletionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image=fixture()

    def test_original_sha_rejects_fixture(self):
        with self.assertRaisesRegex(ValueError,"SHA-256 mismatch"):
            m.audit(self.image)

    def test_initial_in_and_out_are_return_only(self):
        result=audited(self.image)
        entries=result["initial_completion_handlers"]
        self.assertEqual(entries["bulk_in_0x87"]["handler"],"0x6080affa")
        self.assertEqual(entries["bulk_out_0x07"]["handler"],"0x6080affc")
        self.assertEqual(entries["bulk_in_0x87"]["handler_ram"],"0x20009170")
        self.assertEqual(entries["bulk_out_0x07"]["handler_ram"],"0x20009178")
        self.assertEqual(entries["bulk_out_0x07"]["context_ram"],"0x2000917c")
        self.assertTrue(all(x["machine_code"]=="7047" for x in entries.values()))
        self.assertEqual(result["vendor_object"]["base"],"0x20009160")
        self.assertFalse(result["device_access"])

    def test_completion_callback_registration_chain(self):
        report=audited(self.image)
        self.assertIn("0x60806558",report["callback_path"]["usb_completion"])
        self.assertEqual(report["callback_path"]["bulk_out_adapter"],"0x6080a06a")
        self.assertEqual(report["callback_path"]["vendor_completion_forwarder"],"0x6080a062")

    def test_replacement_and_other_paths_not_excluded(self):
        report=audited(self.image)
        self.assertEqual(report["later_handler_replacement"],"NOT RULED OUT")
        self.assertEqual(report["other_update_routes"],"NOT EXCLUDED")
        self.assertEqual(report["hab_closed_bypass"],"NOT DEMONSTRATED")
        self.assertEqual(report["usb_to_flash_writer"],"NOT DEMONSTRATED")
        self.assertFalse(report["usb_commands_sent"])

    def test_changed_out_constructor_literal_fails(self):
        bad=bytearray(self.image)
        struct.pack_into("<I",bad,0xBBB8,0x60801235)
        with self.assertRaisesRegex(ValueError,"constructor literal"):
            audited(bytes(bad))

    def test_changed_in_constructor_literal_fails(self):
        bad=bytearray(self.image)
        struct.pack_into("<I",bad,0xBBB4,0x60801235)
        with self.assertRaisesRegex(ValueError,"constructor literal"):
            audited(bytes(bad))

    def test_class_vtable_replacement_fails(self):
        bad=bytearray(self.image)
        struct.pack_into("<I",bad,0x14F34,0)
        with self.assertRaisesRegex(ValueError,"vendor class dispatch table"):
            audited(bytes(bad))

    def test_usb_callback_table_replacement_fails(self):
        bad=bytearray(self.image)
        struct.pack_into("<I",bad,0x14F24,0)
        with self.assertRaisesRegex(ValueError,"USB endpoint callback table"):
            audited(bytes(bad))

    def test_out_stub_mutation_fails(self):
        bad=bytearray(self.image)
        bad[0xAFFC] ^= 1
        with self.assertRaisesRegex(ValueError,"Instruction anchor"):
            audited(bytes(bad))

    def test_in_stub_mutation_fails(self):
        bad=bytearray(self.image)
        bad[0xAFFA] ^= 1
        with self.assertRaisesRegex(ValueError,"Instruction anchor"):
            audited(bytes(bad))

    def test_recv_function_store_mutation_fails(self):
        bad=bytearray(self.image)
        bad[0xBB5A] ^= 1
        with self.assertRaisesRegex(ValueError,"Instruction anchor"):
            audited(bytes(bad))

    def test_unanchored_region_mutation_fails(self):
        reference=digests(self.image)
        bad=bytearray(self.image)
        bad[0xBB5E] ^= 1
        with self.assertRaisesRegex(ValueError,"fingerprint mismatch"):
            audited(bytes(bad),reference)

    def test_bad_length_fails(self):
        with self.assertRaisesRegex(ValueError,"131072"):
            audited(self.image[:-1])

    def test_bad_usb_descriptor_fails(self):
        bad=bytearray(self.image)
        bad[0x1529F] ^= 1
        with self.assertRaisesRegex(ValueError,"vendor USB endpoint descriptors"):
            audited(bytes(bad))

    def test_exact_constructor_store_search_limited_scope(self):
        report=audited(self.image)
        self.assertEqual(report["literal_opcode_scan"]["exact_recv_store_0x600"],
                         ["0x6080bb5a"])
        self.assertIn("dynamic",report["literal_opcode_scan"]["limitation"])

if __name__ == "__main__":
    unittest.main()
