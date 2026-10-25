"""Synthetic tests of the read-only application surface; no real firmware."""
import hashlib
import struct
import unittest

from tools import audit_signed_app_surface as m


def fixture():
    image=bytearray(b"\xff"*m.IMAGE_SIZE)
    struct.pack_into("<II",image,0,0x2002B828,0x60040501)
    for at,encoding in m.ANCHORS.items():
        raw=bytes.fromhex(encoding)
        image[at:at+len(raw)]=raw
    for label,value in m.STRING_LABELS.items():
        offsets={
            "unknown_host_request":0xDB5F3,
            "applied_update_status":0xDBFC7,
            "vendor_component":0xDE054,
            "build_string":0xDB4B6,
        }
        at=offsets[label]
        image[at:at+len(value)]=value
        for ref in m.EXPECTED_REFERENCE_OFFSETS[label]:
            struct.pack_into("<I",image,ref,m.ASSUMED_XIP_BASE+at)
    return bytes(image)


def audited(image, expected_region=None):
    return m.inspect(
        image,
        expected_sha256=hashlib.sha256(image).hexdigest(),
        expected_region=expected_region or
            hashlib.sha256(image[m.REGION_BEGIN:m.REGION_END]).hexdigest()
    )


class SignedApplicationSurfaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fake=fixture()
        cls.region_digest=hashlib.sha256(
            cls.fake[m.REGION_BEGIN:m.REGION_END]).hexdigest()

    def test_pinned_original_hash_rejects_synthetic(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            m.inspect(self.fake)

    def test_vector_fields_match_assumed_application_offset(self):
        v=audited(self.fake)["model"]
        self.assertEqual(v["initial_stack_pointer"],"0x2002b828")
        self.assertEqual(v["thumb_reset_vector"],"0x60040501")
        self.assertEqual(v["base_assumption"],"0x60040000")

    def test_parser_entry_first_byte_guard_and_target(self):
        p=audited(self.fake)["parser_candidate"]
        self.assertEqual(p["entry"],"0x60058b68")
        self.assertEqual(p["payload_first_byte_guard"],"0x60058b74")
        self.assertEqual(p["guard_value"],5)
        self.assertEqual(p["next_direct_call"],"0x60058aa8")
        self.assertIn("NOT USB bRequest",p["guard_classification"])

    def test_string_references_are_limited_and_labeled(self):
        refs=audited(self.fake)["read_only_literal_xrefs"]
        self.assertEqual(refs["unknown_host_request"]["word_reference_file_offsets"],
                         ["0x00018bd8"])
        self.assertEqual(refs["vendor_component"]["reference_count"],2)
        self.assertEqual(refs["build_string"]["reference_count"],2)

    def test_not_an_installed_firmware_claim(self):
        r=audited(self.fake)
        self.assertEqual(r["same_as_full_installed_flash"],"NOT VERIFIED")
        self.assertEqual(r["limits"]["safe_custom_execution"],"NOT DEMONSTRATED")
        self.assertFalse(r["usb_io"])

    def test_wrong_vector_rejected(self):
        b=bytearray(self.fake)
        struct.pack_into("<I",b,4,0x60041001)
        with self.assertRaisesRegex(ValueError,"vector"):
            audited(bytes(b))

    def test_original_region_fingerprint_detects_mutation(self):
        b=bytearray(self.fake)
        b[0x18B84]^=1
        with self.assertRaisesRegex(ValueError,"fingerprint"):
            audited(bytes(b),expected_region=self.region_digest)

    def test_changed_parser_guard_rejected_by_anchor(self):
        b=bytearray(self.fake)
        b[0x18B74]^=1
        with self.assertRaisesRegex(ValueError,"anchor"):
            audited(bytes(b))

    def test_wrong_bl_target_rejected(self):
        b=bytearray(self.fake)
        b[0x18B7A]^=1
        with self.assertRaisesRegex(ValueError,"call destination|Thumb BL"):
            audited(bytes(b))

    def test_literal_pointer_mutation_rejected(self):
        b=bytearray(self.fake)
        struct.pack_into("<I",b,0x18BD8,0)
        with self.assertRaisesRegex(ValueError,"xrefs"):
            audited(bytes(b))

    def test_missing_string_rejected(self):
        b=bytearray(self.fake)
        b[0xDB5F3]^=1
        with self.assertRaisesRegex(ValueError,"label absent"):
            audited(bytes(b))

    def test_image_length_rejected(self):
        with self.assertRaisesRegex(ValueError,"1050984"):
            audited(self.fake[:-1])

    def test_decoder_rejects_non_bl_and_odd_locations(self):
        with self.assertRaisesRegex(ValueError,"Not an unconditional"):
            m.decode_thumb_bl_target(self.fake,0x18B74)
        with self.assertRaisesRegex(ValueError,"Invalid Thumb BL"):
            m.decode_thumb_bl_target(self.fake,0x18B75)

    def test_no_exploit_or_execution_inference(self):
        r=audited(self.fake)
        self.assertEqual(r["parser_candidate"]["reachable_from_real_host_usb_request"],
                         "NOT DEMONSTRATED")
        self.assertEqual(r["parser_candidate"]["update_write_or_HAB_authentication_path"],
                         "NOT DEMONSTRATED")
        self.assertEqual(r["limits"]["HAB_closed_bypass"],"NOT DEMONSTRATED")
        self.assertFalse(r["flash_or_fuse_writes"])


if __name__=="__main__":
    unittest.main()
