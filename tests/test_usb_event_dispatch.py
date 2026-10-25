"""Synthetic regression tests for phase 15; never access original firmware or USB."""
import hashlib
import unittest
from unittest.mock import patch

from tools import audit_usb_event_dispatch as m


def fixture():
    data = bytearray(m.IMAGE_BYTES)
    data[m.TRANSFER_GUARD:m.TRANSFER_GUARD+4] = m.GUARD_BYTES
    data[m.DISPATCH:m.DISPATCH+8] = m.DISPATCH_BYTES
    data[m.DISPATCH+12:m.DISPATCH+16] = m.TBB_BYTES
    data[m.TABLE:m.TABLE+11] = bytes.fromhex("0632458686495d86707680")
    data[m.DEFAULT:m.DEFAULT+2] = m.DEFAULT_BYTES
    data[m.VENDOR_HANDLER:m.VENDOR_HANDLER+6] = m.VENDOR_BYTES
    data[m.CLASS_EVENT_TABLE:m.CLASS_EVENT_TABLE+4] = (
        m.BASE+m.DISPATCH+1).to_bytes(4,"little")
    data[m.VENDOR_EVENT_TABLE:m.VENDOR_EVENT_TABLE+4] = (
        m.BASE+m.VENDOR_HANDLER+1).to_bytes(4,"little")
    data[0xBBB0:0xBBB4] = m.DEFAULT_VENDOR_POINTER.to_bytes(4,"little")
    image = bytes(data)
    spans = {(start,end):hashlib.sha256(image[start:end]).hexdigest()
             for start,end in m.SPANS}
    return image, spans


def run_fixture(image, spans):
    with patch.object(m, "SPANS", spans):
        return m.audit(image, expected_sha256=hashlib.sha256(image).hexdigest())


class UsbEventDispatchTests(unittest.TestCase):
    def test_real_digest_rejects_synthetic(self):
        image,_=fixture()
        with self.assertRaisesRegex(ValueError,"SHA-256 mismatch"):
            m.audit(image)

    def test_invalid_size_rejected(self):
        image, spans=fixture()
        for other in (image[:-1], image+b"\0"):
            with self.subTest(size=len(other)), self.assertRaisesRegex(ValueError,"131072"):
                run_fixture(other, spans)

    def test_byte_fingerprints_are_checked(self):
        image,spans=fixture()
        bad=bytearray(image)
        bad[0x9b50] ^= 1
        with self.assertRaisesRegex(ValueError,"Instruction evidence mismatch"):
            run_fixture(bytes(bad),spans)

    def test_valid_synthetic_report(self):
        image,spans=fixture()
        report=run_fixture(image,spans)
        self.assertTrue(report["image_sha256_verified"])
        self.assertFalse(report["usb_commands_sent"])
        self.assertFalse(report["flash_write_or_fuse_operations"])
        self.assertEqual(report["usb_host_command_parser"],"NOT IDENTIFIED")
        self.assertEqual(report["custom_firmware_execution"],"NOT DEMONSTRATED")
        self.assertEqual(report["transfer_guard"]["maximum_bytes_at_this_helper"],512)

    def test_event_table_exact_11_cases(self):
        image,spans=fixture()
        cases=run_fixture(image,spans)["event_dispatch"]["cases"]
        self.assertEqual([c["event_id"] for c in cases],list(range(1,12)))
        self.assertEqual([c["entry"] for c in cases],[
            "0x60809c74","0x60809ccc","0x60809cf2",
            "0x60809d74","0x60809d74","0x60809cfa",
            "0x60809d22","0x60809d74","0x60809d48",
            "0x60809d54","0x60809d68"])
        self.assertEqual([c["event_id"] for c in cases
                          if c["uses_default_error_branch"]],[4,5,8])

    def test_bad_event_target_rejected(self):
        image,_=fixture()
        changed=bytearray(image)
        changed[m.TABLE]=0
        changed=bytes(changed)
        spans={(a,b):hashlib.sha256(changed[a:b]).hexdigest() for a,b in m.SPANS}
        with self.assertRaisesRegex(ValueError,"Unexpected event-table"):
            run_fixture(changed,spans)

    def test_bad_vendor_callback_pointer_rejected(self):
        image,spans=fixture()
        changed=bytearray(image)
        changed[m.VENDOR_EVENT_TABLE]=0
        with self.assertRaisesRegex(ValueError,"class-event callback pointers"):
            run_fixture(bytes(changed),spans)

    def test_bad_default_registration_rejected(self):
        image,spans=fixture()
        changed=bytearray(image)
        changed[0xBBB0:0xBBB4]=(m.BASE+1).to_bytes(4,"little")
        with self.assertRaisesRegex(ValueError,"initial default vendor"):
            run_fixture(bytes(changed),spans)

    def test_transfer_guard_anchor_rejected_after_rehash(self):
        image,_=fixture()
        changed=bytearray(image)
        changed[m.TRANSFER_GUARD+1] ^= 0x10
        changed=bytes(changed)
        spans={(a,b):hashlib.sha256(changed[a:b]).hexdigest() for a,b in m.SPANS}
        with self.assertRaisesRegex(ValueError,"Transfer limit"):
            run_fixture(changed,spans)

    def test_source_fingerprints_have_expected_shape(self):
        self.assertEqual(len(m.SPANS),7)
        for (start,end),digest in m.SPANS.items():
            self.assertLess(start,end)
            self.assertLessEqual(end,m.IMAGE_BYTES)
            self.assertEqual(len(digest),64)


if __name__=="__main__":
    unittest.main()
