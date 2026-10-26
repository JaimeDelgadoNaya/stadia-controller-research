"""Synthetic-only regression for phase46 USB1-to-class endpoint evidence."""
import unittest
from tools import audit_bruce_usb1_ep0_bridge_phase46 as p

class USB1EP0BridgeTests(unittest.TestCase):
    def test_usb1_vector_slot_mapping(self):
        self.assertEqual(p.VECTOR_USB_OTG1_OFFSET,(16+113)*4)
        self.assertEqual(p.VECTOR_USB_OTG1_OFFSET,0x204)

    def test_thumb_callback_literal_targets_are_original_signed(self):
        self.assertEqual(p.CALLBACK_THUMB_POINTER_ANCHORS[0x600547A0],0x600CFC71)
        self.assertEqual(p.CALLBACK_THUMB_POINTER_ANCHORS[0x60054870],0x600CFC1B)

    def test_receiver_dispatch_anomaly_stays_guarded(self):
        self.assertEqual(p.EP0_RECEIVER_ANCHORS[0x600D104E],("blx","r5"))
        self.assertEqual(p.REGISTRAR_ANCHORS[0x600D10DA],("str","r2, [r3, #0x10]"))

    def test_stale_bytes_cannot_pass_original_sha(self):
        with self.assertRaisesRegex(ValueError,"SHA-pinned"):
            p.scan(b"synthetic instead of OEM image")

    def test_read_u32_out_of_bounds(self):
        with self.assertRaisesRegex(ValueError,"outside"):
            p.read_u32(b"1234",2)


if __name__=="__main__":
    unittest.main()
