"""Synthetic evidence checks for Cortex-M USB vector mapping in signed Bruce."""
import unittest

from tools import audit_bruce_usb_irq_vector as v


class USBVectorTests(unittest.TestCase):
    def test_nxp_irq_slots(self):
        self.assertEqual((v.CORE_EXCEPTIONS+v.IRQS["USB_OTG2"])*4,0x200)
        self.assertEqual((v.CORE_EXCEPTIONS+v.IRQS["USB_OTG1"])*4,0x204)

    def test_pointer_classifier_does_not_infer_ep0(self):
        self.assertEqual(v.categorize(0),"non_thumb_or_null")
        self.assertEqual(v.categorize(0x60040201),"signed_flash_XIP")
        self.assertEqual(v.byte_offset_for_handler(0x60040201),0x200)
        self.assertEqual(v.categorize(0x000021a1),"startup_relocated_ITCM_candidate")
        self.assertEqual(v.byte_offset_for_handler(0x000021a1),
                         v.ITCM_SOURCE_OFFSET+0x21a0)
        self.assertEqual(v.categorize(0x20001235),"RAM_pointer_unverified")
        self.assertIsNone(v.byte_offset_for_handler(0x20001235))

    def test_signed_setup_dispatch_anchors_and_semantic_drift(self):
        original=dict(v.EP0_RECEIVER_ANCHORS)
        self.assertTrue(v.check_setup_dispatch_anchors(original))
        altered=dict(original)
        altered[0x600D104E]=("bx","lr")
        with self.assertRaisesRegex(ValueError,"semantic drift"):
            v.check_setup_dispatch_anchors(altered)

    def test_callback_is_dynamic_not_an_immediate_constant(self):
        self.assertEqual(v.EP0_RECEIVER_ANCHORS[0x600D104A],
                         ("ldrd","r5, r2, [r3, #0xc]"))
        self.assertEqual(v.EP0_RECEIVER_ANCHORS[0x600D104E],("blx","r5"))

    def test_source_requires_exact_original(self):
        with self.assertRaisesRegex(ValueError,"signed Bruce"):
            v.inspect(bytes(v.IMAGE_SIZE))


if __name__=="__main__":
    unittest.main()
