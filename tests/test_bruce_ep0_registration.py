"""Synthetic safety and utility tests for SHA-pinned EP0 registration discovery."""
import unittest
from tools import audit_bruce_ep0_registration as r

class EP0RegistrationTests(unittest.TestCase):
    def test_slot_arithmetic(self):
        self.assertEqual(r.EP0_OUT_INDEX,0)
        self.assertEqual(r.EP0_IN_INDEX,1)
        self.assertEqual(r.ENDPOINT_STRIDE,12)
        self.assertEqual(0xc+r.ENDPOINT_STRIDE,0x18)

    def test_registrar_provenance_pins_callback_and_context_stores(self):
        decoded=dict(r.REGISTRAR_ANCHORS)
        pointers=dict(r.CALLBACK_THUMB_POINTER_ANCHORS)
        self.assertTrue(r.validate_registration_anchors(decoded,pointers))
        self.assertEqual(decoded[0x600D10DE],("str","r4, [r3, #0xc]"))
        self.assertEqual(decoded[0x600D10DA],("str","r2, [r3, #0x10]"))
        self.assertEqual(pointers[0x600547A8],0x600CFC53)

    def test_semantic_drift_and_literal_drift_rejected(self):
        decoded=dict(r.REGISTRAR_ANCHORS)
        pointers=dict(r.CALLBACK_THUMB_POINTER_ANCHORS)
        decoded[0x600D10DE]=("str","r4, [r3, #0x1c]")
        with self.assertRaisesRegex(ValueError,"semantic drift"):
            r.validate_registration_anchors(decoded,pointers)
        decoded=dict(r.REGISTRAR_ANCHORS)
        pointers[0x60054870]=0x600CFC1D
        with self.assertRaisesRegex(ValueError,"literal pointer drift"):
            r.validate_registration_anchors(decoded,pointers)

    def test_requires_known_exact_oem_image(self):
        with self.assertRaisesRegex(ValueError,"Exact signed Bruce"):
            r.audit(bytes(r.IMAGE_SIZE))

    def test_bl_target_decode_is_not_host_request(self):
        self.assertEqual(r.direct_call_target({"m":"bl","op":"#0x600d0fb6"}),0x600d0fb6)
        self.assertIsNone(r.direct_call_target({"m":"blx","op":"r5"}))
        self.assertIsNone(r.direct_call_target({"m":"str","op":"r0, [r1]"}))
        self.assertIsNone(r.direct_call_target({"m":"bl","op":"r3"}))
        self.assertIsNone(r.direct_call_target({"m":"bl","op":"#invalid"}))

    def test_decode_bounds(self):
        for start,end in [(0,2),(r.BASE,r.BASE),(r.BASE-2,r.BASE+4),
                          (r.BASE+0xff000-2,r.BASE+0xff000+4)]:
            with self.subTest(start=start):
                with self.assertRaises(ValueError):
                    r.decode(b"",start,end)


if __name__=="__main__":
    unittest.main()
