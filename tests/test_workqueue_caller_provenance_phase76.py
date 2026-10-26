"""Phase 76 original signed caller attribution and no-host-control guards."""
import json
import os
from pathlib import Path
import unittest
from tools import audit_workqueue_caller_provenance_phase76 as a

ROOT=Path(__file__).resolve().parents[1]

class WorkQueueCallerProvenanceTests(unittest.TestCase):
    def test_callsite_boundaries(self):
        self.assertEqual(a.CALL_A,0x6006228C)
        self.assertEqual(a.CALL_B,0x6006B2B0)
        self.assertEqual(a.API,0x600926A0)
        self.assertEqual(a.CALL_A_ANCHORS[0x60062288],
                         ("add.w","r0, r4, #0x10"))
        self.assertEqual(a.CALL_B_ANCHORS[0x6006B2AC],
                         ("add.w","r0, r4, #0x11c"))

    def test_signed_anchor_covers_status_conditions(self):
        self.assertEqual(a.CALL_A_ANCHORS[0x60062272],
                         ("ldrexb","r3, [r5]"))
        self.assertEqual(a.CALL_B_ANCHORS[0x6006B294],
                         ("bl","#0x600d8f64"))
        self.assertEqual(a.CALL_B_ANCHORS[0x6006B2AA],
                         ("bne","#0x6006b2cc"))

    def test_host_USB_is_not_assumed_from_function_proximity(self):
        self.assertNotIn(a.CALL_A,a.USB_ANCHOR_TARGETS.values())
        self.assertNotIn(a.CALL_B,a.USB_ANCHOR_TARGETS.values())
        self.assertEqual(a.B_ENTRY,0x6006B290)

    def test_original_B_callback_and_shared_helper_expected_anchors(self):
        self.assertEqual(a.CALL_B_INSTALL_PINS[0x6006B416],
                         ("ldr","r3, [pc, #0x9c]"))
        self.assertEqual(a.CALL_B_INSTALL_PINS[0x6006B41C],
                         ("str.w","r4, [r4, #0x120]"))
        self.assertEqual(a.CALL_B_INSTALL_PINS[0x6006B420],
                         ("str.w","r3, [r4, #0x11c]"))
        self.assertEqual(a.B_CALLBACK_WORD_PC,0x6006B4B4)

    def test_sha_fail_closed(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            a.audit(b"synthetic-no-signed-oem")

    def test_boundaries_reject_malformed_XIP(self):
        with self.assertRaisesRegex(ValueError,"outside image"):
            a.rows(b"",a.BASE,a.BASE+100)

    @unittest.skipUnless(os.environ.get("STADIA_BRUCE_IMAGE"),
                         "Original signed OEM image not mounted")
    def test_original_signed_pins_and_no_invented_USB(self):
        image=Path(os.environ["STADIA_BRUCE_IMAGE"]).read_bytes()
        found=a.audit(image)
        self.assertEqual(found["signed_original_pin_counts"]["total_pins"],
                         len(a.CALL_A_ANCHORS)+len(a.CALL_B_ANCHORS))
        self.assertEqual(len(found["signed_producer_callsites"]),2)
        self.assertEqual(found["limits"]["physical_USB_event_origin"],"UNPROVEN")
        self.assertEqual(found["limits"]["callback_BLX"],"NOT_EXECUTED")
        self.assertEqual(found["B_signed_callback_initializer"]["literal_value"],
                         "0x6006b291")
        self.assertEqual(found["B_signed_callback_initializer"]["callback_origin"],
                         "SIGNED_OEM_INITIALIZER_STATICALLY_PROVEN")
        self.assertEqual(
            found["phase66_phase76_shared_signed_helper"]["shared_target"],
            "0x6009267c")
        self.assertEqual(found["B_nested_status_source_xrefs"]
                         ["B_callback_literal_PC_load_candidates"][0]["pc"],
                         "0x6006b416")

    @unittest.skipUnless(
        os.environ.get("STADIA_BRUCE_IMAGE") and
        (ROOT/"evidence/usb-workqueue-caller-provenance-phase76.json").exists(),
        "Original signed OEM and published evidence required")
    def test_original_evidence_reproducibility(self):
        image=Path(os.environ["STADIA_BRUCE_IMAGE"]).read_bytes()
        expected=json.loads(
            (ROOT/"evidence/usb-workqueue-caller-provenance-phase76.json").read_text()
        )
        self.assertEqual(a.audit(image),expected)

if __name__=="__main__":
    unittest.main()
