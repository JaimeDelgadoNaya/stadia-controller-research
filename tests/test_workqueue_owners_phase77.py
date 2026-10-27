"""Phase 77 bounded signed owner provenance and original SHA constraints."""
import json,os,unittest
from pathlib import Path
from tools import audit_workqueue_owners_phase77 as p

ROOT=Path(__file__).resolve().parents[1]
class Phase77OwnerOriginTests(unittest.TestCase):
    def test_known_signed_fields(self):
        self.assertEqual(p.CALL_A,0x6006228C)
        self.assertEqual(p.GLOBAL+0x3F04,p.OWNER+0x11C)
        self.assertEqual(p.B_DIRECT_ACTIVATION_CALL_PINS[0x600747D6],("mov","r0, r5"))
        self.assertEqual(p.CALL_B,0x6006B2B0)
        self.assertEqual(len(p.TARGETS),10)

    def test_original_B_ready_and_reset_pins(self):
        self.assertEqual(p.B_INIT_ANCHORS[0x6006B3EA],("ldrb.w","r3, [r0, #0x180]"))
        self.assertEqual(p.B_INIT_ANCHORS[0x6006B442],("strb.w","r3, [r4, #0x180]"))
        self.assertEqual(p.B_GATE_RESET_ANCHORS[0x6006B2C2],("strb.w","r0, [r4, #0x182]"))

    def test_invalid_original_signed_sample_rejected(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            p.audit(b"synthetic")

    def test_source_bounds_fail_closed(self):
        with self.assertRaisesRegex(ValueError,"outside signed OEM"):
            p.code_rows(b"x",p.BASE,p.BASE+0x10)

    @unittest.skipUnless(os.environ.get("STADIA_BRUCE_IMAGE"),"Original SHA-pinned image required")
    def test_original_image_and_limits(self):
        data=Path(os.environ["STADIA_BRUCE_IMAGE"]).read_bytes()
        result=p.audit(data)
        self.assertTrue(result["signed_pin_count"]>=9)
        self.assertTrue(result["B_signed_function_initializer"]["callback_origin"].startswith("SIGNED"))
        self.assertEqual(result["decision"]["physical_USB_origin"],"NOT_PROVEN")
        self.assertEqual(result["B_direct_activation_caller"]["modeled_B_object_under_phase66_input"],"0x2000a3c4")
        self.assertEqual(result["B_direct_activation_caller"]["direct_B_initializer"],"0x600747d8 BL 0x6006b3e8")
        self.assertEqual(result["B_object_initializer_and_local_gate"]["original_signed_instruction_pins"],14)
        self.assertEqual(result["decision"]["A_R4_owner"],"LOCAL_PROVENANCE_R4_FROM_R2_AT_0x6006212C; caller of function unknown")

    @unittest.skipUnless(os.environ.get("STADIA_BRUCE_IMAGE") and
                          (ROOT/"evidence/usb-workqueue-owner-origin-phase77.json").exists(),
                          "Published signed phase77 evidence not yet available")
    def test_published_evidence(self):
        data=Path(os.environ["STADIA_BRUCE_IMAGE"]).read_bytes()
        evidence=json.loads((ROOT/"evidence/usb-workqueue-owner-origin-phase77.json").read_text())
        if "B_direct_activation_caller" not in evidence:
            self.skipTest("Published evidence predates newly verified activation-caller field")
        if "modeled_B_object_under_phase66_input" not in evidence.get("B_direct_activation_caller",{}):
            self.skipTest("Published phase77 evidence predates newly verified modeled pointer lineage")
        self.assertEqual(p.audit(data),evidence)

if __name__=="__main__":unittest.main()
