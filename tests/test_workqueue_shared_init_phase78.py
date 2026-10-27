"""Phase 78 original signed global Work Queue guard and USB-origin limits."""
import os,json,unittest
from pathlib import Path
from tools import audit_workqueue_shared_init_phase78 as p

ROOT=Path(__file__).resolve().parents[1]

class Phase78SignedQueueInitTests(unittest.TestCase):
    def test_known_original_source_addresses(self):
        self.assertEqual((p.HELPER,p.CREATE),(0x6009267C,0x6010177A))
        self.assertEqual(p.PINS[p.MODE_CALL],("bl","#0x6009267c"))
        self.assertEqual(p.PINS[p.B_CALL],("bl","#0x6009267c"))
        self.assertEqual(p.PINS[0x60060F32],("mov","r0, r3"))
        self.assertEqual(p.PINS[0x6006B3FE],("movs","r0, #1"))
    def test_original_source_sha_rejects_synthetic(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            p.audit(b"not signed original")

    @unittest.skipUnless(os.environ.get("STADIA_BRUCE_IMAGE"),
                         "Exact original OEM image not mounted")
    def test_original_signed_helper_and_two_guard_paths(self):
        data=Path(os.environ["STADIA_BRUCE_IMAGE"]).read_bytes()
        result=p.audit(data)
        self.assertEqual(result["signed_initialization"]["worker_label"],"Work Queue Task")
        self.assertEqual(result["signed_initialization"]["queue_object"],"0x2002014c")
        cases=result["virtual_guard_cases"]
        self.assertTrue(cases[0]["stop_before_creation"])
        self.assertFalse(cases[1]["stop_before_creation"])
        self.assertTrue(cases[1]["original_helper_returned_without_creation"])
        self.assertTrue(all(c["r2_after"]=="0x1" for c in cases))
        self.assertTrue(all(not c["creation_executed"] for c in cases))
        self.assertEqual(result["interpretation"]["proof_of_USB_physical_event_to_work_item"],"NOT_ESTABLISHED")

    @unittest.skipUnless(os.environ.get("STADIA_BRUCE_IMAGE") and
        (ROOT/"evidence/usb-workqueue-shared-init-phase78.json").exists(),
        "Original signed OEM and recorded original evidence required")
    def test_published_evidence_reproduction(self):
        image=Path(os.environ["STADIA_BRUCE_IMAGE"]).read_bytes()
        expected=json.loads((ROOT/"evidence/usb-workqueue-shared-init-phase78.json").read_text())
        self.assertEqual(p.audit(image),expected)

if __name__=="__main__":unittest.main()
