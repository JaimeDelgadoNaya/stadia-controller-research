"""Phase46 synthetic event1 bRequest bridge and gate regressions; no USB."""
import unittest
from tools import audit_bruce_event_to_brequest_phase46 as p

class Event1BRequest46Tests(unittest.TestCase):
    def test_event1_branch_table_math(self):
        self.assertEqual(p.EVENT_TABLE_BASE,0x600D0E6C)
        self.assertEqual((p.EVENT1_EXPECTED-p.EVENT_TABLE_BASE)//2,27)
        self.assertEqual(p.PINS[0x600CFC46],("movs","r1, #1"))
        self.assertEqual(p.EVENT_TABLE_BASE+2*18,0x600D0E90)
        self.assertEqual(p.PINS[0x600D0EB8],("ldrb","r1, [r1, #1]"))

    def test_missing_ep0_runtime_registration_is_not_success(self):
        self.assertEqual(p.symbolic_chain_event1(endpoint_registered=False,
                         class_vtable_matches=True,setup_pointer_valid=True),
                         "EP0_SLOT_UNKNOWN")

    def test_missing_class_vtable_is_not_success(self):
        self.assertEqual(p.symbolic_chain_event1(endpoint_registered=True,
                         class_vtable_matches=False,setup_pointer_valid=True),
                         "CLASS_EVENT_METHOD_UNKNOWN")

    def test_missing_setup_source_is_not_success(self):
        self.assertEqual(p.symbolic_chain_event1(endpoint_registered=True,
                         class_vtable_matches=True,setup_pointer_valid=False),
                         "SETUP_BUFFER_POINTER_UNVERIFIED")

    def test_only_interface_eligible(self):
        kwargs={"endpoint_registered":True,"class_vtable_matches":True,
                "setup_pointer_valid":True}
        self.assertEqual(p.symbolic_chain_event1(**kwargs,bm_request_type=0x20),
                         "INTERFACE_RECIPIENT_REJECTED")
        self.assertEqual(p.symbolic_chain_event1(**kwargs,iface_matches=False),
                         "INTERFACE_NUMBER_REJECTED")
        self.assertEqual(p.symbolic_chain_event1(**kwargs),
                         "CONDITIONAL_CLASS10_BREQUEST_BYTE_PATH")

    def test_original_image_sha_required(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            p.audit(b"made-up binary")

if __name__=="__main__":
    unittest.main()
