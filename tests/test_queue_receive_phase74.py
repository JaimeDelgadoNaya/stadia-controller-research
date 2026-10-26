"""Phase74 original queue receiver fail-closed and modeled-state boundary tests."""
import unittest
from tools.audit_queue_receive_phase74 import audit,itcm_code,word,receiver_code,VENEER
from tools.audit_usb_provider_phase63 import BASE


class QueueReceivePhase74Tests(unittest.TestCase):
    def test_original_SHA_gate(self):
        with self.assertRaisesRegex(ValueError,"SHA-pinned"):
            audit(b"not signed")

    def test_exact_target_at_bounded_entry(self):
        self.assertEqual(VENEER,0x6013D268)

    def test_signed_word_rejects_invalid_addresses(self):
        with self.assertRaisesRegex(ValueError,"Invalid"):
            word(b"x"*128,BASE+3)
        with self.assertRaisesRegex(ValueError,"Invalid"):
            word(b"x"*128,BASE+128)

    def test_signed_ITCM_target_rejects_unaligned(self):
        with self.assertRaisesRegex(ValueError,"Outside"):
            itcm_code(b"bad",1,16)

    def test_signed_ITCM_target_rejects_out_of_range(self):
        from tools.audit_app_usb_dispatch import ITCM_LENGTH
        with self.assertRaisesRegex(ValueError,"Outside"):
            itcm_code(b"bad",ITCM_LENGTH-2,32)

    def test_no_implicit_veneer_semantics_for_dummy(self):
        with self.assertRaises(ValueError):
            receiver_code(b"short")

if __name__=="__main__":
    unittest.main()
