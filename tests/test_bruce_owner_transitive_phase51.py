"""Phase 51: one-hop candidate scanning remains read-only and explicitly bounded."""
import unittest
from tools import audit_bruce_owner_transitive_phase51 as a
class OneHop51(unittest.TestCase):
    def test_follows_relevant_owner_thunk_targets(self):
        self.assertEqual(a.FOLLOW["owner_config_init_function"],0x60060f84)
        self.assertEqual(a.FOLLOW["owner_mode2_transition"],0x60060fe8)
        self.assertEqual(a.FOLLOW["owner_thunk_to_0x600d4e64"],0x600d4e64)
        self.assertLess(a.SPAN,0x100)
    def test_original_signed_sha_required(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):a.inspect(b"synthetic")
if __name__=="__main__":unittest.main()
