"""Original signed owner-pointer xref gate checks, no physical controller assumptions."""
import unittest
from tools import audit_bruce_owner_xrefs_phase50 as a
class OriginalOwnerXrefs50(unittest.TestCase):
    def test_base_and_three_derived_fields(self):
        self.assertEqual(a.OWNER,0x2000a2a8)
        self.assertEqual([a.OWNER+n for n in (4,8,12)],[0x2000a2ac,0x2000a2b0,0x2000a2b4])
    def test_required_signed_file(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):a.audit(b"not original")
if __name__=="__main__":unittest.main()
