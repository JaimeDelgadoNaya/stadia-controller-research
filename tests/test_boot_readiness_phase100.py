"""Synthetic IVT and HAB gate regression; no physical board or firmware writes."""
import struct
import unittest
from tools.audit_boot_readiness_phase100 import (
    IVTError,inspect_ivt,compare_bootloaders,hab_scenario,synthetic_reference
)
def fixture(*,length=128,csf=0,offset=0,declared=128):
    b=bytearray(length)
    base=0x60001000 if offset==0 else 0x20000000
    selfptr=base+offset
    struct.pack_into("<8I",b,offset,0x412000d1,base+4096,0,0,selfptr+32,selfptr,csf,0)
    struct.pack_into("<3I",b,offset+32,base,declared,0)
    return bytes(b)

class BootGatePhase100(unittest.TestCase):
    def test_ivt_without_csf_has_no_signature(self):
        x=inspect_ivt(fixture(),0)
        self.assertEqual(x.csf_address,0)
        self.assertFalse(x.signature_verified)
        self.assertFalse(x.hab_closed_boot_verified)
    def test_csf_pointer_alone_proves_nothing(self):
        x=inspect_ivt(fixture(csf=0x60818000),0)
        self.assertNotEqual(x.csf_address,0)
        self.assertFalse(x.signature_verified)
    def test_loader_ivt_offset_0x400(self):
        x=inspect_ivt(fixture(offset=0x400,length=2048,declared=4096),0x400)
        self.assertEqual(x.self_address,0x20000400)
        self.assertEqual(x.declared_minus_supplied,2048)
    def test_invalid_ivt_header_rejected(self):
        with self.assertRaises(IVTError):inspect_ivt(bytes(128),0)
    def test_invalid_boot_data_address_rejected(self):
        blob=bytearray(fixture())
        struct.pack_into("<I",blob,0x10,0x30000000)
        with self.assertRaises(IVTError):inspect_ivt(bytes(blob),0)
    def test_original_and_changed_candidates(self):
        a=fixture(csf=0x60818000,declared=128)
        b=fixture(length=64,declared=128)
        c=compare_bootloaders(a,b)
        self.assertEqual(c["changes_in_shared_prefix"],3)
        self.assertFalse(c["candidate_csf_pointer"])
        self.assertFalse(c["candidate_retail_boot_proven"])
        self.assertFalse(c["safe_to_flash"])
    def test_closed_unsigned_rejected_even_after_sdp(self):
        a=hab_scenario("CLOSED",False,sdp_entered=True)
        self.assertFalse(a["candidate_signature_prerequisites_met"])
        self.assertFalse(a["sdp_proves_signature_bypass"])
        self.assertFalse(a["retail_flash_permitted"])
    def test_open_dev_board_is_not_retail_permission(self):
        self.assertFalse(hab_scenario("OPEN",False)["retail_flash_permitted"])
    def test_unknown_state_not_trusted(self):
        self.assertFalse(hab_scenario("UNKNOWN",True,True)["candidate_signature_prerequisites_met"])
    def test_even_trusted_synthetic_case_recovery_missing(self):
        x=hab_scenario("CLOSED",True,True)
        self.assertTrue(x["candidate_signature_prerequisites_met"])
        self.assertFalse(x["device_recovery_validated"])
        self.assertFalse(x["retail_flash_permitted"])
    def test_reference_no_retail_proof(self):
        x=synthetic_reference()
        self.assertEqual(x["changed_bytes_in_prefix"],72)
        self.assertEqual(x["community_ram_flashloader_declared_bytes"]-x["community_ram_flashloader_bytes"],156)
        self.assertFalse(x["retail_closed_hab_execution_proven"])

if __name__=="__main__":unittest.main()
