"""No OEM firmware, no USB access. Synthetic tests of final phase-31 decision."""
import copy
import hashlib
import struct
import unittest

from tools import audit_final_auth_recovery as m


def fake_image(name):
    info=copy.deepcopy(m.SAMPLES[name])
    data=bytearray(b"\xff"*info["size"])
    struct.pack_into("<8I",data,info["ivt_offset"],*info["ivt_expected"])
    off=info["csf_offset"]
    data[off:off+4]=bytes((0xD4,0,info["csf_length"],0x42))
    for key,(start,end,_) in info["code_fingerprints"].items():
        info["code_fingerprints"][key]=(start,end,hashlib.sha256(data[start:end]).hexdigest())
    return bytes(data),info


class Phase31DecisionTests(unittest.TestCase):
    def test_known_sample_sizes(self):
        self.assertEqual(m.SAMPLES["bootloader_a"]["size"],131072)
        self.assertEqual(m.SAMPLES["bruce_signed_update"]["size"],1050984)

    def test_boothab_layout_using_synthetic_image(self):
        b,info=fake_image("bootloader_a")
        result=m.decode_layout(b,info)
        self.assertEqual(result["ivt_self"],"0x60001000")
        self.assertEqual(result["ivt_csf_pointer"],"0x60818000")
        self.assertEqual(result["csf_file_offset"],"0x18000")
        self.assertIn("explicit file-offset alias",result["ivt_source_coordinates"])

    def test_bruce_layout_using_synthetic_image(self):
        b,info=fake_image("bruce_signed_update")
        result=m.decode_layout(b,info)
        self.assertEqual(result["ivt_entry"],"0x60040000")
        self.assertEqual(result["ivt_csf_pointer"],"0x6013f030")
        self.assertEqual(result["csf_file_offset"],"0xff030")

    def test_synthetic_image_does_not_pass_real_sha(self):
        b,_=fake_image("bootloader_a")
        with self.assertRaisesRegex(ValueError,"SHA-256 mismatch"):
            m.hash_verified(b,m.SAMPLES["bootloader_a"]["sha256"])

    def test_wrong_ivt_rejected(self):
        b,info=fake_image("bootloader_a")
        data=bytearray(b);data[0]^=1
        with self.assertRaisesRegex(ValueError,"vector"):
            m.decode_layout(bytes(data),info)

    def test_wrong_csf_rejected(self):
        b,info=fake_image("bruce_signed_update")
        data=bytearray(b);data[info["csf_offset"]]^=1
        with self.assertRaisesRegex(ValueError,"CSF header"):
            m.decode_layout(bytes(data),info)

    def test_code_region_mutation_rejected(self):
        b,info=fake_image("bootloader_a")
        data=bytearray(b);data[0x1F5C]^=1
        with self.assertRaisesRegex(ValueError,"fingerprint"):
            m.decode_layout(bytes(data),info)

    def test_short_image_rejected(self):
        b,info=fake_image("bruce_signed_update")
        with self.assertRaisesRegex(ValueError,"length"):
            m.decode_layout(b[:-1],info)

    def test_stop_with_verified_host_but_without_custom_auth(self):
        r=m.decision_gate(True,False,True,True)
        self.assertEqual(r["decision"],"STOP_INTERNAL__START_EXTERNAL_BRIDGE")
        self.assertIn("executable_custom_code_authenticated",
                      r["unproven_requirements"])

    def test_stop_with_custom_auth_but_no_recovery(self):
        r=m.decision_gate(True,True,True,False)
        self.assertEqual(r["decision"],"STOP_INTERNAL__START_EXTERNAL_BRIDGE")
        self.assertIn("reliable_recovery_verified",r["unproven_requirements"])

    def test_stop_with_no_real_host_path(self):
        r=m.decision_gate(False,True,True,True)
        self.assertEqual(r["decision"],"STOP_INTERNAL__START_EXTERNAL_BRIDGE")

    def test_stop_when_receiver_unreachable(self):
        r=m.decision_gate(True,True,False,True)
        self.assertEqual(r["decision"],"STOP_INTERNAL__START_EXTERNAL_BRIDGE")

    def test_continue_only_when_all_four_gates_are_true(self):
        r=m.decision_gate(True,True,True,True)
        self.assertEqual(r["decision"],"CONTINUE_INTERNAL")
        self.assertEqual(r["unproven_requirements"],[])

    def test_final_gate_does_not_allow_override_of_unknown_flags(self):
        all_scenarios=[(a,b,c,d) for a in (False,True) for b in (False,True)
                       for c in (False,True) for d in (False,True)]
        self.assertEqual(sum(m.decision_gate(*v)["decision"]=="CONTINUE_INTERNAL"
                             for v in all_scenarios),1)

    def test_offline_no_device_io_in_module(self):
        self.assertIn("No WebUSB",m.__doc__ or "")
        self.assertTrue(m.decision_gate(True,False,True,False)
                        ["no_further_open_ended_pointer_phases"])


if __name__=="__main__":
    unittest.main()
