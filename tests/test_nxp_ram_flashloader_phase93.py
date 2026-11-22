"""Synthetic-only tests for the NXP-style RAM flashloader parser."""
import struct
import unittest

from tools.audit_nxp_ram_flashloader_phase93 import audit

DEVICE = bytes.fromhex("1201000200000040a2157300020001020001")
CONFIG = bytes.fromhex(
    "09022900010100c032"
    "090400000203000003"
    "092100010001224c00"
    "07058103400001"
    "07050203400001"
)


def fixture():
    data=bytearray(0x17F64)
    struct.pack_into("<8I",data,0x400,
        0x412000D1,0x20002000,0,0,0x20000420,0x20000400,0,0)
    struct.pack_into("<3I",data,0x420,0x20000000,0x18000,0)
    struct.pack_into("<2I",data,0x2000,0x20007000,0x2000262D)
    data[0x1000:0x1020]=b"UART\x00I2C\x00SPI\x00CAN\x00HID\x00CDC\x00DFU\x00MSD\x00"
    data[0x17E98:0x17E98+len(CONFIG)]=CONFIG
    data[0x17EC1:0x17EC1+18]=DEVICE
    return bytes(data)


class NxpRamFlashloaderPhase93(unittest.TestCase):
    def setUp(self):
        self.data=fixture()
        self.report=audit(self.data)

    def test_ivt_and_boot_data(self):
        self.assertEqual(self.report["ivt"]["entry"],"0x20002000")
        self.assertEqual(self.report["ivt"]["self"],"0x20000400")
        self.assertEqual(self.report["ivt"]["csf"],"0x0")
        self.assertEqual(self.report["boot_data"]["load_address"],"0x20000000")
        self.assertEqual(self.report["boot_data"]["declared_length"],"0x18000")

    def test_entry_points_to_vector_table_candidate(self):
        v=self.report["entry_vector_candidate"]
        self.assertEqual(v["initial_stack_pointer"],"0x20007000")
        self.assertEqual(v["reset_handler"],"0x2000262d")
        self.assertTrue(v["reset_handler_thumb_bit_set"])
        self.assertTrue(v["reset_handler_in_declared_load_range"])

    def test_length_shortfall_is_reported_not_hidden(self):
        self.assertEqual(self.report["size_bytes"],0x17F64)
        self.assertEqual(self.report["boot_data"]["file_shortfall_bytes"],0x9C)
        self.assertFalse(self.report["boot_data"]["declared_length_matches_file"])

    def test_nxp_hid_device_identity(self):
        d=self.report["usb_device"]
        self.assertEqual((d["vid"],d["pid"]),("0x15a2","0x0073"))
        self.assertEqual(d["class"],0)
        self.assertEqual(d["bNumConfigurations"],1)

    def test_usb_configuration_is_hid_not_cdc_acm(self):
        c=self.report["usb_configuration"]
        self.assertEqual(c["total_length"],41)
        self.assertEqual(c["bNumInterfaces"],1)
        self.assertEqual([i["class_code"] for i in c["interfaces"]],[3])
        self.assertEqual([e["address"] for e in c["endpoints"]],["0x81","0x02"])
        self.assertEqual(c["hid_report_descriptor_lengths"],[76])
        self.assertEqual(c["cdc_unions"],[])

    def test_transport_strings_do_not_prove_enabled_interfaces(self):
        self.assertTrue(self.report["transport_name_markers"]["CDC"])
        self.assertEqual(self.report["usb_configuration"]["interfaces"][0]["class_code"],3)

    def test_no_signature_or_execution_claims(self):
        limits=self.report["limits"]
        self.assertFalse(limits["hab_signature_verified"])
        self.assertFalse(limits["sdpoverrun_applicability_verified"])
        self.assertFalse(limits["exploit_executed"])
        self.assertFalse(limits["firmware_executed"])
        self.assertFalse(limits["hardware_accessed"])

    def test_invalid_ivt_rejected(self):
        bad=bytearray(self.data);bad[0x400]=0
        with self.assertRaisesRegex(ValueError,"IVT"):
            audit(bytes(bad))

    def test_bad_boot_data_pointer_rejected(self):
        bad=bytearray(self.data);struct.pack_into("<I",bad,0x410,0x30000000)
        with self.assertRaisesRegex(ValueError,"Boot Data pointer"):
            audit(bytes(bad))

    def test_bad_device_descriptor_rejected(self):
        bad=bytearray(self.data);bad[0x17EC1]=0
        with self.assertRaisesRegex(ValueError,"device descriptor"):
            audit(bytes(bad))


if __name__=="__main__":
    unittest.main()
