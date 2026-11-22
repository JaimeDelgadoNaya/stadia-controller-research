"""Offline USB descriptor gate; authentic source is third-party captured original."""
import unittest
from tools.audit_xusb_usb_phase100 import (
    REFERENCE_DEVICE,REFERENCE_CONFIG,USBStructureError,inspect_xusb_usb
)

class XUSBUSBPhase100(unittest.TestCase):
    def test_genuine_reference_descriptor_sizes(self):
        self.assertEqual(len(REFERENCE_DEVICE),18)
        self.assertEqual(len(REFERENCE_CONFIG),153)
        self.assertEqual(REFERENCE_CONFIG[:9],bytes.fromhex("09029900040100a0fa"))
    def test_four_vendor_interfaces(self):
        x=inspect_xusb_usb(REFERENCE_DEVICE,REFERENCE_CONFIG)
        self.assertTrue(x["xusb_original_reference_structure"])
        self.assertEqual(len(x["interfaces"]),4)
        self.assertEqual(x["interfaces"][0]["class"],(0xff,0x5d,0x01))
        self.assertEqual(x["interfaces"][3]["class"],(0xff,0xfd,0x13))
    def test_gamepad_interrupt_in_out(self):
        x=inspect_xusb_usb(REFERENCE_DEVICE,REFERENCE_CONFIG)
        endpoints={e["address"]:e for e in x["interfaces"][0]["endpoints"]}
        self.assertEqual(set(endpoints),{0x81,0x01})
        self.assertEqual(endpoints[0x81]["max_packet"],32)
        self.assertEqual(endpoints[0x81]["interval"],4)
        self.assertEqual(endpoints[0x01]["interval"],8)
    def test_wrong_original_stadia_identity_does_not_pass(self):
        d=bytearray(REFERENCE_DEVICE)
        d[8:12]=bytes.fromhex("d1186b94")
        r=inspect_xusb_usb(bytes(d),REFERENCE_CONFIG)
        self.assertEqual(r["reference_vid_pid"],"18d1:946b")
        self.assertFalse(r["xusb_original_reference_structure"])
    def test_bad_class_never_passes(self):
        d=bytearray(REFERENCE_DEVICE);d[4]=3
        self.assertFalse(inspect_xusb_usb(bytes(d),REFERENCE_CONFIG)["xusb_original_reference_structure"])
    def test_truncated_configuration_rejected(self):
        with self.assertRaises(USBStructureError):
            inspect_xusb_usb(REFERENCE_DEVICE,REFERENCE_CONFIG[:-1])
    def test_missing_endpoint_rejected(self):
        d=bytearray(REFERENCE_CONFIG);d[13]=3
        with self.assertRaises(USBStructureError):
            inspect_xusb_usb(REFERENCE_DEVICE,bytes(d))
    def test_reference_does_not_authenticate(self):
        r=inspect_xusb_usb(REFERENCE_DEVICE,REFERENCE_CONFIG)
        self.assertFalse(r["windows_xusb_driver_bound_proven"])
        self.assertFalse(r["xbox_console_authentication_proven"])
        self.assertFalse(r["retail_stadia_usb_enumeration_proven"])
        self.assertFalse(r["microsoft_vid_authorized_for_commercial_use"])

if __name__=="__main__":unittest.main()
