"""Fixture-based Windows host simulation, no USB/hid drivers."""
import unittest
from tools.virtual_stadia_firmware_phase101 import Bundle, VirtualStadia, lab_keys, xusb_lab_payload
from tools.virtual_usb_xinput_phase102 import VirtualWindowsHost,VirtualUSBError,demo


def ready():
    key,pub=lab_keys();d=VirtualStadia('OPEN',pub)
    d.provision(Bundle.create('factory',1,b'FAKE_FACTORY'))
    d.boot();d.install(Bundle.create('xusb',2,xusb_lab_payload(b'fake C source')))
    return d

class VirtualUSBPhase102(unittest.TestCase):
    def test_01_factory_is_not_an_xbox(self):
        _,pub=lab_keys();d=VirtualStadia('OPEN',pub)
        d.provision(Bundle.create('factory',1,b'FACTORY'));d.boot()
        with self.assertRaises(VirtualUSBError):VirtualWindowsHost().enumerate(d)

    def test_02_xbox_fictitious_profile_is_structural_only(self):
        result=VirtualWindowsHost().enumerate(ready())
        self.assertTrue(result['virtual_descriptor_match'])
        for field in ('real_windows_usb_enumerated','driver_bound',
                      'physical_microsoft_vid_exposed','xsm3_authenticated'):
            self.assertFalse(result[field])

    def test_03_poll_button_A_publishes_xusb(self):
        h=VirtualWindowsHost();h.enumerate(ready())
        a=bytes((3,8,0,64,128,128,128,128,0,0,0))
        result=h.poll(a)
        self.assertIn('a',result['state']['buttons'])
        self.assertEqual(result['bytes'],20)
        self.assertEqual(result['endpoint'],'0x81')

    def test_04_rumble_is_bytes_only(self):
        h=VirtualWindowsHost();h.enumerate(ready())
        out=h.rumble(bytes((0,8,0,255,128,0,0,0)))
        self.assertEqual(out.hex(),'05ffff8080')

    def test_05_no_unauthenticated_poll(self):
        with self.assertRaises(VirtualUSBError):
            VirtualWindowsHost().poll(bytes(11))

    def test_06_no_unauthenticated_rumble(self):
        with self.assertRaises(VirtualUSBError):
            VirtualWindowsHost().rumble(bytes((0,8,0,0,0,0,0,0)))

    def test_07_invalid_delay_rejected(self):
        h=VirtualWindowsHost();h.enumerate(ready())
        for n in (-1,1001,2.5):
            with self.assertRaises(VirtualUSBError):h.poll(bytes(11),n)

    def test_08_runtime_frame_is_never_a_windows_driver_claim(self):
        s=demo(ready())
        self.assertEqual(s['input']['bytes'],20)
        self.assertFalse(s['real_windows_xinput_ready'])
        self.assertFalse(s['microsoft_hardware_authenticated'])

if __name__=='__main__':unittest.main()
