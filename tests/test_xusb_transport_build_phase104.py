"""Cross-compiler and native finite-state-machine regression, no board or ROM use."""
import hashlib
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'firmware_codec'
ARM_HEADERS = ROOT / 'tools' / 'arm_phase104_headers'


class BuildAndSafetyPhase104(unittest.TestCase):
    def test_native_c_control_flow_and_ubsan(self):
        cc = shutil.which(os.environ.get('CC', 'cc'))
        if cc is None:
            self.skipTest('C compiler absent')
        with tempfile.TemporaryDirectory(prefix='stadia104-native-') as tmp:
            target = Path(tmp) / 'test_usb_fsm'
            cmd=[cc,'-std=c11','-Wall','-Wextra','-Werror','-pedantic',
                 '-fsanitize=undefined','-fno-omit-frame-pointer',
                 str(SRC / 'stadia_xusb_codec.c'),
                 str(SRC / 'stadia_xusb_transport.c'),
                 str(ROOT / 'tests' / 'test_xusb_transport.c'), '-o',str(target)]
            subprocess.run(cmd,check=True,capture_output=True,text=True,timeout=30)
            run=subprocess.run([str(target)],check=True,capture_output=True,text=True,timeout=30)
            self.assertIn('USB transport tests passed',run.stdout)

    def test_cross_compile_both_objects_for_cortex_m7(self):
        clang=shutil.which('clang')
        if clang is None:
            self.skipTest('ARM-targeting clang absent')
        with tempfile.TemporaryDirectory(prefix='stadia104-arm-') as tmp:
            for name in ('stadia_xusb_codec','stadia_xusb_transport'):
                dest=Path(tmp)/(name+'.o')
                cmd=[clang,'--target=armv7em-none-eabi','-mcpu=cortex-m7','-mthumb',
                     '-mfloat-abi=soft','-ffreestanding','-fno-builtin',
                     '-fno-stack-protector','-O2','-std=c11','-Wall','-Wextra','-Werror',
                     '-I',str(ARM_HEADERS),'-I',str(SRC),'-c',str(SRC/(name+'.c')),
                     '-o',str(dest)]
                subprocess.run(cmd,check=True,capture_output=True,text=True,timeout=30)
                data=dest.read_bytes()
                self.assertTrue(data.startswith(b'\x7fELF\x01\x01'))
                e_type,e_machine=struct.unpack_from('<HH',data,16)
                self.assertEqual((e_type,e_machine),(1,40))
                self.assertEqual(data[39],0x05)  # high byte of EABI5 flags (offset 36)
                self.assertGreater(len(data),400)

    def test_no_hardware_access_in_transport_sources(self):
        data=(SRC/'stadia_xusb_transport.c').read_text()
        for token in ('USB_DeviceSendRequest', 'USB_DeviceRun', 'fuse_',
                      'SDP_', 'HAB_', '0x045e', '0x028e', 'flash_erase',
                      '#include <libusb', 'HW_'):
            self.assertNotIn(token,data)

    def test_documented_open_development_gate(self):
        doc=(ROOT/'docs'/'es'/'plan-usb-rt1060-fase104.md').read_text()
        self.assertIn('NO FLASH',doc)
        self.assertIn('HAB CLOSED',doc)
        self.assertIn('MCUXpresso',doc)
        self.assertIn('Microsoft',doc)

if __name__=='__main__':unittest.main()
