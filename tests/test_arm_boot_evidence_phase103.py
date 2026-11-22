import json
import shutil
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.audit_signed_regions_phase103 import ImageFormatError, describe_image
from tools.verify_arm_codec_phase103 import ArmObjectError, compile_arm_object, read_elf_arm_object, SYMBOLS

SRC_ROOT=Path(__file__).resolve().parents[1]
SCRIPT=SRC_ROOT/'tools'


def fabricated_nxp_ivt(*,csf=True, csf_inside=True):
    image=bytearray(256)
    base=0x60001000
    ptr=base+0x80 if csf_inside else base+0x10000
    struct.pack_into('<8I',image,0,0x412000d1,0x60800000,0,0,base+32,base,
                     ptr if csf else 0,0)
    struct.pack_into('<3I',image,32,base,256,0)
    if csf and csf_inside:
        image[0x80:0x84]=b'\xd4\x00\x48\x42'
    return bytes(image)


class TestNxpSignedRegions(unittest.TestCase):
    def test_csf_data_inside_synthetic_image_does_not_prove_signature(self):
        o=describe_image(fabricated_nxp_ivt(),0,label='synthetic')
        self.assertTrue(o['csf_bytes_in_supplied_image'])
        self.assertTrue(o['csf_header_d4_found'])
        self.assertEqual(o['csf_header_length_only'],72)
        self.assertFalse(o['cryptographic_signature_verified'])
        self.assertFalse(o['permission_to_flash_retail'])

    def test_external_csf_offset_cannot_be_verified_from_truncated_file(self):
        o=describe_image(fabricated_nxp_ivt(csf_inside=False),0,label='synthetic')
        self.assertEqual(o['csf_offset_within_flat_image'],'0x10000')
        self.assertFalse(o['csf_bytes_in_supplied_image'])
        self.assertFalse(o['csf_header_d4_found'])

    def test_no_csf_pointer(self):
        o=describe_image(fabricated_nxp_ivt(csf=False),0,label='unsigned synthetic')
        self.assertIsNone(o['csf_pointer_address'])
        self.assertFalse(o['cryptographic_signature_verified'])

    def test_invalid_ivt_header(self):
        b=bytearray(fabricated_nxp_ivt());b[0]=0
        with self.assertRaises(ImageFormatError):describe_image(bytes(b),0,label='bad')

    def test_invalid_ivt_offsets(self):
        for value in (-1,255,10_000):
            with self.subTest(value=value):
                with self.assertRaises(ImageFormatError):describe_image(fabricated_nxp_ivt(),value,label='bad')

    def test_invalid_boot_data_pointer(self):
        b=bytearray(fabricated_nxp_ivt()); struct.pack_into('<I',b,0x10,0x70000000)
        with self.assertRaises(ImageFormatError):describe_image(bytes(b),0,label='bad')

    def test_signed_image_never_claims_fuse_state(self):
        o=describe_image(fabricated_nxp_ivt(),0,label='test')
        self.assertFalse(o['retail_fuse_state_read'])
        self.assertFalse(o['fused_trust_anchor_known'])

class TestArmCrossCompilation(unittest.TestCase):
    def arm_object_bytes(self):
        if not shutil.which('clang'):
            self.skipTest('Cross-target Clang not available')
        codec = SRC_ROOT/'firmware_codec'
        with tempfile.TemporaryDirectory() as t:
            compile_arm_object(codec/'stadia_xusb_codec.c', codec,
                               SCRIPT/'arm_phase103_headers', Path(t))
            return (Path(t)/'stadia_xusb_codec_cortex_m7.o').read_bytes()

    def test_cross_compile_stadia_codec(self):
        if not shutil.which('clang'):
            self.skipTest('Cross-target Clang not available')
        hdr=SRC_ROOT/'firmware_codec'
        if not (hdr/'stadia_xusb_codec.c').exists():
            self.skipTest('This standalone suite requires codec sources')
        with tempfile.TemporaryDirectory() as t:
            r=compile_arm_object(hdr/'stadia_xusb_codec.c',hdr,
                                 SCRIPT/'arm_phase103_headers',Path(t))
            self.assertEqual(r['machine'],'EM_ARM')
            self.assertEqual(r['eabi_version'],5)
            self.assertEqual(set(r['exported_codec_symbols']),set(SYMBOLS))
            self.assertFalse(r['is_bootable_image'])
            self.assertFalse(r['signed_for_retail_hab'])
            self.assertIn('memset',r['undefined_runtime_symbols'])
            self.assertGreater(r['size_bytes'],500)

    def test_elf_header_wrong_machine_rejected(self):
        b=bytearray(self.arm_object_bytes());b[18:20]=b'\x3e\x00'
        with self.assertRaises(ArmObjectError):read_elf_arm_object(bytes(b))

    def test_elf_header_executable_rejected(self):
        b=bytearray(self.arm_object_bytes());b[16:18]=b'\x02\x00'
        with self.assertRaises(ArmObjectError):read_elf_arm_object(bytes(b))

    def test_elf_truncated_rejected(self):
        with self.assertRaises(ArmObjectError):read_elf_arm_object(b'\x7fELF')

    def test_elf_eabi_mismatch_rejected(self):
        b=bytearray(self.arm_object_bytes());b[39]=0
        with self.assertRaises(ArmObjectError):read_elf_arm_object(bytes(b))

    def test_no_hardware_subsystem_imports(self):
        data=(SCRIPT/'verify_arm_codec_phase103.py').read_text()
        for s in ('pyusb', 'hidapi', 'HAB_UNLOCK', 'FLASH_ERASE', 'mcp__GitHub__'):
            self.assertNotIn(s,data)


if __name__=='__main__':unittest.main()
