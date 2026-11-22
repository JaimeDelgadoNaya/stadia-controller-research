"""Phase100 differential harness: portable C11 codec vs independent Python model.

C shared library is built to a disposable temp directory. No USB or hardware.
"""
import ctypes
from pathlib import Path
import random
import shutil
import struct
import subprocess
import tempfile
import unittest
from tools.simulate_xinput_phase99 import (
    parse_bruce_hid,parse_bruce_raw,to_xusb,rumble_xusb_to_stadia
)
ROOT=Path(__file__).resolve().parent.parent

@unittest.skipUnless(shutil.which("cc"),"C compiler not installed")
class C11CodecPhase100(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix="stadia-xusb-c11-")
        target=Path(cls.tmp.name)/"codec.so"
        subprocess.run(["cc","-std=c11","-Wall","-Wextra","-Werror","-pedantic",
                        "-fPIC","-shared",
                        str(ROOT/"firmware_codec/stadia_xusb_codec.c"),
                        "-o",str(target)],check=True,capture_output=True)
        cls.lib=ctypes.CDLL(str(target))
        for name in ("stadia_xusb_from_bruce_hid","stadia_xusb_from_bruce_raw"):
            f=getattr(cls.lib,name)
            f.argtypes=(ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_int)
            f.restype=ctypes.c_int
        f=cls.lib.stadia_xusb_rumble_to_bruce
        f.argtypes=(ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p)
        f.restype=ctypes.c_int
    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()
    def encode(self,name,packet,polarity=True,size=20):
        buf=ctypes.create_string_buffer(packet)
        out=ctypes.create_string_buffer(size)
        r=getattr(self.lib,name)(buf,len(packet),out,int(polarity))
        return r,out.raw
    def test_c_hid_neutral(self):
        p=bytes((3,8,0,0,128,128,128,128,0,0,0))
        code,data=self.encode("stadia_xusb_from_bruce_hid",p)
        self.assertEqual(code,0)
        self.assertEqual(data,to_xusb(parse_bruce_hid(p)))
    def test_500_random_hid_vectors(self):
        rng=random.Random(990)
        for _ in range(500):
            p=bytes((3,rng.randrange(9)))+rng.randrange(32768).to_bytes(2,"little")+bytes(rng.randrange(256) for _ in range(7))
            r,output=self.encode("stadia_xusb_from_bruce_hid",p)
            self.assertEqual(r,0)
            self.assertEqual(output,to_xusb(parse_bruce_hid(p)))
    def test_1000_random_12bit_variants(self):
        rng=random.Random(1000)
        for _ in range(500):
            s=bytearray(0x34)
            for i in range(8,0x1b):s[i]=rng.randrange(2)
            struct.pack_into("<6I",s,0x1c,*(rng.randrange(4097) for _ in range(6)))
            for y in (False,True):
                code,out=self.encode("stadia_xusb_from_bruce_raw",bytes(s),polarity=y)
                self.assertEqual(code,0)
                self.assertEqual(out,to_xusb(parse_bruce_raw(bytes(s)),invert_y=y))
    def test_rumble_in_c11(self):
        input_packet=bytes((0,8,0,255,128,0,0,0))
        src=ctypes.create_string_buffer(input_packet)
        out=ctypes.create_string_buffer(5)
        status=self.lib.stadia_xusb_rumble_to_bruce(src,len(input_packet),out)
        self.assertEqual(status,0)
        self.assertEqual(out.raw,rumble_xusb_to_stadia(input_packet))
    def test_bad_input_rejected(self):
        status,_=self.encode("stadia_xusb_from_bruce_hid",b"\x00"*11)
        self.assertNotEqual(status,0)

if __name__=="__main__":unittest.main()
