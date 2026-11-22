"""Phase 104: portable report queue and USB host contract, no USB hardware.

Compiles a shared native codec/transport library, compares randomized buffers and
reconstructs state transitions. The test never asks the OS to enumerate USB.
"""
from __future__ import annotations
import ctypes as C
import os
from pathlib import Path
import random
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CODEC = ROOT / 'firmware_codec' / 'stadia_xusb_codec.c'
TRANSPORT = ROOT / 'firmware_codec' / 'stadia_xusb_transport.c'
HEADER = ROOT / 'firmware_codec' / 'stadia_xusb_transport.h'

class Transport(C.Structure):
    _fields_ = [
        ('configured',C.c_uint8),('in_flight',C.c_uint8),('pending',C.c_uint8),
        ('tx',C.c_uint8*20),('last_sent',C.c_uint8*20),
        ('tx_completions',C.c_uint32),('tx_errors',C.c_uint32),
        ('pending_replacements',C.c_uint32),('rx_valid',C.c_uint32),
        ('rx_invalid',C.c_uint32)
    ]


def buf(data:bytes):
    return (C.c_uint8*len(data)).from_buffer_copy(data)


def prepare():
    cc = os.environ.get('CC','cc')
    temp = tempfile.TemporaryDirectory(prefix='xusb104-')
    libfile = Path(temp.name)/'libxusb104.so'
    subprocess.run([cc,'-shared','-fPIC','-std=c11','-Wall','-Wextra','-Werror',
                    '-pedantic','-O2',str(CODEC),str(TRANSPORT),'-o',str(libfile)],
                   check=True,capture_output=True,text=True)
    dll=C.CDLL(str(libfile))
    ptr=C.POINTER(C.c_uint8)
    dll.stadia_xusb_transport_init.argtypes=[C.POINTER(Transport)]
    dll.stadia_xusb_transport_bus_reset.argtypes=[C.POINTER(Transport)]
    dll.stadia_xusb_transport_set_configured.argtypes=[C.POINTER(Transport),C.c_int]
    for name in ('stadia_xusb_transport_queue_hid','stadia_xusb_transport_queue_raw'):
        f=getattr(dll,name)
        f.argtypes=[C.POINTER(Transport),ptr,C.c_size_t,C.c_int]
        f.restype=C.c_int
    dll.stadia_xusb_transport_acquire_in.argtypes=[C.POINTER(Transport),ptr]
    dll.stadia_xusb_transport_acquire_in.restype=C.c_int
    dll.stadia_xusb_transport_finish_in.argtypes=[C.POINTER(Transport),C.c_int]
    dll.stadia_xusb_transport_finish_in.restype=C.c_int
    dll.stadia_xusb_transport_process_out.argtypes=[C.POINTER(Transport),ptr,C.c_size_t,ptr]
    dll.stadia_xusb_transport_process_out.restype=C.c_int
    dll.stadia_xusb_from_bruce_hid.argtypes=[ptr,C.c_size_t,ptr,C.c_int]
    dll.stadia_xusb_from_bruce_hid.restype=C.c_int
    return temp,dll


class Phase104HostSimulation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp,cls.lib=prepare()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.state=Transport()
        self.lib.stadia_xusb_transport_init(C.byref(self.state))

    def configure(self):
        self.lib.stadia_xusb_transport_set_configured(C.byref(self.state),1)

    def queue(self,payload:bytes):
        return self.lib.stadia_xusb_transport_queue_hid(C.byref(self.state),buf(payload),len(payload),0)

    def pull(self):
        out=(C.c_uint8*20)()
        status=self.lib.stadia_xusb_transport_acquire_in(C.byref(self.state),out)
        return status,bytes(out)

    def finish(self,ok=True):
        return self.lib.stadia_xusb_transport_finish_in(C.byref(self.state),1 if ok else 0)

    def test_hardware_not_required(self):
        self.assertNotIn('fsl_',TRANSPORT.read_text())
        self.assertNotIn('USB_Device',TRANSPORT.read_text())
        self.assertIn('NOT thread safe',HEADER.read_text())

    def test_neutral_source_roundtrip(self):
        self.configure()
        src=bytes((3,8,0,0,128,128,128,128,0,0,0))
        self.assertEqual(self.queue(src),0)
        status,report=self.pull()
        self.assertEqual(status,0)
        self.assertEqual((len(report),report[0],report[1]),(20,0,20))
        self.assertEqual(report[2:6],bytes(4))
        self.assertEqual(self.finish(),0)
        self.assertEqual(self.state.tx_completions,1)

    def test_not_configured_rejected(self):
        src=bytes((3,8,0,0,128,128,128,128,0,0,0))
        self.assertEqual(self.queue(src),-1)
        self.assertEqual(self.pull()[0],-1)
        self.configure()
        self.lib.stadia_xusb_transport_bus_reset(C.byref(self.state))
        self.assertEqual(self.queue(src),-1)
        self.assertEqual(self.state.pending,0)

    def test_failed_transfer_retries_last_frame(self):
        src=bytes((3,8,0,0,128,128,128,128,255,0,0))
        self.configure()
        self.queue(src)
        _,first=self.pull()
        self.assertEqual(self.finish(False),0)
        _,again=self.pull()
        self.assertEqual(first,again)
        self.assertEqual(self.state.tx_errors,1)

    def test_busy_and_latest_sample_wins(self):
        self.configure()
        src=bytes((3,8,0,0,128,128,128,128,0,0,0))
        self.queue(src)
        self.pull()
        self.assertEqual(self.pull()[0],-3)
        for hat in range(9):
            self.queue(bytes((3,hat,0,0,128,128,128,128,0,0,0)))
        self.assertEqual(self.state.pending_replacements,8)
        self.assertEqual(self.finish(False),0)
        status,report=self.pull()
        self.assertEqual(status,0)
        self.assertEqual(report[2],0)

    def test_bad_report_cannot_destroy_pending_sample(self):
        self.configure()
        good=bytes((3,8,0,0,128,128,128,128,0,0,0))
        self.queue(good)
        self.assertEqual(self.queue(b'invalid'),-2)
        self.assertEqual(self.pull()[0],0)

    def test_rumble_good_and_bad(self):
        self.configure()
        out=(C.c_uint8*5)(9,9,9,9,9)
        cmd=bytes((0,8,0,255,127,0,0,0))
        result=self.lib.stadia_xusb_transport_process_out(C.byref(self.state),buf(cmd),len(cmd),out)
        self.assertEqual(result,0)
        self.assertEqual(bytes(out),bytes((5,255,255,127,127)))
        bad=cmd[:6]+b'\x01\x00'
        result=self.lib.stadia_xusb_transport_process_out(C.byref(self.state),buf(bad),8,out)
        self.assertEqual(result,-2)
        self.assertEqual(bytes(out),bytes((5,255,255,127,127)))

    def test_randomized_host_sequences(self):
        random.seed(104)
        src_base=bytes((3,8,0,0,128,128,128,128,0,0,0))
        for _ in range(120):
            self.setUp()
            configured=False
            for step in range(65):
                action=random.randrange(7)
                if action==0:
                    self.lib.stadia_xusb_transport_bus_reset(C.byref(self.state))
                    configured=False
                elif action==1:
                    self.configure()
                    configured=True
                elif action==2:
                    src=bytes((3,random.randrange(9)))+bytes(random.randrange(256) for x in range(2))+bytes(random.randrange(256) for x in range(7))
                    status=self.queue(src)
                    self.assertIn(status, (0,-1,-2))
                elif action==3:
                    code,packet=self.pull()
                    self.assertIn(code,(0,-1,-3))
                    if code==0:self.assertEqual((packet[0],packet[1]),(0,20))
                elif action==4:
                    self.assertIn(self.finish(bool(random.randrange(2))), (0,-1,-3))
                elif action==5:
                    self.queue(src_base)
                else:
                    out=(C.c_uint8*5)()
                    cmd=bytes((0,8,0,random.randrange(256),random.randrange(256),0,0,0))
                    status=self.lib.stadia_xusb_transport_process_out(C.byref(self.state),buf(cmd),8,out)
                    self.assertIn(status,(0,-1))
                self.assertEqual(bool(self.state.configured),configured)
                if not configured:self.assertFalse(self.state.pending or self.state.in_flight)
                self.assertIn(self.state.pending,(0,1))
                self.assertIn(self.state.in_flight,(0,1))

    def test_xusb_input_sanity_for_all_valid_buttons(self):
        self.configure()
        for bit in range(15):
            bitmap=1<<bit
            src=bytes((3,8,bitmap&255,bitmap>>8,128,128,128,128,0,0,0))
            self.assertEqual(self.queue(src),0)
            code,p=self.pull()
            self.assertEqual(code,0)
            self.assertEqual(p[1],20)
            self.assertEqual(p[14:],bytes(6))
            self.assertEqual(self.finish(),0)

    def test_bruce_raw_full_resolution(self):
        self.configure()
        raw=bytearray(0x34)
        for i,value in enumerate((0,2048,4096,2048,4096,0)):
            raw[0x1c+4*i:0x20+4*i]=value.to_bytes(4,'little')
        self.assertEqual(self.lib.stadia_xusb_transport_queue_raw(C.byref(self.state),buf(bytes(raw)),len(raw),0),0)
        code,p=self.pull()
        self.assertEqual(code,0)
        self.assertEqual((p[4],p[5]),(255,0))
        self.assertEqual(p[6:8],b'\x00\x80')
        self.assertEqual(p[8:10],b'\x00\x00')
        self.assertEqual(p[10:12],b'\xff\x7f')

if __name__ == '__main__':unittest.main()
