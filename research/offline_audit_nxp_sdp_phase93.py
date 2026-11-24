#!/usr/bin/env python3
"""Offline structure-checking harness for user-supplied nxp-sdp-overrun source.

Does NOT access USB, execute real shellcode or assemble the actual exploit.
Usage:
    python research/offline_audit_nxp_sdp_phase93.py /path/to/nxp-sdp-overrun
"""
import ast
import hashlib
import importlib.util
import pathlib
import struct
import sys
import types
import unittest

if len(sys.argv) < 2:
    raise SystemExit("Usage: python offline_audit_nxp_sdp_phase93.py /path/to/nxp-sdp-overrun")

SOURCE_ROOT = pathlib.Path(sys.argv.pop(1)).resolve()
MAIN = SOURCE_ROOT / "main.py"
SRC = MAIN.read_text(encoding="utf-8")
SOURCE_SHA256 = hashlib.sha256(MAIN.read_bytes()).hexdigest()

# Stub real device I/O and assembly libraries before importing source module.
for name in ("hidraw", "hid", "keystone.arm_const", "keystone.keystone_const"):
    sys.modules[name] = types.ModuleType(name)
keystone = types.ModuleType("keystone")
keystone.Ks = None
sys.modules["keystone"] = keystone
sys.path.insert(0, str(SOURCE_ROOT))
spec = importlib.util.spec_from_file_location("nxp_sdp_main_offline", MAIN)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# Two INERT Thumb instructions: nop; bx lr. This is NOT the real shellcode.
mod.assemble_shellcode = lambda code, addrs, base: b"\x00\xbf\x70\x47"


class StaticAndSyntheticChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload = mod.make_payload(mod.RT1060Addresses, mod.SHELLCODE_ROMC)
        cls.addrs = mod.RT1060Addresses

    def test_source_is_valid_python(self):
        ast.parse(SRC)

    def test_documented_overflow_capacity(self):
        self.assertEqual(self.addrs.REPORT_BUF + 2048, self.addrs.SDP_DEV + 3)
        self.assertEqual(self.addrs.REPORT_BUF, 0x2020723f)

    def test_mocked_payload_length_and_invalid_report(self):
        self.assertEqual(len(self.payload.buf), 2047)
        self.assertEqual(self.payload.buf[0], 0xff)
        self.assertEqual(self.payload.buf[-2:], (0x20207240).to_bytes(4, "little")[:2])

    def test_pointer_redirection_reconstructs_forged_device(self):
        offset = self.addrs.SDP_DEV - self.addrs.REPORT_BUF
        pair = self.payload.buf[offset:offset + 2]
        old = self.addrs.USB_DEV.to_bytes(4, "little")
        redirected = int.from_bytes(pair + old[2:], "little")
        self.assertEqual(redirected, 0x20207240)
        forged = mod.UsbDeviceStruct._unpack(
            self.payload.buf[1:1 + mod.UsbDeviceStruct._struct.size]
        )
        self.assertEqual(forged.controller_handle, 0x202072b0)
        callback = struct.unpack("<I", forged.ep_callback_packed[:4])[0]
        self.assertEqual(callback & 1, 1)
        offset = (callback - 1) - self.addrs.REPORT_BUF
        self.assertEqual(self.payload.buf[offset:offset + 4], b"\x00\xbf\x70\x47")

    def test_synthetic_usb_dispatch_reaches_inert_callback(self):
        # This models conditions stated by the author, NOT real BootROM flow.
        def region(addr, size):
            offset = addr - self.addrs.REPORT_BUF
            self.assertGreaterEqual(offset, 0)
            self.assertLessEqual(offset + size, len(self.payload.buf))
            return self.payload.buf[offset:offset + size]

        forged_addr = 0x20207240
        dev = mod.UsbDeviceStruct._unpack(
            region(forged_addr, mod.UsbDeviceStruct._struct.size)
        )
        ehci = mod.EhciStateStruct._unpack(
            region(dev.controller_handle, mod.EhciStateStruct._struct.size)
        )
        self.assertEqual(ehci.device_handle, forged_addr)
        regs = mod.EhciRegsPartial140._unpack(
            region(ehci.register_base + 0x140, mod.EhciRegsPartial140._struct.size)
        )
        self.assertEqual(regs.usbsts & regs.usbintr & 1, 1)
        self.assertEqual(regs.endptcomplete & 1, 1)
        callback = mod.EpCallback._unpack(
            dev.ep_callback_packed[:mod.EpCallback._struct.size]
        )
        self.assertEqual(callback.callback_param, 0)
        self.assertFalse(callback.is_busy)
        self.assertEqual(
            region(callback.callback_fn & ~1, 4), b"\x00\xbf\x70\x47"
        )

    def test_permanent_fuse_branch_is_present(self):
        self.assertIn("SHELLCODE_FIELD_RETURN", SRC)
        self.assertIn("FIELD_RETURN", SRC)
        self.assertIn('"--permanent"', SRC)
        self.assertIn('"REOPEN"', SRC)

    def test_target_and_dependencies_are_explicit(self):
        self.assertIn("RT1060Addresses", SRC)
        self.assertNotIn("RT1061Addresses", SRC)
        deps = (SOURCE_ROOT / "pyproject.toml").read_text()
        self.assertIn("hidapi", deps)
        self.assertIn("keystone-engine", deps)


if __name__ == "__main__":
    print("Source main.py SHA256:", SOURCE_SHA256)
    print("Mocked safe shellcode only; no USB, no OTP, no compiled exploit")
    unittest.main(verbosity=2)
