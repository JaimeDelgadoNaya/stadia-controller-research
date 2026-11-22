"""Tests basados en tramas inventadas y forma pública del protocolo NS1."""
import unittest

from tools.simulate_switch_pro_phase97 import (
    ALLOWLIST_SPI, SYNTHETIC_MAC, SyntheticFactorySPI,
    UnsupportedProtocol, VirtualNS1Pro97, make_host_subcommand,
    pack12, unpack12, run_offline_trace,
)


def ready():
    d = VirtualNS1Pro97()
    for b in (b'\x80\x01', b'\x80\x02', b'\x80\x03', b'\x80\x04'):
        d.process(b)
    return d


class SwitchProPhase97(unittest.TestCase):
    def test_spi_length_and_echo_603d(self):
        d=ready()
        req=make_host_subcommand(0x10, bytes.fromhex('3d60000019'))
        r=d.process(req)
        self.assertEqual(len(r),64)
        self.assertEqual(r[0],0x21)
        self.assertEqual(r[13:20],bytes.fromhex('90103d60000019'))
        self.assertEqual(r[20:45],d.flash.read(0x603D,25))
        self.assertEqual(r[45:],bytes(19))

    def test_spi_reader_6080_and_user_fallback(self):
        d=ready()
        for addr,size in ((0x6080,0x18),(0x8010,0x18),(0x8028,0x18)):
            payload=addr.to_bytes(4,'little')+bytes([size])
            r=d.process(make_host_subcommand(0x10,payload))
            self.assertEqual(r[13:15],b'\x90\x10')
            self.assertEqual(r[15:20],payload)
            self.assertEqual(len(r[20:20+size]),size)
        self.assertEqual(d.flash.read(0x8010,0x18),bytes([0xff])*0x18)

    def test_allowed_regions_have_stable_lengths(self):
        d=SyntheticFactorySPI()
        self.assertEqual(len(ALLOWLIST_SPI),8)
        for addr,size in ALLOWLIST_SPI:
            with self.subTest(addr=hex(addr)):
                self.assertEqual(len(d.read(addr,size)),size)

    def test_unknown_spi_addresses_fail_closed(self):
        d=SyntheticFactorySPI()
        for addr,size in ((0x6040,0x18),(0x7000,0x18),(0x6000,0),(0x6000,30),(-1,0x10)):
            with self.subTest(addr=addr,size=size):
                with self.assertRaises(UnsupportedProtocol):d.read(addr,size)

    def test_missing_spi_payload_does_not_access_memory(self):
        d=ready()
        for raw in (b'',b'\x00',bytes(4)):
            with self.assertRaisesRegex(UnsupportedProtocol,'Truncated SPI'):
                d.process(make_host_subcommand(0x10,raw))

    def test_stick_calibration_is_synthetic_and_packed(self):
        mem=SyntheticFactorySPI().read(0x603D,0x19)
        self.assertEqual(unpack12(mem[:3]),(0x700,0x700))
        self.assertEqual(unpack12(mem[3:6]),(0x800,0x800))
        self.assertEqual(unpack12(mem[6:9]),(0x700,0x700))
        self.assertEqual(mem[18],0xff)
        self.assertEqual(mem[19:25],bytes(6))

    def test_stick_pack_roundtrip(self):
        for a in range(0,4096,173):
            for b in range(0,4096,211):
                self.assertEqual(unpack12(pack12(a,b)),(a,b))

    def test_init_requires_proper_state(self):
        d=VirtualNS1Pro97()
        with self.assertRaises(UnsupportedProtocol):d.process(make_host_subcommand(0x10))
        self.assertEqual(d.process(b'\x80\x01'),bytes((0x81,1,0,3))+SYNTHETIC_MAC)
        self.assertEqual(d.process(b'\x80\x02'),b'\x81\x02')
        self.assertEqual(d.process(b'\x80\x03'),b'\x81\x03')
        self.assertIsNone(d.process(b'\x80\x04'))
        self.assertEqual(d.phase,'usb_ready')

    def test_device_info_payload_and_synthetic_mac(self):
        d=ready()
        r=d.process(make_host_subcommand(0x02))
        self.assertEqual((r[0],r[13],r[14]),(0x21,0x82,0x02))
        self.assertEqual(r[19:25],SYNTHETIC_MAC)
        self.assertEqual(len(r),64)

    def test_mode_selection_and_supported_subcommands(self):
        d=ready()
        self.assertFalse(d.can_stream())
        for cmd,args,ack in ((0x03,b'\x30',0x80),(0x08,b'',0x80),
                             (0x04,b'',0x83),(0x40,b'\x00',0x80),
                             (0x48,b'\x01',0x80),(0x30,b'\x03',0x80)):
            with self.subTest(subcommand=hex(cmd)):
                r=d.process(make_host_subcommand(cmd,args))
                self.assertEqual(r[13:15],bytes((ack,cmd)))
        self.assertTrue(d.can_stream())
        self.assertEqual(d.leds,3)
        self.assertTrue(d.vibration_enabled)
        self.assertFalse(d.imu_enabled)

    def test_imu_enable_and_nfc_remain_explicit_blockers(self):
        d=ready()
        with self.assertRaisesRegex(UnsupportedProtocol,'motion/IMU'):
            d.process(make_host_subcommand(0x40,b'\x01'))
        with self.assertRaisesRegex(UnsupportedProtocol,'not modeled'):
            d.process(make_host_subcommand(0x21))

    def test_malformed_report_rejected(self):
        d=ready()
        for invalid in (b'',b'\x00',b'\x01\x00',b'\xff\x00',
                        bytes([1])+bytes(10),b'\x80\x01\x00'):
            with self.subTest(packet=invalid.hex()):
                with self.assertRaises(UnsupportedProtocol):d.process(invalid)

    def test_report_mode_restricted(self):
        d=ready()
        for args in (b'',b'\x3f',b'\x31'):
            with self.assertRaises(UnsupportedProtocol):d.process(make_host_subcommand(0x03,args))

    def test_spi_reply_is_not_faked_for_unsupported_size(self):
        d=ready()
        for payload in (bytes.fromhex('3d6000001e'), bytes.fromhex('3d60000000')):
            with self.assertRaises(UnsupportedProtocol):d.process(make_host_subcommand(0x10,payload))

    def test_staged_trace_blocks_missing_features(self):
        r=run_offline_trace()
        self.assertEqual(len(r['steps']),13)
        self.assertEqual(len(r['blocked_scenarios']),3)
        self.assertTrue(r['supported_host_subset'])
        self.assertFalse(r['full_switch2_console_handshake_proven'])
        self.assertFalse(r['original_pro_usb_descriptor_emitted'])
        self.assertFalse(r['stadia_retail_custom_firmware_boot_proven'])
        self.assertFalse(r['actual_devices_contacted'])

    def test_no_external_device_module_imports(self):
        import inspect, tools.simulate_switch_pro_phase97 as module
        source=inspect.getsource(module)
        for forbidden in ('import usb', 'import hid', 'socket.', 'serial.', 'subprocess.',
                          'ctypes.', 'flash_erase_region', 'field_return'):
            self.assertNotIn(forbidden,source)


if __name__=='__main__':unittest.main()
