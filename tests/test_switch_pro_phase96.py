"""Synthetic-only Phase96 tests: no physical controller or Switch 2."""
import unittest

from tools.simulate_switch_pro_phase96 import (
    SOURCE_BUTTONS,HATS,VirtualNS1Pro,ProtocolGap,axis8_to_12,
    pack12,unpack12,translate_bruce,demonstration
)


def sample(*,hat=8,keys=(),axes=(128,128,128,128),triggers=(0,0),consumer=0):
    bm=sum(1<<SOURCE_BUTTONS[k] for k in keys)
    return bytes([3,hat])+bm.to_bytes(2,"little")+bytes(axes)+bytes(triggers)+bytes([consumer])


class SwitchProProtocolPhase96(unittest.TestCase):
    def test_neutral_report_64_bytes(self):
        r=translate_bruce(sample())
        self.assertEqual(len(r),64)
        self.assertEqual(r[0],0x30)
        self.assertEqual(r[3:6],bytes(3))
        self.assertEqual(unpack12(r[6:9]),(2048,2048))
        self.assertEqual(unpack12(r[9:12]),(2048,2048))
        self.assertTrue(all(x==0 for x in r[13:]))

    def test_all_face_button_positions(self):
        for source,expected in [("a",0x04),("b",0x08),("x",0x01),("y",0x02)]:
            with self.subTest(source=source):
                self.assertEqual(translate_bruce(sample(keys=[source]))[3],expected)

    def test_face_button_labels_alternative(self):
        for source,expected in [("a",0x08),("b",0x04),("x",0x02),("y",0x01)]:
            with self.subTest(source=source):
                self.assertEqual(translate_bruce(sample(keys=[source]),face_layout="labels")[3],expected)

    def test_all_dpad_directions_and_neutral(self):
        expected={0:0x02,1:0x06,2:0x04,3:0x05,4:0x01,
                  5:0x09,6:0x08,7:0x0a,8:0}
        for hat,bits in expected.items():
            with self.subTest(hat=hat):
                self.assertEqual(translate_bruce(sample(hat=hat))[5]&0x0f,bits)

    def test_all_source_buttons_are_defined_uniquely(self):
        self.assertEqual(len(SOURCE_BUTTONS),15)
        self.assertEqual(len(set(SOURCE_BUTTONS.values())),15)
        self.assertEqual(set(HATS),set(range(9)))

    def test_shoulders_menu_stick_click_and_capture(self):
        keys=["l","r","minus","plus","ls","rs","home","capture"]
        x=translate_bruce(sample(keys=keys))
        self.assertEqual(x[3:6],bytes([0x40,0x3f,0x40]))

    def test_trigger_cutoff_and_click_override(self):
        a=translate_bruce(sample(triggers=(127,128)))
        self.assertEqual(a[3]&0x80,0x80)
        self.assertEqual(a[5]&0x80,0)
        b=translate_bruce(sample(keys=["lt"]))
        self.assertEqual(b[5]&0x80,0x80)

    def test_exhaustive_axis_endpoints_monotonic(self):
        v=[axis8_to_12(i) for i in range(256)]
        self.assertEqual(v[0],0)
        self.assertEqual(v[1],0)
        self.assertEqual(v[-1],4095)
        self.assertTrue(all(x<=y for x,y in zip(v,v[1:])))
        self.assertLessEqual(len(set(v)),255)

    def test_pack_12bit_roundtrip_selected_grid(self):
        for x in range(0,4096,127):
            for y in range(0,4096,131):
                self.assertEqual(unpack12(pack12(x,y)),(x,y))

    def test_invalid_bruce_report_rejected(self):
        with self.assertRaises(ValueError):translate_bruce(b"")
        with self.assertRaises(ValueError):translate_bruce(bytes([4])+bytes(10))
        with self.assertRaises(ValueError):translate_bruce(sample(hat=8)[:1]+bytes([9])+sample()[2:])
        with self.assertRaises(ValueError):translate_bruce(sample(keys=["a"])[:3]+b"\x80"+sample()[4:])
        with self.assertRaises(ValueError):translate_bruce(sample(),face_layout="untrusted")
        with self.assertRaises(ValueError):translate_bruce(sample(),trigger_threshold=256)

    def test_init_order_is_enforced(self):
        d=VirtualNS1Pro()
        with self.assertRaises(ProtocolGap):d.command(b"\x80\x04")
        self.assertEqual(d.command(b"\x80\x01")[:4],bytes([0x81,1,0,3]))
        self.assertEqual(d.command(b"\x80\x02"),bytes([0x81,2]))
        self.assertEqual(d.command(b"\x80\x03"),bytes([0x81,3]))
        self.assertIsNone(d.command(b"\x80\x04"))
        self.assertEqual(d.state,"stream")

    def test_mode_switch_required_before_input_reports(self):
        d=VirtualNS1Pro()
        for cmd in (b"\x80\x01",b"\x80\x02",b"\x80\x03",b"\x80\x04"):
            d.command(cmd)
        with self.assertRaises(ProtocolGap):d.sample(sample())
        mode=d.command(bytes([1,0])+bytes(8)+bytes([3,0x30]))
        self.assertEqual(mode[0],0x21)
        self.assertEqual(mode[13:15],bytes([0x80,3]))
        self.assertEqual(d.sample(sample())[0],0x30)

    def test_spi_calibration_gap_is_explicit(self):
        d=VirtualNS1Pro()
        for cmd in (b"\x80\x01",b"\x80\x02",b"\x80\x03",b"\x80\x04"):
            d.command(cmd)
        with self.assertRaisesRegex(ProtocolGap,"SPI factory calibration"):
            d.command(bytes([1,0])+bytes(8)+bytes([0x10])+bytes(5))

    def test_refuses_unsupported_reports(self):
        d=VirtualNS1Pro()
        for cmd in (b"",b"\x80",b"\x81\x00",b"\x01"+bytes(10)):
            with self.assertRaises(ProtocolGap):
                d.command(cmd)

    def test_analog_trigger_and_consumer_precision_lost(self):
        a=sample(triggers=(180,180),consumer=0)
        b=sample(triggers=(250,255),consumer=7)
        self.assertEqual(translate_bruce(a),translate_bruce(b))

    def test_virtual_trace_does_not_claim_hardware_success(self):
        s=demonstration()
        self.assertEqual(s["report_id"],0x30)
        self.assertEqual(s["report_size"],64)
        self.assertIn("SPI",s["spi_calibration_blocker"])
        self.assertFalse(s["retail_hab_closed_boot_proven"])
        self.assertFalse(s["switch_2_compatibility_proven"])
        self.assertFalse(s["hardware_or_console_access"])


if __name__=="__main__":
    unittest.main()
