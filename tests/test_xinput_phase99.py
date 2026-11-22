"""Phase99: 20-byte XUSB report semantics grounded in Bruce layout and Xbox capture."""
import random
import struct
import unittest

from tools.simulate_xinput_phase99 import (
    BRUCE_BITS, XUSB_BITS, HATS, RAW_BUTTON_OFFSETS, PacketError,
    parse_bruce_hid, parse_bruce_raw, axis, trigger,
    to_xusb, decode_xusb, rumble_xusb_to_stadia, led_xusb, demonstration
)

def hid(hat=8,keys=(),axes=(128,128,128,128),triggers=(0,0),consumer=0):
    b=sum(1<<BRUCE_BITS[k] for k in keys)
    return bytes((3,hat))+b.to_bytes(2,"little")+bytes(axes)+bytes(triggers)+bytes((consumer,))

def raw(keys=(),axes=(2048,2048,2048,2048),triggers=(0,0)):
    out=bytearray(0x34)
    for key in keys:out[RAW_BUTTON_OFFSETS[key]]=1
    struct.pack_into("<6I",out,0x1c,*axes,*triggers)
    return bytes(out)

class XUSBPhase99(unittest.TestCase):
    def test_neutral_exact_20_bytes(self):
        p=to_xusb(parse_bruce_hid(hid()))
        self.assertEqual(p,bytes((0,20))+bytes(18))
        self.assertEqual(decode_xusb(p)["buttons"],[])
    def test_source_15_buttons(self):
        self.assertEqual(len(BRUCE_BITS),15)
        self.assertEqual(set(BRUCE_BITS.values()),set(range(15)))
    def test_all_xusb_buttons_one_at_a_time(self):
        for key in XUSB_BITS:
            if key in ("up","right","down","left"):
                packet=hid(hat={"up":0,"right":2,"down":4,"left":6}[key])
            else:packet=hid(keys=(key,))
            with self.subTest(key=key):
                self.assertIn(key,decode_xusb(to_xusb(parse_bruce_hid(packet)))["buttons"])
    def test_all_nine_hat_states(self):
        for hat,names in HATS.items():
            with self.subTest(hat=hat):
                self.assertEqual(set(decode_xusb(to_xusb(parse_bruce_hid(hid(hat=hat))))["buttons"]),set(names))
    def test_unmapped_special_buttons(self):
        self.assertEqual(to_xusb(parse_bruce_hid(hid(keys=("assistant","capture"),consumer=7))),
                         bytes((0,20))+bytes(18))
    def test_8bit_trigger_passthrough(self):
        x=decode_xusb(to_xusb(parse_bruce_hid(hid(triggers=(99,255)))))
        self.assertEqual((x["lt"],x["rt"]),(99,255))
    def test_12bit_trigger_scaling(self):
        x=decode_xusb(to_xusb(parse_bruce_raw(raw(triggers=(2048,4096)))))
        self.assertEqual((x["lt"],x["rt"]),(128,255))
    def test_12bit_full_axis_endpoints(self):
        x=decode_xusb(to_xusb(parse_bruce_raw(raw(axes=(0,0,4096,4096)))))
        self.assertEqual((x["lx"],x["ly"],x["rx"],x["ry"]),(-32768,32767,32767,-32768))
    def test_axis_monotonic_full_domain(self):
        for bits,top,mid in ((8,255,128),(12,4096,2048)):
            values=[axis(i,bits) for i in range(top+1)]
            self.assertEqual((values[0],values[mid],values[-1]),(-32768,0,32767))
            self.assertTrue(all(x<=y for x,y in zip(values,values[1:])))
    def test_trigger_monotonic_raw(self):
        values=[trigger(i,12) for i in range(4097)]
        self.assertEqual((values[0],values[-1]),(0,255))
        self.assertTrue(all(x<=y for x,y in zip(values,values[1:])))
    def test_raw_button_offsets_in_notes(self):
        for name in RAW_BUTTON_OFFSETS:
            with self.subTest(name=name):
                self.assertIn(name,parse_bruce_raw(raw(keys=(name,))).buttons)
    def test_raw_socd_opposites_neutral(self):
        x=decode_xusb(to_xusb(parse_bruce_raw(raw(keys=("up","down","left","right")))))
        self.assertEqual(x["buttons"],[])
    def test_y_polarity_explicit(self):
        src=parse_bruce_raw(raw(axes=(2048,3000,2048,1000)))
        straight=decode_xusb(to_xusb(src,invert_y=False))
        flipped=decode_xusb(to_xusb(src,invert_y=True))
        self.assertEqual(flipped["ly"],-straight["ly"])
        self.assertEqual(flipped["ry"],-straight["ry"])
    def test_bruce_invalid_report(self):
        for p in (b"",bytes(11),b"\x03\x09"+bytes(9),b"\x03\x08\xff\xff"+bytes(7)):
            with self.assertRaises(PacketError):parse_bruce_hid(p)
    def test_raw_invalid_range(self):
        b=bytearray(raw());b[0x1c:0x20]=(4097).to_bytes(4,"little")
        with self.assertRaises(PacketError):parse_bruce_raw(bytes(b))
    def test_xusb_reserved_bit_and_trailer(self):
        correct=bytearray(to_xusb(parse_bruce_hid(hid())))
        correct[3]=8
        with self.assertRaises(PacketError):decode_xusb(bytes(correct))
        correct[3]=0;correct[19]=1
        with self.assertRaises(PacketError):decode_xusb(bytes(correct))
    def test_rumble_8_to_5_bytes(self):
        self.assertEqual(rumble_xusb_to_stadia(bytes((0,8,0,255,128,0,0,0))),
                         bytes.fromhex("05ffff8080"))
    def test_rumble_invalid(self):
        for p in (b"",bytes(8),bytes((0,8,1,0,0,0,0,0))):
            with self.assertRaises(PacketError):rumble_xusb_to_stadia(p)
    def test_led_does_not_pretend_ring(self):
        self.assertIsNone(led_xusb(b"\x01\x03\x06")["stadia_led_command"])
    def test_fuzz_bruce_hid_1000_packets_never_malformed_output(self):
        rng=random.Random(99)
        for _ in range(1000):
            source=bytes((3,rng.randrange(9)))+rng.randrange(32768).to_bytes(2,"little")+bytes(rng.randrange(256) for _ in range(7))
            report=to_xusb(parse_bruce_hid(source))
            self.assertEqual(len(report),20)
            self.assertEqual(report[:2],b"\x00\x14")
            decode_xusb(report)
    def test_demo_disclaims_hardware(self):
        d=demonstration()
        self.assertFalse(d["physical_USB_emitted"])
        self.assertFalse(d["retail_HAB_closed_boot_proven"])
        self.assertFalse(d["Windows_XUSB_driver_binding_proven"])
        self.assertFalse(d["Xbox_console_authenticated"])

if __name__=="__main__":unittest.main()
