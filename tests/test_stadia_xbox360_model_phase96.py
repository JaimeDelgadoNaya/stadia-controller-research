"""18 synthetic tests: no BLE, USB, OTP or flash calls."""
import unittest
from research.stadia_xbox360_model_phase96 import (
    convert, neutral, signed_stick, DPAD,
)


class Xbox360ReportModelPhase96Tests(unittest.TestCase):
    def test_01_neutral_packet_header_and_length(self):
        self.assertEqual(convert(neutral()), bytes((0, 20)) + bytes(18))

    def test_02_all_eight_dpad_positions(self):
        for pos, expected in enumerate(DPAD):
            with self.subTest(pos=pos):
                s = bytearray(neutral())
                s[0] = pos
                self.assertEqual(convert(s)[2], expected)

    def test_03_dpad_out_of_range_means_neutral(self):
        s = bytearray(neutral())
        s[0] = 15
        self.assertEqual(convert(s)[2], 0)

    def test_04_abxy_face_buttons(self):
        s = bytearray(neutral())
        s[2] = 0b01111000
        self.assertEqual(convert(s)[3], 0xF0)

    def test_05_lb_rb(self):
        s = bytearray(neutral())
        s[2] = 0b00000110
        self.assertEqual(convert(s)[3], 0x03)

    def test_06_stadia_maps_to_guide(self):
        s = bytearray(neutral())
        s[1] = 0x10
        self.assertEqual(convert(s)[3], 0x04)

    def test_07_menu_options_map_start_back(self):
        s = bytearray(neutral())
        s[1] = 0x60
        self.assertEqual(convert(s)[2], 0x30)

    def test_08_left_right_stick_click(self):
        s = bytearray(neutral())
        s[1] = 0x80
        s[2] = 0x01
        self.assertEqual(convert(s)[2], 0xC0)

    def test_09_analog_triggers(self):
        s = bytearray(neutral())
        s[7:9] = bytes((71, 255))
        self.assertEqual(convert(s)[4:6], bytes((71, 255)))

    def test_10_stick_center_is_zero(self):
        self.assertEqual(signed_stick(128), 0)
        self.assertEqual(signed_stick(128, True), 0)

    def test_11_stick_min_max(self):
        self.assertEqual(signed_stick(0), -32767)
        self.assertEqual(signed_stick(255), 32767)

    def test_12_inverted_vertical_axes(self):
        s = bytearray(neutral())
        s[4] = 0
        s[6] = 255
        x = convert(s)
        self.assertEqual(int.from_bytes(x[8:10], "little", signed=True), 32767)
        self.assertEqual(int.from_bytes(x[12:14], "little", signed=True), -32767)

    def test_13_horizontal_axes(self):
        s = bytearray(neutral())
        s[3] = 0
        s[5] = 255
        x = convert(s)
        self.assertEqual(int.from_bytes(x[6:8], "little", signed=True), -32767)
        self.assertEqual(int.from_bytes(x[10:12], "little", signed=True), 32767)

    def test_14_assistant_capture_no_xbox_button(self):
        s = bytearray(neutral())
        s[1] = 0x03
        self.assertEqual(convert(s), convert(neutral()))

    def test_15_usb_report_padding_zero(self):
        s = bytearray(neutral())
        s[9] = 254
        self.assertEqual(convert(s)[14:20], bytes(6))

    def test_16_short_report_rejected(self):
        with self.assertRaises(ValueError):
            convert(bytes(9))

    def test_17_long_report_rejected(self):
        with self.assertRaises(ValueError):
            convert(bytes(11))

    def test_18_buttons_and_dpad_combined(self):
        s = bytearray(neutral())
        s[0] = 1
        s[1] = 0x30
        s[2] = 0x44
        x = convert(s)
        self.assertEqual(x[2], 0x19)
        self.assertEqual(x[3], 0x15)


if __name__ == "__main__":
    unittest.main(verbosity=2)
