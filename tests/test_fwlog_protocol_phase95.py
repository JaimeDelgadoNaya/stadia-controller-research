"""Synthetic-only tests of community fwlog wire format; no USB or hardware."""
import inspect
import unittest

from tools.audit_fwlog_protocol_phase95 import (
    MalformedMessage, decode_fields, inspect_frame
)


def varint(n):
    result=bytearray()
    while True:
        b=n & 127
        n >>= 7
        result.append(b | (128 if n else 0))
        if not n:
            return bytes(result)


def field(tag, value):
    if isinstance(value, int):
        return varint(tag << 3) + varint(value)
    return varint(tag << 3 | 2) + varint(len(value)) + bytes(value)


class FirmwareLogWireProtocolTests(unittest.TestCase):
    def test_record_metadata_and_default_redaction(self):
        record=(field(1, 1234) + field(2, b"WiFi SSID=PRIVATE") +
                field(3, b"usb_device.cc") + field(4, 336) + field(5, 0x14))
        parsed=inspect_frame(field(6,record))
        self.assertEqual(parsed["kind"],"firmware_log")
        self.assertEqual(parsed["timestamp"],1234)
        self.assertEqual(parsed["level"],"debug")
        self.assertEqual(parsed["source_file"],"usb_device.cc")
        self.assertEqual(parsed["source_line"],336)
        self.assertTrue(parsed["message_redacted"])
        self.assertNotIn("PRIVATE",str(parsed))
        self.assertNotIn("message",parsed)

    def test_explicit_local_message_inspection(self):
        record=field(1,1)+field(2,b"synthetic hello")+field(5,0x1e)
        parsed=inspect_frame(field(6,record),include_log_text=True)
        self.assertEqual(parsed["message"],"synthetic hello")
        self.assertFalse(parsed["message_redacted"])
        self.assertEqual(parsed["level"],"info")

    def test_challenge_never_leaks_token_or_identity(self):
        challenge=field(1,b"PRIVATE_TOKEN")+field(2,b"PRIVATE_DEVICE_ID")+field(3,2)
        parsed=inspect_frame(field(3,challenge),include_log_text=True)
        self.assertEqual(parsed,{"kind":"unlock_challenge","state":2,
                                  "identity_and_token_redacted":True})
        self.assertNotIn("PRIVATE",repr(parsed))

    def test_status_text_is_not_returned(self):
        parsed=inspect_frame(field(2,field(1,3)+field(2,b"private error")))
        self.assertEqual(parsed,{"kind":"status","code":3})

    def test_unknown_fields_are_metadata_only(self):
        self.assertEqual(inspect_frame(field(7,b"secret")),
                         {"kind":"unknown","field_numbers":[7]})

    def test_varint_overflow_and_truncation_fail_closed(self):
        with self.assertRaises(MalformedMessage):
            decode_fields(bytes([0x08,0x80]))
        with self.assertRaises(MalformedMessage):
            decode_fields(bytes([0x08])+b"\xff"*11)

    def test_length_truncation_and_oversized_frames(self):
        with self.assertRaises(MalformedMessage):
            decode_fields(b"\x12\x05hi")
        with self.assertRaises(MalformedMessage):
            decode_fields(b"\x12\x80\x80\x02")
        with self.assertRaises(MalformedMessage):
            decode_fields(b"\x00"*65537)

    def test_unsupported_wire_type_and_duplicate_fields(self):
        with self.assertRaises(MalformedMessage):
            decode_fields(bytes([0x0b]))
        with self.assertRaises(MalformedMessage):
            decode_fields(field(1,3)+field(1,4))
        with self.assertRaises(MalformedMessage):
            decode_fields(b"\x00")

    def test_fixed32_fixed64_parsing(self):
        self.assertEqual(decode_fields(bytes([0x0d])+b"\x12\x34\x56\x78")[1],0x78563412)
        self.assertEqual(decode_fields(bytes([0x09])+b"\x01\x02\x03\x04\x05\x06\x07\x08")[1],0x0807060504030201)

    def test_no_usb_import_or_device_open_path(self):
        import tools.audit_fwlog_protocol_phase95 as module
        src=inspect.getsource(module)
        for unsafe in ("usb.core","hidapi","ctrl_transfer","flash_erase_region","write_memory","SDP("):
            self.assertNotIn(unsafe,src)
        self.assertFalse(hasattr(module,"open_device"))


if __name__=="__main__":
    unittest.main()
