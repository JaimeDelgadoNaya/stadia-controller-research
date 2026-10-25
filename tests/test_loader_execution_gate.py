"""Synthetic offline regression tests; no proprietary loader or controller."""
import hashlib
import struct
import unittest
from tools import audit_loader_execution_gate as m


def fixture():
    data = bytearray(m.SIZE)
    for offset, encoded in m.ANCHORS.items():
        data[offset:offset + len(bytes.fromhex(encoded))] = bytes.fromhex(encoded)
    for offset, word in m.WORDS.items():
        struct.pack_into("<I", data, offset, word)
    for n, pair in enumerate(m.WRITE_RANGES):
        struct.pack_into("<2I", data, 0x16744 + 8 * n, *pair)
    for tag, handler in [(9, 0x200033a1), (10, 0x2000340d)]:
        struct.pack_into("<3I", data, m.TABLE + 12 * (tag - 1), handler, 0, 0)
    return data


def synthetic_audit(data):
    return m.audit(data, expected_sha=hashlib.sha256(data).hexdigest())


class LoaderExecutionGateTests(unittest.TestCase):
    def test_synthetic_cannot_impersonate_original_image(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            m.audit(fixture())

    def test_disabled_nonnull_handlers_are_not_dispatched(self):
        result = synthetic_audit(fixture())
        for entry in result["commands"]:
            if entry["tag"] in (9, 10):
                self.assertNotEqual(entry["handler"], "0x0")
                self.assertFalse(entry["dispatches"])
        self.assertEqual(result["disabled_response_status"], "0x2710")

    def test_modified_gate_instruction_is_rejected(self):
        data = fixture()
        data[0x2f0a] ^= 1
        with self.assertRaisesRegex(ValueError, "instruction anchor"):
            synthetic_audit(data)

    def test_enabled_call_is_not_misreported_as_disabled(self):
        data = fixture()
        data[m.TABLE + 12 * 9 + 8] = 1
        self.assertTrue(m.command_entry(data, 10)["dispatches"])
        with self.assertRaisesRegex(ValueError, "table gate"):
            synthetic_audit(data)

    def test_changed_runtime_table_pointer_is_rejected(self):
        data = fixture()
        struct.pack_into("<I", data, 0x166c4, 0x20000000)
        with self.assertRaisesRegex(ValueError, "pointer/literal"):
            synthetic_audit(data)

    def test_out_of_range_tags_have_no_entry(self):
        self.assertIsNone(m.command_entry(fixture(), 0))
        self.assertIsNone(m.command_entry(fixture(), 22))

    def test_ordinary_table_patch_is_excluded_but_configuration_buffer_allowed(self):
        self.assertFalse(m.ordinary_write_allowed(0x200159e0, 1))
        self.assertFalse(m.ordinary_write_allowed(0x200159ec, 1))
        self.assertTrue(m.ordinary_write_allowed(0x2000, 512))
        self.assertFalse(m.ordinary_write_allowed(0x2000, 513))

    def test_wraparound_is_explicitly_outside_model(self):
        with self.assertRaisesRegex(ValueError, "nonwrapping"):
            m.ordinary_write_allowed(0x200159e0, 0xe0000000)

    def test_expanded_write_range_is_detected(self):
        data = fixture()
        struct.pack_into("<2I", data, 0x16744, 0, 0xffffffff)
        with self.assertRaisesRegex(ValueError, "write policy"):
            synthetic_audit(data)

    def test_huge_command_total_does_not_become_backend_fragment_length(self):
        for address in (0x200159e0, 0x200159ec):
            fragment = m.usb_fragment_length(0xffffffff, 0xffff)
            self.assertEqual(fragment, 65535)
            self.assertFalse(m.ordinary_write_allowed(address, fragment))
        self.assertEqual(m.usb_fragment_length(1, 512), 1)

    def test_fragment_model_rejects_impossible_uint16_size(self):
        with self.assertRaisesRegex(ValueError, "uint16"):
            m.usb_fragment_length(0xffffffff, 0x10000)


if __name__ == "__main__":
    unittest.main()
