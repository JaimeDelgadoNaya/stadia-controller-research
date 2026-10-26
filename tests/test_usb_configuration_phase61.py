import json
from pathlib import Path
import unittest

from tools.parse_usb_configuration import parse_configuration


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        report = json.loads((Path(__file__).resolve().parents[1] /
            'evidence/usb-enumeration-phase61.json').read_text(encoding='utf-8'))
        self.hub = bytes.fromhex(report['hub']['configuration'])
        self.function = bytes.fromhex(report['winusb_function_view']['configuration'])

    def test_complete_and_function_views_differ(self):
        full = parse_configuration(self.hub)
        partial = parse_configuration(self.function)
        self.assertEqual([i['usb_class'] for i in full['interfaces']], [255, 3])
        self.assertEqual(len(partial['interfaces']), 1)
        self.assertEqual(full['interfaces'][0], partial['interfaces'][0])
        self.assertEqual(full['interfaces'][1]['hid_report_descriptor_bytes'], 182)
        self.assertEqual([e['address'] for i in full['interfaces'] for e in i['endpoints']],
                         ['0x87', '0x07', '0x83', '0x03'])

    def test_truncated_or_malformed_rejected(self):
        for data in (self.hub[:-1], self.hub[:9] + b'\x00' + self.hub[10:],
                     self.hub[:4] + b'\x03' + self.hub[5:],
                     self.hub[:21] + b'\x03' + self.hub[22:]):
            with self.subTest(data=data.hex()):
                with self.assertRaises(ValueError):
                    parse_configuration(data)
