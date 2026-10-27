import json
import os
from pathlib import Path
import unittest
from tools.compare_bridge_layout_phase83 import audit, compare, usb_positions, parse_positions
ROOT=Path(__file__).resolve().parents[1]
DESC=bytes.fromhex(json.loads((ROOT/'evidence/stadia-hid-report-contract.json').read_text())['descriptor_hex'])
CAPTURE=json.loads((ROOT/'evidence/usb-live-hid-input-phase80.json').read_text())

class BridgeLayout83Tests(unittest.TestCase):
    def test_descriptor_positions_preserve_report_id_boundary(self):
        buttons,axes=usb_positions(DESC)
        self.assertEqual(buttons[(2,6)],1)
        self.assertEqual(buttons[(2,5)],2)
        self.assertEqual(buttons[(1,2)],20)
        self.assertEqual(buttons[(1,3)],19)
        self.assertEqual(axes[3],(1,48))
        self.assertEqual(axes[7],(2,197))
        self.assertEqual(len(buttons),15)
        self.assertEqual(len(axes),6)

    def test_compare_is_position_based_and_rejects_aliases_or_holes(self):
        usb_buttons,usb_axes=usb_positions(DESC)
        counts={str(x):0 for x in usb_buttons.values()}
        b,a=compare({'example':(2,6)},{'example_axis':7},usb_buttons,usb_axes,counts)
        self.assertEqual(b[0]['usb_button_usage'],1)
        self.assertEqual((a[0]['usb_usage_page'],a[0]['usb_usage']),(2,197))
        with self.assertRaises(ValueError):compare({'a':(2,6),'b':(2,6)},{},usb_buttons,usb_axes,counts)
        with self.assertRaises(ValueError):compare({'a':(0,0)},{},usb_buttons,usb_axes,counts)
        with self.assertRaises(ValueError):compare({}, {'a':9},usb_buttons,usb_axes,counts)

    def test_unsigned_sources_are_rejected(self):
        with self.assertRaises(ValueError):parse_positions(b'not pinned source')
        with self.assertRaises(ValueError):usb_positions(b'not recorded descriptor')

    @unittest.skipUnless(os.environ.get('STADIA_BRIDGE_SOURCE'),'Pinned external GPL source not mounted')
    def test_original_pinned_source_reproduces_evidence(self):
        source=Path(os.environ['STADIA_BRIDGE_SOURCE']).read_bytes()
        expected=json.loads((ROOT/'evidence/usb-ble-layout-comparison-phase83.json').read_text())
        self.assertEqual(audit(source,DESC,CAPTURE),expected)
        self.assertEqual(len(expected['matched_button_positions']),13)
        self.assertEqual(len(expected['matched_analog_positions']),6)
        self.assertEqual(expected['usb_button_usages_without_upstream_label'],[19,20])
        with self.assertRaises(ValueError):parse_positions(source+b'\n')
