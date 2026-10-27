import json
from pathlib import Path
import unittest
from tools.decode_hid_input_phase81 import decode_report,replay,BUTTON_USAGES
from tools.audit_hid_report_contract import decode
from tools.analyze_hid_input_phase80 import field_values
ROOT=Path(__file__).resolve().parents[1]
DESC=bytes.fromhex(json.loads((ROOT/'evidence/stadia-hid-report-contract.json').read_text())['descriptor_hex'])

class HidDecoder81Tests(unittest.TestCase):
    def test_buttons_follow_descriptor_order_not_numeric_order(self):
        for bit, usage in enumerate(BUTTON_USAGES):
            raw=bytearray.fromhex('0308000080808080000000')
            raw[2:4]=(1<<bit).to_bytes(2,'little')
            self.assertEqual(decode_report(raw,DESC)['button_usages'],[usage])
        self.assertEqual(BUTTON_USAGES,(18,17,20,19,13,12,11,15,14,8,7,5,4,2,1))

    def test_null_hat_padding_and_analog_boundaries(self):
        for value in range(16):
            raw=bytearray.fromhex('0308000001ff01ff00ff00')
            raw[1]=value
            state=decode_report(raw,DESC)
            self.assertEqual(state['hat_direction'],value if value<8 else None)
            self.assertEqual(state['axes'],{'X':1,'Y':255,'Z':1,'Rz':255})
            self.assertEqual(state['page2_values'],{'0xc5':0,'0xc4':255})
            self.assertFalse(state['nonzero_constant_padding'])
        raw=bytes.fromhex('03f88080008080800000ff')
        state=decode_report(raw,DESC)
        self.assertTrue(state['nonzero_constant_padding'])
        self.assertTrue(state['generic_axes_outside_logical_range'])
        self.assertEqual(state['consumer_usages'],[233,234,205])

    def test_descriptor_driven_crosscheck_every_recorded_report(self):
        capture=json.loads((ROOT/'evidence/usb-live-hid-input-phase80.json').read_text())
        fields=[f for f in decode(DESC)['fields'] if f['direction']=='input' and not f['flags']&1]
        for row in capture['distinct_reports']:
            raw=bytes.fromhex(row['hex']); state=decode_report(raw,DESC)
            values=[field_values(raw,f) for f in fields]
            self.assertEqual(state['button_usages'],[u for u,v in zip(fields[1]['usages'],values[1]) if v])
            self.assertEqual(list(state['axes'].values()),values[2]+values[3])
            self.assertEqual(list(state['page2_values'].values()),values[4])
        expected=json.loads((ROOT/'evidence/usb-hid-decoder-replay-phase81.json').read_text())
        self.assertEqual(replay(capture,DESC),expected)

    def test_reject_descriptor_report_and_count_drift(self):
        with self.assertRaises(ValueError):decode_report(bytes(11),DESC)
        with self.assertRaises(ValueError):decode_report(b'\x03',DESC)
        with self.assertRaises(ValueError):decode_report(bytes(11),b'bad')
        with self.assertRaises(ValueError):replay({'phase':80,'report_count':0,'distinct_reports':[]},b'bad')
        with self.assertRaises(ValueError):replay({'phase':80,'report_count':1,'distinct_reports':[]},DESC)
        for count in (0,-1,True,0.5):
            with self.assertRaises(ValueError):replay({'phase':80,'report_count':count,'distinct_reports':[{'hex':'0308000080808080000000','count':count}]},DESC)
