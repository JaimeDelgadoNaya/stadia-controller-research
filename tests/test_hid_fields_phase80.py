import copy
import json
from pathlib import Path
import unittest
from tools.analyze_hid_input_phase80 import analyze, field_values
ROOT=Path(__file__).resolve().parents[1]

class HidField80Tests(unittest.TestCase):
    def test_cross_byte_and_signed_extraction(self):
        f={'size':5,'count':2,'report_id':3,'payload_bit_offset':6,'logical_min':-16}
        value=(31<<6)|(7<<11)
        self.assertEqual(field_values(b'\x03'+value.to_bytes(3,'little'),f),[-1,7])
        with self.assertRaises(ValueError): field_values(b'\x03',f)

    def test_capture_reproduction_and_rejections(self):
        source=json.loads((ROOT/'evidence/usb-live-hid-input-phase80.json').read_text())
        descriptor=bytes.fromhex(json.loads((ROOT/'evidence/stadia-hid-report-contract.json').read_text())['descriptor_hex'])
        expected=json.loads((ROOT/'evidence/usb-hid-field-observations-phase80.json').read_text())
        self.assertEqual(analyze(source,descriptor),expected)
        self.assertEqual(expected['report_count'],1758)
        self.assertTrue(source['all_match_id3_length11'])
        for bad in ('0400000000000000000000','03'):
            modified=copy.deepcopy(source)
            modified['distinct_reports'][0]['hex']=bad
            with self.assertRaises(ValueError): analyze(modified,descriptor)
        modified=copy.deepcopy(source)
        modified['report_count']+=1
        with self.assertRaises(ValueError): analyze(modified,descriptor)

    def test_empty_capture_has_no_observed_values(self):
        descriptor=bytes.fromhex(json.loads((ROOT/'evidence/stadia-hid-report-contract.json').read_text())['descriptor_hex'])
        r=analyze({'report_count':0,'distinct_reports':[]},descriptor)
        self.assertTrue(all(v['min'] is None for f in r['fields'] for v in f['observed_elements']))
