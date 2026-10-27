import json
from pathlib import Path
import unittest
from tools.audit_hid_differential_phase82 import audit
from tools.decode_hid_input_phase81 import decode_report,replay
ROOT=Path(__file__).resolve().parents[1]
DESC=bytes.fromhex(json.loads((ROOT/'evidence/stadia-hid-report-contract.json').read_text())['descriptor_hex'])

class Differential82Tests(unittest.TestCase):
    def test_all_vectors_and_recorded_evidence(self):
        expected=json.loads((ROOT/'evidence/usb-hid-differential-phase82.json').read_text())
        self.assertEqual(audit(DESC),expected)
        self.assertEqual(sum(expected['synthetic_vector_counts'].values()),39424)
        self.assertEqual(expected['rejected_wrong_ids'],255)
        self.assertEqual(expected['rejected_single_bit_descriptor_mutations'],len(DESC)*8)

    def test_comparison_detects_swapped_button_mapping(self):
        def swapped(raw,descriptor):
            result=decode_report(raw,descriptor)
            result['button_usages']=[17 if u==18 else 18 if u==17 else u for u in result['button_usages']]
            return result
        with self.assertRaisesRegex(ValueError,'Differential mismatch'):
            audit(DESC,decoder=swapped)

    def test_comparison_detects_lost_padding_diagnostic(self):
        def lost(raw,descriptor):
            result=decode_report(raw,descriptor)
            result['nonzero_constant_padding']=False
            return result
        with self.assertRaisesRegex(ValueError,'Differential mismatch'):
            audit(DESC,decoder=lost)

    def test_aggregate_total_requires_integer_even_if_numerically_equal(self):
        for invalid in (True,False,1.0,0.0,-1,'1',None):
            rows=[] if invalid in (False,0.0) else [{'hex':'0308000080808080000000','count':1}]
            with self.assertRaisesRegex(ValueError,'integer report_count'):
                replay({'phase':80,'report_count':invalid,'distinct_reports':rows},DESC)
        result=replay({'phase':80,'report_count':0,'distinct_reports':[]},DESC)
        self.assertEqual(result['report_count'],0)

    def test_reference_requires_recorded_descriptor(self):
        with self.assertRaises(ValueError):audit(b'not the descriptor')
