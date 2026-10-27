import json
import os
from pathlib import Path
import unittest
from tools.audit_bridge_host_phase84 import audit, run_cases, FLAGS
ROOT=Path(__file__).resolve().parents[1]
CAPTURE=json.loads((ROOT/'evidence/usb-live-hid-input-phase80.json').read_text())

class BridgeHost84Tests(unittest.TestCase):
    def test_audit_detects_output_dependency_on_target_bit(self):
        class Bad:
            def run(self, payload):
                result=bytearray(20)
                result[2]=payload[1]&4
                return bytes(result),dict.fromkeys(FLAGS,0)
        with self.assertRaisesRegex(ValueError,'Unexpected changed output'):
            run_cases(Bad(),{'phase':80,'report_count':0,'distinct_reports':[]})

    def test_capture_total_rejects_boolean(self):
        with self.assertRaisesRegex(ValueError,'nonnegative integer'):
            run_cases(None,{'phase':80,'report_count':False,'distinct_reports':[]})

    @unittest.skipUnless(os.environ.get('STADIA_BRIDGE_CHECKOUT') and os.environ.get('STADIA_BRIDGE_LIBRARY'),
                         'Pinned bridge checkout and host library path not configured')
    def test_original_c_host_experiment_reproduces_evidence(self):
        result=audit(Path(os.environ['STADIA_BRIDGE_CHECKOUT']),Path(os.environ['STADIA_BRIDGE_LIBRARY']),CAPTURE)
        expected=json.loads((ROOT/'evidence/usb-bridge-host-tests-phase84.json').read_text())
        self.assertEqual(result,expected)
        self.assertEqual(result['hypothetical_usb_as_ble_paired_checks'],6995)
        rows={(r['payload_byte'],r['bit']):r for r in result['individual_bit_cases']}
        self.assertEqual(rows[(1,0)]['changed_parsed_flags'],['capture'])
        self.assertEqual(rows[(1,1)]['changed_parsed_flags'],['assistant'])
        self.assertEqual(rows[(1,2)]['changed_output_bytes'],[])
        self.assertEqual(rows[(1,3)]['changed_parsed_flags'],[])
        self.assertTrue(all(not rows[(9,n)]['changed_output_bytes'] for n in range(8)))
