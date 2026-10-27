import copy
import json
from pathlib import Path
import unittest
from tools.analyze_labeled_controls_phase85 import analyze
ROOT=Path(__file__).resolve().parents[1]
SOURCE=json.loads((ROOT/'evidence/usb-labeled-controls-phase85.json').read_text())
DESC=bytes.fromhex(json.loads((ROOT/'evidence/stadia-hid-report-contract.json').read_text())['descriptor_hex'])
BRIDGE=json.loads((ROOT/'evidence/usb-ble-layout-comparison-phase83.json').read_text())

class LabeledControls85Tests(unittest.TestCase):
    def test_recorded_map_reproduces_and_candidate_boundary_is_bounded(self):
        result=analyze(SOURCE,DESC,BRIDGE)
        self.assertEqual(result,json.loads((ROOT/'evidence/usb-control-map-phase85.json').read_text()))
        self.assertEqual([result['trials'][x]['usb_button_usage'] for x in ('A','B','X','Y')],[1,2,4,5])
        self.assertEqual([result['trials'][x]['hat_direction_code'] for x in ('dpad_up','dpad_right','dpad_down','dpad_left')],[0,2,4,6])
        self.assertEqual((result['trials']['LT']['usb_analog_usage'],result['trials']['LT']['usb_button_usage']),('0xc5',20))
        self.assertEqual((result['trials']['RT']['usb_analog_usage'],result['trials']['RT']['usb_button_usage']),('0xc4',19))
        self.assertTrue(result['trials']['LT']['sampled_analog_64'])
        self.assertFalse(result['trials']['RT']['sampled_analog_64'])
        self.assertTrue(all(result['corresponding_upstream_ble_position_matches_usb_observation'].values()))

    def test_reject_unconfirmed_or_contaminated_trial(self):
        bad=copy.deepcopy(SOURCE)
        bad['trials'][0]['interaction']['actual_action_confirmation']='pending'
        with self.assertRaisesRegex(ValueError,'unconfirmed'):analyze(bad,DESC,BRIDGE)
        bad=copy.deepcopy(SOURCE)
        bad['trials'][0]['distinct_reports'][1]['hex']='0308006080808080000000'
        with self.assertRaisesRegex(ValueError,'not isolated'):analyze(bad,DESC,BRIDGE)
        bad=copy.deepcopy(SOURCE)
        bad['trials'][0]['report_count']+=1
        with self.assertRaisesRegex(ValueError,'count mismatch'):analyze(bad,DESC,BRIDGE)
        with self.assertRaisesRegex(ValueError,'descriptor'):analyze(SOURCE,b'wrong',BRIDGE)

    def test_fail_closed_on_incomplete_or_repeated_trials(self):
        bad=copy.deepcopy(SOURCE)
        bad['trials'].pop()
        with self.assertRaisesRegex(ValueError,'ten confirmed'):analyze(bad,DESC,BRIDGE)
        bad=copy.deepcopy(SOURCE)
        bad['trials'].append(copy.deepcopy(bad['trials'][0]))
        with self.assertRaisesRegex(ValueError,'Duplicate'):analyze(bad,DESC,BRIDGE)
