"""Synthetic-only regression cases for Phase 79. No physical capture in tests."""
import csv
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tools.audit_passive_usb_phase79 import FIELDS, audit, expected_endpoints

DEVICE = '12010102ef020140d1180094000101020301'
CONFIG = ('0902500002010080fa080b0001ff0000000904000002ff00000007058702000200'
          '07050702000200080b01010300000009040100020300000009211101000122b600'
          '0705830340000607050303400006')
PHASE61 = {'hub': {'device': DEVICE, 'configuration': CONFIG}}


def urb(bus='1', address='4', endpoint='0x07', kind='S', data_len='5',
        vid='', pid='', bm='', request=''):
    return dict(zip(FIELDS, (bus, address, endpoint, kind, data_len, bm, request, vid, pid)))


class PassiveUsbPhase79(unittest.TestCase):
    def run_rows(self, rows, headers=FIELDS, phase61=PHASE61, bus=1, address=4):
        with TemporaryDirectory() as d:
            p = Path(d) / 'meta.csv'
            with p.open('w', newline='', encoding='utf-8') as fd:
                w = csv.DictWriter(fd, fieldnames=headers)
                w.writeheader()
                w.writerows(rows)
            return audit(p, phase61, bus, address)

    def test_original_phase61_fingerprint_and_class_map(self):
        endpoints, sha = expected_endpoints(PHASE61)
        self.assertEqual(sha, '01b299fc757c731df8c2de21a953ed8b0fc0c854f6043c178b8cc7588c26e5db')
        self.assertEqual({k:v['usb_class'] for k,v in endpoints.items()},
                         {0x87:'0xff',0x07:'0xff',0x83:'0x03',0x03:'0x03'})

    def test_events_request_classes_and_mixed_device_filter(self):
        rows = [
            urb(endpoint='0x00', kind='S', data_len='0', bm='0x80', request='0x06', vid='0x18d1',pid='0x9400'),
            urb(endpoint='0x00', kind='C', data_len='18'),
            urb(endpoint='0x00', kind='S', bm='0x21', request='0x09'),
            urb(endpoint='0x07', kind='S', data_len='64'),
            urb(endpoint='0x87', kind='C', data_len='512'),
            urb(endpoint='0x83', kind='C', data_len='11'),
            urb(endpoint='0x03', kind='E', data_len=''),
            urb(endpoint='0x89', kind='S', data_len='2'),
            urb(bus='1', address='5', endpoint='0x07', vid='0x1234',pid='0x5678'),
        ]
        result = self.run_rows(rows)
        self.assertEqual(result['device_identity_in_selected_urbs'], 'observed_vid_pid')
        self.assertEqual(result['counts']['selected_urb_events'], 8)
        self.assertEqual(result['counts']['known_endpoint_events'], 4)
        self.assertEqual(result['undeclared_endpoint_events'], {'0x89':1})
        self.assertEqual(result['control_ep0']['setup_request_classes'],
                         {'class:OUT:bRequest=0x09':1,'standard:IN:bRequest=0x06':1})
        eps={e['address']:e for e in result['endpoints']}
        self.assertEqual(eps['0x07']['submit'], 1)
        self.assertEqual(eps['0x87']['reported_data_length_sum'], 512)
        self.assertEqual(eps['0x03']['missing_length'], 1)
        report=json.dumps(result)
        self.assertNotIn('0x2002', report)
        self.assertNotIn('payload', result)

    def test_selection_without_vid_pid_does_not_claim_identity(self):
        result=self.run_rows([urb()])
        self.assertEqual(result['device_identity_in_selected_urbs'], 'not_observed')
        self.assertEqual(result['counts']['selected_urb_events'], 1)

    def test_wrong_vid_pid_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'different VID/PID'):
            self.run_rows([urb(vid='0x18d1', pid='0x946b')])

    def test_partial_id_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'Partial VID/PID'):
            self.run_rows([urb(vid='0x18d1')])

    def test_descriptor_byte_drift_fails_closed(self):
        bad=json.loads(json.dumps(PHASE61))
        bad['hub']['configuration']=bad['hub']['configuration'][:-2]+'07'
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            self.run_rows([urb()], phase61=bad)

    def test_disallow_private_or_payload_columns(self):
        with self.assertRaisesRegex(ValueError, 'Unapproved columns'):
            self.run_rows([{**urb(), 'usb.capdata':'deadbeef'}], headers=(*FIELDS,'usb.capdata'))

    def test_invalid_event_or_missing_rows_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'Unexpected USB URB'):
            self.run_rows([urb(kind='UNKNOWN')])
        with self.assertRaisesRegex(ValueError, 'No URBs'):
            self.run_rows([urb(address='5')])

    def test_ep0_missing_setup_does_not_invent_request(self):
        result = self.run_rows([urb(endpoint='0x00', data_len='0')])
        self.assertEqual(result['control_ep0']['incomplete_submit_setup'], 1)
        self.assertEqual(result['control_ep0']['setup_request_classes'], {})

    def test_no_header_or_broken_address_rejected(self):
        with self.assertRaisesRegex(ValueError, 'CSV missing required'):
            self.run_rows([{'usb.bus_id':'1'}],headers=('usb.bus_id',))
        with self.assertRaisesRegex(ValueError, 'Out-of-range'):
            self.run_rows([urb(endpoint='0x1ff')])


if __name__ == '__main__':
    unittest.main()
