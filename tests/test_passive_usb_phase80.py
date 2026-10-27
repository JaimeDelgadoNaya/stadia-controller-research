"""Phase 80 synthetic-only tests: in-memory pairing of USB URB/IRP identifiers."""
import csv
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tools.audit_passive_usb_phase79 import FIELDS, audit, urb_identifier

PHASE61 = {'hub': {
    'device': '12010102ef020140d1180094000101020301',
    'configuration': ('0902500002010080fa080b0001ff0000000904000002ff00000007058702000200'
                      '07050702000200080b01010300000009040100020300000009211101000122b600'
                      '0705830340000607050303400006'),
}}


def urb(bus='1', address='4', endpoint='0x07', kind='S', data_len='5'):
    return dict(zip(FIELDS[:5], (bus, address, endpoint, kind, data_len)))


def event(kind='S', ep='0x07', urb_id='', irp_id='', bus='1', address='4'):
    return {**urb(kind=kind, endpoint=ep, bus=bus, address=address),
            'usb.urb_id': urb_id, 'usb.irp_id': irp_id}


class PassiveUsbPhase80(unittest.TestCase):
    def run_rows(self, rows, headers=FIELDS):
        with TemporaryDirectory() as d:
            path = Path(d) / 'events.csv'
            with path.open('w', encoding='utf-8', newline='') as stream:
                writer = csv.DictWriter(stream, fieldnames=headers)
                writer.writeheader()
                writer.writerows(rows)
            return audit(path, PHASE61, bus=1, address=4)

    def test_paired_complete_error_and_reused_identifier(self):
        rows = [
            event('S', urb_id='0x123'),
            event('C', urb_id='0x123'),
            event('S', ep='0x83', urb_id='0x123'),
            event('E', ep='0x83', urb_id='0x123'),
            event('S', ep='0x00', urb_id='0xabcdef'),
            event('C', ep='0x00', urb_id='0xabcdef'),
        ]
        pairing = self.run_rows(rows)['urb_pairing']
        self.assertEqual(pairing['status'], 'id_events_observed')
        self.assertEqual(pairing['paired_complete'], 2)
        self.assertEqual(pairing['paired_error'], 1)
        self.assertEqual(pairing['unmatched_submit_at_end'], 0)
        self.assertEqual(pairing['duplicate_pending_submit'], 0)
        self.assertEqual(pairing['id_events'], 6)
        self.assertNotIn('0xabcdef', json.dumps(pairing))
        self.assertNotIn('0x123', json.dumps(pairing))

    def test_unmatched_terminals_and_capture_tail(self):
        pairing = self.run_rows([
            event('C', urb_id='0x1'),
            event('E', urb_id='0x2'),
            event('S', urb_id='0x3'),
        ])['urb_pairing']
        self.assertEqual(pairing['unmatched_complete'], 1)
        self.assertEqual(pairing['unmatched_error'], 1)
        self.assertEqual(pairing['unmatched_submit_at_end'], 1)
        self.assertEqual(pairing['paired_complete'], 0)

    def test_endpoint_mismatch_is_not_counted_as_pair(self):
        pairing = self.run_rows([
            event('S', ep='0x07', urb_id='0x1'),
            event('C', ep='0x87', urb_id='0x1'),
        ])['urb_pairing']
        self.assertEqual(pairing['endpoint_mismatch'], 1)
        self.assertEqual(pairing['paired_complete'], 0)
        self.assertEqual(pairing['unmatched_submit_at_end'], 0)

    def test_duplicate_pending_id_is_ambiguous_not_a_pair(self):
        pairing = self.run_rows([
            event('S', urb_id='0x9'),
            event('S', urb_id='0x9'),
            event('C', urb_id='0x9'),
        ])['urb_pairing']
        self.assertEqual(pairing['duplicate_pending_submit'], 1)
        self.assertEqual(pairing['ambiguous_id_terminal'], 1)
        self.assertEqual(pairing['paired_complete'], 0)

    def test_irp_id_windows_fallback_and_multiple_devices(self):
        pairing = self.run_rows([
            event('S', irp_id='18446744073709551615'),
            event('C', irp_id='0xffffffffffffffff'),
            event('S', irp_id='0xab', address='5'),
            event('C', irp_id='0xab', address='5'),
        ])['urb_pairing']
        self.assertEqual(pairing['paired_complete'], 1)
        self.assertEqual(pairing['id_events'], 2)
        self.assertEqual(pairing['unmatched_submit_at_end'], 0)

    def test_conflicting_urb_irp_ids_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Conflicting'):
            self.run_rows([event('S', urb_id='0x12', irp_id='0x13')])
        pairing = self.run_rows([
            event('S', urb_id='18', irp_id='0x12'),
            event('C', urb_id='0x12', irp_id='18'),
        ])['urb_pairing']
        self.assertEqual(pairing['paired_complete'], 1)

    def test_missing_ids_do_not_fake_a_pair(self):
        pairing = self.run_rows([
            event('S', urb_id='0x5'),
            event('C'),
            event('S'),
        ])['urb_pairing']
        self.assertEqual(pairing['status'], 'partial_ids')
        self.assertEqual(pairing['missing_id_events'], 2)
        self.assertEqual(pairing['paired_complete'], 0)
        self.assertEqual(pairing['unmatched_submit_at_end'], 1)

    def test_identifiers_not_exported_keeps_legacy_behavior(self):
        old_fields = FIELDS[:-2]
        old_row = {k:v for k,v in event('S').items() if k in old_fields}
        result = self.run_rows([old_row], headers=old_fields)
        self.assertEqual(result['urb_pairing']['status'], 'not_exported')
        self.assertEqual(result['counts']['known_endpoint_events'], 1)

    def test_missing_endpoint_id_cannot_pair(self):
        pairing = self.run_rows([
            event('S', ep='', urb_id='0x4'),
            event('C', ep='', urb_id='0x4'),
        ])['urb_pairing']
        self.assertEqual(pairing['unpairable_endpoint_events'], 2)
        self.assertEqual(pairing['paired_complete'], 0)

    def test_bad_64bit_identifiers_fail_closed(self):
        for bad in ('0x10000000000000000', '18446744073709551616',
                    '-1', 'bad id', '0x'):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self.run_rows([event('S', urb_id=bad)])

    def test_id_parser_does_not_echo_private_identifier(self):
        self.assertEqual(urb_identifier('0xFFFFFFFFFFFFFFFF'), 2**64-1)
        with self.assertRaises(ValueError) as cm:
            urb_identifier('secret-pointer-12345')
        self.assertNotIn('secret-pointer-12345', str(cm.exception))


if __name__ == '__main__':
    unittest.main()
