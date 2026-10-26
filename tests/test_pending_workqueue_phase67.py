import json
import os
from pathlib import Path
import unittest

from tools.audit_pending_workqueue_phase67 import audit,verify_pins,BASE,LABEL

ROOT=Path(__file__).resolve().parents[1]


class PendingQueueTests(unittest.TestCase):
    def test_image_gate_before_execution(self):
        with self.assertRaisesRegex(ValueError,'SHA-pinned'):
            audit(b'')

    def test_recorded_return_and_error_boundaries(self):
        r=json.loads((ROOT/'evidence/usb-pending-workqueue-phase67.json').read_text())
        cases=r['cases']
        self.assertEqual([c['original_queue_status'] for c in cases],[0,9,3,0])
        self.assertTrue(all(c['original_pending_call_executed'] for c in cases))
        self.assertTrue(all(c['mode_field_after_attempt']==1 for c in cases))
        self.assertFalse(cases[0]['creation_primitive_reached'])
        self.assertTrue(cases[3]['creation_primitive_reached'])
        self.assertEqual(cases[0]['stop_pc'],'0x600747b6')
        self.assertEqual(cases[1]['stop_pc'],'0x60060f3e')
        chain=r['post_completed_mode_function_chain']
        self.assertEqual(chain['snapshot']['record_instance'],'0x200040e0')
        self.assertEqual(chain['transition']['mode_at_stop'],1)
        self.assertTrue(any('not validated' in limit for limit in r['limits']))

    @unittest.skipUnless(os.environ.get('STADIA_BRUCE_IMAGE'),'Optional original fixture unavailable')
    def test_original_image_exact_reproduction(self):
        image=Path(os.environ['STADIA_BRUCE_IMAGE']).read_bytes()
        published=json.loads((ROOT/'evidence/usb-pending-workqueue-phase67.json').read_text())
        self.assertEqual(audit(image),published)

    @unittest.skipUnless(os.environ.get('STADIA_BRUCE_IMAGE'),'Optional original fixture unavailable')
    def test_queue_guard_size_guard_and_label_drift_rejected(self):
        image=Path(os.environ['STADIA_BRUCE_IMAGE']).read_bytes()
        for address in (0x60092684,0x600CC194,LABEL):
            changed=bytearray(image)
            changed[address-BASE]^=1
            with self.subTest(address=hex(address)):
                with self.assertRaisesRegex(ValueError,'drift'):
                    verify_pins(changed)
                with self.assertRaisesRegex(ValueError,'SHA-pinned'):
                    audit(changed)
