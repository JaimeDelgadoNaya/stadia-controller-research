import json
import os
from pathlib import Path
import unittest

from tools.audit_class10_instance_phase65 import audit, verify_pins, BASE

ROOT=Path(__file__).resolve().parents[1]


class Class10InstanceTests(unittest.TestCase):
    def test_hash_gate_before_execution(self):
        with self.assertRaisesRegex(ValueError,'SHA-pinned'):
            audit(b'')

    def test_published_guards_and_explicit_driver_assumption(self):
        r=json.loads((ROOT/'evidence/usb-class10-instance-phase65.json').read_text())
        self.assertEqual([c['r0_at_stop'] for c in r['isolated_class10_cases']],[4,4,0,2,2])
        success,failure=r['owner_to_class10_cases']
        self.assertEqual(success['snapshot']['record_instance'],'0x200040e0')
        self.assertEqual(success['snapshot']['class_record'],'0x2000a274')
        self.assertEqual(success['snapshot']['core_config'],'0x2000a2ac')
        self.assertTrue(any(w['pc']=='0x6005512e' for w in success['original_writes']))
        self.assertTrue(any(w['pc']=='0x60055340' for w in success['original_writes']))
        self.assertTrue(any(c['target']=='0x6005556c' and c['returned']==0 for c in success['stubbed_calls']))
        self.assertFalse(failure['class10_initializer_reached'])
        self.assertEqual(failure['stop'],'driver_failure_before_cleanup')
        self.assertEqual(failure['driver_error_r5_at_failure'],5)
        self.assertEqual(r['constructor_snapshot_previous_mode'],0)

    @unittest.skipUnless(os.environ.get('STADIA_BRUCE_IMAGE'),'Optional pinned OEM fixture unavailable')
    def test_original_image_exact_evidence_reproduction(self):
        image=Path(os.environ['STADIA_BRUCE_IMAGE']).read_bytes()
        expected=json.loads((ROOT/'evidence/usb-class10-instance-phase65.json').read_text())
        self.assertEqual(audit(image),expected)

    @unittest.skipUnless(os.environ.get('STADIA_BRUCE_IMAGE'),'Optional pinned OEM fixture unavailable')
    def test_original_gate_store_and_driver_pointer_drift_rejected(self):
        image=Path(os.environ['STADIA_BRUCE_IMAGE']).read_bytes()
        for address in (0x6005503A,0x60055340,0x60104BC4):
            changed=bytearray(image)
            changed[address-BASE]^=1
            with self.subTest(address=hex(address)):
                with self.assertRaisesRegex(ValueError,'drift'):
                    verify_pins(changed)
                with self.assertRaisesRegex(ValueError,'SHA-pinned'):
                    audit(changed)
