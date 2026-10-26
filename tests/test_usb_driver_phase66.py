import json
import os
from pathlib import Path
import unittest

from tools.audit_usb_driver_phase66 import audit,verify_pins,BASE

ROOT=Path(__file__).resolve().parents[1]


class DriverModeTests(unittest.TestCase):
    def test_hash_gate_before_execution(self):
        with self.assertRaisesRegex(ValueError,'SHA-pinned'):
            audit(b'')

    def test_published_mask_threshold_and_unsupported_mode(self):
        r=json.loads((ROOT/'evidence/usb-driver-mode-phase66.json').read_text())
        cases=r['raw_original_driver_cases']
        self.assertEqual([c['original_return'] for c in cases],[1,1,0,0,0,1,6])
        for c in cases:
            self.assertFalse(c['driver_or_helper_stubbed'])
            self.assertEqual(c['helper_55400_executed'],c['original_return']==0)
            if c['original_return']==0:
                self.assertEqual(c['output_driver_pointer'],'0x20011dfc')
                self.assertEqual(c['driver_context'],'0x200063c0')
                self.assertTrue(c['mmio_writes'])
            else:
                self.assertFalse(c['mmio_writes'])

    def test_published_composition_keeps_remaining_boundaries(self):
        r=json.loads((ROOT/'evidence/usb-driver-mode-phase66.json').read_text())
        zero,success,failure=r['transition_driver_class10_cases']
        self.assertEqual(zero['stop'],'transition_early_return')
        self.assertFalse(zero['class10_initializer_reached'])
        self.assertEqual(success['snapshot']['record_instance'],'0x200040e0')
        self.assertEqual(success['original_driver']['engine_driver_object'],'0x20011dfc')
        self.assertIsNone(success['inputs']['driver_status_stub'])
        self.assertEqual(success['transition']['mode_at_stop'],1)
        self.assertEqual(success['transition']['requested_mode'],2)
        self.assertFalse(failure['class10_initializer_reached'])
        self.assertEqual(failure['driver_error_r5_at_failure'],1)
        self.assertEqual(r['original_prior_mode_writer']['stop_before_call'],'0x6009267c')

    @unittest.skipUnless(os.environ.get('STADIA_BRUCE_IMAGE'),'Optional original fixture unavailable')
    def test_original_image_exact_reproduction(self):
        image=Path(os.environ['STADIA_BRUCE_IMAGE']).read_bytes()
        published=json.loads((ROOT/'evidence/usb-driver-mode-phase66.json').read_text())
        self.assertEqual(audit(image),published)

    @unittest.skipUnless(os.environ.get('STADIA_BRUCE_IMAGE'),'Optional original fixture unavailable')
    def test_changed_gate_mmio_base_and_mode_store_rejected(self):
        image=Path(os.environ['STADIA_BRUCE_IMAGE']).read_bytes()
        for address in (0x60055594,0x600555D0,0x60060F2C):
            changed=bytearray(image)
            changed[address-BASE]^=1
            with self.subTest(address=hex(address)):
                with self.assertRaisesRegex(ValueError,'drift'):
                    verify_pins(changed)
                with self.assertRaisesRegex(ValueError,'SHA-pinned'):
                    audit(changed)
