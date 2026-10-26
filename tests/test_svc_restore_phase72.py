import json
import os
from pathlib import Path
import unittest

from tools.audit_svc_restore_phase72 import audit,verify_pins
from tools.audit_usb_provider_phase63 import BASE

ROOT=Path(__file__).resolve().parents[1]


class SvcRestoreTests(unittest.TestCase):
    def test_image_gate_before_execution(self):
        with self.assertRaisesRegex(ValueError,'SHA-pinned'):
            audit(b'')

    def test_original_software_restore_without_exception_return(self):
        r=json.loads((ROOT/'evidence/usb-svc-restore-phase72.json').read_text())
        c=r['original_software_restore']
        self.assertEqual(c['before']['basepri'],'0x50')
        self.assertEqual(c['after']['basepri'],'0x0')
        self.assertEqual(c['after']['msp'],c['before']['msp'])
        self.assertEqual(c['after']['psp'],'0x20020b28')
        self.assertEqual(c['after']['lr'],'0xfffffffd')
        self.assertEqual(c['after']['cpu_r0'],'0x0')
        self.assertEqual(c['pending_hardware_frame']['stacked_r0'],'0x2002014c')
        self.assertEqual(c['pending_hardware_frame']['stacked_pc'],'0x60101760')
        self.assertTrue(c['restored_words_match_original_frame'])
        self.assertEqual(len(c['restored_r4_through_r11']),8)
        self.assertTrue(all(not c[k] for k in ('svc_executed','exception_entry_executed','exception_return_executed','task_entry_executed')))
        self.assertNotIn(c['stop_pc'],c['executed_instruction_addresses'])

    @unittest.skipUnless(os.environ.get('STADIA_BRUCE_IMAGE'),'Optional original fixture unavailable')
    def test_original_image_exact_reproduction(self):
        image=Path(os.environ['STADIA_BRUCE_IMAGE']).read_bytes()
        expected=json.loads((ROOT/'evidence/usb-svc-restore-phase72.json').read_text())
        self.assertEqual(audit(image),expected)

    @unittest.skipUnless(os.environ.get('STADIA_BRUCE_IMAGE'),'Optional original fixture unavailable')
    def test_vector_register_restore_and_exception_return_drift_rejected(self):
        image=Path(os.environ['STADIA_BRUCE_IMAGE']).read_bytes()
        for offset in (0x2C,0x6004CB46-BASE,0x6004CB5A-BASE):
            changed=bytearray(image)
            changed[offset]^=1
            with self.subTest(offset=hex(offset)):
                with self.assertRaisesRegex(ValueError,'drift'):
                    verify_pins(changed)
                with self.assertRaisesRegex(ValueError,'SHA-pinned'):
                    audit(changed)
