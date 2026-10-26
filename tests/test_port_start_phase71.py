import json
import os
from pathlib import Path
import unittest

from tools.audit_port_start_phase71 import audit,verify_pins
from tools.audit_usb_provider_phase63 import BASE

ROOT=Path(__file__).resolve().parents[1]


class PortStartTests(unittest.TestCase):
    def test_image_gate_before_execution(self):
        with self.assertRaisesRegex(ValueError,'SHA-pinned'):
            audit(b'')

    def test_normalization_and_pre_svc_boundaries(self):
        r=json.loads((ROOT/'evidence/usb-port-start-phase71.json').read_text())
        wide,accepted,narrow=r['port_start_cases']
        self.assertEqual([c['priority_readback_mask'] for c in (wide,accepted,narrow)],['0xff','0xf0','0xe0'])
        self.assertEqual(accepted['outcome'],'stopped_before_svc')
        self.assertEqual(accepted['nesting_after'],'0x0')
        self.assertEqual(accepted['virtual_basepri_after'],'0x50')
        self.assertEqual(accepted['virtual_msp'],'0x2002b828')
        self.assertEqual(accepted['tick_reload'],accepted['clock_word_from_virtual_initialized_data']//1000-1)
        for failed in (wide,narrow):
            self.assertEqual(failed['outcome'],'assertion_call_before_normalization')
            self.assertEqual(failed['nesting_after'],'0xaaaaaaaa')
        self.assertTrue(all(not c['svc_executed'] and not c['task_entry_executed'] for c in (wide,accepted,narrow)))
        self.assertFalse(r['original_vector']['handler_executed'])
        self.assertEqual(r['original_vector']['static_mask_clear_pc'],'0x6004cb56')

    @unittest.skipUnless(os.environ.get('STADIA_BRUCE_IMAGE'),'Optional original fixture unavailable')
    def test_original_image_exact_evidence_reproduction(self):
        image=Path(os.environ['STADIA_BRUCE_IMAGE']).read_bytes()
        expected=json.loads((ROOT/'evidence/usb-port-start-phase71.json').read_text())
        self.assertEqual(audit(image),expected)

    @unittest.skipUnless(os.environ.get('STADIA_BRUCE_IMAGE'),'Optional original fixture unavailable')
    def test_nesting_store_svc_instruction_and_handler_mask_drift_rejected(self):
        image=Path(os.environ['STADIA_BRUCE_IMAGE']).read_bytes()
        for address in (0x600CC624,0x600CC536,0x6004CB56):
            changed=bytearray(image)
            changed[address-BASE]^=1
            with self.subTest(address=hex(address)):
                with self.assertRaisesRegex(ValueError,'drift'):
                    verify_pins(changed)
                with self.assertRaisesRegex(ValueError,'SHA-pinned'):
                    audit(changed)
