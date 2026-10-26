import json
import os
from pathlib import Path
import unittest

from tools.audit_scheduler_registration_phase70 import audit,verify_pins
from tools.audit_usb_provider_phase63 import BASE
from tools.audit_app_usb_dispatch import DATA_SOURCE_OFFSET,DATA_DESTINATION

ROOT=Path(__file__).resolve().parents[1]


class RegistrationTests(unittest.TestCase):
    def test_image_gate_before_execution(self):
        with self.assertRaisesRegex(ValueError,'SHA-pinned'):
            audit(b'')

    def test_original_lists_and_distinct_critical_states(self):
        r=json.loads((ROOT/'evidence/usb-scheduler-registration-phase70.json').read_text())
        states=[c['original_registration'] for c in r['original_registration_cases']]
        for c in states:
            self.assertEqual(c['task_count'],1)
            self.assertEqual(c['current_task'],'0x20020278')
            self.assertEqual(c['ready_bitmap'],'0x2')
            self.assertEqual(c['ready_count'],1)
            self.assertEqual(c['ready_next'],'0x2002027c')
            self.assertEqual(c['ready_previous'],c['ready_next'])
            self.assertEqual(c['node_container'],c['ready_list'])
            self.assertTrue(c['itcm_helpers_executed'])
            self.assertFalse(c['stubbed'])
            self.assertFalse(c['task_entry_executed'])
        self.assertEqual([c['final_critical_nesting'] for c in states],['0xaaaaaaaa','0x0'])
        self.assertEqual([c['virtual_basepri'] for c in states],['0x50','0x0'])
        self.assertEqual(r['post_registration_class10_chain']['snapshot']['record_instance'],'0x200040e0')

    @unittest.skipUnless(os.environ.get('STADIA_BRUCE_IMAGE'),'Optional original fixture unavailable')
    def test_original_image_exact_evidence_reproduction(self):
        image=Path(os.environ['STADIA_BRUCE_IMAGE']).read_bytes()
        expected=json.loads((ROOT/'evidence/usb-scheduler-registration-phase70.json').read_text())
        self.assertEqual(audit(image),expected)

    @unittest.skipUnless(os.environ.get('STADIA_BRUCE_IMAGE'),'Optional original fixture unavailable')
    def test_list_call_veneer_and_nesting_source_drift_rejected(self):
        image=Path(os.environ['STADIA_BRUCE_IMAGE']).read_bytes()
        sentinel=DATA_SOURCE_OFFSET+0x20003D68-DATA_DESTINATION
        for offset in (0x600CA05C-BASE,0x6013D18C-BASE,sentinel):
            changed=bytearray(image)
            changed[offset]^=1
            with self.subTest(offset=hex(offset)):
                with self.assertRaisesRegex(ValueError,'drift'):
                    verify_pins(changed)
                with self.assertRaisesRegex(ValueError,'SHA-pinned'):
                    audit(changed)
