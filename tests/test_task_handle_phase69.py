import json
import os
from pathlib import Path
import unittest

from tools.audit_task_handle_phase69 import audit,verify_pins
from tools.audit_usb_provider_phase63 import BASE

ROOT=Path(__file__).resolve().parents[1]


class TaskHandleTests(unittest.TestCase):
    def test_hash_gate_before_execution(self):
        with self.assertRaisesRegex(ValueError,'SHA-pinned'):
            audit(b'')

    def test_original_handle_and_frame_without_task_execution(self):
        r=json.loads((ROOT/'evidence/usb-task-handle-phase69.json').read_text())
        worker=r['original_creation_and_handle']
        c=worker['original_creator']
        self.assertEqual(worker['handle_field_after'],'0x20020278')
        self.assertEqual(c['handle'],'0x20020278')
        self.assertEqual(c['frame_pointer'],'0x20020b04')
        self.assertEqual(c['prepared_pc'],'0x60101760')
        self.assertEqual(c['prepared_r0'],'0x2002014c')
        self.assertEqual(c['priority_word'],1)
        self.assertFalse(c['opaque_return_injected'])
        self.assertFalse(c['task_entry_executed'])
        self.assertTrue(c['registration_stubbed'])
        self.assertFalse(any(m['target']=='0x600ca1f8' for m in worker['models']))
        self.assertEqual(r['post_return_class10_chain']['snapshot']['record_instance'],'0x200040e0')

    @unittest.skipUnless(os.environ.get('STADIA_BRUCE_IMAGE'),'Optional original fixture unavailable')
    def test_original_image_exact_reproduction(self):
        image=Path(os.environ['STADIA_BRUCE_IMAGE']).read_bytes()
        expected=json.loads((ROOT/'evidence/usb-task-handle-phase69.json').read_text())
        self.assertEqual(audit(image),expected)

    @unittest.skipUnless(os.environ.get('STADIA_BRUCE_IMAGE'),'Optional original fixture unavailable')
    def test_handle_store_frame_pc_and_return_source_drift_rejected(self):
        image=Path(os.environ['STADIA_BRUCE_IMAGE']).read_bytes()
        for address in (0x600CA1A0,0x600CC566,0x600CA264):
            changed=bytearray(image)
            changed[address-BASE]^=1
            with self.subTest(address=hex(address)):
                with self.assertRaisesRegex(ValueError,'drift'):
                    verify_pins(changed)
                with self.assertRaisesRegex(ValueError,'SHA-pinned'):
                    audit(changed)
