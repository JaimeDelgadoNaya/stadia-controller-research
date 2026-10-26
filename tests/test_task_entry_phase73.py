import json
import os
from pathlib import Path
import unittest

from tools.audit_task_entry_phase73 import audit,verify_pins,basic_frame_plan
from tools.audit_usb_provider_phase63 import BASE

ROOT=Path(__file__).resolve().parents[1]


class TaskEntryTests(unittest.TestCase):
    def test_image_gate_before_execution(self):
        with self.assertRaisesRegex(ValueError,'SHA-pinned'):
            audit(b'')

    def test_frame_bridge_rejects_unsupported_profiles(self):
        words=[0x2002014C,0,0,0,0,0x600D5665,0x60101760,0x01000000]
        self.assertEqual(basic_frame_plan(0xFFFFFFFD,0x20020B28,words)['psp_after'],0x20020B48)
        for token,address,frame in ((0xFFFFFFED,0x20020B28,words),(0xFFFFFFFD,0x20020B2C,words),
                                    (0xFFFFFFFD,0x20020B28,words[:-1]),
                                    (0xFFFFFFFD,0x20020B28,words[:-1]+[0]),
                                    (0xFFFFFFFD,0x20020B28,words[:-1]+[0x01000200]),
                                    (0xFFFFFFFD,0x20020B28,words[:-1]+[0x01000001])):
            with self.subTest(token=hex(token),address=hex(address),frame=frame):
                with self.assertRaisesRegex(ValueError,'Unsupported'):
                    basic_frame_plan(token,address,frame)

    def test_recorded_entry_preserves_exception_and_queue_boundaries(self):
        r=json.loads((ROOT/'evidence/usb-task-entry-phase73.json').read_text())['task_entry_case']
        self.assertFalse(r['exception_return_model']['bx_lr_executed'])
        self.assertEqual(r['exception_return_model']['selected_psp'],'0x20020b48')
        self.assertEqual(r['original_worker_method'],'0x600ee143')
        self.assertEqual(r['observed_call_arguments']['r0_queue_control'],'0x200201ac')
        self.assertEqual(r['observed_call_arguments']['r2_wait_value'],'0xffffffff')
        self.assertTrue(r['task_entry_executed_in_virtual_model'])
        self.assertFalse(r['queue_call_executed'])
        self.assertFalse(r['work_item_callback_executed'])
        self.assertNotIn(r['stop_before_queue_call'],r['original_instruction_addresses'])

    @unittest.skipUnless(os.environ.get('STADIA_BRUCE_IMAGE'),'Optional original fixture unavailable')
    def test_original_image_exact_evidence_reproduction(self):
        image=Path(os.environ['STADIA_BRUCE_IMAGE']).read_bytes()
        expected=json.loads((ROOT/'evidence/usb-task-entry-phase73.json').read_text())
        self.assertEqual(audit(image),expected)

    @unittest.skipUnless(os.environ.get('STADIA_BRUCE_IMAGE'),'Optional original fixture unavailable')
    def test_indirect_method_and_first_queue_call_drift_rejected(self):
        image=Path(os.environ['STADIA_BRUCE_IMAGE']).read_bytes()
        for address in (0x6010176A,0x600EE14E,0x600EE152):
            changed=bytearray(image)
            changed[address-BASE]^=1
            with self.subTest(address=hex(address)):
                with self.assertRaisesRegex(ValueError,'drift'):
                    verify_pins(changed)
                with self.assertRaisesRegex(ValueError,'SHA-pinned'):
                    audit(changed)
