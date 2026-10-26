"""Phase74 signed receiver instruction pins and bounded virtual guard execution."""
import json
import os
from pathlib import Path
import unittest

from tools.execute_queue_guards_phase74 import audit,verify_original,execute_guards,PINS,classify_unexecuted_queue_branch

ROOT=Path(__file__).resolve().parents[1]

class QueueReceiveGuardsTests(unittest.TestCase):
    def test_sha_required(self):
        with self.assertRaisesRegex(ValueError,'SHA-pinned'):
            audit(b'wrong')

    def test_key_original_edges_pinned(self):
        self.assertEqual(PINS[0x6D38],('cbnz','r0, #0x6d46'))
        self.assertEqual(PINS[0x6D46],('cbnz','r7, #0x6d58'))
        self.assertEqual(PINS[0x6D7C],('cbz','r5, #0x6db4'))
        self.assertEqual(len(PINS),12)

    def test_projected_empty_queue_wait_is_not_execution(self):
        fake={'control_words':['0x0']*16,
              'queue_receive_r2_timeout':'0xffffffff'}
        result=classify_unexecuted_queue_branch(fake)
        self.assertEqual(result['unexecuted_branch_expectation'],
                         'EXPECTED_EMPTY_QUEUE_THEN_WAIT_IF_STATE_UNCHANGED')
        self.assertFalse(result['critical_sections_and_scheduler_executed'])
        self.assertFalse(result['queue_delivery_or_callback_observed'])

    def test_nonblocking_empty_queue_prediction(self):
        fake={'control_words':['0x0']*16,
              'queue_receive_r2_timeout':'0x0'}
        self.assertEqual(classify_unexecuted_queue_branch(fake)
                         ['unexecuted_branch_expectation'],
                         'EXPECTED_EMPTY_QUEUE_NO_WAIT_IF_STATE_UNCHANGED')

    @unittest.skipUnless(os.environ.get('STADIA_BRUCE_IMAGE'),
                         'Original signed image optional fixture unavailable')
    def test_original_image_regression(self):
        image=Path(os.environ['STADIA_BRUCE_IMAGE']).read_bytes()
        self.assertEqual(verify_original(image),13)
        result=audit(image)
        case=result['original_receive_guard_execution']
        self.assertEqual(case['stop_before_helper'],'0x6d58')
        self.assertEqual(case['input_queue_control'],'0x200201ac')
        self.assertEqual(case['input_wait'],'0xffffffff')
        self.assertEqual(case['saved_queue_control_R4'],case['input_queue_control'])
        self.assertEqual(case['saved_output_buffer_R7'],case['input_output_buffer'])
        self.assertTrue(case['original_guard_path_executed'])
        self.assertFalse(case['queue_dequeue_executed'])
        self.assertFalse(case['work_item_callback_executed'])

    @unittest.skipUnless(os.environ.get('STADIA_BRUCE_IMAGE') and
                         (ROOT/'evidence/usb-queue-receive-phase74.json').exists(),
                         'Published phase74 evidence not yet recorded')
    def test_published_evidence_reproducible(self):
        image=Path(os.environ['STADIA_BRUCE_IMAGE']).read_bytes()
        expected=json.loads((ROOT/'evidence/usb-queue-receive-phase74.json').read_text())
        self.assertEqual(audit(image),expected)

if __name__=='__main__':
    unittest.main()
