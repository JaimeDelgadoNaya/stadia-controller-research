import json
import os
from pathlib import Path
import unittest

from tools.audit_workqueue_constructor_phase68 import audit,verify_pins,BASE,SLOT,QUEUE,CONTROL,STACK

ROOT=Path(__file__).resolve().parents[1]


class QueueConstructorTests(unittest.TestCase):
    def test_hash_gate_before_execution(self):
        with self.assertRaisesRegex(ValueError,'SHA-pinned'):
            audit(b'')

    def test_original_fields_and_signed_table_link(self):
        r=json.loads((ROOT/'evidence/usb-workqueue-constructor-phase68.json').read_text())
        self.assertEqual(r['signed_initializer_link']['index'],43)
        self.assertEqual(r['signed_initializer_link']['entries'],45)
        expected=dict(handle='0x0',control=hex(CONTROL),control_stack_pointer=hex(STACK),control_words=512)
        self.assertEqual([c['fields'] for c in r['constructor_cases']],[expected,expected])
        self.assertEqual([c['old_fields_poisoned'] for c in r['constructor_cases']],[False,True])
        self.assertTrue(any(w['pc']=='0x6009271e' and w['address']==hex(QUEUE+0x5C)
                            for w in r['constructor_cases'][0]['original_writes']))
        worker=r['pending_call_using_original_fields']
        self.assertTrue(worker['queue_fields_preserved_from_input'])
        self.assertEqual(worker['inputs']['control_words'],512)
        self.assertEqual(worker['initial_control_pointer'],hex(CONTROL))
        self.assertTrue(worker['creation_primitive_reached'])
        self.assertEqual(r['post_return_driver_class10_chain']['snapshot']['record_instance'],'0x200040e0')

    @unittest.skipUnless(os.environ.get('STADIA_BRUCE_IMAGE'),'Optional pinned OEM fixture unavailable')
    def test_original_image_exact_reproduction(self):
        image=Path(os.environ['STADIA_BRUCE_IMAGE']).read_bytes()
        expected=json.loads((ROOT/'evidence/usb-workqueue-constructor-phase68.json').read_text())
        self.assertEqual(audit(image),expected)

    @unittest.skipUnless(os.environ.get('STADIA_BRUCE_IMAGE'),'Optional pinned OEM fixture unavailable')
    def test_table_pointer_auxiliary_store_and_size_drift_rejected(self):
        image=Path(os.environ['STADIA_BRUCE_IMAGE']).read_bytes()
        for offset in (SLOT,0x6009271E-BASE,0x60092710-BASE):
            changed=bytearray(image)
            changed[offset]^=1
            with self.subTest(offset=hex(offset)):
                with self.assertRaisesRegex(ValueError,'drift'):
                    verify_pins(changed)
                with self.assertRaisesRegex(ValueError,'SHA-pinned'):
                    audit(changed)
