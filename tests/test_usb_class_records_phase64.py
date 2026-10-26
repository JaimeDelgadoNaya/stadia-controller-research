import json
import os
from pathlib import Path
import unittest

from tools.audit_usb_class_records_phase64 import (
    audit, verify_sources, initialized_offset, DATA_DESTINATION, DATA_END, BASE,
)

ROOT = Path(__file__).resolve().parents[1]


class OriginalRecordTests(unittest.TestCase):
    def test_hash_gate_precedes_emulation(self):
        with self.assertRaisesRegex(ValueError,'SHA-pinned'):
            audit(b'')

    def test_startup_mapping_rejects_outside_and_overrun(self):
        for address, size in ((DATA_DESTINATION-1,1),(DATA_END,1),(DATA_END-4,8),(DATA_DESTINATION,0)):
            with self.subTest(address=address,size=size):
                with self.assertRaises(ValueError):
                    initialized_offset(address,size)

    def test_published_original_records_and_class10_argument(self):
        r = json.loads((ROOT/'evidence/usb-class-records-phase64.json').read_text())
        flow = r['original_flow']
        self.assertEqual([v['selector'] for v in flow['copied_records']],[10,1,2,4])
        self.assertTrue(all(v['exact_signed_source_bytes'] for v in flow['copied_records']))
        self.assertEqual(flow['owner_config']['count'],4)
        self.assertEqual(flow['copied_records'][0]['callback'],'0x600613fd')
        self.assertEqual(flow['selector_matches'][0]['method_thumb'],'0x60055321')
        self.assertEqual(flow['selector_matches'][0]['argument_r1'],'0x2000a274')
        self.assertTrue(all(v['pc']=='0x60073e00' for v in flow['original_record_stores']))
        self.assertFalse(flow['class_methods_executed'])
        self.assertEqual(r['conclusions']['physical_class10_active'],'UNMEASURED')

    @unittest.skipUnless(os.environ.get('STADIA_BRUCE_IMAGE'),'Optional original OEM fixture unavailable')
    def test_original_image_exact_evidence_reproduction(self):
        image = Path(os.environ['STADIA_BRUCE_IMAGE']).read_bytes()
        expected = json.loads((ROOT/'evidence/usb-class-records-phase64.json').read_text())
        self.assertEqual(audit(image),expected)

    @unittest.skipUnless(os.environ.get('STADIA_BRUCE_IMAGE'),'Optional original OEM fixture unavailable')
    def test_changed_producer_record_or_descriptor_rejected(self):
        image = Path(os.environ['STADIA_BRUCE_IMAGE']).read_bytes()
        for offset in (0x600613F8-BASE,0xFDF5C,initialized_offset(0x20003104)):
            changed = bytearray(image)
            changed[offset] ^= 1
            with self.subTest(offset=hex(offset)):
                with self.assertRaisesRegex(ValueError,'drift'):
                    verify_sources(changed)
                with self.assertRaisesRegex(ValueError,'SHA-pinned'):
                    audit(changed)
