import json
import os
from pathlib import Path
import struct
import unittest

from tools.audit_usb_provider_phase63 import (
    audit, verify_pins, BASE, OWNER, RECORDS, PROVIDER, PROVIDER_SLOT, TABLE,
)

ROOT = Path(__file__).resolve().parents[1]


class ProviderTests(unittest.TestCase):
    def test_rejects_wrong_image_before_execution(self):
        with self.assertRaisesRegex(ValueError, 'SHA-pinned'):
            audit(b'')

    def test_evidence_distinguishes_records_and_interfaces(self):
        report = json.loads((ROOT / 'evidence/usb-provider-phase63.json').read_text())
        chain = report['synthetic_chain']
        self.assertEqual(chain['class_count_byte'], 4)
        self.assertEqual(chain['metadata_words'][hex(PROVIDER)], hex(TABLE))
        self.assertEqual(chain['metadata_words'][hex(OWNER+4)], hex(RECORDS))
        self.assertEqual(chain['metadata_words'][hex(PROVIDER_SLOT)], hex(PROVIDER))
        self.assertEqual(chain['flag_final_bytes'], '0000')
        self.assertEqual(chain['internal_event'], 12)
        self.assertTrue(chain['original_indirect_selector_reached'])
        self.assertEqual((chain['descriptor_pointer'], chain['descriptor_bytes']), ('0x6011e45a', 80))
        self.assertTrue(any('synthetic zero' in s for s in chain['limits']))

    @unittest.skipUnless(os.environ.get('STADIA_BRUCE_IMAGE'), 'Optional pinned OEM fixture unavailable')
    def test_original_image_exact_reproduction(self):
        image = Path(os.environ['STADIA_BRUCE_IMAGE']).read_bytes()
        published = json.loads((ROOT / 'evidence/usb-provider-phase63.json').read_text())
        self.assertEqual(audit(image), published)

    @unittest.skipUnless(os.environ.get('STADIA_BRUCE_IMAGE'), 'Optional pinned OEM fixture unavailable')
    def test_pointer_store_and_event_table_drift_are_rejected(self):
        image = Path(os.environ['STADIA_BRUCE_IMAGE']).read_bytes()
        for address, replacement in (
            (0x60105B88, struct.pack('<I', 0x600619BF)),
            (0x6007409A, b'\x00\xbf'),
            (0x60060D6A+22, b'\x00\x00'),
        ):
            changed = bytearray(image)
            changed[address-BASE:address-BASE+len(replacement)] = replacement
            with self.subTest(address=hex(address)):
                with self.assertRaisesRegex(ValueError, 'drift'):
                    verify_pins(changed)
                with self.assertRaisesRegex(ValueError, 'SHA-pinned'):
                    audit(changed)
