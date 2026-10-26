import json
import os
from pathlib import Path
import unittest

from tools.audit_usb_descriptor_match_phase62 import (
    audit, occurrences, conditional_variant, verify_selector, ENTRY, BASE,
)
from tools.parse_usb_configuration import parse_configuration

ROOT = Path(__file__).resolve().parents[1]


class DescriptorMatchTests(unittest.TestCase):
    def test_hash_gate_rejects_untrusted_input_before_parsing(self):
        with self.assertRaisesRegex(ValueError, 'SHA-pinned'):
            audit(b'', {})

    def test_exact_search_includes_overlaps_and_rejects_empty(self):
        self.assertEqual(occurrences(b'aaaa', b'aa'), [0, 1, 2])
        self.assertEqual(occurrences(b'abcd', b'ac'), [])
        with self.assertRaises(ValueError):
            occurrences(b'abc', b'')

    def test_published_descriptor_evidence_and_branch_outcomes(self):
        evidence = json.loads((ROOT / 'evidence/usb-descriptor-oem-match-phase62.json').read_text())
        self.assertEqual(evidence['exact_full_descriptor_matches'], ['0xde45a'])
        self.assertEqual(evidence['exact_winusb_view_matches'], [])
        self.assertEqual([v['length'] for v in evidence['variants']], [80, 40, 204, 287])
        self.assertEqual([v['exact_live_hub_match'] for v in evidence['variants']], [True, False, False, False])
        self.assertEqual(len(evidence['emulation']), 8)
        seen = set()
        for row in evidence['emulation']:
            h, a, b = (row[k] for k in ('synthetic_helper_result', 'synthetic_flag_a', 'synthetic_flag_b'))
            seen.add((h, a, b))
            offset, length = conditional_variant(h, a, b)
            self.assertEqual((int(row['output_pointer'], 16), row['output_length']), (BASE+offset, length))
        self.assertEqual(len(seen), 8)

    @unittest.skipUnless(os.environ.get('STADIA_BRUCE_IMAGE'), 'Optional SHA-pinned OEM fixture unavailable')
    def test_original_image_match_all_eight_virtual_branches_and_pin_mutation(self):
        image = Path(os.environ['STADIA_BRUCE_IMAGE']).read_bytes()
        live = json.loads((ROOT / 'evidence/usb-enumeration-phase61.json').read_text())
        result = audit(image, live, emulate=True)
        self.assertEqual(result['exact_full_descriptor_matches'], ['0xde45a'])
        self.assertEqual(len(result['emulation']), 8)
        changed = bytearray(image)
        changed[ENTRY-BASE:ENTRY-BASE+2] = b'\x00\xbf'  # NOP replaces PUSH.
        with self.assertRaisesRegex(ValueError, 'semantic drift'):
            verify_selector(changed)
        with self.assertRaisesRegex(ValueError, 'SHA-pinned'):
            audit(changed, live)


if __name__ == '__main__':
    unittest.main()
