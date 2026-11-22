"""Synthetic USB descriptor verification: no physical/controller operations."""
import unittest
from tools.audit_usb_descriptors_phase92 import parse_device,parse_configuration,audit_candidate

DEVICE=bytes.fromhex('12 01 00 02 ef 02 01 40 d1 18 6b 94 01 00 01 02 04 03')
# One vendor interface, then one CDC ACM + one CDC data interface.
CFG=bytes.fromhex('09 02 55 00 03 01 00 80 fa '
 '09 04 00 00 02 ff 00 00 00 07 05 87 02 00 02 00 07 05 07 02 00 02 00 '
 '09 04 01 00 01 02 02 00 00 05 24 00 10 01 04 24 02 06 05 24 06 01 02 '
 '07 05 82 03 08 00 07 '
 '09 04 02 00 02 0a 00 00 00 07 05 81 02 00 02 00 07 05 01 02 00 02 00')

class StaticUsbTest(unittest.TestCase):
    def test_exact_fixture_total(self):
        self.assertEqual(len(CFG),85)
    def test_device_identity(self):
        d=parse_device(DEVICE,0)
        self.assertEqual((d['vid'],d['pid']),('18d1','946b'))
        self.assertEqual((d['device_class'],d['device_subclass'],d['device_protocol']),(239,2,1))
        self.assertEqual(d['iSerialNumber'],4)
    def test_configuration_topology(self):
        c=parse_configuration(CFG,0)
        self.assertEqual(c['descriptor_count'],12)
        self.assertEqual(c['interface_count_parsed'],3)
        self.assertEqual(len(c['endpoints']),5)
        self.assertEqual(c['cdc_unions'],[{'master':1,'slaves':[2]}])
        self.assertEqual(c['iad_count'],0)
        self.assertEqual(c['errors'],[])
    def test_endpoint_consistency(self):
        c=parse_configuration(CFG,0)
        self.assertEqual([x['endpoint'] for x in c['endpoints']],['0x87','0x07','0x82','0x81','0x01'])
        self.assertEqual(c['endpoints'][0]['max_packet_size'],512)
        self.assertEqual(c['endpoints'][2]['transfer'],3)
    def test_claim_boundaries(self):
        r=audit_candidate(DEVICE+CFG,0,len(DEVICE))
        self.assertTrue(r['iad_class_triple_without_iad'])
        self.assertFalse(r['host_enumeration_verified'])
        self.assertFalse(r['firmware_signature_verified'])
    def test_bad_total_length(self):
        with self.assertRaisesRegex(ValueError,'wTotalLength'):
            parse_configuration(CFG[:2]+b'\xff\x7f'+CFG[4:],0)
    def test_zero_length_record(self):
        buf=bytearray(CFG)
        buf[9]=0
        with self.assertRaisesRegex(ValueError,'bLength'):
            parse_configuration(bytes(buf),0)
    def test_truncated_input(self):
        with self.assertRaisesRegex(ValueError,'truncated'):
            parse_configuration(CFG[:-1],0)
    def test_interface_count_mismatch(self):
        b=bytearray(CFG);b[4]=4
        self.assertIn('interface_count_mismatch',parse_configuration(bytes(b),0)['errors'])
    def test_cdc_union_reference_mismatch(self):
        b=bytearray(CFG); i=b.index(bytes.fromhex('05 24 06 01 02'));b[i+4]=5
        self.assertIn('cdc_union_references_unknown_interface',parse_configuration(bytes(b),0)['errors'])
    def test_iad_present_variant(self):
        b=bytearray(CFG)
        i=b.index(bytes.fromhex('09 04 01 00'))
        b[i:i]=bytes.fromhex('08 0b 01 02 02 02 01 00')
        b[2:4]=len(b).to_bytes(2,'little')
        c=parse_configuration(bytes(b),0)
        self.assertEqual(c['iad_count'],1)
        self.assertEqual(c['errors'],[])
    def test_device_offset_rejected(self):
        with self.assertRaisesRegex(ValueError,'out of range'):
            parse_device(DEVICE,1)

if __name__=='__main__':
    unittest.main()
