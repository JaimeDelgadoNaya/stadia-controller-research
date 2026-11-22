"""Compare archived measured phase61 hub bytes to phase92 synthetic descriptor fixture."""
import json
import unittest
from pathlib import Path
from tools.audit_usb_descriptors_phase92 import parse_device, parse_configuration
from tests.test_usb_descriptors_phase92 import DEVICE, CFG

EVIDENCE = Path(__file__).resolve().parents[1] / 'evidence' / 'usb-enumeration-phase61.json'


class OfflineBaselineComparison(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        record=json.loads(EVIDENCE.read_text(encoding='utf-8'))
        cls.oem_dev=parse_device(bytes.fromhex(record['hub']['device']),0)
        cls.oem_cfg=parse_configuration(bytes.fromhex(record['hub']['configuration']),0)
        cls.candidate_dev=parse_device(DEVICE,0)
        cls.candidate_cfg=parse_configuration(CFG,0)

    def test_physically_recorded_oem_is_not_candidate(self):
        self.assertEqual((self.oem_dev['vid'],self.oem_dev['pid']),('18d1','9400'))
        self.assertEqual((self.candidate_dev['vid'],self.candidate_dev['pid']),('18d1','946b'))
        self.assertNotEqual(self.oem_dev['pid'],self.candidate_dev['pid'])

    def test_iad_difference_is_positive_observation_of_bytes(self):
        self.assertEqual(self.oem_cfg['iad_count'],2)
        self.assertEqual(self.candidate_cfg['iad_count'],0)
        self.assertEqual((self.oem_cfg['total_length'],self.candidate_cfg['total_length']),(80,85))

    def test_oem_hid_vs_candidate_cdc(self):
        self.assertEqual([i['class_code'] for i in self.oem_cfg['interfaces']],[255,3])
        self.assertEqual([i['class_code'] for i in self.candidate_cfg['interfaces']],[255,2,10])
        self.assertEqual(self.oem_cfg['errors'],[])
        self.assertEqual(self.candidate_cfg['errors'],[])

    def test_endpoint_overlap_not_handler_proof(self):
        actual={e['endpoint'] for e in self.oem_cfg['endpoints']}
        proposed={e['endpoint'] for e in self.candidate_cfg['endpoints']}
        self.assertEqual(actual & proposed, {'0x07','0x87'})
        self.assertNotEqual(actual,proposed)

    def test_configuration_and_string_indexes_are_not_real_serials(self):
        self.assertEqual((self.oem_dev['bNumConfigurations'],self.candidate_dev['bNumConfigurations']),(1,3))
        self.assertEqual((self.oem_dev['iSerialNumber'],self.candidate_dev['iSerialNumber']),(3,4))

if __name__=='__main__':
    unittest.main()
