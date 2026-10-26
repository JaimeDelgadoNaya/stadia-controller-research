"""Phase48 signed EP0 control event1 to class10 fanout conditionality."""
import unittest
from tools import audit_bruce_ep0_class10_fanout_phase48 as a

class ClassFanout48Tests(unittest.TestCase):
    def test_ep0_has_two_original_event1_router_calls(self):
        self.assertEqual(a.EVENT1_EP0_SITES,[(0x60054E08,0x60054E1A),
                                             (0x60054E5A,0x60054E6A)])
        self.assertEqual(a.PINS[0x60054E1A],("bl","#0x6005505c"))
        self.assertEqual(a.PINS[0x60054E6A],("bl","#0x6005505c"))

    def test_signed_class_method_selector(self):
        self.assertEqual(a.PINS[0x600550A8],("cmp","r3, #0xa"))
        self.assertEqual(a.PINS[0x600550BA],("ldr","r3, [r3, #8]"))
        self.assertEqual(a.PINS[0x600550BC],("blx","r3"))
        self.assertEqual(a.PINS[0x600550B6],("mov","r1, r7"))

    def test_runtime_config_gate_is_mandatory(self):
        self.assertEqual(a.conditional_class10(1,[],runtime_config_known=False)["stage"],
                         "runtime_class_config_unmeasured")
        self.assertEqual(a.conditional_class10(1,[1,2,4],runtime_config_known=True)["stage"],
                         "class10_not_in_configuration")
        self.assertEqual(a.conditional_class10(1,[10],runtime_config_known=True)["class10_method8"],
                         "0x600d0e59")
        self.assertEqual(a.conditional_class10(2,[10],runtime_config_known=True)["stage"],
                         "not_event1")

    def test_drift_and_wrong_oem_file_rejected(self):
        self.assertEqual(a.verify_pins(dict(a.PINS)),len(a.PINS))
        mutated=dict(a.PINS)
        mutated[0x600550B6]=("mov","r1, r6")
        with self.assertRaisesRegex(ValueError,"drift"):
            a.verify_pins(mutated)
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            a.audit(b"synthetic")

if __name__=="__main__":
    unittest.main()
