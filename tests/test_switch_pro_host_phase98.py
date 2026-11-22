"""HID descriptor and discrete-host timing checks. No physical USB access."""
import hashlib
import unittest

from tools.audit_switch_pro_host_phase98 import (
    USBProfile, DescriptorError, DiscreteHostProbe, classify, report_lengths,
    run_gate_scenarios,
)
from tools.simulate_switch_pro_phase97 import (
    VirtualNS1Pro97, make_host_subcommand,
)

# Public NS1 Pro USB HID report descriptor represented in
# hifihedgehog/HIDMaestro/profiles/nintendo/switch-pro-usb.json
# source blob sha: 0b1646a3694a72fa135f17e89773a85ff98e131f
# USB functional metadata only: not a Stadia firmware dump or private MAC.
CAPTURED_NS1_HID_DESCRIPTOR=bytes.fromhex(
    '050115000904a1018530050105091901290a150025017501950a550065008102'
    '0509190b290e150025017501950481027501950281030b01000100a1000b30000100'
    '0b310001000b320001000b35000100150027ffff0000751095048102c00b39000100'
    '150025073500463b0165147504950181020509190f291215002501750195048102'
    '7508953481030600ff852109017508953f8103858109027508953f810385010903'
    '7508953f9183851009047508953f9183858009057508953f9183858209067508953f9183c0'
)


def renderer(data,*,tick=0):
    from tools.simulate_switch_pro_phase96 import translate_bruce
    return translate_bruce(data,tick=tick)


def fake_profile():
    return USBProfile('synthetic',0x057e,0x2009,3,0x81,0x01,True,True,
                      CAPTURED_NS1_HID_DESCRIPTOR)


class USBHostGatePhase98Tests(unittest.TestCase):
    def test_descriptor_hash_and_size_pinned(self):
        self.assertEqual(len(CAPTURED_NS1_HID_DESCRIPTOR),203)
        self.assertEqual(hashlib.sha256(CAPTURED_NS1_HID_DESCRIPTOR).hexdigest(),
                         '25f0b3b7e59bdfec05e8cced16e43a8878509865a0cb223f05025c556f3bedba')

    def test_report_descriptor_measured_ids_and_lengths(self):
        parsed=report_lengths(CAPTURED_NS1_HID_DESCRIPTOR)
        self.assertEqual(parsed['input'],{0x30:64,0x21:64,0x81:64})
        self.assertEqual(parsed['output'],{0x01:64,0x10:64,0x80:64,0x82:64})
        self.assertNotIn(0x3f,parsed['input'])

    def test_synthetic_profile_passes_structural_gate_only(self):
        r=classify(fake_profile())
        self.assertTrue(r['structural_gate_pass'])
        self.assertFalse(r['genuine_nintendo_descriptor_authenticated'])
        self.assertFalse(r['switch2_console_accepted'])

    def test_real_uploaded_stadia_bootloader_fails_ns1_identity(self):
        r=classify(USBProfile('Stadia original bootloader',0x18d1,0x946b,0xff,
                              0x87,0x07,False,False,None))
        self.assertFalse(r['structural_gate_pass'])
        self.assertTrue(any('VID:PID' in x for x in r['reasons']))
        self.assertTrue(any('HID report descriptor' in x for x in r['reasons']))

    def test_community_ram_flashloader_also_fails_identity(self):
        r=classify(USBProfile('NXP RAM flashloader',0x15a2,0x0073,3,
                              0x81,0x02,True,True,None))
        self.assertFalse(r['structural_gate_pass'])
        self.assertTrue(any('VID:PID' in x for x in r['reasons']))

    def test_generic_hid_wrong_report_descriptor_rejected(self):
        r=classify(USBProfile('wrong report ids',0x057e,0x2009,3,
                              0x81,0x01,True,True,b'\x85\x30\x75\x08\x95\x3f\x81\x03'))
        self.assertFalse(r['structural_gate_pass'])
        self.assertTrue(any('21' in x for x in r['reasons']))

    def test_missing_interrupt_out_endpoint_rejected(self):
        p=USBProfile('missing OUT',0x057e,0x2009,3,0x81,None,True,False,
                     CAPTURED_NS1_HID_DESCRIPTOR)
        self.assertFalse(classify(p)['structural_gate_pass'])

    def test_truncated_and_overly_large_descriptors_rejected(self):
        for raw in (b'',b'\x85',b'\x85\x00',b'\xfe\x03\x00\x11',b'\x75\x08'*3000):
            with self.subTest(raw=raw[:4].hex()):
                with self.assertRaises(DescriptorError):report_lengths(raw)

    def test_globally_nested_report_sizes(self):
        descriptor=bytes.fromhex('8501750895018103a4750195088103b48103')
        lengths=report_lengths(descriptor)
        self.assertEqual(lengths['input'][1],4)

    def test_init_usb_replies_are_padded_to_64_bytes(self):
        pad=VirtualNS1Pro97()
        r=pad.process(b'\x80\x01'+bytes(62))
        self.assertEqual(len(r),64)
        self.assertEqual(r[:4],bytes((0x81,1,0,3)))
        for cmd in (2,3):
            resp=pad.process(bytes([0x80,cmd])+bytes(62))
            self.assertEqual(len(resp),64)
            self.assertEqual(resp[:2],bytes([0x81,cmd]))
        self.assertIsNone(pad.process(b'\x80\x04'+bytes(62)))

    def test_nonzero_padding_must_be_rejected(self):
        from tools.simulate_switch_pro_phase97 import UnsupportedProtocol
        with self.assertRaises(UnsupportedProtocol):
            VirtualNS1Pro97().process(b'\x80\x01\x01'+bytes(61))

    def test_host_stays_silent_before_report_mode_in_current_model(self):
        d=DiscreteHostProbe(VirtualNS1Pro97(),renderer,
                            bytes((3,8,0,0,128,128,128,128,0,0,0)))
        for cmd in (1,2,3,4):
            d.send(bytes((0x80,cmd))+bytes(62))
        self.assertEqual(d.step(45),[])
        self.assertEqual(d.now_ms,45)

    def test_after_report_mode_15ms_clock_is_deterministic(self):
        d=DiscreteHostProbe(VirtualNS1Pro97(),renderer,
                            bytes((3,8,0,0,128,128,128,128,0,0,0)))
        for cmd in (1,2,3,4):
            d.send(bytes((0x80,cmd))+bytes(62))
        d.send(make_host_subcommand(3,b'\x30'))
        self.assertEqual(len(d.step(14)),0)
        self.assertEqual(len(d.step(1)),1)
        self.assertEqual(len(d.step(30)),2)
        self.assertEqual(d.now_ms,45)

    def test_integer_timing_validation_and_bounded_output(self):
        d=DiscreteHostProbe(VirtualNS1Pro97(),renderer,bytes((3,8,0,0,128,128,128,128,0,0,0)))
        for bad in (-1,10_001,1.1):
            with self.assertRaises(ValueError):d.step(bad)
        d.interval_ms=0
        with self.assertRaises(ValueError):d.step(1)

    def test_full_gate_scenarios_have_explicit_unverified_fields(self):
        r=run_gate_scenarios(CAPTURED_NS1_HID_DESCRIPTOR,renderer)
        self.assertTrue(r['structural_usb_gate']['synthetic_reference']['structural_gate_pass'])
        self.assertFalse(r['structural_usb_gate']['actual_stadia_bootloader']['structural_gate_pass'])
        self.assertFalse(r['structural_usb_gate']['actual_nxp_ram_flashloader']['structural_gate_pass'])
        self.assertEqual(r['init_0x81_reply_lengths'],[64,64,64,None])
        self.assertTrue(r['no_input_before_report_mode'])
        self.assertEqual(r['scheduled_frames_in_45ms'],3)
        for flag in ('usb_enumeration_hardware_verified','switch2_emulator_acceptance_verified',
                     'stadia_hab_closed_custom_boot_verified','real_usb_commands_sent'):
            self.assertFalse(r[flag])


if __name__=='__main__':unittest.main()
