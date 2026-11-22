"""Self-contained tests for fictional boot & power failure model. No hardware IO."""
import random
import unittest
from dataclasses import replace
from pathlib import Path
from tools.virtual_stadia_firmware_phase101 import (
    Bundle, VirtualStadia, VirtualBootError, VirtualPowerLoss,
    lab_keys, xusb_lab_payload, scenarios, manifest, NEUTRAL, PAYLOAD_MAGIC,
    MAX_BUNDLE_SIZE,
)
from tools.simulate_xinput_phase99 import parse_xusb_report

SOURCE = (Path(__file__).resolve().parents[1]/'firmware_codec'/'stadia_xusb_codec.c').read_bytes()
FACTORY = b'FAKE_FACTORY_BOOT'
TARGET = xusb_lab_payload(SOURCE)


def device(mode='OPEN'):
    key, root = lab_keys()
    d = VirtualStadia(mode, root)
    d.provision(Bundle.create('factory',1,FACTORY,key if mode=='CLOSED' else None))
    d.boot()
    return d,key


class VirtualStadiaPhase101(unittest.TestCase):
    def test_01_open_unsigned_install_and_run(self):
        d,_=device()
        r=d.install(Bundle.create('xusb',2,TARGET))
        self.assertEqual(r['outcome'],'installed_in_virtual_flash')
        self.assertEqual((d.active,d.confirmed),('B','B'))
        self.assertEqual(d.status,'running_xusb')

    def test_02_presses_xusb_a_after_virtual_boot(self):
        d,_=device();d.install(Bundle.create('xusb',2,TARGET))
        report=d.input(bytes((3,8,0,64,128,128,128,128,0,0,0)))
        self.assertEqual(len(report),20)
        self.assertIn('a',parse_xusb_report(report)['buttons'])

    def test_03_closed_rejects_unsigned_update(self):
        d,_=device('CLOSED')
        out=d.install(Bundle.create('xusb',2,TARGET))
        self.assertEqual(out['outcome'],'rejected_auth_or_integrity')
        self.assertEqual(d.active,'A')

    def test_04_closed_accepts_ephemeral_lab_key_only(self):
        d,key=device('CLOSED')
        out=d.install(Bundle.create('xusb',2,TARGET,key))
        self.assertEqual(out['outcome'],'installed_in_virtual_flash')
        self.assertEqual(d.status,'running_xusb')
        self.assertFalse(out['real_hab_authenticated'])

    def test_05_closed_rejects_other_signature(self):
        d,_=device('CLOSED');key,_=lab_keys()
        self.assertEqual(d.install(Bundle.create('xusb',2,TARGET,key))['outcome'],
                         'rejected_auth_or_integrity')

    def test_06_closed_rejects_tampered_payload(self):
        d,key=device('CLOSED')
        valid=Bundle.create('xusb',2,TARGET,key)
        bad=replace(valid,payload=valid.payload+b'x')
        self.assertEqual(d.install(bad)['outcome'],'rejected_auth_or_integrity')

    def test_07_closed_rejects_tampered_manifest(self):
        d,key=device('CLOSED')
        valid=Bundle.create('xusb',2,TARGET,key)
        self.assertEqual(d.install(replace(valid,meta=b'{}'))['outcome'],
                         'rejected_auth_or_integrity')

    def test_08_closed_rejects_tampered_signature(self):
        d,key=device('CLOSED')
        valid=Bundle.create('xusb',2,TARGET,key)
        broken=replace(valid,signature=bytes(len(valid.signature)))
        self.assertEqual(d.install(broken)['outcome'],'rejected_auth_or_integrity')

    def test_09_open_mode_still_checks_manifest_integrity(self):
        d,_=device()
        valid=Bundle.create('xusb',2,TARGET)
        self.assertEqual(d.install(replace(valid,meta=b'NOPE'))['outcome'],
                         'rejected_auth_or_integrity')

    def test_10_open_rejects_wrong_payload_kind_health(self):
        d,_=device()
        out=d.install(Bundle.create('xusb',2,b'incorrect marker'))
        self.assertEqual(out['outcome'],'rolled_back')
        self.assertEqual(d.status,'running_factory')

    def test_11_health_check_forced_failure_rolls_back(self):
        d,_=device()
        r=d.install(Bundle.create('xusb',2,TARGET),bad_health=True)
        self.assertEqual(r['outcome'],'rolled_back')
        self.assertEqual(d.active,d.confirmed)

    def test_12_powerloss_during_write_preserves_previous(self):
        d,_=device()
        with self.assertRaises(VirtualPowerLoss):
            d.install(Bundle.create('xusb',2,TARGET),power_fail='write')
        self.assertEqual(d.power_on(),'running_factory')
        self.assertEqual(d.active,'A')

    def test_13_powerloss_before_commit_preserves_previous(self):
        d,_=device()
        with self.assertRaises(VirtualPowerLoss):
            d.install(Bundle.create('xusb',2,TARGET),power_fail='precommit')
        self.assertEqual(d.power_on(),'running_factory')
        self.assertEqual(d.active,'A')

    def test_14_powerloss_after_commit_rolls_back(self):
        d,_=device()
        with self.assertRaises(VirtualPowerLoss):
            d.install(Bundle.create('xusb',2,TARGET),power_fail='postcommit')
        self.assertEqual(d.pending,'B')
        self.assertEqual(d.power_on(),'running_factory')
        self.assertEqual(d.active,'A')
        self.assertIsNone(d.pending)

    def test_15_powerloss_before_confirm_rolls_back(self):
        d,_=device()
        with self.assertRaises(VirtualPowerLoss):
            d.install(Bundle.create('xusb',2,TARGET),power_fail='preconfirm')
        self.assertEqual(d.power_on(),'running_factory')
        self.assertIsNone(d.pending)

    def test_16_cannot_stage_on_unconfirmed_bank(self):
        d,_=device()
        with self.assertRaises(VirtualPowerLoss):
            d.install(Bundle.create('xusb',2,TARGET),power_fail='postcommit')
        with self.assertRaises(VirtualBootError):
            d.install(Bundle.create('xusb',3,TARGET))

    def test_17_bad_active_image_recovers_to_confirmed(self):
        d,_=device()
        with self.assertRaises(VirtualPowerLoss):
            d.install(Bundle.create('xusb',2,TARGET),power_fail='postcommit')
        b=d.banks['B'].image
        d.banks['B'].image=replace(b,payload=b.payload+b'corruption')
        self.assertEqual(d.boot(),'running_factory')
        self.assertIn('auth_rejected_B',d.history)

    def test_18_corrupt_only_confirmed_image_fails_safely(self):
        d,_=device()
        b=d.banks['A'].image
        d.banks['A'].image=replace(b,payload=b.payload+b'corruption')
        with self.assertRaises(VirtualBootError):d.boot()
        self.assertEqual(d.status,'recovery_required')

    def test_19_min_version_rollback_policy(self):
        d,key=device('CLOSED');d.min_version=3
        self.assertEqual(d.install(Bundle.create('xusb',2,TARGET,key))['outcome'],
                         'rejected_auth_or_integrity')

    def test_20_versioned_second_upgrade_alternates_banks(self):
        d,_=device()
        d.install(Bundle.create('xusb',2,TARGET))
        out=d.install(Bundle.create('xusb',3,TARGET))
        self.assertEqual(out['outcome'],'installed_in_virtual_flash')
        self.assertEqual(d.active,'A')
        self.assertEqual(d.banks['A'].image.version,3)

    def test_21_no_fake_real_hardware_claims(self):
        d,_=device();r=d.install(Bundle.create('xusb',2,TARGET))
        for key in ('real_firmware_installed','real_hab_authenticated','device_contacted',
                    'real_usb_enumerated'):
            self.assertFalse(r[key],key)

    def test_22_rejects_oversize_and_invalid_bundle_data(self):
        for payload in (b'',b'a'*(MAX_BUNDLE_SIZE+1)):
            with self.assertRaises(ValueError):Bundle.create('xusb',2,payload)
        for kind in ('invalid','raw_nxp_ivt'):
            with self.assertRaises(ValueError):manifest(kind,2,TARGET)

    def test_23_only_factory_can_be_provisioned(self):
        key,root=lab_keys();d=VirtualStadia('OPEN',root)
        with self.assertRaises(VirtualBootError):
            d.provision(Bundle.create('xusb',2,TARGET))

    def test_24_factory_cannot_be_reprovisioned(self):
        d,_=device()
        with self.assertRaises(VirtualBootError):d.provision(Bundle.create('factory',1,FACTORY))

    def test_25_invalid_lab_state_rejected(self):
        _,root=lab_keys()
        with self.assertRaises(ValueError):VirtualStadia('UNKNOWN',root)

    def test_26_invalid_fault_point_rejected(self):
        d,_=device()
        with self.assertRaises(ValueError):d.install(Bundle.create('xusb',2,TARGET),power_fail='fuse')

    def test_27_no_xusb_app_before_install(self):
        d,_=device()
        with self.assertRaises(VirtualBootError):d.input(NEUTRAL)

    def test_28_ephemeral_lab_keys_differ(self):
        _,a=lab_keys();_,b=lab_keys()
        from cryptography.hazmat.primitives import serialization
        r=lambda k:k.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.assertNotEqual(r(a),r(b))

    def test_29_model_checks_500_random_fault_scenarios(self):
        rnd=random.Random(101)
        for i in range(500):
            mode=rnd.choice(('OPEN','CLOSED'))
            d,key=device(mode)
            kind=rnd.choice(('xusb','xusb','xusb'))
            version=rnd.randint(1,6)
            sign=rnd.choice(('good','missing','wrong'))
            wrong,_=lab_keys()
            signing_key=(key if sign=='good' else wrong if sign=='wrong' else None)
            package=Bundle.create(kind,version,TARGET,signing_key)
            fault=rnd.choice((None,'write','precommit','postcommit','preconfirm'))
            try:r=d.install(package,power_fail=fault)
            except VirtualPowerLoss:
                d.power_on()
            else:
                self.assertIn(r['outcome'],('rejected_auth_or_integrity','installed_in_virtual_flash'))
            self.assertIsNone(d.pending)
            self.assertEqual(d.active,d.confirmed)
            self.assertTrue(d.banks[d.active].image.valid_structure())
            self.assertTrue(d.verify(d.banks[d.active].image))
            self.assertIn(d.status,('running_xusb','running_factory'))

    def test_30_full_demo_uses_lab_only(self):
        r=scenarios(SOURCE)
        self.assertEqual(r['open_unsigned']['outcome'],'installed_in_virtual_flash')
        self.assertEqual(r['closed_lab_signed']['outcome'],'installed_in_virtual_flash')
        self.assertEqual(r['closed_unsigned']['outcome'],'rejected_auth_or_integrity')
        self.assertFalse(r['limits']['arm_code_executed'])
        self.assertFalse(r['limits']['actual_stadia_bootable'])
        self.assertEqual(len(bytes.fromhex(r['xusb_button_a_packet'])),20)

if __name__=='__main__':unittest.main()
