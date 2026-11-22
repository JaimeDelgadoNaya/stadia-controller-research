"""Fictional dual-bank Stadia lab; NOT a RT1061/ROM/HAB emulator or flash image.

Ed25519 here uses disposable LAB trust roots, not NXP's HAB CSF/signatures.
A *virtual installation* stores a manifest/codec fingerprint, not ARM code.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from hashlib import sha256
import json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from tools.simulate_xinput_phase99 import parse_bruce_hid, xusb_report, parse_xusb_report

PAYLOAD_MAGIC = b'FICTIVE_STADIA_XUSB_CODEC_V1\x00'
MAX_BUNDLE_SIZE = 128 * 1024
NEUTRAL = bytes((3,8,0,0,128,128,128,128,0,0,0))

class VirtualBootError(RuntimeError): pass
class VirtualPowerLoss(RuntimeError): pass

def manifest(kind, version, payload):
    if kind not in ('factory','xusb') or type(version) is not int or not 1<=version<=65535:
        raise ValueError('Invalid virtual image kind/version')
    if type(payload) is not bytes or not 1<=len(payload)<=MAX_BUNDLE_SIZE:
        raise ValueError('Invalid virtual image length')
    return json.dumps({'format':'fictional-v1-NOT-REAL','kind':kind,'version':version,
        'length':len(payload),'sha256':sha256(payload).hexdigest()},
        sort_keys=True,separators=(',',':')).encode()

@dataclass(frozen=True)
class Bundle:
    kind: str
    version: int
    payload: bytes
    meta: bytes
    signature: bytes | None

    @classmethod
    def create(cls,kind,version,payload,key=None):
        data=manifest(kind,version,payload)
        return cls(kind,version,payload,data,key.sign(data+b'\x00'+payload) if key else None)

    def valid_structure(self):
        try: return self.meta==manifest(self.kind,self.version,self.payload)
        except (ValueError,TypeError): return False

@dataclass
class Bank:
    image: Bundle | None = None
    staged: bytearray = field(default_factory=bytearray)
    state: str = 'empty'

@dataclass
class VirtualStadia:
    mode: str
    lab_root: Ed25519PublicKey
    banks: dict = field(default_factory=lambda:{'A':Bank(),'B':Bank()})
    active: str = 'A'
    confirmed: str = 'A'
    pending: str | None = None
    status: str = 'off'
    min_version: int = 1  # fictional in-memory policy; NOT an eFuse
    history: list[str] = field(default_factory=list)
    reports: list[bytes] = field(default_factory=list)

    def __post_init__(self):
        if self.mode not in ('OPEN','CLOSED'):raise ValueError('Invalid lab security mode')

    def verify(self,image):
        if not isinstance(image,Bundle) or not image.valid_structure() or image.version<self.min_version:
            return False
        if self.mode=='OPEN': return True
        if image.signature is None: return False
        try:self.lab_root.verify(image.signature,image.meta+b'\x00'+image.payload)
        except (InvalidSignature,ValueError,TypeError):return False
        return True

    def provision(self,image):
        if any(b.image is not None for b in self.banks.values()):raise VirtualBootError('Provision once')
        if image.kind!='factory' or not self.verify(image):raise VirtualBootError('Invalid factory')
        self.banks['A']=Bank(image,bytearray(),'good')
        self.active=self.confirmed='A';self.status='factory_ready'
        self.history.append('factory_A')

    def boot(self):
        image=self.banks[self.active].image
        if image is None or not self.verify(image):
            self.history.append('auth_rejected_'+self.active)
            if self.pending is not None and self.active!=self.confirmed:
                self.active,self.pending=self.confirmed,None
                self.history.append('rollback_'+self.confirmed)
                return self.boot()
            self.status='recovery_required'
            raise VirtualBootError('No authenticated boot target')
        self.status='running_'+image.kind
        self.history.append('boot_'+self.active+'_'+image.kind)
        return self.status

    def health(self):
        image=self.banks[self.active].image
        if image is None or not self.verify(image):return False
        if image.kind=='factory':return True
        if image.kind!='xusb' or not image.payload.startswith(PAYLOAD_MAGIC):return False
        # Simulate app logic with Phase99 Python codec: do NOT execute stored bytes.
        report=xusb_report(parse_bruce_hid(NEUTRAL))
        state=parse_xusb_report(report)
        self.reports.append(report)
        return len(report)==20 and state['buttons']==() and state['lt']==0

    def input(self,packet):
        if self.status!='running_xusb' or not self.health():
            raise VirtualBootError('Virtual XUSB app is not running')
        report=xusb_report(parse_bruce_hid(packet))
        self.reports.append(report)
        return report

    def rollback(self):
        self.active,self.pending=self.confirmed,None
        self.history.append('rollback_'+self.confirmed)
        return self.boot()

    def power_on(self):
        if self.pending is not None:
            self.history.append('unconfirmed_update_reverted')
            return self.rollback()
        return self.boot()

    def result(self,outcome,slot):
        return {'outcome':outcome,'mode':self.mode,'target':slot,'active':self.active,
                'confirmed':self.confirmed,'running':self.status,
                'virtual_xusb_running':self.status=='running_xusb',
                'real_firmware_installed':False,'real_hab_authenticated':False,
                'device_contacted':False,'real_usb_enumerated':False}

    def install(self,image,*,power_fail=None,bad_health=False):
        if power_fail not in (None,'write','precommit','postcommit','preconfirm'):
            raise ValueError('Unsupported simulated power failure')
        if self.pending is not None or self.active!=self.confirmed:
            raise VirtualBootError('Another update is pending')
        if self.banks[self.confirmed].image is None:
            raise VirtualBootError('No previous good bank')
        target='B' if self.confirmed=='A' else 'A'
        bank=self.banks[target]
        bank.image=None;bank.staged.clear();bank.state='writing'
        self.history.append('stage_'+target)
        for start in range(0,len(image.payload),32):
            bank.staged.extend(image.payload[start:start+32])
            if power_fail=='write':
                self.status='off';self.history.append('powerloss_write')
                raise VirtualPowerLoss('Power loss while staging inactive bank')
        if bytes(bank.staged)!=image.payload or not self.verify(image):
            bank.staged.clear();bank.state='empty'
            self.history.append('rejected_before_switch')
            return self.result('rejected_auth_or_integrity',target)
        bank.image=image;bank.state='staged'
        self.history.append('verified_'+target)
        if power_fail=='precommit':
            self.status='off';self.history.append('powerloss_precommit')
            raise VirtualPowerLoss('Power loss before pointer switch')
        self.active=target;self.pending=target;bank.state='pending'
        self.history.append('pointer_'+target)
        if power_fail=='postcommit':
            self.status='off';self.history.append('powerloss_postcommit')
            raise VirtualPowerLoss('Power loss after pointer switch')
        try:
            self.boot()
            if not self.health() or bad_health:
                raise VirtualBootError('Codec health check failed')
            if power_fail=='preconfirm':
                self.status='off';self.history.append('powerloss_preconfirm')
                raise VirtualPowerLoss('Power loss before confirmation')
        except VirtualPowerLoss:raise
        except VirtualBootError:
            self.history.append('failed_health')
            self.rollback()
            return self.result('rolled_back',target)
        self.confirmed,self.pending=target,None
        bank.state='good';self.history.append('confirmed_'+target)
        return self.result('installed_in_virtual_flash',target)


def lab_keys():
    private=Ed25519PrivateKey.generate()
    return private,private.public_key()


def xusb_lab_payload(c_code):
    if type(c_code) is not bytes or not c_code:raise ValueError('No C codec')
    # An arbitrary marker with source-code digest, NOT an NXP image or executable.
    return PAYLOAD_MAGIC+sha256(c_code).hexdigest().encode()


def scenarios(c_code):
    key,root=lab_keys();factory=b'FICTIONAL_FACTORY_APP';target=xusb_lab_payload(c_code)
    results={}
    device=VirtualStadia('OPEN',root)
    device.provision(Bundle.create('factory',1,factory))
    device.boot()
    results['open_unsigned']=device.install(Bundle.create('xusb',2,target))
    a=bytes((3,8,0,64,128,128,128,128,0,0,0))
    results['xusb_button_a_packet']=device.input(a).hex()
    for name,stage in (('during_write','write'),('before_commit','precommit'),
                       ('after_commit','postcommit'),('before_confirmation','preconfirm')):
        d=VirtualStadia('OPEN',root)
        d.provision(Bundle.create('factory',1,factory));d.boot()
        try:d.install(Bundle.create('xusb',2,target),power_fail=stage)
        except VirtualPowerLoss:pass
        results[name]={'after_power_restore':d.power_on(),'bank':d.active,
                       'confirmed':d.confirmed,'unconfirmed':d.pending is not None}
    closed=VirtualStadia('CLOSED',root)
    closed.provision(Bundle.create('factory',1,factory,key));closed.boot()
    results['closed_unsigned']=closed.install(Bundle.create('xusb',2,target))
    results['closed_lab_signed']=closed.install(Bundle.create('xusb',2,target,key))
    other,_=lab_keys()
    results['closed_wrong_signature']=closed.install(Bundle.create('xusb',3,target,other))
    broken=VirtualStadia('OPEN',root)
    broken.provision(Bundle.create('factory',1,factory));broken.boot()
    results['xusb_health_failure']=broken.install(Bundle.create('xusb',2,target),bad_health=True)
    results['limits']={'virtual_install_success':True,'arm_code_executed':False,
       'hab_keys_available':False,'real_hab_bypassed':False,'actual_stadia_bootable':False,
       'actual_usb_xinput_enumerated':False,'xbox_console_authenticated':False}
    return results

if __name__=='__main__':
    from pathlib import Path
    c=Path(__file__).resolve().parents[1]/'firmware_codec'/'stadia_xusb_codec.c'
    print(json.dumps(scenarios(c.read_bytes()),indent=2,sort_keys=True))
