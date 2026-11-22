"""Virtual XUSB host on a fictional flashed Stadia; never uses USB APIs.

Structural USB fixture is a public Xbox 360 reference descriptor; this is not
Microsoft-licensed VID use, a running USB device, or Windows driver binding.
"""
from dataclasses import dataclass, field
from tools.audit_xusb_usb_phase100 import (
    REFERENCE_X360_DEVICE, REFERENCE_X360_CONFIG, inspect_x360_reference)
from tools.simulate_xinput_phase99 import xusb_rumble_to_bruce, parse_xusb_report
from tools.virtual_stadia_firmware_phase101 import VirtualStadia,VirtualBootError


class VirtualUSBError(RuntimeError):pass


@dataclass
class VirtualWindowsHost:
    connected: VirtualStadia | None = None
    samples: list[bytes] = field(default_factory=list)
    rumble_commands: list[bytes] = field(default_factory=list)
    endpoint_in: int = 0x81
    endpoint_out: int = 0x01
    interval_ms: int = 4
    current_ms: int = 0

    def enumerate(self, device: VirtualStadia):
        if device.status!='running_xusb' or not device.health():
            raise VirtualUSBError('Virtual USB controller is not in XUSB firmware mode')
        gate=inspect_x360_reference(REFERENCE_X360_DEVICE,REFERENCE_X360_CONFIG)
        if not gate['original_reference_structural_match']:
            raise VirtualUSBError('XUSB reference descriptor structure invalid')
        self.connected=device
        return {'virtual_descriptor_match':True,'xusb_report_bytes':20,
                'device_profile':'fictitious Xbox 360 reference',
                'real_windows_usb_enumerated':False,'driver_bound':False,
                'physical_microsoft_vid_exposed':False,'xsm3_authenticated':False}

    def poll(self,stadia_packet:bytes,dt_ms:int=4)->dict:
        if self.connected is None:
            raise VirtualUSBError('No virtual XUSB controller attached')
        if type(dt_ms) is not int or not 0<=dt_ms<=1000:
            raise VirtualUSBError('Invalid virtual poll delay')
        report=self.connected.input(stadia_packet)
        self.current_ms+=dt_ms
        self.samples.append(report)
        return {'time_ms':self.current_ms,'endpoint':'0x81','bytes':len(report),
                'state':parse_xusb_report(report),'virtual':True}

    def rumble(self,xusb_command:bytes)->bytes:
        if self.connected is None:raise VirtualUSBError('No virtual device')
        out=xusb_rumble_to_bruce(xusb_command)
        self.rumble_commands.append(out)
        return out  # No motors are powered or contacted.


def demo(device:VirtualStadia)->dict:
    h=VirtualWindowsHost()
    info=h.enumerate(device)
    a=bytes((3,8,0,64,128,128,128,128,0,0,0))
    poll=h.poll(a)
    vib=h.rumble(bytes((0,8,0,100,200,0,0,0)))
    return {'enumeration':info,'input':poll,'rumble_converted_bytes':vib.hex(),
            'elapsed_ms_virtual':h.current_ms,'real_windows_xinput_ready':False,
            'microsoft_hardware_authenticated':False}
