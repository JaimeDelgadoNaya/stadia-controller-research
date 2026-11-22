"""Offline NS1 Pro USB/HID profile gate and deterministic host-poll experiment.

No hardware, IO endpoints, emulation of RT1061 code, USB driver or live console.
The 203-byte reference report descriptor is third-party public evidence, not
proof the Switch 2 recognizes this or any Stadia controller.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from tools.simulate_switch_pro_phase97 import VirtualNS1Pro97, make_host_subcommand

NS1_VID_PID = (0x057E, 0x2009)
NS1_REQUIRED_INPUTS = {0x21: 64, 0x30: 64, 0x81: 64}
NS1_REQUIRED_OUTPUTS = {0x01: 64, 0x10: 64, 0x80: 64, 0x82: 64}


class DescriptorError(ValueError):
    pass


def report_lengths(descriptor: bytes) -> dict[str, dict[int, int]]:
    """Decode HID main/global items and count report bits, including ID byte.

    No host assumptions or Nintendo identity are read from the descriptor.
    """
    if type(descriptor) is not bytes or not 1 <= len(descriptor) <= 4096:
        raise DescriptorError('Empty, invalid or oversized HID report descriptor')
    result: dict[str, dict[int, int]] = {'input': {}, 'output': {}, 'feature': {}}
    report_bits: dict[tuple[str, int], int] = {}
    report_size, report_count, report_id = 0, 0, 0
    stack: list[tuple[int,int,int]] = []
    off = 0
    while off < len(descriptor):
        prefix = descriptor[off]
        off += 1
        if prefix == 0xFE:
            if off + 2 > len(descriptor):
                raise DescriptorError('Truncated long item header')
            length = descriptor[off]
            off += 2
            if off + length > len(descriptor):
                raise DescriptorError('Truncated long item body')
            off += length
            continue
        size = (0,1,2,4)[prefix & 3]
        typ = (prefix >> 2) & 3
        tag = (prefix >> 4) & 15
        if off + size > len(descriptor):
            raise DescriptorError('Truncated HID short item')
        value = int.from_bytes(descriptor[off:off + size], 'little')
        off += size
        if typ == 1:
            if tag == 7:
                report_size = value
            elif tag == 8:
                if not 1 <= value <= 255:
                    raise DescriptorError('Invalid report ID')
                report_id = value
            elif tag == 9:
                report_count = value
            elif tag == 10:
                if len(stack) >= 16:
                    raise DescriptorError('Excessive HID global nesting')
                stack.append((report_size, report_count, report_id))
            elif tag == 11:
                if not stack:
                    raise DescriptorError('Unmatched HID global pop')
                report_size,report_count,report_id = stack.pop()
        elif typ == 0 and tag in (8,9,11):
            if report_size > 4096 or report_count > 8192:
                raise DescriptorError('Excessive HID field width or count')
            label = {8:'input', 9:'output', 11:'feature'}[tag]
            key = (label,report_id)
            report_bits[key] = report_bits.get(key,0) + report_size*report_count
            if report_bits[key] > 32768:
                raise DescriptorError('HID report is too large')
    for (label,rid),bits in report_bits.items():
        result[label][rid] = (bits+7)//8 + (1 if rid else 0)
    return result


@dataclass(frozen=True)
class USBProfile:
    name: str
    vid: int
    pid: int
    interface_class: int
    endpoint_in: int | None
    endpoint_out: int | None
    interrupt_in: bool
    interrupt_out: bool
    report_descriptor: bytes | None


def classify(profile: USBProfile) -> dict[str, object]:
    issues: list[str] = []
    if (profile.vid,profile.pid) != NS1_VID_PID:
        issues.append('USB VID:PID is not Nintendo NS1 Pro 057e:2009')
    if profile.interface_class != 3:
        issues.append('USB interface class is not HID')
    if not (profile.interrupt_in and profile.interrupt_out and
            profile.endpoint_in is not None and profile.endpoint_out is not None and
            profile.endpoint_in & 0x80 and not profile.endpoint_out & 0x80):
        issues.append('Missing HID interrupt IN+OUT pair')
    lengths = None
    if profile.report_descriptor is None:
        issues.append('HID report descriptor not available')
    else:
        try:
            lengths=report_lengths(profile.report_descriptor)
        except DescriptorError as exc:
            issues.append(f'Invalid HID report descriptor: {exc}')
        else:
            for direction,expected in (('input',NS1_REQUIRED_INPUTS),
                                       ('output',NS1_REQUIRED_OUTPUTS)):
                for rid,size in expected.items():
                    if lengths[direction].get(rid) != size:
                        issues.append(f'Missing/mismatched {direction} report {rid:02x} (64 bytes)')
            if 0x3F in lengths['input']:
                issues.append('Reference wired Pro USB descriptor does not define simple 0x3f')
    return {
        'profile':profile.name,
        'vid_pid':f'{profile.vid:04x}:{profile.pid:04x}',
        'structural_gate_pass':not issues,
        'reasons':issues,
        'report_lengths':lengths,
        'genuine_nintendo_descriptor_authenticated':False,
        'real_usb_device_enumerated':False,
        'switch2_console_accepted':False,
    }


@dataclass
class DiscreteHostProbe:
    """Simulate a synthetic host that needs periodic reports at a chosen cadence.

    15 ms is sourced from an independent community USB profile, not a measured
    Switch 2 deadline. A failed timing test is a model gap, not hardware proof.
    """
    pad: VirtualNS1Pro97
    renderer: Callable[..., bytes]
    source: bytes
    interval_ms: int = 15
    now_ms: int = 0
    next_report_ms: int | None = None

    def send(self, frame: bytes) -> bytes | None:
        reply=self.pad.process(frame)
        if self.pad.can_stream() and self.next_report_ms is None:
            self.next_report_ms=self.now_ms+self.interval_ms
        return reply

    def step(self, delta_ms: int) -> list[bytes]:
        if type(delta_ms) is not int or not 0 <= delta_ms <= 10000:
            raise ValueError('Invalid virtual time step')
        if not 1 <= self.interval_ms <= 1000:
            raise ValueError('Invalid virtual report interval')
        end=self.now_ms+delta_ms
        output=[]
        while self.next_report_ms is not None and self.next_report_ms <= end:
            if len(output)>=1024:
                raise ValueError('Too many virtual reports in one step')
            report=self.pad.sample(self.source,self.renderer)
            if len(report)!=64 or report[0]!=0x30:
                raise ValueError('Malformed input report emitted')
            output.append(report)
            self.next_report_ms += self.interval_ms
        self.now_ms=end
        return output


def run_gate_scenarios(public_descriptor: bytes, renderer: Callable[..., bytes]) -> dict[str, object]:
    synthetic=USBProfile('synthetic_ns1_structural_reference',0x057e,0x2009,3,
                         0x81,0x01,True,True,public_descriptor)
    stadia=USBProfile('stadia_bootloader_A_or_CDC',0x18d1,0x946b,0xff,
                      0x87,0x07,False,False,None)
    flashloader=USBProfile('community_nxp_ram_flashloader',0x15a2,0x0073,3,
                           0x81,0x02,True,True,None)
    neutral=bytes([3,8,0,0,128,128,128,128,0,0,0])
    probe=DiscreteHostProbe(VirtualNS1Pro97(),renderer,neutral)
    replies=[]
    for command in (1,2,3,4):
        r=probe.send(bytes([0x80,command])+bytes(62))
        replies.append(None if r is None else len(r))
    no_pre_mode_stream = len(probe.step(45))==0
    response=probe.send(make_host_subcommand(3,b'\x30'))
    reports=probe.step(45)
    return {
        'structural_usb_gate':{
            'synthetic_reference':classify(synthetic),
            'actual_stadia_bootloader':classify(stadia),
            'actual_nxp_ram_flashloader':classify(flashloader),
        },
        'init_0x81_reply_lengths':replies,
        'no_input_before_report_mode':no_pre_mode_stream,
        'mode_0x30_ack_report_length':len(response) if response else None,
        'scheduled_frames_in_45ms':len(reports),
        'all_scheduled_frames_64_bytes':all(len(x)==64 and x[0]==0x30 for x in reports),
        'schedule_interval_ms_assumption':15,
        'initial_stream_gap_if_host_requires_pre_mode_input':no_pre_mode_stream,
        'usb_enumeration_hardware_verified':False,
        'switch2_emulator_acceptance_verified':False,
        'stadia_hab_closed_custom_boot_verified':False,
        'real_usb_commands_sent':False,
    }
