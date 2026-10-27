"""Offline Bruce ID3 input decoder. HID usages are not physical button labels.

Layout pinned to the owner-device descriptor recorded in the repository.
No device I/O or console output protocol is implemented here.
"""
import argparse
import hashlib
import json
from pathlib import Path

DESCRIPTOR_SHA256 = '88121159b7b6cf6ffa4025d0d5aebe1d4ae83013ee34acc8dd4bf2cff52116d8'
BUTTON_USAGES = (18,17,20,19,13,12,11,15,14,8,7,5,4,2,1)
CONSUMER_USAGES = (0xE9,0xEA,0xCD)


def decode_report(raw, descriptor):
    if hashlib.sha256(descriptor).hexdigest() != DESCRIPTOR_SHA256:
        raise ValueError('Exact recorded HID descriptor required')
    if len(raw) != 11 or raw[0] != 3:
        raise ValueError('Expected report ID3 with 11 bytes')
    buttons = int.from_bytes(raw[2:4], 'little')
    hat = raw[1] & 15
    return {'hat_raw':hat, 'hat_direction':hat if hat <= 7 else None,
            'button_usages':[usage for bit,usage in enumerate(BUTTON_USAGES) if buttons & (1<<bit)],
            'axes':dict(zip(('X','Y','Z','Rz'),raw[4:8])),
            'page2_values':{'0xc5':raw[8], '0xc4':raw[9]},
            'consumer_usages':[usage for bit,usage in enumerate(CONSUMER_USAGES) if raw[10] & (1<<bit)],
            'nonzero_constant_padding':bool(raw[1]&0xF0 or raw[3]&0x80 or raw[10]&0xF8),
            'generic_axes_outside_logical_range':any(v==0 for v in raw[4:8])}


def replay(capture, descriptor):
    if hashlib.sha256(descriptor).hexdigest() != DESCRIPTOR_SHA256:
        raise ValueError('Exact recorded HID descriptor required')
    if type(capture['report_count']) is not int or capture['report_count'] < 0:
        raise ValueError('Nonnegative integer report_count required')
    counts = {usage:0 for usage in BUTTON_USAGES}
    consumers = {usage:0 for usage in CONSUMER_USAGES}
    total = null_hat = padding = zero_axes = 0
    hats=set()
    for row in capture['distinct_reports']:
        count=row['count']
        if type(count) is not int or count <= 0:
            raise ValueError('Positive integer aggregate count required')
        state=decode_report(bytes.fromhex(row['hex']),descriptor)
        total+=count
        null_hat+=count*(state['hat_direction'] is None)
        padding+=count*state['nonzero_constant_padding']
        zero_axes+=count*state['generic_axes_outside_logical_range']
        hats.add(state['hat_raw'])
        for usage in state['button_usages']:counts[usage]+=count
        for usage in state['consumer_usages']:consumers[usage]+=count
    if total != capture['report_count']:
        raise ValueError('Aggregate report count mismatch')
    return {'phase':81,'descriptor_sha256':DESCRIPTOR_SHA256,
            'source_phase':capture['phase'],'report_count':total,
            'button_usage_pressed_report_counts':{str(k):v for k,v in counts.items()},
            'consumer_usage_pressed_report_counts':{hex(k):v for k,v in consumers.items()},
            'hat_raw_values':sorted(hats),'null_hat_report_count':null_hat,
            'nonzero_padding_report_count':padding,
            'generic_axis_outside_range_report_count':zero_axes,
            'limits':['Counts describe reports, not press events or durations.',
                      'Physical button labels and left/right control assignment unverified.',
                      'No output protocol, console compatibility or firmware execution demonstrated.']}


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('capture',type=Path)
    p.add_argument('descriptor',type=Path)
    p.add_argument('--out',type=Path,required=True)
    args=p.parse_args()
    result=replay(json.loads(args.capture.read_text()),bytes.fromhex(json.loads(args.descriptor.read_text())['descriptor_hex']))
    args.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,indent=2))
