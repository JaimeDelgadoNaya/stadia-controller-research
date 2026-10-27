"""Compare pinned BLE bridge source positions with recorded USB HID descriptor.

Offset coincidences are hypotheses, not a measurement of BLE or physical labels.
The GPL-licensed upstream checkout remains separate and is not imported here.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
from tools.audit_hid_report_contract import decode
from tools.decode_hid_input_phase81 import DESCRIPTOR_SHA256, replay

SOURCE_SHA256 = '375821e4e1b846ebab99b5e124f4399b7b06a8f0d9ce9eb6f306d82467335334'
COMMIT = 'd8392de8f838e12cf16c985b9beb8080c7acd970'
BUTTON_NAMES = {'assistant','capture','rs','options','menu','stadia',
                'a','b','x','y','lb','rb','ls'}
AXIS_NAMES = {'lx','ly','rx','ry','lt','rt'}


def parse_positions(source):
    if hashlib.sha256(source).hexdigest()!=SOURCE_SHA256:
        raise ValueError('Pinned upstream bridge.c SHA-256 required')
    text=source.decode('utf-8')
    marker='void stadia_parse_state('
    start=text.index(marker)
    end=text.index('\nvoid stadia_to_xbox360(',start)
    body=text[start:end]
    buttons=re.findall(r'out->(\w+)\s*=\s*\(s\[(\d+)\]\s*&\s*\(1\s*<<\s*(\d+)\)\)\s*!=\s*0\s*;',body)
    axes=re.findall(r'out->(\w+)\s*=\s*(?:map_stick\(s\[(\d+)\],\s*[01]\)|s\[(\d+)\])\s*;',body)
    if len(buttons)!=len(BUTTON_NAMES) or {x[0] for x in buttons}!=BUTTON_NAMES:
        raise ValueError('Unexpected pinned BLE button assignments')
    if len(axes)!=len(AXIS_NAMES) or {x[0] for x in axes}!=AXIS_NAMES:
        raise ValueError('Unexpected pinned BLE axis assignments')
    return ({name:(int(byte),int(bit)) for name,byte,bit in buttons},
            {name:int(first or second) for name,first,second in axes})


def usb_positions(descriptor):
    if hashlib.sha256(descriptor).hexdigest()!=DESCRIPTOR_SHA256:
        raise ValueError('Recorded USB HID descriptor required')
    buttons={}
    values={}
    for f in decode(descriptor)['fields']:
        if f['direction']!='input' or f['report_id']!=3 or f['flags']&1:
            continue
        if len(f['usages'])!=f['count']:
            raise ValueError('Expected explicit HID usage for each variable element')
        for i,usage in enumerate(f['usages']):
            offset=f['payload_bit_offset']+i*f['size']
            if f['usage_page']==9 and f['size']==1:
                buttons[(offset//8,offset%8)]=usage
            elif f['size']==8 and f['usage_page'] in (1,2):
                if offset%8:raise ValueError('Expected byte aligned analog field')
                values[offset//8]=(f['usage_page'],usage)
    return buttons,values


def compare(buttons, axes, usb_buttons, usb_values, counts):
    if len(set(buttons.values()))!=len(buttons) or len(set(axes.values()))!=len(axes):
        raise ValueError('Duplicate upstream source positions')
    if set(buttons.values())-set(usb_buttons) or set(axes.values())-set(usb_values):
        raise ValueError('Upstream positions do not match declared USB fields')
    button_matches=[]
    for name,(byte,bit) in sorted(buttons.items()):
        usage=usb_buttons[(byte,bit)]
        button_matches.append({'upstream_ble_label':name,'payload_byte':byte,'bit':bit,
                               'usb_button_usage':usage,
                               'usb_recorded_reports_with_bit_set':counts[str(usage)]})
    analog_matches=[]
    for name,byte in sorted(axes.items()):
        page,usage=usb_values[byte]
        analog_matches.append({'upstream_ble_label':name,'payload_byte':byte,
                               'usb_usage_page':page,'usb_usage':usage})
    return button_matches,analog_matches


def audit(source, descriptor, capture):
    buttons,axes=parse_positions(source)
    usb_buttons,usb_values=usb_positions(descriptor)
    report=replay(capture,descriptor)
    button_matches,analog_matches=compare(buttons,axes,usb_buttons,usb_values,report['button_usage_pressed_report_counts'])
    return {'phase':83,'upstream_commit':COMMIT,'upstream_bridge_sha256':SOURCE_SHA256,
            'usb_descriptor_sha256':DESCRIPTOR_SHA256,'usb_capture_phase':capture['phase'],
            'usb_capture_report_count':report['report_count'],
            'matched_button_positions':button_matches,'matched_analog_positions':analog_matches,
            'usb_button_usages_without_upstream_label':sorted(set(usb_buttons.values())-{x['usb_button_usage'] for x in button_matches}),
            'last_payload_byte':{'upstream_source_comment':'BLE byte 9 described as padding',
                                 'usb_descriptor':'consumer-page input bits 0..2 and constant bits 3..7',
                                 'usb_capture_consumer_active_reports':report['consumer_usage_pressed_report_counts']},
            'limits':['BLE source labels are upstream assumptions, not independently verified physical assignments.',
                      'Equal offsets across transports do not establish equal live BLE semantics.',
                      'USB aggregate counts are not button press counts or proof of individual actions.',
                      'No BLE capture, compiled bridge, hardware testing or console compatibility established.']}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('bridge_source',type=Path)
    p.add_argument('descriptor',type=Path)
    p.add_argument('capture',type=Path)
    p.add_argument('--out',type=Path,required=True)
    args=p.parse_args()
    result=audit(args.bridge_source.read_bytes(),bytes.fromhex(json.loads(args.descriptor.read_text())['descriptor_hex']),json.loads(args.capture.read_text()))
    args.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,indent=2))
