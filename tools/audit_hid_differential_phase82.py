"""Synthetic differential tests against descriptor-driven HID field extraction.

Exhaustive button combinations and individual-byte sweeps are not exhaustive
coverage of the full 80-bit payload. No hardware operations are performed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import random
from tools.audit_hid_report_contract import decode
from tools.analyze_hid_input_phase80 import field_values
from tools.decode_hid_input_phase81 import decode_report, DESCRIPTOR_SHA256


def reference(raw, fields):
    state={'hat_raw':None,'hat_direction':None,'button_usages':[],
           'axes':{},'page2_values':{},'consumer_usages':[],
           'nonzero_constant_padding':False,
           'generic_axes_outside_logical_range':False}
    for field in fields:
        values=field_values(raw,field)
        if field['flags'] & 1:
            state['nonzero_constant_padding'] |= any(values)
            continue
        for usage,value in zip(field['usages'],values):
            page=field['usage_page']
            if page==1 and usage==0x39:
                state['hat_raw']=value
                state['hat_direction']=value if field['logical_min']<=value<=field['logical_max'] else None
            elif page==9 and value:
                state['button_usages'].append(usage)
            elif page==1 and usage in (0x30,0x31,0x32,0x35):
                state['axes'][{0x30:'X',0x31:'Y',0x32:'Z',0x35:'Rz'}[usage]]=value
                state['generic_axes_outside_logical_range'] |= not field['logical_min']<=value<=field['logical_max']
            elif page==2:
                state['page2_values'][hex(usage)]=value
            elif page==12 and value:
                state['consumer_usages'].append(usage)
    return state


def vectors():
    neutral=bytes.fromhex('0308000080808080000000')
    for buttons in range(1<<15):
        raw=bytearray(neutral)
        raw[2:4]=buttons.to_bytes(2,'little')
        yield 'all_button_combinations',bytes(raw)
    for index in range(1,11):
        for value in range(256):
            raw=bytearray(neutral)
            raw[index]=value
            yield 'individual_payload_byte_sweeps',bytes(raw)
    rng=random.Random(82)
    for _ in range(4096):
        yield 'seed82_mixed_payloads',bytes([3]+[rng.randrange(256) for _ in range(10)])


def audit(descriptor, decoder=decode_report):
    if hashlib.sha256(descriptor).hexdigest()!=DESCRIPTOR_SHA256:
        raise ValueError('Exact recorded HID descriptor required')
    fields=[f for f in decode(descriptor)['fields'] if f['direction']=='input']
    counts={}
    digest=hashlib.sha256()
    for group,raw in vectors():
        expected=reference(raw,fields)
        actual=decoder(raw,descriptor)
        if actual!=expected:
            raise ValueError(f'Differential mismatch in {group}: {raw.hex()}')
        digest.update(raw)
        counts[group]=counts.get(group,0)+1
    rejected_ids=0
    for report_id in range(256):
        if report_id==3:continue
        try:decoder(bytes([report_id])+bytes(10),descriptor)
        except ValueError:rejected_ids+=1
        else:raise ValueError('Wrong report ID accepted')
    rejected_lengths=0
    for size in range(65):
        if size==11:continue
        raw=(b'\x03'+bytes(size))[:size]
        try:decoder(raw,descriptor)
        except ValueError:rejected_lengths+=1
        else:raise ValueError('Wrong report length accepted')
    rejected_descriptors=0
    for bit in range(len(descriptor)*8):
        altered=bytearray(descriptor)
        altered[bit//8]^=1<<(bit%8)
        try:decoder(bytes.fromhex('0308000080808080000000'),altered)
        except ValueError:rejected_descriptors+=1
        else:raise ValueError('Changed descriptor accepted')
    return {'phase':82,'descriptor_sha256':DESCRIPTOR_SHA256,
            'synthetic_vector_counts':counts,'vector_stream_sha256':digest.hexdigest(),
            'rejected_wrong_ids':rejected_ids,
            'rejected_lengths_in_0_to_64':rejected_lengths,
            'rejected_single_bit_descriptor_mutations':rejected_descriptors,
            'differential_mismatches':0,
            'limits':['Synthetic decoder validation, not physical control mapping.',
                      'All 32768 button subsets covered; full 80-bit payload space not exhausted.',
                      'Reference shares the earlier generic descriptor parser and bit extractor.',
                      'No USB I/O, output protocol or console compatibility tested.']}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('descriptor',type=Path)
    p.add_argument('--out',type=Path,required=True)
    args=p.parse_args()
    result=audit(bytes.fromhex(json.loads(args.descriptor.read_text())['descriptor_hex']))
    args.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,indent=2))
