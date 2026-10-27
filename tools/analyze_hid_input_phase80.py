"""Offline descriptor-based field observations of aggregated HID reports."""
import argparse
import hashlib
import json
from pathlib import Path
from tools.audit_hid_report_contract import decode


def field_values(report, field):
    size = field['size']
    if size <= 0 or field['count'] <= 0:
        raise ValueError('Positive HID field size/count required')
    payload = report[1:] if field['report_id'] else report
    if field['payload_bit_offset'] + size*field['count'] > len(payload)*8:
        raise ValueError('Truncated report field')
    bits = int.from_bytes(payload, 'little')
    values = []
    for index in range(field['count']):
        value = (bits >> (field['payload_bit_offset']+index*size)) & ((1 << size)-1)
        if field['logical_min'] < 0 and value & (1 << (size-1)):
            value -= 1 << size
        values.append(value)
    return values


def analyze(capture, descriptor):
    contract = decode(descriptor)
    rows = capture['distinct_reports']
    if sum(row['count'] for row in rows) != capture['report_count']:
        raise ValueError('Capture count mismatch')
    reports = {r['report_id']: r for r in contract['reports'] if r['direction']=='input'}
    for row in rows:
        raw = bytes.fromhex(row['hex'])
        if row['count'] <= 0 or not raw or raw[0] not in reports or len(raw) != reports[raw[0]]['wire_bytes']:
            raise ValueError('Unexpected report ID, length or count')
    result = []
    for field in contract['fields']:
        if field['direction'] != 'input':
            continue
        observations = [set() for _ in range(field['count'])]
        for row in rows:
            raw = bytes.fromhex(row['hex'])
            if raw[0] != field['report_id']:
                continue
            for values, value in zip(observations, field_values(raw, field)):
                values.add(value)
        result.append({k: field[k] for k in ('report_id','usage_page','usages','payload_bit_offset','size','count','flags','logical_min','logical_max')})
        result[-1]['observed_elements'] = [
            {'distinct': len(values), 'min': min(values) if values else None,
             'max': max(values) if values else None,
             'outside_logical_range': sorted(v for v in values if not field['logical_min'] <= v <= field['logical_max'])}
            for values in observations]
    return {'phase':80, 'descriptor_sha256':hashlib.sha256(descriptor).hexdigest(),
            'report_count':capture['report_count'], 'distinct_reports':len(rows),
            'fields':result,
            'limits':['Descriptor usages, not labeled physical actions.',
                      'Out-of-range values are observations, not automatically faults; null states and constant padding require interpretation.',
                      'Aggregates retain no timing/order; no polling-rate inference.',
                      'No vendor bulk, Work Queue, callback or unsigned execution evidence.']}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('capture',type=Path)
    p.add_argument('descriptor',type=Path)
    p.add_argument('--out',type=Path,required=True)
    args=p.parse_args()
    result=analyze(json.loads(args.capture.read_text()),bytes.fromhex(json.loads(args.descriptor.read_text())['descriptor_hex']))
    args.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,indent=2))
