"""Decode a complete configuration descriptor; no device I/O."""
import argparse
import json
from pathlib import Path


def parse_configuration(data: bytes) -> dict:
    if len(data) < 9 or data[:2] != b'\x09\x02':
        raise ValueError('Missing configuration header')
    if int.from_bytes(data[2:4], 'little') != len(data):
        raise ValueError('Configuration total length mismatch')
    interfaces = []
    current = None
    offset = 0
    while offset < len(data):
        length = data[offset]
        if length < 2 or offset + length > len(data):
            raise ValueError('Invalid descriptor length')
        d = data[offset:offset + length]
        kind = d[1]
        if kind == 4:
            if length != 9:
                raise ValueError('Invalid interface descriptor')
            current = dict(number=d[2], alternate=d[3], declared_endpoints=d[4],
                           usb_class=d[5], subclass=d[6], protocol=d[7], endpoints=[])
            interfaces.append(current)
        elif kind == 5:
            if current is None or length < 7:
                raise ValueError('Invalid endpoint descriptor')
            current['endpoints'].append(dict(address=f'0x{d[2]:02x}',
                direction='IN' if d[2] & 128 else 'OUT',
                transfer_type=['control', 'isochronous', 'bulk', 'interrupt'][d[3] & 3],
                max_packet_bytes=int.from_bytes(d[4:6], 'little') & 0x7ff,
                interval=d[6]))
        elif kind == 0x21 and current is not None:
            if length < 9 or d[5] != 1 or d[6] != 0x22:
                raise ValueError('Unsupported HID descriptor layout')
            current['hid_report_descriptor_bytes'] = int.from_bytes(d[7:9], 'little')
        offset += length
    if len({i['number'] for i in interfaces}) != data[4]:
        raise ValueError('Interface count mismatch')
    for interface in interfaces:
        if len(interface['endpoints']) != interface['declared_endpoints']:
            raise ValueError('Endpoint count mismatch')
    return dict(total_bytes=len(data), configuration_value=data[5],
                declared_interfaces=data[4], interfaces=interfaces)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    args = parser.parse_args()
    report = json.loads(args.evidence.read_text(encoding='utf-8-sig'))
    print(json.dumps({key: parse_configuration(bytes.fromhex(report[key]['configuration']))
                      for key in ('hub', 'winusb_function_view')}, indent=2))


if __name__ == '__main__':
    main()
