"""Phase 79: offline USB URB metadata triage against phase 61 descriptors.

Accepts a Tshark CSV metadata export, never opens a USB device or parses payloads.
A bus/device pair is mandatory because VID/PID are often absent on later URBs.
Selection is not hardware-identity proof unless VID/PID occur in that pair.
"""

import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path

from tools.parse_usb_configuration import parse_configuration

CONFIG_SHA256 = '01b299fc757c731df8c2de21a953ed8b0fc0c854f6043c178b8cc7588c26e5db'
VID, PID = 0x18D1, 0x9400
FIELDS = (
    'usb.bus_id', 'usb.device_address', 'usb.endpoint_address',
    'usb.urb_type', 'usb.data_len', 'usb.bmRequestType',
    'usb.setup.bRequest', 'usb.idVendor', 'usb.idProduct',
    'usb.urb_id', 'usb.irp_id',
)
EVENT_NAMES = {'S': 'submit', 'C': 'complete', 'E': 'error'}
REQUEST_CLASSES = ('standard', 'class', 'vendor', 'reserved')
MAX_ROWS = 2_000_000
MAX_PENDING_URBS = 200_000


def integer(text, name, maximum=None):
    if text is None or not str(text).strip():
        return None
    text = str(text).strip()
    if len(text) > 16:
        raise ValueError(f'Invalid {name}: excessive length')
    try:
        value = int(text, 16) if text.lower().startswith('0x') else int(text, 10)
    except ValueError as exc:
        raise ValueError(f'Invalid numeric {name}') from exc
    if value < 0 or (maximum is not None and value > maximum):
        raise ValueError(f'Out-of-range {name}')
    return value


def urb_identifier(value):
    """Parse a capture-local 64-bit ID; never include it in reports or exceptions."""
    if value is None or not str(value).strip():
        return None
    raw = str(value).strip()
    try:
        if raw.lower().startswith('0x'):
            if len(raw) > 18:
                raise ValueError('ID too long')
            result = int(raw[2:], 16)
        else:
            if len(raw) > 20:
                raise ValueError('ID too long')
            result = int(raw, 10)
    except ValueError as exc:
        raise ValueError('Invalid USB URB/IRP identifier') from exc
    if not 0 <= result <= 0xffffffffffffffff:
        raise ValueError('Out-of-range USB URB/IRP identifier')
    return result


def expected_endpoints(phase61):
    hub = phase61['hub']
    device = bytes.fromhex(hub['device'])
    config = bytes.fromhex(hub['configuration'])
    if len(device) != 18 or device[1] != 1:
        raise ValueError('Phase61 device descriptor invalid')
    if (int.from_bytes(device[8:10], 'little'), int.from_bytes(device[10:12], 'little')) != (VID, PID):
        raise ValueError('Phase61 VID/PID mismatch')
    digest = hashlib.sha256(config).hexdigest()
    if digest != CONFIG_SHA256:
        raise ValueError('Phase61 full hub descriptor hash mismatch')
    parsed = parse_configuration(config)
    known = {}
    for iface in parsed['interfaces']:
        for ep in iface['endpoints']:
            addr = int(ep['address'], 16)
            if addr in known:
                raise ValueError('Duplicate endpoint addresses in phase61')
            known[addr] = dict(interface=iface['number'], usb_class=f"0x{iface['usb_class']:02x}",
                               transfer_type=ep['transfer_type'], max_packet_bytes=ep['max_packet_bytes'])
    if set(known) != {0x87, 0x07, 0x83, 0x03}:
        raise ValueError('Phase61 endpoint inventory changed')
    return known, digest


def audit(csv_path, phase61, bus, address):
    if not (0 <= bus <= 65535 and 1 <= address <= 255):
        raise ValueError('Invalid bus/device selection (post-enumeration address required)')
    known, descriptor_sha = expected_endpoints(phase61)
    counters = {ep: Counter() for ep in known}
    control = Counter()
    unknown = Counter()
    selected = 0
    rows = 0
    vid_pid_seen = False
    incomplete_setup = 0
    missing_endpoint = 0
    for_recognized = 0
    pairing = Counter()
    pending = {}
    id_columns = []

    with open(csv_path, encoding='utf-8-sig', newline='') as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames is None or len(reader.fieldnames) != len(set(reader.fieldnames)):
            raise ValueError('CSV missing or repeated headers')
        required = {'usb.bus_id', 'usb.device_address', 'usb.endpoint_address', 'usb.urb_type'}
        if not required.issubset(reader.fieldnames):
            raise ValueError('CSV missing required Tshark fields')
        forbidden = set(reader.fieldnames) - set(FIELDS)
        if forbidden:
            raise ValueError('Unapproved columns (possible raw payload/private fields): '+', '.join(sorted(forbidden)))
        id_columns = [name for name in ('usb.urb_id', 'usb.irp_id')
                      if name in reader.fieldnames]
        for row in reader:
            rows += 1
            if rows > MAX_ROWS:
                raise ValueError('CSV row limit exceeded')
            if None in row:
                raise ValueError('CSV contains extra cells')
            b = integer(row['usb.bus_id'], 'bus', 65535)
            d = integer(row['usb.device_address'], 'device', 255)
            if b != bus or d != address:
                continue
            selected += 1
            vid = integer(row.get('usb.idVendor'), 'VID', 65535)
            pid = integer(row.get('usb.idProduct'), 'PID', 65535)
            if vid is not None or pid is not None:
                if vid is None or pid is None:
                    raise ValueError('Partial VID/PID for selected device')
                if (vid, pid) != (VID, PID):
                    raise ValueError('Selected bus/device belongs to a different VID/PID')
                vid_pid_seen = True
            ep = integer(row.get('usb.endpoint_address'), 'endpoint', 255)
            event = row['usb.urb_type'].strip()
            if event not in EVENT_NAMES:
                raise ValueError('Unexpected USB URB event (expected S/C/E)')
            payload_length = integer(row.get('usb.data_len'), 'data_len', 2**32-1)
            if id_columns:
                present_ids = {ident for name in id_columns
                               if (ident := urb_identifier(row.get(name))) is not None}
                if len(present_ids) > 1:
                    raise ValueError('Conflicting USB URB/IRP identifiers')
                if not present_ids:
                    pairing['missing_id_events'] += 1
                else:
                    pairing['id_events'] += 1
                    identifier = next(iter(present_ids))
                    if ep is None:
                        pairing['unpairable_endpoint_events'] += 1
                    elif event == 'S':
                        if identifier in pending:
                            previous_ep, _ = pending[identifier]
                            pending[identifier] = (previous_ep, True)
                            pairing['duplicate_pending_submit'] += 1
                        else:
                            pending[identifier] = (ep, False)
                            if len(pending) > MAX_PENDING_URBS:
                                raise ValueError('Too many pending URB identifiers')
                    else:
                        previous = pending.pop(identifier, None)
                        if previous is None:
                            pairing['unmatched_' + EVENT_NAMES[event]] += 1
                        elif previous[1]:
                            pairing['ambiguous_id_terminal'] += 1
                        elif previous[0] != ep:
                            pairing['endpoint_mismatch'] += 1
                        else:
                            pairing['paired_' + EVENT_NAMES[event]] += 1
            if ep is None:
                missing_endpoint += 1
                continue
            if ep == 0:
                control[EVENT_NAMES[event]] += 1
                if event == 'S':
                    bm = integer(row.get('usb.bmRequestType'), 'bmRequestType', 255)
                    req = integer(row.get('usb.setup.bRequest'), 'bRequest', 255)
                    if bm is None or req is None:
                        incomplete_setup += 1
                    else:
                        category = REQUEST_CLASSES[(bm >> 5) & 3]
                        direction = 'IN' if bm & 0x80 else 'OUT'
                        control[f'{category}:{direction}:bRequest=0x{req:02x}'] += 1
                continue
            if ep not in known:
                unknown[ep] += 1
                continue
            for_recognized += 1
            count = counters[ep]
            count[EVENT_NAMES[event]] += 1
            if payload_length is None:
                count['missing_length'] += 1
            else:
                count['reported_data_length_sum'] += payload_length
                if payload_length:
                    count['nonempty_events'] += 1
    if not selected:
        raise ValueError('No URBs for selected bus/device')

    pairing_status = ('not_exported' if not id_columns
                      else 'not_observed' if not pairing['id_events']
                      else 'partial_ids' if pairing['missing_id_events']
                      else 'id_events_observed')
    endpoints = []
    for ep in sorted(known):
        n = counters[ep]
        endpoints.append(dict(address=f'0x{ep:02x}', **known[ep],
                              submit=n['submit'], complete=n['complete'], error=n['error'],
                              nonempty_events=n['nonempty_events'],
                              missing_length=n['missing_length'],
                              reported_data_length_sum=n['reported_data_length_sum']))
    return {
        'phase': 79,
        'input_kind': 'offline_tshark_metadata_csv',
        'phase61_full_descriptor_sha256': descriptor_sha,
        'expected_usb_vid_pid': '18d1:9400',
        'device_identity_in_selected_urbs': 'observed_vid_pid' if vid_pid_seen else 'not_observed',
        'counts': {'csv_rows_seen': rows, 'selected_urb_events': selected,
                   'known_endpoint_events': for_recognized, 'missing_endpoint_events': missing_endpoint},
        'endpoints': endpoints,
        'control_ep0': {'submit': control['submit'], 'complete': control['complete'],
                        'error': control['error'], 'incomplete_submit_setup': incomplete_setup,
                        'setup_request_classes': dict(sorted((key,value) for key,value in control.items()
                                                 if key not in ('submit','complete','error')))},
        'undeclared_endpoint_events': {f'0x{ep:02x}': count for ep,count in sorted(unknown.items())},
        'urb_pairing': {
            'status': pairing_status, 'id_fields_exported': id_columns,
            'id_events': pairing['id_events'], 'missing_id_events': pairing['missing_id_events'],
            'paired_complete': pairing['paired_complete'], 'paired_error': pairing['paired_error'],
            'unmatched_complete': pairing['unmatched_complete'],
            'unmatched_error': pairing['unmatched_error'],
            'unmatched_submit_at_end': len(pending),
            'duplicate_pending_submit': pairing['duplicate_pending_submit'],
            'ambiguous_id_terminal': pairing['ambiguous_id_terminal'],
            'endpoint_mismatch': pairing['endpoint_mismatch'],
            'unpairable_endpoint_events': pairing['unpairable_endpoint_events'],
        },
        'limits': [
            'Bus and device address are operator-selected; VID/PID validation is positive only if observed within the selected rows.',
            'Only URB event and header metadata were analyzed. Captured bytes, serial numbers and timings are neither read nor exported.',
            'Submit and completion may describe one transfer; counts and reported lengths are not independent USB transactions or verified bytes on wire.',
            'URB/IRP IDs, when exported, are used only in memory. Pairing is a capture-local association, not proof of delivery, firmware processing or host-triggered callback.',
            'Unmatched or ambiguous identifiers can arise from capture boundaries, dropped events, reused IDs or incomplete exports. Pairing requires equal endpoints.',
            'Known endpoint membership is a match to phase61 enumeration, not a signed OEM function or parser assignment.',
            'No installed-firmware hash, live RAM state, USB-to-WorkQueue callback, host pointer control, code execution or HAB bypass was established.',
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('csv', type=Path, help='Tshark -T fields CSV; strictly metadata only')
    parser.add_argument('--phase61', type=Path, default=Path('evidence/usb-enumeration-phase61.json'))
    parser.add_argument('--bus', type=int, required=True)
    parser.add_argument('--address', type=int, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.csv, json.loads(args.phase61.read_text(encoding='utf-8')),
                   args.bus, args.address)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(f"Phase79 metadata: {result['counts']['selected_urb_events']} selected URB events; "
          f"VID/PID {result['device_identity_in_selected_urbs']}; report {args.out}")


if __name__ == '__main__':
    main()
