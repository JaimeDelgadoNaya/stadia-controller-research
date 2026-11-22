"""Read-only structural analysis of USB descriptor candidates in a local binary.

No device access, USB traffic, firmware modification or arbitrary-code execution.
The audit proves static descriptor bytes ONLY; no host enumeration inference.
"""
import argparse
import hashlib
import json
from pathlib import Path

MAX_FILE = 32 * 1024 * 1024
MAX_CONFIG = 4096


def parse_device(data, offset):
    if not isinstance(data, bytes) or not (0 <= offset <= len(data) - 18):
        raise ValueError('Device descriptor out of range')
    d = data[offset:offset+18]
    if d[0:2] != b'\x12\x01' or d[7] not in (8, 16, 32, 64):
        raise ValueError('Invalid device descriptor header')
    u16 = lambda i: int.from_bytes(d[i:i+2], 'little')
    return dict(offset=hex(offset), bcdUSB=hex(u16(2)),
                device_class=d[4], device_subclass=d[5], device_protocol=d[6],
                ep0_max_packet=d[7], vid=f'{u16(8):04x}', pid=f'{u16(10):04x}',
                bcdDevice=hex(u16(12)), iManufacturer=d[14], iProduct=d[15],
                iSerialNumber=d[16], bNumConfigurations=d[17])


def parse_configuration(data, offset):
    if not isinstance(data, bytes) or not (0 <= offset <= len(data) - 9):
        raise ValueError('Configuration descriptor out of range')
    first = data[offset:offset+9]
    if first[:2] != b'\x09\x02':
        raise ValueError('Invalid configuration descriptor header')
    length = int.from_bytes(first[2:4], 'little')
    if length < 9 or length > MAX_CONFIG or offset + length > len(data):
        raise ValueError('Invalid wTotalLength or truncated configuration')
    config = data[offset:offset+length]
    descriptors=[]
    pos=0
    while pos < length:
        if pos + 2 > length:
            raise ValueError('Descriptor header truncated')
        size, typ = config[pos:pos+2]
        if size < 2 or pos + size > length:
            raise ValueError('Invalid descriptor bLength')
        part=config[pos:pos+size]
        item={'offset':hex(offset+pos),'length':size,'type':typ}
        if typ == 4:
            if size != 9:
                raise ValueError('Interface descriptor length')
            item.update(interface=part[2], alternate=part[3], endpoint_count=part[4],
                        class_code=part[5], subclass=part[6], protocol=part[7])
        elif typ == 5:
            if size != 7:
                raise ValueError('Endpoint descriptor length')
            item.update(endpoint=f'0x{part[2]:02x}', transfer=part[3] & 0x03,
                        max_packet_size=int.from_bytes(part[4:6], 'little') & 0x7ff)
        elif typ == 11:
            if size != 8:
                raise ValueError('IAD descriptor length')
            item.update(first_interface=part[2], interface_count=part[3])
        elif typ == 0x24:
            item['subtype']=part[2] if size > 2 else None
            if item['subtype']==6 and size>=5:
                item.update(cdc_union_master=part[3], cdc_union_slaves=list(part[4:]))
        descriptors.append(item)
        pos+=size
    interfaces=[x for x in descriptors if x['type']==4]
    endpoints=[x for x in descriptors if x['type']==5]
    grouped={}
    current=None
    errors=[]
    for item in descriptors:
        if item['type']==4:
            current=(item['interface'], item['alternate'])
            grouped[current]=[]
        elif item['type']==5:
            if current is None:
                errors.append('endpoint_before_interface')
            else:
                grouped[current].append(item['endpoint'])
    unique=set(x['interface'] for x in interfaces)
    if len(unique)!=first[4]:
        errors.append('interface_count_mismatch')
    for x in interfaces:
        eps=grouped[(x['interface'], x['alternate'])]
        if len(eps)!=x['endpoint_count']:
            errors.append('endpoint_count_mismatch')
        if len(set(eps))!=len(eps):
            errors.append('duplicate_endpoint_within_interface')
    unions=[x for x in descriptors if x.get('cdc_union_master') is not None]
    for u in unions:
        if u['cdc_union_master'] not in unique or any(s not in unique for s in u['cdc_union_slaves']):
            errors.append('cdc_union_references_unknown_interface')
    return dict(offset=hex(offset),total_length=length,interface_count_declared=first[4],
                interface_count_parsed=len(unique),iad_count=sum(x['type']==11 for x in descriptors),
                cdc_unions=[{'master':u['cdc_union_master'],'slaves':u['cdc_union_slaves']} for u in unions],
                interfaces=[{**x,'endpoints':grouped[(x['interface'],x['alternate'])]} for x in interfaces],
                endpoints=endpoints,descriptor_count=len(descriptors),errors=sorted(set(errors)))


def audit_candidate(data, device_offset, configuration_offset):
    device=parse_device(data,device_offset)
    cfg=parse_configuration(data,configuration_offset)
    return dict(kind='static_candidate_not_host_observation',
                size_bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),
                device=device,configuration=cfg,
                iad_class_triple_without_iad=(device['device_class'],device['device_subclass'],device['device_protocol'])==(0xef,2,1) and cfg['iad_count']==0,
                host_enumeration_verified=False,windows_driver_binding_verified=False,
                firmware_signature_verified=False,flashing_or_exploit_attempted=False)


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('binary',type=Path)
    p.add_argument('--device-offset',type=lambda s:int(s,0),required=True)
    p.add_argument('--configuration-offset',type=lambda s:int(s,0),required=True)
    args=p.parse_args(argv)
    if not args.binary.is_file() or args.binary.stat().st_size>MAX_FILE:
        p.error('Missing file or size limit exceeded')
    print(json.dumps(audit_candidate(args.binary.read_bytes(),args.device_offset,args.configuration_offset),indent=2,sort_keys=True))

if __name__=='__main__':
    main()
