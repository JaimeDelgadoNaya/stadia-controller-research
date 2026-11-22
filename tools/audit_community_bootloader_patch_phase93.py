"""Static differential audit of an OEM bootloader and a community CDC candidate.

Read-only file parser. It never communicates with a controller or modifies firmware.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

DEVICE_OFFSET = 0xBF78
CONFIG_OFFSET = 0x1527C
CODE_LENGTH_OFFSET = 0xAF4E
CONFIG_POINTER_OFFSET = 0xAF54
CSF_OFFSET = 0x18000
MAX_IMAGE = 2 * 1024 * 1024


def parse_ivt(data):
    if len(data) < 32 or data[0] != 0xD1 or data[1:3] != b"\x00\x20" or data[3] != 0x41:
        raise ValueError("Expected NXP IVT header at file offset zero")
    words = struct.unpack_from("<8I", data, 0)
    return {
        "entry": words[1], "dcd": words[3], "boot_data": words[4],
        "self": words[5], "csf": words[6]
    }


def parse_device_descriptor(data, offset=DEVICE_OFFSET):
    if offset < 0 or offset + 18 > len(data):
        raise ValueError("Device descriptor out of range")
    d = data[offset:offset + 18]
    if d[0] != 18 or d[1] != 1:
        raise ValueError("Invalid USB device descriptor")
    u16 = lambda i: int.from_bytes(d[i:i+2], "little")
    return {
        "offset": hex(offset), "bcdUSB": hex(u16(2)),
        "class": d[4], "subclass": d[5], "protocol": d[6],
        "ep0_max_packet": d[7], "vid": f"0x{u16(8):04x}",
        "pid": f"0x{u16(10):04x}", "bcdDevice": hex(u16(12)),
        "iManufacturer": d[14], "iProduct": d[15],
        "iSerialNumber": d[16], "bNumConfigurations": d[17]
    }


def parse_configuration(data, offset=CONFIG_OFFSET):
    if offset < 0 or offset + 9 > len(data):
        raise ValueError("Configuration descriptor out of range")
    h = data[offset:offset+9]
    if h[0:2] != b"\x09\x02":
        raise ValueError("Invalid configuration descriptor header")
    total = int.from_bytes(h[2:4], "little")
    if total < 9 or offset + total > len(data):
        raise ValueError("Invalid or truncated wTotalLength")
    block = data[offset:offset+total]
    desc = []
    pos = 0
    current = None
    endpoint_counts = {}
    interfaces = []
    endpoints = []
    iad = []
    unions = []
    while pos < total:
        if pos + 2 > total:
            raise ValueError("Truncated descriptor header")
        n, typ = block[pos], block[pos+1]
        if n < 2 or pos + n > total:
            raise ValueError("Invalid descriptor bLength")
        b = block[pos:pos+n]
        item = {"offset": hex(offset+pos), "length": n, "type": typ}
        if typ == 4:
            if n != 9:
                raise ValueError("Invalid interface descriptor length")
            current = (b[2], b[3])
            endpoint_counts[current] = 0
            item.update(interface=b[2], alternate=b[3], endpoint_count=b[4],
                        class_code=b[5], subclass=b[6], protocol=b[7])
            interfaces.append(item)
        elif typ == 5:
            if n != 7:
                raise ValueError("Invalid endpoint descriptor length")
            if current is None:
                raise ValueError("Endpoint before interface")
            endpoint_counts[current] += 1
            item.update(address=f"0x{b[2]:02x}", transfer=b[3] & 3,
                        max_packet=int.from_bytes(b[4:6], "little") & 0x7ff)
            endpoints.append(item)
        elif typ == 0x0B:
            if n != 8:
                raise ValueError("Invalid IAD descriptor length")
            item.update(first_interface=b[2], interface_count=b[3],
                        function_class=b[4], function_subclass=b[5],
                        function_protocol=b[6])
            iad.append(item)
        elif typ == 0x21:
            if n < 9:
                raise ValueError("Invalid HID descriptor length")
            item.update(report_descriptor_length=int.from_bytes(b[7:9], "little"))
        elif typ == 0x24:
            if n < 3:
                raise ValueError("Invalid CDC functional descriptor length")
            item["subtype"] = b[2]
            if b[2] == 6:
                if n < 5:
                    raise ValueError("Truncated CDC Union descriptor")
                item.update(master=b[3], slaves=list(b[4:]))
                unions.append(item)
        desc.append(item)
        pos += n
    declared = h[4]
    unique = {i["interface"] for i in interfaces}
    if len(unique) != declared:
        raise ValueError("bNumInterfaces does not match parsed interfaces")
    for i in interfaces:
        if endpoint_counts[(i["interface"], i["alternate"])] != i["endpoint_count"]:
            raise ValueError("Interface endpoint count mismatch")
    for u in unions:
        if u["master"] not in unique or any(s not in unique for s in u["slaves"]):
            raise ValueError("CDC Union references unknown interface")
    return {
        "offset": hex(offset), "total_length": total,
        "bNumInterfaces": declared, "descriptor_count": len(desc),
        "iad_count": len(iad), "interfaces": interfaces,
        "endpoints": endpoints,
        "cdc_unions": [{"master":u["master"],"slaves":u["slaves"]} for u in unions],
        "hid_report_descriptor_lengths": [
            x["report_descriptor_length"] for x in desc
            if x["type"] == 0x21 and "report_descriptor_length" in x
        ]
    }


def _ranges(indices):
    if not indices:
        return []
    out=[]
    start=previous=indices[0]
    for value in indices[1:]:
        if value != previous + 1:
            out.append([hex(start), hex(previous+1)])
            start=value
        previous=value
    out.append([hex(start), hex(previous+1)])
    return out


def audit(original, candidate):
    if not isinstance(original, bytes) or not isinstance(candidate, bytes):
        raise ValueError("Inputs must be byte strings")
    if len(original) > MAX_IMAGE or len(candidate) > MAX_IMAGE:
        raise ValueError("Image exceeds offline size limit")
    if len(original) < len(candidate):
        raise ValueError("Candidate is larger than OEM reference")
    o_ivt, c_ivt = parse_ivt(original), parse_ivt(candidate)
    o_dev = parse_device_descriptor(original)
    c_dev = parse_device_descriptor(candidate)
    o_cfg = parse_configuration(original)
    c_cfg = parse_configuration(candidate)
    overlap = len(candidate)
    changed = [i for i,(a,b) in enumerate(zip(original[:overlap],candidate)) if a != b]
    allowed = set(range(0x18,0x1c)) | {CODE_LENGTH_OFFSET} | set(
        range(CONFIG_OFFSET, CONFIG_OFFSET + max(o_cfg["total_length"],c_cfg["total_length"]))
    )
    outside = [i for i in changed if i not in allowed]
    code_o = original[CODE_LENGTH_OFFSET]
    code_c = candidate[CODE_LENGTH_OFFSET]
    ptr_o = struct.unpack_from("<I", original, CONFIG_POINTER_OFFSET)[0]
    ptr_c = struct.unpack_from("<I", candidate, CONFIG_POINTER_OFFSET)[0]
    csf_header = original[CSF_OFFSET:CSF_OFFSET+4]
    return {
        "kind":"static_oem_to_community_bootloader_differential",
        "original":{"size_bytes":len(original),"sha256":hashlib.sha256(original).hexdigest(),
                    "ivt":{k:hex(v) for k,v in o_ivt.items()},
                    "device":o_dev,"configuration":o_cfg},
        "candidate":{"size_bytes":len(candidate),"sha256":hashlib.sha256(candidate).hexdigest(),
                     "ivt":{k:hex(v) for k,v in c_ivt.items()},
                     "device":c_dev,"configuration":c_cfg},
        "diff":{"overlap_bytes":overlap,"changed_bytes":len(changed),
                "changed_ranges":_ranges(changed),
                "changed_outside_ivt_code_descriptor":len(outside),
                "tail_removed_bytes":len(original)-len(candidate)},
        "code_patch":{
            "file_offset":hex(CODE_LENGTH_OFFSET),
            "original_immediate":hex(code_o),"candidate_immediate":hex(code_c),
            "original_thumb_halfword":original[CODE_LENGTH_OFFSET-1:CODE_LENGTH_OFFSET+1].hex(),
            "candidate_thumb_halfword":candidate[CODE_LENGTH_OFFSET-1:CODE_LENGTH_OFFSET+1].hex(),
            "original_descriptor_length_constant":code_o,
            "candidate_descriptor_length_constant":code_c,
            "pointer_literal":hex(ptr_o),
            "pointer_unchanged":ptr_o==ptr_c==0x6081527C,
            "length_matches_configuration":code_o==o_cfg["total_length"] and code_c==c_cfg["total_length"]
        },
        "authentication":{
            "original_csf_pointer":hex(o_ivt["csf"]),
            "candidate_csf_pointer":hex(c_ivt["csf"]),
            "original_csf_header_at_0x18000":csf_header.hex(),
            "candidate_reaches_csf_offset":len(candidate)>CSF_OFFSET,
            "candidate_retains_original_csf_pointer":c_ivt["csf"]==o_ivt["csf"],
            "candidate_original_signature_verified":False,
            "candidate_hab_acceptance_verified":False
        },
        "checks":{
            "same_device_descriptor":o_dev==c_dev,
            "same_vid_pid":(o_dev["vid"],o_dev["pid"])==(c_dev["vid"],c_dev["pid"]),
            "only_ivt_csf_code_length_and_usb_configuration_changed":len(outside)==0,
            "candidate_csf_pointer_cleared":o_ivt["csf"]!=0 and c_ivt["csf"]==0,
            "original_csf_block_present":csf_header[:1]==b"\xd4",
            "candidate_truncated_before_original_csf":len(candidate)<CSF_OFFSET,
            "flash_safety_verified":False,
            "hardware_tested":False,
            "firmware_executed":False
        }
    }


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("original",type=Path)
    p.add_argument("candidate",type=Path)
    args=p.parse_args(argv)
    for f in (args.original,args.candidate):
        if not f.is_file() or f.stat().st_size>MAX_IMAGE:
            p.error(f"Missing or oversized file: {f}")
    print(json.dumps(audit(args.original.read_bytes(),args.candidate.read_bytes()),indent=2,sort_keys=True))


if __name__=="__main__":
    main()
