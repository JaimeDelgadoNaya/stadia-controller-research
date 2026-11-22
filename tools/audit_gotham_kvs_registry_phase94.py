"""Offline static KVS/URL audit of pinned public Gotham PVT-A/PVT-B images.

The workflow downloads public images to a temporary runner directory, verifies Git
blob IDs, emits only hashes, offsets, string presence and bounded registry metadata,
then deletes the binaries. No controller I/O or KVS writes.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

MAX_IMAGE = 8 * 1024 * 1024
ENTRY_SIZE = 0x20
MAX_ENTRIES = 256
IMAGE_BASE_CANDIDATES = (
    0x60040000, 0x60000000, 0x60800000, 0x20000000,
    0x60080000, 0x60100000, 0x60020000, 0x60140000
)
KEYS = (
    "YetiEnvironment", "YetiDiscoUrl", "YetiGmsgUrl", "IsDfDevice",
    "AppImageFdrVer", "BootImageFdrVer", "UpdateGauge", "OtaFromBuild",
    "AnalyticsOptIn", "LastKnownSntp"
)
MARKERS = (
    "kvs_operations.cc", "vendor_usb_task.cc", "firmware_image_upload.cc",
    "Missing key name", "Failed to set value", "UNKNOWN KVS KEY TYPE",
    "FVCResponse", "VendorUsbTask"
)
HOSTS = (
    "cloudcast-pa.googleapis.com", "cloudcast-gmsg-prod.googleapis.com",
    "play.googleapis.com", "time.google.com",
    "connectivitycheck.gstatic.com", "clients3.google.com"
)


def git_blob_sha1(data):
    header = b"blob " + str(len(data)).encode("ascii") + b"\x00"
    return hashlib.sha1(header + data).hexdigest()


def find_offsets(data, token, encoding="ascii", limit=8):
    needle = token.encode(encoding)
    out=[]
    start=0
    while len(out)<limit:
        pos=data.find(needle,start)
        if pos<0:
            break
        out.append(hex(pos))
        start=pos+1
    return out


def _read_ascii_name(data, offset):
    if offset < 0 or offset >= len(data):
        return None
    end=data.find(b"\x00",offset,min(len(data),offset+96))
    if end<0:
        return None
    raw=data[offset:end]
    if not raw or any(b<0x20 or b>0x7e for b in raw):
        return None
    return raw.decode("ascii")


def parse_registry_at(data, table_offset, image_base):
    entries=[]
    expected=1
    stop="maximum_entries"
    for idx in range(MAX_ENTRIES):
        off=table_offset+idx*ENTRY_SIZE
        if off+ENTRY_SIZE>len(data):
            stop="end_of_file"
            break
        words=struct.unpack_from("<8I",data,off)
        name=_read_ascii_name(data,words[0]-image_base)
        if name is None:
            stop="invalid_name_pointer"
            break
        if words[6]!=expected:
            stop="nonsequential_table_word6"
            break
        entries.append({
            "record_sequence":expected,
            "table_word6":words[6],
            "name":name,
            "record_offset":hex(off),
            "raw_type_word":hex(words[1]),
            "raw_default_word":hex(words[2]),
            "raw_flag_word":hex(words[4])
        })
        expected+=1
    else:
        stop="maximum_entries"
    next_off=table_offset+len(entries)*ENTRY_SIZE
    next_preview=None
    if next_off+ENTRY_SIZE<=len(data):
        w=struct.unpack_from("<8I",data,next_off)
        candidate_name=_read_ascii_name(data,w[0]-image_base)
        next_preview={
            "record_offset":hex(next_off),
            "name_pointer":hex(w[0]),
            "name_candidate":candidate_name,
            "table_word6":hex(w[6]),
            "continues_expected_sequence":w[6]==len(entries)+1 and candidate_name is not None
        }
    return {
        "table_offset":hex(table_offset),"image_base":hex(image_base),
        "entry_size":ENTRY_SIZE,"entry_count":len(entries),
        "first_table_word6":entries[0]["table_word6"] if entries else None,
        "last_table_word6":entries[-1]["table_word6"] if entries else None,
        "stop_reason":stop,"next_record_preview":next_preview,"entries":entries
    }


def find_registry(data, bases=IMAGE_BASE_CANDIDATES):
    candidates=[]
    for base in bases:
        for off in range(0, len(data)-ENTRY_SIZE, 4):
            if struct.unpack_from("<I",data,off+24)[0] != 1:
                continue
            name_ptr=struct.unpack_from("<I",data,off)[0]
            if _read_ascii_name(data,name_ptr-base) is None:
                continue
            parsed=parse_registry_at(data,off,base)
            if parsed["entry_count"]>=8:
                candidates.append(parsed)
    if not candidates:
        return None
    candidates.sort(key=lambda x:(x["entry_count"],x["entry_size"]),reverse=True)
    return candidates[0]


def pointer_references(data, address, limit=16):
    needle=struct.pack("<I",address)
    out=[]
    start=0
    while len(out)<limit:
        pos=data.find(needle,start)
        if pos<0:
            break
        out.append(hex(pos))
        start=pos+1
    return out


def _diff_summary(a,b,limit=24):
    if len(a)!=len(b):
        return {"same_size":False,"size_a":len(a),"size_b":len(b),"changed_bytes":None,"changed_ranges":[]}
    changed=[i for i,(x,y) in enumerate(zip(a,b)) if x!=y]
    ranges=[]
    if changed:
        start=previous=changed[0]
        for v in changed[1:]:
            if v!=previous+1:
                ranges.append([hex(start),hex(previous+1)])
                if len(ranges)>=limit:
                    break
                start=v
            previous=v
        if len(ranges)<limit:
            ranges.append([hex(start),hex(previous+1)])
    return {"same_size":True,"size_a":len(a),"size_b":len(b),
            "changed_bytes":len(changed),"changed_ranges":ranges,
            "ranges_truncated":len(ranges)>=limit}


def audit_image(path, expected_git_blob_sha=None, expected_size=None):
    path=Path(path)
    if not path.is_file() or path.stat().st_size>MAX_IMAGE:
        raise ValueError("Missing or oversized Gotham image")
    data=path.read_bytes()
    if expected_size is not None and len(data)!=expected_size:
        raise ValueError("Gotham image size mismatch")
    blob=git_blob_sha1(data)
    if expected_git_blob_sha and blob!=expected_git_blob_sha:
        raise ValueError("Gotham Git blob SHA-1 mismatch")
    registry=find_registry(data)
    entries=registry["entries"] if registry else []
    by_name={x["name"]:x for x in entries}
    by_sequence={x["record_sequence"]:x["name"] for x in entries}
    literal_offsets={}
    for name in KEYS+MARKERS+HOSTS:
        literal_offsets[name]=find_offsets(data,name)
    base=int(registry["image_base"],16) if registry else None
    pointer_refs_by_base={}
    for candidate_base in IMAGE_BASE_CANDIDATES:
        refs={}
        for name in ("YetiEnvironment","YetiDiscoUrl","YetiGmsgUrl",
                     "kvs_operations.cc","vendor_usb_task.cc",
                     "Missing key name","Failed to set value"):
            offsets=find_offsets(data,name,limit=2)
            for off in offsets:
                found=pointer_references(data,candidate_base+int(off,16))
                if found:
                    refs.setdefault(name,{})[off]=found
        if refs:
            pointer_refs_by_base[hex(candidate_base)]=refs
    selected_names={name:by_name.get(name,{}).get("table_word6") for name in KEYS}
    selected_zero_based={name:(value-1 if value is not None else None)
                         for name,value in selected_names.items()}
    selected_sequence={str(i):by_sequence.get(i) for i in (21,22,23,40,41,44,45,46)}
    return {
        "file":path.name,"size_bytes":len(data),
        "sha256":hashlib.sha256(data).hexdigest(),
        "git_blob_sha1":blob,
        "registry":{
            "found":registry is not None,
            "table_offset":registry["table_offset"] if registry else None,
            "image_base":registry["image_base"] if registry else None,
            "entry_size":registry["entry_size"] if registry else None,
            "entry_count":registry["entry_count"] if registry else 0,
            "first_table_word6":registry["first_table_word6"] if registry else None,
            "last_table_word6":registry["last_table_word6"] if registry else None,
            "stop_reason":registry["stop_reason"] if registry else "not_found",
            "next_record_preview":registry["next_record_preview"] if registry else None,
            "record_sequence_to_name":selected_sequence,
            "selected_name_to_table_word6":selected_names,
            "selected_name_to_zero_based_candidate_id":selected_zero_based
        },
        "literal_offsets":literal_offsets,
        "pointer_references_by_base":pointer_refs_by_base,
        "limits":{
            "table_word6_is_runtime_registry_id_proven":False,
            "zero_based_candidate_mapping_proven":False,
            "usb_vendor_set_kvs_call_chain_proven":False,
            "write_permissions_proven":False,
            "GMsg_URL_consumer_proven":False,
            "controller_accessed":False,
            "KVS_write_performed":False,
            "firmware_executed":False
        }
    }


def audit_pair(pvt_a, pvt_b, expected):
    data_a=Path(pvt_a).read_bytes()
    data_b=Path(pvt_b).read_bytes()
    a=audit_image(pvt_a,expected["pvt_a"]["git_blob_sha"],expected["pvt_a"]["size"])
    b=audit_image(pvt_b,expected["pvt_b"]["git_blob_sha"],expected["pvt_b"]["size"])
    return {
        "phase":94,"kind":"static_gotham_pvt_kvs_registry_and_url_audit",
        "source_repository":"StadiaMemories/firmware",
        "source_commit":"c86e2a397a747ce51c0988cd967142e5324ef0f9",
        "pvt_a":a,"pvt_b":b,
        "image_diff":_diff_summary(data_a,data_b),
        "comparison":{
            "registry_found_in_both":a["registry"]["found"] and b["registry"]["found"],
            "registry_counts_equal":a["registry"]["entry_count"]==b["registry"]["entry_count"],
            "selected_table_word6_equal":a["registry"]["selected_name_to_table_word6"]==b["registry"]["selected_name_to_table_word6"],
            "YetiGmsgUrl_literal_in_a":bool(a["literal_offsets"]["YetiGmsgUrl"]),
            "YetiGmsgUrl_literal_in_b":bool(b["literal_offsets"]["YetiGmsgUrl"]),
            "YetiGmsgUrl_table_entry_in_a":a["registry"]["selected_name_to_table_word6"].get("YetiGmsgUrl") is not None,
            "YetiGmsgUrl_table_entry_in_b":b["registry"]["selected_name_to_table_word6"].get("YetiGmsgUrl") is not None,
            "zero_based_claim_alignment_in_a":{
                "YetiEnvironment":a["registry"]["selected_name_to_zero_based_candidate_id"].get("YetiEnvironment")==21,
                "YetiDiscoUrl":a["registry"]["selected_name_to_zero_based_candidate_id"].get("YetiDiscoUrl")==22,
                "AppImageFdrVer":a["registry"]["selected_name_to_zero_based_candidate_id"].get("AppImageFdrVer")==44
            }
        },
        "safety":{
            "binaries_committed":False,"raw_strings_dumped":False,
            "device_accessed":False,"vendor_usb_command_sent":False,
            "KVS_written":False,"firmware_executed":False
        }
    }


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("pvt_a",type=Path)
    p.add_argument("pvt_b",type=Path)
    p.add_argument("--pvt-a-blob",required=True)
    p.add_argument("--pvt-b-blob",required=True)
    p.add_argument("--expected-size",type=int,default=4163944)
    args=p.parse_args(argv)
    expected={"pvt_a":{"git_blob_sha":args.pvt_a_blob,"size":args.expected_size},
              "pvt_b":{"git_blob_sha":args.pvt_b_blob,"size":args.expected_size}}
    print(json.dumps(audit_pair(args.pvt_a,args.pvt_b,expected),indent=2,sort_keys=True))


if __name__=="__main__":
    main()
