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
    0x60080000, 0x60100000
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
            stop="nonsequential_id"
            break
        entries.append({"id":words[6],"name":name,"record_offset":hex(off),
                        "raw_type_word":hex(words[1]),"raw_default_word":hex(words[2]),
                        "raw_flag_word":hex(words[4])})
        expected+=1
    else:
        stop="maximum_entries"
    return {"table_offset":hex(table_offset),"image_base":hex(image_base),
            "entry_size":ENTRY_SIZE,"entry_count":len(entries),
            "first_id":entries[0]["id"] if entries else None,
            "last_id":entries[-1]["id"] if entries else None,
            "stop_reason":stop,"entries":entries}


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
    by_name={x["name"]:x["id"] for x in entries}
    by_id={x["id"]:x["name"] for x in entries}
    literal_offsets={}
    for name in KEYS+MARKERS+HOSTS:
        literal_offsets[name]=find_offsets(data,name)
    base=int(registry["image_base"],16) if registry else None
    refs={}
    if base is not None:
        for name in ("YetiEnvironment","YetiDiscoUrl","YetiGmsgUrl",
                     "kvs_operations.cc","vendor_usb_task.cc",
                     "Missing key name","Failed to set value"):
            offs=find_offsets(data,name)
            refs[name]={
                off:pointer_references(data,base+int(off,16))
                for off in offs
            }
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
            "first_id":registry["first_id"] if registry else None,
            "last_id":registry["last_id"] if registry else None,
            "stop_reason":registry["stop_reason"] if registry else "not_found",
            "selected_id_to_name":{str(i):by_id.get(i) for i in (21,22,23,40,41,44)},
            "selected_name_to_id":{name:by_name.get(name) for name in KEYS}
        },
        "literal_offsets":literal_offsets,
        "pointer_references":refs,
        "limits":{
            "usb_vendor_set_kvs_call_chain_proven":False,
            "write_permissions_proven":False,
            "GMsg_URL_consumer_proven":False,
            "controller_accessed":False,
            "KVS_write_performed":False,
            "firmware_executed":False
        }
    }


def audit_pair(pvt_a, pvt_b, expected):
    a=audit_image(pvt_a,expected["pvt_a"]["git_blob_sha"],expected["pvt_a"]["size"])
    b=audit_image(pvt_b,expected["pvt_b"]["git_blob_sha"],expected["pvt_b"]["size"])
    return {
        "phase":94,"kind":"static_gotham_pvt_kvs_registry_and_url_audit",
        "source_repository":"StadiaMemories/firmware",
        "source_commit":"c86e2a397a747ce51c0988cd967142e5324ef0f9",
        "pvt_a":a,"pvt_b":b,
        "comparison":{
            "registry_found_in_both":a["registry"]["found"] and b["registry"]["found"],
            "registry_counts_equal":a["registry"]["entry_count"]==b["registry"]["entry_count"],
            "selected_key_ids_equal":a["registry"]["selected_name_to_id"]==b["registry"]["selected_name_to_id"],
            "YetiGmsgUrl_literal_in_a":bool(a["literal_offsets"]["YetiGmsgUrl"]),
            "YetiGmsgUrl_literal_in_b":bool(b["literal_offsets"]["YetiGmsgUrl"]),
            "YetiGmsgUrl_registry_entry_in_a":a["registry"]["selected_name_to_id"].get("YetiGmsgUrl") is not None,
            "YetiGmsgUrl_registry_entry_in_b":b["registry"]["selected_name_to_id"].get("YetiGmsgUrl") is not None
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
