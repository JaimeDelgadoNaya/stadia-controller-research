"""Parse the KVS name/ID table in one exact signed Bruce production image.

This is NOT a Gotham registry parser. No device I/O, KVS writes or firmware execution.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

EXPECTED_SHA256 = "466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3"
IMAGE_BASE = 0x60040000
TABLE_OFFSET = 0xC3C60
ENTRY_SIZE = 0x20
MAX_ENTRIES = 128
SELECTED_IDS = (21,22,23,24,25,40,41,42,43,44)


def parse_registry(data, table_offset=TABLE_OFFSET, image_base=IMAGE_BASE):
    if not isinstance(data, bytes) or table_offset < 0:
        raise ValueError("Invalid input")
    entries=[]
    expected_id=1
    stop_reason="maximum_entries"
    for index in range(MAX_ENTRIES):
        off=table_offset+index*ENTRY_SIZE
        if off+ENTRY_SIZE>len(data):
            stop_reason="end_of_file"
            break
        words=struct.unpack_from("<8I",data,off)
        name_ptr=words[0]
        name_off=name_ptr-image_base
        if name_off<0 or name_off>=len(data):
            stop_reason="name_pointer_out_of_image"
            break
        end=data.find(b"\x00",name_off,min(len(data),name_off+96))
        if end<0:
            stop_reason="unterminated_name"
            break
        raw_name=data[name_off:end]
        if not raw_name or any(c<0x20 or c>0x7e for c in raw_name):
            stop_reason="non_ascii_or_empty_name"
            break
        if words[6] != expected_id:
            stop_reason="nonsequential_id"
            break
        entries.append({
            "id":words[6],
            "name":raw_name.decode("ascii"),
            "raw_type_word":hex(words[1]),
            "raw_default_word":hex(words[2]),
            "raw_flag_word":hex(words[4]),
            "record_offset":hex(off)
        })
        expected_id+=1
    else:
        stop_reason="maximum_entries"
    if not entries:
        raise ValueError("No sequential KVS name/ID entries found")
    return {"table_offset":hex(table_offset),"entry_size":ENTRY_SIZE,
            "entry_count":len(entries),"first_id":entries[0]["id"],
            "last_id":entries[-1]["id"],"stop_reason":stop_reason,
            "entries":entries}


def audit(data, expected_sha256=EXPECTED_SHA256):
    digest=hashlib.sha256(data).hexdigest()
    if expected_sha256 and digest!=expected_sha256:
        raise ValueError("Input SHA-256 does not match the pinned Bruce production image")
    registry=parse_registry(data)
    by_id={e["id"]:e["name"] for e in registry["entries"]}
    names={e["name"]:e["id"] for e in registry["entries"]}
    selected={str(i):by_id.get(i) for i in SELECTED_IDS}
    return {
        "kind":"static_bruce_kvs_name_id_table_not_gotham",
        "size_bytes":len(data),"sha256":digest,
        "registry_table":{k:v for k,v in registry.items() if k!="entries"},
        "selected_id_to_name":selected,
        "selected_name_to_id":{
            key:names.get(key) for key in
            ("IsDfDevice","AnalyticsOptIn","LastKnownSntp","AppImageFdrVer","LogToUart")
        },
        "yeti_ascii_literals":{
            key:(key.encode("ascii") in data) for key in
            ("YetiEnvironment","YetiDiscoUrl","YetiGmsgUrl")
        },
        "limits":{
            "gotham_registry_verified":False,
            "usb_vendor_set_kvs_call_chain_verified":False,
            "writer_permissions_verified":False,
            "real_kvs_write_performed":False,
            "device_accessed":False
        }
    }


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--expected-sha256",default=EXPECTED_SHA256)
    args=p.parse_args(argv)
    if not args.image.is_file():
        p.error("Image file not found")
    print(json.dumps(audit(args.image.read_bytes(),args.expected_sha256),indent=2,sort_keys=True))


if __name__=="__main__":
    main()
