"""Synthetic-only tests for the Gotham KVS scanner; real PVT binaries run in CI."""
import struct
import tempfile
import unittest
from pathlib import Path

from tools.audit_gotham_kvs_registry_phase94 import (
    IMAGE_BASE_CANDIDATES, audit_image, audit_pair, find_registry,
    git_blob_sha1, pointer_references
)

BASE=0x60040000
NAMES=[f"Setting{i:03d}" for i in range(1,116)]
NAMES[20]="YetiEnvironment"
NAMES[21]="YetiDiscoUrl"
NAMES[22]="IsDfDevice"
NAMES[43]="AppImageFdrVer"
NAMES[44]="BootImageFdrVer"
NAMES[45]="YetiGmsgUrl"  # in this fixture it is a registry entry only if intentionally included


def make_image(include_gmsg_in_registry=False):
    data=bytearray(0x9000)
    table=0x100
    string_off=0x4000
    names=NAMES.copy()
    if not include_gmsg_in_registry:
        names[45]="Setting046"
    for idx,name in enumerate(names,1):
        raw=name.encode("ascii")+b"\x00"
        ptr=BASE+string_off
        struct.pack_into("<8I",data,table+(idx-1)*0x20,
                         ptr,0x01000001,0,0,1,0,idx,0)
        data[string_off:string_off+len(raw)]=raw
        string_off+=len(raw)
    # Standalone literal can exist without a registry entry.
    if not include_gmsg_in_registry:
        raw=b"YetiGmsgUrl\x00"
        data[0x7000:0x7000+len(raw)]=raw
    return bytes(data)


class GothamKvsPhase94(unittest.TestCase):
    def test_git_blob_sha1_uses_git_header(self):
        self.assertEqual(git_blob_sha1(b"hello\n"),"ce013625030ba8dba906f756967f9e9ca394464a")

    def test_finds_115_entry_registry(self):
        r=find_registry(make_image())
        self.assertIsNotNone(r)
        self.assertEqual(r["entry_count"],115)
        self.assertEqual(r["first_id"],1)
        self.assertEqual(r["last_id"],115)
        self.assertEqual(r["image_base"],hex(BASE))

    def test_extracts_yeti_keys_and_ids(self):
        r=find_registry(make_image())
        mapping={x["name"]:x["id"] for x in r["entries"]}
        self.assertEqual(mapping["YetiEnvironment"],21)
        self.assertEqual(mapping["YetiDiscoUrl"],22)
        self.assertEqual(mapping["IsDfDevice"],23)
        self.assertEqual(mapping["AppImageFdrVer"],44)
        self.assertNotIn("YetiGmsgUrl",mapping)

    def test_literal_can_exist_without_registry_entry(self):
        data=make_image()
        self.assertIn(b"YetiGmsgUrl\x00",data)
        r=find_registry(data)
        mapping={x["name"]:x["id"] for x in r["entries"]}
        self.assertNotIn("YetiGmsgUrl",mapping)

    def test_pointer_references_are_reported(self):
        data=make_image()
        r=find_registry(data)
        entry=next(x for x in r["entries"] if x["name"]=="YetiEnvironment")
        off=int(entry["record_offset"],16)
        ptr=struct.unpack_from("<I",data,off)[0]
        refs=pointer_references(data,ptr)
        self.assertIn(hex(off),refs)

    def test_no_registry_is_a_supported_result(self):
        r=find_registry(b"\x00"*0x2000)
        self.assertIsNone(r)

    def test_audit_pair_pins_both_git_blobs(self):
        a=make_image()
        b=make_image()
        with tempfile.TemporaryDirectory() as tmp:
            pa=Path(tmp)/"a.bin";pb=Path(tmp)/"b.bin"
            pa.write_bytes(a);pb.write_bytes(b)
            expected={"pvt_a":{"git_blob_sha":git_blob_sha1(a),"size":len(a)},
                      "pvt_b":{"git_blob_sha":git_blob_sha1(b),"size":len(b)}}
            r=audit_pair(pa,pb,expected)
            self.assertTrue(r["comparison"]["registry_found_in_both"])
            self.assertEqual(r["pvt_a"]["registry"]["entry_count"],115)
            self.assertTrue(r["comparison"]["YetiGmsgUrl_literal_in_a"])
            self.assertFalse(r["comparison"]["YetiGmsgUrl_registry_entry_in_a"])

    def test_wrong_git_blob_hash_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/"a.bin";p.write_bytes(make_image())
            with self.assertRaisesRegex(ValueError,"Git blob SHA-1"):
                audit_image(p,expected_git_blob_sha="0"*40)


if __name__=="__main__":
    unittest.main()
