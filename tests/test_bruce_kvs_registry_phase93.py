"""Synthetic parser tests plus an optional exact-hash Bruce image audit."""
import os
import struct
import unittest
from pathlib import Path

from tools.audit_bruce_kvs_registry_phase93 import (
    EXPECTED_SHA256, IMAGE_BASE, audit, parse_registry
)

NAMES = [f"Key{i:02d}" for i in range(67)]
NAMES[20]="AnalyticsOptIn"
NAMES[21]="LastKnownSntp"
NAMES[22]="IsDfDevice"
NAMES[23]="UpdateGauge"
NAMES[24]="OtaFromBuild"
NAMES[39]="AppImageFdrVer"
NAMES[40]="BootImageFdrVer"
NAMES[41]="HidOverGatt"
NAMES[42]="SupportNoBat"
NAMES[43]="LogToUart"


def synthetic_image():
    data=bytearray(0x5000)
    table=0x100
    string_off=0x2000
    for idx,name in enumerate(NAMES):
        encoded=name.encode("ascii")+b"\x00"
        ptr=IMAGE_BASE+string_off
        struct.pack_into("<8I",data,table+idx*0x20,
                         idx,0x01000001,ptr,0,0,1,0,0)
        data[string_off:string_off+len(encoded)]=encoded
        string_off+=len(encoded)
    return bytes(data)


class BruceKvsRegistryPhase93(unittest.TestCase):
    def test_synthetic_registry_has_sequential_ids(self):
        r=parse_registry(synthetic_image(),table_offset=0x100)
        self.assertEqual(r["entry_count"],67)
        self.assertEqual((r["first_id"],r["last_id"]),(0,66))
        self.assertEqual(r["stop_reason"],"name_pointer_out_of_image")

    def test_synthetic_key_mapping(self):
        r=parse_registry(synthetic_image(),table_offset=0x100)
        mapping={x["id"]:x["name"] for x in r["entries"]}
        self.assertEqual(mapping[20],"AnalyticsOptIn")
        self.assertEqual(mapping[21],"LastKnownSntp")
        self.assertEqual(mapping[22],"IsDfDevice")
        self.assertEqual(mapping[39],"AppImageFdrVer")
        self.assertEqual(mapping[43],"LogToUart")

    def test_nonsequential_id_stops_table(self):
        data=bytearray(synthetic_image())
        struct.pack_into("<I",data,0x100+4*0x20,99)
        r=parse_registry(bytes(data),table_offset=0x100)
        self.assertEqual(r["entry_count"],4)
        self.assertEqual(r["stop_reason"],"nonsequential_id")

    def test_bad_name_pointer_stops_table(self):
        data=bytearray(synthetic_image())
        struct.pack_into("<I",data,0x100+8,0x100)
        with self.assertRaisesRegex(ValueError,"No sequential"):
            parse_registry(bytes(data),table_offset=0x100)

    def test_pinned_hash_rejects_other_image(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            audit(synthetic_image(),EXPECTED_SHA256)

    @unittest.skipUnless(os.environ.get("STADIA_BRUCE_IMAGE"),
                         "exact public Bruce image supplied by CI workflow")
    def test_exact_bruce_production_image_registry(self):
        image=Path(os.environ["STADIA_BRUCE_IMAGE"]).read_bytes()
        r=audit(image)
        self.assertEqual(r["registry_table"]["entry_count"],67)
        self.assertEqual(r["selected_id_to_name"]["20"],"AnalyticsOptIn")
        self.assertEqual(r["selected_id_to_name"]["21"],"LastKnownSntp")
        self.assertEqual(r["selected_id_to_name"]["22"],"IsDfDevice")
        self.assertEqual(r["selected_id_to_name"]["39"],"AppImageFdrVer")
        self.assertEqual(r["selected_id_to_name"]["43"],"LogToUart")
        self.assertFalse(r["yeti_ascii_literals"]["YetiGmsgUrl"])
        self.assertFalse(r["limits"]["gotham_registry_verified"])


if __name__=="__main__":
    unittest.main()
