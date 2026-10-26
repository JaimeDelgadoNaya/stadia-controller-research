"""Find potential producers of signed Bruce's 12-byte class configuration records.

Read-only. The OEM image's SHA-256 is mandatory. Tests initialized RAM and
signed XIP data for static triplets shaped as [callback, instance, descriptor].
A structural match does NOT prove an instantiated class10 EP0 receiver, a
USB-controlled address, execution, or a usable firmware patch.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from tools.audit_signed_app_surface import IMAGE_SHA256, IMAGE_SIZE, ASSUMED_XIP_BASE
from tools.audit_app_usb_dispatch import (
    DATA_SOURCE_OFFSET, DATA_DESTINATION, DATA_END
)

BASE = ASSUMED_XIP_BASE
SIGNED_LIMIT = BASE + 0xFF000
DATA_LENGTH = DATA_END - DATA_DESTINATION
CLASS_SELECTORS = (1, 2, 4, 10)

def le32(blob, off):
    if off<0 or off+4>len(blob):
        raise ValueError("outside available source bytes")
    return struct.unpack_from("<I",blob,off)[0]

def code_thumb(v):
    return v&1 and BASE <= (v&~1) < SIGNED_LIMIT

def signed_pointer(v):
    return BASE <= v < SIGNED_LIMIT

def ram_pointer(v):
    return 0x20000000 <= v < 0x21000000

def descriptor_class_byte(image, ptr):
    """Treat signed XIP or *boot-initialized* RAM as a hypothetical byte buffer.

    This does not establish that the pointer is a USB descriptor: it only
    bounds and reads the byte +4 which is used by the selected code path.
    """
    if signed_pointer(ptr) and ptr+4<SIGNED_LIMIT:
        return image[ptr-BASE+4], "XIP"
    if DATA_DESTINATION <= ptr < DATA_END-4:
        origin=DATA_SOURCE_OFFSET+(ptr-DATA_DESTINATION)
        return image[origin+4], "initialized_RAM_image"
    if ram_pointer(ptr):
        return None,"uninitialized_or_unmapped_RAM"
    return None,"not_a_signed_XIP_or_RAM_buffer"

def record_candidate(image, off, *, label):
    a,b,c=(le32(image,off+4*k) for k in range(3))
    if not code_thumb(a):
        return None
    if b!=0 and not ram_pointer(b):
        return None
    if not (signed_pointer(c) or ram_pointer(c)):
        return None
    value,kind=descriptor_class_byte(image,c)
    return {
      "source_label":label,
      "source_offset":hex(off),
      "source_xip":hex(BASE+off),
      "copied_to_ram":hex(DATA_DESTINATION+off-DATA_SOURCE_OFFSET)
          if DATA_SOURCE_OFFSET<=off<DATA_SOURCE_OFFSET+DATA_LENGTH else None,
      "candidate_callback_word":hex(a),
      "candidate_instance_output_word":hex(b),
      "candidate_descriptor_word":hex(c),
      "descriptor_byte_plus_4":value,
      "descriptor_storage":kind,
      "matches_class10_byte":value==10,
      "candidate_only":True
    }

def scan_range(image,start,end,*,label,max_examples=25):
    count=0
    matches=[]
    class_hist={}
    for off in range(start,end-11,4):
        obj=record_candidate(image,off,label=label)
        if obj is None:
            continue
        count+=1
        key="unresolved" if obj["descriptor_byte_plus_4"] is None else str(obj["descriptor_byte_plus_4"])
        class_hist[key]=class_hist.get(key,0)+1
        if len(matches)<max_examples or obj["matches_class10_byte"]:
            matches.append(obj)
    selected=[o for o in matches if o["matches_class10_byte"]]
    other=[o for o in matches if not o["matches_class10_byte"]]
    return {
      "scanned_start_offset":hex(start),"scanned_end_offset_exclusive":hex(end),
      "all_shape_matches":count,
      "class_byte_histogram":dict(sorted(class_hist.items())),
      "class10_shape_matches":sum(1 for off in range(start,end-11,4)
        if (t:=record_candidate(image,off,label=label)) is not None and t["matches_class10_byte"]),
      "class10_matches":selected[:max_examples],
      "non_class10_examples":other[:max_examples],
      "limits":"Candidate shapes only. Does not trace pointer stores or check executable dataflow."
    }

def classify_caller_pointer_locations(image):
    """Exact signed word census for configuration object and class10 handler.

    Base pointer is a whole-word immediate, so this census does not cover
    Thumb PC-relative address construction or registers at runtime.
    """
    words=[0x600550E5,0x60055321,0x600D0E59,
           0x60104B74,0x60104BA4,0x20004080,0x200040E0]
    out={}
    for val in words:
        raw=struct.pack("<I",val)
        offs=[o for o in range(0,0xFF030-3,4)
              if image[o:o+4]==raw]
        out[hex(val)]={"count":len(offs),"source_file_offsets":[hex(o) for o in offs[:24]]}
    return out

def inspect(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("Exact signed Bruce original SHA-256/length required")
    # XIP scan includes only the region with contiguous static configuration
    # tables and strings; data-copy ranges are separately scanned.
    return {
      "source":"Original OEM signed Bruce update; not physical flash readback",
      "sha256":IMAGE_SHA256,
      "sha256_verified":True,
      "search_model":"three signed 32-bit words: signed Thumb ptr, zero-or-RAM, signed XIP-or-RAM descriptor; descriptor byte +4 inspected",
      "signed_high_XIP_candidates":scan_range(image,0xB0000,0xFD000,label="signed_XIP_static_data"),
      "boot_initialized_RAM_candidates":scan_range(
          image,DATA_SOURCE_OFFSET,DATA_SOURCE_OFFSET+DATA_LENGTH,
          label="copied_initialized_RAM"),
      "literal_pointer_census":classify_caller_pointer_locations(image),
      "actual_writer_of_record_first_word":"UNRESOLVED",
      "synthetic_table_matching_implies_real_class10":"NO",
      "host_controlled_callback":"NOT PROVEN",
      "physical_usb_used":False,
      "firmware_written":False
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    args=p.parse_args()
    result=inspect(args.image.read_bytes())
    if args.out:
        args.out.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    for region in ("signed_high_XIP_candidates","boot_initialized_RAM_candidates"):
        r=result[region]
        print("REGION",region,
              "SHAPE_MATCHES",r["all_shape_matches"],
              "CLASS10_CANDIDATES",r["class10_shape_matches"])
        print("CLASS_BYTE_DISTRIBUTION",json.dumps(r["class_byte_histogram"]))
        print("CLASS10_EXAMPLES",json.dumps(r["class10_matches"]))
        print("OTHER_EXAMPLES",json.dumps(r["non_class10_examples"][:8]))
    print("CLASS TABLE SOURCE WORDS",json.dumps(result["literal_pointer_census"]))
    print("NO LIVE CALLBACK OR EXECUTION CLAIMS")

if __name__=="__main__":
    main()
