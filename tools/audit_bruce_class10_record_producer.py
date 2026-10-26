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
        if ptr-BASE+4>=len(image):
            return None, "signed_XIP_not_mapped_in_synthetic_fixture"
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


SIGNED_BOOT_RECORDS = (
    (0xFDF50,0x60061249,0x200030A0,2),
    (0xFDF5C,0x600613FD,0x20003100,10),
)

def confirmed_boot_records(image):
    """Verify two *adjacent* 12-byte records copied by authenticated startup.

    This attests bytes and class-selector byte only, NOT selection in physical
    hardware or that the record's first word is executed as a function.
    """
    result=[]
    for off, callback, descriptor, selector in SIGNED_BOOT_RECORDS:
        raw=[le32(image,off+4*i) for i in range(3)]
        if raw != [callback,0,descriptor]:
            raise ValueError("signed initialized class-callback record drift "+hex(off))
        class_byte,storage=descriptor_class_byte(image,descriptor)
        if class_byte!=selector or storage!="initialized_RAM_image":
            raise ValueError("signed class config descriptor guard drift")
        result.append({
          "source_file_offset":hex(off),
          "destination_boot_RAM":hex(DATA_DESTINATION+off-DATA_SOURCE_OFFSET),
          "callback_thumb_word":hex(callback),
          "class_object_initially_zero":True,
          "descriptor_RAM":hex(descriptor),
          "byte_at_descriptor_plus_4":class_byte,
          "callback_function_address":hex(callback&~1),
          "callback_runtime_invoked":"NOT VERIFIED"
        })
    if SIGNED_BOOT_RECORDS[1][0] != SIGNED_BOOT_RECORDS[0][0]+12:
        raise AssertionError("expected contiguous configuration records")
    return result

def focused_pointer_refs(image):
    values=[
        0x200030E8,0x200030F4,0x20003100,0x200030A0,0x2000312C,
        0x60061249,0x600613FD,0x600624F9,
    ]
    refs=[]
    for v in values:
        raw=struct.pack("<I",v)
        offsets=[o for o in range(0,0xFF030-3,4)
            if image[o:o+4]==raw]
        refs.append({"value":hex(v),"count":len(offsets),
                     "aligned_file_offsets":[hex(x) for x in offsets[:45]],
                     "boot_RAM_pointer_in_file": [
                        hex(DATA_DESTINATION+x-DATA_SOURCE_OFFSET)
                        for x in offsets if DATA_SOURCE_OFFSET<=x<DATA_SOURCE_OFFSET+DATA_LENGTH
                     ][:25],
                     "is_runtime_linkage_proof":False})
    return refs

def boot_copy_context(image,start=0xFDF28,stop=0xFDFA0):
    if start%4 or stop%4 or not DATA_SOURCE_OFFSET<=start<stop<=DATA_SOURCE_OFFSET+DATA_LENGTH:
        raise ValueError("invalid source data boundaries")
    return [{"source":hex(o),
             "boot_RAM":hex(DATA_DESTINATION+o-DATA_SOURCE_OFFSET),
             "word":hex(le32(image,o))}
            for o in range(start,stop,4)]

def class10_callback_thumb_preview(image,lo=0x600613FC,hi=0x60061540):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    if not BASE<=lo<hi<SIGNED_LIMIT:
        raise ValueError("original signed callback preview outside XIP")
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    return [{"pc":hex(i.address),"ins":i.mnemonic+" "+i.op_str}
            for i in md.disasm(image[lo-BASE:hi-BASE],lo)]


HANDLER_PINS={
  0x600613FC:("cmp","r1, #0x7f"),
  0x60061400:("bls","#0x60061422"),
  0x60061402:("ldr","r0, [pc, #0x24]"),
  0x60061404:("movw","r3, #0x3a38"),
  0x60061408:("ldr","r4, [pc, #0x20]"),
  0x6006140A:("ldr","r3, [r0, r3]"),
  0x6006140C:("cmp","r3, r4"),
  0x6006140E:("beq","#0x60061422"),
  0x60061410:("movw","r4, #0x3a3c"),
  0x60061414:("ldr","r0, [r0, r4]"),
  0x60061416:("blx","r3"),
  0x60061418:("uxtb","r0, r0"),
  0x6006141C:("it","ne"),
  0x60061420:("pop","{r4, pc}"),
  0x60061422:("movs","r0, #0"),
  0x60061424:("b","#0x60061420"),
}
PROVIDER_PINS={
  0x600610FC:("ldr","r0, [pc, #0]"),
  0x600610FE:("bx","lr"),
  0x60061104:("ldr","r0, [pc, #0]"),
  0x60061106:("bx","lr"),
}
def check_pins(decoded,expected):
    for pc,pair in expected.items():
        if decoded.get(pc)!=pair:
            raise ValueError("Original signed callback semantic drift at "+hex(pc)+
                             ": "+str(decoded.get(pc)))
    return True

def original_class10_handler_guard(image):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    def window(lo,hi):
        return {i.address:(i.mnemonic,i.op_str)
                for i in md.disasm(image[lo-BASE:hi-BASE],lo)}
    check_pins(window(0x600613FC,0x60061426),HANDLER_PINS)
    check_pins(window(0x600610FC,0x6006110C),PROVIDER_PINS)
    callback_base=le32(image,0x60061428-BASE)
    callback_sentinel=le32(image,0x6006142C-BASE)
    provider_words=[
       {"source":hex(p),"value":hex(le32(image,p-BASE))}
       for p in (0x60061100,0x60061108,0x600613F8)
    ]
    if any(p["value"]!="0x200030e8" for p in provider_words[:2]):
        raise ValueError("class2/class10 group getter pointer drift")
    if callback_base!=0x200064C0:
        raise ValueError("signed original class10 callback base literal drift")
    if callback_sentinel!=0x600D4F05:
        raise ValueError("signed original class10 callback sentinel literal drift")
    return {
       "original_semantic_pins_verified":len(HANDLER_PINS)+len(PROVIDER_PINS),
       "callback_thumb":"0x600613fd",
       "callback_code":"0x600613fc",
       "bRequest_unsigned_greater_than_0x7f_required":True,
       "bRequest_0x81_0x83_0x84_passes_first_gate":True,
       "global_base_from_pc_literal":hex(callback_base),
       "sentinel_word_from_pc_literal":hex(callback_sentinel),
       "registered_callback_word_address":hex(callback_base+0x3a38),
       "registered_context_word_address":hex(callback_base+0x3a3c),
       "callback_pointer_read_at":"0x6006140a",
       "callback_pointer_compared_to_sentinel_at":"0x6006140c",
       "indirect_callback_not_executed":"0x60061416 BLX R3",
       "group_source_getter_raw_literals":provider_words[:2],
       "unverified_extra_neighbor_word":provider_words[2],
       "registered_callback_runtime_value":"UNMEASURED",
       "host_can_replace_registered_callback":"NOT DEMONSTRATED"
    }

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
      "pinned_contiguous_boot_records":confirmed_boot_records(image),
      "class10_handler_verified_control_gate":original_class10_handler_guard(image),
      "focused_record_pointer_refs":focused_pointer_refs(image),
      "boot_copy_words_around_class10":boot_copy_context(image),
      "class10_callback_original_thumb_preview":class10_callback_thumb_preview(image),
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
    print("PINNED CONTIGUOUS BOOT RECORDS",json.dumps(result["pinned_contiguous_boot_records"]))
    print("FOCUSED RECORD POINTER XREFS",json.dumps(result["focused_record_pointer_refs"]))
    print("BOOT CLASS10 WORD CONTEXT",json.dumps(result["boot_copy_words_around_class10"][:35]))
    print("CLASS10 INDIRECT CALLBACK GUARD",json.dumps(result["class10_handler_verified_control_gate"]))
    print("REAL CLASS10 CALLBACK THUMB",json.dumps(result["class10_callback_original_thumb_preview"][:30]))
    print("CLASS TABLE SOURCE WORDS",json.dumps(result["literal_pointer_census"]))
    print("NO LIVE CALLBACK OR EXECUTION CLAIMS")

if __name__=="__main__":
    main()
