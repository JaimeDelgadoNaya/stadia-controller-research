"""Phase 57: OEM signed constructor -> post-init call -> +0x80 reader provenance.

Do not equate same register spelling across functions. This auditor first
verifies the signed caller: an allocation-like return is saved as R4,
passed to constructor, and passed as R0 to post-initialization. It then
examines signed, bounded reader neighborhoods, recording whether their
base register can be shown to derive from the post-init R0.

No hardware USB or flash writes; no installed RAM sample.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SHA256, IMAGE_SIZE, ASSUMED_XIP_BASE, decode_thumb_bl_target
from tools.audit_bruce_ep0_registration import decode
from tools.audit_bruce_parent_r0_phase56 import prove_r0_producer, offset_reader
from tools.audit_app_usb_dispatch import ITCM_SOURCE_OFFSET, ITCM_LENGTH
from tools.audit_bruce_parent_r0_phase56 import itcm_rows

CALLER_START=0x60079D74
CTOR_CALL=0x60079D84
POST_INIT_CALL=0x60079D9A
POST_INIT_ENTRY=0x6007E784
CANDIDATE_READERS=(0x6007E7EA,0x6007E810,0x6007E9A4)

# Known signed source site + call from prior phase 56. These pins ensure
# the producer's R4 really survives until passed to the next routine.
CALLER_PINS={
    0x60079D74:("movs","r0, #0xa4"),
    0x60079D76:("bl","#0x6013d378"),
    0x60079D7E:("mov","r4, r0"),
    0x60079D84:("bl","#0x6007eb8c"),
    0x60079D90:("bl","#0x6013d3c8"),
    0x60079D96:("mov","r0, r4"),
    0x60079D98:("str","r3, [r4, #0x68]"),
    0x60079D9A:("bl","#0x6007e784"),
}
GLOBAL_CHAIN_PINS={
    0x60079D9E:("tst.w","r0, #0xff"),
    0x60079DA2:("beq","#0x60079dba"),
    0x60079DBA:("mov","r1, r4"),
    0x60079DBC:("ldr","r0, [pc, #0x24]"),
    0x60079DBE:("bl","#0x60079c6c"),
    0x60079C50:("ldr","r1, [pc, #0x14]"),
    0x60079C52:("ldr","r3, [r1], #4"),
    0x60079C5A:("str","r3, [r0], #4"),
    0x60079C70:("mov","r6, r0"),
    0x60079C74:("mov","r4, r1"),
    0x60079C78:("str","r1, [sp]"),
    0x60079CD2:("ldr","r3, [sp]"),
    0x60079CD8:("str","r3, [r6]"),
}
GLOBAL_GETTER_LITERAL_SITE=0x60079C68
GLOBAL_PRODUCER_LITERAL_SITE=0x60079DE4


def verify_global_chain(image):
    """Same signed GLOBAL address; dynamic value depends on runtime.

    The writer saves incoming R1 (caller R4), then reads it from its
    stack local into R3 and STRs it to [R6] (incoming global R0).
    Getter later copies the first word of that same global into
    caller-provided [R0], then the caller loads [SP] for reader R0.
    No temporal ordering or live RAM identity is inferred.
    """
    pins=verify_pins(image,GLOBAL_CHAIN_PINS,[
        (0x60079D9E,0x60079DC2),
        (0x60079C50,0x60079C5E),
        (0x60079C6C,0x60079C7C),
        (0x60079CD2,0x60079CDA),
    ])
    source=struct.unpack_from("<I",image,
                   GLOBAL_PRODUCER_LITERAL_SITE-ASSUMED_XIP_BASE)[0]
    getter=struct.unpack_from("<I",image,
                   GLOBAL_GETTER_LITERAL_SITE-ASSUMED_XIP_BASE)[0]
    if source!=getter:
        raise ValueError(
          f"phase57 global holder mismatch: writer={source:#x}, getter={getter:#x}"
        )
    if not 0x20000000<=source<0x20040000:
        raise ValueError("phase57 global holder not in expected SRAM range")
    return {
        "pinned_signed_instructions":pins,
        "writer_literal_file_address":hex(GLOBAL_PRODUCER_LITERAL_SITE),
        "getter_literal_file_address":hex(GLOBAL_GETTER_LITERAL_SITE),
        "same_global_RAM_address":hex(source),
        "producer":"0x60079dba R1=R4; 0x60079dbe BL 0x60079c6c; 0x60079cd8 STR R3,[R6]",
        "saved_value":"R1 input (caller R4) via [SP] at 0x60079c78 and 0x60079cd2",
        "getter":"0x60079c50 reads [GLOBAL] and writes to argument buffer",
        "consumer":"0x60074da4 loads saved [SP], passes R0 to 0x6007e794",
        "identity":"SAME_STATIC_GLOBAL_ADDRESS; RUNTIME_VALUE_AND_ORDER_UNMEASURED",
        "on_hardware":"UNVERIFIED",
    }


SUPPLIER_PINS={
    0x60074D8C:("push","{r0, r1, r2, r4, r5, lr}"),
    0x60074D92:("mov","r0, sp"),
    0x60074D94:("bl","#0x60079c50"),
    0x60074DA4:("ldr","r0, [sp]"),
    0x60074DA6:("cbz","r0, #0x60074dae"),
    0x60074DA8:("movs","r1, #1"),
    0x60074DAA:("bl","#0x6007e794"),
}
READ_PINS={
    0x6007E7EA:("ldr.w","r0, [r0, #0x80]"),
    0x6007E810:("ldr.w","r0, [r4, #0x80]"),
    0x6007E9A4:("ldr.w","r0, [r4, #0x80]"),
}
POST_INIT_WRAPPER_PINS={
    0x6007E784:("movs","r2, #0x1b"),
    0x6007E786:("ldr","r1, [pc, #8]"),
    0x6007E788:("adds","r0, #0xc"),
    0x6007E78A:("b.w","#0x6010177a"),
}
READER_ENTRIES={
    "state_dispatch": {
        0x6007E794:("ldr","r3, [r0, #0x78]"),
        0x6007E798:("push","{r4, r5, lr}"),
        0x6007E79A:("mov","r4, r0"),
        0x6007E7A2:("cmp","r3, #2"),
        0x6007E7A4:("beq","#0x6007e7e8"),
        0x6007E7AA:("cmp","r5, #2"),
        0x6007E7AC:("beq","#0x6007e80e"),
    },
    "later_dispatch":{
        0x6007E8AC:("ldr.w","r3, [r0, #0x8c]"),
        0x6007E8B0:("push.w","{r4, r5, r6, r7, r8, lr}"),
        0x6007E8B8:("mov","r4, r0"),
        0x6007E96E:("bne","#0x6007e99c"),
        0x6007E99E:("bne","#0x6007e9ae"),
    },
}
XREF_TARGETS=(0x6007E784,0x6007E794,0x6007E8AC)
XIP_SCAN_START=0xC800
XIP_SCAN_END=0xFF000


def signed_call_and_literal_xrefs(image):
    """Instruction-shape scan and aligned literal matches, NOT true callgraph.

    Inline literal/table bytes may coincidentally decode to BL. Record
    candidate locations only. Require known positive BL to wrapper.
    """
    targets=set(XREF_TARGETS)
    bl={hex(t):[] for t in targets}
    literal={hex(t):[] for t in targets}
    for off in range(XIP_SCAN_START,XIP_SCAN_END,2):
        try:
            result=decode_thumb_bl_target(image,off)
        except ValueError:
            continue
        if result in targets:
            bl[hex(result)].append(hex(ASSUMED_XIP_BASE+off))
    for off in range(0,len(image)-3,4):
        word=struct.unpack_from("<I",image,off)[0]
        if (word&~1) in targets and (word&1):
            literal[hex(word&~1)].append(hex(off))
    if hex(0x60079D9A) not in bl[hex(0x6007E784)]:
        raise ValueError("phase57 known post-constructor BL positive xref missing")
    return {
        "candidate_thumb_bl_sites":bl,
        "literal_thumb_pointer_file_offsets":literal,
        "source":"signed OEM full-file pattern scan; not complete reachable CFG",
        "live_function_invocation":"UNVERIFIED",
    }


WINDOWS={
    "direct_state_reader_caller":(0x60074D88,0x60074DBC),
    "state_reader_argument_supplier":(0x60079C50,0x60079CDC),
    "state_supplier_followup":(0x60079CD4,0x60079D16),
    "constructor_after_postinit":(0x60079D98,0x60079DE0),
    "constructor_caller":(0x60079D74,0x60079DA8),
    "post_init_entry":(0x6007E784,0x6007E7CC),
    "post_init_reader_early":(0x6007E7C8,0x6007E838),
    "reader_later":(0x6007E8A0,0x6007E9BA),
}


def inspect_global_argument_pointers(image):
    """Signed static reference through a getter, not observed live RAM.

    PC-relative literal for 0x60079c50 points to RAM or XIP; its runtime
    dereference is a separate unmeasured value. Output includes candidate
    producer literals to permit explicit equality comparison later.
    """
    pc=0x60079C50
    instruction=decode(image,pc,pc+2)
    if len(instruction)!=1 or (instruction[0]["m"],instruction[0]["op"])!=(
        "ldr","r1, [pc, #0x14]"
    ):
        raise ValueError("phase57 signed state-reader supplier literal drift")
    literal=((pc+4)&~3)+0x14
    word=struct.unpack_from("<I",image,literal-ASSUMED_XIP_BASE)[0]
    candidates=[
        {"site":hex(p),"aligned_PC_base_not_a_literal_pointer":hex((p+4)&~3),
         "raw_instruction":[{"pc":hex(x["pc"]),"m":x["m"],"op":x["op"]}
                 for x in decode(image,p,p+4)]}
        for p in (0x60079DBA,0x60079DBC)
    ]
    return {
        "getter_call_from":"0x60074d94 BL 0x60079c50",
        "getter_pc":hex(pc),"literal_at":hex(literal),
        "getter_literal_value":hex(word),
        "runtime_first_word":"UNMEASURED",
        "getter_sink":"0x60074da4 LDR R0,[SP] -> 0x60074daa BL 0x6007e794",
        "getter_source":"0x60074d92 MOV R0,SP then BL 0x60079c50 copies first word of a static global into SP",
        "producer_sites_for_followup":candidates,
        "same_as_constructor_object":"UNPROVEN",
    }


def verify_itcm_reader_veneer(image):
    """Original Thumb veneer at ITCM 0xB7C8 -> signed XIP 0x6007E8AC.

    The linked method is only a static signed-code branch target. Search
    direct BL sites in relocated ITCM using runtime PC, not image XIP.
    """
    address=0xB7C8
    rows=itcm_rows(image,address,4)
    if len(rows)!=1 or (rows[0]["m"],rows[0]["op"])!=(
        "ldr.w","pc, [pc, #-0x0]"
    ):
        raise ValueError("phase57 original ITCM reader veneer drift")
    word=struct.unpack_from("<I",image,ITCM_SOURCE_OFFSET+address+4)[0]
    if word!=0x6007E8AD:
        raise ValueError("phase57 original ITCM reader target literal drift")
    callers=[]
    for off in range(ITCM_SOURCE_OFFSET,
                     ITCM_SOURCE_OFFSET+ITCM_LENGTH-3,2):
        try:
            target=decode_thumb_bl_target(image,off,base=-ITCM_SOURCE_OFFSET)
        except ValueError:
            continue
        if target==address:
            callers.append(hex(off-ITCM_SOURCE_OFFSET))
    return {
        "veneer_runtime_pc":hex(address),
        "veneer_original_image_offset":hex(ITCM_SOURCE_OFFSET+address),
        "literal_file_offset":hex(ITCM_SOURCE_OFFSET+address+4),
        "thumb_destination":hex(word),
        "destination_XIP_entry":hex(word&~1),
        "possible_relocated_ITCM_BL_callers":callers,
        "executed_on_hardware":"UNVERIFIED",
    }


def inspect_reader_pointer_table(image, refscan):
    """Inspect a Thumb pointer located *within signed ITCM-copy bytes*.

    Does not imply table is loaded or executed on a real controller.
    """
    sites=refscan["literal_thumb_pointer_file_offsets"][hex(0x6007E8AC)]
    out=[]
    for addr in sites:
        off=int(addr,16)
        info={
            "file_offset":hex(off),
            "pointer":hex(struct.unpack_from("<I",image,off)[0]),
            "lies_in_startup_ITCM_copy":ITCM_SOURCE_OFFSET<=off<ITCM_SOURCE_OFFSET+ITCM_LENGTH,
            "itcm_runtime_address":hex(off-ITCM_SOURCE_OFFSET) if
                                  ITCM_SOURCE_OFFSET<=off<ITCM_SOURCE_OFFSET+ITCM_LENGTH else None,
            "aligned_words_around":[
                {"file_offset":hex(i),"word":hex(struct.unpack_from("<I",image,i)[0])}
                for i in range(off-16,off+20,4)
            ],
            "runtime_reader_link":"UNPROVEN",
        }
        out.append(info)
    return out


def bounded_decode(image, start, end):
    return [
        {"pc":hex(r["pc"]),"m":r["m"],"op":r["op"]}
        for r in decode(image,start,end)
    ]


def verify_pins(image, pinset, windows):
    observed={}
    for begin,end in windows:
        observed.update({
            row["pc"]:(row["m"],row["op"])
            for row in decode(image,begin,end)
        })
    for pc,pair in pinset.items():
        if observed.get(pc)!=pair:
            raise ValueError(f"phase57 original signed instruction drift {pc:#x}: {observed.get(pc)!r}")
    return len(pinset)


def same_register_without_redefinition(rows, from_pc, to_pc, name):
    """Conservative single-block local check; never cross calls or branches.

    Returns False if a control-flow barrier, unknown instruction, or write
    to the tracked register appears. This is NOT a CFG reachability proof.
    """
    saw_from=False
    for row in rows:
        pc=int(row["pc"],16)
        if pc==from_pc:
            saw_from=True
            continue
        if not saw_from:
            continue
        if pc==to_pc:
            return True
        m=row["m"].split(".")[0]
        op=row["op"]
        if m in ("b","bl","blx","bx","pop","ldm","cbz","cbnz","tbb","tbh"):
            return False
        if m.startswith("it") or (m.startswith("b") and m!="bic"):
            return False
        if op.split(",",1)[0]==name and m not in ("cmp","tst","str","strb","strh","strd","push"):
            return False
    return False


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("phase57 original SHA-256-pinned signed OEM required")
    original=prove_r0_producer(image)
    ncaller=verify_pins(image,CALLER_PINS,[(0x60079D74,0x60079DA8)])
    nsupplier=verify_pins(image,SUPPLIER_PINS,[(0x60074D8C,0x60074DAE)])
    npost=verify_pins(image,POST_INIT_WRAPPER_PINS,[(0x6007E784,0x6007E78E)])
    nentry={
        "state_dispatch":verify_pins(image,READER_ENTRIES["state_dispatch"],
              [(0x6007E794,0x6007E7B0)]),
        "later_dispatch":verify_pins(image,READER_ENTRIES["later_dispatch"],
              [(0x6007E8AC,0x6007E9A4)]),
    }
    refscan=signed_call_and_literal_xrefs(image)
    pointer_table=inspect_reader_pointer_table(image,refscan)
    reader_veneer=verify_itcm_reader_veneer(image)
    supplier=inspect_global_argument_pointers(image)
    global_chain=verify_global_chain(image)
    nread=verify_pins(image,READ_PINS,[
        (0x6007E7E8,0x6007E7EE),
        (0x6007E80E,0x6007E814),
        (0x6007E9A2,0x6007E9A8),
    ])
    views={name:bounded_decode(image,*bounds) for name,bounds in WINDOWS.items()}
    # R4 is callee-saved by AAPCS, but without proving that each signed
    # callee conforms and returns we only claim a conditional argument route.
    # 0x60079d7e -> 0x60079d96 both save and forward caller's R4.
    chain={
        "allocation_like_return_to_r4":"0x60079d7e MOV R4,R0",
        "constructor":"0x60079d84 BL 0x6007eb8c",
        "after_constructor_call":"0x60079d90 BL 0x6013d3c8",
        "post_constructor_r0":"0x60079d96 MOV R0,R4",
        "post_constructor_entry":"0x60079d9a BL 0x6007e784",
        "argument_identity":"CONDITIONAL: caller R4 is callee-saved across intervening signed BLs",
        "live_execution":"UNMEASURED",
    }
    readers=[]
    for pc in CANDIDATE_READERS:
        match=READ_PINS[pc]
        check=offset_reader(*match)
        if check is None:
            raise ValueError("phase57 reader semantic drift "+hex(pc))
        readers.append({
            "pc":hex(pc),
            "instruction":match[0]+" "+match[1],
            "base_register":check["base"],
            "post_init_object_identity":"UNKNOWN_ACROSS_DISTINCT_CALLEES",
            "claim":"SIGNED_READ_INSTRUCTION; NOT_YET_PROVEN_SAME_OBJECT",
        })
    return {
        "phase":57,
        "sha256":IMAGE_SHA256,
        "original_signed_image_verified":True,
        "caller_pin_count":ncaller,
        "supplier_pin_count":nsupplier,
        "reader_conditional_alias_paths":[
            {
                "entry":"0x6007e794",
                "entry_argument":"R0 from global holder getter (if executed and not overwritten)",
                "guard":"0x6007e7a2 CMP R3,#2; 0x6007e7a4 BEQ 0x6007e7e8",
                "field80_load":"0x6007e7ea LDR.W R0,[R0,#0x80]",
                "register_provenance":"R0 input preserved on this direct guarded edge",
                "classification":"CONDITIONAL_SIGNED_SAME_ARGUMENT_READ",
            },
            {
                "entry":"0x6007e794",
                "guard":"0x6007e7aa CMP R5,#2; 0x6007e7ac BEQ 0x6007e80e",
                "field80_load":"0x6007e810 LDR.W R0,[R4,#0x80]",
                "register_provenance":"R4 saved from incoming R0 at 0x6007e79a",
                "classification":"CONDITIONAL_SIGNED_SAME_ARGUMENT_READ",
            },
            {
                "entry":"0x6007e8ac",
                "ITCM_caller":"0xaa20 MOV R0,R4; 0xaa22 BL 0xb7c8",
                "field80_load":"0x6007e9a4 LDR.W R0,[R4,#0x80]",
                "register_provenance":"R4 from this distinct function's incoming R0",
                "linked_to_global_0x2001ee30":"UNPROVEN",
            },
        ],
        "reader_pin_count":nread,
        "wrapper_pin_count":npost,
        "reader_entry_pins":nentry,
        "signed_cross_references":refscan,
        "reader_pointer_table":pointer_table,
        "itcm_reader_veneer":reader_veneer,
        "reader_global_argument_source":supplier,
        "linked_signed_global_holder":global_chain,
        "itcm_veneer_caller_window":itcm_rows(image,0xAA00,0x50),
        "post_init_wrapper":{
            "argument": "R0 = allocated object from saved R4 (conditional)",
            "operation":"R0 += 12, R2=27, R1 literal; tail branch 0x6010177a",
            "reads_plus80":False,
            "reader_functions_are_separate":"0x6007e794 and 0x6007e8ac",
        },
        "phase56_producer":original,
        "post_constructor_pass":chain,
        "read_candidates":readers,
        "instruction_windows":views,
        "owner_config_fields":"UNMEASURED",
        "active_class10":"UNVERIFIED",
        "host_code_execution":"NOT DEMONSTRATED",
        "HAB_CLOSED_bypass":"NOT DEMONSTRATED",
        "device_IO":False,"flash_or_efuse_writes":False,
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image",type=Path)
    parser.add_argument("--out",type=Path)
    args=parser.parse_args()
    result=audit(args.image.read_bytes())
    if args.out:
        args.out.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    print("PHASE57 CONSTRUCTOR-POSTINIT PASS",json.dumps(result["post_constructor_pass"]))
    for name,rows in result["instruction_windows"].items():
        print("PHASE57 ORIGINAL WINDOW",name,json.dumps(rows))
    print("PHASE57 POST INIT WRAPPER",json.dumps(result["post_init_wrapper"]))
    print("PHASE57 READER ENTRY PINS",json.dumps(result["reader_entry_pins"]))
    print("PHASE57 CROSS REFERENCES",json.dumps(result["signed_cross_references"]))
    print("PHASE57 READER POINTER TABLE",json.dumps(result["reader_pointer_table"]))
    print("PHASE57 ITCM READER VENEER",json.dumps(result["itcm_reader_veneer"]))
    print("PHASE57 READER ARGUMENT GLOBAL",json.dumps(result["reader_global_argument_source"]))
    print("PHASE57 GLOBAL HOLDER CHAIN",json.dumps(result["linked_signed_global_holder"]))
    print("PHASE57 ITCM VENEER CALLER",json.dumps(result["itcm_veneer_caller_window"]))
    print("PHASE57 READER CANDIDATES",json.dumps(result["read_candidates"]))
    print("PHASE57 PINS",result["caller_pin_count"],result["reader_pin_count"])
    print("PHASE57 NO LIVE USB CONFIG OR EXECUTION PROOF")


if __name__=="__main__":
    main()
