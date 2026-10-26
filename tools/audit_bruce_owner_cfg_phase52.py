"""Phase 52: bounded, branch-aware, interprocedural USB owner-pointer CFG.

Proves a *conditional signed-code dataflow* from owner 0x2000A2A8
through USB mode=2 to the shared singleton's config pointer store. It does
NOT prove mode 2 actually occurred, owner class records were populated,
class10 was active, or arbitrary host-controlled pointers are executable.

Abstract values are exact signed-file literal addresses, arithmetic on
known registers, or UNKNOWN. The worklist splits unknown branches,
clobbers caller-saved R0-R3 at external BLs, and never reads device RAM.
Every unexplained control transfer terminates the local proof. The model
is bounded and NOT an exhaustive whole-firmware control-flow graph.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import struct
from collections import deque
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SHA256, IMAGE_SIZE, ASSUMED_XIP_BASE
from tools.audit_bruce_ep0_registration import decode
from tools.audit_bruce_usb_owner_pointer_phase50 import OWNER

BASE=ASSUMED_XIP_BASE
SHARED_USB=0x20004080
CONFIG_SLOT=SHARED_USB+4
FIELDS={OWNER+4:"record_array_pointer",
        OWNER+8:"configuration_method",
        OWNER+12:"class_record_count",
        OWNER+0x10:"mode_byte",
        OWNER+0x90:"current_USB_mode",
        OWNER+0x98:"engine_output"}
WINDOWS={
    "mode_transition":(0x60060FE8,0x60061080),
    "owner_constructor":(0x60060F84,0x60060FC4),
    "shared_config_constructor":(0x600550E4,0x60055144),
}
PINS={
    0x60060FF0:("mov","r4, r0"),
    0x60060FF2:("mov","r5, r1"),
    0x60061020:("cmp","r5, #2"),
    0x6006102A:("bne","#0x60061080"),
    0x6006102C:("mov","r0, r4"),
    0x6006102E:("bl","#0x60060f84"),
    0x60060F86:("add.w","r2, r0, #0x98"),
    0x60060F8A:("adds","r1, r0, #4"),
    0x60060F8E:("ldrb","r0, [r0, #0x10]"),
    0x60060F90:("bl","#0x600550e4"),
    0x600550EA:("mov","r4, r1"),
    0x600550F6:("ldr","r3, [r1, #4]"),
    0x600550F8:("cmp","r3, #0"),
    0x600550FA:("beq","#0x600551a2"),
    0x60055104:("ldr","r3, [pc, #0xa0]"),
    0x6005510C:("mov","r5, r3"),
    0x6005512E:("str","r4, [r5, #4]"),
}
REG_MEM=re.compile(r"^([a-z][a-z0-9]*), \[([a-z][a-z0-9]*)(?:, #(0x[0-9a-f]+|\d+))?\]!?$")
REGISTER=re.compile(r"^r(?:1[0-2]|[0-9])$|^(?:sb|sl|fp|lr)$")
HEX_TARGET=re.compile(r"^#0x[0-9a-f]+$")


def val(token,registers):
    if token.startswith("#"):
        try: return int(token[1:],0)
        except ValueError:return None
    return registers.get(token)


def verify_pins(code):
    for pc,pair in PINS.items():
        actual=code.get(pc)
        if actual is None or (actual["m"],actual["op"])!=pair:
            raise ValueError("Phase52 original signed CFG anchor drift "+hex(pc))
    return len(PINS)


def code_map(image):
    rows={}
    for lo,hi in WINDOWS.values():
        items=decode(image,lo,hi)
        for i,row in enumerate(items):
            row=dict(row)
            row["next"]=items[i+1]["pc"] if i+1<len(items) else None
            rows[row["pc"]]=row
    verify_pins(rows)
    return rows


def flow(code,image,initial_mode,*,max_states=2800):
    """Worklist explores two-sided unknown branches; an observed store is
    a conditional code path, *never* evidence of physical device execution."""
    q=deque([(0x60060FE8,{"r0":OWNER,"r1":initial_mode},None,
              ("0x60060fe8",))])
    seen=set()
    store_events={}
    read_events={}
    calls=set()
    terminated={}
    states=0

    def stop(reason):
        terminated[reason]=terminated.get(reason,0)+1

    while q:
        pc,regs,eq,chain=q.popleft()
        key=(pc,tuple(sorted(regs.items())),eq,chain)
        if key in seen:continue
        seen.add(key)
        states+=1
        if states>max_states:
            raise ValueError("Phase52 CFG state budget exhausted")
        x=code.get(pc)
        if x is None:
            stop("out_of_bounded_CFG")
            continue
        m,op=x["m"],x["op"]
        next_pc=x["next"]

        def add(pc2,regs2=None,eq2=None,chain2=None):
            if pc2 is not None:
                q.append((pc2,dict(regs if regs2 is None else regs2),
                          eq if eq2 is None else eq2,
                          chain if chain2 is None else chain2))
        if m.startswith(("pop","bx")) or m in ("udf","svc"):
            stop("function_return_or_unknown_control")
            continue
        # Thumb B and CB edges. Unknown conditions traverse both sides.
        if m in ("b","b.w") and HEX_TARGET.match(op):
            add(int(op[1:],0))
            continue
        if m.startswith("b") and m not in ("bl","blx","bkpt","bic") and HEX_TARGET.match(op):
            branch=(eq if m in ("beq","b.eq") else
                    (None if eq is None else not eq) if m in ("bne","b.ne")
                    else None)
            if branch is not False:add(int(op[1:],0))
            if branch is not True:add(next_pc)
            continue
        if m in ("cbz","cbnz"):
            items=[s.strip() for s in op.split(",")]
            if len(items)!=2 or not HEX_TARGET.match(items[1]):
                stop("unsupported_CB_target")
                continue
            v=regs.get(items[0])
            take=None if v is None else ((v==0) if m=="cbz" else (v!=0))
            if take is not False:add(int(items[1][1:],0))
            if take is not True:add(next_pc)
            continue
        if m in ("bl","blx"):
            if m=="bl" and HEX_TARGET.match(op):
                target=int(op[1:],0)
                if target in (0x60060F84,0x600550E4):
                    entry_name=("owner_constructor" if target==0x60060F84
                                else "shared_config_constructor")
                    if len(chain)<5:
                        add(target,dict(regs),None,chain+(entry_name,))
                        calls.add((hex(pc),hex(target),
                                   hex(regs["r0"]) if "r0" in regs else "UNKNOWN",
                                   hex(regs["r1"]) if "r1" in regs else "UNKNOWN"))
            # Unknown return values/caller-saved regs are never kept as facts.
            for reg in ("r0","r1","r2","r3","r12"):
                regs.pop(reg,None)
            add(next_pc,regs,None)
            continue
        if m=="cmp":
            items=[s.strip() for s in op.split(",")]
            if len(items)==2:
                a,b=val(items[0],regs),val(items[1],regs)
                eq=(a==b) if a is not None and b is not None else None
            else:eq=None
            add(next_pc,regs,eq)
            continue
        if m.startswith(("push","nop","dmb","dsb")) or m in ("tst","tst.w"):
            add(next_pc,regs,None if m.startswith("tst") else eq)
            continue

        nm=m.split(".")[0]
        mem=REG_MEM.match(op)
        if mem and nm.startswith(("ldr","str")):
            dst,base,imm=mem.groups()
            base_value=((pc+4)&~3) if base=="pc" else regs.get(base)
            disp=int(imm,0) if imm else 0
            address=base_value+disp if base_value is not None else None
            if address in FIELDS and nm.startswith("ldr"):
                read_events[(hex(pc),hex(address),FIELDS[address])]={
                    "pc":hex(pc),"address":hex(address),
                    "field":FIELDS[address],
                    "classification":"SIGNED_CODE_READ_FROM_UNKNOWN_LIVE_RAM"
                }
            if nm.startswith("str") and address is not None:
                if address in FIELDS or address==CONFIG_SLOT:
                    src=regs.get(dst)
                    event={"pc":hex(pc),"address":hex(address),
                           "source":hex(src) if src is not None else "UNKNOWN",
                           "source_reg":dst,
                           "field":FIELDS.get(address,"shared_config_pointer"),
                           "mode_seed":initial_mode,
                           "call_chain":list(chain),
                           "classification":"SIGNED_CONDITIONAL_CODE_PATH_NOT_LIVE_EXECUTION"}
                    k=(event["pc"],event["address"],event["source"],tuple(chain))
                    store_events[k]=event
            if nm.startswith("ldr"):
                if base=="pc" and nm=="ldr" and address is not None and BASE<=address<=BASE+len(image)-4 and address%4==0:
                    regs[dst]=struct.unpack_from("<I",image,address-BASE)[0]
                else: regs.pop(dst,None)
            # Writes do not redefine base/source registers unless writeback; ! syntax
            if op.endswith("!"):
                regs.pop(base,None)
            add(next_pc,regs,eq)
            continue
        # Simple exact pointer expressions.
        args=[s.strip() for s in op.split(",")]
        if nm=="mov" and len(args)==2 and REGISTER.match(args[0]):
            v=val(args[1],regs)
            if v is None:regs.pop(args[0],None)
            else:regs[args[0]]=v
            add(next_pc,regs,eq)
            continue
        if nm in ("add","adds","sub","subs") and len(args) in (2,3):
            dst=args[0];src=args[1] if len(args)==3 else dst
            imm=args[2] if len(args)==3 else args[1]
            v=regs.get(src);amount=val(imm,{})
            if v is not None and amount is not None and REGISTER.match(dst):
                regs[dst]=v+(amount if nm.startswith("add") else -amount)
            else:regs.pop(dst,None)
            add(next_pc,regs,eq)
            continue

        # Unmodelled instruction could mutate first register. Fail closed.
        if args and REGISTER.match(args[0]) and not m.startswith(("str","stm")):
            regs.pop(args[0],None)
        if m in ("it","ite","itt","itet","ittt"):
            # No conditional semantics modelled: discard speculative facts
            # and stop rather than overclaiming proof across an IT block.
            stop("unmodelled_IT_predicate")
            continue
        add(next_pc,regs,None)

    return {
      "initial_mode_assumption":initial_mode,
      "scanned_states":states,
      "conditional_store_candidates":list(store_events.values()),
      "reads_of_owner_fields":list(read_events.values()),
      "direct_followed_calls":[{"site":a,"target":b,"r0":c,"r1":d}
                               for a,b,c,d in sorted(calls)],
      "termination_counts":terminated,
      "coverage":"bounded three signed OEM routines, CFG branches split, unknown RAM not read",
    }


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("phase52 exact original Bruce signed SHA-256 required")
    code=code_map(image)
    mode2=flow(code,image,2)
    mode1=flow(code,image,1)
    matches=[q for q in mode2["conditional_store_candidates"]
             if q["address"]==hex(CONFIG_SLOT) and q["source"]==hex(OWNER+4)
             and q["pc"]=="0x6005512e"]
    if not matches:
        raise ValueError("signed conditional owner-to-shared-config transfer not established: "+json.dumps({"calls":mode2["direct_followed_calls"],"stores":mode2["conditional_store_candidates"],"reads":mode2["reads_of_owner_fields"],"termination":mode2["termination_counts"],"states":mode2["scanned_states"]}))
    if any(q["address"]==hex(CONFIG_SLOT) for q in mode1["conditional_store_candidates"]):
        raise ValueError("mode1 unexpectedly reaches phase52 mode2 config constructor")
    return {
        "phase":52,
        "signed_OEM_original_SHA_verified":True,
        "signed_static_pins":len(PINS),
        "conditional_mode2":mode2,
        "mode1_control":mode1,
        "verified_conditional_owner_to_shared_config_store":matches,
        "preinstallation_method_guard":"0x600550f6 reads [config+4] = [owner+8]; 0x600550f8 CMP #0; 0x600550fa BEQ abort",
        "important_limits":{
            "mode2_really_selected_on_hardware":"UNVERIFIED",
            "owner_plus4_list_pointer_current_contents":"UNMEASURED",
            "owner_plus8_method_pointer_current_contents":"UNMEASURED",
            "owner_plus12_record_count_current_contents":"UNMEASURED",
            "active_class10_runtime_record":"UNVERIFIED",
            "full_interprocedural_CFG":False,
            "arbitrary_USB_pointer_control":"NOT DEMONSTRATED",
            "unsigned_execution":"NOT DEMONSTRATED",
            "HAB_CLOSED_bypass":"NOT DEMONSTRATED",
            "physical_USB_access":False,
            "flash_efuse_writes":False,
        }
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    a=p.parse_args()
    z=audit(a.image.read_bytes())
    if a.out:a.out.write_text(json.dumps(z,indent=2)+"\n")
    print("PHASE52 CONDITIONAL OWNER TRANSFER",json.dumps(z["verified_conditional_owner_to_shared_config_store"]))
    print("PHASE52 MODE2 STATS",json.dumps({k:z["conditional_mode2"][k]
                    for k in ("scanned_states","direct_followed_calls","reads_of_owner_fields","termination_counts")}))
    print("PHASE52 MODE1 CONTROL",json.dumps({k:z["mode1_control"][k]
                    for k in ("scanned_states","conditional_store_candidates")}))
    print("PHASE52 RUNTIME CONFIG CLASS10 UNKNOWN; NO DEVICE I/O")

if __name__=="__main__":main()
