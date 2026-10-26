"""Offline SHA-pinned Thumb PC-relative reference census for signed Bruce.

Literal pools are data. Decoding is a bounded candidate search, not proof
of runtime reachability. No hardware access.
"""
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
from tools.audit_signed_app_surface import IMAGE_SIZE, IMAGE_SHA256, ASSUMED_XIP_BASE
from tools.audit_app_usb_dispatch import ITCM_SOURCE_OFFSET, ITCM_LENGTH

BASE=ASSUMED_XIP_BASE
START=0x60104B80
END=0x60104BE0
REG=re.compile(r'^\w+, \[pc(?:, #(-?0x[0-9a-f]+|-?\d+))?\]$')

def pc_ldr_literal(pc, mnemonic, operands):
    if not mnemonic.startswith("ldr"):
        return None
    m=REG.match(operands.lower())
    if m is None:
        return None
    return ((pc+4)&~3)+(int(m.group(1),0) if m.group(1) else 0)


def constructed_reference_candidates(data):
    """MOVW/MOVT register pairs in local chunks; register liveness unproven."""
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    out=[]
    begin=(ITCM_SOURCE_OFFSET+ITCM_LENGTH+1)&~1
    for off in range(begin,0xFF000,0x2000):
        recent={}
        for idx,ins in enumerate(md.disasm(data[off:min(off+0x2000,0xFF000)],BASE+off)):
            if ins.mnemonic not in ("movw","movt"):
                continue
            fields=ins.op_str.split(",")
            if len(fields)!=2 or not fields[1].strip().startswith("#"):
                continue
            reg=fields[0].strip()
            try:
                imm=int(fields[1].strip()[1:],0)
            except ValueError:
                continue
            if ins.mnemonic=="movw":
                recent[reg]=(imm,ins.address,idx)
            else:
                lower=recent.get(reg)
                if lower and idx-lower[2]<=20:
                    address=(imm<<16)|lower[0]
                    if START<=address<END:
                        out.append({"low_at":hex(lower[1]),
                                    "high_at":hex(ins.address),
                                    "candidate":hex(address),
                                    "register_or_branch_clobber_checked":False})
    return out

def audit(data):
    if len(data)!=IMAGE_SIZE or hashlib.sha256(data).hexdigest()!=IMAGE_SHA256:
        raise ValueError("Requires exact original signed Bruce SHA256")
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    begin=(ITCM_SOURCE_OFFSET+ITCM_LENGTH+1)&~1
    hits=[]
    for off in range(begin,0xFF000,0x2000):
        for ins in md.disasm(data[off:min(off+0x2000,0xFF000)],BASE+off):
            lit=pc_ldr_literal(ins.address,ins.mnemonic,ins.op_str)
            if lit is None or lit<BASE or lit>=BASE+0xFF000 or lit%4:
                continue
            val=struct.unpack_from("<I",data,lit-BASE)[0]
            if START<=lit<END or START<=val<END:
                hits.append({"pc":hex(ins.address),"ins":ins.mnemonic+" "+ins.op_str,
                             "literal":hex(lit),"word":hex(val),
                             "note":"linear Thumb decode candidate; not verified reachable"})
    words=[{"pc":hex(at),"word":hex(struct.unpack_from("<I",data,at-BASE)[0])}
           for at in range(START,END,4)]
    return {"original_sha256_verified":True,"table_words":words,
            "pc_relative_literal_hits":hits,
            "local_movw_movt_reference_candidates":constructed_reference_candidates(data),
            "callback_registration_in_live_EP0":"NOT PROVEN",
            "custom_firmware_execution":"NOT PROVEN",
            "hardware_io":False}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("image",type=Path)
    a=p.parse_args()
    res=audit(a.image.read_bytes())
    print(json.dumps({"original_sha256_verified":res["original_sha256_verified"],
                      "pc_relative_literal_hits":res["pc_relative_literal_hits"],
                      "movw_movt_candidates":res["local_movw_movt_reference_candidates"]}))
    for ins in Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS).disasm(a.image.read_bytes()[0x16780:0x167D0],BASE+0x16780):
        print("TABLE NEIGHBOR CONTEXT",hex(ins.address),ins.mnemonic,ins.op_str)
if __name__=="__main__":
    main()
