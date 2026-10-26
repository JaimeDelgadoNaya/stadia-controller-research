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
            "callback_registration_in_live_EP0":"NOT PROVEN",
            "custom_firmware_execution":"NOT PROVEN",
            "hardware_io":False}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("image",type=Path)
    a=p.parse_args()
    res=audit(a.image.read_bytes())
    print(json.dumps({"original_sha256_verified":res["original_sha256_verified"],
                      "pc_relative_literal_hits":res["pc_relative_literal_hits"]}))
if __name__=="__main__":
    main()
