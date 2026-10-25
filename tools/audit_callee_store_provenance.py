"""Phase 24: SHA-locked, offline store/provenance audit of selected callees.

Uses the owner's private Stadia bootloader A (build 169429). The image is
never committed and no device, USB endpoint, flash or fuse is accessed.
The audit follows only explicit register aliases in selected function ranges.
Pointers loaded from RAM fields are treated as unknown values, not as proof of
where they point. A zero direct callback-store count is not a whole-program
absence proof.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

BASE = 0x60800000
SIZE = 131072
SHA256 = "59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0"
GLOBAL = 0x20008B78
ALIAS_SPAN = 0x1000

CALLBACK_FIELDS = {
    0x5F8: "bulk_in_handler",
    0x5FC: "bulk_in_context",
    0x600: "bulk_out_handler",
    0x604: "bulk_out_context",
}

# Offsets are file offsets relative to BASE. Each fingerprint excludes any
# adjacent literal pool and is verified against the complete image SHA-256.
CODE_RANGES = {
    "misc_subobject": (0xA990, 0xAA3C, "9846228281d488b762dd0af06741682ce861e6c1011687065ebb8c42becbd1f0"),
    "state_subobject": (0x22A0, 0x22E8, "097be77920ee84cc83618fc99cce5a8d76b26c450e6c6d25a7895f43b4e687f9"),
    "controller_data_init": (0x990C, 0x995E, "f1503f6e76e3996adf8c4c698e3995131a372757eb343df61fed680bb9918e9c"),
    "cdc_subobject": (0x9D98, 0x9DA8, "d8060378f81c652ced44c93ea3210118d6be1d0f80fa28afff0e7d253dd2fe3c"),
    "state_service": (0x2174, 0x21A8, "a3a428e31aa337e2b114d6d1b6a57687b759d6df4d10fa2bf052260e15b04edd"),
    "subobject_setup": (0x21B4, 0x228A, "c65fab5320452ebd44eba634c1bce282d1da0099c9e4686df1707b531a5fd545"),
    "global_state_helper": (0xC150, 0xC16C, "d5dd59b65ca1a822ef37f00208f6bb8d955a5b0e3ff56af5ea45cfa3cb9b1fe5"),
    "member_init": (0x10210, 0x10236, "a5cb4ce7a201c637ffd0c668b3103ba465acf3152fc7552e78b3130e231841bf"),
    "member_constructor": (0x10BB8, 0x10C30, "5f4547526ac63d076f8458632a76424eafbdd4db39662299ec8e245a6fbf1397"),
    "member_subobject_init": (0x10B38, 0x10BAC, "0fa57a7b2597da9f56a7f8d8cd8e8572710b2ed2eb8cc61bb1de584872cd23b7"),
    "linked_node_init": (0x1099C, 0x109B2, "8f64714e4d62060e0a8b9a64105cb9285c0780b3b11e15fd63c86079332c58cc"),
    "linked_list_worker": (0x11DC8, 0x11E30, "48bc771095a3b03dcc8888a9b1047d448380e26cf9dcc2989424ca31d77b1b16"),
}

# These are bounded straight-line windows. Split windows explicitly where an
# epilogue precedes an alternate branch block, rather than carrying registers
# through an impossible linear path.
ANALYSES = (
    {"name":"misc_subobject_body", "range":"misc_subobject", "start":0xA990, "end":0xAA36, "seed":{"r0":0x568}},
    {"name":"misc_subobject_late_block", "range":"misc_subobject", "start":0xAA36, "end":0xAA3C, "seed":{"r5":0x568}},
    {"name":"state_subobject", "range":"state_subobject", "start":0x22A0, "end":0x22E8, "seed":{"r0":0x560}},
    {"name":"controller_data_init", "range":"controller_data_init", "start":0x990C, "end":0x995E, "seed":{"r0":0x630}},
    {"name":"cdc_subobject", "range":"cdc_subobject", "start":0x9D98, "end":0x9DA8, "seed":{"r0":0x578}},
    {"name":"state_service", "range":"state_service", "start":0x2174, "end":0x21A8, "seed":{"r0":0x560}},
    {"name":"subobject_setup", "range":"subobject_setup", "start":0x21B4, "end":0x228A, "seed":{"r0":0x560}},
    {"name":"global_state_helper", "range":"global_state_helper", "start":0xC150, "end":0xC16C, "seed":{"r0":0x630}},
    {"name":"member_init", "range":"member_init", "start":0x10210, "end":0x10236, "seed":{"r0":0x58C}},
    {"name":"member_constructor", "range":"member_constructor", "start":0x10BB8, "end":0x10C30, "seed":{"r3":0x58C}},
    {"name":"member_subobject_init_body", "range":"member_subobject_init", "start":0x10B38, "end":0x10B98, "seed":{"r0":0x58C}},
    {"name":"member_subobject_init_alt", "range":"member_subobject_init", "start":0x10B98, "end":0x10BAC, "seed":{"r4":0x58C}},
    {"name":"linked_node_init_at_59c", "range":"linked_node_init", "start":0x1099C, "end":0x109B2, "seed":{"r0":0x59C}},
    {"name":"linked_node_init_at_5b0", "range":"linked_node_init", "start":0x1099C, "end":0x109B2, "seed":{"r0":0x5B0}},
    {"name":"linked_list_worker", "range":"linked_list_worker", "start":0x11DC8, "end":0x11E30, "seed":{"r0":0x59C}},
)

EXPECTED_STORES = {
    "misc_subobject_body": {0xA9D4:(0x574,)},
    "misc_subobject_late_block": {0xAA36:(0x574,)},
    "controller_data_init": {0x9910:(0x6C0,)},
    "cdc_subobject": {0x9DA4:(0x588,)},
    "member_init": {0x10226:(0x5DC,)},
    "member_constructor": {
        0x10C10:(0x5D2,), 0x10C14:(0x58C,),
        0x10C16:(0x5C8,0x5CC), 0x10C22:(0x5D8,),
    },
    "member_subobject_init_body": {
        0x10B54:(0x594,), 0x10B5E:(0x590,), 0x10B62:(0x598,),
        0x10B66:(0x5C4,), 0x10B68:(0x5D0,), 0x10B6C:(0x5D1,),
    },
    "linked_node_init_at_59c": {
        0x109A4:(0x5A0,), 0x109A6:(0x5AC,),
        0x109A8:(0x5A4,0x5A8), 0x109AE:(0x59C,),
    },
    "linked_node_init_at_5b0": {
        0x109A4:(0x5B4,), 0x109A6:(0x5C0,),
        0x109A8:(0x5B8,0x5BC), 0x109AE:(0x5B0,),
    },
    "state_subobject": {},
    "state_service": {},
    "subobject_setup": {},
    "global_state_helper": {},
    "member_subobject_init_alt": {},
    "linked_list_worker": {},
}

EXPECTED_HANDOFFS = (
    ("state_subobject", 0x22AE, 0x21B4, "r0", 0x560),
    ("state_subobject", 0x22C2, 0x2174, "r0", 0x560),
    ("controller_data_init", 0x9916, 0xC150, "r0", 0x630),
    ("cdc_subobject", 0x9D9E, 0x10210, "r0", 0x58C),
    ("member_init", 0x10222, 0x10BB8, "r3", 0x58C),
    ("member_constructor", 0x10C1A, 0x10B38, "r0", 0x58C),
    ("member_subobject_init_body", 0x10B7A, 0x11DC8, "r0", 0x59C),
    ("member_subobject_init_alt", 0x10B9C, 0x1099C, "r0", 0x59C),
    ("member_subobject_init_alt", 0x10BA4, 0x1099C, "r0", 0x5B0),
)

EXPECTED_FIELD_DERIVED_CALLS = (
    ("misc_subobject_body", 0xA9BA, 0x9048, "r0", 0x568),
    ("misc_subobject_body", 0xA9F0, 0x9048, "r0", 0x568),
    ("misc_subobject_body", 0xAA26, 0x9048, "r0", 0x568),
    ("subobject_setup", 0x21D2, 0x9048, "r0", 0x560),
    ("linked_list_worker", 0x11DE2, 0x109FE, "r0", 0x5A8),
)

def fmt_addr(value):
    return f"0x{value:08x}"

def fmt_ram_offset(offset):
    return fmt_addr(GLOBAL + offset)

def callback_fields_overlapped(global_offset, width):
    if global_offset is None or width is None or width <= 0:
        return []
    end = global_offset + width
    return [name for start, name in CALLBACK_FIELDS.items()
            if global_offset < start + 4 and end > start]

def _capstone():
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
        from capstone.arm import (
            ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG,
            ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3,
            ARM_REG_R4, ARM_REG_R5, ARM_REG_R6, ARM_REG_R7,
            ARM_REG_R8, ARM_REG_R9, ARM_REG_R10, ARM_REG_R11,
            ARM_REG_R12, ARM_REG_PC,
        )
    except ImportError as exc:
        raise RuntimeError("Install pinned dependencies: python -m pip install -r requirements.txt") from exc
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    md.detail = True
    regs = {
        "r0":ARM_REG_R0, "r1":ARM_REG_R1, "r2":ARM_REG_R2, "r3":ARM_REG_R3,
        "r4":ARM_REG_R4, "r5":ARM_REG_R5, "r6":ARM_REG_R6, "r7":ARM_REG_R7,
        "r8":ARM_REG_R8, "r9":ARM_REG_R9, "r10":ARM_REG_R10, "r11":ARM_REG_R11,
        "r12":ARM_REG_R12,
    }
    return md, regs, ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC

def _provenance_for_alias(offset):
    return {"kind":"global_object_alias", "global_offset":offset,
            "ram_address":fmt_addr(GLOBAL+offset)}

def _root_field(provenance):
    if provenance is None:
        return None
    return provenance.get("root_global_field_offset")

def scan_range(image, name, start, end, seed_aliases, md=None):
    """Scan one bounded Thumb range; branch feasibility is not inferred."""
    if not (0 <= start < end <= len(image)) or start & 1 or end & 1:
        raise ValueError("Invalid aligned code range")
    if md is None:
        md, regs, ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC = _capstone()
    else:
        _, regs, ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC = _capstone()
    code = image[start:end]
    insns = list(md.disasm(code, BASE+start))
    cursor = BASE+start
    for ins in insns:
        if ins.address != cursor:
            raise ValueError(f"Disassembly gap at {fmt_addr(cursor)} in {name}")
        cursor += ins.size
    if cursor != BASE+end:
        raise ValueError(f"Disassembly did not cover {name} through {fmt_addr(BASE+end)}")

    aliases = {regs[reg]: offset for reg, offset in seed_aliases.items()}
    loaded_from = {}
    reads, stores, dynamic_accesses, calls, literals, indirect = [], [], [], [], [], []
    self_loops = []
    caller_saved = {regs[x] for x in ("r0","r1","r2","r3","r12")}
    load_ops = {"ldr","ldrb","ldrh","ldrsb","ldrsh","ldrd","ldm","ldmia","ldmdb"}
    store_ops = {"str","strb","strh","strd","stm","stmia","stmdb","stmib","stmda"}
    for ins in insns:
        mnemonic = ins.mnemonic.lower()
        op = mnemonic.split(".")[0]
        operands = ins.operands
        mem_index = next((i for i, operand in enumerate(operands)
                          if operand.type == ARM_OP_MEM), None)
        is_load = op in load_ops and mem_index is not None
        is_store = op in store_ops and mem_index is not None

        if is_load or is_store:
            mem = operands[mem_index].mem
            base_reg, index_reg, disp = mem.base, mem.index, mem.disp
            indexed = bool(index_reg)
            width = {"ldrb":1,"strb":1,"ldrh":2,"strh":2,"ldr":4,"str":4,
                     "ldrd":8,"strd":8}.get(op)
            dest_regs = [x.reg for x in operands[:mem_index] if x.type == ARM_OP_REG] if is_load else []

            if base_reg in aliases:
                base_offset = aliases[base_reg]
                effective = None if indexed else base_offset + disp
                if is_load:
                    if effective is None:
                        dynamic_accesses.append({
                            "at":fmt_addr(ins.address),"kind":"indexed_read_from_global_alias",
                            "base_global_offset":base_offset,"index_register":md.reg_name(index_reg),
                            "displacement":disp,"destination_registers":[md.reg_name(x) for x in dest_regs]})
                    else:
                        offsets = [effective, effective+4] if op == "ldrd" else [effective]
                        reads.append({
                            "at":fmt_addr(ins.address),"mnemonic":mnemonic,
                            "base_register":md.reg_name(base_reg),
                            "global_offsets_read":offsets,
                            "ram_addresses":[fmt_addr(GLOBAL+x) for x in offsets],
                        })
                    for i, reg in enumerate(dest_regs):
                        aliases.pop(reg, None)
                        if effective is not None:
                            field_offset = effective + (4*i if op == "ldrd" else 0)
                            loaded_from[reg] = {
                                "kind":"value_loaded_from_global_field",
                                "root_global_field_offset":field_offset,
                                "chain":[{"kind":"load","global_field_offset":field_offset}],
                                "pointer_addend":0,
                            }
                        else:
                            loaded_from.pop(reg, None)
                else:
                    offsets = [] if effective is None else (
                        [effective,effective+4] if op == "strd" else [effective])
                    stores.append({
                        "at":fmt_addr(ins.address),"mnemonic":mnemonic,
                        "base_register":md.reg_name(base_reg),
                        "base_global_offset":base_offset,"displacement":disp,
                        "global_offsets_written":offsets,
                        "ram_addresses":[fmt_addr(GLOBAL+x) for x in offsets],
                        "width_bytes":width,
                        "dynamic_index_register":md.reg_name(index_reg) if indexed else None,
                        "callback_fields_overlapped":(
                            [] if effective is None else callback_fields_overlapped(effective,width)),
                    })
                if getattr(ins,"writeback",False):
                    aliases.pop(base_reg,None)
                    loaded_from.pop(base_reg,None)
                continue

            if base_reg == ARM_REG_PC and is_load and not indexed and op in {"ldr","ldrd"}:
                literal_address = ((ins.address+4)&~3)+disp
                literal_offset = literal_address-BASE
                value = None
                if 0 <= literal_offset <= len(image)-4:
                    value = struct.unpack_from("<I",image,literal_offset)[0]
                literals.append({"at":fmt_addr(ins.address),
                                 "literal_address":fmt_addr(literal_address),
                                 "value":fmt_addr(value) if value is not None else None})
                for i, reg in enumerate(dest_regs):
                    loaded_from.pop(reg,None)
                    if value is not None and GLOBAL <= value < GLOBAL+ALIAS_SPAN and i == 0:
                        aliases[reg] = value-GLOBAL
                    else:
                        aliases.pop(reg,None)
                continue

            if base_reg in loaded_from:
                provenance = loaded_from[base_reg]
                if is_load:
                    dynamic_accesses.append({
                        "at":fmt_addr(ins.address),"kind":"dereference_of_field_derived_pointer",
                        "mnemonic":mnemonic,"base_register":md.reg_name(base_reg),
                        "pointer_provenance":provenance,"displacement":disp,
                        "index_register":md.reg_name(index_reg) if indexed else None,
                        "destination_registers":[md.reg_name(x) for x in dest_regs],
                    })
                    for i, reg in enumerate(dest_regs):
                        aliases.pop(reg,None)
                        loaded_from[reg] = {
                            "kind":"value_loaded_through_field_derived_pointer",
                            "root_global_field_offset":_root_field(provenance),
                            "chain":provenance.get("chain",[])+[
                                {"kind":"dereference","displacement":disp}],
                            "pointer_addend":0,
                        }
                elif is_store:
                    dynamic_accesses.append({
                        "at":fmt_addr(ins.address),"kind":"store_through_field_derived_pointer",
                        "mnemonic":mnemonic,"base_register":md.reg_name(base_reg),
                        "pointer_provenance":provenance,"displacement":disp,
                        "index_register":md.reg_name(index_reg) if indexed else None,
                    })
                continue

            if is_load:
                for reg in dest_regs:
                    aliases.pop(reg,None)
                    loaded_from.pop(reg,None)
            continue

        if op in {"bl","blx"}:
            target = None
            target_register = None
            if operands:
                last = operands[-1]
                if last.type == ARM_OP_IMM:
                    target = fmt_addr(last.imm & 0xFFFFFFFF)
                elif last.type == ARM_OP_REG:
                    target_register = md.reg_name(last.reg)
            arguments = {}
            for arg_name in ("r0","r1","r2","r3"):
                reg = regs[arg_name]
                if reg in aliases:
                    arguments[arg_name] = _provenance_for_alias(aliases[reg])
                elif reg in loaded_from:
                    arguments[arg_name] = {
                        **loaded_from[reg],
                        "argument_kind":"field_derived_unknown_value",
                    }
            if arguments:
                calls.append({"at":fmt_addr(ins.address),"mnemonic":mnemonic,
                              "target":target,"indirect_target_register":target_register,
                              "argument_provenance":arguments})
            for reg in caller_saved:
                aliases.pop(reg,None)
                loaded_from.pop(reg,None)
            continue

        if op in {"mov","movs"} and len(operands)>=2 and operands[0].type==ARM_OP_REG:
            dest=operands[0].reg
            source=operands[1]
            source_alias=aliases.get(source.reg) if source.type==ARM_OP_REG else None
            source_provenance=dict(loaded_from[source.reg]) if source.type==ARM_OP_REG and source.reg in loaded_from else None
            aliases.pop(dest,None); loaded_from.pop(dest,None)
            if source.type==ARM_OP_REG:
                if source_alias is not None:
                    aliases[dest]=source_alias
                elif source_provenance is not None:
                    loaded_from[dest]=source_provenance
            continue

        if op in {"add","adds","addw","sub","subs","subw"} and operands and operands[0].type==ARM_OP_REG:
            dest=operands[0].reg
            source_reg=None; immediate=None
            if len(operands)>=3 and operands[1].type==ARM_OP_REG and operands[2].type==ARM_OP_IMM:
                source_reg=operands[1].reg; immediate=operands[2].imm
            elif len(operands)==2 and operands[1].type==ARM_OP_IMM:
                source_reg=dest; immediate=operands[1].imm
            source_alias=aliases.get(source_reg) if source_reg is not None else None
            source_provenance=dict(loaded_from[source_reg]) if source_reg is not None and source_reg in loaded_from else None
            aliases.pop(dest,None); loaded_from.pop(dest,None)
            if source_reg is not None and immediate is not None:
                delta = -immediate if op.startswith("sub") else immediate
                if source_alias is not None:
                    aliases[dest]=source_alias+delta
                elif source_provenance is not None:
                    source_provenance["pointer_addend"]=source_provenance.get("pointer_addend",0)+delta
                    source_provenance["chain"]=source_provenance.get("chain",[])+[
                        {"kind":"pointer_arithmetic","delta":delta}]
                    loaded_from[dest]=source_provenance
            continue

        if op == "bx" and operands and operands[0].type == ARM_OP_REG:
            target_reg=operands[0].reg
            if md.reg_name(target_reg)!="lr":
                transfer={"at":fmt_addr(ins.address),"kind":"indirect_branch",
                          "target_register":md.reg_name(target_reg)}
                if target_reg in aliases:
                    transfer["target_provenance"]=_provenance_for_alias(aliases[target_reg])
                elif target_reg in loaded_from:
                    transfer["target_provenance"]={"kind":"field_derived_unknown_value",
                                                   **loaded_from[target_reg]}
                indirect.append(transfer)
            continue

        if op.startswith("b") and operands and operands[-1].type==ARM_OP_IMM:
            if (operands[-1].imm & 0xFFFFFFFF)==ins.address:
                self_loops.append(fmt_addr(ins.address))

        # Unknown instructions kill any aliases in registers they write.
        try:
            _, written = ins.regs_access()
        except (ValueError, AttributeError):
            written = []
        for reg in written:
            aliases.pop(reg,None)
            loaded_from.pop(reg,None)

    return {
        "name":name,"start":fmt_addr(BASE+start),"end_exclusive":fmt_addr(BASE+end),
        "instruction_count":len(insns),
        "seed_aliases":{reg:fmt_ram_offset(offset) for reg,offset in seed_aliases.items()},
        "reads_via_known_alias":reads,"stores_via_known_alias":stores,
        "dynamic_pointer_accesses":dynamic_accesses,"field_derived_call_handoffs":calls,
        "pc_relative_literals":literals,"indirect_transfers":indirect,
        "unconditional_self_loops":self_loops,
        "scope":"linear decoded bytes with explicit alias tracking; no full CFG or runtime reachability",
    }

def _site_store_map(analysis):
    return {int(item["at"],16)-BASE:tuple(item["global_offsets_written"])
            for item in analysis["stores_via_known_alias"]}

def audit(image, expected_sha256=SHA256):
    if len(image)!=SIZE:
        raise ValueError("Expected 131072-byte Stadia bootloader A")
    digest=hashlib.sha256(image).hexdigest()
    if digest!=expected_sha256:
        raise ValueError("SHA-256 mismatch for bootloader A")
    for name,(start,end,expected) in CODE_RANGES.items():
        actual=hashlib.sha256(image[start:end]).hexdigest()
        if actual!=expected:
            raise ValueError(f"Code fingerprint mismatch for {name} at {fmt_addr(BASE+start)}")

    md,_,_,_,_,_=_capstone()
    results=[]
    for spec in ANALYSES:
        results.append(scan_range(image,spec["name"],spec["start"],spec["end"],
                                  spec["seed"],md=md))
    by_name={item["name"]:item for item in results}

    for name,expected in EXPECTED_STORES.items():
        actual=_site_store_map(by_name[name])
        if actual!=expected:
            raise ValueError(f"Unexpected direct-store map in {name}: {actual!r}")

    for name,site,target,arg_reg,offset in EXPECTED_HANDOFFS:
        matches=[c for c in by_name[name]["field_derived_call_handoffs"]
                 if int(c["at"],16)==BASE+site]
        if not matches or matches[0]["target"]!=fmt_addr(BASE+target):
            raise ValueError(f"Call target mismatch at {fmt_addr(BASE+site)}")
        prov=matches[0]["argument_provenance"].get(arg_reg,{})
        if prov.get("kind")!="global_object_alias" or prov.get("global_offset")!=offset:
            raise ValueError(f"Alias handoff mismatch at {fmt_addr(BASE+site)}")

    for name,site,target,arg_reg,field_offset in EXPECTED_FIELD_DERIVED_CALLS:
        matches=[c for c in by_name[name]["field_derived_call_handoffs"]
                 if int(c["at"],16)==BASE+site]
        if not matches or matches[0]["target"]!=fmt_addr(BASE+target):
            raise ValueError(f"Field-derived call mismatch at {fmt_addr(BASE+site)}")
        prov=matches[0]["argument_provenance"].get(arg_reg,{})
        if prov.get("argument_kind")!="field_derived_unknown_value" or _root_field(prov)!=field_offset:
            raise ValueError(f"Dynamic pointer provenance mismatch at {fmt_addr(BASE+site)}")

    stores=[{"function":a["name"],**s} for a in results for s in a["stores_via_known_alias"]]
    callback_writes=[s for s in stores if s["callback_fields_overlapped"]]
    dynamic_accesses=[{"function":a["name"],**x} for a in results for x in a["dynamic_pointer_accesses"]]
    handoffs=[{"function":a["name"],**c} for a in results for c in a["field_derived_call_handoffs"]]
    self_loops=[{"function":a["name"],"at":x} for a in results for x in a["unconditional_self_loops"]]

    if callback_writes:
        raise ValueError("Unexpected direct write overlaps a known USB callback field")

    return {
        "phase":24,"bootloader_build":169429,"image_bytes":len(image),
        "sha256_verified":True,"sha256":digest,
        "hardware_access":False,"usb_transactions":False,
        "flash_or_fuse_operations":False,
        "audited_code_ranges":[{"name":n,"start":fmt_addr(BASE+s),"end_exclusive":fmt_addr(BASE+e),
                                "bytes":e-s,"sha256":h}
                               for n,(s,e,h) in CODE_RANGES.items()],
        "function_analyses":results,
        "direct_store_observation_count":len(stores),
        "unique_direct_store_instruction_site_count":len({s["at"] for s in stores}),
        "unique_direct_store_instruction_sites":sorted({s["at"] for s in stores}),
        "direct_stores":stores,
        "direct_callback_field_store_count":len(callback_writes),
        "direct_callback_field_stores":callback_writes,
        "dynamic_pointer_access_count":len(dynamic_accesses),
        "dynamic_pointer_accesses":dynamic_accesses,
        "field_derived_call_handoffs":handoffs,
        "self_loops":self_loops,
        "interpretation":{
            "direct_callback_store":"NOT FOUND IN THESE SHA-LOCKED RANGES",
            "dynamic_pointer_sinks":"UNRESOLVED; values loaded from object fields may point elsewhere",
            "usb_host_reachability":"NOT DEMONSTRATED",
            "later_callback_replacement":"NOT PROVEN OR EXCLUDED",
            "host_to_flash_write":"NOT DEMONSTRATED",
            "hab_closed_bypass":"NOT DEMONSTRATED",
            "custom_firmware_execution":"NOT DEMONSTRATED",
        },
        "limitations":"Bounded instruction ranges and conservative register provenance; no whole-program CFG, pointer alias set, runtime RAM capture or complete analysis of callees 0x60809048/0x6080109FE.",
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("bootloader",type=Path,help="Private local matching bootloader A")
    p.add_argument("--out",type=Path,help="Optional local JSON report")
    args=p.parse_args()
    output=json.dumps(audit(args.bootloader.read_bytes()),indent=2)+"\n"
    if args.out:
        args.out.write_text(output,encoding="utf-8")
    else:
        print(output,end="")

if __name__=="__main__":
    main()
