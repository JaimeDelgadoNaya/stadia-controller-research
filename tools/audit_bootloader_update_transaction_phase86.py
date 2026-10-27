"""Phase 86: offline audit of Stadia bootloader A update-transaction ordering.

Consumes already published, *selected* original Thumb instruction records.
No owner-private bootloader is rediscovered, rehashed or executed here.
This is a bounded instruction graph + synthetic state model, NOT emulator,
hardware update, signature bypass, or proof of power-fail recovery.
"""
import argparse
from itertools import product
import json
from pathlib import Path

from tools.trace_write_path import scan as audit_write_path

BOOT_SHA = "59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0"
BOOT_BUILD = 169429
TRANSACTION_FUNC = 0x60801DD4

# Site, exact original opcode bytes, mnemonic, operand text, direct BL target or None.
# Selected pins distinguish structural precheck from authenticated validation,
# fixed 4 KiB IVT access, write-before-HAB, and fallible rollback.
PINS = [
    (0x60801E00,"0121","movs","r1, #1",None),
    (0x60801E02,"00f051f9","bl","#0x608020a8",0x608020A8),
    (0x60801E08,"69b1","cbz","r1, #0x60801e26",None),
    (0x60801E26,"3046","mov","r0, r6",None),
    (0x60801E28,"00f03ef9","bl","#0x608020a8",0x608020A8),
    (0x60801E2E,"12b1","cbz","r2, #0x60801e36",None),
    (0x60801E3E,"4ff48053","mov.w","r3, #0x1000",None),
    (0x60801E42,"b847","blx","r7",None),
    (0x60801E48,"e5d1","bne","#0x60801e16",None),
    (0x60801E58,"9847","blx","r3",None),
    (0x60801E5C,"dbd1","bne","#0x60801e16",None),
    (0x60801E62,"fff79bff","bl","#0x60801d9c",0x60801D9C),
    (0x60801E68,"c7b2","uxtb","r7, r0",None),
    (0x60801E6A,"4fb1","cbz","r7, #0x60801e80",None),
    (0x60801E7A,"0ed1","bne","#0x60801e9a",None),
    (0x60801E80,"0121","movs","r1, #1",None),
    (0x60801E84,"00f010f9","bl","#0x608020a8",0x608020A8),
    (0x60801E8C,"b3d0","beq","#0x60801df6",None),
    (0x60801E9E,"fff74fff","bl","#0x60801d40",0x60801D40),
    (0x60801EA6,"b6d0","beq","#0x60801e16",None),
    (0x60801EA8,"4ff00f00","mov.w","r0, #0xf",None),
    (0x60801DA8,"4ff48053","mov.w","r3, #0x1000",None),
    (0x60801DAE,"a847","blx","r5",None),
    (0x60801DB6,"4ff00a00","mov.w","r0, #0xa",None),
    (0x60801DC0,"fff7beff","bl","#0x60801d40",0x60801D40),
    (0x60801D94,"4ff48053","mov.w","r3, #0x1000",None),
    (0x60801D98,"a047","blx","r4",None),
    (0x60802154,"55b1","cbz","r5, #0x6080216c",None),
    (0x60802168,"fff7f8be","b.w","#0x60801f5c",0x60801F5C),
    (0x60801F00,"00f084f8","bl","#0x6080200c",0x6080200C),
    (0x60801F46,"9746","mov","pc, r2",None),
]

GATES = ("current_auth", "candidate_structure", "backup_read",
         "power_guard", "candidate_read", "candidate_write",
         "final_auth", "rollback_write")


def validate_corpus(evidence):
    """Fail closed on changed original instruction pins and storage topology."""
    if (evidence.get("sha256") != BOOT_SHA or
            evidence.get("build") != BOOT_BUILD or
            evidence.get("bytes") != 131072):
        raise ValueError("Bootloader evidence provenance mismatch")
    write = audit_write_path(evidence)
    by_address = {int(i["address"], 16): i
                  for f in evidence["functions"] for i in f["instructions"]}
    for at, raw, name, operands, target in PINS:
        ins = by_address.get(at)
        if not ins or (ins["bytes"], ins["mnemonic"], ins["operands"]) != (raw,name,operands):
            raise ValueError(f"Pinned original instruction mismatch at 0x{at:08x}")
        if target is not None and int(ins.get("direct_target","0"),16) != target:
            raise ValueError(f"Pinned original branch target mismatch at 0x{at:08x}")
    # An earlier direct path remains conditional on a constructed storage vtable;
    # read/write must not be silently treated as independently user-controllable.
    assert len(write["path"]) >= 6
    return write


def model(*, current_auth=True, candidate_structure=True, backup_read=True,
          power_guard=True, candidate_read=True, candidate_write=True,
          final_auth=True, rollback_write=True):
    """A small abstract interpreter over the *documented* branch ordering.

    Booleans represent synthetic outcomes of routines, not controllable USB
    inputs. Any write means *attempted call*, not physical success or torn data.
    """
    trace = ["select_current_and_candidate"]
    writes = []
    if not current_auth:
        trace.append("stop_current_auth_failed")
        return dict(trace=trace,writes=writes,post_write_auth_attempted=False,
                    accepted=False,return_class="error_before_write")
    trace.append("current_hab_auth_passed")
    if not candidate_structure:
        trace.append("stop_candidate_structural_check_failed")
        return dict(trace=trace,writes=writes,post_write_auth_attempted=False,
                    accepted=False,return_class="error_before_write")
    trace.append("candidate_structure_passed_without_hab_auth")
    if not backup_read:
        trace.append("stop_ivt_backup_read_failed")
        return dict(trace=trace,writes=writes,post_write_auth_attempted=False,
                    accepted=False,return_class="error_before_write")
    trace.append("ivt_backup_read_4096")
    if not power_guard:
        trace.append("stop_power_or_input_guard_failed")
        return dict(trace=trace,writes=writes,post_write_auth_attempted=False,
                    accepted=False,return_class="error_before_write")
    trace.append("power_input_guard_passed")
    if not candidate_read:
        trace.append("candidate_ivt_read_error_0x0a_before_write")
        return dict(trace=trace,writes=writes,post_write_auth_attempted=False,
                    accepted=False,return_class="candidate_read_failure")
    trace.append("candidate_ivt_read_4096")
    writes.append("attempt_write_candidate_ivt_4096")
    trace.append("attempt_write_candidate_ivt_4096")
    if candidate_write:
        trace.append("candidate_ivt_write_return_success")
        trace.append("post_write_hab_auth_attempt")
        if final_auth:
            trace.append("post_write_hab_auth_return_success")
            return dict(trace=trace,writes=writes,post_write_auth_attempted=True,
                        accepted=True,return_class="validated_update_return")
        trace.append("post_write_hab_auth_return_failure")
    else:
        trace.append("candidate_ivt_write_return_failure_0x0f")
    writes.append("attempt_restore_saved_ivt_4096")
    trace.append("attempt_restore_saved_ivt_4096")
    trace.append("rollback_return_success" if rollback_write else "rollback_return_failure_0x0f")
    return dict(trace=trace,writes=writes,
                post_write_auth_attempted=bool(candidate_write),
                accepted=False,
                return_class="rollback_attempt_after_write_or_auth_failure")


def audit(evidence):
    write_path = validate_corpus(evidence)
    scenarios = {
        "valid": model(),
        "current_hab_reject": model(current_auth=False),
        "candidate_structure_reject": model(candidate_structure=False),
        "backup_read_failure": model(backup_read=False),
        "power_guard_reject": model(power_guard=False),
        "candidate_read_failure": model(candidate_read=False),
        "candidate_write_failure_rollback_success": model(candidate_write=False),
        "candidate_write_failure_rollback_failure": model(candidate_write=False,rollback_write=False),
        "post_write_auth_failure_rollback_success": model(final_auth=False),
        "post_write_auth_failure_rollback_failure": model(final_auth=False,rollback_write=False),
    }
    # Deliberately prove model invariants over all 2^8 synthetic outcomes.
    allcases=[model(**dict(zip(GATES,values))) for values in product((False,True),repeat=len(GATES))]
    assert all(not c["accepted"] or c["post_write_auth_attempted"] for c in allcases)
    assert all("attempt_write_candidate_ivt_4096" not in c["writes"] or
               "candidate_structure_passed_without_hab_auth" in c["trace"] for c in allcases)
    assert all(c["accepted"] or c["return_class"] != "validated_update_return" for c in allcases)
    return {
        "research_phase":86,
        "evidence_source":"selected published original Thumb disassembly, not owner raw firmware",
        "bootloader_sha256_in_source":BOOT_SHA,
        "bootloader_build_in_source":BOOT_BUILD,
        "selected_instruction_pins_checked":len(PINS),
        "source_storage_write_path_verified":len(write_path["path"])>=6,
        "transactional_order":[
            "current bootloader HAB authentication",
            "candidate bootloader structural validation (r1=0, not HAB)",
            "backup existing shared IVT (0x1000)",
            "physical-power/input guard callback",
            "read candidate IVT (0x1000)",
            "attempt install candidate IVT (0x1000)",
            "post-write candidate HAB authentication (r1=1)",
            "conditional attempted restore of backed-up IVT on failure",
        ],
        "fixed_ivt_io_bytes":4096,
        "write_before_candidate_hab_final_validation":True,
        "unsigned_code_execution_established":False,
        "physical_write_or_rollback_demonstrated":False,
        "host_controls_update_state":False,
        "power_interruption_rollback_proven":False,
        "synthetic_scenarios":scenarios,
        "synthetic_state_combinations_checked":len(allcases),
        "decision":"NO_GO_FOR_CUSTOM_FIRMWARE_EXECUTION; GO_FOR_BOUNDED_RECOVERY_AND_AUTH_TRUST_BOUNDARY_REVIEW",
        "limitations":[
            "Pre-validation r1=0 is structural only, and is followed by signed HAB auth where selected.",
            "An IVT installation is attempted before the later HAB check. It is not a boot or arbitrary code execution.",
            "Actual flash programming, timing, reset behavior, power-loss recovery and spare B contents are not simulated.",
            "The selected disassembly has gaps and does not establish USB reachability or full bootloader coverage.",
            "Image digest labels are from previously extracted source evidence; no full binary SHA-256 was recomputed in this session.",
        ],
        "device_access":False, "flash_or_fuse_writes":False,
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("evidence",nargs="?",type=Path,
                   default=Path(__file__).resolve().parents[1]/"evidence/bootloader-analysis.json")
    p.add_argument("--out",type=Path)
    args=p.parse_args()
    result=audit(json.loads(args.evidence.read_text(encoding="utf-8")))
    report=json.dumps(result,indent=2,ensure_ascii=False)+"\n"
    if args.out:
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(report,encoding="utf-8")
    else:
        print(report,end="")


if __name__=="__main__":
    main()
