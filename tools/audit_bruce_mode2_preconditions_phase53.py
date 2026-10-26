"""Phase 53: SHA-pinned *necessary* OEM USB mode-2 preconditions.

This is a signed-code guard audit, not a live-RAM read, emulator of the
whole controller, or proof of physical EP0/class-10 reachability. It does not
send USB requests or write flash/eFuses.

The prior mode is read from owner+0x90 BEFORE the mode transition. Reaching
the mode-2 constructor requires a nonzero prior mode different from 2.
The routine first writes a transient status value 1 to owner+0x90, and only
later has a code path storing requested mode 2. Neither fact establishes
which path executed on a real unit.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SHA256, IMAGE_SIZE
from tools.audit_bruce_ep0_registration import decode
from tools.audit_bruce_usb_owner_pointer_phase50 import OWNER

PREVIOUS_MODE_FIELD = OWNER + 0x90
MODE2_CONSTRUCTOR = 0x60060F84
MODE_TRANSITION = 0x60060FE8
EXIT = 0x6006107C

# Each tuple includes the exact original signed machine-code mnemonic and
# operand rendering used by Capstone pinned in requirements.txt.
PINS = {
    0x60071428: ("cmp", "r4, #1"),
    0x6007142A: ("ite", "eq"),
    0x6007142C: ("moveq", "r1, #2"),
    0x6007142E: ("movne", "r1, #1"),
    0x60071430: ("b", "#0x60071416"),
    0x60060FEC: ("ldr.w", "r3, [r0, #0x90]"),
    0x60060FF0: ("mov", "r4, r0"),
    0x60060FF2: ("mov", "r5, r1"),
    0x60060FF4: ("cmp", "r3, r1"),
    0x60060FF6: ("beq", "#0x6006107c"),
    0x60060FF8: ("cmp", "r3, #0"),
    0x60060FFA: ("beq", "#0x6006107c"),
    0x6006101C: ("movs", "r7, #1"),
    0x60061020: ("cmp", "r5, #2"),
    0x60061022: ("str.w", "r7, [r4, #0x90]"),
    0x60061026: ("strb.w", "r3, [r4, #0x94]"),
    0x6006102A: ("bne", "#0x60061080"),
    0x6006102C: ("mov", "r0, r4"),
    0x6006102E: ("bl", "#0x60060f84"),
    0x60061032: ("tst.w", "r0, #0xff"),
    0x60061036: ("beq", "#0x60061056"),
    0x6006106E: ("cmp", "r5, #1"),
    0x60061070: ("str.w", "r5, [r4, #0x90]"),
    0x600550F6: ("ldr", "r3, [r1, #4]"),
    0x600550F8: ("cmp", "r3, #0"),
    0x600550FA: ("beq", "#0x600551a2"),
    0x6005512E: ("str", "r4, [r5, #4]"),
}

WINDOWS = (
    (0x60071428, 0x60071432),
    (0x60060FE8, 0x6006107C),
    (0x600550F4, 0x60055134),
)


def necessary_mode2_guard(previous_mode: int, requested_mode: int) -> bool:
    """Exact outcome of the two early compares + the mode-2 gate only.

    True means *not excluded by THESE guards*, not constructor reachability:
    external calls, hardware, memory, and further guards remain unmodelled.
    """
    if previous_mode < 0 or requested_mode < 0:
        raise ValueError("modes must be non-negative")
    return (
        previous_mode != requested_mode
        and previous_mode != 0
        and requested_mode == 2
    )


def method_guard(method_value: int) -> bool:
    """Necessary nonzero guard at 0x600550f6..0x600550fa.

    A nonzero value is not proof of a valid callable function pointer.
    """
    if not (0 <= method_value <= 0xFFFFFFFF):
        raise ValueError("method must be an unsigned 32-bit word")
    return method_value != 0


def verify_original_pins(image: bytes) -> dict:
    actual = {}
    for start, end in WINDOWS:
        for row in decode(image, start, end):
            actual[row["pc"]] = (row["m"], row["op"])
    for pc, expected in PINS.items():
        if actual.get(pc) != expected:
            raise ValueError(
                f"Phase53 original signed guard drift {pc:#x}: "
                f"{actual.get(pc)!r} != {expected!r}"
            )
    return {"count": len(PINS), "pcs": [hex(pc) for pc in PINS]}


def audit(image: bytes) -> dict:
    if len(image) != IMAGE_SIZE or hashlib.sha256(image).hexdigest() != IMAGE_SHA256:
        raise ValueError("Phase53 exact SHA-256-pinned signed OEM update required")
    pins = verify_original_pins(image)
    prior_modes = (0, 1, 2, 3, 4)
    controls = [
        {"previous_mode": n, "requested_mode": 2,
         "passes_necessary_early_guards": necessary_mode2_guard(n, 2)}
        for n in prior_modes
    ]
    return {
        "phase": 53,
        "signed_original_sha256": IMAGE_SHA256,
        "signed_image_verified": True,
        "original_instruction_pins": pins,
        "owner_address": hex(OWNER),
        "prior_mode_field_address": hex(PREVIOUS_MODE_FIELD),
        "initial_gate": {
            "read": "0x60060fec LDR.W R3,[R0,#0x90]",
            "first_abort": "0x60060ff4 CMP R3,R1 / 0x60060ff6 BEQ",
            "second_abort": "0x60060ff8 CMP R3,#0 / 0x60060ffa BEQ",
            "mode2_only": "0x60061020 CMP R5,#2 / 0x6006102a BNE",
            "necessary_condition": "prior_mode != 0 and prior_mode != requested_mode and requested_mode == 2",
            "illustrative_not_reachable_guarantees": controls,
        },
        "status_write_sequence_in_signed_code": [
            {
                "pc": "0x60061022",
                "field": hex(PREVIOUS_MODE_FIELD),
                "value": "1 (R7 initialized at 0x6006101c)",
                "claim": "conditional transient status write before constructor",
            },
            {
                "pc": "0x6006102e",
                "action": "BL 0x60060f84 if branch gates permit",
                "claim": "conditional call; no proof that hardware takes it",
            },
            {
                "pc": "0x60061070",
                "field": hex(PREVIOUS_MODE_FIELD),
                "value": "requested mode (R5; 2 for mode-2 seed)",
                "claim": "later signed conditional store, not a snapshot of runtime state",
            },
        ],
        "separate_constructor_method_guard": {
            "memory_address": hex(OWNER + 8),
            "method": "0x600550f6 LDR R3,[R1,#4], 0x600550f8 CMP R3,#0, 0x600550fa BEQ",
            "zero_value_rejected": True,
            "nonzero_pointer_known_or_valid": False,
        },
        "boundaries": {
            "what_this_proves": "necessary code-level guards and two original mode-field store sites",
            "prior_mode_on_real_controller": "UNMEASURED",
            "live_method_value": "UNMEASURED",
            "class_array_and_count": "UNMEASURED",
            "active_class10": "UNVERIFIED",
            "device_USB_requests": False,
            "flash_or_efuse_writes": False,
            "unsigned_execution": "NOT DEMONSTRATED",
            "HAB_CLOSED_bypass": "NOT DEMONSTRATED",
            "complete_CFG_or_runtime_emulation": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    output = audit(args.image.read_bytes())
    if args.out:
        args.out.write_text(json.dumps(output, indent=2) + "\n")
    print("PHASE53 ORIGINAL SIGNED GUARDS", json.dumps({
        "pins": output["original_instruction_pins"]["count"],
        "prior_modes": output["initial_gate"]["illustrative_not_reachable_guarantees"],
        "status_writes": output["status_write_sequence_in_signed_code"],
        "method_value": output["boundaries"]["live_method_value"],
    }))
    print("PHASE53 NO LIVE CLASS10 OR UNSIGNED EXECUTION PROOF")


if __name__ == "__main__":
    main()
