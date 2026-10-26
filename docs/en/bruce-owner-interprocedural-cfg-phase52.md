# Phase 52 — Bounded interprocedural CFG for the signed OEM USB-owner config transfer

**26 October 2026 · PR #54 · Offline-only analysis of the exact SHA-256-pinned original signed Bruce OEM update.**

## Confirmed conditional original-code chain

The new interpreter performs bounded ARM Thumb control-flow and symbolic address propagation across **three signed OEM functions**, tracing a hypothetical USB mode-2 configuration path:

\`\`\`text
0x60060FE8  USB mode-change function, R0=owner=0x2000A2A8
    |
    | signed conditional mode-2 guard
    v
0x6006102E  BL 0x60060F84
    |
0x60060F8A  ADDS R1,R0,#4       ; R1 = owner+4 = 0x2000A2AC
0x60060F90  BL 0x600550E4
    |
0x600550EA  MOV R4,R1            ; keep config STRUCT ADDRESS
0x60055104  LDR R3,[PC,#0xA0]   ; literal = 0x20004080
0x6005510C  MOV R5,R3
    |
0x6005512E  STR R4,[R5,#4]       ; [0x20004084] = 0x2000A2AC
\`\`\`

The OEM audit establishes the **conditional transfer of the address of the configuration struct**. It does not reveal the runtime **contents** of that struct.

The signed config installer also validates its method pointer before registration:

\`\`\`asm
0x600550F6  LDR R3,[R1,#4]  ; [owner+8]=[0x2000A2B0]
0x600550F8  CMP R3,#0
0x600550FA  BEQ 0x600551A2 ; abort if method is null
\`\`\`

**A non-null method is a precondition**, but neither its runtime value nor its source or host controllability has been demonstrated.

## Control sample and audit mechanics

The same symbolic CFG is run with mode 2 versus mode 1 as explicitly hypothetical starting inputs.

- Mode 2: **113 abstract states**, a conditional path to \`0x6005512E\` and an exact store of pointer value \`0x2000A2AC\` into address \`0x20004084\`.
- Mode 1: **31 abstract states**, no shared config pointer store through the surveyed three-routine path. This does not rule out other paths elsewhere.

The interpreter resolves Thumb PC-relative literals with \`((pc+4)&~3)+immediate\`, propagates known RAM/XIP pointers and constant offsets, explores unknown branch outcomes, preserves known callee-saved registers and discards caller-saved values after unmodeled calls. It stops at unsupported control boundaries and never evaluates real device RAM.

The first OEM CI audit **failed safely** when the interpreter omitted the Thumb PC base from a signed literal load. The defect was repaired and a synthetic test added for the exact PC-relative calculation and shared config pointer transfer. Unit tests alone were not accepted as OEM proof.

## Still unverified

| RAM field | Live value |
|---|---|
| \`owner+4 = 0x2000A2AC\` | Class-record array pointer **unmeasured** |
| \`owner+8 = 0x2000A2B0\` | Dynamic config method pointer **unmeasured** |
| \`owner+12 = 0x2000A2B4\` | Runtime class-record count **unmeasured** |

No connected-controller class10 selection, EP0-to-class10 live execution, host-controlled arbitrary function pointer, unsigned custom firmware, HAB CLOSED bypass, or native Xbox/Switch 2 compatibility has been established. **No device access, USB command, RAM readback, flash write or eFuse write occurred.**

This is a **bounded** interprocedural CFG, not an exhaustive whole-firmware proof. Other initializer functions remain unexplored.

## Next phase

Phase 53 should investigate the **writers of owner+8 (required non-null method) and owner+4/+12 (live class list)** using validated call contexts/aliases, or gather passive read-only USB enumeration evidence. Descriptor captures by themselves cannot prove internal RAM pointer state.

## Reproduce

\`\`\`bash
python -m unittest tests.test_bruce_owner_cfg_phase52 -v
python -m tools.audit_bruce_owner_cfg_phase52 bruce_pvt_a_prod_signed.bin --out phase52-owner-cfg.json
\`\`\`

Pinned original signed OEM SHA-256: \`466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3\`.

[Spanish report](../es/bruce-cfg-interprocedural-owner-fase52.md) · [PR #54](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/54).
