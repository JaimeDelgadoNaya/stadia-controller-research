# Phase 74 — Signed original Work Queue receiver guard execution and wait boundary

**26 October 2026.** Offline, exact SHA-256-pinned signed Bruce OEM image only (`466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`). Follows [phase 73](modeled-return-task-entry-phase73.md).

## Verified entry and signed mapping

The phase73 original worker had reached but not executed `0x600EE152 BL 0x6013D268`. Phase74 runs this original BL in the **retained virtual CPU state**, resolves the signed XIP veneer `0x6013D268 LDR.W PC,[PC,#-0]` through the *data* literal `0x00006D2D`, and executes original signed, startup-relocated ITCM instructions beginning at `0x6D2C`.

The ITCM bytes for runtime PC `0x6D2C` originate from file offset **`0x7548=0x81C+0x6D2C`**. The virtual machine inherited from phase73 previously mapped XIP but not ITCM. First original execution reached PC `0x6D2C` and failed with an unmapped fetch. Loading **only original signed startup ITCM bytes** into virtual memory repaired the emulator, not the device.

**13 signed instruction/literal pins** establish the entry and branch guards; the original executable path is:

```text
0x600EE152 → 0x6013D268 → 0x6D2C → 0x6D30 → 0x6D32 →
0x6D34 → 0x6D36 → 0x6D38 → 0x6D46
STOP before 0x6D58 BL 0x7734
```

After this execution, virtual R4 = queue control `0x200201AC`, R7 = output buffer `0x20020B1C`, and original timeout `0xFFFFFFFF` is preserved at `[SP+4]`. The virtual output buffer remains `0xA5A5A5A5`; **no item was delivered**.

## Original receiver branch conditions (static projection ONLY)

The signed receiver's later `0x6D7A LDR R5,[R4,#0x38]` and `0x6D7C CBZ` distinguish a zero item count. `0x6DB4 LDR R5,[SP,#4]` and `0x6DB6 CBNZ` lead toward a wait path when timeout is nonzero.

Virtual `[control+0x38]` currently equals **zero**, and timeout is **`0xFFFFFFFF`**. **If these values remain the same after unexecuted kernel synchronization helpers**, the empty-queue/wait branch would be selected. That is a conditional *static expectation*, **not executed blocking, scheduling, queue delivery, or callback**.

No original `0x7734` helper, critical sections, blocking, receive loop or callbacks were run. This is not a full architectural exception return and does not establish the same work queue/USB activity on physical hardware.

## Research decision

The original consumer entry and its argument checks are now anchored. The next useful investigation is **the genuine work-item producers**, including any connection to USB EP0/class10 or peripheral events. Fabricating a queue element to force a callback would not be admissible evidence. Phase75 should trace signed enqueue producers to an actual object and message format; then the receive path can be resumed with explicitly bounded synchronization models.

Unsigned code execution, active physical class10, host-controlled handlers and a HAB CLOSED bypass remain **unproven**.

## Reproduction

```bash
python -m pip install -r requirements-emulation.txt
python -m tools.audit_queue_receive_phase74 local/bruce.bin
python -m tools.execute_queue_guards_phase74 local/bruce.bin --out local/phase74.json
STADIA_BRUCE_IMAGE=local/bruce.bin python -m unittest tests.test_queue_receive_phase74 tests.test_queue_receive_guards_phase74 -v
```

[Structured original evidence](../../evidence/usb-queue-receive-phase74.json) · [PR #76](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/76).

No physical USB traffic, RAM readback, flash writes or eFuse changes.
