# Phase 48 — Signed EP0 class-control object, shared singleton and conditional class10 fanout

**26 October 2026 · PR #50 · Read-only reverse engineering of the exact SHA-256-pinned original OEM Bruce signed update.**

## Main discovery

The signed firmware has **two different dispatch mechanisms**. The generic control bridge at `0x600D0BFA` calls a method through a USB configuration object whose live contents remain unknown. More importantly, the signed **EP0-specific handler `0x60054D74` has two conditional callsites that forward internal event 1 to `0x6005505C`**, a class-aware fanout that recognizes class selector **10** and invokes signed class method **`0x600D0E59`** when an active runtime record has that selector.

This is a **static conditional route, not proof of actual class10 selection on a connected Stadia controller**. No host-controlled arbitrary callback, unsigned firmware execution, HAB CLOSED bypass or native console mode has been demonstrated.

## Verified memory ownership — five distinct RAM structures

A signed PC-relative literal at `0x60054FAC`, loaded by `0x60054F8A`, contains **`0x20004080`**. Signed lookup `0x60054F7C` compares its argument USB object with `[0x20004080]` and only on match returns the address `0x20004080` through its output pointer.

This common USB global is **distinct** from the other four class initializer addresses, pinned from signed literal pools:

| Signed initializer / lookup | RAM global |
|---|---|
| Shared USB lookup `0x60054F7C` | **`0x20004080`** |
| Class 1 `0x600552F0` | `0x200040C0` |
| Class 2 `0x60054C7C` | `0x20004040` |
| Class 4 `0x60054874` | `0x20004020` |
| Class 10 `0x60055320` | **`0x200040E0`** |

Initial attempts to attribute the shared EP0 address to class 1 were rejected by original-image audits. These are five distinct signed memory references, **not live object dumps**.

## Method call at 0x600D0BFA

After a successful shared-object lookup, signed instructions run:

```asm
0x600D0BF6  LDR R3, [R3,#4]   ; USB configuration object at [shared_global+4]
0x600D0BF8  LDR R3, [R3,#4]   ; dynamic configuration method pointer
0x600D0BFA  BLX R3
```

The method value at `config+4` cannot be resolved from the original file alone. It must **not** be equated with class10 ROM method-4 `0x600D0ECB`: the signed ROM method table has a different layout and the active configuration pointer is read from runtime RAM.

## A better signed path: two EP0 event-1 calls to the common class dispatcher

The signed EP0 handler `0x60054D74` includes these two original conditional regions:

```asm
0x60054E08  MOVS R1,#1
0x60054E1A  BL 0x6005505C

0x60054E5A  MOVS R1,#1
0x60054E6A  BL 0x6005505C
```

The class dispatcher `0x6005505C` performs a shared USB lookup (`0x60055072`); loads the **runtime configuration** from shared global offset `+4` (`0x6005508A`); reads its class-record count at `config+8` and its 12-byte runtime-record array at `config+0`. It reads each class selector from `[record+8]+4` and explicitly compares against **10** at `0x600550A8`.

The function also loads a **signed 16-byte per-class ROM method table** from a PC-relative literal at `0x600550E0`, which contains `0x60104B74`. If selector 10 is present, it uses class record index **3**, preserving event R1 via R7 and payload R2 via R6. At `0x600550BA`, it fetches the original class table's **method+8** function pointer, and at `0x600550BC: BLX R3` calls it. The signed class10 entry's method+8 is **`0x600D0E59`**.

The recipient/interface and bRequest guards and the further second callback dispatch were previously pinned in phases 45–46. This phase supplies a direct static connection between EP0 event 1 and the general class fanout, **subject to the real configuration containing class 10**.

## Verified class registration, ROM-vs-RAM distinction

The original class-selector loop at `0x60055178–94` reads 12-byte runtime records, compares their descriptor's class selector with each signed ROM table entry and invokes method+0 to initialize a class. It passes the runtime record pointer in R1 and record+4 in R2. The class10 constructor `0x60055320` stores R1 into **`[0x200040E0+4]`** and its singleton pointer at `[R2]`.

This is independent of the common EP0 singleton at `0x20004080`. Consequently the signed ROM `0x60104BA4` cannot simply be treated as the object's live 12-byte record or a dynamic config callback. The class2/class4 initializers and their distinct globals further reinforce this distinction.

## Remaining decision gates

The following have not been demonstrated: which configuration and class records the physical controller activates; which callback the real EP0 slots hold after startup; whether runtime event 1 reaches class10; whether the second signed class10 callback is enabled; live RAM readback; any user-supplied executable address; or a recoverable way around HAB CLOSED. No physical USB transfers, firmware flash modifications or eFuse changes were made.

**Phase 49 recommended:** trace writers of the **shared USB configuration pointer** `[0x20004080+4]`, the dynamic method at `config+4`, and the actual runtime class-record table. Only after that, evaluate safe passive device observation and decide whether the OEM path is feasible.

## Reproduce

```bash
python -m unittest tests.test_bruce_ep0_class_object_phase48 tests.test_bruce_class_singleton_phase48 tests.test_bruce_ep0_class10_fanout_phase48 -v
python -m tools.audit_bruce_ep0_class_object_phase48 local/bruce_pvt_a_prod_signed.bin
python -m tools.audit_bruce_class_singleton_phase48 local/bruce_pvt_a_prod_signed.bin
python -m tools.audit_bruce_ep0_class10_fanout_phase48 local/bruce_pvt_a_prod_signed.bin
```

Original signed OEM update SHA-256: `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`.

[Detailed Spanish report](../es/bruce-objeto-clases-ep0-fase48.md) · [PR #50](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/50).
