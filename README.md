# Stadia Controller Research

**Research integration.** The USB and NXP/bootloader tracks keep separate evidence and regression tests. Static analysis is not proof of physical execution, host access to the updater or HAB CLOSED bypass. [Five research workstreams](docs/en/parallel-research.md).

**[Phase 88 — SRC_GPR7 register-map correction and update-bit writer review](docs/en/src-gpr7-writers-phase88.md).** NXP documents `0x400F8038` as **SRC_GPR7**, not GPR6 (`0x400F8034`); phase87 corrected. The selected owner bootloader A instructions show **two attributable GPR7 writes**, clearing to `0` and app-status `0x10/0x20`; neither sets `0x08`. **New signed Bruce finding:** original code at `0x60078A1C–0x60078A28` writes **5 or 6** to SRC_GPR7; neither value asserts update bit `0x08`. The update-bit writer and USB provenance remain **unproved**. SHA-pinned original Thumb sequence and OEM literal census. [Tool](tools/audit_src_gpr7_writers_phase88.py).

**[Phase 87 — bootloader A GPR7 bit-3 update trigger](docs/en/bootloader-update-trigger-phase87.md).** Original signed code reads/clears `0x400F8038`; saved bit `0x08` conditionally invokes wrapper `0x60801ED0`, with **OEM-fixed callback, context and storage arguments**. The separate `0x10/0x20` app-failure status writer does not assert this trigger bit. **No proven writer of bit 3 or USB host control.** [Auditor](tools/audit_bootloader_update_trigger_phase87.py).

**[Phase 86 — bootloader A IVT update authentication/rollback audit](docs/en/bootloader-update-transaction-phase86.md).** **31 published original Thumb instruction pins** confirm current bootloader HAB authentication, structural-only candidate precheck, IVT backup and an **attempted fixed 4096-byte IVT install before candidate post-write HAB authentication**. Restore is attempted on relevant errors; **power-loss atomicity/recovery is not established**. 256 synthetic state combinations; 64 cumulative NXP tests passed. **No unsigned execution or HAB bypass proven.** [Evidence](evidence/bootloader-update-transaction-phase86.json).

**[NXP phase 85 — HAB `failsafe` decision](docs/en/nxp-hab-failsafe-decision-phase85.md).** SHA-256-pinned original signed Bruce scan finds **zero direct pointer words and zero directly decoded Thumb branches** to failsafe veneer `0x60040726`. **52 synthetic tests passed**. **Provisional NO-GO** for this stub as a custom-execution/ROM-version path; indirect callers remain unexcluded. [Evidence](evidence/nxp-hab-failsafe-callers-phase85.json).

**[NXP research phase 84 — original OEM HAB `failsafe` veneer](docs/en/nxp-hab-rvt-literals-phase84.md).** Exact original signed Bruce Thumb bytes load RVT base `0x00200300` and branch through NXP **`failsafe` (`+0x28`)**, not `get_version` (`+0x30`). Two RVT base literals found in Bruce; no direct `get_version` word in Bruce or RAM loader. **No ROM version measurement or HAB bypass.** [Evidence](evidence/nxp-hab-rvt-failsafe-phase84.json).

**[Phase 83 — provenance of the BootROM HAB version](docs/en/hab-rom-version-phase83.md).** NXP places the RT1060 HAB RVT at `0x00200300` and the `get_version` pointer slot at `0x00200330`. SHA-pinned offline auditing separates signed-image IVT/CSF format headers from live ROM revision. **No actual owner's `get_version` return is archived; precise HAB version and applicability remain unknown.** [Tool](tools/audit_hab_rom_version_phase83.py).

**[Phase 82 — interpreting HAB CSF UNLOCK](docs/en/nxp-hab-unlock-phase82.md).** **Pinned original finding:** signed RAM loader contains UNLOCK **OCOTP / SRK_REVOKE** (engine `0x21`, mask `0x00000002`, no UID), while Bruce has no UNLOCK. Offline CI/tests; no fuse access or HAB bypass. **UNLOCK affects selected peripheral access after BootROM; it does not disable HAB CLOSED or authorize custom code.** [Tool](tools/audit_hab_unlock_phase82.py).

**[Phase 81 — NXP HAB/CSF and SDP security advisories](docs/en/nxp-rom-csf-phase81.md).** SHA-256-pinned offline IVT/CSF checker with synthetic tests and CI on two archived public signed OEM images. Separates additional-image HAB authentication advisory from CVE-2022-45163 (SDP information disclosure). **BootROM HAB version unknown; no custom execution, signature bypass, or recovery demonstrated.** [Tool](tools/audit_nxp_rom_advisories_phase81.py).

**[Phase 80 — offline URB/IRP event pairing](docs/en/urb-irp-event-correlation-phase80.md).** Extends phase 79 to match USB S submissions to C completions/E errors with `usb.urb_id` or `usb.irp_id` **in memory only**. Reports orphan, reused, ambiguous duplicate and cross-endpoint events without exposing IDs. Older CSV exports and phase 61 descriptor gating remain supported. **Synthetic-only tests; no physical capture or USB→Work Queue linkage has been established.** [Tests](tests/test_passive_usb_phase80.py).


**[Phase 79 — passive USB metadata audit against measured OEM descriptors](docs/en/passive-usb-metadata-audit-phase79.md).** New **offline** Tshark CSV metadata auditor: SHA-pins the 80-byte phase61 physical descriptor, classifies known endpoint/EP0 URBs and S/C/E events, and refuses payload/serial-number columns. **Ten synthetic tests** cover classification and fail-closed errors; **no new physical capture** exists, and host→Work Queue callback control, unsigned execution and HAB CLOSED bypass remain unproven. [Tool](tools/audit_passive_usb_phase79.py) · [Tests](tests/test_passive_usb_phase79.py).

**[Phase 85 — physically confirmed USB controls](docs/en/usb-labeled-controls-phase85.md).** With isolated, user-confirmed actions: **A/B/X/Y → 1/2/4/5**, cardinal D-pad → **0/2/4/6**, and usages **20/19 are the left/right trigger digital indicators** alongside analog values. [Map](evidence/usb-control-map-phase85.json).

**[Phase 84 — original bridge functions on host](docs/en/bridge-host-experiment-phase84.md).** The pinned BLE translator was host-compiled for **6,995 paired checks** using hypothetical USB-derived payloads. Candidate 19/20 and consumer bits do not affect output or 13 inspected flags; Assistant/Capture affect their flags. Actual BLE remains unverified. [Evidence](evidence/usb-bridge-host-tests-phase84.json).

**[Phase 83 — USB and BLE bridge positions](docs/en/usb-ble-layout-comparison-phase83.md).** The pinned BLE parser shares positions with **13 USB button fields and six analog values**; cross-transport physical labels remain hypotheses. USB consumer bits and the BLE padding claim need separate testing. [Evidence](evidence/usb-ble-layout-comparison-phase83.json).

**[Phase 82 — differential HID tests](docs/en/hid-differential-tests-phase82.md).** **39,424 synthetic vectors without mismatches**, including every button subset, plus rejection of wrong IDs/lengths and 1,504 descriptor mutations. Fixed acceptance of Boolean/floating-point aggregate totals. Entirely offline. [Evidence](evidence/usb-hid-differential-phase82.json).

**[Phase 81 — offline HID decoder](docs/en/offline-hid-decoder-phase81.md).** Replay of **1,758 reports** handles the nonconsecutive HID button usages, raw axes, null states and diagnostics. Descriptor cross-checks validate parsing; physical labels and bridge output remain pending. [Evidence](evidence/usb-hid-decoder-replay-phase81.json).

**[Phase 80 — physical HID input confirmed](docs/en/hid-input-fields-phase80.md).** A 30-second window delivered **1,758 reports, all ID 3 and 11 bytes**, with changing buttons and six analog fields. Individual physical control assignments remain unresolved. [Evidence](evidence/usb-hid-field-observations-phase80.json).

**[Phase 79 — physical HID observation](docs/en/hid-observation-phase79.md).** A 10-second input read of the connected controller received **zero reports**. Without requested button actions this does not distinguish inactivity, mode or failure. This is not a bus capture or evidence of a Work Queue link. [Evidence](evidence/usb-live-hid-input-phase79.json).

**[Phase 78 — signed shared Work Queue initializer and USB inference boundary](docs/en/original-shared-workqueue-init-phase78.md).** Both the signed USB-mode writer from phase 66 and B initializer from phases 76–77 call original `0x6009267C` with **R0=1**. **16 pinned signed instructions** show it reads global Work Queue `0x2002014C`, handle `+0x58`, and the `Work Queue Task` literal. Two **original virtual guard paths executed**: absent handle stops before creation at `0x6010177A`; existing handle skips creation and returns zero. A common singleton initialization helper is **not evidence of a physical host USB packet, controllable callback, unsigned execution or HAB CLOSED bypass**. [Evidence](evidence/usb-workqueue-shared-init-phase78.json) · [PR #80](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/80).

**[Phase 77 — owner-relative Work Queue object and producer guards](docs/en/workqueue-owner-lineage-phase77.md).** Original OEM activation contains a **direct `0x600747D8 BL 0x6006B3E8`** to the signed B work-object constructor. Signed pointer math forms `GLOBAL+0x3F04`, or **`0x2000A3C4 = owner+0x11C`** under the phase66 modeled initial input. The original B constructor installs signed `0x6006B291` method at object `+0x11C`, context at `+0x120` and a byte at `+0x180`; callback B reads and clears separate `+0x182`. A's local input provenance is `R5=R0`, `R4=R2`, with additional signed `0x0E` and atomic guards. **No physical USB-origin event, live callback control, unsigned firmware execution or HAB CLOSED bypass is established.** [Evidence](evidence/usb-workqueue-owner-origin-phase77.json) · [PR #79](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/79).

**[Phase 76 — upstream Work Queue caller provenance and signed OEM callback](docs/en/workqueue-caller-origin-phase76.md).** Original signed guards are now pinned for two producers: `0x6006228C` passes `R4+0x10` following an exclusive-byte/previous-zero flag check; `0x6006B2B0` passes `R4+0x11C` when `[R4+0x182]==0` and `0x600D8F64` returns 2. **New finding:** the signed initializer loads original Thumb `0x6006B291` at `0x6006B416` and writes the callback/context to `[R4+0x11C]/[R4+0x120]`. This B item uses an **OEM-provided function pointer** on the shown path, not a proven host-supplied address. The B initializer and phase66 owner-mode fragment share helper `0x6009267C`, **without proven common object or USB event reachability**. No live callback, own firmware or HAB CLOSED bypass. [Evidence](evidence/usb-workqueue-caller-provenance-phase76.json) · [PR #78](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/78).

**[Phase 75 — signed Work Queue producers and conditional callback dispatch](docs/en/workqueue-message-producers-phase75.md).** Original OEM instructions link two signed callers (`0x6006228C`/`0x6006B2B0`) to a **producer for the same Work Queue** `0x2002014C`: `0x600926A0 → 0x600EE18A → 0x6013D0E8 → ITCM 0x6A74`. The producer prepares **type-zero work messages with an item pointer**; a conditional queue path increments the count at `0xB394/0xB396`. The original worker after receiving has a method/argument load and `0x600EE172 BLX R3`. **This is a signed, conditional static pipeline, not an observed enqueue, callback, hardware USB trigger, custom firmware execution or HAB CLOSED bypass.** [Evidence](evidence/usb-workqueue-producers-phase75.json) · [PR #77](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/77).

**[Phase 74 — original Work Queue receive guards and bounded wait boundary](docs/en/original-workqueue-receive-phase74.md).** Original `0x600EE152 BL` reaches `0x6013D268` veneer and signed ITCM **`0x6D2C`**. Signed startup ITCM bytes are loaded into the retained phase73 virtual machine; original argument guards execute, stopping **before `0x6D58 BL 0x7734`**. The original input is preserved (control `0x200201AC`, output `0x20020B1C`, timeout `0xFFFFFFFF`), with unchanged output. Virtual `[control+0x38]` is **zero**, implying an **unexecuted conditional empty-queue/wait prediction** only. No fabricated messages, synchronization/dequeue/callback execution, physical class10 activation, unsigned execution or HAB CLOSED bypass. [Evidence](evidence/usb-queue-receive-phase74.json) · [PR #76](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/76).

**[Phase 73 — explicit return model and original task entry](docs/en/modeled-return-task-entry-phase73.md).** An explicit basic-frame register bridge loads the prepared task context; original entry 0x60101760 dispatches to OEM worker 0x600EE142 and stops before its queue call. Real exception return, queue reception, callbacks and physical activation remain unexecuted/unmeasured.

**[Phase 72 — original SVC software restore](docs/en/svc-software-restore-phase72.md).** The retained pre-SVC virtual CPU executes the original wrapper/handler, restores saved words, sets PSP 0x20020B28 and clears BASEPRI. It stops before BX LR: SVC delivery, exception return, hardware unstacking and task entry remain unexecuted.

**[Phase 71 — nesting normalization and pre-SVC stop](docs/en/critical-normalization-svc-phase71.md).** Original port-start code clears the OEM nesting sentinel with virtual priority readback mask 0xF0 and stops before SVC. BASEPRI remains 0x50 there; its later handler clear is statically identified. Exception/context switch and physical priority behavior remain unexecuted/unmeasured.

**[Phase 70 — original scheduler registration and critical state](docs/en/scheduler-registration-phase70.md).** Original registration and ITCM list/critical helpers insert the prepared state in a virtual priority-1 ready list. The OEM nesting sentinel retains virtual BASEPRI 0x50; a separate zero-depth vector restores zero. No task entry/context switch or physical activation executes.

**[Phase 69 — original task handle and frame](docs/en/original-task-handle-phase69.md).** Original creator/state/frame code derives handle 0x20020278 and prepares PC 0x60101760 with Work Queue argument 0x2002014C. No opaque handle is injected. Scheduler registration remains stubbed and task entry/physical activation are not executed.

**[Phase 68 — original work-queue constructor](docs/en/workqueue-constructor-phase68.md).** Signed initializer entry 43 points to 0x600926D0. Original stores clear the handle and provide auxiliary pointer 0x20020278, buffer pointer 0x2002034C and size word 0x200, replacing phase67 auxiliary fixtures. Actual task creation and physical startup remain modeled/unmeasured.

**[Phase 67 — pending work-queue call and return conditions](docs/en/pending-workqueue-call-phase67.md).** Original 0x6009267C now executes to normal return or observed error. Nonzero handle field returns zero; missing auxiliary state returns 9 and the tested below-threshold size returns 3. Mode 1 is already stored even on error. Scheduler state remains synthetic and physical activation unmeasured.

**[Phase 66 — original driver and prior-mode writer](docs/en/usb-driver-prior-mode-phase66.md).** The original driver/helper execute against virtual MMIO: low five bits of 0x402E0124 must exceed 7. An original store establishes prior mode 1 in a modeled caller path; staged transition/driver/class10 execution succeeds for virtual word 8 and blocks for 7. Pending 0x6009267C and real peripheral behavior remain unexecuted.

**[Phase 65 — class10 instance gates and owner path](docs/en/class10-instance-phase65.md).** Original owner/core/class code binds the OEM record to instance 0x200040E0 when the low-level driver is stubbed to succeed; driver failure blocks it. Missing/mismatched engine returns 4 and busy class returns 2. Earlier mode-transition guards and physical activation remain unresolved.

**[Phase 64 — original records include internal class 10](docs/en/original-class-records-phase64.md).** Original producer execution builds class records [10, 1, 2, 4] from signed startup data. Class10 carries callback 0x600613FD; the original selector matches method 0x60055321 before its call. Physical activation and complete engine setup remain unmeasured.

**[Phase 63 — provider and initial flag writers](docs/en/usb-provider-initialization-phase63.md).** Signed initialization links owner 0x2000A2A8 to the descriptor provider and supplies initial zero stores for both flags. Bounded virtual internal-event dispatch reaches the original 80-byte selector; actual class-record contents and installed RAM remain unresolved.

**[Phase 62 — exact live descriptor match in OEM](docs/en/usb-descriptor-oem-match-phase62.md).** The complete 80-byte hub descriptor matches exactly once at OEM XIP 0x6011E45A. Bounded original-code emulation verifies four conditional descriptor profiles; live flags and callback activation remain unmeasured.

**[Phase 61 — live USB enumeration](docs/en/usb-enumeration-phase61.md).** Parent-hub reads expose two interfaces in 80 bytes; the WinUSB function view contains only the vendor interface in 32 bytes. Bulk 0x07/0x87 and HID 0x03/0x83 are declared. No callback reachability or custom execution proven.

[English](README.md) · [Español](README.es.md)

Reverse-engineering notes, measured evidence and offline tools for investigating
the original Google Stadia Controller electronics. The long-term question is
whether custom firmware can run on the original hardware.

**Current result: secure boot is CLOSED on the tested controller. No custom
firmware execution or signature bypass has been demonstrated.**

**[Phase #60 — USB callback hypothesis decision](docs/en/bruce-pair-usb-decision-phase60.md).** The signed OEM audit traced **10 bounded local aliases** from global base `0x2000F878` to pair `0x2000FBF4/FBF8`, confirming the **two signed writer sites** but **no proven reader** along those runs. It found **37 aligned Thumb-shaped literals** (35 no-op `0x600CE233`, one `0xA9C5`, one `0x6007E6A1`) and **no direct BL shapes** to the studied targets in audited ranges. **Provisional NO-GO** as a host-controlled execution avenue: no verified pair invoker or host USB trigger, **not proof of impossibility**. Prioritize read-only USB enumeration and evaluate an external bridge. Custom firmware execution and HAB CLOSED bypass remain unproven. [Evidence](evidence/bruce-pair-event-phase60.json) · [PR #62](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/62).

**[Phase #59 — signed global pair consumers and resolved ITCM handler](docs/en/bruce-pair-consumers-phase59.md).** On the original signed OEM update, **8 aligned literals** and **10 candidate PC-relative LDR sites** reference base `0x2000F878`. A corrected **every-halfword Thumb scan**, requiring the two known original stores as positive controls, found **11 offset-shaped `+0x37C/+0x380` operations**. Its single direct byte reader (`0x600BD138`) loads a **different base, `0x20025CE0`**; no reader/invoker of the exact pair `0x2000FBF4/FBF8` has been proved. ITCM `0xA9C4→0xB980` is a veneer whose signed pointer resolves to actual XIP handler **`0x6007E6A0`**, which checks internal state and uses atomics. **No proven USB-host control, live class10, custom code execution or HAB CLOSED bypass.** [Evidence](evidence/bruce-pair-consumers-phase59.json) · [PR #61](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/61).

**[Phase #58 — signed global function/context pair after +0x80 reader](docs/en/bruce-function-context-registry-phase58.md).** The two original signed branches `0x6007E7FA/0x6007E81E` call `0x600D54B8`, which **does not forward its incoming R0 directly**; it stages the former R1/R2 into `0x6006386C`, which writes a two-word pair at **`0x2000FBF4/0x2000FBF8`**. One branch writes **`0x600CE233`** (signed XIP `BX LR` no-op) with context 0; the other **`0xA9C5`** (ITCM `B.W 0xB980`) with context R4 (object pointer). **Callback/context-like**, but no proof of invocation, live class10, host-controllable USB entry, custom firmware execution or HAB CLOSED bypass. [Evidence](evidence/bruce-field80-helper-phase58.json) · [PR #60](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/60).

**[Phase #57 — signed dynamic object to shared SRAM global and USB reader](docs/en/bruce-global-consumer-phase57.md).** Signed OEM code conditionally stores `owner` at `[object+0x80]` and publishes that object through **global SRAM `0x2001EE30`**. A separate getter reads **the exact same literal SRAM address** before calling `0x6007E794`, whose guarded paths dereference the input's `+0x80` (`0x6007E7EA`/`0x6007E810`). This closes a **conditional static producer/global/reader chain**, **not runtime ordering, current RAM values or physical host reachability**. A second ITCM veneer reader was identified but remains unlinked to that same instance. No custom execution or HAB CLOSED bypass. [Evidence](evidence/bruce-parent-consumer-phase57.json) · [PR #59](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/59).

**[Phase #56 — dynamic R0 producer and +0x80 reader candidates](docs/en/bruce-parent-r0-phase56.md).** The constructor call at `0x60079D84` receives R0 from **`0x6013D378` called with size 164**. The signed veneer resolves into **ITCM runtime `0xB532`**, forwarding through `0x8832` to `0x7F58`, with **allocation-like behavior**, while the actual runtime R0 value stays unmeasured. A signed-code census finds **32 candidate +0x80 reads** (29 LDR, 3 LDRB), **none proven to use that same allocated object**. Active class10, `owner+4/+8/+12` producers, custom execution and HAB CLOSED bypass remain unresolved. [Evidence](evidence/bruce-parent-r0-phase56.json) · [PR #58](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/58).

**[Phase #55 — signed owner pointer stored through unknown R0 object base](docs/en/bruce-owner-holder-phase55.md).** The signed Bruce OEM code loads `owner=0x2000A2A8` into **R2**, passes it to `0x6007EB8C`, saves it in **R8**, and conditionally writes **`[R4+0x80]`**, with R4 derived from an *unknown R0 object base (not attributable to owner fields)*. **19 original signed instruction pins** are verified. Separately, two signed getters load `0x200030E8`, the start of adjacent boot-initialized records with selectors **2 and 10**. **No proven link** joins the parent holder, these records, and live USB class selection. `owner+4/+8/+12` remain unmeasured; no custom firmware execution or HAB CLOSED bypass. [Evidence](evidence/bruce-owner-holder-phase55.json) · [PR #57](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/57).

**[Phase #54 — bounded USB owner writer search with positive controls](docs/en/bruce-owner-writers-phase54.md).** A bounded interprocedural scan of **11 original signed owner LDR PC sources** found **no attributed writer** to `owner+4/+8/+12` within its scope, but recovered **two independently pinned original stores** to the distinct control field `owner+0x90` (`0x60061022`, `0x60061070`). One seed exhausted the 10,000-state search budget, so this **does not prove absence of writers**. Live class10, custom execution and HAB CLOSED bypass remain unverified. [Evidence](evidence/bruce-owner-writers-phase54.json) · [PR #56](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/56).

**[Phase #53 — signed mode-2 entry preconditions](docs/en/bruce-mode2-preconditions-phase53.md).** Original signed OEM code exits early when the **previous USB mode is 0** or already equals the requested mode. Requesting mode 2 therefore clears these early guards only if the prior mode is nonzero and differs from 2. Original code also writes a **transient 1** to `owner+0x90` before the constructor, with a later conditional store of the requested mode. These are **necessary static-code conditions**, not a RAM measurement, active class10 evidence or custom firmware execution. [Evidence](evidence/bruce-mode2-preconditions-phase53.json).

**[Phase #52 — bounded interprocedural CFG for signed USB owner](docs/en/bruce-owner-interprocedural-cfg-phase52.md).** The original signed OEM audit conditionally traces USB mode 2 through `0x60060FE8 → 0x60060F84 → 0x600550E4` and identifies the exact configuration **address** transfer at `0x6005512E`: **`[0x20004084] = 0x2000A2AC`** (`owner+4`). Registration is further gated on **non-null `[owner+8]`** (read/compare/branch at `0x600550F6–FA`). The bounded CFG visited 113 hypothetical mode-2 states vs 31 mode-1 states, with no analogous config-store in the latter route. **Actual `owner+4/+8/+12` values, active class10 membership, unsigned execution, and HAB CLOSED bypass remain unproven.** [Evidence](evidence/bruce-owner-interprocedural-cfg-phase52.json) · [PR #54](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/54).

**[Phase #51 — signed USB owner class-field writer provenance](docs/en/bruce-owner-class-writers-phase51.md).** The exact original Bruce signed update contains **16 aligned owner-base literals**, with **11 PC-address-matched LDR candidates**. Bounded local alias tracing establishes **no direct store** to `owner+4/+8/+12` along those straight-line regions. One-hop callees mostly inspect USB mode/status (`+0x90/+0x98/+0x104`); a tempting `+4` store is **not** attributable to owner because the pointer is provided in R2 while stores use R0. **This does not exclude indirect/interprocedural writers or establish actual class10 activation**. Live RAM, custom execution and HAB CLOSED bypass remain unproven. [Evidence](evidence/bruce-owner-class-writers-phase51.json) · [PR #53](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/53).

**[Phase #50 — signed USB owner RAM pointer and guarded mode-2 setup](docs/en/bruce-usb-owner-runtime-class-fields-phase50.md).** The original signed OEM code loads **`owner = 0x2000A2A8`** at `0x60071416` and conditionally enters USB mode **2** through `0x60060FE8` and configuration constructor `0x60060F84`. Derived RAM field addresses are `owner+4 = 0x2000A2AC` (class array), `owner+8 = 0x2000A2B0` (dynamic method) and `owner+12 = 0x2000A2B4` (record count). **16 aligned signed XIP literals** reference owner base; actual field values, active class10 membership and live EP0 reachability remain **unmeasured**. No custom firmware execution or HAB CLOSED bypass. [Evidence](evidence/bruce-usb-owner-class-fields-phase50.json) · [PR #52](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/52).

**[Phase #49 — signed shared USB configuration writer and owner provenance](docs/en/bruce-active-usb-configuration-phase49.md).** Signed function `0x600550E4` stores its caller's configuration pointer at **`0x20004084`** using `0x6005512E`. Signed caller `0x60060F84` passes **`owner+4`** as config, `owner+0x10` as mode byte and `owner+0x98` for USB engine output; `0x60055350` installs fixed **OEM-signed** USB callbacks and vtable. The live **`config+0` class list, `config+4` control method and `config+8` record count** are runtime fields whose values are not read back. Existence of a signed class10 record does **not** prove its presence in the active USB configuration, custom execution or HAB CLOSED bypass. [Evidence](evidence/bruce-active-usb-configuration-phase49.json) · [PR #51](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/51).

**[Phase #48 — signed conditional EP0 event1-to-class10 fanout](docs/en/bruce-ep0-class-object-phase48.md).** The original signed EP0 handler (`0x60054D74`) has **two conditional internal-event-1** calls to the shared class fanout `0x6005505C`, which inspects runtime class records, checks selector **10**, and can call signed method **`0x600D0E59`**. EP0 lookup uses the shared USB singleton **`0x20004080`**, distinct from class 1/2/4/10 globals (`0x200040C0/40/20/E0`). The separate dynamic `0x600D0BFA` configuration method remains unresolved. **Live class10 presence and physical USB reachability are unverified; no unsigned execution or HAB CLOSED bypass.** [Evidence](evidence/bruce-ep0-class-fanout-phase48.json) · [PR #50](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/50).

**[Phase #47 — dedicated signed OEM EP0 IN/OUT installer identified](docs/en/bruce-ep0-slot-writers-phase47.md).** The signed Bruce update contains **`0x60054F30`**, which conditionally installs the **same original signed callback `0x60054D75`** into EP0 IN (`0x80`) and EP0 OUT (`0x00`), rolling back the first on second-register failure. Original code confirms guarded caller `0x600D0BE0`; the EP0 handler `0x60054D74` reads SETUP-like fields and has routes calling `0x600D0BC8` for additional control dispatch. Generic endpoint selector/clearer conditions are also pinned. **This is a static signed-image execution graph, not live USB EP0 slot/vtable or class10 reachability proof.** No unsigned code, HAB CLOSED bypass or native console support demonstrated. [Evidence](evidence/bruce-ep0-pair-phase47.json) · [PR #49](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/49).

**[Phase #46 — signed USB1 endpoint callbacks and bRequest event bridge](docs/en/bruce-usb1-ep0-class10-phase46.md).** The signed USB1 vector (`0x600610D1`), XIP endpoint event receiver (`0x600D0FB6`) and dynamic 12-byte endpoint callback slots are pinned (EP0 OUT slot 0, IN slot 1). Four OEM adapters pass **internal event types**, not raw USB `bRequest` values. The signed class event TBB bytes confirm **event 1 → `0x600D0EA2` → bRequest load**, correcting an earlier event-4 hypothesis. **Actual physical EP0 callback contents and USB1-to-class10 runtime reachability remain unverified.** [Evidence](evidence/bruce-usb1-ep0-class10-phase46.json) · [PR #48](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/48).

**[Phase #45 — conditional USB request byte to signed class10 dispatch](docs/en/bruce-ep0-class10-r1-phase45.md).** Original signed code conditionally forwards `SETUP[1]` as R1 via `0x600D0EB8`, then the class10 guard at `0x600613FC` (R1 > `0x7F`) and installed signed OEM secondary callback `0x600DB029` can dispatch to **13 cases `0x80–0x8C`**. Local signed effects of all cases were inspected; `0x81/0x83/0x84` do not locally show arbitrary callback-pointer installation. **Real USB1 EP0 routing, active class selection and physical execution remain unverified.** [Evidence](evidence/bruce-ep0-class10-phase45.json) · [PR #47](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/47).

**[Phase #44 — second signed callback writer and 13-way dispatch](docs/en/bruce-secondary-writers-phase44.md).** Original signed Bruce code writes a second **OEM-signed function `0x600DB029`** to `0x20009EF8` and context object **`0x20003670`** to `0x20009EFC`; its handler switches over **13 cases, `0x80–0x8C`**. The verified static caller gets the object pointer from a signed literal; device execution, live EP0 host control, custom execution and HAB CLOSED bypass are **not** demonstrated. [Evidence](evidence/bruce-secondary-writers-phase44.json) · [PR #46](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/46).

**[Phase #43 — signed startup constructor path to secondary callback](docs/en/bruce-startup-init-chain-phase43.md).** Original code at `0x6004C742` calls a **45-entry** constructor-array walker; entry 21 calls wrapper `0x600748EC`, which passes original base literal **`0x200064C0`** to the global initializer. That initializer writes signed no-op sentinel `0x600D4F05` at **`0x20009EF8`** and zero context at **`0x20009EFC`**. **Static signed-image chain proven**, actual device execution and later writes **not measured**. No demonstrated host control, HAB CLOSED bypass or firmware interoperability. [PR #45](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/45).

**[Phase #42 — signed secondary callback initializer](docs/en/bruce-class10-secondary-init-phase42.md).** Original OEM signed code contains a routine writing the fixed no-op sentinel `0x600D4F05` to `base+0x3A38` and zero to `base+0x3A3C`. **If** the runtime base argument is `0x200064C0`, this exactly addresses the suspected callback/context (`0x20009EF8/FC`), but **the actual caller, argument and runtime execution are unverified**. A separately verified direct caller of one phase-41 candidate writes elsewhere (`0x20015F70`). [PR #44](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/44). No host-controlled code execution, HAB bypass or physical device writes.

**[Phase #41 — secondary class-10 callback slot census](docs/en/bruce-secondary-callback-phase41.md).** Exact OEM signed-image audit confirms the original `0x6006140A` read of RAM callback slot `0x20009EF8`. **No statically resolved direct writer** appeared in the bounded model: of 24 offset-shaped stores, 12 are stack-based, 3 resolve elsewhere and **9 have unknown non-stack bases**. The real RAM contents, USB host control and custom code execution remain unproven. [Evidence](evidence/bruce-secondary-callback-phase41.json) · [PR #43](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/43).

**[Phase #40 — original class-10 callback located](docs/en/bruce-class10-signed-callback-origin.md).** Signed OEM Bruce boot data initializes the class-10 record at `0x200030F4` with Thumb pointer **`0x600613FD`**, initially-null object and an associated class-10 descriptor at `0x20003100`. Original code `0x600613FC` rejects `bRequest <= 0x7F`; `0x81/0x83/0x84` pass this initial check and depend on a **second callback registered in RAM**, whose live source/value is unproven. Offline-only; no own firmware execution, HAB CLOSED bypass or Xbox/Switch 2 interoperability. **Active objective: direct original-electronics compatibility without an external bridge.**

**[Package A complete — archived WebHID/WebUSB host protocol](docs/en/archived-updater-host-protocol.md).** The host installs images via **ROM SDP and signed RAM flashloader**, not bootloader-A Bulk OUT `0x07`. See [sanitized evidence](evidence/archived-updater-host-protocol.json). Custom unsigned execution remains unproven; package B was completed in phase 31.

**HISTORICAL DECISION — [Phase 31: stop internal firmware modification, begin external bridge](docs/en/final-execution-recovery-decision.md).** The agreed last offline work package is complete. ROM HAB **CLOSED**, signed images validate, but no authorizable custom execution or reliable rollback was established. **Stop internal modification unless independent new evidence changes the gates.** Next: reversible ESP32-S3 Stadia BLE → **PC** Xbox 360-style gamepad prototype; Xbox One/Series authentication requires separate verification.

**[FillMemory policy verified on the original signed loader](docs/en/fillmemory-verified-policy.md).** FillMemory (operation 0) and WriteMemory (operation 2) invoke the same range verifier `0x200039A8` with **different allowed-address tables**. The normal FillMemory table excludes the Execute/Call gate bytes. Overflow and indirect-backend effects remain unproven; there is no HAB bypass or custom firmware execution.

**[FillMemory 32-bit wrap and backend limitations](docs/en/fillmemory-overflow-boundaries.md).** An original-image-anchored model finds wrapped end addresses that pass two static range checks. The dynamic protection check and real write effects remain **unverified**; the backend attempts a huge fill beyond the mapped RAM region. No custom execution or HAB bypass has been shown.

**[FillMemory dynamic-guard initialized bounds](docs/en/fillmemory-dynamic-guard-provenance.md).** PR #29 verifies the four constants written by the original signed initializer. With those limits, the modeled guard can miss a wrapped end address, but completing the implied ~3.5 GiB fill is unproven. No physical initialized RAM measurement, firmware execution, or safe recovery is claimed.

**[FillMemory: initializer order and virtual backend stop](docs/en/fillmemory-init-order-first-boundary.md).** PR #30 executed the original low-level FillMemory Thumb code in bounded Unicorn memory. Wrapped-length cases enter a **byte-by-byte store loop** and hit the *virtual* unmapped region at `0x20020000` without returning. This is not a physical bus fault or custom execution proof. Initialization before dispatch is still not proven.

**[New audit: OEM-signed Bruce prod/stage/dev and updater](docs/en/bruce-oem-signed-variants-execution.md).** Exact public originals verify that all three OEM images have **identical authenticated executable application bytes**; the differences are in signing material, with distinct embedded signer keys. The only aligned signed-to-tail pointer is IVT→CSF metadata. Archived updater uses ROM SDP plus a vendor-signed RAM loader. **No arbitrary execution, HAB bypass or reliable recovery demonstrated.**

**[Bruce normal-mode USB class receiver audit](docs/en/bruce-normal-usb-class-requests.md).** PR #32 compared OEM host's `0x81/0x83/0x84` class requests to the exact signed Bruce code. Eight raw CMP-immediate matches were cataloged, but the examined candidates operate on **buffer bytes or structure fields**, not a confirmed EP0 SETUP `bRequest`. **No host-to-custom-execution path or verified recovery.**


**[New phase: signed Bruce USB SETUP → endpoint callback chain](docs/en/bruce-ep0-callback-chain.md).** PR #33 verifies the OTG1 vector, relocated ITCM SETUP intake, XIP dispatcher at `0x600D0FB6` and dynamic callback call `0x600D104E`. **Actual EP0 callback registration and OEM class bRequest handlers remain unresolved.** No physical memory writes or arbitrary code execution.


**[Signed Bruce endpoint callback registration — phase #34](docs/en/bruce-ep0-registration.md).** The original OEM image verifies `0x600D10B8` as the 12-byte endpoint callback registrar, two descriptor-loop callers and four signed class-event forwarders. **The actual EP0 slot and host `bRequest 0x81/0x83/0x84` receiver remain unidentified.** No custom code execution, HAB bypass, physical USB commands or device modifications.


**[Phase #35 — USB SETUP and class callback provenance](docs/en/bruce-class-control-setup-provenance.md).** Signed original Bruce image analysis validates SETUP-like `bmRequestType`, `bRequest`, `wValue`, `wIndex` field reads, a standard-request range 1–11, and **conditional class `bRequest` forwarding via `0x600D0EB8`**. Adjacent `0x60104BA4` and `0x60104BC4` tables are not interchangeable. Live EP0 object and receiver for `0x81/0x83/0x84` remain unverified; no controller I/O, HAB bypass, installable firmware or Xbox/Switch 2 support claimed.


**[Phase #36 — signed Bruce class-table references](docs/en/bruce-class-table-xrefs.md).** The original SHA-verified firmware shows that PC-relative load at `0x6005679A` points to a **different eight-byte-stride indirect dispatch table** at `0x60104BDC`. PC-relative and local `MOVW/MOVT` scans did not establish live EP0 registration of `0x600D0E58` or a receiver for `0x81/0x83/0x84`. Offline only; no hardware or firmware writes.


**[Phase #37 — original signed class records and synthetic SETUP execution](docs/en/bruce-class-records-synthetic-setup.md).** **Corrected in phase #38:** five 16-byte entries start at `0x60104B74`, with selector at offset `+12`; **selector `10`**, not `4`, owns `0x600D0E58`. Bounded Unicorn execution of **original signed Thumb instructions** forwards synthetic `0x81/0x83/0x84` in R1 only when recipient/interface match, stopping **before** the indirect callback. This does **not** prove real EP0 registration, host reachability, own code execution or HAB bypass.


**[Phase #38 — verified signed Bruce class selection](docs/en/bruce-class-selector-phase38.md).** Two Thumb PC literals resolve the true `0x60104B74` base and five 16-byte entries. Bounded Unicorn execution confirms class ID `4` selects `0x60054875` while ID `10` selects `0x60055321`; no class method executed. The SETUP forwarding method `0x600D0E58` belongs to ID **10**. Physical EP0 and final callback remain unverified.


**[Phase #39 — source of class10 callback R1](docs/en/bruce-class10-r1-origin.md).** The original SHA-pinned Bruce machine code shows `0x60055320` receives a **12-byte application configuration entry**, selected as `R1=[original_config_argument]+12*interface_index`. Record `+8` points to a descriptor, `+4` receives the class instance and `+0` is a potential callback word whose writer remains unresolved. No host-chosen function pointer, arbitrary execution or native console interoperability proven.

## Current priority: on-controller software and direct Switch 2

The owner excludes adapters and external boards. The active goal is software
modification on the original Stadia electronics for direct console use, including
**Switch 2**. See [feasibility and minimum target](docs/en/direct-switch2.md).

Nintendo documents wired original Pro Controller support on Switch 2. Emulating
that USB protocol is an initial target conditional on achieving custom execution
on Stadia; a name or VID/PID change alone is insufficient. Switch 2 controllers
use proprietary BLE rather than Stadia's generic BLE HID profile.

The owner's new instruction reopens bounded offline investigation. Phase 31's
technical blockers remain: repeated local signature verification passes original
images and rejects a one-byte mutation. Custom execution, HAB bypass and complete
recovery remain unproven. No controller firmware was changed.

The [message receiver review](docs/en/application-message-role.md) corrects the entry and identifies
tag 5 as two-value HID control, possibly rumble; it does not establish a
firmware update handler.

The continuation adds [USB dispatch and code relocation](docs/en/application-usb-dispatch.md),
[live HID capabilities](docs/es/capacidades-hid.md) and the
[loader's initial Execute/Call gate](docs/en/loader-execution-gate.md).
The device query read metadata only; no output reports were sent. These results
are not an unlock.

Historical external-route work is retained in the [console matrix](docs/en/console-compatibility.md),
[pinned bridge preparation](docs/en/external-bridge.md) and
[Windows input diagnostic](docs/es/diagnostico-entrada.md). It is not the current
implementation priority.

## Measured progress

| Item | Observed result |
|---|---|
| Application | Bruce build **337784** (`0x52778`) |
| Bootloader A | Build **169429** (`0x295D5`), extracted and CMS signatures verified |
| Bootloader B slot | 128 KiB entirely `0xFF`; no installed second bootloader |
| MCU identifier | `0x006C0000`, labelled **106XA0** by stadiatool |
| Flash identification | `0x17C8`, GigaDevice 16 MB |
| ROM HAB status | **CLOSED**, `0x12343412` |
| Signed RAM loader property `0x11` | Value **1**; statically traced to `OCOTP_CFG5` bit 1 |
| Final device state | Normal USB mode; original version response unchanged |

Measurements come from **one controller**, on 2026-10-25. They do not establish
that every controller has the same configuration. The firmware build was read
from the device; the full installed application was not dumped and hash-matched.

## Research notes

- **[Complete handoff: state, reproduction and where to resume](docs/en/handoff.md)**
- [Device measurements and extraction method](docs/en/measurements.md)
- [Boot chain, update validation and open questions](docs/en/boot-chain.md)
- [IVT update flow and ARM emulation — phase 10](docs/en/update-flow.md)
- [Storage mapping and wrapper emulation — phase 11](docs/en/storage.md)
- [Application A/B selection and boot status — phase 12](docs/en/application-selection.md)
- [Roadmap and evidence levels](docs/en/roadmap.md)
- [Evidence manifest](evidence/manifest.json)
- [Credits, provenance and publication scope](NOTICE.md)

The new static analysis traces application validation before the final branch to
the application's reset handler. It also distinguishes structural pre-validation
from the authentication-enabled calls around a bootloader update operation.
An arithmetic range-check observation is recorded with an offline witness;
reachability with useful impact and any authentication bypass remain unproven.

Phase 10 resolves the indirect callback to a power/input guard and traces the
fixed 4096-byte IVT transfer arguments and restoration path. Executing the
recorded range helper in isolated ARM emulation confirms the arithmetic witness
across eight cases; it does not establish a device-level exploit.


- **[Phase 12: IVT write-path audit](docs/en/write-path.md)**

**Phase 12** audits a selected call path to the physical flash writer with a
constructed IVT context. It verifies instruction anchors, virtual tables and
fixed 4096-byte arguments. **USB reachability**, out-of-bounds physical writes,
and custom-firmware execution are **not established**.

- **[Phase 13 — USB surface and dispatcher limits](docs/en/usb-surface.md)**

Phase 13 quantifies coverage of the published bootloader disassembly and adds a **read-only** static USB triage tool for a locally SHA-verified image. No exploitable USB dispatcher or custom-firmware execution has been demonstrated.

- **[Phase 14 — Bootloader vendor USB interface and callback](docs/en/usb-callbacks.md)**

A SHA-256-matched private bootloader image establishes **two USB interfaces** (vendor bulk + HID) and conditional vendor event dispatch to a RAM callback pointer. No externally reachable flash-write path or custom-firmware execution has been demonstrated.

- **[Phase 15 — Internal USB event dispatch and transfer guard](docs/en/usb-events.md)**

The SHA-matched bootloader contains an 11-case internal event table (not host USB commands) and a 512-byte upper-bound guard in one transfer helper. No external flash-write reachability or signature bypass is established.

- **[Phase 16 — CDC versus vendor callback provenance](docs/en/usb-reception.md)**

The 512-byte guarded helper belongs to a **CDC-labelled method table**, separate from the vendor event callback. Both initial callback states and selected internal call paths are verified. A bulk OUT `0x07` host-to-flash path and custom firmware execution are still **unproven**.

- **[Phase 17 — Vendor endpoint callback registration](docs/en/vendor-endpoints.md)**

On the SHA-verified bootloader A, two endpoint registrations reach `0x60806660`. Bulk OUT `0x07` and IN `0x87` map to distinct internal slots, but the specific OUT callback assignment and actual message parser are unproven. HAB CLOSED has not been bypassed.

- **[Phase 18 — RAM initialization resolves bulk OUT callback](docs/en/usb-ram-initialization.md)**

Normal startup copies compact endpoint records from flash into RAM, proving the initial **bulk OUT `0x07` callback is `0x6080A06A`** and bulk IN `0x87` is `0x60809E30`. The final dynamic handler, external flash-write reachability and HAB bypass remain unresolved.

- **[Phase 19 — Initially inert vendor USB completion handlers](docs/en/usb-completion-defaults.md)**

The initial vendor bulk IN `0x87` and OUT `0x07` completion callbacks both point to single-instruction `BX LR` stubs. Later registration and other USB update paths are **not excluded**; HAB CLOSED has not been bypassed.

- **[Phase 20 — Bounded USB callback-writer census](docs/en/callback-writer-census.md)**

The bounded Thumb-2 encoding search finds only constructor stores for the vendor IN/OUT callback fields within the selected range. **No later setter is proved or ruled out**, and there is no externally reachable flash-write or HAB-bypass demonstration.

- **[Phase 21 — Global RAM literal sources and constructor alias](docs/en/global-ram-aliases.md)**

The image has **21 aligned global-pointer literals** and **29 candidate PC-relative loads**. One direct alias chain reaches the known constructor initialization stores; this is **not** a later callback setter or proof of USB-to-flash reachability.

- **[Phase 22 — Bounded USB pointer dataflow](docs/en/usb-pointer-dataflow.md)**

Conservative tracking of 29 RAM-alias source candidates, with writes to state field `+0x6C4` distinguished from the IN/OUT completion callback fields. Call and branch boundaries remain unresolved.

- **[Phase 23 — Bounded interprocedural pointer handoffs](docs/en/interprocedural-aliases.md)**

Four verified Thumb direct calls pass the global RAM object to internal routines. One initializer derives four subobject pointers. No externally reachable callback setter, USB-to-flash write path, or HAB bypass is demonstrated.

- **[Phase 24 — Callee stores and pointer provenance](docs/en/callee-callback-store-audit.md)**

Four callees and their auxiliary-object initialization chain were reviewed. The bounded audit records 23 store observations across 19 unique instruction sites, with no overlap with the four known callback fields. Values loaded from `global+0x568/+0x570/+0x560` and passed to `0x60809048`, plus the pointer derived from `global+0x5A8` passed to `0x608109FE`, remain unresolved.

- **[Phase 25 — Dynamic pointer sinks](docs/en/dynamic-pointer-sinks.md)**

`0x60809048` processes an opaque incoming object and delegates calls; `0x608109FE` unlinks list nodes through dynamic RAM pointers. Neither a concrete write to known USB callback fields nor an externally reachable host-to-flash route has been demonstrated.

- **[Phase 26 — Initialized pointers and list sentinels](docs/en/initial-pointer-and-list-heads.md)**

Both `global+0x560` and `global+0x568` initially point at `global+0x134`; `global+0x570` is a **byte field**, not a demonstrated third pointer. Two self-referential list heads have also been reconstructed. Later runtime changes and USB-to-flash reachability remain unproven.

- **[Phase 27 — List insertion routines and pointer-field search](docs/en/list-insertions-and-aliases.md)**

Verified direct insertion `0x608109B8` and ordered insertion `0x608109D0` with 14 selected static call/branch edges. Two callers compute heads using `0x2000A7F8 + 20×index`. Later reassignments of `global+0x560/+0x568` and USB reachability are still unproven.

- **[Phase 28 — Indexed node and bucket-index provenance](docs/en/indexed-node-provenance.md)**

At `0x60811A32` and `0x60811E0C`, nodes are embedded at `object+4` while bucket indices come from `object+0x2C`. The observed comparisons occur after insertion; upstream validation, invalid indices and USB reachability remain unproven.

- **[Phase 29 — Bucket-index writer provenance and bounds](docs/en/bucket-index-writers.md)**

One constructor clamps `object+0x2C` to **0–15** and initializes `object+0x50`; four later paths may copy or update the index. This is not proof that the initial bound holds at runtime or that USB can control the index.

## Offline reproduction

Python 3.11 or newer:

```sh
python -m venv .venv
# Activate the environment using the command for your operating system.
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python tools/model_ranges.py
```

Optional instruction-level reproduction from the public evidence, without a
firmware binary or connected controller:

```sh
python -m pip install -r requirements-emulation.txt
python tools/emulate_range_check.py
```

With your own matching bootloader dump:

```sh
python tools/analyze_bootloader.py local/bootloader-a.bin
python tools/verify_hab.py local/bootloader-a.bin --base 0x60800000 --csf-offset 0x18000 --alias 0x60001000:0:0x1000
```

The alias explicitly represents the shared IVT block using the image's first
4096 bytes. CMS verification validates content digests and RSA signatures with
embedded certificates; it does **not** independently validate the fused SRK
trust anchor or establish a complete recovery image.

`tools/StadiaRead.cs` and `tools/Read-Stadia.ps1` provide a Windows version reader
using an already-installed WinUSB interface. The Python analysis tools above
perform no device I/O, downloads or firmware execution.

## Contributing

Include the image build/hash, exact addresses, reproduction steps and whether a
claim is measured, statically inferred or hypothetical. Keep device identifiers,
credentials, full device dumps and proprietary firmware binaries out of patches.
See the bilingual roadmap for bounded research tasks. This repository is a
research log, not an installable firmware release.
