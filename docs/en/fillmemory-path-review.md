# PR #24 follow-up — Is FillMemory a custom-execution path?

**25 October 2026: hypothesis unproven.** This is a read-only comparison of
the independently evidenced FillMemory command against WriteMemory, not a
hardware test or an exploit.

The original signed `restricted_ivt_flashloader.bin` (100672 bytes,
SHA-256 `c39ea8962cc3094a9167ba80634f1ea0652b747b4572d1de2802d9f2f4e144c5`)
has **enabled** FillMemory command tag `0x05` and Thumb handler
`0x20003381`. Execute tag `0x09` and Call `0x0A` have non-null
handlers but their dispatch entries are **disabled**.

The prior PR traced **WriteMemory's data phase** through an explicit
range check; its HID receive-fragment length is bounded by a uint16
value. This proof does **not** automatically apply to FillMemory.

[GaryOderNichts' flashloader client](https://github.com/GaryOderNichts/StadiaController/blob/main/stadiatool/flashloader.py)
uses three command parameters (destination, count, word pattern);
its `set32` method illustrates a 4-byte fill without a separate
data-transfer stage. [NXP's official bootloader reference](https://mcuxpresso.nxp.com/mcuxsdk/25.09.00/html/middleware/mcu_bootloader/docs/MCU_Bootloader_Reference_Manual/topics/mcu_bootloader_command_api.html)
states that **generic FillMemory follows WriteMemory's memory access
rules**, aside from carrying the pattern inside the command. **Google's
restricted binary may differ**, so the exact handler must be traced.

The four remaining gates are parameter parsing/alignment/overflow,
policy/back-end call convergence, actual permission to modify a
target RAM region, and demonstrable custom execution with recovery.
Neither FillMemory's availability nor a successful command response
would establish an unsigned custom boot on a HAB CLOSED device.

### Read-only reproducer

```sh
python tools/audit_fillmemory_route.py local/restricted_ivt_flashloader.bin --out local/fillmemory-review.json
python -m unittest tests.test_fillmemory_route -v
```

The new tool checks the **exact original loader SHA-256**, compares
command-table enabled states, decodes the bounded FillMemory
entry region using Capstone and previews immediate callees. An observed
call to the prior WriteMemory range-policy routine does not prove
its execution on all branches; **no observed call within these
bounded previews does not prove its absence**. This is intentionally
not a full control-flow or memory-safety proof.

The original loader binary is not available as a mounted file in the
current working container, so this new analysis **has not yet been
run against that original sample here**. CI uses **synthetic fixtures**
only. No controller commands, persistent memory changes, or
recovery risks were undertaken.

**Conclusion:** FillMemory is worth inspecting, but a control-memory
write, enabled Execute/Call, HAB bypass, custom code execution and
reliable rollback are **not demonstrated**.
