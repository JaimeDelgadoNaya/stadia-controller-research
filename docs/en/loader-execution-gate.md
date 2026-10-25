# Original signed RAM loader: Execute and Call dispatch gate

The original 100,672-byte `restricted_ivt_flashloader.bin`, SHA-256
`c39ea8962cc3094a9167ba80634f1ea0652b747b4572d1de2802d9f2f4e144c5`,
contains Execute and Call implementations, but **normal command dispatch disables
both before invoking their handlers**. This is an offline receiver finding,
not an attempted device command or proof that all possible execution routes fail.

## Concrete receiver path

The startup copy at `0x2000247E..0x20002490` copies `0x830` bytes from
`0x200164D8` to `0x20208000`. Its initialized global at `0x202081F4`
has command-interface pointer `+0x10 = 0x202081E4`; that interface's `+8`
points to the table initialized from the signed image at `0x20015978`.

The packet dispatcher `0x20002EB4` reads the incoming command tag at
`0x20002EF4`. It bounds the tag to 1..21 and computes a 12-byte table entry.
At `0x20002F0A`, it reads entry byte `+8`; zero replaces the entry pointer
with NULL. The NULL entry branches to `0x20002F2C`, which sends a generic
response with status `0x2710` (10000) and the original command tag. Only an
enabled, non-NULL handler can reach `BLX R3` at `0x20002F1A`.

| Command | Tag | Entry address | Thumb handler | Enabled byte |
|---|---|---|---|---|
| Execute | `0x09` | `0x200159D8` | `0x200033A1` | 0 |
| Call | `0x0A` | `0x200159E4` | `0x2000340D` | 0 |
| ReadMemory | `0x03` | `0x20015990` | `0x200035A5` | 1 |
| WriteMemory | `0x04` | `0x2001599C` | `0x200030D9` | 1 |

Execute/Call rejection at this gate does not depend on the proposed destination
address or on GetProperty `0x11`. That property takes the separate case at
`0x20009AF0`, calls `0x2000A87C`, and reports bit 1 of OCOTP_CFG5
(`0x401F4460`), normalized to 0/1. A status report is not an unlock switch.

## Can WriteMemory enable the disabled RAM entries?

The table resides in RAM; its signed provenance does not make it physically
immutable. However, the ordinary WriteMemory data path calls the memory backend
through `0x20003250`. Global memory-vtable slot `+8` resolves to `0x20003B7C`,
which invokes `0x200039A8` with operation 2 at `0x20003B8E..0x20003B90`.
That policy selects four inclusive ranges from initialized RAM `0x2020826C`
(image offset `0x16744`): `0x2000..0x21FF`, `0x60000000..0x60000FFF`,
`0x60001000..0x60001FFF`, `0x60004000..0x60FFFFFF`.

An ordinary positive nonwrapping patch of either enabled byte (`0x200159E0`
or `0x200159EC`) therefore fails with `0x27D8` before generic RAM dispatch.
The generic memory map containing RAM is insufficient to bypass this preceding
policy.

The policy calculates the last address with 32-bit arithmetic. Crucially, the
WriteMemory backend receives a **fragment size**, not the full declared command
length: `0x200031EC..0x200031FE` takes the minimum of remaining bytes and received
fragment length; `0x20003244..0x20003250` invokes the backend with that length.
The USB packet-reader table `0x20015F38`, referenced by the transport record at
`0x20016124`, has its read method at `0x20004EF5` (Thumb). Its
`0x20004F5E..0x20004F78` assembles the length from **two header bytes**, verifies
it fits the received transfer minus its four-byte header, and returns it.
Consequently backend size is at most 65535 bytes on this intact USB path,
regardless of a huge total command length. This conservative upper bound does
not assert such a large USB report is accepted. Neither table byte address can
wrap with that bound, so the specific huge-total-to-table-patch hypothesis fails.

Other mutation paths, malformed/corrupted transport state, other transports and
general integer-wrap effects remain outside scope. The range model deliberately
rejects wrapping inputs. ReadMemory was not exhaustively traced in this package.

No payload, packet,
RAM write or flash operation was sent. This finding does not rule out a separate
vulnerability, state corruption, another signed loader or another execution path.
It supplies no new custom-code execution, recovery or direct-console evidence.

## Reproduce offline

```sh
python tools/audit_loader_execution_gate.py local/restricted_ivt_flashloader.bin
python -m unittest discover -s tests -p test_loader_execution_gate.py -v
```

The auditor checks whole-file size/hash, selected original instruction bytes,
startup pointers and command entries. Tests use synthetic byte arrays only.
[Sanitized evidence](../../evidence/loader-execution-gate.json) contains decoded
addresses and conclusions, not a proprietary firmware image. These checks verify
the recorded interpretation against the exact image; they do not emulate the
full receiver or prove reachability from arbitrary malformed packets.

## Scope boundary for other commands

The table also enables FillMemory. The WriteMemory fragment bound must not be
applied to FillMemory or other commands without tracing their own receivers and
backends. Their presence is not a custom-execution result, and this audit does
not provide an exploit or validate a bypass through them.

**Independent FillMemory follow-up:** [offline review](fillmemory-path-review.md). Command `0x05` is enabled, but the original handler has not yet been proven to share WriteMemory's policy or use another backend. Keep data-phase fragment bounds separate.
