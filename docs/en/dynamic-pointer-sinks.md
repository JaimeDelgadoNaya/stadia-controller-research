# Phase 25 — Two unresolved dynamic pointer sinks

**Sample:** privately extracted Stadia bootloader A build 169429, 131072 bytes,
SHA-256 `59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.
The analysis is **offline**; no device access or firmware publication.

## `0x60809048`: operations on an opaque incoming object

Its R0 argument comes from RAM fields `global+0x560/+0x568/+0x570`
(`global=0x20008B78`), depending on the caller. These are **loaded values**,
not statically known object addresses.

At `0x6080904C` the function derives `R5=R0+0xA4` and at
`0x60809052` preserves input R0 in R4. It reads
`[R4+0x158]`, `[R4+0x15C]` and `[R4+0x154]`,
and constructs `R4+0x6C` and `R4+0xF8` for other calls.
Its direct callees include `0x608101AA`, `0x608101BC`,
`0x608041F0`, `0x60808E7C` and `0x6081022C`.

No store through the tracked incoming object is observed **within the
attested `0x60809048..0x60809174` region**; explicit stores there
prepare stack arguments. This does **not** exclude side effects in
called functions or prove an externally reachable USB packet parser.

## `0x608109FE`: doubly linked node detach

A bounded disassembly establishes the following memory operations:

| Address | Observed operation |
|---|---|
| `0x608109FE` | Load previous/next from node offsets +4/+8 |
| `0x60810A02` | Load owner from node offset +0x10 |
| `0x60810A04` | Store next at previous+8 |
| `0x60810A08` | Store previous at next+4 |
| `0x60810A10` | Conditionally update owner+4 |
| `0x60810A14` | Clear node+0x10 |
| `0x60810A1A` | Write decremented counter to owner+0 |

Those stores target memory **through opaque pointers**, not independently
verified absolute RAM addresses.

The caller `0x60811DC8` loads a parent pointer from
`[context+0xC]`, then a link from `[parent+0xC]`,
and calls the unlink function with `link+0x18` (at
`0x60811DE2`) and, on another path, `link+4` (at
`0x60811DF0`). Earlier research associates the outer context with
a subobject derived from `global+0x59C`, but the loaded pointer
chain cannot be resolved to absolute RAM from these instructions alone.

## Conclusion and limitations

No write to known USB callback fields `0x20009170/74/78/7C`
is demonstrated by these unknown pointer values. An alias is
**neither proved nor excluded**. There remains no demonstrated
host→USB-parser→flash path, HAB CLOSED bypass or custom execution.

`tools/audit_dynamic_pointer_sinks.py` verifies the whole-image SHA-256,
three code region digests, exact instruction anchors and direct Thumb BL
edges. CI runs synthetic tests only.

```sh
python tools/audit_dynamic_pointer_sinks.py local/bootloader-a.bin --out local/phase25.json
python -m unittest discover -s tests -v
```

**Phase 26:** prioritize where the values in
`global+0x560/+0x568/+0x570` are assigned and how linked
nodes are allocated/registered, rather than attributing callback
stores to unidentified pointers.
