# Phase 13 — Bounded USB dispatcher research

Goal: establish what is and is not known about the USB input surface of the
**169429** Stadia bootloader without accessing the controller or publishing
copyrighted images.

The recorded corpus in `evidence/bootloader-analysis.json` covers **28
selected regions / 2,340 instruction bytes** of a **131,072-byte image**
(**1.785%**). It contains **67** direct calls, of which **41** target
addresses outside the selected ranges, and **16** indirect transfer sites.
These figures show evidence coverage, **not** the number of missing functions
or real USB endpoints.

**No USB-to-flash-writer reachable path has been demonstrated.** Phase 12's
IVT update path uses a constructed storage object with **fixed zero offset
and 4,096-byte length**, rather than a demonstrated external USB argument.

## SHA-locked local-only analysis

`tools/audit_usb_surface.py` can accept the owner's matching 128 KiB
`bootloader-a.bin`. It first verifies SHA-256
`59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.
It then searches for plausible 18-byte USB device descriptors, aligned pointers
to them, vector-table entry candidates, and a bounded heuristic Thumb control
flow from those vectors. It reports potential PC-relative references and
unresolved indirect transfers.

These are **candidates**, not proven active USB commands. The walker cannot
completely follow dynamic control flow, function pointers or jump tables and
may produce false positives. It does not prove external reachability, flash
writes, HAB bypass or custom-firmware execution. It never accesses hardware.

```sh
python -m pip install -r requirements.txt
python tools/audit_usb_surface.py > phase13-public.json
python tools/audit_usb_surface.py --bootloader local/bootloader-a.bin > phase13-local.json
python -m unittest discover -s tests -v
```

Do not commit bootloader binaries or device identifiers. Next step: manually
review possible request dispatchers in the independently SHA-verified binary
and follow user-controlled argument provenance through signature checks.
