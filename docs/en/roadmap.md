# Roadmap and evidence levels

[Español](../es/hoja-de-ruta.md)

**Measured:** device responses, region contents, final normal-mode version.
**Offline verified:** signed-block hashes and CMS signatures using embedded keys.
**Static inference:** selected control flow and RVT mapping for the recorded hash.
**Emulated:** the isolated range helper agrees with its arithmetic model in eight cases.
**Open question:** arithmetic reachability, update callbacks and alternative code execution.

Next bounded tasks:

1. Resolve storage virtual methods and the concrete mapping of descriptor `0x12`.
   Phase 10 resolved the separate power/input callback and traced fixed IVT
   transfer arguments and restoration logic; backend restrictions remain open.
2. Trace boot-data sizes into the range helper and the subsequent HAB checks.
   Determine whether any malformed range can matter after cryptographic validation.
3. Reconstruct application A/B selection, boot-attempt metadata and fallback
   behavior. An empty bootloader B slot does not imply that application B is empty.
4. Map normal/bootloader USB request dispatch and determine which diagnostic
   interfaces are available on production hardware.
5. Identify a concrete, recoverable execution path before implementing a new
   USB/Bluetooth controller protocol. Xbox-console compatibility is a separate
   problem and has not been implemented.

No complete ROM audit, complete device backup, exploit or custom firmware exists
in this repository. Initial analysis tools deliberately operate on local files.
