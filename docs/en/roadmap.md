# Roadmap and evidence levels

[Español](../es/hoja-de-ruta.md)

**Measured:** device responses, region contents, final normal-mode version.
**Offline verified:** signed-block hashes and CMS signatures using embedded keys.
**Static inference:** selected control flow and RVT mapping for the recorded hash.
**Emulated:** the isolated range helper agrees with its arithmetic model in eight cases.
**Open question:** arithmetic reachability, update callbacks and alternative code execution.

Next bounded tasks:

1. Trace externally controllable arguments into the resolved storage methods.
   Phase 11 maps descriptor `0x12` to the 4096-byte shared IVT and emulates the
   plain write wrapper with a mocked physical backend. Input reachability and
   real-device acceptance of malformed arguments remain unproven.
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

## Priority change after phase 29 (finite stop/go gate)

The earlier task list remains a set of hypotheses, but current execution priority is the **[bounded real-updater decision gate](update-execution-decision-gate.md)**: at most two offline work packages (archived host WebUSB protocol to actual receiver, then signed Bruce application/recoverable execution only if warranted), followed by an explicit **continue/stop** decision. Do not open another unlimited sequence of generic pointer scans. If an externally controllable and recoverable custom-execution path is not shown, shift to an external Xbox bridge while distinguishing PC XInput from console authentication.

## Current priority: internal software and direct Switch 2

The owner's later instruction excludes external devices and supersedes the
external-bridge priority above. See [the direct target](direct-switch2.md) and
[application receiver correction](application-message-role.md). Bounded offline
investigation is resumed; signatures, custom execution and recovery remain
technical barriers. No controller firmware was modified in this review.
