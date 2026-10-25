# Direct Stadia software target: Switch 2 over USB

[Español](../es/switch2-directa.md)

Reviewed **2026-10-25**. The owner explicitly requires software on the Stadia
controller itself and no external adapter, superseding phase 31's external
priority. Bounded offline application-receiver analysis resumes. Custom execution,
an installable image and direct console compatibility remain unproved.

The proposed minimum target is the **original Switch Pro Controller USB profile**.
Nintendo explicitly documents using that controller wired on Switch 2 after
enabling Pro Controller wired communication under Controllers and Accessories.
Acceptance of the original does not establish acceptance of an emulator.
[Nintendo instructions](https://en-americas-support.nintendo.com/app/answers/detail/a_id/49387/p/989/c/947).

VID/PID changes alone are insufficient. Original-protocol research describes
USB `0x80/0x81` status, handshake and USB-persistence exchanges, plus subcommand
responses and periodic input reports. Reproduce host-visible behavior, not the
original controller's internal UART architecture.
[USB notes](https://github.com/dekuNukem/Nintendo_Switch_Reverse_Engineering/blob/b354f21ae81f7b0d1d060b2b61e66ad0d9bc1756/USB-HID-Notes.md),
[report formats](https://github.com/dekuNukem/Nintendo_Switch_Reverse_Engineering/blob/b354f21ae81f7b0d1d060b2b61e66ad0d9bc1756/bluetooth_hid_notes.md),
[subcommands](https://github.com/dekuNukem/Nintendo_Switch_Reverse_Engineering/blob/b354f21ae81f7b0d1d060b2b61e66ad0d9bc1756/bluetooth_hid_subcommands_notes.md).

Switch 2 BLE is a separate, larger target. ndeadly documents proprietary
advertisements, pairing and GATT rather than standard HID-over-GATT, with special
connection parameters. Existing Stadia BLE support is not proof its stack can
emulate this transport. The original Switch controller instead uses BR/EDR.
[BLE research at a3306b473acff0d6844fb1e288883a3940df0baf](https://github.com/ndeadly/switch2_controller_research/blob/a3306b473acff0d6844fb1e288883a3940df0baf/bluetooth_interface.md).

Proceed with offline receiver/control-flow work and a hardware-independent USB
protocol core using synthetic transcripts. Only connect that core to Stadia USB
after establishing custom-code execution and recovery. Initial console acceptance
would cover menus, buttons, sticks, neutral state and reconnect. Trigger-to-digital
ZL/ZR thresholds must be explicit; IMU, NFC, audio, wake and rumble are later goals.
Offline protocol tests cannot establish code execution or physical compatibility.

Source pins: dekuNukem `b354f21ae81f7b0d1d060b2b61e66ad0d9bc1756` and ndeadly
`a3306b473acff0d6844fb1e288883a3940df0baf`. Neither inspected root tree contains
a general license file. This is attributed protocol analysis, not incorporated
upstream code; inspect file-specific permissions before reusing any source,
documentation or capture in the MIT project.
