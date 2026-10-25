# Measurements and extraction

[Español](../es/mediciones.md)

## Sample and evidence

One controller was examined on 2026-10-25. The application version query returned
`78 27 05 00 D5 95 02 00`: two little-endian integers, 337784 and 169429. The first
is the application build; the second matches the build metadata of the extracted
bootloader. Its exact USB-handler semantics have not yet been traced.

USB enumeration confirmed the sequence `18D1:9400` (normal), `18D1:946B`
(bootloader), `1FC9:0135` (ROM SDP), and `15A2:0073` (signed RAM flashloader).
Physical button presses were performed by the owner.

The ROM `ERROR_STATUS` command (`0x0505`) returned report 3 containing
`0x12343412`, the documented HAB CLOSED value, followed by report 4 containing
`0xF0F0F0F0` (HAB Success). Success is not an Open security configuration.

The preserved, original signed loader was cross-checked between two archives:
SHA-256 `c39ea8962cc3094a9167ba80634f1ea0652b747b4572d1de2802d9f2f4e144c5`.
Its signatures and content digests were also checked offline. The ROM accepted
the loader in RAM at `0x20000000`, using IVT address `0x20000400`.

`GetProperty 0x11` returned command status 0 and value 1. In this exact loader,
the jump table at `0x20009A90` selects `0x20009AF0`, which calls `0x2000A87C`.
That function reads `0x401F4460` and extracts bit 1. This links the property's
meaning to HAB for this binary, rather than assuming a generic property name.
Direct four-byte `ReadMemory` of the register was rejected with status 10200.

## Flash extraction

The MCU identification register returned `0x006C0000` (upstream label 106XA0).
The flash identification command returned `0x17C8` (upstream Giga-16m mapping).

Following the published FlexSPI approach, a temporary FCB was uploaded to SRAM
at `0x2000`. Device/configuration-mode command enables were zero. The LUT used
for content extraction contained only single-pad `READ 0x03` and `RDSR 0x05`;
program, erase and write-enable sequences were removed. ID command `0x90` was
used separately before content extraction. Registers were accessed through the
signed loader's permitted interface.

Each 128 KiB bootloader region was read in four-byte words. An optimized sequence
was checked against the original register sequence at six addresses first.
Twelve separated words were re-read after extraction and matched the saved data.
The A image's CSF and image signatures verified. Region B is entirely `0xFF`.

| Region | Address | Bytes | SHA-256 |
|---|---|---:|---|
| Bootloader A | `0x60800000` | 131072 | `59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0` |
| Bootloader B slot | `0x60820000` | 131072 | `b5a41c3758763bbec72769fab4a2533bf2db0b6312d93d25a695f9e4b9e02260` |

There were RAM/SRAM and peripheral-register writes, but no firmware programming,
flash erase or fuse programming commands. Calling the entire procedure
"write-free" would be inaccurate. The documented loader RESET command returned
success; normal USB mode and the original eight-byte version response were
confirmed afterward.

## Limits

This is not a complete 16 MB device backup. An empty B slot provides no installed
bootloader redundancy. CMS validation checks the declared signed blocks, not
every byte of every region, and does not independently read the fused SRK hash.
The full installed application and ROM were not extracted. No unsigned image,
modified image, persistent update or invalid-signature boot was attempted.
