# Bruce signed variants and archived updater: alternative execution boundaries

**25 October 2026 · PR #31; offline only.** Original signed Bruce update
files were compared to the archived OEM updater JavaScript. No physical
controller connection, USB packets, firmware writes or HAB modification.

## Verified sources and signature scope

The public
[StadiaMemories production Bruce image](https://github.com/StadiaMemories/firmware/blob/main/bruce_pvt_a_prod_signed.bin)
is **bit-identical by SHA-256** to the previously owner-provided signed
sample: 1,050,984 bytes; SHA-256
`466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`.

Its two embedded-cert CMS/RSA signatures verify mathematically. The
authenticated application block is `[0x0,0xFF030)`, 1,044,528 bytes.
The final 6,456 bytes include the CSF commands (72 bytes) and the
remaining signature/certificate material (6,384 bytes). **Do not treat
these as general-purpose unsigned executable space.** The device fuse
SRK trust has not been checked here, and the publicly archived update
image has not been compared byte-for-byte with installed flash.

A scan for **aligned literal 32-bit pointers** from authenticated image
bytes into the CSF/post-CSF region found exactly one:
`0xFF018 → 0x6013F030`. This is the IVT's **CSF metadata pointer**,
not a Thumb executable function reference. This bounded scan does
not rule out computed/unaligned/dynamic references.

## Original OEM prod, stage and dev variants

All three archives matched their pinned Git blob SHA-1 and passed
two CMS/RSA checks apiece. Comparing each to `prod`:

| Result | Stage | Dev |
|---|---:|---:|
| Differing application code bytes `[0,0xFF000)` | **0** | **0** |
| Differing signed-block bytes `[0,0xFF030)` | **0** | **0** |
| Differing bytes after `0xFF030` | 3,182 | 3,192 |
| First difference | `0xFF03A` | `0xFF03A` |
| Shared embedded signer public key with prod | No | No |
| Boot on actual HAB CLOSED production board | **Not tested** | **Not tested** |

**Result:** `stage` and `dev` are not different executable Bruce
application builds in this archived family. They contain the **same
authenticated application and IVT** as `prod`; differences lie in
authentication material. They cannot by themselves provide different
debugging logic or arbitrary user-supplied code.

Valid CMS signatures with embedded certificates **do not establish
which certificates the production board's fused SRK trusts**. This
project has not installed these alternative OEM images on a device.

## Host/app boundaries

The archived updater JS is verified as the exact original blob:
normal USB `18D1:9400` makes version/battery queries; official
updates traverse ROM SDP `1FC9:0135` and the Google-signed RAM
loader `15A2:0073`, rather than the application's rumble/tag-5
callback or bootloader-A vendor bulk endpoint. Host header checks are
not signature authentication.

The original image's signed application provides no demonstrated
USB-to-custom-code path, arbitrary unsigned firmware acceptance,
recovery guarantee or direct console compatibility.

## Reproduce without hardware

```sh
python -m unittest tests.test_signed_app_host_boundary tests.test_signed_bruce_variants -v
python -m tools.audit_signed_app_host_boundary local/bruce_pvt_a_prod_signed.bin local/app_combined.js
python -m tools.audit_signed_bruce_variants local/bruce_pvt_a_prod_signed.bin local/bruce_dvt_a_stage_signed.bin local/bruce_dvt_a_dev_signed.bin
```

[Pinned original-image and JS CI run](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40239207683).
No images or signer certificates are published as CI artifacts.
