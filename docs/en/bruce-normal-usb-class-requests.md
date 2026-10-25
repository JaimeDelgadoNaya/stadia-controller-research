# Bruce normal-mode USB class requests: bounded original-image receiver audit

**25 October 2026 · PR #32 · strictly offline.** Archived OEM host JS
uses USB class/interface control requests in normal Stadia mode
`18D1:9400`: IN `bRequest 0x81` for version, OUT `0x83` to
initiate battery sampling, and IN `0x84` for battery data. The update
itself is programmed in the signed ROM SDP/flashloader path.

The audit uses exact original Bruce update image SHA-256
`466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`,
1,050,984 bytes. It **does not** prove the update image matches all
installed flash bytes.

## Firmware findings

Both known literal references to the `usb_device_vendor.cc` source
label (at `0x60061504`, `0x600615B4`) occur in log or message
formatting paths. They do **not** identify the actual receiver for
EP0 class SETUP requests.

An offline *linear* Thumb CMP-immediate census produces:

| Compared immediate | Raw candidate occurrences | Verified host USB handler? |
|---|---:|---|
| `0x81` | 2 | No |
| `0x83` | 1 | No |
| `0x84` | 5 | No |

These values are not evidence that the code is USB SETUP command
dispatch: decoding arbitrary bytes can turn literal tables into false
instructions, and dispatch may use indirect tables rather than direct
CMP immediates. Copied-ITCM bytes are displayed at source, not runtime
PCs.

At `0x60070C4C`, code loads `[R1]` and
`0x60070C54` compares that **input buffer first byte** against
`0x81` (another branch checks `0x30`). Branches then examine
bytes +1, +3 and +5 and extract state bits. There is no verified
dataflow from a USB `setup.bRequest` to this buffer.

At `0x600F4B44`, code compares a field read from an object's
offset `+0x32` with `0x84` (or `2` on the alternative branch).
This is a structure-field check, not proven to be the OEM host's
`bRequest 0x84`. Other direct occurrences are also unproven.

## Conclusion

The official host's three normal-mode requests are well documented,
but **no original Bruce EP0 class SETUP receiver address has been
linked to them**, and there is **no demonstrated external-to-own-code
execution path, HAB CLOSED bypass, recoverable custom firmware, or
native Xbox/Switch 2 support**.

Further work should establish an actual
**USB SETUP packet → interface registered handler → branch → effects**
chain using independent device/USB controller evidence. Byte-value
similarity alone is not enough, and unknown or write-capable commands
should not be issued to the only physical controller.

```sh
python -m unittest tests.test_bruce_class_requests -v
python -m tools.audit_bruce_class_requests local/bruce_pvt_a_prod_signed.bin --preview
```

The temporary CI image is hash-verified and deleted; no firmware
or private binary is committed or sent to a device.

[PR and CI reference](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/32).
