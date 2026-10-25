# Offline Stadia input decoding

[Español](../es/decodificacion-entrada.md)

`tools/decode_stadia_input.py` decodes the measured 11-byte USB report ID 3
without accessing hardware. Byte 1 contains the hat; bytes 2–3 contain fifteen
button bits; bytes 4–7 contain X/Y/Z/Rz; bytes 8–9 contain Simulation usages
C5/C4; byte 10 contains Consumer E9/EA/CD bits.

Padding is ignored, out-of-range hats become null, and zero axes are preserved
and flagged outside the declared 1–255 range. Physical button labels, trigger
sides, axis inversion, actual centers and dead zones are not inferred.
Example center 128 is synthetic.

```sh
python tools/decode_stadia_input.py "03 08 00 00 80 80 80 80 00 00 00"
python -m unittest discover -s tests -q
```

Six new tests cross-check the descriptor layout, activate each button separately,
cover null hats/padding, distinguish controls and reject incorrect framing.
All 354 tests pass. No physical input samples were collected in this continuation.

The original Pro uses reports 21/30, packed 12-bit stick axes and digital ZL/ZR;
translation and protocol state are required.
[Pinned primary notes](https://github.com/dekuNukem/Nintendo_Switch_Reverse_Engineering/blob/b354f21ae81f7b0d1d060b2b61e66ad0d9bc1756/bluetooth_hid_notes.md).
Linux initializes with 80/02, 80/03, 80/02, 80/04. The final command has no reply;
the driver ignores its timeout. This is Linux host evidence, not a Switch 2
capture or acceptance test.
[Pinned driver](https://github.com/torvalds/linux/blob/21a7f44fd0765fcc5194130b28767786eba1d1e7/drivers/hid/hid-nintendo.c).

Next: labeled rest, individual buttons, stick extremes and individual triggers
before defining physical mapping and ZL/ZR thresholds. Custom execution and
recovery remain unresolved; this decoder is not installable firmware.
