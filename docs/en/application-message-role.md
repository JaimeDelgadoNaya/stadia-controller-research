# Bounded application message-role review

2026-10-25. The owner requests software changes on the original Stadia controller,
with no external adapter, including direct Switch 2 use. This reopens a bounded
offline review rather than assuming phase 31's technical barriers are solved.

The private signed Bruce update sample remains SHA-256
`466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`.
It is not a verified full dump of the installed application. Re-running the
existing final-authentication audit verified original signatures and rejected
one-byte mutations in temporary copies. Nothing was sent to the controller.

## Correction to the earlier candidate

The earlier surface audit started its selected window at `0x60058B68`. The
function starts at `0x60058B64`: it subtracts one from the incoming length and
checks the remaining range before dispatching the tag byte. On tag 5, the
callee at `0x60058AA8` checks for at least four payload bytes, decodes two
little-endian 16-bit values into RAM `0x2001A430` and `+2`, and posts event 6.
The nearby component literal is `hid_input_target.cc`. The initializer also
references `HidRumbleTimer` and registers the two-value consumer. The entry
accepts total lengths 1..255; tag 5 requires at least five total bytes.

This supports a bounded two-channel HID-control interpretation, possibly
rumble. It does not establish a firmware-update receiver, arbitrary RAM writes,
custom execution or a secure-boot bypass. A callback reference is registration
evidence, not by itself proof of externally controllable USB delivery. Exact
checks, scope and unresolved edges are recorded by the offline auditor:

```sh
python tools/audit_app_message_role.py local/bruce_pvt_a_prod_signed.bin
python -m unittest discover -s tests -v
```

See [sanitized evidence](../../evidence/application-message-role.json) and the
[direct Switch 2 target](direct-switch2.md). No vendor output transfers, fuzzing,
mode transitions, flash writes, resets or driver changes are needed for this review.

## Independent lead review

[Gary's stadiatool](https://github.com/GaryOderNichts/StadiaController/blob/main/stadiatool/README.md)
documents flashing signed firmware. The reviewed public forks did not provide a
reproducible unsigned-code route. The [bitnullbyte WIP report](https://www.reddit.com/r/Stadia/comments/1vm7mp6/wip_we_have_honestly_never_been_closer_to_a/)
describes stock Wi-Fi restoration and provisioning; modified URLs are future
work in that report. No reproducible custom image/execution procedure was found
there. These are search results, not proof that no undisclosed route exists.

The next useful execution lead must identify a controllable input, its receiver
and actual executable effect on the original hardware. Recovery remains a
separate unresolved requirement. A protocol implementation or a renamed USB
descriptor cannot supply the missing execution path.
