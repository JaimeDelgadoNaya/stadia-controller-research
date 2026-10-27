# Phase 82 — Offline HAB CSF UNLOCK command decoder

**27 October 2026.** Follows [phase 81](nxp-rom-csf-phase81.md). The original signed RAM loader's CSF contains one `UNLOCK` command whereas the signed Bruce application does not. This is **not** a USB command or disabling HAB CLOSED.

The [NXP CST User Guide](https://community.nxp.com/pwmxy87654/attachments/pwmxy87654/imx-processors/202591/1/CST_UG.pdf) defines `[Unlock]` as selecting peripheral engine features to leave accessible after BootROM exit. Supported engines are SRTC, CAAM, SNVS, OCOTP; certain OCOTP features require an eight-byte device UID. **This does not disable signature authentication**.

[NXP's SPSDK HAB implementation](https://github.com/nxp-mcuxpresso/spsdk/blob/main/spsdk/image/hab/commands/cmd_unlock.py) uses a `0xB2` header, two-byte big-endian command length, engine selector as the fourth header byte, and a four-byte big-endian feature mask. Any optional UID bytes remain **redacted**, never emitted by the tool. Unknown flags remain unknown, not inferred.

The [SHA-pinned original-file decoder](../../tools/audit_hab_unlock_phase82.py) extends the phase81 checks for verified signed Bruce, signed RAM loader, and owner-held private bootloader A. It publishes CSF-relative offset, engine and feature mask only. [Synthetic tests](../../tests/test_hab_unlock_phase82.py) cover masks, unmapped features, redaction and malformed data. The [offline CI](../../.github/workflows/nxp-rom-advisories-phase81.yml) temporarily downloads the two publicly archived images, checks SHA-256 and deletes them.

```sh
python -m unittest tests/test_hab_unlock_phase82.py -v
python -m tools.audit_hab_unlock_phase82 local/restricted_ivt_flashloader.bin --sample restricted_ram_loader
python -m tools.audit_hab_unlock_phase82 local/bruce_pvt_a_prod_signed.bin --sample bruce_prod
```

## Exact signed OEM result

[Sanitized immutable evidence](../../evidence/nxp-hab-unlock-phase82.json) · [GitHub Actions verified original](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40556380124)

| CSF field | Original signed RAM loader | Signed Bruce |
|---|---|---|
| UNLOCK count | **1** | **0** |
| Relative CSF offset | **0x48** | — |
| Engine | **0x21 / OCOTP** | — |
| Feature mask | **0x00000002** | — |
| NXP feature | **SRK_REVOKE** | — |
| UID field | **Absent** | — |

The Google-authored CSF requests that ROM leave **OCOTP SRK revocation capability** unlocked after its exit. This is not an SRK revocation event, not evidence of free access to OTP fuses, and **does not disable HAB authentication**. Revoking SRKs would irreversibly alter trust configuration; no such operation is attempted.

The dedicated CI asserts those actual pinned values so future changes cannot silently reinterpret the original. Sixteen phase81/82 synthetic tests passed; live OCOTP register/fuse state remains unmeasured.

**Evidence boundary:** a signed CSF expresses vendor-intended post-ROM peripheral policy. This is not physical runtime register measurement, proof of the BootROM HAB version, control of ROM parsing, signature bypass or arbitrary code execution. CVE-2022-45163 concerns a separate ROM SDP memory disclosure question. No connected controller, USB requests, flash writes or eFuse access.
