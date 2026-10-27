# Phase 81 — NXP HAB ROM / CSF / SDP advisories (offline only)

**27 October 2026.** Two separate vendor advisories are assessed with original hash-pinned firmware and recorded measurements. No USB/SDP operation, firmware flash write, recovery attempt or OTP-fuse programming occurred.

**HAB additional-image authentication:** [NXP's official advisory](https://community.nxp.com/t5/i-MX-Security/Authentication-Vulnerability-when-extending-the-Root-of-Trust/ta-p/1511348) covers versions up to **HAB 4.3.6** when software extends the root of trust using the ROM authentication API. This is **not** a universal claim about primary boot. [AN12263](https://community.nxp.com/pwmxy87654/attachments/pwmxy87654/imx-processors/160465/2/AN12263.pdf) recommends screening the DCD pointer and deprecated CSF commands before additional-image authentication.

**CVE-2022-45163:** [NXP's SDP disclosure advisory](https://community.nxp.com/t5/i-MX-Security/SDP-Read-Bypass-CVE-2022-45163/ta-p/1553565) explicitly lists all RT105x/106x revisions, but describes **potential information disclosure**, not arbitrary execution or HAB signature bypass. NXP suggests a permanent SDP-disable OTP mitigation; no fuse changes are proposed.

On the tested Stadia controller, archived evidence records **HAB CLOSED** (`0x12343412`), physical ROM SDP `1fc9:0135` and MCU ID `0x006c0000` labelled 106XA0. The extracted original bootloader A calls `authenticate_image_no_dcd` via ROM RVT `0x0020032c`. That avoids the DCD route **for that call**, but is not proof that the BootROM CSF parser has been updated. **The precise on-chip HAB version remains unknown.** See [measurements](../es/mediciones.md) and [boot chain](../es/arranque.md).

The [phase81 read-only auditor](../../tools/audit_nxp_rom_advisories_phase81.py) checks exact size and SHA-256 of three pinned original samples (private bootloader A, archived Bruce signed application, archived signed RAM loader), validates IVT header/pointers and iterates length-bounded CSF commands. It identifies deprecated `WRITE_DATA` (`0xcc`), `CHECK_DATA` (`0xcf`) and `SET MID` (`0xb1` / `0x01`), alongside unknown commands and malformed structure. The classifications follow [U-Boot's hardened CSF checks](https://qemu.googlesource.com/u-boot/+/bef9fdbed2e525ce9264d2fbcb37db7472052/arch/arm/mach-imx/hab.c).

The [synthetic tests](../../tests/test_nxp_rom_advisories_phase81.py) cover fail-closed behavior. [Dedicated GitHub Actions](../../.github/workflows/nxp-rom-advisories-phase81.yml) downloads **only the two public archived samples**, verifies their SHA-256 hashes and deletes temporary files; the private bootloader is never uploaded.

```sh
python -m unittest tests/test_nxp_rom_advisories_phase81.py -v
python -m tools.audit_nxp_rom_advisories_phase81 local/bruce_pvt_a_prod_signed.bin --sample bruce_prod
python -m tools.audit_nxp_rom_advisories_phase81 local/restricted_ivt_flashloader.bin --sample restricted_ram_loader
python -m tools.audit_nxp_rom_advisories_phase81 local/bootloader-a.bin --sample bootloader_a
```

**Evidence limit:** the absence of deprecated commands in unchanged signed OEM images does **not** prove the ROM would reject a modified CSF. This checker does not inspect ROM firmware, read its HAB version, verify fused SRK or establish acceptance of custom code. The SDP confidentiality and HAB authentication advisories address distinct potential weaknesses; neither constitutes a verified firmware unlock on Stadia. No destructive testing is proposed.
