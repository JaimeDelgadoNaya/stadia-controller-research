# Phase 83 — Evidence provenance for RT1060 BootROM HAB version

**27 October 2026 — precise on-device ROM HAB version is not measured.** Offline evidence audit only: no USB, SDP, RAM/flash operations or OTP writes.

[NXP AN12263](https://community.nxp.com/pwmxy87654/attachments/pwmxy87654/imx-processors/160465/2/AN12263.pdf) and the i.MX RT1060 reference manual place the HAB **ROM Vector Table (RVT)** at `0x00200300`. The **pointer slots** for `authenticate_image_no_dcd` and `get_version` are offsets `+0x2c` (`0x0020032c`) and `+0x30` (`0x00200330`). The slot holds a function pointer; **it is not a callable function address itself**. The [official HABv4 API guide](https://community.nxp.com/pwmxy87654/attachments/pwmxy87654/MCX/481/1/HAB4_API.pdf) specifies RVT tag `0xdd` and `uint32_t get_version(void)` to report the library version.

NXP AN12263 explicitly notes **HAB 4.2.7** as an exception to availability of `get_version` and `authenticate_image_no_dcd`. The [additional-image HAB security advisory](https://community.nxp.com/t5/i-MX-Security/Authentication-Vulnerability-when-extending-the-Root-of-Trust/ta-p/1511348) covers releases up to **4.3.6** only in applications using the ROM API to authenticate further images.

**Evidence separation:**

- Previously measured `0x12343412` = HAB CLOSED and `0xf0f0f0f0` = successful status, **neither encodes patch version**.
- Original signed bootloader A calls the `authenticate_image_no_dcd` **RVT pointer slot** at `0x0020032c`; its code alone does not reveal the version of the ROM it calls.
- Image IVT/CSF header version bytes describe **signed data-structure formats**. They **must not be read as a ROM HAB patch level**.
- No owner ROM RVT read or `get_version()` return is currently archived; applicability and firmware unlock remain **unresolved**.

The [SHA-256-pinned offline auditor](../../tools/audit_hab_rom_version_phase83.py) and [synthetic tests](../../tests/test_hab_rom_version_phase83.py) distinguish signed-file headers, optionally check a previously obtained bounded ROM RVT snapshot (tag, length, pointer slots), and leave **actual HAB library version unmeasured**. Any optional operator-provided snapshot or return value stays **unverified** without independent provenance and does not authorize a bypass claim.

```sh
python -m unittest tests/test_hab_rom_version_phase83.py -v
python -m tools.audit_hab_rom_version_phase83 local/restricted_ivt_flashloader.bin --sample restricted_ram_loader
python -m tools.audit_hab_rom_version_phase83 local/bruce_pvt_a_prod_signed.bin --sample bruce_prod
```

The related [CVE-2022-45163 advisory](https://community.nxp.com/t5/i-MX-Security/SDP-Read-Bypass-CVE-2022-45163/ta-p/1553565) concerns potential SDP **memory disclosure**, a different property from signed-code execution. No access to hardware, ROM execution or test firmware is performed or implied.
