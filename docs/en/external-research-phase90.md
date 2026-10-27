# Phase 90 — External Stadia research transfer assessment

**27 October 2026.** Three offline, independent evidence checks. No controller communication, Wi-Fi credentials, flash writes, eFuse programming or third-party code execution.

## Signed recovery / GaryOderNichts

Primary sources: [Gary's original analysis](https://garyodernichts.blogspot.com/2023/01/looking-into-stadia-controller.html), [StadiaController](https://github.com/GaryOderNichts/StadiaController). We pin **exact Git blobs** in public upstream commit `1396830b449eee10e4d4de047c8db75d503f4ba3`: `stadiatool.py` (`4044e32aab2ea9a849101b03ef841fe358225b3e`), `flashloader.py` (`60c693767e3f795c7489dd5d38895c9d564724e0`) and `sdp.py` (`ff97d184ce4346e48b7457c5f3d772711cc9fa30`). The independent CI only hashes/parses **source text**, never imports or executes it.

Gary's flash dump issues **FlexSPI register writes** to configure each read through the signed restricted flashloader, then reads FIFO. It is not a purely passive action. The source also contains IVT erase/write and reset functions, which are **dangerous on an unrecoverable sole controller**; the author explicitly warns the tool can render hardware unusable. The older comment calling address `0x400F8038` “GPR 6” is incorrect under the RT1060 register map: that address is **SRC_GPR7**.

**Decision:** offline recovery/rollback model GO; physical dump, flash programming or claimed reliable power-loss recovery NO-GO without independently established safeguards.

## NCC Group HAB bypass transfer

Primary sources: [NCC Group i.MX6ULL experiment](https://www.nccgroup.com/research/shining-new-light-on-an-old-rom-vulnerability-secure-boot-bypass-via-dcd-and-csf-tampering-on-nxp-imx-devices/) and [NXP AN12263](https://community.nxp.com/pwmxy87654/attachments/pwmxy87654/imx-processors/160465/2/AN12263.pdf). The original verified Bruce/flashloader IVTs have **null DCD**; their original CSFs lack deprecated WRITE/CHECK/SET MID commands. The selected signed Stadia bootloader A path uses **`authenticate_image_no_dcd`**, not the DCD-processing API in the external exploit. **RT1060 ROM HAB patch version still unmeasured.** This weakens direct DCD-transfer applicability, but cannot definitively exclude pre-auth modified CSF behavior: modified inputs and memory effects are untested.

**Decision:** documentary applicability study GO; physical exploit claims or bypass NO-GO.

## Gotham BLE / Wi-Fi local services

Community [26 October provisioning post](https://www.reddit.com/r/Stadia/comments/1xfwq9w/stadia_controller_wifi_provisioning_python_script/) links a [Python gist](https://gist.github.com/supernielsen/6cb9215b21481baafe171d645542f40f). Its author reports BLE provisioning of original **Gotham** Wi-Fi firmware (state `0x3c`) and on 27 October reports partial TLS progress. **The actual gist revision has not been fetched, hash-verified or independently audited in this phase.** No authenticated local controller input protocol has been demonstrated and the owner controller's actual Gotham/Bruce installed image has not been matched.

**Decision:** prioritize a *revision-pinned static* protocol and credential-handling audit, followed by synthetic test vectors; do not handle real SSIDs/passwords, send BLE provisioning or claim a local WebRTC endpoint is already supported.

## Reproducibility

[Static original-source triage](../../tools/audit_external_research_phase90.py) · [fail-closed tests](../../tests/test_external_research_phase90.py) · [sanitized structured report](../../evidence/external-research-phase90.json) · [three-lane GitHub Actions](../../.github/workflows/external-research-phase90.yml).

These workflows are automated verification checks, **not persistent autonomous research agents**. No original custom firmware, signature bypass or guaranteed restoration has been achieved.
