# Phase 32 — External console routes

[Español](../es/compatibilidad-consolas.md)

Official-source review: **2026-10-25**. The owner prioritizes whichever consoles
can accept Stadia while preserving its firmware. **No adapter/console pairing
below has been tested locally.** These are vendor-documented candidates.

| Target | Candidate and evidence |
|---|---|
| Switch / PS3 | USB Stadia → MAYFLASH MAGIC-NS 2. Stadia introduced in **M:V1.19 / S:V1.30**. Switch Pro output requires wired Pro Controller communication enabled. [Product](https://mayflash.com/product/showproduct.php?id=45), [Stadia release](https://www.mayflash.com/Support/showdownload.php?id=203). |
| PS4 / PS3 / Switch | USB Stadia → MAGIC-S PRO 2. Stadia introduced in **M:V1.12 / S:V1.30**. [Product and releases](https://www.mayflash.com/Support/showdownload.php?id=207). |
| Xbox One / Series X\|S | USB Stadia → MAGIC-X. Stadia introduced in **M:V1.07 / S:V1.30**. Console acceptance and continued operation remain local test requirements; vendor compatibility is not proof of authorization. [Product and releases](https://www.mayflash.com/Support/showdownload.php?lang=en&id=208). |
| PS5 | MAGIC-S Ultimate is a bounded hypothesis: Stadia added in **M:V1.05 / S:V1.30**, later beta **M:V1.06 / S:V1.31** advertises mainly PS5 fighting games. This does not establish Stadia+PS5 operation or general PS5 game support. [Product](https://www.mayflash.com/product/showproduct.php?id=49). |
| Switch 2 | Current MAGIC-NS 2 / MAGIC-X product pages list this target. Stadia+Switch 2 and required firmware remain untested here. |

These are introduction versions, not latest-version claims. Use the correct
adapter model/revision and its vendor instructions. Start with USB: Stadia
release notes mention replugging after idle/disconnection. Stadia BLE support
is not explicitly distinguished in the reviewed general wireless lists; do not
assume it or transfer generic rumble/audio claims to Stadia.

No explicit Stadia entry was found in reviewed
[8BitDo Adapter 2](https://shop.8bitdo.com/products/8bitdo-usb-adapter-2) or
[Brook downloads](https://www.brookaccessory.com/dl.php) sources. This is not an
exhaustive incompatibility finding. The ESP32-S3 bridge's PC Xbox 360 output
does not establish any console route or an adapter chain.

Next physical test: record console/system, game, adapter revision/firmware and
cable; test buttons, axes, triggers, home/guide, reconnect and sleep/resume.
Record rumble and extra functions separately. Mark only the exact observed
combination as tested. No purchase or adapter installation was performed.

Source access: Stadia release pages `id=203`, `id=207`, `id=208` and numeric
NS 2/Ultimate product pages were retrieved directly. Named MAGIC-X and
MAGIC-S PRO 2 product URLs returned 404; their target-console lists were
available in official-page search results only. Those two target claims need
direct reconfirmation; table links use the retrievable Stadia release pages.
