# Phase 61 — Physical USB descriptors and the partial WinUSB view

**26 October 2026.** Read-only measurements from one connected controller in normal USB mode, `18D1:9400`, following phase 60. The installed application was not dumped/hash-matched and its build was not queried again.

The parent hub returns configuration 1, **80 bytes**, two interfaces at alternate setting 0:

| Interface | USB class/subclass/protocol | Declared endpoints | Maximum packet |
|---|---|---|---|
| 0 | `FF/00/00`, vendor | bulk IN `0x87`, OUT `0x07` | 512 bytes |
| 1 | `03/00/00`, HID | interrupt IN `0x83`, OUT `0x03` | 64 bytes |

The HID descriptor advertises a 182-byte report descriptor; its raw contents were not retrieved. Windows parsed capabilities report ID3 input (11 bytes), ID5 output (5 bytes, two 16-bit values) and no declared feature reports. Output capabilities do not prove rumble behavior.

## Measured API-view difference

`WinUsb_GetDescriptor` on MI_00 returns a **32-byte**, single-interface configuration containing only the vendor bulk endpoints. A parent-hub `IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION` returns the complete 80-byte configuration, including both interface associations and HID. Device descriptor bytes match across views. Both exact responses are retained. This difference was measured on this host; it is not generalized to all Windows/driver versions.

Microsoft documents the [hub descriptor IOCTL](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/usbioctl/ni-usbioctl-ioctl_usb_get_descriptor_from_node_connection) and [request structure](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/usbioctl/ns-usbioctl-_usb_descriptor_request). The stack fixes the request to standard device-to-host GET_DESCRIPTOR.

## Hypothesis implications

The live application advertises bulk `0x07/0x87`, matching bootloader endpoint directions and packet sizes. This does **not** identify the live application's parser or callback: application and bootloader are distinct contexts. The configuration declares USB classes `0xFF` and `0x03`, with no USB class `0x0A` interface. The firmware's **internal selector 10** must not automatically be equated to USB `bInterfaceClass=0x0A`; its internal use remains unresolved.

No RAM fields, callback invocation, host-to-callback path, arbitrary execution, HAB bypass or native console compatibility were measured. Phase 60's NO-GO remains in force.

## Reproduction and scope

```powershell
./tools/Get-StadiaUsbDescriptors.ps1 -OutFile local/usb-enumeration-phase61.json
./tools/Get-StadiaHidCapabilities.ps1 -OutFile local/hid-capabilities-phase61.json
python tools/parse_usb_configuration.py evidence/usb-enumeration-phase61.json
python -m unittest tests.test_usb_configuration_phase61 -v
```

Create `local/` first. Requires Windows, one USB controller and its existing drivers. The collector resolves the parent hub/port using PnP and reads standard descriptors types 1 and 2, index 0. No strings, serial values, paths or Bluetooth addresses are recorded. WinUSB is opened with the access needed for initialization. No class/vendor transfers, bulk payloads, output reports, driver changes, mode changes, memory/flash/eFuse writes, packet capture or reconnect were performed.

[Raw measured descriptors](../../evidence/usb-enumeration-phase61.json) · [Measured HID capabilities](../../evidence/hid-capabilities-phase61.json)

Next: compare the full descriptors offline against candidate tables in the exact signed OEM application, separately from the bootloader. Linking internal selector 10 requires a verified descriptor/record path to the configuration that reproduces these interfaces; endpoint coincidence alone is insufficient.
