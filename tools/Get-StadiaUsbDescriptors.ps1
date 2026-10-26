<# Standard descriptor reads only. Does not request strings or send class/vendor commands. #>
param([string]$OutFile)
$ErrorActionPreference = 'Stop'
foreach ($name in 'StadiaUsbDescriptors','StadiaHubDescriptors') {
    if (-not ($name -as [type])) { Add-Type -Path (Join-Path $PSScriptRoot "$name.cs") }
}
$devices = @(Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId.StartsWith('USB\VID_18D1&PID_9400\') })
if ($devices.Count -ne 1) { throw 'Exactly one connected USB Stadia controller is required.' }
$hub = (Get-PnpDeviceProperty -InstanceId $devices[0].InstanceId -KeyName DEVPKEY_Device_Parent).Data
$port = (Get-PnpDeviceProperty -InstanceId $devices[0].InstanceId -KeyName DEVPKEY_Device_Address).Data
function Convert-Descriptors([string]$Text) {
    $result = [ordered]@{}
    foreach ($line in ($Text -split "`n")) {
        if ($line -match '^(Device|Configuration) descriptor(?: \(\d+ bytes\))?: ([0-9A-F-]+)') {
            $result[$Matches[1].ToLowerInvariant()] = $Matches[2].Replace('-', '').ToLowerInvariant()
        }
    }
    if ($result.Count -ne 2) { throw 'Missing descriptor response.' }
    return $result
}
$report = [ordered]@{
    schema_version = 1
    phase = 61
    captured_at = [DateTimeOffset]::Now.ToString('o')
    hub = Convert-Descriptors ([StadiaHubDescriptors]::Run($hub,$port))
    winusb_function_view = Convert-Descriptors ([StadiaUsbDescriptors]::Run())
    methods = @('Hub IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION, types 1 and 2, index 0', 'WinUsb_GetDescriptor, types 1 and 2, index 0')
    limits = @('One controller, current USB mode only; no packet capture.', 'Descriptor availability does not prove bulk parser, callback invocation or RAM contents.', 'Internal firmware class selector 10 must not be equated with bInterfaceClass 0x0A.', 'No string descriptors, device paths, serial values or Bluetooth addresses are recorded.', 'No class/vendor requests, bulk payloads, output reports, mode changes, flash or eFuse writes.')
}
if ($report.hub.device -ne $report.winusb_function_view.device) { throw 'Device descriptor mismatch.' }
if (-not $report.hub.device.StartsWith('1201') -or $report.hub.device.Substring(16,8) -ne 'd1180094') { throw 'Unexpected hub device identity.' }
$json = $report | ConvertTo-Json -Depth 8
if ($OutFile) { [IO.File]::WriteAllText($OutFile, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false)) }
$json
