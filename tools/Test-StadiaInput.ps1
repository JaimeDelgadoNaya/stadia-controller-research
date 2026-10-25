<# Read-only WinMM sampling. JSON is written to stdout; redirect it to save a run. #>
[CmdletBinding()]
param(
    [ValidateRange(1, 60)][int]$Seconds = 10,
    [ValidateRange(10, 1000)][int]$IntervalMs = 50,
    [ValidateRange(0, 255)][int]$JoystickIndex
)
$ErrorActionPreference = 'Stop'
$explicitIndex = $PSBoundParameters.ContainsKey('JoystickIndex')
$report = [ordered]@{
    schema_version = 1
    api = 'Windows WinMM joystick read-only queries'
    requested_seconds = $Seconds
    interval_ms = $IntervalMs
    selection = $(if ($explicitIndex) { 'explicit_index_unverified_identity' } else { 'WinMM manufacturer/product IDs 18D1:9400' })
    status = 'initializing'
    devices = @()
    limitations = @(
        'WinMM is a legacy input view; absence here does not prove absence of HID or Bluetooth.'
        'WinMM manufacturer/product identifiers are driver-reported, not independently verified USB identity.'
        'Observed min/max are sampled values, not calibrated full travel; stationary samples do not test controls.'
        'No vibration, Bluetooth pairing, XInput, console authentication or bridge hardware is tested.'
    )
}
try {
    if ($env:OS -ne 'Windows_NT') { throw 'This diagnostic requires Windows and winmm.dll.' }
    if (-not ('StadiaInputWinMM' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class StadiaInputWinMM {
 [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
 public struct Caps {
  public ushort Mid, Pid;
  [MarshalAs(UnmanagedType.ByValTStr, SizeConst=32)] public string Name;
  public uint Xmin,Xmax,Ymin,Ymax,Zmin,Zmax,Buttons,PeriodMin,PeriodMax;
  public uint Rmin,Rmax,Umin,Umax,Vmin,Vmax,Flags,MaxAxes,Axes,MaxButtons;
  [MarshalAs(UnmanagedType.ByValTStr, SizeConst=32)] public string RegKey;
  [MarshalAs(UnmanagedType.ByValTStr, SizeConst=260)] public string OemVxd;
 }
 [StructLayout(LayoutKind.Sequential)] public struct Position {
  public uint Size,Flags,X,Y,Z,R,U,V,Buttons,ButtonNumber,Pov,Reserved1,Reserved2;
 }
 [DllImport("winmm.dll")] public static extern uint joyGetNumDevs();
 [DllImport("winmm.dll", EntryPoint="joyGetDevCapsW", CharSet=CharSet.Unicode)]
 public static extern uint joyGetDevCaps(UIntPtr id, out Caps caps, uint size);
 [DllImport("winmm.dll")] public static extern uint joyGetPosEx(uint id, ref Position position);
}
'@
    }
    $slotCount = [StadiaInputWinMM]::joyGetNumDevs()
    $report.supported_slots = $slotCount
    $indices = if ($explicitIndex) { @($JoystickIndex) } elseif ($slotCount -gt 0) { @(0..($slotCount - 1)) } else { @() }
    $selected = @()
    foreach ($index in $indices) {
        $caps = New-Object StadiaInputWinMM+Caps
        $result = [StadiaInputWinMM]::joyGetDevCaps([UIntPtr][uint32]$index, [ref]$caps, [uint32][Runtime.InteropServices.Marshal]::SizeOf($caps))
        if ($result -ne 0) {
            if ($explicitIndex) { $report.selection_error_code = $result }
            continue
        }
        if (-not $explicitIndex -and ($caps.Mid -ne 0x18D1 -or $caps.Pid -ne 0x9400)) { continue }
        $axes = [ordered]@{ X = @{ min = $null; max = $null }; Y = @{ min = $null; max = $null } }
        foreach ($entry in @(@('Z',1), @('R',2), @('U',4), @('V',8))) {
            if ($caps.Flags -band $entry[1]) { $axes[$entry[0]] = @{ min = $null; max = $null } }
        }
        $selected += [ordered]@{
            index = $index
            manufacturer_id = ('{0:X4}' -f $caps.Mid)
            product_id = ('{0:X4}' -f $caps.Pid)
            reported_axes = $caps.Axes
            reported_buttons = $caps.Buttons
            pov_supported = [bool]($caps.Flags -band 16)
            successful_samples = 0
            failed_samples = 0
            last_error_code = $null
            observed_axes = $axes
            buttons_seen_mask = [uint32]0
            pov_values_seen = @()
        }
    }
    if ($selected.Count -eq 0) {
        $report.status = 'no_matching_winmm_device'
    } else {
        $timer = [Diagnostics.Stopwatch]::StartNew()
        do {
            foreach ($device in $selected) {
                $position = New-Object StadiaInputWinMM+Position
                $position.Size = [uint32][Runtime.InteropServices.Marshal]::SizeOf($position)
                $position.Flags = 0xFF # JOY_RETURNALL
                $result = [StadiaInputWinMM]::joyGetPosEx([uint32]$device.index, [ref]$position)
                if ($result -ne 0) {
                    $device.failed_samples++
                    $device.last_error_code = $result
                    continue
                }
                $device.successful_samples++
                foreach ($axis in @($device.observed_axes.Keys)) {
                    $value = $position.$axis
                    $range = $device.observed_axes[$axis]
                    if ($null -eq $range.min -or $value -lt $range.min) { $range.min = $value }
                    if ($null -eq $range.max -or $value -gt $range.max) { $range.max = $value }
                }
                $device.buttons_seen_mask = [uint32]($device.buttons_seen_mask -bor $position.Buttons)
                if ($device.pov_supported -and $device.pov_values_seen -notcontains $position.Pov) { $device.pov_values_seen += $position.Pov }
            }
            $remaining = $Seconds * 1000 - $timer.ElapsedMilliseconds
            if ($remaining -gt 0) { Start-Sleep -Milliseconds ([int][Math]::Min($IntervalMs, $remaining)) }
        } while ($timer.Elapsed.TotalSeconds -lt $Seconds)
        $timer.Stop()
        $report.elapsed_seconds = [Math]::Round($timer.Elapsed.TotalSeconds, 3)
        $report.devices = @($selected)
        $successful = @($selected | Where-Object { $_.successful_samples -gt 0 })
        $report.status = if ($successful.Count -gt 0) { 'sampled' } else { 'no_successful_samples' }
    }
} catch {
    $report.status = 'diagnostic_unavailable'
    # Do not include arbitrary exception text, paths or device identifiers in JSON.
    $report.error_type = $_.Exception.GetType().Name
}
$report | ConvertTo-Json -Depth 8
