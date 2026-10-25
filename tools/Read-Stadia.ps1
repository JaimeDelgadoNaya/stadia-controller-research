$ErrorActionPreference = 'Stop'
if (-not ('StadiaRead' -as [type])) { Add-Type -Path (Join-Path $PSScriptRoot 'StadiaRead.cs') }
[StadiaRead]::Run()
