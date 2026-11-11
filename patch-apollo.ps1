<#
  Apollo 4.2.x - keyless patch (in place)

  Hex-patches the Apollo host exe so the license record is trusted locally:
    * the online verdict gate is nop'd  (server authorized / expiry / version lock stop mattering)
    * the record loader's HMAC check is skipped (any license.json content is accepted)
  Then writes an unsigned, far-future license.json; the host re-signs it itself on first launch.

  Elevates only if the install directory is not writable (Program Files).

  Usage
    powershell -ExecutionPolicy Bypass -File patch-apollo.ps1
    powershell -ExecutionPolicy Bypass -File patch-apollo.ps1 -AppDir "D:\Games\Apollo\app"
#>
[CmdletBinding()]
param(
    [string]$AppDir,
    [switch]$Elevated
)

$ErrorActionPreference = 'Stop'

function Find-AppDir {
    $roots = @('C:\Program Files', ${env:ProgramFiles(x86)}, $env:LOCALAPPDATA, $env:USERPROFILE)
    foreach ($r in $roots) {
        if (-not $r -or -not (Test-Path $r)) { continue }
        $hits = Get-ChildItem -Path $r -Recurse -Depth 4 -Filter 'resources' -Directory -ErrorAction SilentlyContinue |
            Where-Object { Test-Path (Join-Path $_.FullName 'modules') }
        foreach ($h in @($hits)) { return (Split-Path $h.FullName) }
    }
    throw 'Apollo install not found. Pass -AppDir "<the folder containing resources\modules>".'
}

function Find-Pattern([byte[]]$hay, [byte[]]$needle) {
    $last = $hay.Length - $needle.Length
    for ($i = 0; $i -le $last; $i++) {
        if ($hay[$i] -ne $needle[0]) { continue }
        $ok = $true
        for ($j = 1; $j -lt $needle.Length; $j++) {
            if ($hay[$i + $j] -ne $needle[$j]) { $ok = $false; break }
        }
        if ($ok) { return $i }
    }
    return -1
}

# ---- locate --------------------------------------------------------------
if (-not $AppDir) { $AppDir = Find-AppDir }
$modules = Join-Path $AppDir 'resources\modules'
if (-not (Test-Path $modules)) { throw "no resources\modules under $AppDir" }

$hosts = @(Get-ChildItem -Path $modules -Filter '*.exe' -File)
if ($hosts.Count -ne 1) { throw "expected exactly one *.exe in $modules, found $($hosts.Count)" }
$hostExe = $hosts[0]
$hostName = $hostExe.Name
$hostBase = [System.IO.Path]::GetFileNameWithoutExtension($hostName)
Write-Output "host: $($hostExe.FullName)  ($($hostExe.Length) bytes)"

# ---- writability / elevation ---------------------------------------------
$canWrite = $false
try {
    $probe = Join-Path $modules ('.writetest-' + [guid]::NewGuid().ToString('N'))
    [System.IO.File]::WriteAllText($probe, 'x')
    Remove-Item $probe -Force
    $canWrite = $true
} catch { $canWrite = $false }

if (-not $canWrite -and -not $Elevated) {
    $ps = (Get-Process -Id $PID).Path
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"",
                 '-Elevated', '-AppDir', "`"$AppDir`"")
    Write-Output 'install dir is read-only - relaunching with UAC...'
    Start-Process -FilePath $ps -Verb RunAs -ArgumentList $argList
    return
}

# ---- running instance ----------------------------------------------------
$running = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and ($_.Path -ieq $hostExe.FullName) })
if ($running.Count) {
    Write-Output 'Apollo host is running - closing it'
    $running | Stop-Process -Force
    Start-Sleep -Milliseconds 700
}

# ---- patch ---------------------------------------------------------------
$bytes = [System.IO.File]::ReadAllBytes($hostExe.FullName)

# site 1: verdict builder - "cmp byte [rbx+0x10],0 ; je <skip-online-result>"
$p1 = [byte[]](0x80, 0x7B, 0x10, 0x00, 0x0F, 0x84)
$at1 = Find-Pattern $bytes $p1
if ($at1 -lt 0) { throw 'verdict-gate signature not found - unsupported build' }
[Array]::Copy([byte[]](0x90, 0x90, 0x90, 0x90, 0x90, 0x90), 0, $bytes, $at1 + 4, 6)
Write-Output ("patch 1: online verdict gate nop'd at file offset 0x{0:X}" -f ($at1 + 4))

# site 2: record loader - null-sig guard + HMAC verify + "return null" -> success return
$p2 = [byte[]](0x48, 0x85, 0xD2, 0x74, 0x0C, 0x48, 0x8B, 0xCE, 0xE8, 0xBC, 0x0E, 0x00, 0x00,
               0x85, 0xC0, 0x75, 0x04, 0x33, 0xC0, 0xEB, 0x36)
$at2 = Find-Pattern $bytes $p2
if ($at2 -lt 0) { throw 'signature-check signature not found - unsupported build' }
$jump = [byte[]](0xE9, 0x10, 0x00, 0x00, 0x00,
                 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90)
[Array]::Copy($jump, 0, $bytes, $at2, 21)
Write-Output ("patch 2: HMAC signature check disabled at file offset 0x{0:X}" -f $at2)

# ---- write back ----------------------------------------------------------
$backupDir = Join-Path $AppDir 'host-backup'
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
$backup = Join-Path $backupDir ($hostBase + '.stock.bin')
if (-not (Test-Path $backup)) {
    Copy-Item $hostExe.FullName $backup
    Write-Output "backed up stock host -> $backup"
}

[System.IO.File]::WriteAllBytes($hostExe.FullName, $bytes)
Write-Output "patched host written -> $($hostExe.FullName)"

# ---- license record ------------------------------------------------------
$stateDir = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'Apollo'
New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
$lic = Join-Path $stateDir 'license.json'
if (Test-Path $lic) { Copy-Item $lic "$lic.stock.bak" -Force }

$now = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
$record = [ordered]@{
    key             = 'APOLLO-UNSIGNED-0000-0000-0000-0000-0000'
    verifiedUtc     = $now
    expiryUtc       = '2099-12-31T23:59:59.0000000Z'
    deadMessage     = ''
    lastSeenUtc     = $now
    offlineLaunches = 0
    outdatedMsg     = ''
    sig             = 'unsigned'
}
[System.IO.File]::WriteAllText($lic, ($record | ConvertTo-Json -Compress), (New-Object System.Text.UTF8Encoding($false)))
Write-Output "license record -> $lic"

Write-Output ''
Write-Output 'done. launch Apollo from the desktop shortcut - the License page should read active until 2099-12-31.'
