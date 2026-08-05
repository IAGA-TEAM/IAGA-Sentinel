#requires -Version 5.1
<#
.SYNOPSIS
    Detach from IAGA Sentinel. Dry run by default.

.DESCRIPTION
    Prints exactly what it would remove and exits. Pass -Yes to actually remove it.

    The signing key is deliberately NOT removed unless you also pass -IncludeKey.
    Deleting the database throws away the evidence; deleting the key throws away
    your ability to check evidence you already exported — including chains
    sitting in someone else's audit folder. There is no recovery.

.EXAMPLE
    .\scripts\uninstall.ps1                 # dry run
    .\scripts\uninstall.ps1 -Yes            # remove the install, keep the key
    .\scripts\uninstall.ps1 -Yes -IncludeKey
#>
[CmdletBinding()]
param(
    [string]$Path = '.',
    [switch]$Yes,
    [switch]$IncludeKey
)

$ErrorActionPreference = 'Stop'
$dir = (Resolve-Path $Path).Path
$key = if ($env:IAGA_SENTINEL_SIGNER_KEY_PATH) { $env:IAGA_SENTINEL_SIGNER_KEY_PATH }
       else { Join-Path $env:USERPROFILE '.iaga-sentinel\keys\receipt_signer.ed25519' }

Write-Host 'IAGA Sentinel: detach'
Write-Host ("  working directory: {0}" -f $dir)
Write-Host ''

# Anything still running keeps a handle on the database.
$running = @(Get-Process iaga, iaga-sentinel -ErrorAction SilentlyContinue)
if ($running.Count -gt 0) {
    Write-Host 'STILL RUNNING (stop these first, or this script cannot free the database):' -ForegroundColor Yellow
    $running | ForEach-Object { Write-Host ("    pid {0}  {1}" -f $_.Id, $_.ProcessName) }
    Write-Host ''
}

$candidates = @(
    'iaga_sentinel.db', 'iaga_sentinel.db-wal', 'iaga_sentinel.db-shm',
    'iaga_shared.db',   'iaga_shared.db-wal',   'iaga_shared.db-shm',
    'iaga-sentinel.yaml', 'iaga-sentinel.yml', 'iaga-sentinel.json',
    'agent_rules.dictum', 'chain.json'
) | ForEach-Object { Join-Path $dir $_ } | Where-Object { Test-Path $_ }

if ($candidates.Count -eq 0) {
    Write-Host 'Nothing to remove in this directory.'
} else {
    Write-Host 'WOULD REMOVE:' -ForegroundColor Cyan
    $candidates | ForEach-Object { Write-Host ("    {0}" -f $_) }
    Write-Host ''
    Write-Host '  What that costs you: the audit trail and every signed receipt in that'
    Write-Host '  database. Chains you already exported to a .json file stay valid and'
    Write-Host '  keep verifying - that is the point of exporting them.'
}
Write-Host ''

if (Test-Path $key) {
    if ($IncludeKey) {
        Write-Host 'WOULD ALSO DESTROY THE SIGNING KEY:' -ForegroundColor Red
        Write-Host ("    {0}" -f $key)
        Write-Host '  Every receipt ever produced on this machine becomes permanently'
        Write-Host '  unverifiable, including chains already exported and handed to someone'
        Write-Host '  else. There is no recovery. Archive the file instead if you are unsure.'
    } else {
        Write-Host ("KEEPING the signing key: {0}" -f $key) -ForegroundColor Green
        Write-Host '  It is shared by every project on this machine and is what makes past'
        Write-Host '  receipts verifiable. Pass -IncludeKey to destroy it anyway.'
    }
} else {
    Write-Host ("No signing key at {0} (nothing to keep)." -f $key)
}
Write-Host ''

if (-not $Yes) {
    Write-Host 'Dry run. Nothing was removed. Re-run with -Yes to proceed.' -ForegroundColor Yellow
    exit 0
}

if ($running.Count -gt 0) {
    Write-Host 'Refusing to remove anything while a governed process is still running.' -ForegroundColor Red
    Write-Host 'Stop it and re-run.'
    exit 1
}

$candidates | ForEach-Object { Remove-Item $_ -Force; Write-Host ("removed  {0}" -f $_) }
if ($IncludeKey -and (Test-Path $key)) {
    Remove-Item $key -Force; Write-Host ("removed  {0}" -f $key)
}

Write-Host ''
Write-Host 'Done. What is left on this machine:'
Write-Host '  - the checkout itself (delete the directory to remove it)'
Write-Host '  - the binary, if you ran `cargo install` (cargo uninstall iaga-sentinel-core)'
if (-not $IncludeKey) { Write-Host ("  - the signing key, on purpose: {0}" -f $key) }
Write-Host ''
Write-Host 'Your agent is now ungoverned: nothing is checked and nothing is recorded.'
Write-Host 'Say so out loud rather than assuming it is still protecting you.'
