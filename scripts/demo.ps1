#requires -Version 5.1
<#
.SYNOPSIS
    IAGA Sentinel demo launcher: build, reset, serve, print the dashboard URL.

.DESCRIPTION
    One-command, idempotent entrypoint for recording the IAGA Sentinel demo.
    Builds the release binaries if needed, wipes the demo SQLite DB so every
    take starts from an identical seeded state, starts `iaga serve --seed-demo`
    in the foreground (server logs stay visible on camera) and prints the
    dashboard URL once /health responds. Safe to re-run for retakes.

    No product behaviour is changed; this only orchestrates the existing CLI.

.PARAMETER Build
    Force a release rebuild even if the binaries already exist.

.PARAMETER Force
    Alias of -Build.

.PARAMETER Port
    Port the server binds (default 4010, matching the product default).

.PARAMETER KeepDb
    Skip the DB wipe. NOT recommended: a clean DB is what makes the demo
    start from an identical seeded state every run.

.EXAMPLE
    .\scripts\demo.ps1 -Build
    Build (forced) then launch the server, ready for recording.

.EXAMPLE
    .\scripts\demo.ps1
    Re-launch for a retake (rebuilds only if a binary is missing).
#>
[CmdletBinding()]
param(
    [switch]$Build,
    [switch]$Force,
    [int]$Port = 4010,
    [switch]$KeepDb
)

$ErrorActionPreference = 'Stop'

# scripts\ -> repo root. Both serve and replay resolve the demo DB relative to
# the working directory, so everything must run from the repo root.
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$IagaExe   = Join-Path $RepoRoot 'target\release\iaga.exe'
$VerifyExe = Join-Path $RepoRoot 'target\release\iaga-verify.exe'
$DbBase    = Join-Path $RepoRoot 'iaga_sentinel.db'
$HealthUrl = "http://localhost:$Port/health"
$Dashboard = "http://localhost:$Port/"

function Write-Rule {
    param([string]$Text, [string]$Color = 'Cyan')
    $bar = ('=' * 64)
    Write-Host ''
    Write-Host $bar -ForegroundColor $Color
    Write-Host ("  " + $Text) -ForegroundColor $Color
    Write-Host $bar -ForegroundColor $Color
    Write-Host ''
}

Write-Rule 'IAGA SENTINEL  -  DEMO LAUNCHER' 'Green'
Write-Host ("Repo root : {0}" -f $RepoRoot)
Write-Host ("Dashboard : {0}" -f $Dashboard)

# 1. Ensure both release binaries exist (iaga + iaga-verify).
$needBuild = $Build -or $Force -or -not (Test-Path $IagaExe) -or -not (Test-Path $VerifyExe)
if ($needBuild) {
    Write-Rule 'Building release binaries (CARGO_INCREMENTAL=0)' 'Yellow'
    $env:CARGO_INCREMENTAL = '0'
    & cargo build --release -p iaga-sentinel-core -p iaga-sentinel-verify
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }
} else {
    Write-Host 'Build     : up-to-date binaries found, skipping (pass -Build to force).' -ForegroundColor DarkGray
}
if (-not (Test-Path $IagaExe))   { throw "iaga.exe not found at $IagaExe" }
if (-not (Test-Path $VerifyExe)) { throw "iaga-verify.exe not found at $VerifyExe" }

# 2. Reset the demo DB so every recording starts from an identical seed.
if (-not $KeepDb) {
    Write-Host 'Reset     : deleting iaga_sentinel.db (+ -wal/-shm) for a clean seed.' -ForegroundColor DarkGray
    Remove-Item $DbBase, ($DbBase + '-wal'), ($DbBase + '-shm') -ErrorAction SilentlyContinue
}

# 3. Environment: open mode (no API key needed for the demo) + no incremental.
# Bind to loopback explicitly: open mode makes every unauthenticated caller
# an implicit ADMIN, and the server's own default host is 0.0.0.0.
$env:IAGA_SENTINEL_HOST      = '127.0.0.1'
$env:IAGA_SENTINEL_OPEN_MODE = 'true'
$env:CARGO_INCREMENTAL       = '0'
$env:PORT                    = "$Port"

# 4. Background readiness watcher: returns once /health responds.
$watcher = Start-Job -ScriptBlock {
    param($HealthUrl)
    for ($i = 0; $i -lt 60; $i++) {
        try {
            $h = Invoke-RestMethod -Uri $HealthUrl -TimeoutSec 2
            if ($h.ok) { return @{ ready = $true; openMode = $h.openMode } }
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
    return @{ ready = $false }
} -ArgumentList $HealthUrl

# 5. Start the server in the foreground (logs visible for the recording).
Write-Host ''
Write-Host 'Starting server (foreground). Waiting for /health ...' -ForegroundColor Cyan
$srv = Start-Process -FilePath $IagaExe -ArgumentList 'serve', '--seed-demo' `
        -WorkingDirectory $RepoRoot -PassThru -NoNewWindow

$res = Receive-Job -Job $watcher -Wait
Remove-Job -Job $watcher -Force -ErrorAction SilentlyContinue

if (-not $res.ready) {
    Write-Host 'Server did not become healthy in time. Check the logs above.' -ForegroundColor Red
    if (-not $srv.HasExited) { Stop-Process -Id $srv.Id -Force -ErrorAction SilentlyContinue }
    exit 1
}

Write-Rule 'READY' 'Green'
Write-Host '  DASHBOARD ->  ' -NoNewline -ForegroundColor Green
Write-Host $Dashboard -ForegroundColor White
Write-Host ("  Open mode :  {0}" -f $res.openMode) -ForegroundColor DarkGray
Write-Host ''
Write-Host '  In a SECOND pane, run the live driver:' -ForegroundColor Cyan
Write-Host '      .\scripts\demo_run.ps1' -ForegroundColor White
Write-Host ''
Write-Host '  Press Ctrl+C here to stop the server when the take is done.' -ForegroundColor DarkGray
Write-Host ''

# 6. Stay attached to the server until Ctrl+C, then clean up the process.
try {
    Wait-Process -Id $srv.Id
} finally {
    if (-not $srv.HasExited) { Stop-Process -Id $srv.Id -Force -ErrorAction SilentlyContinue }
}
