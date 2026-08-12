#requires -Version 5.1
<#
.SYNOPSIS
    IAGA Sentinel live demo driver: 3 real verdicts + offline receipt proof.

.DESCRIPTION
    Drives three real seeded scenarios through the live governance pipeline
    (Allow -> Review -> Block), paced so the dashboard Live feed is watchable,
    and asserts each verdict so a non-deterministic take can never be recorded.

    All three beats share one sessionId, so their signed receipts form a single
    hash-chained run. The driver then exports that run and verifies it offline
    with iaga-verify (no server, no DB, no network) - twice: against the key
    embedded in the export, then with that key stated explicitly plus
    --expect-count. The key comes from the export either way, so the second
    call silences the self-asserted warning rather than authenticating
    authorship; the count is the external anchor that catches a chain that
    is not the one this take drove.

    Nothing is faked: every verdict comes from POST /v1/inspect on the running
    server, and the scenario payloads are fetched live from the server itself.

.PARAMETER BaseUrl
    Server base URL (default http://localhost:4010).

.PARAMETER SessionId
    Fixed sessionId used as the receipt run_id, grouping all three beats into
    one hash-chained run.

.PARAMETER PauseSec
    Seconds to pause between beats so each verdict lands on camera (default 5).

.PARAMETER ChainFile
    Output path for the exported receipt chain (default chain.json, gitignored).

.EXAMPLE
    .\scripts\demo_run.ps1
#>
[CmdletBinding()]
param(
    [string]$BaseUrl   = 'http://localhost:4010',
    [string]$SessionId = 'demo-session-iaga',
    [int]   $PauseSec  = 5,
    [string]$ChainFile = 'chain.json'
)

$ErrorActionPreference = 'Stop'

# replay reads the demo DB relative to the working directory, and chain.json is
# written here too, so run from the repo root (same CWD as the server).
$RepoRoot  = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot
$IagaExe   = Join-Path $RepoRoot 'target\release\iaga.exe'
$VerifyExe = Join-Path $RepoRoot 'target\release\iaga-verify.exe'
$ChainPath = Join-Path $RepoRoot $ChainFile

function Write-Banner {
    param([string]$Text, [string]$Fg = 'White', [string]$Bg = 'DarkCyan')
    $width = 64
    $pad = [Math]::Max(0, $width - $Text.Length)
    Write-Host ''
    Write-Host (' ' * ($width + 2)) -BackgroundColor $Bg
    Write-Host (' ' + $Text + (' ' * $pad)) -ForegroundColor $Fg -BackgroundColor $Bg
    Write-Host (' ' * ($width + 2)) -BackgroundColor $Bg
    Write-Host ''
}

function Write-Verdict {
    param([string]$Decision, [int]$Score)
    switch ($Decision.ToLower()) {
        'allow'  { Write-Banner ("VERDICT: ALLOW    risk=$Score") 'Black' 'Green' }
        'review' { Write-Banner ("VERDICT: REVIEW   risk=$Score   (human-in-the-loop)") 'Black' 'Yellow' }
        'block'  { Write-Banner ("VERDICT: BLOCK    risk=$Score   (action denied)") 'White' 'Red' }
        default  { Write-Banner ("VERDICT: $($Decision.ToUpper())   risk=$Score") 'White' 'DarkGray' }
    }
}

function Select-Beat {
    param($Scenarios, [int]$StepNum, [string]$TitleNeedle)
    $hit = $Scenarios | Where-Object { $_.step -eq "Step $StepNum" } | Select-Object -First 1
    if ($null -eq $hit) {
        $hit = $Scenarios | Where-Object { $_.title -like "*$TitleNeedle*" } | Select-Object -First 1
    }
    if ($null -eq $hit) { throw "Could not locate beat: Step $StepNum / '$TitleNeedle'" }
    return $hit
}

Write-Banner 'IAGA SENTINEL  -  LIVE GOVERNANCE  (one signed session)' 'White' 'DarkBlue'
Write-Host ("Server  : {0}" -f $BaseUrl)
Write-Host ("Session : {0}   (all 3 beats chain into one run, run_id = <agentId>:{0})" -f $SessionId)

# Determinism guard: reset adaptive risk weights to defaults. In open mode the
# request authenticates as implicit admin, so no token is needed. The driver
# never calls /v1/risk/feedback, so weights stay at defaults for the whole run.
try {
    Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/risk/weights/reset" -TimeoutSec 5 | Out-Null
    Write-Host 'Weights : reset to defaults (determinism guard).' -ForegroundColor DarkGray
} catch {
    Write-Host ("Weights : reset skipped ({0}); a fresh server already uses defaults." -f $_.Exception.Message) -ForegroundColor DarkYellow
}

# Pull the real seeded scenarios from the running server (source of truth).
$scenarios = Invoke-RestMethod -Uri "$BaseUrl/v1/demo/scenarios" -TimeoutSec 10

$beats = @(
    @{ N = 1; Expect = 'allow';  Beat = (Select-Beat $scenarios 1 'repository inspection') },
    @{ N = 2; Expect = 'review'; Beat = (Select-Beat $scenarios 2 'secret injection') },
    @{ N = 3; Expect = 'block';  Beat = (Select-Beat $scenarios 3 'Destructive') }
)

$failures = 0

foreach ($b in $beats) {
    $beat = $b.Beat
    Write-Banner ("BEAT {0}/3   ABOUT TO: {1}    | expected: {2}" -f $b.N, $beat.title, $b.Expect.ToUpper()) 'White' 'DarkCyan'

    # Round-trip the server's own request object and only inject the shared
    # sessionId, so every field name stays exactly as the product emits it.
    $req = $beat.request
    if (($req.PSObject.Properties.Name -contains 'metadata') -and $req.metadata) {
        $req.metadata | Add-Member -NotePropertyName sessionId -NotePropertyValue $SessionId -Force
    } else {
        $req | Add-Member -NotePropertyName metadata -NotePropertyValue @{ sessionId = $SessionId } -Force
    }

    $body = $req | ConvertTo-Json -Depth 12
    $resp = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/inspect" -ContentType 'application/json' -Body $body -TimeoutSec 15

    $decision = "$($resp.decision)"
    $score    = [int]$resp.risk.score
    Write-Verdict $decision $score

    Write-Host '  Why:' -ForegroundColor DarkGray
    # Policy/budget attributions are APPENDED to risk.reasons, so a plain
    # "first four" drops exactly the line that names the rule that refused.
    # Show them first, then fill the rest with baseline reasons.
    $allReasons = @($resp.risk.reasons)
    $attributed = @($allReasons | Where-Object { $_ -match '^(dictum\[|cost:)' })
    $baseline   = @($allReasons | Where-Object { $_ -notmatch '^(dictum\[|cost:)' })
    foreach ($reason in @($attributed + $baseline | Select-Object -First 4)) {
        Write-Host ("    - {0}" -f $reason) -ForegroundColor DarkGray
    }
    if ($resp.reviewRequestId) {
        Write-Host ("  reviewRequestId    : {0}" -f $resp.reviewRequestId) -ForegroundColor DarkGray
    }
    Write-Host ("  auditEvent.eventId : {0}" -f $resp.auditEvent.eventId) -ForegroundColor DarkGray

    if ($decision.ToLower() -ne $b.Expect) {
        Write-Host ("  ASSERTION FAILED: expected {0}, got {1}. Determinism broken." -f $b.Expect.ToUpper(), $decision.ToUpper()) -ForegroundColor Red
        $failures++
    }

    if ($b.N -lt 3) {
        Write-Host ("  ... pausing {0}s (watch the dashboard Live feed) ..." -f $PauseSec) -ForegroundColor DarkGray
        Start-Sleep -Seconds $PauseSec
    }
}

if ($failures -gt 0) {
    Write-Banner ("STOP: {0} verdict assertion(s) failed - do NOT use this take." -f $failures) 'White' 'Red'
    exit 1
}

# Let the final receipt commit before reading it back.
Start-Sleep -Seconds 2

# ── Money shot: export the signed chain and verify it offline ──
Write-Banner 'MONEY SHOT  -  OFFLINE PROOF (no server, no DB, just a file + a key)' 'White' 'DarkMagenta'

Write-Host ("> iaga replay {0} --export {1}" -f $SessionId, $ChainFile) -ForegroundColor Cyan
$exportOut = & $IagaExe replay $SessionId --export $ChainPath
if ($LASTEXITCODE -ne 0) {
    Write-Banner 'EXPORT FAILED' 'White' 'Red'
    $exportOut | ForEach-Object { Write-Host $_ -ForegroundColor Red }
    exit 1
}
$exportOut | ForEach-Object { Write-Host $_ -ForegroundColor Green }

$chain  = Get-Content $ChainPath -Raw | ConvertFrom-Json
$pubHex = $chain.signer_verifying_key
$runId  = $chain.run_id
$count  = @($chain.receipts).Count
# How many receipts THIS take is entitled to. The run_id is <agentId>:<sessionId>
# and the sessionId is fixed, so a second driver run against a server that is
# still up appends to the same chain instead of starting a new one: the export
# comes back with 6 receipts and every verdict assertion still passes, because
# the verdicts really were Allow/Review/Block both times. Without this anchor
# the take prints a green CHAIN OK over a chain that is not the one you drove.
$expected = $beats.Count
Write-Host ''
Write-Host ("  run_id   : {0}" -f $runId) -ForegroundColor White
Write-Host ("  receipts : {0}   (this take drove {1}: Allow, Review, Block)" -f $count, $expected) -ForegroundColor White
Write-Host ("  pub key  : {0}" -f $pubHex) -ForegroundColor DarkGray
Write-Host ''

# Verify against the key embedded in the export (prints a self-asserted warning).
Write-Host ("> iaga-verify {0}" -f $ChainFile) -ForegroundColor Cyan
& $VerifyExe $ChainPath | ForEach-Object { Write-Host $_ -ForegroundColor Green }
$embeddedExit = $LASTEXITCODE

# Verify again with the key stated explicitly AND with the receipt count this
# take drove.
#
# Note what this second call does and does not prove. The key comes from
# chain.json itself (`$chain.signer_verifying_key`), so passing it back only
# silences the self-asserted warning — it cannot authenticate authorship,
# because a forger who re-signed the chain would have supplied their own key
# here too. Authenticating authorship means pinning a key you obtained OUT OF
# BAND (your key file, a published fingerprint) and passing that. The count,
# by contrast, is a real external anchor: it comes from what this driver drove,
# not from the file. `CHAIN OK` alone proves PREFIX
# integrity, so it is silent about both truncation and a chain that grew past
# the run you recorded; --expect-count is the external anchor that catches both.
Write-Host ''
Write-Host ("> iaga-verify {0} --key {1} --expect-count {2}" -f $ChainFile, $pubHex, $expected) -ForegroundColor Cyan
$pinnedOut = & $VerifyExe $ChainPath --key $pubHex --expect-count $expected
$pinnedExit = $LASTEXITCODE
$pinnedOut | ForEach-Object { Write-Host $_ -ForegroundColor Green }

if (($embeddedExit -eq 0) -and ($pinnedExit -eq 0)) {
    Write-Banner ("CHAIN OK   run_id={0}   receipts={1}   terminal verdict = BLOCK" -f $runId, $count) 'Black' 'Green'
    Write-Host '  Verified offline: no network, no server, no DB - just this file + the public key.' -ForegroundColor Green
    Write-Host '  The terminal receipt cryptographically attests the BLOCK.' -ForegroundColor Green
} else {
    Write-Banner ("VERIFY FAILED  (embedded exit={0}, pinned exit={1})" -f $embeddedExit, $pinnedExit) 'White' 'Red'
    if ($count -ne $expected) {
        Write-Host ("  The chain holds {0} receipts but this take drove {1}. A stale server is still" -f $count, $expected) -ForegroundColor Red
        Write-Host ('  up and the previous take is chained into the same run_id: stop it, then re-run') -ForegroundColor Red
        Write-Host ('  .\scripts\demo.ps1 (it wipes the DB and re-seeds). Do NOT use this take.') -ForegroundColor Red
    }
    exit 1
}
