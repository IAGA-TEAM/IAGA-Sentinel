#requires -Version 5.1
<#
.SYNOPSIS
    IAGA Sentinel agent self-bootstrap: encode policy -> serve -> self-connect
    over MCP -> prove the agent's own policy governs its MCP calls.

.DESCRIPTION
    One command that runs the whole AGENTS.md "Standing procedure for the AI
    agent" over the MCP self-connect path, deterministically, on a virgin DB:

      1. Resolve/build the `iaga` binary (no PATH assumption).
      2. Start from a FRESH shared DB (per-agent trust persists, so only a clean
         DB guarantees identical verdicts).
      3. Write agent_rules.dictum (the agent's instructions as enforced policy)
         and validate it (lint + check).
      4. `iaga serve --policy agent_rules.dictum` on the shared DB (open mode),
         wait for /health, confirm the overlay actually loaded.
      5. Self-connect over MCP with `iaga mcp-server --policy agent_rules.dictum`
         (SAME policy, SAME shared DB) and drive three beats:
           - ALLOW : read /workspace/README.md            (baseline allow)
           - REVIEW: read /workspace/secret.env           (YOUR overlay tightens
                     an otherwise-identical read to review -> proof the policy is
                     in force on the MCP path, attributed as dictum[...])
           - BLOCK : rm -rf on the DB                      (baseline block)
       Every beat lands in the shared DB, so it is visible in the dashboard.

    The key thing this proves that the old procedure did NOT: passing --policy to
    BOTH `serve` and `mcp-server` is what makes your authored policy actually
    decide the MCP verdict. `mcp-server` shares the database with `serve` but not
    its in-memory overlay, so without --policy the MCP verdict ignores your rules.

.PARAMETER Build   Force a release rebuild even if the binary exists.
.PARAMETER Port    Port the dashboard binds (default 4010).
.PARAMETER KeepServer  Leave the server running after the run (default: stop it).

.EXAMPLE
    .\scripts\agent_bootstrap.ps1 -Build
#>
[CmdletBinding()]
param(
    [switch]$Build,
    [int]$Port = 4010,
    [switch]$KeepServer
)

$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$IagaExe    = Join-Path $RepoRoot 'target\release\iaga.exe'
$PolicyFile = Join-Path $RepoRoot 'agent_rules.dictum'
$SharedDb   = Join-Path $RepoRoot 'iaga_shared.db'
$DbUrl      = 'sqlite:iaga_shared.db?mode=rwc'
# Probe over 127.0.0.1 (explicit IPv4): the server binds 0.0.0.0, and WinPS 5.1
# Invoke-RestMethod may resolve `localhost` to ::1 first and never fall back.
$HealthUrl  = "http://127.0.0.1:$Port/health"
$OverlayUrl = "http://127.0.0.1:$Port/v1/policy/overlay"
$Dashboard  = "http://localhost:$Port/"

function Write-Rule {
    param([string]$Text, [string]$Color = 'Cyan')
    Write-Host ''
    Write-Host ('=' * 64) -ForegroundColor $Color
    Write-Host ("  " + $Text) -ForegroundColor $Color
    Write-Host ('=' * 64) -ForegroundColor $Color
    Write-Host ''
}

Write-Rule 'IAGA SENTINEL  -  AGENT SELF-BOOTSTRAP (MCP self-connect)' 'Green'

# 1. Resolve/build the binary (the Standing procedure must not assume PATH).
if ($Build -or -not (Test-Path $IagaExe)) {
    Write-Rule 'Building release binary (CARGO_INCREMENTAL=0)' 'Yellow'
    $env:CARGO_INCREMENTAL = '0'
    & cargo build --release -p iaga-sentinel-core
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed ($LASTEXITCODE)" }
}
if (-not (Test-Path $IagaExe)) { throw "iaga.exe not found at $IagaExe" }
Write-Host ("Binary  : {0}" -f $IagaExe) -ForegroundColor DarkGray

# 2. Fresh shared DB: per-agent trust persists + re-hydrates, so a clean DB is
#    the only way to get identical verdicts. (Weights-reset alone is not enough.)
Remove-Item $SharedDb, ($SharedDb + '-wal'), ($SharedDb + '-shm') -ErrorAction SilentlyContinue
Write-Host 'DB      : fresh iaga_shared.db (deterministic seed + trust)' -ForegroundColor DarkGray

# 3. Encode the agent's instructions as enforced Dictum policy.
$policy = @'
// agent_rules.dictum - my operating instructions, encoded as ENFORCED policy.
// Loaded by BOTH `iaga serve --policy` and `iaga mcp-server --policy`.

// "Never destroy production data."
policy "never_destroy_production_data" {
  when action.kind == "shell" and risk.score > 50
  then block, reason="destructive shell is outside my mandate"
}

// "Never send raw credentials to a host we haven't approved."
// NOTE: secret_ref() detects RAW credential material (AWS keys, PEM blocks),
// NOT secretref:// references. See AGENTS.md secret_ref vs secretref://.
//
// ORDER MATTERS: secret_ref() comes FIRST on purpose.
// url_host() reads `destination` and only `destination`; on a payload naming its
// target url/uri/endpoint/href/target/webhook it ERRORS, and an erroring `when`
// on a block rule fires FAIL-CLOSED (reason `dictum-eval-error`). `and`
// short-circuits, so testing for a credential first means an ordinary call with
// no secret never reaches url_host() and is not refused for a rule it does not
// violate. A payload that DOES carry a secret still evaluates url_host(), so an
// alias there still fails closed -- the protection is unchanged, the false
// refusal is gone. Host-check the other key names on the WORKSPACE policy
// (destinationFields on the tool), which applies the allowlist to all of them.
policy "no_secret_egress_off_allowlist" {
  when action.kind == "http"
   and secret_ref(action.payload)
   and url_host(action.payload.destination) not in workspace.allowlist
  then block, reason="credentials must not leave approved hosts",
       evidence=action.payload.destination
}

// "Ask me before you modify any file."
policy "human_approves_file_writes" {
  when action.kind == "file_write"
  then review, reason="a human confirms every file modification"
}

// Demonstrable rule: reading a sensitive file needs human review. A plain
// README read stays ALLOW, so a REVIEW on secret.env proves THIS overlay is
// what decided the MCP verdict (attributed as dictum[human_reviews_sensitive_reads]).
policy "human_reviews_sensitive_reads" {
  when action.kind == "file_read" and action.payload.path == "/workspace/secret.env"
  then review, reason="a human reviews access to sensitive files"
}
'@
# Write UTF-8 WITHOUT a BOM: `Set-Content -Encoding utf8` on PS 5.1 prepends a
# BOM that the .dictum lexer would choke on.
[System.IO.File]::WriteAllText($PolicyFile, $policy, (New-Object System.Text.UTF8Encoding($false)))
Write-Host ("Policy  : wrote {0} (4 rules)" -f (Split-Path -Leaf $PolicyFile)) -ForegroundColor DarkGray

Write-Host '> iaga policy lint / check' -ForegroundColor Cyan
& $IagaExe policy lint  $PolicyFile;  if ($LASTEXITCODE -ne 0) { throw "policy lint failed" }
& $IagaExe policy check $PolicyFile;  if ($LASTEXITCODE -ne 0) { throw "policy check failed" }

# 4. Serve with the overlay on the shared DB.
# Bind to loopback explicitly: open mode makes every unauthenticated caller
# an implicit ADMIN, and the server's own default host is 0.0.0.0.
$env:IAGA_SENTINEL_HOST      = '127.0.0.1'
$env:IAGA_SENTINEL_OPEN_MODE = 'true'
$env:DATABASE_URL            = $DbUrl
Write-Host ''
Write-Host 'Starting dashboard server (iaga serve --policy) ...' -ForegroundColor Cyan
$srv = Start-Process -FilePath $IagaExe `
        -ArgumentList 'serve', '--seed-demo', '--port', "$Port", '--policy', $PolicyFile `
        -WorkingDirectory $RepoRoot -PassThru -NoNewWindow

$ready = $false
for ($i = 0; $i -lt 60; $i++) {
    try { if ((Invoke-RestMethod -Uri $HealthUrl -TimeoutSec 2).ok) { $ready = $true; break } }
    catch { Start-Sleep -Milliseconds 500 }
}
if (-not $ready) {
    if (-not $srv.HasExited) { Stop-Process -Id $srv.Id -Force -ErrorAction SilentlyContinue }
    throw 'server did not become healthy'
}

$overlay = Invoke-RestMethod -Uri $OverlayUrl -TimeoutSec 5
if (-not $overlay.loaded) { throw 'overlay did not load on serve' }
Write-Host ("Overlay : loaded={0} policies={1} hash={2}" -f $overlay.loaded, $overlay.policyCount, $overlay.policyHash.Substring(0,12)) -ForegroundColor Green

# 5. Self-connect over MCP (SAME --policy) and drive three beats over stdio.
function Invoke-McpBeats {
    param([string[]]$Requests)
    $env:DATABASE_URL = $DbUrl
    $inFile  = Join-Path $env:TEMP ("iaga_mcp_in_{0}.jsonl"  -f $PID)
    $outFile = Join-Path $env:TEMP ("iaga_mcp_out_{0}.jsonl" -f $PID)
    # One JSON-RPC message per line, LF-only, no BOM. Redirect stdin from a file
    # so `mcp-server` gets a clean EOF and exits (a PowerShell string-pipe does
    # not reliably close stdin, which hangs the server on read).
    [System.IO.File]::WriteAllText($inFile, (($Requests -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))
    Start-Process -FilePath $IagaExe -ArgumentList 'mcp-server', '--policy', $PolicyFile `
        -WorkingDirectory $RepoRoot -NoNewWindow -Wait `
        -RedirectStandardInput $inFile -RedirectStandardOutput $outFile | Out-Null
    $byId = @{}
    foreach ($line in (Get-Content $outFile)) {
        $t = "$line".Trim()
        if ($t.StartsWith('{')) {
            try { $o = $t | ConvertFrom-Json; if ($null -ne $o.id) { $byId[[int]$o.id] = $o } } catch {}
        }
    }
    Remove-Item $inFile, $outFile -ErrorAction SilentlyContinue
    return $byId
}

$init = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"agent","version":"1.0"}}}'
function New-Inspect {
    param([int]$Id, [string]$Type, [string]$Tool, $Payload)
    $args = @{ agentId='openclaw-builder-01'; workspaceId='ws-demo'; framework='openclaw'; protocol='mcp';
               action=@{ type=$Type; toolName=$Tool; payload=$Payload }; metadata=@{ sessionId='agent-bootstrap' } }
    $params = @{ name='iaga.inspect'; arguments=$args }
    return (@{ jsonrpc='2.0'; id=$Id; method='tools/call'; params=$params } | ConvertTo-Json -Depth 12 -Compress)
}

$beat1 = New-Inspect 2 'file_read'  'filesystem.read' @{ path='/workspace/README.md'; intent='inspect repository documentation' }
$beat2 = New-Inspect 3 'file_read'  'filesystem.read' @{ path='/workspace/secret.env'; intent='inspect configuration' }
$beat3 = New-Inspect 4 'shell'      'terminal.exec'   @{ command='rm -rf /var/lib/postgresql/data'; intent='cleanup old data' }

$byId = Invoke-McpBeats @($init, $beat1, $beat2, $beat3)

function Show-Beat {
    param([string]$Label, $Resp, [string]$Expect)
    $sc = $Resp.result.structuredContent
    $decision = "$($sc.decision)"
    $score = [int]$sc.risk.score
    $dictum = @($sc.auditEvent.reasons | Where-Object { "$_".StartsWith('dictum[') })
    $ok = ($decision -eq $Expect)
    $color = if ($ok) { 'Green' } else { 'Red' }
    Write-Host ("  {0,-34} -> {1,-6} risk={2,-3} {3}" -f $Label, $decision.ToUpper(), $score, ($(if ($dictum) { "[$($dictum -join '; ')]" } else { '' }))) -ForegroundColor $color
    return $ok
}

Write-Rule 'MCP SELF-CONNECT  -  three governed beats (overlay IN FORCE)' 'Magenta'
$allOk = $true
$allOk = (Show-Beat 'read README.md            (allow)' $byId[2] 'allow')  -and $allOk
$allOk = (Show-Beat 'read secret.env  (MY POLICY->review)' $byId[3] 'review') -and $allOk
$allOk = (Show-Beat 'rm -rf DB                 (block)' $byId[4] 'block')  -and $allOk

# Assert the REVIEW on secret.env is attributed to the agent's OWN rule.
$b2reasons = @($byId[3].result.structuredContent.auditEvent.reasons)
$attributed = $b2reasons | Where-Object { "$_".Contains('dictum[human_reviews_sensitive_reads]') }
if (-not $attributed) { $allOk = $false; Write-Host '  MISSING dictum[human_reviews_sensitive_reads] attribution' -ForegroundColor Red }

Write-Host ''
if ($allOk) {
    Write-Rule 'PASS  -  your policy governs your MCP calls (visible in the dashboard)' 'Green'
    Write-Host ("  Dashboard : {0}" -f $Dashboard) -ForegroundColor White
    Write-Host '  The README read is ALLOW; the identical read of secret.env is REVIEW purely' -ForegroundColor Green
    Write-Host '  because of your policy (dictum[human_reviews_sensitive_reads]); rm -rf is BLOCK.' -ForegroundColor Green
} else {
    Write-Rule 'FAIL  -  verdicts did not match (see red lines above)' 'Red'
}

if (-not $KeepServer) {
    if (-not $srv.HasExited) { Stop-Process -Id $srv.Id -Force -ErrorAction SilentlyContinue }
    Write-Host 'Server  : stopped (pass -KeepServer to leave it running for the dashboard).' -ForegroundColor DarkGray
} else {
    Write-Host ("Server  : left running (PID {0}). Open {1}" -f $srv.Id, $Dashboard) -ForegroundColor DarkGray
}

if (-not $allOk) { exit 1 }
