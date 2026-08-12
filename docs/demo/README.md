# IAGA Sentinel - Demo Recording Kit

A reproducible, nothing-faked demo: three real verdicts (Allow -> Review ->
Block) from the live enforcement pipeline, chained into **one signed session**,
then proven offline with `iaga-verify`. Same verdicts every run.

> Primary platform: **Windows 11 + PowerShell 5.1** + Windows Terminal.
> Bash equivalents are in the appendix for Linux/macOS.

## What the audience sees

1. A live dashboard streaming each governed action into the **Live feed** as it
   happens (Server-Sent Events, no refresh).
2. A terminal driving three real requests, each with a big colour verdict.
3. The money shot: one exported `chain.json` verified with **no server, no DB,
   no network** - just the file and a public key - whose terminal receipt
   attests the **Block**.

## How it works (so nothing is faked)

- `scripts\demo.ps1` builds the real binaries, wipes the demo DB for an
  identical seed, and runs `iaga serve --seed-demo` on `http://localhost:4010`.
- `scripts\demo_run.ps1` fetches the real seeded scenarios from
  `GET /v1/demo/scenarios`, injects a shared `sessionId`, and POSTs each to
  `POST /v1/inspect` - the same endpoint the product uses for live governance.
  Every verdict is the pipeline's real output; the driver only **asserts** them.
- Because all three beats share one `sessionId`, their Ed25519 receipts form one
  hash-chained run. `iaga replay --export` writes that run to `chain.json` and
  `iaga-verify` checks the signatures and chain links offline.

## Prerequisites (once)

- Rust toolchain. The launcher builds `iaga.exe` + `iaga-verify.exe` if missing.
- **Windows Terminal** (renders the ANSI colour banners; the legacy console host
  may not).
- The receipt signer key at
  `%USERPROFILE%\.iaga-sentinel\keys\receipt_signer.ed25519` is created on first
  run and **kept** across retakes so the pinned public key stays identical. Do
  not delete it.

## Window layout (two panes + browser)

```
+-----------------------------+    Pane A (left/top):  scripts\demo.ps1     (server + logs)
|  Browser: the dashboard     |    Pane B (right/bot): scripts\demo_run.ps1 (live driver)
|  http://localhost:4010/     |
|  -> click the "Live feed"   |    Recommended framings:
|     tab, leave it visible   |      - Side by side: browser ~60%, terminal ~40%
+-----------------------------+      - Dashboard hero: browser full screen on
                                       "Live feed", driver terminal as a small
                                       always-on-top overlay; cut to the terminal
                                       for the money shot.
```

## Command order

**Pane A - start the server (foreground, logs visible):**

```powershell
cd path\to\IAGA-Sentinel
.\scripts\demo.ps1
```

Wait for the green **READY** banner and the `DASHBOARD -> http://localhost:4010/`
line. (First run: add `-Build` to force the release build.)

**Browser:** open `http://localhost:4010/`, click the **Live feed** tab, and
leave it visible. (Optional: open a second browser tab on the **Receipts**
view — the signed receipts — for the finale.)

**Pane B - run the live driver:**

```powershell
cd path\to\IAGA-Sentinel
.\scripts\demo_run.ps1
```

The driver pauses ~5s between beats (`-PauseSec` to change) so each verdict lands
on camera, and prints `ALLOW`, `REVIEW`, `BLOCK` in colour as the matching rows
appear in the dashboard Live feed.

## Shot list, captions, and timing (target 75-100s)

| t (s) | On screen | Caption / voiceover |
|------:|-----------|---------------------|
| 0-8   | Dashboard Live feed idle; Pane A shows READY | "One agent, one session. Every action is governed and signed." |
| 8-20  | **Beat 1** banner, ALLOW (green); a green row appears in Live feed | "A safe repository read. Low risk. Allowed - and recorded." |
| 20-40 | **Beat 2** banner, REVIEW (amber); amber row in Live feed; `reviewRequestId` printed | "A shell command needs a production secret. Sentinel holds it for human review." |
| 40-58 | **Beat 3** banner, BLOCK (red); red row in Live feed | "`rm -rf` on the database. Sentinel returns a block verdict and signs the receipt that proves it." |
| 58-62 | Cut to the terminal; optionally click the **Receipts** tab | "Three verdicts. Now the proof." |
| 62-85 | `iaga replay --export`, then `iaga-verify` (embedded), then `--key … --expect-count 3` | "Export the signed chain. Verify it offline - no server, no database, just this file and a public key. CHAIN OK, and it is the chain we drove: three receipts, no more." |
| 85-95 | Final green **CHAIN OK** banner | "Deterministic. Tamper-evident. Cryptographic evidence." |

### What to point at in the dashboard

- **Live feed** - one row per verdict as it happens (decision badge, agent, tool,
  risk score). This is the hero panel during beats 1-3.
- **Receipts** - the signed receipts; show it after the Block to tie the on-screen
  verdicts to durable signed receipts.
- (Optional) **Audit** - the audit explorer, if you want to show the recorded
  event detail.

## Clean retake (one line)

Stop Pane A with `Ctrl+C`, then re-run the launcher - it wipes the DB and
re-seeds:

```powershell
.\scripts\demo.ps1
```

For a hard manual reset:

```powershell
Remove-Item .\iaga_sentinel.db,.\iaga_sentinel.db-wal,.\iaga_sentinel.db-shm,.\chain.json -ErrorAction SilentlyContinue
```

> **Stop the server first, and start a new one afterwards — deleting the database
> is not enough.** The session graph lives in the process, not in the database, so
> a server that stays up keeps every node the previous take added. Two distinct
> things go wrong, one take apart, and only the second one is loud:
>
> - **Second run against the same live server — the dangerous one.** Measured: all
>   three verdicts are still ALLOW 2 / REVIEW 40 / BLOCK 81, so every verdict
>   assertion passes. Beats 2 and 3 pick up an extra reason
>   `session graph attack: privilege_escalation_chain` without changing the
>   verdict. But the run_id is `<agentId>:<sessionId>` and the `sessionId` is
>   fixed, so the second take **chains onto the first**: `iaga replay --export`
>   comes back with **6 receipts**, not 3, and `iaga-verify` still prints
>   `CHAIN OK` — a longer valid chain verifies exactly like a correct one. That
>   is why the driver anchors the offline proof with
>   `iaga-verify --key <pub> --expect-count 3`: the count is the only thing that
>   distinguishes the chain you drove from the chain that accumulated. Without it
>   the take ends on a green `CHAIN OK` over the wrong chain.
> - **Third run.** Beat 1 finally flips to **REVIEW risk 35** with
>   `session graph attack: privilege_escalation_chain`, and the verdict assertion
>   refuses the take. That is the system working; it is not a flaky verdict.
>
> Both are why the relaunch path above exists.

> Keep `%USERPROFILE%\.iaga-sentinel\keys\receipt_signer.ed25519` so the pinned
> public key stays identical across takes.

## Determinism notes

- A fresh server starts with default adaptive risk weights, and the driver also
  POSTs `/v1/risk/weights/reset` once at the start. The driver never sends
  `/v1/risk/feedback`. So the verdicts are identical **on every run against a
  freshly started server** — which is the qualification that matters: the weights
  reset covers the adaptive scorer, and nothing resets the in-process session
  graph or the per-agent NHI trust, both of which move a verdict. One take per
  server process; restart between takes (see "hard manual reset" above).
- The driver **asserts** each verdict. If any beat does not match
  Allow/Review/Block it prints a red **STOP** banner and exits non-zero - never
  record a take that failed assertions.
- The receipt body carries a wall-clock timestamp, so `chain.json` is freshly
  signed each run (its bytes differ) - but the verdicts are identical and
  `iaga-verify` always returns **CHAIN OK**.

## Recording on Windows

- **Best quality (video):** OBS Studio. Add a *Window Capture* of the browser and
  a *Window Capture* (or Display Capture) of Windows Terminal; 1080p / 30 fps.
  Use a start/stop hotkey so your cursor stays on the content.
- **Quick GIF:** ScreenToGif - record the region covering dashboard + terminal,
  trim, export GIF or MP4.
- **asciinema:** terminal-only and Unix-oriented; on Windows run it inside WSL
  against the bash variant. Not ideal here because the dashboard is half the
  story.
- Use **Windows Terminal**, not the legacy console host - the verdict banners and
  the server startup banner use 24-bit ANSI colour.

## Appendix - Linux / macOS (bash)

```bash
# Pane A: build (first run) + serve
./scripts/demo.sh --build        # omit --build on retakes

# Pane B: drive the demo (needs curl + jq)
./scripts/demo_run.sh

# One-line reset for retakes
rm -f iaga_sentinel.db iaga_sentinel.db-wal iaga_sentinel.db-shm chain.json
```

Same flow as Windows: reset weights, drive three beats with a fixed `sessionId`,
assert each verdict, then `iaga replay --export` + `iaga-verify` (embedded, then
with the key stated and `--expect-count`).

> **What the second `iaga-verify` call proves, and what it does not.** Both
> drivers read the key out of `chain.json` itself, so passing it back with
> `--key` only silences the self-asserted warning — it cannot authenticate
> authorship, because anyone who re-signed the chain would have supplied their
> own key there too. To authenticate authorship, pin a key you obtained out of
> band. `--expect-count` IS an external anchor: it comes from what the driver
> drove, not from the file, which is why it catches a chain that grew.
