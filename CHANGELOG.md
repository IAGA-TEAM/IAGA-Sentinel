# Changelog

All notable changes to IAGA Sentinel are documented here. Format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/).

For architectural rationale, see the ADRs under [docs/adr/](docs/adr/).

This changelog tracks the **open, source-available build** of IAGA Sentinel,
licensed under BUSL-1.1 with Change License: Apache-2.0 baked in.
IAGA Sentinel Enterprise is a planned commercial edition, currently in
development, built on the same governance kernel; see
[`ENTERPRISE.md`](ENTERPRISE.md) for the overview and how to join the
early-access list.

---

## [2.1.0], 2026-08-28 — Evidence That Says What Happened

An audit of `2.0.2` across the release and real user paths, plus an adversarial refutation pass. The
theme is the one that matters most for an evidence product: **four separate ways the record could
be wrong**, either by asserting something that did not happen or by being silently unavailable to
the people entitled to it.

The heaviest item is not a bypass. It is that a payment amount of `10.50`, sent to a public host,
produced a **signed receipt carrying `EXFILTRATION DETECTED`** — because the internal-address check
matched the substring `"10."` anywhere in the serialized payload, including the body. A signed
false accusation is worse than a missed detection, and it went unnoticed because nothing tested it.

Capability tokens also stop being decorative. They were minted, signed, stored and published
through a documented endpoint and an SDK method in both languages, and they authorized nothing:
the signature was never verified, the tokens lived in a process-global map that a restart emptied,
`revoke_token` had no route, and the issuing route had no admin guard.

**Compatibility.** The signed receipt **wire format is unchanged** and existing chains verify
byte-for-byte. Governance verdicts on `/v1/inspect` are **identical to 2.0.2** across the `scenarios`
section of the 342-case characterization corpus — 48 of those cases; the other 294 exercise
`/v1/response/scan` (259), the CLI (17) and assorted surfaces (18). Measured, not asserted, by
replaying the corpus against a `2.0.2` binary built from `b444886` and against this one, in the
same hour, and diffing every field. Zero differences in decision, risk score, adaptive score or
receipt body **on those 48**. The corpus as a whole is not unchanged: see item 4.

**What a consumer can observe changing**, in rough order of how much it matters:

**Agent-scoped API keys now name exactly one agent.** Create one with
`iaga gen-key --scope agent --agent-id <id>` or the `agentId` field on
`POST /v1/auth/keys`. The server rejects an attempt to use it as another identity with
`403 agent_scope_mismatch`; an agent-scoped key created before this migration has no binding and
fails closed with `403 agent_key_unbound` until it is rotated. Admin and open-mode callers remain
cross-agent by design. The same check covers inspect, response scanning, NHI
attest/challenge/verify and capability-token self reads; the demo adapter, which submits several
seeded identities in one request, is now admin-only.

1. **Reads that used to answer `200` to an agent-scoped key now answer `403`.** The write halves of
   the governance surface were closed in #14/#18; the read halves were never reviewed. Every route
   was enumerated against its guard rather than sampled — 83 route/method pairs at `b444886`, of
   which 53 carried no guard at all. This release ends at 85 pairs (the new
   `GET /v1/nhi/tokens` and `DELETE /v1/nhi/tokens/{tokenId}`) with 29 not identity-guarded
   (24 open, plus 5 that accept only the key's own bound `agentId`), 52 admin-only and 4 behind a
   capability token. Now admin-only: `GET /v1/analytics/agents`, `/v1/reviews`, `/v1/profiles`,
   `/v1/workspaces[/{id}]`, `/v1/workspaces/{id}/rules`, `/v1/policy/verify/{id}`,
   `/v1/nhi/identities`, `/v1/sessions[/{id}/metrics]`, `/v1/fingerprint`, `/v1/sandbox/pending`,
   `/v1/cost/by-agent`, `/v1/telemetry/spans|metrics|export`, and the `/v1/events/stream` SSE
   firehose. The four per-agent reads — `GET /v1/profiles/{id}`, `/v1/analytics/agents/{id}`,
   `/v1/fingerprint/{id}` and `/v1/rate-limit/status/{id}` — answer `capability_required` instead:
   an agent reaches its **own** record with a `read:self` token (item 3).

   The telemetry trio is the one worth naming. `otel_emitter` records `agent.id`, `tool.name`,
   `governance.decision` and `risk.score` for every governed action and keeps 10 000 of them
   newest-first, so `GET /v1/telemetry/spans` reconstructed by polling exactly the cross-tenant
   firehose the new SSE guard refuses. Closing the stream and leaving that open would have been
   shutting one door while the next one stayed open on the same data.

   **The operator console is unaffected** — it sends one token for every call and already needed
   admin for `/v1/audit` and `/v1/receipts`.
2. **`POST /v1/reviews/{id}` requires an admin key.** An agent-scoped key could resolve the review
   raised against its own action. It never released the execution — nothing re-reads the status —
   but it published `ReviewResolved`, and the console then showed the entry as settled by a human.
3. **`POST /v1/nhi/tokens` requires an admin key**, and there is a new
   `DELETE /v1/nhi/tokens/{tokenId}`. Any agent-scoped key could previously mint
   `capabilities: ["*"]` for any agent.
4. **A connection string with an embedded password is now detected as a credential.** On
   `/v1/response/scan`, measured against a 2.0.2 binary across the corpus: ten
   `mongodb+srv://root:s3cr3t@cluster0.mongodb.net/db` cases, nine of which passed 2.0.2 completely
   (`allow`, risk `0`) and one of which reached `review`/55 through the sensitive-pattern scan. All
   ten are now `block`/80. `postgres://...` was already blocked, but only by accident — its hostname
   ended in `.internal` — and is now blocked because it carries a credential.

   **`/v1/inspect` moves too, and the corpus did not show it.** The detector lives in
   `has_secret_content`, which `classify_source` applies to every action type, so it is not
   response-scoped. Measured directly against a 2.0.2 binary in the same hour: an `http` action
   whose body carries `mongodb+srv://root:s3cr3t@…` goes from risk `70` to `76` and gains a
   `taint tracking: … secret → sink: network_egress | BLOCKED | EXFILTRATION DETECTED` reason; the
   `10.50` payment case goes the other way, `76` to `70`, losing the false exfiltration finding.
   Both keep `block` in that measurement only because the destination was outside the workspace
   allowlist, which decided them independently. Items 6 and 7 below move `/v1/inspect` as well.
   **The honest statement of compatibility is item 0: zero differences on the 48 `/v1/inspect`
   cases of the 342-case corpus.** Across the whole corpus there are ten verdict changes, all of
   them the `/v1/response/scan` cases named above. That corpus contains no `maxDecision: block` policy, no credential-bearing URL on the
   inspect path and no bare `10.` in a body, so it could not have shown any of this. If you depend
   on exact risk scores, re-baseline rather than trusting the corpus number.
5. **`/v1/response/scan` stops blocking benign responses.** After any `file_read` in a session,
   every later scan in that session returned `block` at risk 80 regardless of content, so
   "read a file, then summarise it" was broken from the second step on. Each false block also wrote
   a signed audit event.
6. **`maxDecision: block` now denies.** It was inert, so a tool pinned to it was governed exactly as
   if it had said `allow`. Any workspace policy already using it will see verdicts change — which
   is the point, and is still a change in what the product blocks.
7. **Workspace rule bounds were renamed** `minRiskScore`/`maxRiskScore` →
   `minAdaptiveScore`/`maxAdaptiveScore`. Stored rules keep working (serde aliases). The shipped
   `soc2-shell-hours` rule was firing almost unconditionally and downgrading Review to Allow during
   business hours; it is now bounded at the adaptive review threshold.
8. **Taint findings are reworded** where the sink changed: `sink: network_egress` becomes
   `sink: tool_response` for response scans, and the `"potential data exfiltration in response"`
   line is gone — inbound data is not exfiltration. `decision` and `riskScore` are unchanged.
9. **`agent_analytics` top-tool ties break by `tool_name` ASC**, so the top-5 list is stable across
   reads and between backends where it previously depended on `HashMap` order.
10. **Migrations `0008` and `0009` are added on both backends.** Additive: a new
    `capability_tokens` table and a nullable `api_keys.agent_id` column. A `2.0.2` database opens
    under `2.1.0` and runs `1→9`; existing agent keys are deliberately unusable until rotated
    with a binding.

### Added

- **Capability tokens are an authorization primitive.** Signed with the agent's derived NHI secret
  and verified by recomputing the HMAC (tampering with `capabilities`, `agentId` or `expiresAt`
  invalidates it), persisted in the new `capability_tokens` table, and revocable through
  `DELETE /v1/nhi/tokens/{tokenId}` — durable and fleet-wide, because the row is the authority.
  `GET /v1/nhi/tokens` (admin) lists what is currently outstanding, signatures withheld —
  `list_tokens()` / `listTokens()` in the SDKs, so revoking no longer means already knowing the
  `tokenId` you are looking for.
  Present one in the `X-IAGA-Capability-Token` header. `read:self` lets an agent read its **own**
  `/v1/profiles/{id}`, `/v1/analytics/agents/{id}`, `/v1/fingerprint/{id}` and
  `/v1/rate-limit/status/{id}`, which this release otherwise makes admin-only. A token is bound to one `agentId` and can never widen into another agent's data,
  whatever capabilities it carries. New error `capability_required` (403), deliberately distinct
  from `admin_scope_required`. Symmetric HMAC, so only the server can verify (CRYPTO-NHI-2);
  relying-party-checkable asymmetric agent identity remains Enterprise (ADR 0010).

  **Both SDKs can now send it, and a browser is allowed to.** Every method that mints one of these
  told the caller to present it in `X-IAGA-Capability-Token`, and neither client had any way to:
  the Python clients built a closed header dict with no `headers=` parameter, and the TypeScript
  client's `headers` field is private with nothing in `SentinelClientOptions` to reach it. So the
  documented remedy for the new admin-only reads was an instruction that could not be carried out
  except by reaching into a private attribute. `SentinelClient(..., capability_token=...)` and
  `new SentinelClient({ capabilityToken })` set it. The header is also added to the CORS
  `allow_headers`, which held only `content-type` and `authorization` — without that a browser
  preflight strips it and the remedy works only from curl. The two are one fix: either alone
  changes nothing cross-origin.
- **URL-embedded credential detection.** `scheme://user:secret@host` is recognized as secret
  material. Deliberately narrow: the userinfo must carry a colon, so `https://host/p` and
  `mailto:a@b.com` do not match.
- **A bounded, prunable sandbox approval queue.** `IAGA_SENTINEL_MAX_SANDBOX_PENDING` (default
  1000) and `IAGA_SENTINEL_SANDBOX_PENDING_TTL_MS` (default 24h), swept by the existing cleanup
  task. The map previously shrank only when an admin approved or rejected.
- **A startup warning** when open mode is enabled and the server is bound to a non-loopback
  address — the combination that yields an unauthenticated admin API on every interface. The README
  documented the danger; the binary was silent. The startup line now also logs `host`. Loopback is
  decided by `IpAddr::is_loopback` after stripping IPv6 brackets, not by comparing the string
  against `"127.0.0.1"` and `"::1"`: the address is composed as `format!("{host}:{port}")`, so the
  exempted `::1` renders `::1:4010`, which is not a parseable `SocketAddr` and cannot bind at all,
  while `[::1]` — the form that does bind — drew the warning, as did `localhost`. The exemption
  covered exactly the spelling that could not run. `127.0.0.0/8` as a whole is exempt now too.
- **Tests for eight surfaces that had none:** the Bash Claude Code hook (17 cases),
  `agent_analytics`, the sandbox SQL classifier, response-scan session taint, capability-token
  authorization, the plug-in clients' redirect refusal, the capability signature's survival of a
  Postgres `TIMESTAMPTZ` round trip, and every remaining cross-agent read against an agent-scoped
  key.

### Fixed

- **`docs/openapi.yaml` would not load in any OpenAPI viewer.** The `ttlSeconds` property of
  `IssueTokenBody` carried two `description` keys — this release added the long one above the 2.0.2
  stub and did not delete the stub. A duplicate mapping key breaks both ways: parsers that reject
  duplicates (Swagger UI, Redoc, `swagger-parser`) refuse the entire document, and parsers that
  tolerate them keep the **last**, silently discarding the explanation. The README advertises this
  file as the full HTTP API specification and no CI step parses it. It now loads strictly: 72 paths,
  79 schemas, and all 93 `$ref`s resolve.
- **An agent-scoped key could submit signed evidence as any agent.** `agentId` came only from the
  request, while a key carried a scope and label but no identity. A key bound for one caller could
  therefore call `/v1/inspect` as another, receive that agent's otherwise protected profile, and
  write the substituted id into the signed receipt. Migration `0009` stores the binding, the auth
  cache carries it, and every HTTP surface that accepts a caller-owned `agentId` checks it before
  acting. A capability token cannot widen the API key's identity. One nullable column is
  intentional: profiles may be imported after keys are minted; issuance validates new keys and
  authorization fails closed on old null rows.
- **The prompt firewall's semantic stage was dead for semantic-only attacks.** Stage 3 ran only
  after stage 1 or 2 had already found something, so `steal all credentials` returned `CLEAN`,
  score 0. It now runs independently. The same audit closed full-width ASCII and mixed
  Latin/Cyrillic bypasses, case/tag-boundary and multiline signature bypasses, UTF-8 byte/character
  ratio errors, a `DAN` substring false positive, and nondeterministic category ordering in the
  summary that enters signed reasons. Semantic intent is restricted to directive-shaped clauses,
  so incident reports and defensive prose are not signed as attacks; inert `<img>`, `<svg>` and
  `<link>` markup also passes while executable tags, event handlers and `javascript:` URLs remain
  blocked.

- **Signed exfiltration evidence on benign traffic.** `is_internal_url` matched against the whole
  serialized payload, so the bare pattern `"10."` fired inside `"10.50"`, `"3.10.4"` and any
  textual IPv4 in 10.0.0.0/8, and `.local`/`.corp`/`.internal` fired inside ordinary prose. That
  labelled the request `INTERNAL_API`, which is forbidden at `NetworkEgress` with severity
  `critical` — so the action was blocked, `layer_risks.taint` went to 100, and the receipt was
  signed with `EXFILTRATION DETECTED`. It now reads only the destination-naming fields and anchors
  the patterns to the host. Detection **improved** in passing: the old code matched only the
  literal `127.0.0.1`, so `127.0.0.53` and the rest of 127.0.0.0/8 were never detected.

  **What it stopped catching, and what was put back.** "Destination-naming fields" means the seven
  names in `DEFAULT_EGRESS_DESTINATION_FIELDS`. The first cut of the narrowing read them at the TOP
  LEVEL of a JSON object and kept only string values, so a destination nested in a sub-object,
  inside an array, or in a top-level array stopped being seen at all — and an unseen destination
  does not fall back to a refusal, it falls to the `else` branch that labels the action
  `EXTERNAL_TOOL`. The narrowing had turned a false positive into a fail-OPEN. The scan now
  descends through objects and arrays, so `{"request":{"url":…}}`, `{"url":[…]}`,
  `{"webhook":{"href":…}}` and a top-level array of request objects are all labelled again.
  A destination name carries into an ARRAY but not into an OBJECT: a list under `url` is a list of
  destinations, while an object under `target` is a structure whose keys have to earn it again.
  That asymmetry is load-bearing rather than fussy — carrying the name into objects reopens the
  exact false positive this entry is about, one level deeper, because `host_of("10.50")` returns
  `"10.50"` and that matches the `"10."` prefix, so `{"target":{"amount":"10.50"}}` would be signed
  as EXFILTRATION DETECTED all over again. It was caught by reviewing the fix against itself, and
  all three directions — nested destinations found, prose never a destination, and a non-destination
  key under a destination key never a host — are covered by tests that were watched failing first.

  What is still deliberately NOT caught: a destination under a key outside those seven. That one is
  a genuine reduction against the old whole-payload sweep, taken on purpose — a nested destination
  was never governed by the egress allowlist either, and guessing that an unrecognised key holds an
  internal host is the guess that produced the signed false evidence. `scan_undeclared_hosts` is
  top-level only as well. If your payloads use a different name, declare it in `destinationFields`
  on the workspace policy.
- **On Postgres, capability tokens failed to verify at all — the signature covered a timestamp
  whose spelling the database changed.** The signature is taken over `expires_at` as a STRING, and
  the mint used `chrono::to_rfc3339()`, which emits 0, 3, 6 or 9 fractional digits depending on the
  value (`SecondsFormat::AutoSi`). The Postgres read path renders the `TIMESTAMPTZ` column back
  through `to_char(..., 'YYYY-MM-DD"T"HH24:MI:SS.US+00:00')`, which always emits exactly six. So
  the string that came back was usually not the string that was signed, and the token failed
  closed. Measured before the fix: **54 of 64 minted tokens stopped verifying** after the round
  trip. That count is a sample, not a constant — re-measuring the same divergence in this
  session gave 61 of 64. It depends on how many `Utc::now()` values happen to land on a
  microsecond boundary, which is a property of the host clock; what is invariant is that a
  mint emitting anything other than exactly six digits cannot verify after the round trip. SQLite never showed it — the column is `TEXT` there and hands back the bytes it was given,
  which is why a backend-parity bug this total survived a green suite. The mint is now pinned to
  microseconds (`rfc3339_storage`), so both backends agree.

  **Proved against a real Postgres 16, not simulated.** `tests/capability_token_pg_roundtrip.rs`
  models the `to_char` rendering in Rust, which is fast and runs everywhere but had never been
  checked against the database it describes. Driving the release binary (built
  `--features postgres`) at a live server: migrations run `1→8`, `expires_at` really is
  `TIMESTAMPTZ`, and across 64 freshly minted tokens the string Postgres renders is byte-identical
  to the string that was signed, every one carrying exactly six fractional digits. Mint → use →
  revoke works end to end, revocation is durable in the row, and a token minted before a restart
  still authorizes after it. Also checked with the database's default `TimeZone` set to
  `Europe/Rome`: `to_char` renders in the session zone while the format string hardcodes `+00:00`,
  so this would have been a second, quieter version of the same bug — the pool pins
  `SET TIME ZONE 'UTC'` in `after_connect`, and the round trip holds.
- **A durable capability token still died at the first restart, because the identity did not
  persist.** Migration `0008` was added so a token "has to survive a restart and a revocation has
  to be durable and fleet-wide". The token row did survive; the agent identity it is bound to did
  not. `verify_token_signature` reads the agent's derived secret out of the in-memory registry and
  fails closed when the agent is absent, and `main.rs` rebuilds that registry at boot from
  `list_identities()` — so an identity that never reached storage is gone after a restart, and
  every token bound to it stops verifying. `POST /v1/nhi/identities` never persisted: the handler
  called the in-memory `register_identity` and did not even take `AppState`. `execute_pipeline` has
  persisted its auto-registered identities since v0.4.0, so the defect was invisible to any flow
  that ran an inspect first. Found by driving the release binary against a real Postgres: a token
  minted before a restart answered `404 agent_not_found` after it. The handler now stores the
  identity and its secret before it answers `201`, mirroring `issue_token_handler`.
- **`iaga proxy` refused every tool of every real MCP server.** MCP schema validation knows four
  tool names — `filesystem.read`, `filesystem.write`, `terminal.exec`, `http.fetch` — and answered
  "invalid" for everything else, while the pipeline turns any schema failure into an unconditional
  Block floor. Measured end to end: a fully registered agent, a workspace policy listing the
  downstream tool at `maxDecision: allow`, and a harmless read still came back `block` on 100% of
  proxied calls, with no configuration able to lift it, because the refusal landed before policy was
  consulted. Four hardcoded names cannot be the allowlist for an open protocol. An unregistered tool
  is now ADVISORY — the gap is named in the findings, and the layers that do know the tool (the
  workspace tool registry, the domain allowlist, taint, the firewall) decide the verdict. An
  unregistered tool is still refused; it is refused by the layer that actually knows.
- **The MCP proxy never produced a receipt chain.** Every intercepted call omitted `sessionId`, so
  receipt creation fell back to a fresh event UUID and a process handling N calls produced N
  unrelated one-receipt runs. `proxy` and `mcp-doctor` now each mint one non-empty session id per
  process and thread it through every governance check: when N is nonzero, their N calls/checks form
  one N-receipt run (`<agent>:mcp-proxy-*` or `<agent>:mcp-doctor-*`). The proxy cache now reads taint under that same
  session key. This also removes the accidental collision with agent-id-keyed state that `serve`
  can rehydrate even though proxy mode does not; existing receipts are not relabelled. The proxy
  regression test proves two allowed calls reach the downstream process and then verify as one
  two-receipt chain; `mcp-doctor` exercises the same required interceptor parameter at compile time.
- **An ordinary HTTP call followed by a shell call was labelled `reverse_shell_setup`.** The
  signature required no taint or data-flow link, and the FSA independently forbade
  `network_egress → shell`, so “download something, then run a command” blocked the whole session,
  held later calls for 60 seconds and added a strike. The unsupported signature is gone (five
  signatures remain, three critical) and that FSA transition is legal. The sequence still adds the
  signed +25 `network-delivered execution arc` anomaly. An external response remains subject to the
  per-request `EXTERNAL_TOOL → ShellExec` taint block; an internal API response is deliberately not
  vetoed by that rule. This includes localhost, `127.*`, `10.*`, `192.168.*` and
  `*.internal`/`*.local`/`*.corp`, the same exposure already granted to `file_read → shell` and
  `db_query → shell`; neither case now poisons the whole session.
- **`redactedPayload` returned the private key it had just found.** The `private_key_block` pattern
  matched only the `-----BEGIN … PRIVATE KEY-----` line, and the same table drives the redaction, so
  a PEM came back as the marker followed by the entire key body and the END line — correctly
  flagged, correctly blocked, and fully disclosed in the one field a caller is entitled to treat as
  safe. The marker made it look handled. The pattern now spans the whole block, including a
  truncated key with no END marker, and two keys in one payload stay two separate redactions.
- **A refusal could state no reason for refusing.** When the verdict came from the composite score
  crossing a threshold rather than from a layer vetoing, `reasons` fell back to
  `"no high-risk rule matched"` — so `"decision": "block"` arrived next to a reason saying nothing
  matched. `reasons` is copied verbatim into the signed `ReceiptBody`, so the contradiction was
  written into the audit event, the human review queue and the cryptographic evidence. A non-allow
  fallback now names the score and the threshold it crossed.
- **A resolved review could be silently re-flipped.** `update_status` was an unconditional UPDATE
  with no state-machine guard and no history, so an admin key could approve a request, let the
  console show it settled, then rewrite it to `rejected` — two `200 OK`s, one surviving row, and
  nothing recording that the decision had ever been anything else. Resolution is terminal now, with
  the guard in the WHERE clause so two concurrent resolutions cannot both win.
- **`/v1/audit/export` date ranges were a lexical string compare**, on both backends. Measured over
  the same one-hour window: `12:00:00+00:00` returned 34 rows, the identical instant written
  `14:00:00+02:00` returned 0, `08:00:00-04:00` returned 0, and the literal string `yesterday`
  returned 0 — every one of them `200 OK`. A filter that silently answers "no events" is worse than
  one that errors. Bounds are parsed, converted to UTC and compared at second resolution;
  unparseable input is now refused. `iaga cost --from/--to` had the same defect at six query sites
  and got the same fix.
- **CSV export did no escaping.** `agent_id`, `framework` and `tool_name` are free-form strings an
  agent controls, so a comma shifted every later column, a quote broke the field, and a newline
  split one audit record into two rows — the second parsing as a whole event with a fabricated
  `event_id`. Measured: 5 of 33 exported records malformed. Fields are quoted per RFC 4180.
- **Missing resources returned inconsistent status codes and malformed error bodies.** Missing DLQ
  entries (retry/delete), webhooks, capability tokens (issue/revoke), NHI challenge identities,
  sandbox entries (approve/reject), fingerprints, threat indicators, policy templates and session
  metrics now all return `404` with the published `{error: "not_found", message: "..."}` shape. The
  template route is the one compatibility change: its missing-id response was documented and
  implemented as `400` since v0.4.0; 2.1.0 changes it to `404`. A DLQ entry whose webhook was removed remains the distinct
  `400 invalid_request`, and the retry route now documents that response and its possible `500`.
- **`GET /v1/audit/export?format=` silently fell back to JSON for unknown formats.** `xml`, `CSV`
  and typos now return `400 invalid_request` naming the supported `json` and `csv` values, matching
  the OpenAPI enum. An omitted or empty value still selects the documented JSON default.
- **`iaga inspect --stdin` was documented and rejected.** The branch that reads stdin existed;
  clap read the leading `--` of the positional as a flag and refused with exit 2 — the code the
  convention reserves for a Block. Both its own `--help` and `AGENTS.md` promised the spelling.
- **A credential leaving was weaker than a credential arriving.** `/v1/response/scan` ran a table of
  compiled credential regexes; `/v1/inspect` — the direction where a secret is *leaving* — ran a
  separate lowercase substring list, which only finds a credential carrying a giveaway word
  (`api_key`, `password`, `bearer `). A credential that is an opaque token with a distinctive shape
  has no such word: measured, `AKIAIOSFODNN7EXAMPLE` scored `review`/70 on the response path and
  `allow`/2 with "no high-risk rule matched" on inspect. Nothing was missing from the product — one
  detector did not share the other's patterns. The egress path now consults the same
  `credential`-category table, and `tests/egress_credential_parity.rs` asserts PARITY rather than a
  fixed list, so a family added to one cannot silently fail to reach the other.

  Scope, stated precisely: the family this actually recovers today is the AWS access key id —
  `ghp_`, PEM blocks and URL credentials were already covered on the egress side. And neither
  detector knows Stripe, Slack or Google API keys: that is a real gap in the shared table, present
  in both directions, and closing it is a separate change from making the two agree.
- **`iaga validate` printed "Config is valid!" above a critical contradiction and exited 0**, and
  `iaga import` then installed that policy, also with exit 0. The headline came first, several lines
  above `error [critical] contradiction`, so a human read the verdict before the evidence against it
  and a CI gate reading the exit code accepted a policy with no single meaning. The headline now
  comes last and says what is true; `critical` fails both commands, `high`/`medium` stay advisory
  (a policy that has not adopted `destinationFields` is legal). Duplicate issues are also collapsed
  — a tool declared twice reported its contradiction twice.
- **`iaga mcp-doctor --probe-tool X` printed `probe: FAILED` and exited 0**, so the one flag whose
  purpose is "does calling this actually work" could not gate the CI job it exists for. A probe runs
  only when asked for by name, so failing on it cannot surprise anyone who did not ask.
- **The operator console reported "connected" while hiding fifteen panels.** It treated only `401`
  as unauthorized, so an agent-scoped key — which the console itself can mint — left the banner
  clear and the header green while 15 of 24 panels answered `403` and rendered their "No decisions
  yet" placeholder. Being told there is nothing to see when there is, is the worst of the three
  possible answers. A `403` now raises its own banner naming the scope and the fix.
- **`ttlSeconds` accepted values that could not be honoured.** A negative TTL minted a `201` token
  the API reported `valid: true` while every check rejected it as expired, and a value large enough
  to push the expiry past year 9999 minted one that could not be rendered back at all. Both are now
  refused with `400`, and the TTL is capped at one year — a bearer credential with no revocation
  pressure on its holder should not be mintable for a decade because nothing stopped you.
- **`review_created` was in the SSE enum, the webhook dispatcher, the OpenAPI event list,
  FEATURES.md and the console's Live feed, and nothing ever constructed it.** The one event that
  says "a human is needed" was the only one that never fired: an operator watching the stream saw
  the action governed and then silence, while the queue filled with nobody told.
- **`GET /v1/receipts` answered `200 OK` with `runs` as an error object** where the spec declares an
  array and marks it required, so `d["runs"][:2]` raised a TypeError on a response the status line
  called a success. The storage failure is still logged; the wire type the spec promises is not
  broken to carry it.
- **Resolving a review left no trace in the audit trail.** The resolution touched
  `review_requests` and nothing else, so the governed action's row kept `reviewStatus: "pending"`
  forever, no row was appended, and the operator who decided was recorded nowhere — the exportable
  evidence record said no human had ever adjudicated anything. Two things were missing. The
  `ReviewRequest` minted its own UUID and neither table had a foreign key to the other, so nothing
  could say which action an adjudication belonged to; the request now carries the governed action's
  `event_id`. And the resolution is APPENDED as its own audit event (framework
  `review-resolution`, with `review-resolved:<status>`, `review-request:<eventId>` and
  `resolved-by:<keyId>` in `reasons`) rather than rewriting the original row: that row's
  `timestamp` is the DECISION time with no second column for the adjudication, so rewriting it in
  place would assert a human approved the action at the instant it was governed, and the signed
  receipt was already built from the row as it stood — an in-place update would put the SQL log out
  of step with the evidence replayed from it. `append` is the only write `AuditStore` has.

  The governed action's own row therefore keeps `reviewStatus: pending` for good: it records what
  was true when the action was governed. The adjudication is the later row, joined to it by
  `review-request:<eventId>`. Two stated costs: an adjudicated action now contributes two rows to
  `/v1/audit/stats` and `agent_analytics`, and because `review_requests.tenant_id` has never been
  written by anything, `/v1/audit/export?tenant_id=X` returns the governed action and not the
  adjudication.
- **An agent could forge the human-in-the-loop record.** `POST /v1/reviews/{id}` had no admin
  guard, so an agent-scoped key could list the queue, find the request raised against its own
  action, and mark it `approved`.
- **Nineteen cross-tenant reads and the SSE firehose were open to any valid key.** The sharpest was
  `GET /v1/workspaces`, which returns `threshold_block` and `threshold_review` — the exact number an
  agent needs to tune itself to just under the block line. `GET /v1/policy/verify/{id}` and
  `GET /v1/workspaces/{id}/rules` were the same disclosure one route over. The rest came out of
  enumerating all 83 route/method pairs against their guards rather than sampling: the telemetry
  buffer (the SSE firehose by another name), `/v1/nhi/identities` (every agent id, SPIFFE id, key
  commitment and trust score — the target list for the per-agent reads), the session graphs, the
  behavioural fingerprints, per-agent spend, and `/v1/sandbox/pending`, whose approve and reject
  twins had been admin-only since 1.x.
- **The Bash Claude Code hook failed open silently, with fail-closed switched on.** `curl` without
  `-f` exits 0 on any HTTP status, and every `SentinelError` serializes to JSON, so `jq -e .`
  accepted a 404/403/500 error body as a verdict, the fail-open/fail-closed branch was skipped
  entirely, and `.decision // "allow"` returned `allow`. `IAGA_FAIL_CLOSED=1` was inert for exactly
  the cases that matter: **404 `agent_not_found`** (the state of every install until the policy is
  imported), **403 `scope_mismatch`**, and **500 `storage_error`** — a governance-database outage
  let every tool call through. The hook now captures the status, routes every non-2xx through the
  fail-closed gate, and writes a diagnostic to stderr, which it never did.
- **Plug-in clients followed redirects.** The VoltAgent client now sends `redirect: "manual"`; the
  Letta client and the Python Claude Code hook install an opener that refuses. Measured: a `302`
  from the configured URL to a hostile server made the Letta client return that server's
  `decision: "allow"`, and the Python hook log `allow (risk=0, receipt=)` — announcing a receipt
  that does not exist. (Note 307/308 were never the hole: `urllib` already refuses those on a POST.)
- **`maxDecision: block` was never enforced.** `evaluate_policy` tested only `== Review`, while
  `formal_verify` reported an all-Block policy as a **critical deny-all** and `iaga validate`
  printed it as an error — so a policy that permitted everything was described to the operator as
  one that denied everything.
- **Workspace rules were compared against the wrong risk scale.** The fields were named
  `min/maxRiskScore` and fed the **adaptive layer** score (ceiling 64, measured band 9–48), while
  every operator-visible number is the composite 0–100. The shipped `review-high-risk-shell`
  (`min 60`) could never fire; `soc2-shell-hours` (`max 40`, decision Allow) fired almost
  unconditionally. Renamed with serde aliases rather than rescaled: the composite depends on the
  rule match, so feeding it back is a genuine cycle, and the 64 ceiling holds only at default
  weights, which `POST /v1/risk/feedback` can lift.
- **`agent_analytics` built its top-5 by splitting a CSV aggregate.** `STRING_AGG`/`GROUP_CONCAT`
  materialized one entry per audit event to produce a five-element list, a tool named `read,write`
  counted as two phantom tools, and the top-5 cut came out of `HashMap` order. Replaced with three
  grouped queries; the per-agent N+1 is gone and `decisions_csv` — selected and never read on both
  backends — with it.
- **The sandbox read `SELECT ... WHERE deleted_at IS NULL` as a critical, irreversible DELETE.**
  Substring matching on `DELETE`/`DROP`/`UPDATE`/`ALTER` also caught `dropbox_url`, `updated_at` and
  `alternate_id`. Nothing signed moved, but it decided `requires_approval`, so it filled the human
  approval queue with destructive-looking reads. Word-boundary matching now, copying the pattern
  `analyze_shell` already used in the same file.
- **NHI `created_at` diverged between backends.** Postgres wrote `NOW()` instead of binding the
  identity's own value, and rendered it as `2026-08-19 12:34:56+00`, which does not parse as
  RFC3339. Since this is the server's startup hydration path, that string is what
  `GET /v1/nhi/identities` returned after every restart.
- **Raw wall-clock subtraction in session eviction.** A backward clock step (NTP, VM snapshot
  restore) panicked in debug — poisoning the global session map — and in release wrapped to a huge
  `u64`, evicting every future-dated session in one sweep. Two sites, both now `saturating_sub`,
  matching the four clock subtractions in the same file that already were.
- **`/v1/audit/export?limit=` was unbounded**, so `?limit=4294967295` materialized the whole table
  into one in-process `String`. Capped at 50 000, with the matching `maximum:` in the OpenAPI spec.
- **`.dockerignore` did not match nested databases.** `*.db` matches only the context root, while
  the test suite leaves one at `crates/iaga-sentinel-core/*.db` and the Dockerfile copies `crates/`.
  Prefixed the DB patterns, `chain.json`, `.env` and `keys/` with `**/`.
- **A tag could publish without passing the tests.** `ci.yml`, `release.yml` and `docker.yml` all
  triggered independently on `v*`, and `publish` depended only on a `cargo build`. Both publish
  paths now have a blocking test gate.
- **Windows and macOS never compiled the test code.** `compile-sanity` ran `cargo build --workspace`
  without `--all-targets`, and every Rust test job is ubuntu-only.
- **The only end-to-end `GovernedTool` test had never run in CI.** It is `#[ignore]`d pending a live
  seeded sidecar — which the CI `test` job has been standing up for other steps all along.

### Changed

- **`iaga-verify` now rejects a chain relabelled to a run that never happened.** The export's
  top-level `run_id` is not covered by any signature, so a chain of genuinely signed receipts could
  be re-pointed at an invented run and this verifier still printed `CHAIN OK` and exited 0 — while
  the Python and Node verifiers refused the same file with exit 1. That made
  `sdks/conformance/README.md`'s promise that all three reach the same verdict false. All three now
  emit the identical `run_id mismatch` line. **A chain that verified before and fails now was
  mislabelled**; the receipts themselves are untouched.
- **`--expect-count` exists in all three verifiers.** It was the only documented offline defence
  against tail truncation and shipped only in the Rust binary — missing from exactly the reader the
  README sends to the dependency-free verifiers *because they cannot build Rust*.
- **`iaga replay --list` and `GET /v1/receipts` read the terminal verdict from the signed receipt
  body**, not from the denormalized `verdict` column beside it. An `UPDATE` on that column made both
  surfaces report `allow` while the sealed evidence in the same row said `block` and the chain still
  verified, with nothing flagging the divergence. The column stays for the indexed reads.
- **`POST /v1/rate-limit/config` persists.** `save_config` shipped with a complete UPSERT on both
  backends and no caller, while boot read the row back — so a tightened limit answered `200`,
  survived until restart, then silently reverted to the defaults, and on multi-replica bound only
  the replica that served the request.
- **`iaga cost by-agent|by-model|by-tool` exit 1 on an unparseable `--from`/`--to`.** They rendered
  a rejected bound as `[]` with exit 0 — byte-identical to a legitimate "no spend in that window".
  `cost summary` already exited 1; the three now match it.
- **The boot log redacts the database password.** `DATABASE_URL` was logged verbatim at INFO, so a
  PostgreSQL deployment wrote its password to stdout on every start — and under the Helm chart that
  value comes from a Secret and lands in the pod log. The product's own response scanner classifies
  that line as a `connection_string` leak.
- **Applying migration `0009` says what it just did.** Every agent-scoped key minted before it has a
  null binding and starts answering `403 agent_key_unbound`, which is deliberate — but the count was
  known at migration time and went unsaid at the default log level, so the first signal was a 403 in
  a caller's face. Anything that fails *open* on an unexpected status turned that into a silent
  `allow`: the Claude Code hook's default did exactly that, which its README now warns about.
- **`404` on capability-token mint and NHI challenge names the remedy** instead of only the symptom.
  An agent can hold a profile and an agent-scoped key and still have no NHI identity, so
  "Agent not registered" was reachable while following the upgrade notes.
- **The Python SDK's action-type heuristic tested `read`/`file` before `write`**, so
  `filesystem.write` and `write_file` reported `file_read`, and its shell branch matched only
  `shell`/`terminal`, so `Bash` reported `custom`. Each was scored on the wrong weight
  (`file_read` 15 vs `file_write` 40; `custom` 25 vs `shell` 60), and the same name classified
  differently here than in the TypeScript SDK, so one policy could not govern both runtimes.
- **`SinkType::ToolResponse`** replaces `NetworkEgress` for response scanning. A secret in the
  response still blocks; the labels that describe where data came *from* no longer apply to data
  coming *in*, and inherited session labels no longer decide the verdict.

### Removed

- `modules/policy/hierarchy.rs` (205 lines): implemented `extends:` policy inheritance.
  `WorkspacePolicy` has no such field, no migration adds the column, and it had zero callers — four
  in-file tests kept it green and therefore invisible.
- The `TenantStore` trait and both implementations (148 lines): zero call sites; the
  `StorageBundle`/`AppState` fields were populated and never dereferenced. **The `tenants` table
  stays** — on Postgres it is the target of six foreign keys, counted on a live 2.1.0 database — as does the `Tenant` type.
- `crates/iaga-sentinel-core/fuzz/` (127 lines): unbuildable since the 1.1.0 rename, because it
  depends on a package name that no longer exists. Every invariant its three targets asserted is
  already covered in `tests/property_tests.rs`, whose five `proptest!` blocks run 500, 500, 300,
  200 and 500 cases.
- `config/load_config.rs` (50 lines): zero callers. The three inline readers in `main.rs` are
  deliberately **not** merged into it — they scan a different filename set and exit differently, on
  purpose.
- Nine of the sixteen SQLite column backfills and their Postgres twins: unreachable by
  construction, because the migrator runs to completion before the loop starts. They could not even
  rescue the case they were written for.
- `TractEngine::from_runnables`, `AgentFingerprintResponse` (a stale duplicate of the type that
  actually serializes), the duplicated `inferActionType` in the TypeScript adapters, the two
  unreadable receipt indexes (`idx_receipts_verdict`, `idx_receipts_timestamp`), and the Python
  SDK's `sync` extra declaring `requests`, which no module imports.

### Verification

- `cargo fmt --all --check` and both CI clippy jobs are clean with `-D warnings`.
- `cargo test --workspace`: **665 passed, 0 failed, 2 ignored** (up from 546 at `b444886`, measured
  by running the suite in a worktree at that commit rather than quoted). The two ignored are the
  live-sidecar `GovernedTool` cases, which CI runs with `-- --ignored` in its SDK e2e step.
  `cargo test -p iaga-sentinel-core --features postgres`: **477 passed, 0 failed** and
  `cargo test -p iaga-sentinel-receipts --features postgres`: **46 passed, 0 failed**, both against
  a live PostgreSQL 16. `cargo test --workspace --all-features -j 2`: **731 passed, 0 failed**.
  The `-j 2` is required only for the all-features build on Windows: unconstrained it dies at link
  with `LNK1102` / `os error 1455` (pagefile), having run **zero** tests. That is a workstation
  limit, not a result — CI runs the same step on Ubuntu after reclaiming ~20 GB.
- Each of the eight per-feature CI steps run clean on its own: `ml`, `plugins`, `dictum-wasm`,
  `plugins,plugin-attestation`, `otel-receipts`, `plugin-manifest-signing`, `cost-control`, and the
  `linux-bpf` scaffold build.
- The Operator Console was rendered, not only fetched: all **13 views** driven through headless
  Chrome with JavaScript executed, no console errors, no error banner, and the Decisions table
  showing the actions that had just been governed. All **30** endpoints the console polls answer
  `200`; SSE delivered every `action_governed` event live; the exported chain verified `CHAIN OK`
  against a **pinned** key from the Rust, Python and Node verifiers with byte-identical output.
- **Not verified here, stated rather than implied:** CI has never run against this tree, so every
  number above is a Windows workstation. The shipped binaries are built at default features, so the
  `DATABASE_URL` redaction below is covered by a unit test rather than a live PostgreSQL boot, and
  the chart's PostgreSQL install needs an image built with `--features postgres` (see Known gaps).

### Known gaps

- Carried over from 2.0.2 and still true: `iaga migrate` reads SQLite only (`postgres` is not a
  default feature, so this holds for every shipped artefact), `iaga replay --export` is SQLite-only
  for the same reason (`main.rs:3079`, chain export and offline verification are unavailable on
  Postgres), `POST /v1/nhi/challenge` does not persist on Postgres, `RUSTSEC-2026-0217` is still
  ignored in `.cargo/audit.toml`, Dictum still cannot match on destination keys
  (see the egress item above), and `ghcr.io/iaga-team/iaga-sentinel` does not resolve.
- `POST /v1/inspect` still returns the caller's own `workspacePolicy`, thresholds included. The
  admin guard added here restricts **cross-workspace** reads; a caller reading back the policy it
  was just governed by is unchanged, and the receipt wire format depends on it.
- **PostgreSQL is a compile-time feature and the shipped `Dockerfile` does not enable it.** The
  chart's own headline install sets `postgres.enabled=true`, but an image built from this repository
  as-is exits 1 on a `postgres://` URL — after printing the full "server is up" banner, so in a
  cluster the only clue is a `CrashLoopBackOff`. Build with
  `--features postgres` or leave `postgres.enabled` off. Documented in
  `charts/iaga-sentinel/README.md`; the `Dockerfile` is deliberately unchanged in this release.
- **The stdio MCP planes carry no identity binding.** `iaga mcp-server` and `iaga proxy` present no
  API key, so the `agentId` they submit is asserted rather than enforced and any local caller can
  obtain a signed receipt under any agent id. Inherent to stdio, unchanged from 2.0.2, and now
  stated in `AGENTS.md` §8 next to the binding it qualifies.
- **Verifying a chain without `--key` proves internal consistency, not authorship.** The verifier
  falls back to the key embedded in the export, which a forger who re-signed the chain also
  supplied; it warns on stderr and stamps `key=embedded`. This is the design of ADR 0015 and is
  unchanged, but the README's own example omitted the flag — it now pins the key and says why.
- **The SSE event payload is snake_case (`tool_name`, `risk_score`) while the REST audit surface is
  camelCase.** Unchanged from 2.0.2 and the console reads both, but a client written against one
  shape will not read the other.

---

## [2.0.2], 2026-08-10 — The Thresholds Postgres Never Read

Follow-up hardening after a live 76-request attack-suite case study. Two attacks got through, both
design gaps rather than implementation bugs; the rest of this is closing those, giving the layers
that changed the tests they never had, and running the Postgres proofs that had only been read.
Running them is what turned up the heaviest item in this release: a Postgres deployment was being
governed at the default thresholds no matter what its policy said.

**Compatibility.** The signed receipt **wire format** is unchanged, and existing chains verify
byte-for-byte — measured in all four directions, generating a chain with the 2.0.1 binary and
verifying it with the 2.0.2 `iaga-verify` and vice versa. `auditEvent.reasons` is unchanged in
content and order for identical traffic.

**What a consumer can observe changing**, in rough order of how much it matters:

1. **Postgres verdicts move.** Workspace thresholds were being read back as the built-in
   `70`/`35` regardless of configuration (see Fixed). A Postgres deployment that ever set custom
   thresholds will now be governed by them — which is the point, and is still a change in what the
   product blocks. SQLite is unaffected. `riskScore` on `/v1/audit` and `/v1/reviews` also stops
   reading back as `0`, and `workspace_policy_hash` changes for any policy whose thresholds were
   not the defaults, so **new** receipts on Postgres carry a different `policyHash` than before.
2. **`/v1/inspect` gains two fields**: `layerRoles` (always present) and
   `taintAnalysis.correlationScope`. Additive, but a strict schema validator will see them.
3. **`risk.reasons` carries more entries** — the Dictum and cost-control attributions now reach the
   caller, so code that counts or exact-matches that array sees more lines. The review queue
   (`GET /v1/reviews`) shows the same lines.
4. **`POST /v1/sandbox/{id}/approve` and `/reject` now require an admin key**; an `agent`-scoped key
   that used to get `200` gets `403 admin_scope_required`.
5. **`audit_events.created_at` is the pipeline's decision time**, not the moment the write-behind
   task landed, so the audit read order changes for rows written inside the same second.
6. **`GET /v1/cost/over-time?bucket=day` on SQLite** now returns `2026-08-09T00:00:00Z` where it
   returned `2026-08-09`, matching Postgres.
7. **The MCP `tools/list` description text changed** for `http.fetch`, and the schema now accepts
   seven destination names where it demanded `destination`.
8. **`iaga validate` and `iaga import` print policy lint output** they did not print before. Exit
   codes are unchanged; on the configs shipped in this repo the new output is one
   `warning [medium] incomplete_coverage`.
9. **The Python `@governed` decorator no longer sends `ctx`/`context`** (under Changed), and the
   Helm chart's `image.tag` no longer has a default (under Fixed).

### Added

- **Per-tool egress destination declaration.** A `ToolPolicy` can declare `destinationFields` — the
  payload keys that carry its egress target. When declared, the domain allowlist is applied
  fail-closed: a payload that exposes none of those keys is refused rather than skipping the
  allowlist. Undeclared tools keep the legacy four-name probe (`destination`/`url`/`endpoint`/`href`),
  so an LLM SDK call whose endpoint is baked into the client is unaffected. The shipped example
  policies (`iaga-sentinel.config.json`, `iaga-sentinel.example.yaml`) now declare it for `http.fetch`.
- **`layerRoles`** on every inspect response and in the SDKs (Python `layer_roles` +
  `is_advisory_layer`, TypeScript `layerRoles`): a machine-readable map marking each layer `veto`,
  `scoring`, or `advisory`, so a consumer is not left to infer that the sandbox result, the
  behavioural fingerprint, and the session graph's `advisoryScore` cannot move a verdict. The
  session graph's *other* score, the signed `anomalyScore`, is not advisory: it is a term in the
  composite and escalates to review on its own at 50.
- **Opt-in agent-scoped taint correlation** (`IAGA_SENTINEL_TAINT_AGENT_WINDOW_SECS`, default off):
  folds the `secret` label an agent accumulated in its other sessions into the current one, within a
  window, so rotating a client-declared `sessionId` between reading a credential and sending it out no
  longer erases the link. Only `secret` crosses a session boundary, and only into a request carrying a
  body, so ordinary read-then-fetch work is unaffected — measured 19/19 attacks blocked with 0 false
  positives on 43 benign controls. Kept opt-in because the store is per-process (best-effort behind
  multiple replicas). Documented in openapi (`TaintCorrelationScope`), the Helm chart, and surfaced on
  every response as `taintAnalysis.correlationScope`.
- **`iaga-verify --expect-count <n>`**: fails a tail-truncated chain. `CHAIN OK` proves prefix
  integrity, not completeness; the expected length is an external anchor, deliberately not part of the
  signed bytes.
- **Postgres integration coverage.** `tests/backend_parity.rs` round-trips the four `INTEGER` columns
  that `pg_row_*` decode (thresholds, audit risk, review risk) against a live database, and a
  `clippy --features postgres` CI leg lints the backend that was previously never linted. Migration
  `0007` adds the composite indexes for the audit read path.

### Changed

- **`@governed` no longer sends arguments named `ctx` or `context`** to the sidecar. The decorator now
  shares `named_payload` with the adapters, whose default exclude is `("self", "ctx", "context")`.
  Excluding `self` was the point (an instance repr, potentially holding a credential, was reaching the
  signed receipt's input hash); excluding `context` is a real, if small, reduction in the governed
  surface. A tool that needs a `context` argument governed should pass it under a different name.

### Fixed

- **Postgres was governing every workspace at the default thresholds, ignoring its own policy.**
  `pg_row_to_workspace` decoded `threshold_block` and `threshold_review` as `i64` from columns
  declared `INTEGER` (`migrations/postgres/0001_initial.sql`). sqlx's Postgres decode is
  strict-equality on the type OID, so every read was rejected and the `unwrap_or(70)` / `unwrap_or(35)`
  fallback stood in — silently, because the fallback is the same value as the default. Measured: a
  workspace stored as `threshold_block=40, threshold_review=20` in the database read back as
  `70`/`35` through the 2.0.1 binary and as `40`/`20` through this one. The same class of decode
  applied to `risk_score` on `/v1/audit` and `/v1/reviews`, which is why both reported `0` on
  Postgres. **This moves verdicts on Postgres** — see the Compatibility note above. Fixed by
  decoding the four columns as `i32`, with a logged fallback rather than a silent one, and pinned by
  `tests/backend_parity.rs` against a live database.
- **Egress allowlist bypass by field name.** A payload naming its destination `target` (or any name
  outside the legacy four) skipped the domain allowlist entirely. Closed by `destinationFields` above;
  an un-migrated workspace now gets a Review escalation via a narrow top-level URL sweep (scheme-
  qualified, content-bearing keys excluded, `Http` actions only) rather than a silent allow.
- **That sweep could be made to panic, and a panicked request left no evidence.** Rewinding to the
  start of a URL used `rfind(...).map(|i| i + 1)` on a match of `char::is_whitespace` — the Unicode
  property, so it matches multi-byte spaces (U+00A0, U+2000–U+200A, U+3000). On one of those, `i + 1`
  lands inside the character and the following slice panics. Since the sweep reads every top-level
  string on every `Http` action, any caller of `/v1/inspect` could send it: the task died, the
  connection closed with no response at all, and **no audit event was written** — a governed action
  with neither a verdict nor a receipt. Found and fixed before release, stepping by the matched
  character's own width, with a test that fails on the panic.
- **The shipped example allowlist used wildcards, which match nothing.**
  `iaga-sentinel.example.yaml` listed `*.openai.com` and `*.github.com`; `allowed_domains` is
  compared for host equality after normalisation, with no glob support, so anyone who copied that
  file had every call to those hosts refused by the egress rule. Replaced with the bare hosts
  (`api.openai.com`, `api.github.com`) and a comment saying there is no wildcard support.
- **The Helm chart shipped an `image.tag` default pointing at an image that does not exist.** A
  plain `helm install` rendered a valid-looking reference to `ghcr.io/iaga-team/iaga-sentinel`, an
  unpublished package, so the first symptom was a pod in `ImagePullBackOff`. `image.tag` now has no
  default and the template calls `required`, so the render refuses with a message naming the value
  and what to set. Chart version `0.1.0` → `0.2.0`; CI renders with an explicit tag and asserts the
  refusal.
- **`LayerRole` was not exported from the TypeScript package root.** `GovernanceResult.layerRoles`
  is typed `Record<string, LayerRole>`, but `src/index.ts` re-exports a named list that omitted the
  interface, so a consumer could read the field and not name its type without a deep import.
- **`AGENTS.md` endorsed seven destination key names that its own example policy cannot read.** The
  MCP schema and the workspace egress layer accept `destination`/`url`/`uri`/`endpoint`/`href`/
  `target`/`webhook`, but the shipped Dictum rule — the one `scripts/agent_bootstrap.*` writes and
  §0 tells every agent to run first — reads `url_host(action.payload.destination)` only. `url_host()`
  errors on the other six, and an erroring `when` on a `block` rule is a documented fail-closed fire,
  so a credential-free `GET` under `uri` was refused with `dictum-eval-error` — a refusal written
  into the signed `auditEvent.reasons` under a rule name about credential egress that never matched.
  **Fixed by reordering the shipped rule**: `secret_ref(action.payload)` now comes before
  `url_host(...)`, and because `and` short-circuits, a call with no credential never reaches the
  erroring builtin. A call that does carry one still evaluates it, so an alias there still fails
  closed — the protection is unchanged and only the false refusal is gone. Measured with the demo
  workspace declaring all seven names: a credential-free `GET` under `uri` or `webhook` to an
  allowlisted host went from **block with `dictum-eval-error`** to **allow**, while `uri` to a
  non-allowlisted host stays blocked and now names the host. Changed in `AGENTS.md` §11b and in the
  policy both `scripts/agent_bootstrap.*` generate, with the reasoning inline so the order is not
  "tidied" back. Declaring `destinationFields` on the workspace policy remains the way to actually
  *cover* the other six names; the two are complementary. Dictum still has no coalescing builtin.
- **Audit read paths were not totally ordered.** `/v1/audit`, `/v1/audit/export`, `/v1/audit/stats`
  and the cost top-N ordered by a non-unique key with no tie-break, so paging was nondeterministic and
  the two backends could disagree. Tie-breaks added across both backends, with the first tests for it.
- **…and, once totally ordered, still not ordered by TIME.** The tie-break made the read
  reproducible; it did not make it chronological. `created_at` was left to the SQLite column
  default, `datetime('now')` — whole seconds — and the INSERT never supplied it, so every row
  written inside one second tied and `event_id DESC`, a UUID, became the real order. Measured on
  five sequential live requests: the newest event came back **fourth**, and the returned order
  matched `sorted(event_id, reverse=True)` exactly. Postgres has microsecond `NOW()` and did not
  tie, so the same traffic produced a different order on each backend. Both INSERTs now supply
  `created_at` from the pipeline's own decision time, so the audit is ordered by when the action
  happened rather than when the write-behind task landed, and the two backends agree. The
  tie-break stays as the last resort it was meant to be.
- **The operator console reported a risk "peak" lower than its own average.** The agent panel's
  `Avg / peak risk` row read the average from `/v1/analytics/agents` (the final governance score)
  and the peak from the behavioural fingerprint, which records the *adaptive layer's* composite —
  two different metrics under one label. Measured on one agent: the row said `36.1 / 26.0` while
  the agent's worst actual risk was **86**, a 3.3x under-report on the screen an operator opens to
  ask exactly that question. The peak is now its own row, named **Peak adaptive score** and marked
  `adv`, and the `Requests` row is marked too when its number falls back to the fingerprint. No
  API or receipt field changed; this is what the console shows.
- **Postgres timestamp rendering assumed UTC without asking for it.** The pool now sets
  `TIME ZONE 'UTC'` on connect, fixing `date_trunc` cost buckets (which glued a literal `"Z"` onto a
  session-local truncation) and the `created_at::text` renders.
- **`policyVerification` is advisory, and an earlier draft of `layerRoles` in this same change set
  said veto.** It lints the workspace policy and is never read back into the decision. To be exact
  about what shipped: 2.0.1 published *no* role for this layer at all — `docs/openapi.yaml` said
  only "L6 formal policy verification result" — so this corrects a draft of the new table, not a
  claim any released version made. Pinned by `tests/layer_roles_openapi_parity.rs`.
- **The session graph's `anomalyScore` is decisive, and the prose describing it drifted while this
  table was being written.** `execute_pipeline` assigns it to `layer_risks.session_graph` and
  escalates to review on its own at 50; the advisory field is the separate `advisoryScore`. Again to
  be exact: 2.0.1 called neither field advisory — the sentence that did appeared in the files this
  change set added and edited (`layerRoles`, both SDKs, `ARCHITECTURE.md`). Understating what is
  inside a signed verdict is the same defect class as 2.0.1's overstating, in the worse direction,
  which is why it is pinned by a new test tying the published prose to the field names rather than
  simply reworded.
- **`layerRoles` said the plugin layer "cannot veto on its own". It can, twice.**
  `execute_pipeline` sets `minimum_decision = Block` from a plugin's `decision_hint`, and again when
  `layer_risks.plugins` reaches the workspace block threshold — a comparison on the plugin's own
  scale, so the 0.10 composite weight the note reasoned about does not bound it. A plugin error
  escalates to review. Corrected, `role` moved from `scoring` to `veto`, and pinned by a test that
  asserts the pipeline still grants the veto before policing the claim.
- **The sentence introducing `layerRoles` counted three inert layers where there are four.** Of the
  ten layer blocks, `sandboxResult`, `behavioralFingerprint`, `telemetrySpan` **and**
  `policyVerification` cannot move a verdict; the list named the first two plus
  `sessionGraph.advisoryScore`, which is a sub-field rather than one of the ten. Undercounting them
  invites a reader to count more defences than exist. The count is now derived from `layer_roles()`
  by a test rather than maintained by hand, in `types.rs`, `openapi.yaml` and both SDKs.
- **The MCP schema for `http.fetch` accepted seven destination names; the egress probe read four.**
  Widening the schema (so a `{method, url}` MCP call is no longer refused before the policy layer can
  host-check it) opened a gap for `uri`, `target` and `webhook`: on a workspace that has not adopted
  `destinationFields`, a BARE host under those names cleared schema validation, was not read by the
  legacy probe, and was skipped by the tier-3 sweep, which requires a scheme. Measured: `{method:
  GET, uri: "attacker.example"}` went from Block to a finding-less **Allow**. The sweep now reads a
  scheme-less value when the key is itself a destination name and the value is host-shaped. Measured
  on the 43-case benign corpus: **0 new false positives**, and one attack that had been caught by the
  threat feed alone is now independently caught by the policy layer too.
- **A tier-3 egress finding contradicted its own verdict, and was signed.** The sweep never received
  the declaration it is named for, so on a declaring tool it re-found the key tier 1 had just refused
  and pushed a second finding stating the key was undeclared and that the request was "escalating for
  human review" — both false on a Block. `risk.reasons` carries this into `auditEvent.reasons`, which
  is signed. Declared keys are now excluded and the escalation wording is conditional.
- **`GET /v1/audit/export?tenant_id=` was accepted and ignored on SQLite**, the default backend: the
  filter was destructured and never used, and the column was missing from the projection, so an
  exported row serialized `"tenantId": null` where Postgres returned the real value. Not a
  confidentiality fix — the endpoint is admin-only, `AuthContext` carries no tenant, and `/v1/audit`
  already returns every tenant to the same caller — but a documented filter that did not filter, and
  a cross-backend divergence. First test added.
- **`POST /v1/sandbox/{id}/approve` and `/reject` are now admin-only.** Releasing or refusing a
  contained action is an operator decision, not one the governed agent makes about itself. The
  operator console is admin-authenticated, so no realistically-configured console regresses; an
  `agent`-scoped key now gets `403 admin_scope_required`. Added to the scope e2e test.
- **The two backends labelled the same daily cost bucket differently.** `GET
  /v1/cost/over-time?bucket=day` returned `2026-08-09` on SQLite and `2026-08-09T00:00:00Z` on
  Postgres for identical data; they already agreed on `bucket=hour`. SQLite now emits the Postgres
  form, so the label is RFC3339 on both. A consumer that string-matched the bare date on SQLite sees
  the fuller form.
- **`import iaga_sentinel` eagerly imported nine framework adapters** because the decorator imported
  its helpers from `adapters/`. The generic helpers moved to `iaga_sentinel._payload`; the package now
  imports no adapter.

### Notes on what did not change, and what is still open

- The adaptive layer's score-driven block arm is **removed in this release** (2.0.1 still had
  `total_score >= 70 => "block"`). No verdict moves, because it was unreachable: its signed ceiling
  is below the block threshold at
  default weights. Admin feedback (`POST /v1/risk/feedback`) can renormalise the weights and lift that
  ceiling, but still cannot block — the decision carries no score arm to reach. Now stated precisely in
  `layerRoles` and openapi, with a test pinning the drift.
- `POST /v1/nhi/challenge` persists nothing to Postgres: `create_challenge` writes only the in-memory
  map, and the durable `store_challenge` has no caller, so challenges do not survive a restart. Found
  while running the Postgres prune proof; reported here rather than silently changed, since wiring
  durable challenges has restart semantics that belong in their own change.

---

## [2.0.1], 2026-08-05 — Layers That Reported Themselves Present and Were Not

A patch release, and every entry in it is a defect that **predates 2.0.0** — most of them the first
commit. No feature, no new endpoint, no new configuration key. The theme is uncomfortable and worth
stating plainly: four of these are components that announce themselves in the response, in the layer
inventory or in the config schema, and do nothing. A gate that reports itself present and never fires
is worse than one that is absent, because the absence is at least visible.

**Compatibility.** The receipt schema, the wire contract and the Dictum language are unchanged: no
receipt field was added, removed or renamed, so every verifier and the receipt DB schema are
untouched, and receipts produced by any earlier release still verify. Three changes are behaviour a
caller can observe, all of them deliberate and all of them the point of the release: the rate limiter
now actually refuses (below), `sandboxResult` now appears on high-risk actions, and three CLI paths
now exit non-zero on a refusal instead of 0. A profile that explicitly sets `toolTrust` is now scored
with the value it declares rather than 0.7, which can move that agent's `risk_score` — see below.

Migration `0006_tool_trust` is additive with a default equal to the value those rows were already
being scored with, so an upgraded database governs exactly as it did before. `scripts/rollback_0006.*`
rolls it back; run it **before** downgrading the binary, because sqlx validates the applied set at
startup and refuses to run against a database carrying a migration it does not know.

Both backends were exercised on a live server for this release, not only compiled: on Postgres 16
the migration applied, a `toolTrust: 0.05` profile round-tripped through import → column →
`GET /v1/profiles`, a governed `/v1/inspect` blocked and persisted its audit row, and the rollback
script ran end to end — printing the value it was about to discard, dropping the column, deleting
the ledger row, with a subsequent `iaga migrate` re-applying cleanly and the trust back at `0.7`,
which is the data loss the script's own header documents.

### Added

- **A real release workflow.** `.github/workflows/release.yml` builds five targets on a `v*`
  tag — Linux x86_64/aarch64, macOS x86_64/aarch64, Windows x86_64 — and publishes
  `iaga-<version>-<target>.tar.gz` plus a single `SHA256SUMS`. Each archive carries **both**
  binaries, `iaga` and `iaga-verify`, with `LICENSE`, `DISCLAIMER.md` and
  `THIRD_PARTY_NOTICES.md`. This replaces the `release` job in `ci.yml`, which attached one
  bare, unversioned Linux `iaga-sentinel` binary: no macOS, no Windows, no checksum, and no
  `iaga-verify` — so the offline proof the README sells was not in the release. That job was
  removed rather than left in place, because two `action-gh-release` calls on the same tag
  race each other.
- **`charts/iaga-sentinel/README.md`**, which did not exist. It documents the three
  independent places the image tag is pinned (`Chart.yaml: appVersion`,
  `values.yaml: image.tag`, `deploy/kubernetes/deployment.yaml`) and how to check they
  agree — the check that would have caught the `v1.8.1` defect below — plus the four-step
  migration rollback, in order, with what it costs.
- **`docs/releases/2.0.1.md`**, the longer write-up: what each dead component claimed versus
  what it did, the four caller-observable changes, the upgrade path, and the known gaps.
- **`scripts/uninstall.ps1` / `scripts/uninstall.sh` — a way out that is as short as the way in.**
  Removing the product was three paragraphs of prose in `AGENTS.md` §19 and nothing else, which is
  how a governance tool becomes the thing people rip out badly: half-deleted, or with the signing
  key gone. The script is a **dry run by default** — it prints every file it would remove, says what
  that costs (the audit trail and the receipts in that database; chains already exported keep
  verifying), and exits. `-Yes` / `--yes` goes through with it. Two guards that matter: it
  **refuses** to delete anything while a governed process still holds the database, and it
  **keeps the signing key** unless you spell out `-IncludeKey` / `--include-key`, because deleting
  that makes every receipt ever exported from this machine permanently unverifiable — including
  copies already in someone else's hands. It ends by saying plainly that the agent is now
  ungoverned, rather than leaving that to be assumed. Surfaced in the README next to the one-prompt
  setup, so both directions are visible from the front page.

### Fixed

- **The rate limiter never fired during the first hour of host uptime.** `Instant`'s epoch is
  implementation-defined — on Windows it is system boot — so when `now` is closer to that epoch than
  the window, `now.checked_sub(window)` returns `None`. All five call sites spelled that
  `.unwrap_or(now)`, which reads as "the window starts now" and therefore **excluded every prior
  timestamp instead of including them all**. Consequences, measured on one build: `check_rate` pruned
  each key's vector to empty on every call, so all three counters read zero and the limiter allowed
  everything — **80 of 80 calls at a configured 60/min, 5 of 5 at 1/min**; `cleanup` dropped every
  window it touched; `status` reported zero traffic. A/B on the **same binary**: uptime 00:59:50 → 0
  refusals in 80; uptime 01:03:28 → 70 refusals. Above an hour it rate-limits correctly, which is why
  the three end-to-end rate-limiter tests read as flaky for eight releases rather than failing. The
  window predicate is now one function, `within_window`, with the `None` branch answering `true`, and
  two unit tests drive both branches from the other side so the assertion does not depend on the
  host's uptime.
- **`GET /v1/rate-limit/status/{agent}` reported zero traffic for every agent, forever.**
  `check_rate` records under the key `agent_id:tool_name` — the pipeline always supplies a tool
  name — while `status` looked up the bare `agent_id`, a key nothing ever writes. Found by
  driving a 2.0.1 build the way an operator would: 12 governed calls, `requestsLastMinute: 0`,
  and the very next call refused with "Rate limit exceeded". A status endpoint that always
  reports zero is worse than no status endpoint, because it reads as evidence that the limiter
  is idle — and it is what an operator checks *before* concluding the limiter is broken. It now
  reports the **maximum** over the agent's per-tool windows, which is the number comparable to
  the `config` shipped in the same payload: when they are equal, the next call on that tool is
  refused. Independent of the window defect above; fixing that one exposed this one.
- **`RateLimiter::cleanup()` had no caller anywhere in the tree.** The limiter prunes a key's
  timestamps when that key is used, but nothing ever removed the **keys**: `windows` gained one entry
  per `agent_id:tool_name` pair and never lost one, so a long-lived server accumulated a map entry for
  every tool every agent ever called. Wired into the existing periodic cleanup task. Deliberately not
  wired before the fix above, because until then this method dropped *every* window under an hour of
  uptime.
- **The containment layer never activated: 0 times out of 42 measured actions.** `should_sandbox` was
  fed `adaptive_result.total_score` while its thresholds (40 / 50 / 65) sit on the **composite** scale
  — the same scale as `threshold_review` 35 and `threshold_block` 70. The two do not overlap where it
  matters: across 42 actions the adaptive score spanned 9..40 while the composite spanned 2..84, so
  nothing ever reached any of the three thresholds, including `curl … | sh`, which scores 84 and
  blocks while charging adaptive 30. The layer now runs after the composite exists and is fed
  `risk.score`; 17 of the same 42 actions are now contained. `sandbox_result` is advisory — it is not
  part of the signed receipt and feeds no term of the composite — so this changes which responses
  carry a `sandboxResult` and changes no verdict, score, reason or signed byte.
- **`AgentProfile.toolTrust` was parsed, validated, exported, and then discarded by both storage
  backends.** Both row mappers hydrated a literal `0.7`, so the configured value never survived a
  round trip. Measured: an agent configured `toolTrust: 0.05` and an agent with no setting at all
  produced the identical reputation signal (score 28, "moderate trust: 0.60"), and
  `GET /v1/profiles/{id}` reported `0.7` for the agent configured at `0.05` — a silent policy loss
  with a read-back that confirmed the wrong value. Migration `0006_tool_trust` (SQLite + Postgres),
  idempotent backfill for existing community databases, rollback scripts, and
  `tool_trust_roundtrip.rs` to pin the round trip.
- **Three shipped CLI paths answered a *refusal* with success.** In each case the library underneath
  was correct *and covered by a test*; the thin adapter on top was neither, so the suite stayed green
  over all three. None touches a receipt byte, and the oldest dates to 1.1.0.
  - **`iaga proxy` wedged on the MCP handshake.** `forward_and_relay` waited for a reply to every
    forwarded message, including JSON-RPC *notifications*, which by definition never get one.
    `notifications/initialized` is the mandatory third step of the handshake, so **every
    spec-compliant MCP client** broke the proxy on its first connection: the downstream server was
    torn down and the next real request failed with `-32603`. The proxy now forwards a notification
    without waiting and without emitting a response line (JSON-RPC 2.0 §4.1). A `tools/call` arriving
    as a notification is malformed and is dropped rather than forwarded — and audited as a Block, so
    an attempt to invoke a tool outside governance leaves a durable record instead of a stderr line.
    `iaga mcp-server` was correct throughout.
  - **`iaga run` exited 0 when the kernel refused the launch.** On `Block`, on `Review`, and on the
    strict env-denylist fail-closed path, the child never starts, so `LaunchOutcome::exit_code` is
    `None` — and the CLI mapped that to process exit 0. `iaga run -- <blocked command> && next_step`
    therefore ran `next_step`. Now mirrors the `iaga inspect` convention: 0 allow / 1 review /
    2 block, with only an allowed launch propagating the child's own status.
  - **`iaga replay --export` wrote empty evidence and exited 0.** An unknown or mistyped `run_id`
    produced a file that reads as authentic — real `signer_key_id`, real `signer_verifying_key`,
    `"receipts": []` — and reported success, so nothing downstream could distinguish "exported the
    evidence" from "exported nothing". It now writes no file and exits 3. The Postgres-only message
    it prints alongside no longer claims a "1.0-alpha.1" restriction that has not existed for eight
    releases.
  - `crates/iaga-sentinel-core/tests/cli_refusal_contract.rs` pins all four exit paths against the
    real binary. Each test was confirmed to fail against the unpatched code first — the proxy case by
    hanging, which is what the old code did to a real client.
- **The TypeScript SDK followed redirects to the sidecar, which is a complete bypass.** `fetch`
  follows by default, so a `307` from the configured sidecar URL to an attacker-controlled server made
  `SentinelClient` return **that** server's `decision: "allow"` — with no evidence anywhere, because
  the real sidecar was never reached. Now `redirect: "manual"`, so the redirect status surfaces as an
  ordinary `SentinelApiError` and the caller's fail-open/fail-closed policy decides, rather than a
  transport exception bypassing that logic. The Python SDK (httpx, `follow_redirects` off) was already
  correct.
- **Three responses were not reproducible between identical runs.** `taintAnalysis.accumulatedLabels`
  serialized a `HashSet`, whose iteration order depends on the hasher's per-process seed (45 differing
  array positions across two identical runs of the same 42 actions); `/v1/sessions` listed a `HashMap`
  (62 moving positions); and both receipt stores ordered `list_runs` by `last_ts` alone, which is not
  a total order, so runs written in the same second tied and the tie broke differently on every call
  (50 moving `run_id` positions). None reached a signed field, so no receipt byte moved — what they
  did was make a response impossible to diff byte-for-byte, one code change away from a
  nondeterministic receipt. All three are now ordered at the source.
- **The MCP stdio planes read lines of unbounded length.** Both `iaga mcp-server` and `iaga proxy`
  read from stdin with `BufReader::lines()`, which grows a `String` until it finds a newline: a
  downstream server or a client that never emits one could take the process to OOM. Capped at 2 MiB,
  aligned with the HTTP body limit, and cancel-safe because the proxy reads inside a `tokio::select!`.
  Verified live: a 3 MiB line exits 1 with nothing processed.
- **Deploy manifests shipped a three-release-old image from a namespace CI no longer publishes to.**
  `helm install` of this chart labelled every object with the current version and then pulled
  `ghcr.io/edoardobambini/iaga-sentinel:v1.8.1`. Since 1.9.0 CI publishes to
  `ghcr.io/iaga-team/iaga-sentinel` (`GITHUB_TOKEN` carries `packages:write` for the owning org, so a
  personal namespace 403s). The chart, `deploy/kubernetes/deployment.yaml`, both plug-in
  `docker-compose.yml` files, `plug-ins/README.md`, `README.md` and `AGENTS.md` now all point at the
  namespace releases actually land in, at `v2.0.1`. Tags published before 1.9.0 under the old
  namespace still resolve; nothing new is pushed there.

  > **Correction (2026-08-09).** The sentence above — "Since 1.9.0 CI publishes to
  > `ghcr.io/iaga-team/iaga-sentinel`" — is wrong, and was wrong when it was written. That
  > namespace has never held a package: the `v2.0.1` tag push uploaded every layer and then failed
  > the manifest with HTTP 403, for organisation-side reasons recorded in
  > `.github/workflows/docker.yml`. Measured again on 2026-08-09:
  > `docker pull ghcr.io/iaga-team/iaga-sentinel:latest` returns `unauthorized`, and the registry
  > refuses an anonymous token. The user-facing quickstarts now build the image locally; the deploy
  > manifests still name the intended coordinates and say plainly that you must supply the image.
- **The repository URL is now consistently `IAGA-TEAM/IAGA-Sentinel`.** Two identities had been
  coexisting: `README.md`'s install command and `AGENTS.md` pointed at the org, while `Cargo.toml`
  `repository`, `CITATION.cff`, `CONTRIBUTING.md`'s clone line, `docs/openapi.yaml`, the Helm chart's
  `sources`, and the SDK/plug-in package metadata still pointed at the personal namespace. The
  CHANGELOG entry recording the 1.1.0 rebrand is left as written — it was true then — and the chart's
  `maintainers[].url` still points at the maintainer's own profile, because that is a person and not
  the repository.
- **No `.dockerignore`.** The Dockerfile reads only `Cargo.toml`, `Cargo.lock`, `crates/`, `LICENSE`
  and `THIRD_PARTY_NOTICES.md`, but the whole working tree was uploaded as build context — including
  `target/` (6-10 GB once built locally), `node_modules/` and `.venv/`. Added, with the paths the
  runtime stage does copy called out explicitly so it cannot silently starve the build.
- **`*.db` did not cover SQLite's sidecar files**, so `iaga_shared.db-journal` survived a run of
  `scripts/agent_bootstrap.*` as an untracked file. `.gitignore` now covers `-journal`, `-shm` and
  `-wal`.
- **`docs/openapi.yaml` documented an API that does not exist.** `/v1/response/scan` was specified as
  `{text, agentId}` returning `{clean, findings:[objects]}`; the real contract is
  `{requestId, agentId, toolName, responsePayload}` returning
  `{requestId, decision, riskScore, findings:[string], redactedPayload?}`, and the `ResponseDecision`
  enum was absent from the file entirely. A client built from the spec got a 422. `SensitivePattern`
  also carried a non-existent `enabled` field and the wrong category enum (the real ones are `pii`,
  `financial`, `credential`).
- **The same for the rate-limit schemas.** `RateLimitConfig` was specified as
  `{requestsPerSecond, burstSize, windowSeconds, cooldownSeconds}`; the real body is
  `{maxPerMinute, maxPerHour, burstLimit}`, and none of the three carries a serde default, so a
  request written from the old spec is rejected outright — **measured: `POST /v1/rate-limit/config`
  with the documented body returns 422**, the corrected body returns 200. `RateLimitStatus` was
  specified as `{allowed, remaining, limit, resetAt}`; not one of those fields exists. The real
  response is `{agentId, requestsLastMinute, requestsLastHour, requestsLast5Seconds, config}`.
- **`AGENTS.md` documented a config-file behaviour the code does not have.** It listed six candidate
  filenames (there are three) and said the file is imported "if the DB is fresh". It is re-imported on
  **every** boot and upserts every profile and workspace, so anything changed in the database by
  another route is silently overwritten on the next start — the opposite of what the file claimed. It
  also now says which `agentId` to be **before** connecting (`404 agent_not_found` on the first
  `iaga.inspect` is the most common first-run failure), probes over `127.0.0.1` rather than
  `localhost` (measured **2065 ms against 47 ms** on a host where `localhost` resolves `::1` first,
  and an outright failure under a short timeout), and carries a new §19 the agent hands to the human:
  how to look at it, change it, turn it off, and the one file whose deletion makes every past receipt
  permanently unverifiable.
- **The dashboard's Evidence tab truncated every `run_id` to 16 characters**, so two different runs
  rendered as the same string and neither could be copied into `iaga replay`. The truncation was
  written when a run id was short; since 1.6.0 it is `<agentId>:<sessionId>`, and 16 characters no
  longer reach the end of the agent id — measured on a two-run server, both rows read
  `openclaw-builder`. The Evidence tab exists to answer "which run do I export and prove", so it now
  shows the whole id, with a `title` so it is also hoverable and copyable.
- **The demo runbook said a reset without relaunching was enough.** It is not: the session graph
  lives in the process, not the database, so a second take against the same live server inherits the
  first one's nodes. Measured: beat 1 comes back **REVIEW risk 35** instead of ALLOW, with
  `session graph attack: privilege_escalation_chain`, because the two takes share one `sessionId` and
  together read as `shell -> file_read -> shell`. The driver then correctly refuses the take — the
  system working, not a flaky verdict. `docs/demo/README.md` now says to stop and restart the server,
  and qualifies "identical every run" as "every run against a freshly started server", naming the two
  pieces of state the weights reset does not cover (the session graph and per-agent NHI trust).
- **`AGENTS.md` §10 documented exit codes for `inspect` and `iaga-verify` but not for the two
  commands this release changes.** `iaga run` now exits 0/1/2 like `inspect`, and
  `replay --export` exits 3 on a run with no receipts — both are the point of the fixes above, and
  both are what a shell script keys on. The two rows now say so, and the `replay` row also spells
  out that a `run_id` is `<agentId>:<sessionId>` (what `--list` prints), which is the shape the
  dashboard was truncating.
- **`AGENTS.md` §17 presented itself as the server environment-variable reference and was missing
  eleven of them**, including the two that decide whether a denylisted variable strips or fails a
  launch closed (`IAGA_SENTINEL_ENV_DENYLIST`, `..._STRICT`) and the four that move a verdict by
  reshaping the session graph (`MAX_SESSIONS`, `SESSION_TTL_MS`, `BLOCK_COOLDOWN_MS`,
  `MAX_BLOCK_COUNT`). All eleven are now listed with the defaults read from the code, grouped by what
  they affect. Cross-checked mechanically: every `IAGA_SENTINEL_*` the crates read now appears in the
  file, and every one the file names is read by something.
- **`SECURITY.md` declared the `1.7.x` line supported**, three minor releases back. It now declares
  `2.0.x` and records that older receipts keep verifying.
- **`DATA_HANDLING.md` described `policy_hash` as "a digest of the compiled policy bundle, or a
  default placeholder when no Dictum overlay is loaded".** That stopped being true when
  `CRYPTO-POLICYHASH-7a` bound the real resolved workspace policy: without an overlay the digest
  covers the workspace id, protocols, allowed domains, tools with their action types and max
  decisions, and the two thresholds, canonicalized so reordering any of those lists does not move
  it. An auditor recomputing the hash from the YAML as written would not have matched. The
  `agent_profiles.tool_trust` column is documented in the same file.
- **`docs/ARCHITECTURE.md` listed `replay` and `policy-test` as unshipped roadmap CLI commands.**
  Both have shipped for several releases. It also still said "8 layers in 1.x", and did not
  mention that layer 5 now runs after the composite score rather than in its listed position. Two
  long-standing gaps were added to the open list rather than left unwritten: session state is
  process-global rather than partitioned by workspace, and a `GET` to an allow-listed host can
  still carry data in its query string.
- **`CONTRIBUTING.md` capped the ADR range at 0019** (it is 0023), omitted `cargo fmt --check` and
  `--all-features` from the commands CI actually runs, and did not say that the Postgres tests
  report green when they are skipped — so an unset `IAGA_SENTINEL_TEST_PG_URL` looks exactly like
  a pass.
- **Two shipped example policies blocked ordinary traffic with `dictum-eval-error`.**
  `url_host(Null)` is an evaluation error, and an evaluation error on a `block` policy **fires** it
  (fail-closed, by design), so `block_offhost_http` in `examples/e2e/secrets_and_egress.dictum` and
  `block_off_allowlist_http` in `crates/iaga-sentinel-core/examples/policies/strict.dictum` blocked
  any `http` action carrying no `destination` — with a reason naming the evaluator rather than the
  policy. Both now probe `action.payload.destination` first. Anyone who copied these examples has the
  same bug.

### Security

- **`wasmtime` 36.0.8 → 36.0.13** (RUSTSEC-2026-0222, 3.8 low). Not in any shipped artifact — it is a
  dev-dependency of `iaga-sentinel-dictum` only, and both `Dockerfile` and the release workflow build
  with default features. Lock file only.
- **`tract-nnef` 0.21.12 is deliberately left at RUSTSEC-2026-0217** (6.1 medium, `--features ml`
  only, in no shipped artifact). Upgrading it forces `tract-linalg` to pin `time` down from 0.3.47 to
  0.3.41, which is affected by RUSTSEC-2026-0009 (**6.8 medium** — worse than the advisory it fixes),
  and the two constraints cannot both be satisfied inside `tract-onnx = "0.21"`. Escaping it means
  bumping to tract 0.23, an API-breaking change to an optional backend with no ONNX model in the tree
  to test against. Recorded as a trade-off rather than committed as a net-worse lock file.
  **The decision is now written down where it is enforced**: the advisory is listed in
  `.cargo/audit.toml`, which CI's `cargo audit` step reads, with the measurement behind "in no
  shipped artifact" spelled out (`cargo tree -p iaga-sentinel-core -i tract-nnef` prints nothing;
  `Dockerfile` and `release.yml` both build with default features; `ml` is not in `default`). Until
  now it was written only in release notes while the check kept failing — `cargo audit` fails on
  `main` today for the same reason, since 2.0.0 shipped the same tract version and the advisory
  predates it. A red check nobody can act on is how real findings stop being read.

---

## [2.0.0], 2026-07-24 — Fully Autonomous Agentic Usage and Setup

IAGA Sentinel can now be **stood up by an AI agent on its own**, from a clean checkout, with the policy
the agent authors **actually enforced on the calls the agent makes over MCP**. This release closes the
gap between "the agent connected" and "the agent is governed".

The central fix: `iaga mcp-server` (and `proxy`, `run`) built their state with **no policy overlay**, so
an agent's `.dictum` rules governed only actions a human sent over HTTP — never the ones the agent itself
made over MCP. Those calls appeared in the dashboard, but the verdict ignored the policy. They now take
`--policy`, exactly like `serve`; point both at the same file and the policy governs the MCP path too.
Because MCP verdicts now include the overlay (and its `policy_hash` is bound into the receipts those
surfaces sign), this is a major version bump.

### Added

- **`--policy <file>` on `mcp-server`, `proxy`, and `run`.** Each loads the Dictum overlay the same way
  `serve` does and binds its `policy_hash` into every receipt it signs. An agent's authored policy now
  governs the actions it takes over MCP, not just the ones typed into the HTTP API.
- **A `filesystem.write` MCP tool schema.** `file_write` over MCP was previously rejected as "no schema
  registered" and force-blocked regardless of policy; it is now validated (`path` + `content`) and
  governed normally.
- **Human-in-the-loop autonomous standing procedure in [`AGENTS.md`](AGENTS.md).** An agent derives its
  rules from its own memory/instruction files, shows them for approval (gate 1), brings the system up,
  makes two live test calls the user watches land on the dashboard (gate 2), then greets them.
- **`scripts/agent_bootstrap.ps1` / `scripts/agent_bootstrap.sh`** — one command runs the whole
  mechanical loop non-interactively (build → policy → serve → self-connect over MCP → two governed test
  calls → offline proof) and asserts the overlay is in force.
- **"Fully Autonomous Agentic Usage and Setup"** section in the README.

### Changed

- **Default service mode is now `sidecar`, not `gateway`.** `/health` reported `gateway` by default,
  contradicting the product's advisory-sidecar positioning. Set `IAGA_SENTINEL_DEFAULT_MODE=gateway` to
  opt back into the old label.
- **The MCP `intent` payload field is advisory.** A missing or short `intent` used to fail schema
  validation and force a `block`, silently escalating benign `allow` actions (e.g. a plain
  `filesystem.read`) over the MCP path. `intent` is now recommended-but-optional and never blocks on its
  own; structural fields (`path`, `command`, `method`+`destination`, `content`) still do.
- **The Dictum lexer tolerates a leading UTF-8 BOM**, so a `.dictum` saved by an editor (or PowerShell
  `Set-Content -Encoding utf8`) no longer fails to parse with `unexpected character` at 1:1.

### Fixed

- MCP `iaga.inspect` verdicts ignored a loaded policy overlay (the overlay lived only in the `serve`
  process). Verified: an identical `filesystem.read` returns `allow` with no overlay and `review` with
  the overlay loaded, attributed as `dictum[<policy>]` in `auditEvent.reasons`.
- Benign, well-formed MCP actions were force-blocked when they omitted `intent`.

Receipt bytes for the HTTP `serve` path and the wire contract are unchanged; existing receipts verify
unchanged. Receipts signed by `mcp-server` / `proxy` / `run` now carry the overlay's `policy_hash` when a
`--policy` is loaded (previously always absent).

---

## [1.9.2], 2026-07-23

Fixes a way to accidentally deny **all** traffic. A Dictum overlay policy that
referenced a context path the runtime never provides — a typo such as
`action.risk_score` instead of `risk.score` — used to load without complaint and
then block every action, including ones the policy had nothing to do with, with a
reason that pointed at the baseline rather than the policy. Two policies shipped
in this repository had exactly that bug.

Receipt bytes, the wire contract, and the Dictum language are unchanged; 1.9.0
and 1.9.1 receipts verify unchanged. The only behavioral change is that a policy
which could never have worked is now refused at startup instead of at runtime.

### Fixed

- **An unknown context path is rejected when the overlay loads.**
  `iaga serve --policy` now validates every path a policy references against the
  context the pipeline actually builds, and exits `2` naming the offending path
  and the valid roots. Previously such a policy loaded, then every request hit an
  eval error on the missing path, and the deliberate fail-closed rule
  (PIP-DICTUM-FAILOPEN) turned that into a block. **The fail-closed behavior is
  unchanged and intentional** — an attacker must not be able to error a guard to
  disable it. What changed is that an authoring mistake no longer reaches the
  point where that rule applies.
- `crates/iaga-sentinel-dictum/examples/no_pii_egress.dictum` used
  `action.risk_score`, which does not exist, and blocked every `shell` action.
  It now uses `risk.score`.
- `crates/iaga-sentinel-core/examples/policies/strict.dictum` compared
  `action.tool_name` against `workspace.allowlist`, which holds domains, so the
  membership test was always true and it blocked every `http` action. It now uses
  `url_host(action.payload.destination)`.
- `crates/iaga-sentinel-dictum/examples/sample_context.json` described a context
  shape the runtime never produces; it now mirrors the real one.

### Added

- `iaga_sentinel_dictum::collect_paths`, which returns every context path a
  program references from both `when` and `evidence`. The language crate stays
  host-agnostic; the embedder supplies the schema.
- A load-time warning when a policy references a root that exists only under some
  configurations (`usage`, `budget`, `ml`), pointing at the guard idiom
  `when budget.limit and usage.session_cost_usd > budget.limit`. These remain
  legal, so they warn rather than fail.
- Regression tests: an unknown path, an unknown root and a path below a scalar
  leaf are each refused at load; the always-present roots load; the shipped
  example policies must load; and `schema_matches_built_context` fails if the
  accepted schema and the built context ever drift apart.

---

## [1.9.1], 2026-07-23

Documentation release: **no change to runtime behavior, the public wire
contract, the receipt schema, or the Dictum language.** Signed receipts produced
by 1.9.0 verify unchanged. Ships `AGENTS.md`, a self-contained bootstrap manual
that lets a human or an LLM agent stand the system up from a clean checkout, plus
corrections to how Dictum's runtime behavior was described — every claim below was
verified against a live server rather than read off the source.

### Added

- **`AGENTS.md`**, a self-contained bootstrap manual: repository layout, the
  nine-crate workspace, build and run, the `iaga-sentinel.yaml` config, the HTTP
  API, auth and API-key bootstrapping, the embedded dashboard, Dictum, the CLI,
  receipts and offline verification, deploy, and every server environment
  variable. Written so an agent can follow it without prior context.
- A standing procedure for AI agents: encode your own operating instructions as a
  Dictum policy, load it as an overlay, connect over MCP, and tell the user the
  dashboard URL and which rules are in force.
- MCP documentation covering the verified stdio handshake (`initialize` →
  `tools/list` → `tools/call`), the two exposed tools `iaga.inspect` and
  `iaga.response_scan`, Claude Desktop / Cursor configuration, and `mcp-doctor`.
  Documents that `iaga mcp-server` is stdio-only and that sharing one
  `DATABASE_URL` with `iaga serve` is what makes MCP-governed actions visible in
  the dashboard.

### Documented

- **A Dictum policy referencing a context path that is absent at runtime blocks
  every action, including unrelated ones.** A missing path resolves to null, the
  ordering operators have no null case and raise an evaluation error, and an
  evaluation error on a `block`/`review` policy fails closed. The default build
  triggers this for budget policies, because `budget.limit` only exists when
  `IAGA_SENTINEL_SESSION_BUDGET_USD` is set. Neither `policy lint` nor `policy
  check` catches it. Documents the working guard, `when budget.limit and …`.
- Policy attribution is surfaced in `auditEvent.reasons` as
  `dictum[<name>]: <reason>`, **not** in `risk.reasons`, which carries only
  baseline reasons — which is why a policy-driven block can look unexplained.
- `policy_hash` is the SHA-256 of the **compiled policy AST**, not of the file
  bytes: reformatting and comments leave it unchanged, any semantic edit changes
  it, and it is bound into the signed receipt.
- The `usage` object on `/v1/inspect` requires `provider` and `model`, and its
  token fields are `promptTokens` / `completionTokens`. Spend counts toward
  subsequent requests, so the request that exceeds a budget is itself allowed.
- Two shipped example policies parse and type-check but over-block at runtime and
  must not be copied: `crates/iaga-sentinel-dictum/examples/no_pii_egress.dictum`
  references the non-existent `action.risk_score` and blocks every `shell`
  action, and `crates/iaga-sentinel-core/examples/policies/strict.dictum`
  compares a tool name against the domain allowlist and blocks every `http`
  action. Both are left in place for this release and flagged in `AGENTS.md`.
- `POST /v1/inspect` requires a **registered** `agentId` (an unknown one returns
  `404 agent_not_found`), shell payloads use the key `command`, and minting an
  API key ends open mode immediately — unauthenticated calls then return `401`
  even with `IAGA_SENTINEL_OPEN_MODE=true`.

---

## [1.9.0], 2026-07-19

An **evidence-integrity and deployment** release, closing an external code
review. Three things stop being best-effort: an operator can now demand that no
verdict ships without its receipt, the governance scope is derived from the
agent profile instead of the request body, and the deployment artifacts produce
a server that is actually reachable and keeps its signing key. Default
behaviour is unchanged and receipt bytes are identical: the fail-closed trade is
opt-in, and every existing chain still verifies.

This release also folds in the community pull requests merged since 1.8.1
(#5, #6, #8, #9, #10, #11, #12) and the hardening that shipped with them.

### Added

- **Opt-in fail-closed receipts** (`IAGA_SENTINEL_RECEIPT_FAIL_CLOSED`). A
  receipt that cannot be signed and persisted normally leaves a gap between the
  SQL audit trail and the signed chain while the verdict ships anyway. Operators
  who position on cryptographic evidence can now invert that trade: with the
  variable set, the governance call fails instead of returning a verdict with no
  evidence behind it, and a server that cannot build a receipt logger at all
  refuses to start (`serve`, `proxy`, `mcp-server`, `run`) rather than silently
  governing unevidenced. **Off by default** — receipts stay advisory evidence and
  never fail the decision, which keeps the 1.8.1 behaviour byte for byte.
  Documented limits, because the guarantee has edges: the audit row is written
  before the receipt so a crash between the two still diverges; a verdict whose
  receipt was lost emits no SSE event and fires no webhook; and
  `iaga.response_scan` over MCP records no receipt in either mode.
- **Startup API-key bootstrap** (`IAGA_SENTINEL_BOOTSTRAP_API_KEY`). With open
  mode off and a fresh database — what every deployment artifact in this repo
  configures — the server answered `401` on every route until someone ran
  `iaga gen-key` by hand, and the resulting key was unknowable to clients
  configured in advance. The server now registers an operator-supplied admin key
  at startup, idempotently, and never logs it. Distinct from the client-side
  `IAGA_SENTINEL_API_KEY` the plug-ins read.
- **Helm chart and Kubernetes manifests** (#5), with the signer key on a
  writable volume so receipts can be generated under a read-only root
  filesystem.
  > **Correction (2026-08-09).** Wherever this release's notes say images
  > publish under `ghcr.io/iaga-team/iaga-sentinel`, they are wrong: that
  > package has never existed. See the correction under [Unreleased].
- CI now renders the Helm chart on every run: default values, a bring-your-own
  Secret, a supplied policy, and a rejected hex signer key.

### Changed

- **`workspaceId` and `tenantId` are no longer taken from the request body.**
  The workspace is derived from the agent profile; a request asserting a
  different one is refused with `403 scope_mismatch` instead of being evaluated
  against that workspace's thresholds, egress allowlist and tool policy. The
  tenant is derived from the profile, then the workspace policy; a supplied
  value is ignored rather than rejected, so existing callers do not break.
- **A config file that is present but unparseable is now fatal.** Previously the
  server logged a warning and continued with zero profiles and zero workspaces —
  configured-looking, governing nothing. A *missing* config file stays
  non-fatal.
- The sensitive-env denylist scrubbed from governed child processes grows to 24
  entries with the bootstrap credential.
- Docker images publish under `ghcr.io/iaga-team/iaga-sentinel`, matching the
  repository that owns the release tag. Tags published earlier under the
  previous namespace still resolve.
- Documentation honesty pass. The subhead now claims evidence "of every action
  an agent routes through it"; the sovereignty bullet becomes "Self-hosted, no
  vendor in the loop" with a claim about IAGA rather than about third parties;
  the Annex IV date is dropped, since Annex I and Annex III high-risk systems do
  not share one deadline. In the demo walkthrough the BLOCK beat no longer says
  the action is "stopped before it runs" — `/v1/inspect` is advisory and returns
  a verdict without intercepting, while `iaga run` blocks a launch outright — and
  the REVIEW beat's risk score is corrected from 41 to the 40 a clean first run
  actually produces.

### Fixed

- **Silent receipt-drop is now visible on the read API.** When a signed receipt
  is lost (append error or retry exhaustion) the SQL audit row still exists but
  the signed chain has a gap; `GET /v1/receipts/{run_id}` reported only the
  receipts that were present and could show the chain as valid with no signal of
  the divergence. The response now carries `receiptDropped` (bool) and
  `droppedReceipts` (count) so a compliance inspector sees the gap (#23).
- **Deployment paths lost the Ed25519 signing key on restart.** Docker Compose
  persisted only the database and the raw Kubernetes manifest used an `emptyDir`
  for the key directory, so the signer key was regenerated on every container or
  pod recreation, changing `signer_key_id` and breaking verification of every
  receipt signed before that point. Both now persist the key directory, matching
  what the Helm chart already did.
- **The Helm chart shipped a server with no policy.** `policy.config` was empty
  by default but still mounted over `/app/iaga-sentinel.yaml`, shadowing the
  valid example policy in the image. The mount is now conditional on a policy
  actually being supplied.
- **The Helm chart's liveness and readiness probes never rendered**, because
  `values.yaml` had no `enabled` key for the condition that gated them.
- **A bring-your-own Secret without a `receipt-signer-key` entry produced a pod
  stuck in `CreateContainerConfigError`**, because the signer-key `subPath` had
  nothing to bind. The mount is now gated on the inline value only.
- **`secrets.receiptSignerKey` was documented as hex but the loader requires 32
  raw bytes.** A 64-character hex string is itself valid base64, so it was
  accepted and decoded to 48 bytes, silently disabling receipts. The value is now
  base64 and a wrong length fails the template render.
- Receipt append retries back off between attempts, so two writers racing on the
  same `run_id` against a shared Postgres do not burn all five attempts at once.
- Session `block_count` no longer double-increments when the FSA and attack
  detection both fire (#10), the session DAG holds its lock across the full
  read-mutate cycle (#11), the cost budget check and add are atomic (#12),
  `EvalBudget::tick` increments after the exhaustion check rather than before
  (#9), `ReviewRequest` timestamps use the pinned decision time instead of a
  fresh `Utc::now()` (#8), and a redundant `#![cfg]` in the Dictum overlay is
  gone (#6).

### Security

- **Audit, receipt, and risk-feedback endpoints now require an admin-scoped
  key.** `GET /v1/audit`, `/v1/audit/export`, `/v1/audit/stats`, `/v1/receipts`,
  and `/v1/receipts/{run_id}` sat behind auth but not behind `RequireAdmin`, so
  an agent-scoped key could enumerate cross-agent audit events, risk scores, and
  signed receipt chains (#18). `POST /v1/risk/feedback` was likewise unguarded,
  letting an agent key floor the process-global adaptive risk weights and
  degrade static-pattern detection for every agent (#19). All six now return
  `403 admin_scope_required`, matching the existing admin surface; the OpenAPI
  spec documents the `403`.
- **`allowed_domains` egress allowlist could be bypassed via alternate payload
  fields.** The workspace egress check read only `payload["destination"]`, so an
  `http` action carrying its URL in `url`/`endpoint`/`href` evaded the domain
  allowlist and was silently allowed (#20). The extractor now scans
  `destination`, `url`, `endpoint`, and `href` and host-checks the first match
  against the allowlist.
- Policy and NHI mutations are admin-gated, response-side blocks are audited, and
  attestation replay is fixed.
- `crossbeam-epoch` bumped to 0.9.20 for RUSTSEC-2026-0204.

---

## [1.8.1], 2026-06-28

A **rebuilt Operator Console** and **cost visibility on by default**. The
governance kernel is unchanged, and signed-receipt bytes stay identical when a
caller reports no `usage` (golden vectors green) — enabling cost metering only
records usage the caller actually supplies.

### Added

- **Rebuilt Operator Console** (served at `/`): a structured multi-view app with
  a left section nav (Overview, Decisions, Agents, Live, Receipts, Telemetry,
  Audit, Reviews & sandbox, Cost, Security, Identity, Plugins, Settings) instead
  of one long page. Strict monochrome (ink-on-paper, brutalist, zero radius),
  system fonts, no external assets (stays air-gapped). The Overview leads with
  the posture question and live charts — governance activity over time, risk
  distribution, most-blocked tools — and every panel renders real endpoint data
  or an honest empty state that names the call to populate it.
- **Downloadable audit reports** (Audit view): fleet-wide or per single agent,
  with 7/30/90/365-day and all-time range presets, exported as **CSV, JSON, or a
  formatted PDF** (KPIs, charts, decision mix, models/frameworks, and the full
  action timeline). The PDF is produced through the browser print pipeline, so
  the console adds no dependency and works offline.
- **Settings view**: API-token connection, runtime/health status, refresh
  interval, and API-key create/list/delete.

### Changed

- **`cost-control` is on by default** (ADR 0020 revised). Token/cost metering,
  the `/v1/cost` API, the cost ledger, and per-model/agent/tool breakdowns are
  available out of the box, so the Cost view and audit reports surface real spend
  and the model(s) each agent used. Receipts stay byte-identical when no `usage`
  is reported (determinism and golden vectors unaffected); build with
  `--no-default-features` for the pre-1.5 wire.

### Fixed

- **Receipts panel** read the run summary with camelCase keys while the
  `/v1/receipts` wire is snake_case (`receipt_count`, `last_timestamp`,
  `terminal_verdict`); the receipt-count and last-seen columns now render.
- Internal cleanup: removed the empty legacy `policy_store` module and the unused
  `verify_all_policies`; the pipeline moves the canonical payload `Value` into
  plugin evaluation instead of cloning it.

## [1.8.0], 2026-06-26

Stronger **userspace process confinement** for `iaga run` and **reverse-shell
detection** in the threat-intel layer. Enforcement stays cooperative/userspace —
kernel eBPF/LSM confinement remains Enterprise (see
[ADR 0010](docs/adr/0010-oss-enterprise-boundary.md)), `iaga kernel status`
reports the posture honestly, and every OSS receipt still carries
`is_authoritative: false`. The default build and signed-receipt bytes are
unchanged from 1.7.2 (golden vectors green, including the frozen
`is_authoritative` shape).

### Added

- **Userspace child hardening** (`UserspaceKernel`): an allowed `iaga run` child
  is now spawned under `setsid`, with core dumps disabled (`RLIMIT_CORE = 0`),
  no-new-privileges (`PR_SET_NO_NEW_PRIVS`, Linux), and reaped with its parent
  (`kill_on_drop`). These are unprivileged POSIX/Linux controls, not eBPF/LSM
  kernel enforcement; `is_authoritative()` stays `false`.
- **Reverse-shell threat patterns**: netcat `-e`/`-c`, `bash` redirection to
  `/dev/tcp`, and `socat … EXEC` are flagged `critical`; recursive `chmod` is
  matched by regex so `chmod -R 777 /` is caught while `chmod +x` stays clean.
- **CI `notices` job**: regenerates `THIRD_PARTY_NOTICES.md` with pinned
  `cargo-about` and fails if it has drifted from `Cargo.lock`.

### Changed

- **`iaga kernel status`** copy clarified and a `containment:` line added
  (env-scrubbed, reaped); the boot banner now reads "EU AI Act conformity
  evidence" instead of the retired "Zero-Trust Security Runtime" framing.
- **`iaga run` default agent**: the `cli-runner` agent and a `ws-cli` workspace
  are seeded, so process governance works out of the box (a few harmless
  read-only commands auto-allow; everything else stays governed by the risk and
  threat-intel layers).
- **Documentation honesty pass**: corrected `docs/openapi.yaml` from "12-layer"
  to "8-layer" (two advisory) and softened "mapped to Annex IV" to the honest
  "structured to support / help produce"; de-softened wording across the README,
  added a verb to the EU AI Act badge, and added nominative-use / non-affiliation
  notes where third-party framework names appear. Removed `docs/CASE_STUDY.md`.

### Fixed

- A brittle kernel test that spawned `cargo` (a rustup proxy that breaks under
  environment scrubbing) now uses an environment-independent command, so the
  hardening suite is deterministic on Linux and Windows.

## [1.7.2], 2026-06-22

The **VoltAgent plug-in** and a consolidated `plug-ins/` home. **Additive and
docs-only for the core:** receipts, policy evaluation, and the default build are
byte-identical to 1.7.1; no wire or receipt-field change.

### Added

- **VoltAgent plug-in** (`@iaga-sentinel/voltagent`, `plug-ins/voltagent-plugin/`): a
  drop-in, dependency-free (global `fetch` only) in-the-loop plug-in for the
  [VoltAgent](https://github.com/VoltAgent/voltagent) framework. `createSentinelHooks()`
  wires VoltAgent's `onToolStart` hook to `POST /v1/inspect`: `allow` runs the tool,
  `block` throws `ToolDeniedError` so `execute()` never fires, `review` is denied by
  default (`onReview: "allow"` to pass through). Optional `scanInput` (prompt-injection
  firewall) and `scanOutput`/`redactOutput` (secret redaction of tool output via
  `/v1/response/scan`). Fail-closed by default; every receipt stays
  `is_authoritative: false`. Verified end-to-end against a real sidecar and a real
  LLM, with offline `CHAIN OK`.

### Changed

- **`plug-ins/` is the home for in-the-loop integrations.** Released plug-ins live as
  `*-plugin/` (e.g. `voltagent-plugin/`); the copy-paste framework integrations move
  there as `*-adapter/`. README, CONTRIBUTING, and the SDK adapter pointers follow.

---

## [1.7.1], 2026-06-19

Documentation and honesty hygiene. **No code-path or wire change:** receipts,
policy evaluation, and the default build are byte-identical to 1.7.0, and
receipts written by earlier releases still verify byte-for-byte unchanged.
Cut after a full audit pass (live end-to-end, tamper-evidence, determinism, and
the default plus `--all-features` test suites all green).

### Changed

- **Honest layer count.** The server boot banner read "12 Layers ARMED" and the
  historical `ARCHITECTURE.md` / `CASE_STUDY.md` notes claimed "12 layers"; the
  executable pipeline runs **8 layers** (two of them — sandbox and
  formal-verify — are advisory and do not change the verdict), plus four
  cross-cutting subsystems. The banner now reads "8 Layers ARMED" and the docs
  state the real count.
- **Documented the `cargo audit` advisory ignores.** `.cargo/audit.toml` now
  records, for each of the three ignored RUSTSEC advisories, the exact
  optional/compile-time path that pulls the crate (`rsa` via `sqlx-mysql`'s
  compile-time query macros, `fxhash` via `wasmtime`, `paste` via `tract`) and
  notes that none is in the default build. Re-verified with `cargo tree`.
- **Version and license hygiene.** The workspace version, the Python and
  TypeScript SDK manifests, and the BUSL `Licensed Work` line (still stamped
  `v1.6.0`) are aligned to the release.

### Fixed

- The README install snippet pinned a stale `--tag` (`v1.6.0`); it now matches
  the release tag.

## [1.7.0], 2026-06-17

OSS backlog closure toward the roadmap's 1.3-1.6 "cryptographic primitive" track:
the Dictum standard library grows deterministic builtins, the MCP wedge gains a
health-check and a Rust `GovernedTool`, the threat-feed *format* opens, SBOM
ingest learns SPDX, and plugins gain offline in-toto/SLSA attestation. **Fully
additive: no receipt field changed**, so receipts written by earlier releases
verify byte-for-byte unchanged, and every OSS receipt stays
`is_authoritative:false`. **No open-core ↔ Enterprise boundary moved** (ADR 0010):
where the faithful fix is Enterprise (verified SLSA, the curated/signed threat
feed, KMS/HSM, authoritative enforcement), OSS ships the honest mechanism and
leaves the Enterprise value intact.

### Added

- **Multilingual offline verifier (Python + Node), dependency-free.** The
  canonical Rust `iaga-verify` verdict is now reproducible on non-Rust stacks:
  `sdks/python/iaga_verify.py` (stdlib only, vendored Ed25519 RFC 8032) and
  `sdks/typescript/verify.mjs` (`node:crypto`) consume the same `ChainExport` and
  emit **byte-identical** `CHAIN OK … seq=0..N` output and exit codes
  (0 valid / 1 broken / 2 usage / 3 IO) as the Rust binary. Parity is anchored to
  a shared signed conformance vector (`sdks/conformance/golden_chain.json`, emitted
  by the canonical Rust code) and proven by `sdks/python/tests/test_iaga_verify.py`
  and `sdks/typescript/verify.smoke.mjs`. A new `python` CI matrix
  (ubuntu/macOS/windows × 3.11/3.12) gates the dependency-free verifier on every
  stack; the Node verifier parity smoke runs in the test job. A receipt carrying
  floats (`ml_scores`) is the one shape the re-serializers refuse rather than risk
  a divergent verdict — use the Rust verifier for those. (A browser WASM/WebCrypto
  build and `@iaga/verify` npm / `iaga-verify` PyPI packaging are follow-ups.)
- **`dictum-std` builtins `timestamp()` and `sha256()`.** Two pure, deterministic
  Dictum builtins. `timestamp(str) -> int` parses an RFC3339 instant to Unix epoch
  seconds, so a policy expresses temporal ranges with the ordinary numeric
  operators (`timestamp(action.ts) > timestamp(workspace.windowEnd)`) — no wall
  clock is read, so the verdict still replays bit-for-bit, and a malformed instant
  fails closed inside a Block/Review guard. `sha256(str) -> str` is a hex content
  digest (e.g. pin an approved payload by hash). NHI identity matching is
  intentionally omitted (redundant with `contains`/membership; verifiable
  asymmetric NHI is Enterprise, CRYPTO-NHI-2).
- **`mcp-doctor` CLI subcommand.** Spawns a target MCP server over stdio, drives
  `initialize` + `tools/list` as a client (the first MCP client driver in the
  tree), checks each tool's `inputSchema` is present and a well-formed JSON object
  (presence + shape, not a full JSON-Schema validator), optionally probes one
  named tool, and runs every listed tool through the same governance interception
  the `proxy` uses — reporting which calls the policy engine would allow / review
  / block. `--format json|table`; the report is always `authoritative:false`.
  Cooperative diagnostics: the governance check runs the real pipeline and writes
  a signed receipt per listed tool (proving each `tools/call` is encapsulable in a
  receipt), so it is not a pure read against the receipt store.
- **`iaga-sentinel-mcp` crate exposing `iaga::mcp::GovernedTool`.** A thin Rust
  client that maps an MCP `tools/call` into the public `InspectRequest`
  (`framework`/`protocol` = `mcp`), POSTs it to `/v1/inspect`, and runs the wrapped
  work only if the verdict is Allow — mirroring the Python/TS `GovernedTool`. A
  blocked call's work future is never polled. Fail-open by default
  (`.fail_closed(true)` to opt in), `is_authoritative:false`, no coupling to the
  core engine (it reuses the public `iaga-sentinel-integrations` client).
- **OSS threat-feed format `threat-intel.toml` + loader.** Point the server at a
  plain-text feed with `IAGA_SENTINEL_THREAT_FEED=path.toml`; its `[[indicator]]`
  entries are added to the built-in indicators. The *format* is open on purpose —
  the curated, signed Enterprise feed is a separate product, not a different
  format (ADR 0010). Loading is deterministic (no clock), so the `threatFeedHash`
  bound into each receipt stays reproducible against the exact indicator set. A
  malformed file is logged and skipped, so a bad config never disarms the
  baseline. Example at `examples/threat-intel.toml`.
- **SPDX SBOM ingest alongside CycloneDX.** `plugin verify` now accepts an SPDX
  JSON SBOM sibling (`<plugin>.spdx.json`) in addition to CycloneDX
  (`<plugin>.cdx.json`); the format is auto-detected (`parse_sbom_bytes`) and bound
  to the signed manifest the same way. Online Rekor inclusion / Fulcio root
  validation remain Enterprise (ADR 0013).
- **`iaga plugin attest --slsa-level N` (feature `plugin-manifest-signing`).** Emits
  an offline in-toto Statement v1 with a SLSA Provenance v1 predicate over the
  plugin's SHA-256; `--sign` wraps it in an Ed25519 DSSE envelope signed with the
  local BYOK signer. The SLSA level is recorded as **operator-declared build
  intent** (`declaredSlsaLevel` plus an in-band disclaimer), explicitly not a
  verified guarantee — offline OSS cannot attest hermeticity. Verified SLSA (Rekor
  inclusion + Fulcio keyless identity) remains Enterprise (ADR 0010/0013). No
  network access.

### Changed / Fixed

- **Logs go to stderr, never stdout.** `init_tracing` now writes to stderr in all
  formats, so the stdio MCP commands (`mcp-server`, `proxy`, `mcp-doctor`) keep
  stdout as a clean JSON-RPC channel — a log line on stdout had been corrupting the
  protocol for any MCP client.
- **`iaga-sentinel-integrations` `InspectRequest` gains an optional `protocol`
  field.** Elided when unset, so existing callers serialize byte-unchanged; the
  MCP `GovernedTool` sets it to `mcp`.
- **Retired the stale `gen_ai.*` OTel plan.** The receipt span describes a
  governance *verdict*, not an LLM call, so it carries `iaga.*` keys, not the
  OpenTelemetry `gen_ai.*` semantic conventions (which model prompts/tokens/model
  ids the verdict surface does not own). The earlier "`gen_ai.*` alignment lands in
  1.4" note is dropped rather than left as an open promise — emitting those keys
  here would misattribute a convention IAGA cannot populate honestly.

## [1.6.0], 2026-06-16

Hardening pass on the two product guarantees — a reproducible signed verdict and
a real, verifiable proof. **No open-core ↔ Enterprise boundary moved** (ADR 0010):
where the faithful fix is Enterprise, OSS ships an honest workaround and the
Enterprise value is left intact.

### Changed (signed-bytes / wire format — new receipts only)

- **Receipt `input_hash` now binds the action payload.** It was
  `SHA256(event_id ‖ agent_id ‖ tool_name)` with a *random* `event_id`, so it
  bound nothing about *what* the action did and was not reproducible. It is now
  `SHA256(agent_id ‖ tool_name ‖ input_sha256)`, where `input_sha256` is the
  SHA-256 of the canonical action payload (PROOF-INPUTHASH-BIND-3). The raw
  payload stays out of the receipt (privacy); only the digest is bound.
- **Signed verdict is now a pure function of (request + resolved policy +
  `decision_time` + ML digest).** A single `decision_time` is computed once per
  request, used as the receipt timestamp, and is the only clock the signed
  off-hours signal reads (DET-CLOCK-1). Signals derived from unregistered
  process-global mutable state — session/temporal burst, prior-block history,
  behavioral-fingerprint novelty/unusual-hours, adaptive baseline velocity —
  **no longer enter the signed score/decision/reasons**; they are surfaced as
  **advisory** on `GovernanceResult.advisory` for dashboards/alerts
  (DET-SESSION-2 / DET-BEHAVIORAL-2). Full session-state capture remains
  Enterprise.
- **ML tokenizer hash is now versioned and stable.** The reasoning-plane
  tokenizer (feature `ml`) replaced `std`'s `DefaultHasher` (SipHash, not stable
  across toolchains/targets) with vendored FNV-1a, so the signed `ml_scores`
  reproduce across builds and machines (DET-REASONING-1).
- **`policy_hash` now binds the real resolved policy.** With no Dictum overlay
  it was a constant placeholder (`SHA256("iaga-sentinel-policy-v0")`), so the
  workspace YAML that decides most verdicts was never digested. It is now the
  SHA-256 of the canonicalized resolved `WorkspacePolicy` (id, protocols,
  domains, tools + action types/decisions, block/review thresholds), stable
  under list reordering (CRYPTO-POLICYHASH-7a). With an overlay loaded the
  compiled Dictum bundle digest is still used.
- **`DictumEvalTrace` carries the real evaluation.** Its `policiesEvaluated` /
  `policiesFired` were hardcoded `0` / `[]`; they now reflect the actual
  evaluation, and a new optional `evidenceSha256` binds the SHA-256 of the fired
  policy's evidence value (not the raw evidence) into the signed bytes
  (PIP-DICTUM-UNBOUND / CRYPTO-POLICYHASH-7c). The trace stays capture-gated
  (`IAGA_SENTINEL_RECEIPT_CAPTURE=1`); `evidenceSha256` is elided when absent, so
  existing receipts are byte-identical.
- **Receipts bind the active threat-intel feed.** A new optional
  `threatFeedHash` records the SHA-256 of the active threat-feed indicator set
  (sorted by id), so the signed score is reproducible against the exact feed that
  produced it (DET-THREAT-1). Elided when absent, so older receipts stay
  byte-identical.
- **`run_id` is qualified by the agent.** A session-grouped run_id is now
  `agent_id:session_id` instead of the bare `session_id`, so two principals that
  pick the same `sessionId` can no longer interleave into one chain that verifies
  as Valid. `run_id` is in the signed bytes and the verifier already checks it is
  consistent across the chain, so this binds the principal with no new field
  (PIP-RUNID-COLLISION). `iaga replay <sessionId>` still resolves a bare session
  to its unique run. Tenant-scoped isolation remains Enterprise; session-less
  callers (run_id = event_id) are unchanged.

  These change the signed bytes of **new** receipts. **Receipts written by
  earlier releases still verify unchanged** — verification reads the stored
  bytes; only the derivation of newly written receipts changed.

### Added / Fixed

- **Chain integrity under concurrency.** The receipt store's `append` now
  validates the link against the current head inside the persistence layer and
  rejects an out-of-order `seq` / bad parent with `ChainViolation`; a concurrent
  `(run_id, seq)` collision surfaces as `DuplicateSeq`. The pipeline logger
  retries on a lost-head race instead of silently dropping the receipt, and
  emits `iaga_sentinel.receipts.signed` / `iaga_sentinel.receipts.dropped`
  counters (+`error!`) so a divergence between the audit trail and the signed
  chain is observable (SND-APPEND-RACE/DROP/NOCHECK, OBS-RECEIPT-DROP).
- **First-gate DoS fix** carried in: char-boundary-safe truncation in the
  injection firewall (attacker-controlled multibyte payloads no longer panic).
- **Honest attestation/verification:** plugin attestation separates
  "digest matches" from "signature verified" and supports operator-pinned-key
  Ed25519 verification; the offline verifier binds the printed `signer=` to the
  key that actually verified. Keyless Fulcio/Rekor identity remains Enterprise.
- **Dictum → WASM codegen declassed to non-canonical.** The tree-walk evaluator
  (`eval.rs`) is documented as the sole canonical executor; the feature-gated
  WASM codegen is labelled an experimental, non-canonical scaffold
  (i32-truncated, bitwise `and`/`or`) and removed from any proof claim. A
  faithful i64 codegen remains Enterprise.
- **Performance on the verdict hot path:** static risk regexes compile once
  (`Lazy`); the action payload is serialized once per request instead of three
  times.
- **Determinism is now tested:** an integration test re-runs the real pipeline
  twice with a pinned `decision_time` and asserts byte-identical
  `ReceiptBody::signing_bytes()`, plus a guard that `serde_json` keeps object
  keys ordered (`preserve_order` off). The governance OpenTelemetry span now
  carries the full decision context instead of only `agent.id`.
- **Stronger test coverage:** a labelled firewall corpus asserts an aggregate
  detection rate / false-positive baseline (TESTS-NO-ACCURACY-ASSERT-7); the
  chain tamper tests are parametrized over genesis/middle/head positions plus
  tail-truncation and middle-deletion (PROOF-CHAIN-EDGE-POS-5); and a property
  test asserts `signing_bytes` is a serialize→parse fixpoint
  (TESTS-FUZZ-NO-DETERMINISM-10). The demo's Allow→Review→Block flow and offline
  `CHAIN OK` are now end-to-end test-backed over real HTTP + the real offline
  verifier, so the recorded narration can't diverge from behaviour.
- **Operator dashboard surfaces the proof posture.** The live feed now shows the
  top signed *reason* on a Review/Block row, and **advisory** signals
  (burst/velocity/fingerprint novelty) as visually distinct dashed chips
  explicitly labelled *not part of the signed verdict* (advisory is now carried
  on the SSE event). The telemetry panel shows `receipts.signed` /
  `receipts.dropped`, flagging when the audit trail and the signed chain diverge.
  No new dependencies; the existing aesthetic is preserved.
- **Dictum overlay fails closed.** An eval error in a Block/Review policy's
  `when` now applies that policy's verdict (with reason `dictum-eval-error`)
  instead of being silently treated as no-fire — an attacker can no longer craft
  a payload that errors a guard to disable it (PIP-DICTUM-FAILOPEN). An erroring
  Allow policy cannot tighten, so evaluation keeps scanning for a stricter later
  policy; an `evidence` error keeps the verdict and drops the evidence (never a
  downgrade).
- **Per-policy Dictum budgets.** Each policy's `when` gets its own instruction
  budget and the fired policy's `evidence` a separate one, so one expensive
  expression can't starve later policies into a fail-open (DET-DICTUM-2).
- **Bundle-hash serialization error is fatal.** Computing a Dictum bundle's
  `policy_hash` no longer falls back to a constant on a serialization error
  (which would have signed a fake-but-valid hash); the host fails to load
  instead (CRYPTO-POLICYHASH-7b).
- **More wall-clock removed from the signed path.** Time-window policy rules now
  evaluate against the pipeline's single `decision_time` (not a fresh
  `Utc::now()`), and the configured `timezone` is honored for fixed offsets
  (`+02:00`, `Z`, …) — an IANA name falls back to UTC explicitly rather than
  silently guessing (DET-DICTUM-3). The NHI master seed is resolved once per
  process (was regenerated on every identity derivation when the env was unset),
  so derived identities/trust are stable within a run (DET-NHI-4); a short
  env-provided seed now warns (ERG-NHI-SEED-VALIDATION-1). Session-graph node
  ids are derived from the session + position + content instead of a random
  UUID, so the persisted/returned graph is reproducible (DET-SESSION-UUID-1).
- **Deterministic cost + ML scoring.** Token cost rounds each component to
  integer micro-USD and sums with `saturating_add` (specified, order-independent,
  overflow-safe) (DET-COST-1, feature `cost-control`); ML model scores are
  quantized onto a fixed `1e-6` grid before entering the signed `ml_scores`, so
  ULP differences across microarchitectures don't change the signed bytes
  (DET-REASONING-2, feature `ml`).
- **Receipt read-time integrity.** The receipt store now asserts the ordering
  `seq` column matches the `seq` inside the signed body on read, catching a
  divergent row instead of silently reordering the chain (DET-SEQ-COLUMN-5).
- **Signed plugin manifest binds the verifying key.** Verification now requires
  the trusted key that actually verifies the signature to be the one the
  manifest *declares* (`signer_key_id`), so with more than one trusted key a
  manifest signed by B can no longer claim `signer=A` and be reported as A
  (CRYPTO-MANIFEST-1, feature `plugin-manifest-signing`).
- **Offline verifier surfaces the chain range, honestly.** `iaga-verify` now
  prints `seq=0..N-1` on a `CHAIN OK`, and DATA_HANDLING documents that a
  `CHAIN OK` proves *prefix* integrity only — tail truncation is not detectable
  offline without an external anchor (Enterprise eIDAS B-LTA) (CRYPTO-EXPORT-TRUNC-7).
- **Kernel resolves the env denylist once.** The `UserspaceKernel` resolves the
  sensitive-env denylist at construction instead of re-reading the env + TOML on
  every launch, and logs a stable fingerprint of the scrubbed-variable set per
  governed launch so the secret-scrubbing posture is recorded (SOUND-KERNEL-1).
- **Secret detector no longer self-DoSes on benign numbers.** The Dictum
  `secret_ref()` credit-card pattern now requires a valid Luhn checksum, and the
  US SSN pattern requires an explicit SSN keyword, so an arbitrary 16-digit or
  `ddd-dd-dddd` value in a payload no longer forces a deterministic Block
  (CRYPTO-DICTUM-9).
- **NHI identity is labelled honestly.** The misleading `public_key_hex` field is
  renamed `key_commitment` (it is a symmetric HMAC commitment, not an asymmetric
  public key; old `publicKeyHex` JSON still deserializes via a serde alias, the
  DB column is unchanged), and the SPIFFE/PKI framing is removed from the module
  docs. Verifiable, relying-party-checkable asymmetric NHI is Enterprise
  (CRYPTO-NHI-2). The demo secret allowlist is clearly labelled as a demo, not a
  real vault (CRYPTO-SECRETS-1).
- **Receipt-store migration coexistence documented.** Investigated converting
  the receipt store to `sqlx::migrate!` (SND-MIGRATION-SPLIT-6) and deliberately
  kept the idempotent direct `CREATE … IF NOT EXISTS`: the receipt store can
  share one database with `iaga-sentinel-core`'s storage, which owns the single
  `_sqlx_migrations` table, so a second sqlx migrator would conflict and silently
  disable receipts. The reason is now documented in the code.
- **Rate-limit receipts declare non-replayability.** A rate-limit Block (which
  depends on `Instant::now()` + an in-memory window) now carries a
  `non-replayable:rate-limit` reason so the signed receipt is honest about not
  being reproducible by replay (DET-RATELIMIT-1).

## [1.5.6], 2026-06-15

The policy DSL is renamed from APL (Agent Policy Language) to **Dictum**. This is a
staged rebrand, not a blind search and replace: the language name, the `.dictum` file
extension, and the code identifiers move to Dictum, while frozen wire artifacts stay
byte-identical and historical references keep resolving. No governance, enforcement, or
receipt behavior changes, and the signed-receipt format is preserved exactly.

### Changed

- **Language rebrand: APL / Agent Policy Language to Dictum.** Prose, comments, docs,
  ADR bodies, dashboard strings, and CLI help now read "Dictum". One continuity note,
  "Dictum (formerly APL / Agent Policy Language)", is kept at the canonical definition
  point so existing references and the AISEC paper citation still resolve.
- **File extension `.apl` to `.dictum`.** Every example, fixture, and end-to-end policy
  file is renamed; loaders, glob patterns, CLI examples, and the Dockerfile follow.
- **Crate, lib, and Cargo features renamed.** `iaga-sentinel-apl` to
  `iaga-sentinel-dictum`, lib `iaga_sentinel_apl` to `iaga_sentinel_dictum`, features
  `apl` to `dictum` and `apl-wasm` to `dictum-wasm`. Internal types follow: `AplError`
  to `DictumError`, `AplOverlay` to `DictumOverlay`, module `apl_overlay` to
  `dictum_overlay`.
- **Runtime reason label `apl[...]` to `dictum[...]`** on audit events and signed receipts.
- **ADR filenames** carrying `apl` renamed to the `dictum` form, with all
  cross-references updated.

### Compatibility

- **Receipt wire format unchanged.** The receipt field `apl_eval_trace` is deliberately
  preserved (the byte-frozen golden vectors pass), so receipts produced before 1.5.6
  still verify bit-identically.

See [ADR 0004](docs/adr/0004-dictum-mvp.md).

## [1.5.5], 2026-06-13

A tooling and documentation release. It adds a self-contained demo recording kit
so anyone can reproduce a live governance run and verify a signed receipt
offline, on their own machine. No product behavior changes: no enforcement,
policy, receipt, or API code was touched, only the workspace version and the new
demo assets. Verdicts are deterministic and the receipt chain verifies offline.

### Added

- **Demo recording kit under `scripts/` and `docs/demo/`.** `scripts/demo.ps1`
  (with the `demo.sh` twin) builds the binaries, resets the demo database for an
  identical seed, and serves the operator dashboard on `:4010`.
  `scripts/demo_run.ps1` (with `demo_run.sh`) drives three real verdicts through
  the live pipeline, Allow then Review then Block, under one shared session so the
  signed receipts form a single hash-chained run. It asserts every verdict so a
  non-deterministic take can never be recorded, then exports the chain and
  verifies it offline with `iaga-verify` (embedded and pinned key). The
  Windows-first recording runbook is in [`docs/demo/README.md`](docs/demo/README.md).
- **`Test me now (1.5.5)` section in the README** with the exact first-person
  steps to run the demo end to end, including the Linux and macOS variant.

## [1.5.4], 2026-06-13

Makes the Armor Policy Language enforce what it advertised and hardens the core
decision path. Two Dictum builtins become real, three core fixes land, and the
signed-receipt schema stays backward compatible: receipts from any prior release
still verify, and a receipt minted without a session id is byte identical to a
1.5.3 receipt.

### Added

- **Functional `secret_ref()` Dictum builtin.** It now scans the serialized payload
  subtree for credentials and PII (AWS, OpenAI, and GitHub keys, PEM private
  keys, generic api_key and password assignments, bearer tokens, database
  connection strings, SSNs, and card numbers) with a fixed, deterministic
  pattern set in `iaga-sentinel-dictum`. Previously it was a placeholder that always
  returned `false`, so secret-egress policies such as
  `crates/iaga-sentinel-dictum/examples/no_pii_egress.dictum` could never fire. Object
  payloads are scanned correctly now, instead of flattening to null before the
  check.
- **`url_host()` Dictum builtin.** Extracts the lowercased host from a URL
  (stripping scheme, userinfo, port, and path), so a policy can express a true
  per-host egress allowlist, for example
  `url_host(action.payload.destination) not in workspace.allowlist`. This
  defeats look-alike bypasses such as `hooks.slack.com.attacker.tld` that a
  substring match would let through.

### Fixed

- **URL-aware workspace egress allowlist.** `evaluate_policy` now normalizes a
  request destination to its host before matching `allowed_domains`
  (case-insensitively), so a full URL to an allowed host (for example
  `https://api.github.com/repos`) is no longer over-blocked. Bare-host
  allowlists are unaffected.
- **No reasonless verdicts.** A `block` or `review` forced by the policy layer
  now surfaces its human-readable cause (for example
  `destination ... is outside allowed workspace domains`) in the audit event and
  the signed receipt, instead of only the generic "escalated by security layers"
  note. The previously silent schema-validation block records a reason too.
- **Session-grouped signed receipts.** When a caller supplies an explicit
  `metadata.sessionId`, every action in that session shares a receipt `run_id`,
  so receipts hash-chain (seq 0, 1, 2, ...) into one tamper-evident Merkle run
  that `iaga-verify` validates end to end. Without a session id the behavior is
  unchanged (one receipt per run) and the receipt body stays byte identical to
  earlier releases.

See [ADR 0023](docs/adr/0023-dictum-secret-detection-host-egress.md).

## [1.5.2], 2026-06-12

Technical-debt remediation across the whole open build: hardening of existing
features, test-coverage closure, and CI/workspace hygiene. No new product
surface beyond minimal API-key scopes; signed receipts produced by any prior
release verify unchanged (now enforced by golden-vector tests), and every new
tunable defaults to the previous hardcoded behavior.

### Added

- **Verified-API-key cache**: the auth middleware no longer pays one
  `list_keys()` query plus an Argon2 verification on *every* request — verified
  keys (stored as SHA-256, never raw) are cached per server instance with a TTL
  (`IAGA_SENTINEL_AUTH_CACHE_TTL_MS`, default 60 s; `0` restores
  verify-every-request). Key deletion invalidates the cache immediately.
- **API-key scopes** (minimal, single-tenant): `admin` (default — identical to
  pre-1.5.2 keys; all existing keys stay admin via migration 0005) and `agent`
  (governance surface only). `iaga gen-key --scope agent --agent-id <id>` (the identity argument is
  required since 2.1.0), `scope` and `agentId` on
  `POST /v1/auth/keys`, and admin-only enforcement (403 `admin_scope_required`)
  on key/webhook/DLQ management, rate-limit config, threat-intel mutations, and
  plugin reloads. Multi-tenant/SSO/SIEM remain Enterprise (ADR 0010).
- **Network configuration**: `IAGA_SENTINEL_HOST` (bind interface, default
  `0.0.0.0`) and `IAGA_SENTINEL_CORS_ORIGINS` (comma-separated allowlist;
  unset keeps the permissive `Any` of previous releases).
- **Tunables for previously hardcoded constants** (defaults unchanged):
  session-graph cap/TTL/cooldown/strikes, background-cleanup cadence/age, and
  response-cache TTL/size (see README → Environment variables).
- **`POST /v1/risk/weights/reset`** (admin): drop feedback-learned adaptive-risk
  weight adjustments; the process-global weight behavior is now documented.
- **Strict env-denylist mode**: `IAGA_SENTINEL_ENV_DENYLIST_STRICT=1` makes
  `iaga run` fail closed (launch blocked) when the denylist TOML extension is
  unreadable or malformed, instead of silently degrading to the built-in list.
- **Pricing freshness**: the built-in price list now carries
  `BUILTIN_PRICING_EFFECTIVE_DATE` (also surfaced as `builtinEffectiveDate` on
  `/v1/cost/pricing`) and the server warns when it is older than 90 days.
- **ML failure visibility**: per-model inference failures are logged and
  recorded in a new additive `MlEvidence.failed_models` (elided when empty —
  serialized shape and receipts unchanged in the no-failure case).
- **Signer key permission posture**: on Unix a freshly created receipt signing
  key is re-checked post-write and creation fails if group/world accessible;
  loading a pre-existing loose key warns (`chmod 600` hint). Windows warns to
  restrict NTFS ACLs.
- **Test-coverage closure**: golden-vector tests freezing `signing_bytes()` for
  every receipt shape since 1.1; a live-Postgres receipts suite mirroring the
  SQLite one; Dictum tree-walk ↔ WASM differential tests (fixed corpus + 256
  property-based cases) plus clean-rejection checks for unsupported constructs;
  a mock-HTTP client suite for `iaga-sentinel-integrations` (verdict mapping +
  wire shape, no live sidecar needed); `iaga-verify` CLI smoke tests pinning
  the documented exit codes 0/1/2/3.
- **CI**: postgres:16 service container with real `--features postgres` test
  runs (receipts + core), a `cargo test --workspace --all-features` job, a
  `linux-bpf` scaffold compile check, and the cross-platform compile-sanity job
  promoted to a blocking status.
- **SDK e2e smoke in CI**: the test job now boots a real sidecar and runs the
  Python SDK adapter suite (previously auto-skipped without a server) plus the
  TypeScript `smoke.cjs` checks against it; a new
  `sdks/typescript/register-smoke-agents.cjs` helper provisions the fresh
  agent pool the smoke needs. The framework-heavy `tests/e2e` suites stay
  local-only.
- **Workspace hygiene**: declared MSRV (`rust-version = "1.88"`),
  `[workspace.lints]` shared by every crate (`unsafe_code = "deny"` among
  others), centralized `wasmtime` version and tokio dev-dependencies.

### Changed

- Raw IO failures now map to a dedicated `SentinelError::Io` and an `io_error`
  HTTP error body; previously they surfaced as `config_error`.
- The `linux-bpf` scaffold's block reason is now machine-readable
  (`bpf-loader-not-implemented: …`) so audit consumers can distinguish
  "loader not implemented" from a policy-driven block. Posture unchanged:
  `is_authoritative()` stays `false`; authoritative kernel enforcement is
  Enterprise (ADR 0010).
- `cargo audit` ignores consolidated into a single `.cargo/audit.toml` at the
  repo root (previously duplicated as CI flags).
- `ApiKeyRecord` gains a `scope` field (serde-defaulted to `admin` for old
  records); the `ApiKeyStore` trait gains `store_key_scoped` /
  `verify_raw_key_scoped` with backward-compatible default implementations.

### Fixed

- Corrupt JSON in storage rows (audit reasons/usage, workspace policies, rules,
  tenant metadata, NHI capabilities, sessions, taint labels, fingerprints) is
  no longer silently replaced by defaults: the same fallback now logs a warning
  naming the column, on both SQLite and Postgres backends.
- The background TTL-cleanup task now derives the durable taint-store prune age
  from the configured TTL instead of a hardcoded 3600 s.
- `docs/openapi.yaml` was three releases stale (frozen at 1.3.0): now at
  1.5.2 with every served route documented (receipts, cost API, audit
  export/stats, analytics, webhook DLQ, NHI challenge/verify, templates,
  workspace rules, plugins, policy overlay / reasoning / kernel status,
  risk-weights reset), admin-scope operations marked with their 403, and the
  `RiskWeights` / `HealthResponse` / error-code schemas corrected to match the
  actual wire shapes.
- The Python SDK `__version__` was stale at 1.4.0 while `pyproject.toml` said
  1.5.x; both now track the release version.

## [1.5.1], 2026-06-10

Patch release: a test-determinism fix only — no change to the open build's
runtime behavior, the public wire contract, or the receipt/cost schema.

### Fixed

- Deterministic adaptive-risk weight tests. The adaptive-risk weights are a
  process-global that `apply_feedback` mutates and `calculate_adaptive_risk`
  reads; in the test binary a parallel feedback test could lower the weight
  feeding a borderline assertion (`test_risk_high_risk_shell_rm_rf`) and fail CI
  nondeterministically. The risk-weight tests now serialize and reset to default
  weights via a new `reset_weights()` helper. Production behavior unchanged.

## [1.5.0], 2026-06-09

Cost control: meter, attribute, and cap LLM spend from the open build, fully
self-hosted (no external billing API), plus a deterministic response cache that
reduces spend on safe, repeated read-only tool calls. All additive and behind a
default-off `cost-control` feature — the default build is byte-identical to 1.4.0
and pre-1.5 signed receipts verify unchanged.

### Added

- **`iaga-sentinel-cost` crate**: canonical cost/usage types + a self-hosted
  pricing engine. `UsageReport` (wire, human USD) resolves to `UsageData` (the
  signed form; money is an integer micro-USD ledger). Local `PricingTable` (dated
  built-in, overridable via `IAGA_SENTINEL_PRICING_FILE`); a caller-supplied cost
  always wins (ADR 0020).
- **Cost on receipts + audit**: optional `usage` on the signed `ReceiptBody`
  (elided when absent, so pre-1.5 receipts stay byte-identical) and on audit
  events, with denormalized columns for fast aggregation (migration 0004).
- **Capture** of usage from `POST /v1/inspect` and the agent SDKs — a new optional
  `usage` field on the public wire contract, plus `with_usage` on the Rust client.
- **Observability**: `/v1/cost/{summary,by-agent,by-model,by-tool,over-time,budget,pricing}`,
  a "Cost Control" dashboard panel, and an `iaga cost` CLI.
- **Budget enforcement**: per-session cumulative spend (`IAGA_SENTINEL_SESSION_BUDGET_USD`)
  injected into the Dictum context as `usage.session_cost_usd` / `budget.limit`, so a
  policy can `when usage.session_cost_usd > budget.limit then block`; a non-Dictum
  fallback enforces the same cap. Stricter-wins: cost can only tighten a verdict
  (ADR 0020).
- **Deterministic response cache**: the MCP proxy serves an identical, safe,
  read-only tool call from cache instead of forwarding it; savings surface in the
  cost summary. Semantic caching is an Enterprise feature (ADR 0021).

### Notes

- The default build is unchanged; enable cost control with `--features cost-control`.
- Cost is reported by instrumented callers and priced locally — indicative, not an
  invoice. Session budgets are in-memory; durable spend, time-windowed budgets, and
  network/eBPF cost interception are Enterprise / follow-up work (ADR 0010).

## [1.4.0], 2026-06-09

Agent & framework integrations: put IAGA Sentinel in the loop of any agent stack,
one signed receipt per tool call. Cooperative governance (`allow` / `review` /
`block`, fail-open-by-default transport); every receipt still records
`is_authoritative: false`. All additive — no change to the receipt schema or the
existing public wire contract.

### Added

- **Python adapters** (`sdks/python/iaga_sentinel/adapters/`): `@governed` (custom),
  LangChain (`SentinelCallbackHandler`), LangGraph (`GovernedToolNode`), LlamaIndex
  (`IagaCallbackHandler`), Pydantic AI (`governed_tool`), OpenAI Agents SDK
  (`iaga_tool_guardrail` + `governed_tool`), CrewAI (`SentinelGuardrail`), AutoGen
  (`AutoGenSentinelHook`), Microsoft Agent Framework (`sentinel_middleware`), OpenAI
  (`sentinel_wrap_openai`), and MCP (`govern_tool`). Shared transport helper
  `_common.py`, fail-open by default (configurable via `fail_closed`).
- **TypeScript adapters** (`sdks/typescript/src/adapters/`): OpenAI
  (`sentinelWrapOpenAI`), Vercel AI SDK (`sentinelMiddleware`), LangGraph
  (`governedToolNode`), and MCP (`governMcpTool`); `failClosed` opt-in.
- **Claude Code** `PreToolUse` hook example (zero-dependency Python + Bash variants)
  and **Claude Agent SDK** examples (`canUseTool` for TS, `PreToolUse` hook for
  Python).
- **MCP `GovernedTool`** wrapper (Python + TS) for MCP servers you author;
  complements the existing `iaga proxy` transparent interception.
- **`iaga-sentinel-integrations` Rust crate**: a lightweight standalone async client
  (`SentinelClient` over `reqwest`) mirroring the public camelCase wire contract,
  decoupled from the pipeline internals (ADR 0019).
- **Examples** for all 15 framework integrations under `examples/integrations/`
  (runnable code + `*.policy.yaml` + README + an index and support matrix).
- **Tests**: dependency-free fakes drive every adapter against the live sidecar in
  CI (`sdks/python/tests/`, `sdks/typescript/smoke.cjs`), plus **real end-to-end
  tests** against the actual framework libraries (`sdks/python/tests/e2e/`,
  `importorskip`-guarded so CI stays green without them).

### License

Unchanged: BUSL-1.1 with Change License Apache-2.0 baked in.

---

## [1.3.1], 2026-06-08

The 1.3 conformity-closure patch: reconciles the shipped open build with the
1.3 roadmap's "verifier sovereignty" OSS track (ADR 0018). All changes are
additive, no breaking changes against 1.3.0. Receipts produced before 1.3.1
verify unchanged, the new optional field is elided when absent.

### Added

- ADR 0018: receipt honesty flag. `ReceiptBody` gains an optional
  `is_authoritative` field, populated `false` on every open-build receipt
  because OSS enforcement is soft (no authoritative kernel ships in the
  community edition; `UserspaceKernel::is_authoritative()` is `false`).
  Elided from `signing_bytes` when absent, so 1.3.0 receipts stay
  byte-identical and verify unchanged.
- OpenTelemetry receipt span now also carries the roadmap-named keys
  `iaga.receipt.id` (`run_id:seq`), `iaga.chain.head` (the receipt body
  hash) and `iaga.policy.verdict`, plus `iaga.is_authoritative`, alongside
  the existing `receipt.*` aliases. Full `gen_ai.*` GenAI semantic-convention
  alignment remains a 1.4 deliverable.
- Sensitive-environment scrub on `UserspaceKernel`: a denylist of 23 known
  secret-bearing variables (cloud and model-provider credentials, registry
  tokens, the receipt signing-key path) is stripped from every governed
  child environment, even when passed explicitly via `ProcessSpec.env`, and
  is extendable at runtime via a TOML file at `IAGA_SENTINEL_ENV_DENYLIST`.
- `verify-only` cargo feature on `iaga-sentinel-verify` (default-on), so the
  documented reproducible build
  `cargo build --release --no-default-features --features verify-only` is
  valid and stable across releases.
- CI now exercises the `otel-receipts` and `plugin-manifest-signing`
  features, 1.3 primitives that previously had no CI coverage.

### License

Unchanged: BUSL-1.1 with Change License Apache-2.0 baked in.

---

## [1.3.0], 2026-06-07

The conformity-evidence release: three additive, opt-in primitives that strengthen the trusted-evidence substrate, plus a repositioning of the public narrative around the EU AI Act conformity evidence layer. All changes are additive, no breaking changes against 1.2.0. Default behaviour and receipt bytes are unchanged with the new features off.

### Added

- ADR 0015: standalone receipt verifier. A new slim crate `iaga-sentinel-verify` (binary `iaga-verify`, no database, no async runtime, about 3 MB) verifies a signed receipt chain offline by reusing `verify_chain`. New CLI flag `iaga replay <run_id> --export <file.json>` writes a run as `{ run_id, signer_verifying_key, receipts }` for the verifier to consume. The expected public key is pinned with `--key`; the embedded key is a self-asserted fallback with a loud warning.
- ADR 0016: OpenTelemetry receipt export, behind the default-off `otel-receipts` feature, no new dependency. Each signed receipt also surfaces as an OTel span `iaga_sentinel.receipt` (run id, seq, verdict, input and policy hashes, risk score, signer key id) in the existing telemetry feed, visible via `GET /v1/telemetry/spans` and `/v1/telemetry/export`.
- ADR 0017: Ed25519-signed plugin manifests, behind the default-off `plugin-manifest-signing` feature, orthogonal to `plugin-attestation`. A plugin ships `<plugin>.manifest.json` plus a detached `.sig`; verification checks the plugin SHA-256 and the signature against a trusted-key list. New CLI `iaga plugins sign-manifest` and `iaga plugins verify-manifest --trusted-keys`.
- Data-handling and security documentation: `DATA_HANDLING.md` covering what a receipt contains, the default hashes-only PII posture, where data lives, the absence of call-home, and offline verification; plus a signing section in `SECURITY.md`. Both are linked from the README.

### Changed

- Public narrative repositioned from "zero-trust governance kernel" to the EU AI Act conformity evidence layer for AI agents. README, ENTERPRISE.md, the operator dashboard, contacts, and the project docs are reconciled to that frame and to the honest posture: soft enforcement today, authoritative eBPF/LSM on the Enterprise roadmap. The operator dashboard at `/` is restyled to a minimal theme.

### Removed

- The unwired `ui/` React visualization (the deferred Visual Plane scaffold), the `ui-embed` Cargo feature, and the optional `rust-embed` dependency are removed. The operator dashboard served at `/` is unaffected; it was never part of the `ui-embed` path. This drops the dead TypeScript and React surface and keeps the repository Rust-first.

---

## [1.2.0], 2026-05-28

The **primitive evolution release**: ships the 4 primitives that
ADR 0010 §3 reinstated to the OSS 1.2 roadmap. All changes are
**additive**; no breaking changes against 1.1.0. The
`IAGA Sentinel Enterprise` boundary (ADR 0010 §2, 20 categories)
is reaffirmed, see [`ENTERPRISE.md`](ENTERPRISE.md).

### Added

- [`docs/adr/0011-signer-trait-and-local-disk.md`](docs/adr/0011-signer-trait-and-local-disk.md) -
  `Signer` trait (async, object-safe) + `LocalDiskSigner` reference impl.
  `ReceiptSigner` becomes a type alias so every 1.0 / 1.1 callsite -
  production and test, compiles unchanged. `SignedReceiptLogger` now
  holds `Arc<dyn Signer>`, giving Enterprise builds a clean injection
  point for KMS-backed signers without ricompiling the OSS core.
- [`docs/adr/0012-drift-replay-additive.md`](docs/adr/0012-drift-replay-additive.md) -
  three new optional fields on `ReceiptBody` (`pipeline_inputs_capture`,
  `apl_eval_trace`, `ml_inference_inputs`), opt-in via host env
  `IAGA_SENTINEL_RECEIPT_CAPTURE=1`. New CLI flag
  `iaga replay --re-execute` surfaces per-receipt capture availability.
  Receipts produced with capture disabled are **byte-identical** to
  1.1, chain hashes and signatures stay stable.
- [`docs/adr/0013-plugin-attestation.md`](docs/adr/0013-plugin-attestation.md) -
  new Cargo feature `plugin-attestation` (default off) gates offline
  Sigstore bundle + CycloneDX 1.5 SBOM verification. Looks for sibling
  `<plugin>.sigstore.json` and `<plugin>.cdx.json` next to each WASM
  plugin; validates bundle well-formedness and confirms the payload
  digest matches the plugin bytes. New CLI subcmd
  `iaga plugin verify <path>`.
- [`docs/adr/0014-dictum-wasm-and-types.md`](docs/adr/0014-dictum-wasm-and-types.md) -
  Hindley-Milner type checker (Algorithm W) over the existing Dictum AST,
  always-available via `compile_with_types(src)` and the CLI
  `iaga policy check <file.dictum>`. New Cargo feature `dictum-wasm`
  (default off) adds a WASM codegen scaffolding for literal +
  boolean / numeric / comparison operations; `iaga policy compile`
  emits the module. The tree-walk evaluator remains canonical for the
  full Dictum surface, Path / Call / Membership are rejected by the WASM
  MVP with clear errors.
- New CLI subcmds (additive): `iaga replay --re-execute`,
  `iaga plugin verify <path>`, `iaga policy check <file.dictum>`,
  `iaga policy compile <file.dictum> [--output bundle.wasm]`.

### Changed

- Workspace version bumped to `1.2.0`. License **unchanged**
  (BUSL-1.1 + Change License Apache-2.0 baked-in).
- `ReceiptBody` gains three optional capture fields, elided from
  serialization when `None` (1.1 byte-equality preserved).
- `PluginManifest` gains three cfg-gated optional fields under
  `plugin-attestation` (`attestation`, `sbom`,
  `attestation_offline_verified`). All `None`/`false` by default.
- `PluginDigest` (in the receipt body) gains optional `attested`
  and `attestation_issuer`. Elided when `None`.
- `SignedReceiptLogger` now accepts `Arc<dyn Signer>` rather than
  the concrete struct. `ReceiptSigner` preserved as a type alias -
  zero breaking change for existing callers.

### Deferred (still OSS-eligible, no schedule)

- `iaga policy migrate` (YAML → Dictum converter), debt closure for
  ADR 0008, not a primitive evolution. Lands in 1.2.x or 1.3.
- Address the 3 RUSTSEC ignores in CI (`RUSTSEC-2023-0071`,
  `-2025-0057`, `-2024-0436`) via dependency hardening pass.
- Dictum WASM codegen full support for Path / Call / Membership +
  parity proptest tree-walk vs WASM. The 1.2 MVP ships scaffolding
  (literal + ops only); full coverage is 1.3.
- Postgres + macOS / Windows full CI matrix (1.2 adds compile
  sanity best-effort; promotion to required CI status is 1.3).

### Still Enterprise (boundary reaffirmed, see [`ENTERPRISE.md`](ENTERPRISE.md))

The OSS 1.2 primitive scope is intentionally narrow. The full
chain-of-trust / production-grade implementations remain in
IAGA Sentinel Enterprise per ADR 0010 §2 (20 categories), including:

- Native KMS SDK backends (AWS KMS / Azure Key Vault / HashiCorp
  Vault / PKCS#11 HSM) plug behind the new `Signer` trait but ship
  Enterprise-only.
- Forensic time-travel replay (event sourcing + DB-state-per-verdict
  temporal queries) vs OSS's input-capture-only drift replay.
- Planned hosted plugin marketplace + supply-chain support commitment
  + signed threat-intel feed integration vs OSS's offline-only Sigstore
  / SBOM primitive.
- Dictum AOT optimized codegen (cranelift opt-levels, WASI side-effects)
  + curated rule library + LSP / language server.
- All other ADR 0010 §2 categories: eIDAS qualified signature, managed
  key lifecycle, mesh tier-2, multi-tenant, Enterprise SSO, SIEM
  connectors, air-gap distro, EU AI Act + GDPR + DORA compliance pack,
  DPO dashboard, curated ML library, curated eBPF/LSM library,
  confidential-computing receipts, commercial support,
  conformity assessment notified-body, real eBPF/LSM loader,
  cross-platform kernel macOS/Windows, mesh single-cluster baseline,
  curated ONNX models + HF tokenizers.

---

## [1.1.0], 2026-05-23

A consolidation + rebrand release. 1.1.0 keeps 1.0.0's runtime
behaviour and API contract, but **renames the project Agent Armor →
IAGA Sentinel** across binary, crates, env vars, paths, and
identifiers (breaking for CLI / ops / crate consumers), and pins **how the OSS line is
positioned** relative to the planned IAGA Sentinel Enterprise commercial
edition.

The 1.0 GA shipped the full governance kernel concept: enforcement
kernel scaffold + `UserspaceKernel` cross-platform, signed Merkle
receipts, Dictum DSL with live overlay, probabilistic reasoning
framework, audit pipeline. That is the OSS contract preserved by
the **never retroactively remove** covenant in `ENTERPRISE.md`.

1.1 holds that line, no new runtime capabilities, and clarifies
the OSS↔Enterprise boundary in the public docs so that users and
would-be contributors know what to expect from the open-source
line going forward.

**Boundary clarification (canonical: [`docs/adr/0010-oss-enterprise-boundary.md`](docs/adr/0010-oss-enterprise-boundary.md)).**
Capabilities originally listed under "Deferred to 1.0.x" or
"Deferred to 1.1" in the 1.0.0 entry below have been re-scoped:

- **Reinstated to OSS 1.2 roadmap** (no fixed date; ships when
  ready, no breaking changes): Dictum WASM codegen + Hindley-Milner
  type checker (was 1.0.3), Sigstore + SBOM CycloneDX plugin
  attestation primitive (was 1.1), drift replay additivo + `iaga
  replay --re-execute` (was 1.1), `Signer` trait +
  `LocalDiskSigner` refactor (was implicit). These are primitive
  evolutions with no scale/UX value beyond what OSS already
  provides; keeping them OSS reinforces the open-core covenant
  without diminishing Enterprise.
- **Scoped to IAGA Sentinel Enterprise** (the planned commercial
  edition, currently in development): real Aya-rs eBPF/LSM loader on Linux
  (was 1.0.1), macOS Endpoint Security backend + Windows ETW/WFP
  backend (was 1.1), governance mesh single-cluster baseline + the
  pre-existing tier-2 multi-region active-active (was 1.1),
  curated ONNX reference models (intent-drift / prompt-injection
  / anomaly-seq) + HuggingFace tokenizer integration + calibration
  framework (was 1.0.2 + 1.1), four native KMS SDK signer backends
  AWS KMS / Azure Key Vault / HashiCorp Vault / PKCS#11 (was 1.1).
  These require specialist engineering at scale and are planned to ship
  in the Enterprise edition with contractual support, managed lifecycle,
  and a curated threat-intel feed.
  None shipped in 1.0 GA, the **never retroactively remove**
  covenant is preserved.

The Enterprise edition is where the EU AI Act + GDPR + DORA
compliance pack, DPO Dashboard, multi-tenant isolation, Enterprise
SSO, eIDAS qualified signature pipeline, native SIEM connectors,
air-gapped distribution, commercial support, confidential-computing
receipts, forensic time-travel replay, conformity assessment
notified-body workflow, and the curated AI-specific eBPF/LSM
program library also live. See [`ENTERPRISE.md`](ENTERPRISE.md) for
the concise Enterprise overview.

### Changed

- Workspace version bumped to `1.1.0`.
- [`CHANGELOG.md`](CHANGELOG.md), [`ENTERPRISE.md`](ENTERPRISE.md), and
  [`README.md`](README.md)
  updated to reflect the OSS↔Enterprise boundary clarification.
- ADR 0010 committed as the canonical public boundary note.

### Renamed (breaking)

- Complete rebrand **Agent Armor → IAGA Sentinel**: primary binary
  `agent-armor` → `iaga-sentinel` (short alias `armor` → `iaga`);
  crates `armor-*` → `iaga-sentinel-*`; library imports `agent_armor`
  / `armor_*` → `iaga_sentinel` / `iaga_sentinel_*`; env vars
  `AGENT_ARMOR_*` and `ARMOR_*` → `IAGA_SENTINEL_*` (clean break, no
  fallback); signer key dir `~/.armor/` → `~/.iaga-sentinel/`; default
  DB `agent_armor.db` → `iaga_sentinel.db`; API-key prefix `aa_` →
  `iaga_` (newly generated keys only, existing keys still validate);
  webhook headers `X-Armor-*` → `X-Iaga-Sentinel-*`; MCP tools
  `agentarmor.*` → `iaga.*`; public types `Armor*` → `Sentinel*`. The GitHub repository is now
  `EdoardoBambini/IAGA-Sentinel`.

### Added

- [`docs/adr/0010-oss-enterprise-boundary.md`](docs/adr/0010-oss-enterprise-boundary.md):
  canonical ADR documenting the 20-category Enterprise boundary +
  the 4 primitives reinstated to OSS 1.2 roadmap.

### Unchanged

- Runtime behaviour, verdict logic, receipt format (Ed25519 +
  Merkle), on-disk schema, Dictum/policy formats, feature flags, and
  the HTTP API contract (endpoints, camelCase JSON, Bearer auth) are
  identical to 1.0.0; existing API keys still validate. **Only
  identifiers were renamed (see Renamed above), behaviour did not
  change.**
- The covenant in `ENTERPRISE.md`: *Enterprise will never
  retroactively remove features from OSS. If something works in
  OSS today, it works in OSS forever.*

### License

Unchanged: BUSL-1.1 with Change License Apache-2.0 baked in. Each
release converts automatically and irrevocably to Apache-2.0 four
years after publication.

---

## [1.0.0], 2026-04-26 ("Fortezza")

Architectural leap from 0.4.0. The 0.4.0 sidecar HTTP gate becomes a
distributed, attested, replayable, probabilistically aware kernel for
autonomous AI agents. Every governance decision is now signed,
chained, and verifiable offline. Policy moves from YAML templates to
a typed deterministic DSL. ML is opt-in and produces evidence the
deterministic policy decides on.

### Fixed (GA pre-flight, after E2E smoke)

- **Dockerfile** rewritten for the workspace layout. Previous version
  pointed at the pre-M1 `community/` paths and shipped a stub binary
  that exited immediately. New Dockerfile builds the real binary
  single-shot and `docker compose up` is healthy on first attempt.
- CLI banner: "8 Layers ARMED" → "12 Layers ARMED" (consistent with
  the 1.0 marketing surface; M3.5 + M4 add 4 layers on top of the
  original 8).
- `iaga-sentinel-core` crate description: "(Community Edition)" →
  "(open-source edition)" for consistency with the new
  Community vs Enterprise docs.

### Added

- **Workspace split** into 5 crates under `crates/`: `iaga-sentinel-core`,
  `iaga-sentinel-receipts`, `iaga-sentinel-dictum`, `iaga-sentinel-reasoning`, `iaga-sentinel-kernel`.
  Single workspace `Cargo.toml` at the root.
- **M2, Signed Action Receipts.** Ed25519-signed records of every
  governance verdict, hash-chained per `run_id` (Merkle append-log).
  SQLite and Postgres backends. New CLI: `iaga replay --list`,
  `iaga replay <run_id>`, `iaga replay <run_id> --verify-only`.
  Signer key auto-generated at `~/.iaga-sentinel/keys/receipt_signer.ed25519`
  on first run, override via `IAGA_SENTINEL_SIGNER_KEY_PATH`.
- **M3, Dictum.** Typed DSL with deterministic
  tree-walk evaluator, instruction budget, short-circuit boolean
  evaluation, hash-linked replay safety. New crate `iaga-sentinel-dictum`. CLI:
  `iaga policy test <file.dictum>` and `iaga policy lint <file.dictum>`.
  WASM codegen for Dictum is tracked for 1.0.3.
- **M3.5, Probabilistic Reasoning Plane.** New crate `iaga-sentinel-reasoning`
  with always-available `NoopEngine` plus `TractEngine` (pure-Rust
  ONNX via `tract-onnx`) behind opt-in `ml` feature. Model SHA-256
  digests embedded in every receipt. CLI: `iaga reasoning info`.
  Pre-trained models ship in 1.0.2. *(See [1.1.0] entry for
  re-scoping: curated ONNX library lives in IAGA Sentinel Enterprise.)*
- **M4, Enforcement Kernel scaffold.** New crate `iaga-sentinel-kernel` with
  cross-platform `UserspaceKernel` (soft enforcement, every OS) and
  Linux `BpfKernel` scaffold under `linux-bpf` feature. New CLI:
  `iaga run [--agent-id ...] [--cwd ...] -- <cmd>` and
  `iaga kernel status`. The real eBPF/LSM loader lands in 1.0.1.
  *(See [1.1.0] entry: real Aya-rs loader re-scoped to IAGA Sentinel
  Enterprise; the OSS scaffold + honest posture continue in 1.x.)*
- **M5, `iaga run` traverses the full governance pipeline.** Every
  governed launch produces a signed receipt. Postgres receipt backend
  is wired automatically based on the `DATABASE_URL` scheme.
  Cargo feature composition: `iaga-sentinel-core/sqlite|postgres` transitively
  enables the matching `iaga-sentinel-receipts` feature.
- **M6, Dictum as live policy engine.** `iaga serve --policy <file.dictum>`
  loads an overlay merged stricter-wins with the YAML profile system.
  Receipts embed the SHA-256 of the active Dictum bundle in
  `policy_hash`. New CLI `iaga policy lint`.
- **UI embedded** in the binary via `rust-embed` behind `ui-embed`
  feature.
- **8 ADRs** documenting every architectural decision (`docs/adr/0001`
  through `0008`).
- **`iaga` short alias binary** alongside `iaga-sentinel`. Same entry
  point.

### Changed

- **Crate renamed**: package `iaga-sentinel` → `iaga-sentinel-core`. Binary
  name `iaga-sentinel` preserved for backward compatibility.
- **License**: stays on BUSL-1.1 with **Change License: Apache-2.0**
  baked into the licence. Each release converts automatically and
  irrevocably to Apache-2.0 four years after publication. See
  [ADR 0002](docs/adr/0002-open-source-license-and-scope.md) for the
  rationale and [`LICENSE`](LICENSE) for the legal text.
- **Defense-in-depth model**: 8 layers → 12 layers. The original 8 are
  hardened in M2-M5; M3.5 + M4 add supply chain attestation /
  blast radius enforcement / behavioral baseline / counterparty trust
  scaffolding.
- **All paths** `community/` → `crates/iaga-sentinel-core/`.
- **Cargo `default` features** for `iaga-sentinel-core`:
  `["demo", "sqlite", "receipts", "dictum", "reasoning", "kernel"]`.

### Re-scoped after 1.0 GA (boundary clarification, see 1.1.0 entry above)

> The lists below preserved verbatim from the 1.0 GA changelog for
> historical fidelity. The **2026-05-08 OSS↔Enterprise boundary
> clarification** re-scopes these capabilities, see the [1.1.0]
> entry above and [`docs/adr/0010-oss-enterprise-boundary.md`](docs/adr/0010-oss-enterprise-boundary.md).
> None of the items below shipped in 1.0 GA, so the **never
> retroactively remove** covenant is preserved.

#### Originally deferred to 1.0.x patch releases

- ~~**1.0.1**~~: real eBPF/LSM loader via `aya-rs` + LLVM 18. LSM
  hooks on `execve`, `openat`, `connect`, `sendto`. Landlock
  fallback. Cgroup jailing. Long-lived detached child handle
  ownership. **Re-scoped → IAGA Sentinel Enterprise.**
- ~~**1.0.2**~~: pre-trained ONNX models for intent-drift /
  prompt-injection / anomaly-seq, plus pluggable tokenizers shipped
  alongside model files. **Re-scoped → Enterprise** (curated ML
  model library with threat-intel feed + GPU acceleration).
- ~~**1.0.3**~~: WASM codegen for Dictum via `wasm-encoder`; full
  Hindley-Milner type checker. **Reinstated → OSS 1.2 roadmap.**

#### Originally deferred to 1.1

- Governance mesh (gRPC gossip, federated rate budgets, CRDT on
  receipt log). **Re-scoped → Enterprise** (single-cluster
  baseline + tier-2 multi-region active-active).
- macOS Endpoint Security + Windows ETW kernel backends.
  **Re-scoped → Enterprise** (signed/notarized turnkey).
- KMS / HSM signer backends for receipts. **OSS keeps the BYOK
  pattern** (filesystem-mount via `IAGA_SENTINEL_SIGNER_KEY_PATH`) and the
  `Signer` trait + `LocalDiskSigner` refactor (reinstated → OSS
  1.2 roadmap). **Re-scoped → Enterprise**: four native KMS SDK
  backends (AWS KMS / Azure Key Vault / HashiCorp Vault / PKCS#11
  HSM) + managed key lifecycle + eIDAS qualified signatures.
- GPU acceleration ML + native ONNX Runtime backend (`ort`).
  **Re-scoped → Enterprise** (curated ML model library).
- Drift replay with full pipeline re-execution against historical
  receipts (requires receipt schema change). **Reinstated → OSS
  1.2 roadmap** as additive (`iaga replay --re-execute`,
  schema-additive); the forensic *time-travel* variant (event
  sourcing + temporal queries DB-state-per-verdict) lives in
  Enterprise.
- Stateful cross-run anomaly detection. **Re-scoped → Enterprise**
  (curated ML model library `anomaly-seq`).
- HuggingFace tokenizers in `iaga-sentinel-reasoning`. **Re-scoped →
  Enterprise** (curated ML model library, paired with the curated
  ONNX models).
- `iaga policy migrate` (YAML → Dictum converter). **OSS-eligible**
  (small utility, debt closure for ADR 0008); not yet scheduled.

### Newly added to OSS 1.2 roadmap (reinstated primitives)

- Sigstore + SBOM CycloneDX plugin attestation primitive (closes
  Pillar 4). The hosted private marketplace + supply-chain SLA
  contractual layer remains Enterprise.

---

## [0.4.0], 2026-04-19 ("Azzurra")

The community runtime that proved the thesis. 8-layer defense in depth
behind a single `/v1/inspect` HTTP gate. Policy as YAML + templates.
SDKs in Python and TypeScript. SQLite + Postgres durable state.

See git history for the full 0.4.0 changelog.
