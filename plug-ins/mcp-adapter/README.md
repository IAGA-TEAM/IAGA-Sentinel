# IAGA Sentinel — MCP `GovernedTool`

Govern the tools **of an MCP server you build**. `govern_tool` (Python) and
`governMcpTool` (TS) wrap a tool handler so every `tools/call` is inspected
through `POST /v1/inspect` before it runs: allow → runs and is receipted;
block/review → the call is refused. One signed receipt per `tools/call`.

> **Already have an external MCP server?** Use `iaga proxy` instead — it
> transparently intercepts every `tools/call` round-trip between client and
> downstream server, no code changes. This wrapper is for servers you author.

## Setup

```bash
cargo build --release --workspace
# open mode makes every unauthenticated caller an implicit ADMIN; the default bind host is 0.0.0.0
IAGA_SENTINEL_HOST=127.0.0.1 IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
```

Register the agent (unregistered agents return 404):

```bash
./target/release/iaga import plug-ins/mcp-adapter/mcp.policy.yaml
```

## Run

- **Python:** `python python_example.py` (needs `mcp iaga-sentinel`)
- **TypeScript:** `npx tsx ts_example.ts` (needs `@modelcontextprotocol/sdk zod @iaga-sentinel/sdk`)

`govern_tool` / `governMcpTool` accept `failClosed`/`fail_closed` to deny when the
sidecar is unreachable (default fail-open). Verify a receipt with
`iaga replay <run_id> --export` + `iaga-verify` (`is_authoritative: false`).
