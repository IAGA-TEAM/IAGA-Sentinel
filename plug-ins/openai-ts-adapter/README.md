# IAGA Sentinel — OpenAI (TypeScript)

Govern an OpenAI client's calls. `sentinelWrapOpenAI` returns a drop-in proxy:
every `chat.completions.create` / `responses.create` is inspected through
`POST /v1/inspect` before the request is sent.

- **allow** → the request is sent and a signed receipt is produced
- **review / block** → throws `SentinelReviewError` / `SentinelBlockedError`
- sidecar unreachable → fail-open by default (`failClosed: true` to deny)

A dangerous prompt (e.g. one carrying `curl … | sh`) is blocked by the injection
firewall **before** any OpenAI spend.

## 1. Start the sidecar

```bash
cargo build --release --workspace
# open mode makes every unauthenticated caller an implicit ADMIN; the default bind host is 0.0.0.0
IAGA_SENTINEL_HOST=127.0.0.1 IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
```

## 2. Register the agent

```bash
./target/release/iaga import plug-ins/openai-ts-adapter/openai-ts.policy.yaml
```

## 3. Run

```bash
npm i openai @iaga-sentinel/sdk
# Set OPENAI_API_KEY in your shell, then:
npx tsx plug-ins/openai-ts-adapter/ts_example.ts
```

```ts
import OpenAI from "openai";
import { sentinelWrapOpenAI } from "@iaga-sentinel/sdk";

const client = sentinelWrapOpenAI(new OpenAI(), { agentId: "openai-ts-demo", baseUrl: "http://localhost:4010" });
await client.chat.completions.create({ model: "gpt-4o", messages: [...] }); // inspected first
```

## Receipts

```bash
./target/release/iaga replay <run_id> --export chain.json
./target/release/iaga-verify chain.json     # -> CHAIN OK  (is_authoritative: false)
```
