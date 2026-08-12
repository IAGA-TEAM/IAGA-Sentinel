# IAGA Sentinel — Vercel AI SDK

Govern Vercel AI SDK generations. `sentinelMiddleware` wraps the model so each
`generate` / `stream` is inspected through `POST /v1/inspect` before it runs.

- **allow** → generates and a signed receipt is produced
- **review / block** → throws `SentinelReviewError` / `SentinelBlockedError`
- sidecar unreachable → fail-open by default (`failClosed: true` to deny)

## 1. Start the sidecar

```bash
cargo build --release --workspace
# open mode makes every unauthenticated caller an implicit ADMIN; the default bind host is 0.0.0.0
IAGA_SENTINEL_HOST=127.0.0.1 IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
```

## 2. Register the agent

```bash
./target/release/iaga import plug-ins/vercel-ai-adapter/vercel-ai.policy.yaml
```

## 3. Run

```bash
npm i ai @ai-sdk/openai @iaga-sentinel/sdk
# Set OPENAI_API_KEY in your shell, then:
npx tsx plug-ins/vercel-ai-adapter/ts_example.ts
```

```ts
import { wrapLanguageModel } from "ai";
import { sentinelMiddleware } from "@iaga-sentinel/sdk";

const model = wrapLanguageModel({
  model: openai("gpt-4o"),
  middleware: sentinelMiddleware({ agentId: "vercel-ai-demo", baseUrl: "http://localhost:4010" }),
});
```

## Receipts

```bash
./target/release/iaga replay <run_id> --export chain.json
./target/release/iaga-verify chain.json     # -> CHAIN OK  (is_authoritative: false)
```
