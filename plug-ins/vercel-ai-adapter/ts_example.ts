/*
 * Govern Vercel AI SDK generations with IAGA Sentinel.
 *
 *   npm i ai @ai-sdk/openai @iaga-sentinel/sdk
 *   IAGA_SENTINEL_HOST=127.0.0.1 IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
 *   # register the agent (see README.md), then run with tsx:
 *   # set OPENAI_API_KEY in your shell, then:
 *   npx tsx plug-ins/vercel-ai-adapter/ts_example.ts
 *
 * sentinelMiddleware wraps the model so each generate/stream is inspected through
 * IAGA first. allow -> generates; block/review -> SentinelBlockedError /
 * SentinelReviewError (a dangerous prompt is blocked by the firewall).
 */
import { generateText, wrapLanguageModel } from "ai";
import { openai } from "@ai-sdk/openai";
import { sentinelMiddleware } from "@iaga-sentinel/sdk";

const model = wrapLanguageModel({
  model: openai("gpt-4o"),
  middleware: sentinelMiddleware({
    agentId: "vercel-ai-demo",
    baseUrl: "http://localhost:4010",
    // failClosed: true, // deny if the sidecar is unreachable (default: fail-open)
  }),
});

const result = await generateText({ model, prompt: "Summarize the README." });
console.log(result.text);
