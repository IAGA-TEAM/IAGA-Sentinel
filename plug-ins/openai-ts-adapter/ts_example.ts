/*
 * Govern an OpenAI client's calls with IAGA Sentinel (TypeScript).
 *
 *   npm i openai @iaga-sentinel/sdk
 *   IAGA_SENTINEL_HOST=127.0.0.1 IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
 *   # register the agent (see README.md), then run with tsx:
 *   # set OPENAI_API_KEY in your shell, then:
 *   npx tsx plug-ins/openai-ts-adapter/ts_example.ts
 *
 * sentinelWrapOpenAI returns a drop-in proxy: every chat.completions.create /
 * responses.create is inspected through IAGA before the request is sent.
 * allow -> sends; block/review -> SentinelBlockedError / SentinelReviewError
 * (a dangerous prompt is blocked by the firewall before any spend).
 */
import OpenAI from "openai";
import { sentinelWrapOpenAI } from "@iaga-sentinel/sdk";

const client = sentinelWrapOpenAI(new OpenAI(), {
  agentId: "openai-ts-demo",
  baseUrl: "http://localhost:4010",
  // failClosed: true, // deny if the sidecar is unreachable (default: fail-open)
});

const res = await client.chat.completions.create({
  model: "gpt-4o",
  messages: [{ role: "user", content: "Summarize the README." }],
});
console.log(res.choices[0].message.content);
