/*
 * Govern a Claude Agent SDK (TypeScript) run with IAGA Sentinel via the
 * `canUseTool` permission callback. Every tool the agent wants to run is
 * inspected first; IAGA denies dangerous ones (e.g. `curl ... | sh`).
 *
 *   npm i @anthropic-ai/claude-agent-sdk @iaga-sentinel/sdk
 *   IAGA_SENTINEL_HOST=127.0.0.1 IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
 *   # register the agent first (see README.md), then run with tsx:
 *   npx tsx plug-ins/claude-agent-sdk-adapter/canUseTool.ts
 *
 * See plug-ins/claude-agent-sdk-adapter/ for the full example.
 */
import { pathToFileURL } from "node:url";
import {
  SentinelClient,
  inspectWithPolicy,
  type ActionType,
  type JsonObject,
} from "@iaga-sentinel/sdk";

export const ACTION_TYPES: Record<string, ActionType> = {
  Bash: "shell",
  Read: "file_read",
  Glob: "file_read",
  Grep: "file_read",
  Write: "file_write",
  Edit: "file_write",
  MultiEdit: "file_write",
  WebFetch: "http",
};

/** The shape the Claude Agent SDK `canUseTool` callback must return. */
export type CanUseToolResult =
  | { behavior: "allow"; updatedInput: Record<string, unknown> }
  | { behavior: "deny"; message: string };

/**
 * Build a Claude Agent SDK `canUseTool` callback that inspects each tool call
 * through IAGA Sentinel before it runs: `block`/`review` become a `deny`,
 * `allow` lets the tool run. Transport errors fail open by default
 * (`failClosed: true` to deny). Wire it up as:
 *
 *   query({ prompt, options: { canUseTool: iagaCanUseTool(client) } })
 */
export function iagaCanUseTool(
  client: SentinelClient,
  opts: { agentId?: string; framework?: string; failClosed?: boolean } = {}
) {
  return async (
    toolName: string,
    input: Record<string, unknown>,
    _options?: unknown
  ): Promise<CanUseToolResult> => {
    const result = await inspectWithPolicy(
      client,
      {
        agentId: opts.agentId ?? process.env.IAGA_AGENT_ID ?? "claude-agent-sdk",
        framework: opts.framework ?? "claude-agent-sdk",
        action: {
          type: ACTION_TYPES[toolName] ?? "custom",
          toolName,
          payload: input as JsonObject,
        },
      },
      { failClosed: opts.failClosed }
    );
    if (result.decision === "block" || result.decision === "review") {
      return {
        behavior: "deny",
        message: result.risk.reasons.join("; ") || "blocked by IAGA Sentinel",
      };
    }
    return { behavior: "allow", updatedInput: input };
  };
}

// Runnable demo (needs @anthropic-ai/claude-agent-sdk + a Claude login).
async function main(): Promise<void> {
  const { query } = await import("@anthropic-ai/claude-agent-sdk");
  const client = new SentinelClient({
    baseUrl: process.env.IAGA_BASE_URL ?? "http://localhost:4010",
  });
  for await (const message of query({
    prompt: "Read README.md and summarize it.",
    options: { canUseTool: iagaCanUseTool(client) },
  })) {
    console.log(message);
  }
}

// Only run the demo when executed directly, not when imported by a test.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
