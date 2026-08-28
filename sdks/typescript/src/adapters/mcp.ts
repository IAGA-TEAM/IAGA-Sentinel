import {
  SentinelBlockedError,
  SentinelClient,
  SentinelReviewError,
  inspectWithPolicy,
} from "../client";
import type { ActionType, InspectRequest, JsonObject, OpenAIAdapterOptions } from "../types";
import { inferActionType } from "./infer-action-type";

/**
 * Wraps an MCP tool handler so every `tools/call` is inspected before it runs.
 * Use it when you build an MCP server and want each tool governed:
 *
 *   server.registerTool("read_file", schema,
 *     governMcpTool(readFileHandler, { agentId: "mcp-demo", toolName: "filesystem.read" }));
 *
 * allow -> runs; block/review -> throws SentinelBlockedError / SentinelReviewError.
 * For transparent wrapping of an *external* MCP server, use `iaga proxy` instead.
 *
 * The default `framework` is "model-context-tool" (not "mcp"): the server treats
 * explicit MCP-protocol traffic specially (a protocol guard), but this wrapper
 * governs the tool call at the handler level, not the raw JSON-RPC envelope.
 */
export interface GovernMcpToolOptions extends OpenAIAdapterOptions {
  toolName?: string;
  actionType?: ActionType;
}

type AnyHandler = (...args: never[]) => unknown;

export function governMcpTool<H extends AnyHandler>(
  handler: H,
  options: GovernMcpToolOptions
): H {
  const client = new SentinelClient(options);
  const name = options.toolName ?? handler.name ?? "mcp.tool";
  const actionType = options.actionType ?? inferActionType(name);

  const wrapped = async (...args: unknown[]): Promise<unknown> => {
    const first = args[0];
    const payload: JsonObject =
      first && typeof first === "object" && !Array.isArray(first)
        ? (first as JsonObject)
        : {};
    const request: InspectRequest = {
      agentId: options.agentId,
      tenantId: options.tenantId,
      workspaceId: options.workspaceId,
      framework: options.framework ?? "model-context-tool",
      sessionId: options.sessionId,
      metadata: options.metadata,
      action: { type: actionType, toolName: name, payload },
    };
    const result = await inspectWithPolicy(client, request, {
      failClosed: options.failClosed,
    });
    if (result.decision === "block") {
      throw new SentinelBlockedError(result);
    }
    if (result.decision === "review") {
      throw new SentinelReviewError(result);
    }
    return (handler as unknown as (...a: unknown[]) => unknown)(...args);
  };

  return wrapped as unknown as H;
}
