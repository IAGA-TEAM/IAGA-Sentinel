import {
  SentinelBlockedError,
  SentinelClient,
  SentinelReviewError,
  inspectWithPolicy,
} from "../client";
import type { ActionType, InspectRequest, JsonObject, OpenAIAdapterOptions } from "../types";
import { inferActionType } from "./infer-action-type";

/**
 * Governs a LangGraph tool node: inspects every tool call before it runs.
 * allow -> execute the tool and return its ToolMessage-shaped output;
 * block/review -> throw (SentinelBlockedError / SentinelReviewError). Pure LLM
 * nodes produce no action and need no receipt.
 *
 * Dependency-light: this module does not import @langchain/langgraph. It
 * duck-types the graph state ({ messages: [...] }), the last message's
 * `tool_calls`, and each tool's invoke()/func()/callable interface.
 */
export interface GovernedToolNodeOptions extends OpenAIAdapterOptions {
  /** Force a specific action type for every tool (default: inferred from name). */
  actionType?: ActionType;
}

interface ToolCall {
  name: string;
  args?: JsonObject;
  id?: string;
}

type ToolLike =
  | {
      name?: string;
      invoke?: (args: unknown) => unknown;
      func?: (args: unknown) => unknown;
    }
  | ((args: unknown) => unknown);

function getToolName(tool: ToolLike): string | undefined {
  if (typeof tool === "function") {
    return tool.name || undefined;
  }
  return tool.name;
}

async function invokeTool(tool: ToolLike | undefined, args: unknown): Promise<unknown> {
  if (!tool) {
    throw new Error("tool not registered with GovernedToolNode");
  }
  if (typeof tool === "function") {
    return tool(args);
  }
  if (typeof tool.invoke === "function") {
    return tool.invoke(args);
  }
  if (typeof tool.func === "function") {
    return tool.func(args);
  }
  throw new Error("don't know how to invoke tool");
}

function getToolCalls(state: unknown): ToolCall[] {
  const messages = Array.isArray(state)
    ? state
    : (state as { messages?: unknown[] } | undefined)?.messages;
  if (!messages || messages.length === 0) {
    return [];
  }
  const last = messages[messages.length - 1] as { tool_calls?: ToolCall[] };
  return last?.tool_calls ?? [];
}

export function governedToolNode(tools: ToolLike[], options: GovernedToolNodeOptions) {
  const client = new SentinelClient(options);
  const byName = new Map<string, ToolLike>();
  for (const tool of tools) {
    const name = getToolName(tool);
    if (name) {
      byName.set(name, tool);
    }
  }

  const run = async (state: unknown): Promise<{ messages: JsonObject[] }> => {
    const outputs: JsonObject[] = [];
    for (const call of getToolCalls(state)) {
      const name = call.name;
      const args = (call.args ?? {}) as JsonObject;
      const request: InspectRequest = {
        agentId: options.agentId,
        tenantId: options.tenantId,
        workspaceId: options.workspaceId,
        framework: options.framework ?? "langgraph",
        sessionId: options.sessionId,
        metadata: options.metadata,
        action: {
          type: options.actionType ?? inferActionType(name),
          toolName: name,
          payload: args,
        },
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
      const output = await invokeTool(byName.get(name), args);
      outputs.push({
        role: "tool",
        name,
        content: String(output),
        tool_call_id: call.id ?? "",
      });
    }
    return { messages: outputs };
  };

  // LangGraph invokes nodes as plain functions or via .invoke().
  (run as unknown as { invoke: typeof run }).invoke = run;
  return run;
}
