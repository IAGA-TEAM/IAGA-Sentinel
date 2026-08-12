/*
 * Govern a LangGraph.js agent's tools with IAGA Sentinel.
 *
 *   npm i @langchain/langgraph @langchain/openai @langchain/core zod @iaga-sentinel/sdk
 *   IAGA_SENTINEL_HOST=127.0.0.1 IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
 *   # register an agent that allows your tools (see README.md), then:
 *   node plug-ins/langgraph-adapter/js_example.mjs
 *
 * governedToolNode is a drop-in for langgraph's ToolNode: it inspects each tool
 * call through IAGA Sentinel first. Allowed calls run and are receipted; blocked
 * calls throw SentinelBlockedError.
 */
import { ChatOpenAI } from "@langchain/openai";
import { StateGraph, MessagesAnnotation, START, END } from "@langchain/langgraph";
import { tool } from "@langchain/core/tools";
import { z } from "zod";
import { governedToolNode } from "@iaga-sentinel/sdk";

const filesystemRead = tool(async ({ path }) => `contents of ${path}`, {
  name: "filesystem.read",
  description: "Read a text file",
  schema: z.object({ path: z.string() }),
});

const shell = tool(async ({ cmd }) => `ran: ${cmd}`, {
  name: "shell",
  description: "Run a shell command",
  schema: z.object({ cmd: z.string() }),
});

const tools = [filesystemRead, shell];
const model = new ChatOpenAI({ model: "gpt-4o" }).bindTools(tools);

// The only IAGA-specific change: swap ToolNode -> governedToolNode.
const governedTools = governedToolNode(tools, {
  agentId: process.env.IAGA_AGENT_ID ?? "langgraph-demo",
  baseUrl: process.env.IAGA_BASE_URL ?? "http://localhost:4010",
  // failClosed: true, // deny if the sidecar is unreachable (default: fail-open)
});

const app = new StateGraph(MessagesAnnotation)
  .addNode("model", async (state) => ({ messages: [await model.invoke(state.messages)] }))
  .addNode("tools", governedTools)
  .addEdge(START, "model")
  .addConditionalEdges("model", (s) =>
    s.messages.at(-1)?.tool_calls?.length ? "tools" : END
  )
  .addEdge("tools", "model")
  .compile();

const out = await app.invoke({
  messages: [{ role: "user", content: "Read ./README.md and summarize it." }],
});
console.log(out.messages.at(-1).content);
