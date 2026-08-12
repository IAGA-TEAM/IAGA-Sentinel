/*
 * Govern an MCP server's tools with IAGA Sentinel (TypeScript SDK).
 *
 *   npm i @modelcontextprotocol/sdk zod @iaga-sentinel/sdk
 *   IAGA_SENTINEL_HOST=127.0.0.1 IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
 *   # register the agent (see README.md), then run with tsx.
 *
 * governMcpTool wraps each handler so every tools/call is inspected first.
 * A dangerous call is blocked before it runs; one signed receipt per call.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { governMcpTool } from "@iaga-sentinel/sdk";

const server = new McpServer({ name: "governed-server", version: "1.0.0" });

server.registerTool(
  "filesystem.read",
  { description: "Read a text file", inputSchema: { path: z.string() } },
  governMcpTool(
    async ({ path }: { path: string }) => ({
      content: [{ type: "text" as const, text: `contents of ${path}` }],
    }),
    {
      agentId: process.env.IAGA_AGENT_ID ?? "mcp-demo",
      toolName: "filesystem.read",
      baseUrl: process.env.IAGA_BASE_URL ?? "http://localhost:4010",
    }
  )
);

await server.connect(new StdioServerTransport());
