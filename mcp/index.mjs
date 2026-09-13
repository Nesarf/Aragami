#!/usr/bin/env node
// Aragami - MCP (Model Context Protocol) stdio server.
//
// Exposes the same tools as the CLI over MCP's stdio transport. It consumes the
// shared core (lib/core.mjs), so MCP and CLI tool logic is identical -
// there is deliberately no second implementation.
//
// Run with:  node ./mcp/index.mjs
// Or spawn as an MCP stdio server, e.g.  { "command": "node", "args": ["./mcp/index.mjs"] }
//
// NOTE ON SCOPE: this server is read-only. It never starts Tor and never touches the
// network, except aragami_version's public release-metadata lookup (which can be disabled
// with online=false). Every response carries boundary_notice - that is by design,
// not decoration: an audit tool must not be mistaken for a safety guarantee.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  McpError,
  ErrorCode,
} from "@modelcontextprotocol/sdk/types.js";
import { TOOLS, safeStringify, VERSION } from "../lib/core.mjs";

const server = new Server(
  { name: "Aragami", version: VERSION },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, () => ({
  tools: TOOLS.map((t) => ({
    name: t.name,
    description: t.description,
    inputSchema: t.inputSchema,
  })),
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const tool = TOOLS.find((t) => t.name === request.params.name);
  if (!tool) {
    throw new McpError(ErrorCode.InvalidParams, `Unknown tool: ${request.params.name}`);
  }
  try {
    const result = await tool.execute(request.params.arguments || {});
    return {
      content: [{ type: "text", text: safeStringify(result, 2) }],
      structuredContent: result,
    };
  } catch (e) {
    return {
      isError: true,
      content: [{ type: "text", text: String((e && e.message) || e) }],
    };
  }
});

// No top-level await: the bundled entry point is emitted as CommonJS for the single-file
// executable, and esbuild cannot lower top-level await to CommonJS.
const transport = new StdioServerTransport();
server.connect(transport).catch((e) => {
  console.error(`MCP server failed to start: ${(e && e.message) || e}`);
  process.exit(1);
});
