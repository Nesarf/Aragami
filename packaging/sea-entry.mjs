#!/usr/bin/env node
/**
 * Single entry point for the Node SEA executable: the CLI and the MCP stdio server in one
 * file, so a single executable serves both uses.
 *
 * Selection: the MCP server runs when the executable is named with "mcp" in it (so a copy
 * named aragami-mcp.exe works without flags), or when --mcp is passed explicitly.
 * Everything else runs the CLI.
 *
 * The two entry modules register their behaviour on import, which is why they are pulled in
 * dynamically. The dispatcher is wrapped in an async IIFE rather than using top-level await,
 * because the bundle is emitted as CommonJS so it can live inside a single-file executable.
 */
import path from "node:path";

(async () => {
  const argv = process.argv.slice(2);
  const invokedAsMcp =
    /mcp/i.test(path.basename(process.argv[1] ?? "")) || argv.includes("--mcp");

  if (invokedAsMcp) {
    // The flag is a dispatcher concern, not a tool argument; strip it before the MCP
    // server ever sees the argument list.
    process.argv = [process.argv[0], process.argv[1], ...argv.filter((a) => a !== "--mcp")];
    await import("../mcp/index.mjs");
  } else {
    await import("../cli/index.mjs");
  }
})().catch((e) => {
  console.error(`Aragami failed to start: ${(e && e.message) || e}`);
  process.exit(1);
});
