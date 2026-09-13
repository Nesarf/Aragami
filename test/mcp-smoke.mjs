#!/usr/bin/env node
// MCP smoke test -- connect to the stdio server with a real MCP client and verify tools/list and tools/call.
//
// What it tests is whether "the portable half" actually holds: the tool list and the
// execution results that any MCP client receives must be exactly the same as what the
// CLI gets.

import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

let pass = 0, fail = 0;
function check(name, ok, detail = "") {
  if (ok) { console.log(`  [ok] ${name}`); pass++; }
  else { console.log(`  [FAIL] ${name}  ${detail}`); fail++; }
}

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [path.join(root, "mcp", "index.mjs")],
  cwd: root,
  stderr: "pipe",
});

const client = new Client({ name: "Aragami-smoke", version: "0.0.1" }, { capabilities: {} });

console.log("== MCP connectivity ==");
await client.connect(transport);
check("stdio connection established", true);

const info = client.getServerVersion();
check("server name is correct", info?.name === "Aragami", JSON.stringify(info));

console.log("\n== tools/list ==");
const { tools } = await client.listTools();
const names = tools.map((t) => t.name).sort();
check("tool count is 4", tools.length === 4, `actual ${tools.length}: ${names.join(", ")}`);
for (const want of ["aragami_audit", "aragami_env", "aragami_layer_assess", "aragami_version"]) {
  check(`contains ${want}`, names.includes(want));
}
for (const t of tools) {
  const hasSchema = t.inputSchema && t.inputSchema.type === "object";
  check(`${t.name} has a valid inputSchema`, hasSchema);
}

console.log("\n== tools/call: aragami_env ==");
const envRes = await client.callTool({ name: "aragami_env", arguments: {} });
check("returns structuredContent", !!envRes.structuredContent);
// The env tool now reports both targets. Assert the shape, not a machine-wide count:
// "how many installs does this developer's machine have" is not something a suite should
// depend on, and asserting it made the suite fail on machines without Tor.
const tgt = envRes.structuredContent?.targets;
check("reports both targets", !!tgt?.tor && !!tgt?.firefox);
check("tor installs is an array", Array.isArray(tgt?.tor?.installs));
check("firefox profiles is an array", Array.isArray(tgt?.firefox?.profiles));
check("tor found matches the list length", tgt?.tor?.found === (tgt?.tor?.installs?.length ?? -1));
check("firefox found matches the list length", tgt?.firefox?.found === (tgt?.firefox?.profiles?.length ?? -1));
check("carries boundary_notice", Array.isArray(envRes.structuredContent?.boundary_notice));
check("boundary_notice is not routinely empty", (envRes.structuredContent?.boundary_notice ?? []).length >= 4);

console.log("\n== tools/call: aragami_audit (metadata layer only) ==");
const auditRes = await client.callTool({
  name: "aragami_audit",
  arguments: { layer: "metadata", min_severity: "warn" },
});
const sc = auditRes.structuredContent;
// This call passes no explicit install, so on a machine with no Tor Browser the tool
// correctly answers with a structured error rather than findings. Demanding an array here
// made the suite depend on what the developer happens to have installed -- the same mistake
// the env assertions above already call out, just not applied to this call. One of the two
// outcomes is required, and neither may be a crash or a silent empty answer.
const hasFindings = Array.isArray(sc?.findings);
check("audit returns findings, or a structured error",
  hasFindings || (typeof sc?.error === "string" && sc.error.length > 0),
  JSON.stringify(sc).slice(0, 180));
// These three hold in both outcomes: with no findings there is nothing that could violate a
// filter, so they assert the filtering is exact rather than that it had work to do.
check("layer filtering takes effect", (sc?.findings ?? []).every((f) => f.layer === "metadata"),
  `layers: ${[...new Set((sc?.findings ?? []).map((f) => f.layer))].join(",")}`);
check("severity filtering takes effect", (sc?.findings ?? []).every((f) => f.severity === "warn" || f.severity === "critical"));
check("audit also carries boundary_notice", Array.isArray(sc?.boundary_notice));

console.log("\n== tools/call: aragami_version (offline mode, no network) ==");
const verRes = await client.callTool({ name: "aragami_version", arguments: { online: false } });
// The local version is read from an installed Tor Browser or its profile, and a machine may
// honestly have neither -- CI included. Offline with nothing installed is a correct answer,
// so what is asserted is the contract rather than the presence of a browser: the verdict is
// still unknown, the boundary notice survives, and a version is either a non-empty string
// or absent. A stale string left over from somewhere would be the failure this catches.
const offlineInstalled = verRes.structuredContent?.installed;
check("offline mode reports a local version, or honestly reports none",
  offlineInstalled === null || offlineInstalled === undefined ||
    (typeof offlineInstalled === "string" && offlineInstalled.length > 0),
  String(offlineInstalled));
check("offline mode verdict=unknown", verRes.structuredContent?.verdict === "unknown");

console.log("\n== tools/call: aragami_layer_assess (layer-mismatch detection) ==");
const layRes = await client.callTool({
  name: "aragami_layer_assess",
  arguments: { metadata_sensitive: true, realtime: true, counterpart_capability: "email-only" },
});
const ls = layRes.structuredContent;
check("recognizes the realtime/metadata hard conflict", (ls?.warnings ?? []).some((w) => w.includes("[HARD CONFLICT]")));
check("does_not_cover is non-empty", (ls?.does_not_cover ?? []).length >= 4);
check("refuses to over-promise", (ls?.verdict ?? "").includes("cannot be solved"));

console.log("\n== an unknown tool must error ==");
let unknownOk = false;
try {
  const bad = await client.callTool({ name: "no_such_tool", arguments: {} });
  unknownOk = bad.isError === true;
} catch { unknownOk = true; }
check("unknown tool is rejected", unknownOk);

await client.close();

console.log(`\n== summary ==\n  passed ${pass} / ${pass + fail}`);
process.exit(fail === 0 ? 0 : 1);
