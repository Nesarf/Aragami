#!/usr/bin/env node
// MCP smoke test -- connect to the stdio server with a real MCP client and verify tools/list and tools/call.
//
// What it tests is whether "the portable half" actually holds: the tool list and the
// execution results that any MCP client receives must be exactly the same as what the
// CLI gets.

import path from "node:path";
import fs from "node:fs";
import os from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { makeMinimalFixture } from "./fixtures.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

// A synthetic install for the calls that need something to audit, so this suite does not depend
// on what the runner has installed.
const fixtureBase = fs.mkdtempSync(path.join(os.tmpdir(), "tpa-mcp-"));
process.on("exit", () => { try { fs.rmSync(fixtureBase, { recursive: true, force: true }); } catch {} });

// The expected tool set is read from the core rather than written down here. A hardcoded
// count goes stale the moment a tool is added -- and it fails in the least useful way, as a
// number that no longer matches, instead of as the property that actually matters: MCP must
// expose exactly what the core declares, no more and no less.
const { TOOLS } = await import(pathToFileURL(path.join(root, "lib", "core.mjs")).href);

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
const coreNames = TOOLS.map((t) => t.name).sort();
check("tool count matches the core", tools.length === TOOLS.length,
  `mcp ${tools.length} vs core ${TOOLS.length}: ${names.join(", ")}`);
check("MCP exposes exactly the core's tools, no more and no less",
  names.join(",") === coreNames.join(","), `mcp [${names}] vs core [${coreNames}]`);
for (const want of coreNames) {
  check(`contains ${want}`, names.includes(want));
}
for (const t of tools) {
  const hasSchema = t.inputSchema && t.inputSchema.type === "object";
  check(`${t.name} has a valid inputSchema`, hasSchema);
  const core = TOOLS.find((c) => c.name === t.name);
  check(`${t.name} description is passed through unchanged`, core?.description === t.description);
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

console.log("\n== tools/call: aragami_checks (the declared surface) ==");
const chkRes = await client.callTool({ name: "aragami_checks", arguments: { target: "tor", layer: "endpoint" } });
const cs = chkRes.structuredContent;
check("checks reports the catalog digest", /^[0-9a-f]{16}$/.test(cs?.catalog_digest ?? ""), String(cs?.catalog_digest));
check("checks narrows by target and layer",
  (cs?.checks ?? []).length > 0 && (cs?.checks ?? []).every((c) => c.targets.includes("tor") && c.layer === "endpoint"));
check("every listed check states its own boundary",
  (cs?.checks ?? []).every((c) => typeof c.does_not_cover === "string" && c.does_not_cover.length >= 20));
check("checks carries boundary_notice", (cs?.boundary_notice ?? []).length >= 4);
const oneRes = await client.callTool({ name: "aragami_checks", arguments: { id: "no-such-check" } });
check("checks reports a missing id honestly", oneRes.structuredContent?.found === false);
const missRes = await client.callTool({ name: "aragami_checks", arguments: { id: "disk-encryption" } });
check("checks finds a real id", missRes.structuredContent?.found === true);

console.log("\n== tools/call: aragami_baseline (capture, then diff against itself) ==");
// The audit is aimed at a SYNTHETIC install rather than at whatever happens to be on the machine.
// The first version of this block did not, and passed here only because this workstation has Tor
// Browser installed -- on the Linux CI runner, which has neither Tor Browser nor Firefox, the
// audit returned an error and six assertions failed. A smoke test whose result depends on the
// runner's software is not a smoke test. test/fixtures.mjs is the shared source of fixtures, so
// this uses it rather than writing a second, smaller copy that would drift.
fs.mkdirSync(fixtureBase, { recursive: true });
const syntheticInstall = makeMinimalFixture(fixtureBase);
const capture = await client.callTool({ name: "aragami_baseline", arguments: { install: syntheticInstall } });
const cap = capture.structuredContent;
check("baseline captures", cap?.mode === "capture" && cap?.baseline?.schema === "aragami-baseline/1",
  JSON.stringify(cap?.error ?? cap?.mode));
check("the captured baseline records the synthetic install",
  cap?.baseline?.subject === syntheticInstall, String(cap?.baseline?.subject));
check("a baseline stores fingerprints and no evidence", (() => {
  const leaves = [];
  (function walk(v) { if (typeof v === "string") leaves.push(v);
    else if (v && typeof v === "object") for (const k of Object.keys(v)) walk(v[k]); })(cap?.baseline?.checks ?? {});
  return leaves.length > 0 && !leaves.some((s) => s.includes(fixtureBase));
})(), "a path reached the baseline");
const difRes = await client.callTool({
  name: "aragami_baseline",
  arguments: { mode: "diff", baseline: cap.baseline, install: syntheticInstall },
});
const df = difRes.structuredContent;
check("diffing a capture against the same install is no-drift", df?.verdict === "no-drift",
  `${df?.verdict}: ${JSON.stringify(df?.summary ?? df?.reason)}`);
check("diff is comparable", df?.comparable === true);
check("diff carries boundary_notice", (df?.boundary_notice ?? []).length >= 4);
const badRes = await client.callTool({ name: "aragami_baseline", arguments: { mode: "diff", baseline: { schema: "nope" } } });
check("diff refuses an unusable baseline", badRes.structuredContent?.verdict === "invalid-baseline");
const noneRes = await client.callTool({ name: "aragami_baseline", arguments: { mode: "diff" } });
check("diff without a baseline refuses rather than inventing one", noneRes.structuredContent?.verdict === "no-baseline");
fs.rmSync(fixtureBase, { recursive: true, force: true });

console.log("\n== every response names its schema ==");
for (const [label, res] of [["env", envRes], ["audit", auditRes], ["version", verRes], ["assess", layRes], ["checks", chkRes], ["baseline", capture]]) {
  check(`${label} response carries a versioned schema`, /^aragami-[a-z-]+\/\d+$/.test(res.structuredContent?.schema ?? ""),
    String(res.structuredContent?.schema));
}

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
