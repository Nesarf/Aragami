#!/usr/bin/env node
/**
 * Traverser -- parameter matrix x invariant assertions x hostile input.
 *
 * Division of labour with selftest:
 *   selftest  asserts "a specific check fires" (semantic correctness)
 *   matrix    asserts "however it is called, the output contract never breaks"
 *             (contract invariance + robustness)
 *
 * It traverses: every tool x every argument value x three fixtures x hostile input,
 * and validates the contract on EVERY single return. One broken contract fails the run.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildAllFixtures } from "./fixtures.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const { TOOLS, LAYERS, SEVERITY_ORDER, safeStringify } = await import(
  pathToFileURL(path.join(root, "lib", "core.mjs")).href
);

const KNOWN_LAYERS = new Set(Object.keys(LAYERS));
const KNOWN_SEV = new Set(Object.keys(SEVERITY_ORDER));

/* ====================== scoring ====================== */

let checks = 0, bad = 0;
const violations = [];
const counts = {};

function violation(where, msg) {
  bad++;
  if (violations.length < 40) violations.push(`${where}: ${msg}`);
}

/** Validate the contract of one call result. Returns the result itself. */
function contract(where, toolName, res) {
  checks++;

  // 1. must be JSON-serializable (tolerating BigInt / circular references)
  let json;
  try { json = safeStringify(res); JSON.parse(json); }
  catch (e) { violation(where, `not serializable: ${e.message}`); return res; }

  // 2. boundary_notice is always present -- this is the clause that cannot be waived
  if (!Array.isArray(res?.boundary_notice)) violation(where, "boundary_notice missing");
  else if (res.boundary_notice.length < 4) violation(where, `boundary_notice has only ${res.boundary_notice.length} entries`);

  // 3. must never claim safety
  for (const phrase of ["you are safe", "is safe now", "guaranteed safe", "absolutely safe", "completely secure", "no risk"]) {
    if (json.includes(phrase)) violation(where, `safety claim found: "${phrase}"`);
  }

  // 4. aragami_audit-specific contract
  if (toolName === "aragami_audit" && Array.isArray(res?.findings)) {
    const AUDIT_LAYERS = new Set(["build", "transport", "crypto", "metadata", "endpoint"]);
    let prev = 99;
    for (const f of res.findings) {
      if (!AUDIT_LAYERS.has(f.layer)) violation(where, `unknown layer ${f.layer}`);
      if (!KNOWN_SEV.has(f.severity)) violation(where, `unknown severity ${f.severity}`);
      if (typeof f.id !== "string" || !f.id) violation(where, "finding is missing id");
      if (typeof f.title !== "string" || !f.title) violation(where, `finding ${f.id} is missing title`);
      if (typeof f.detail !== "string" || f.detail.length < 4) violation(where, `finding ${f.id} detail is too short`);
      const s = SEVERITY_ORDER[f.severity];
      if (s > prev) violation(where, "findings are not sorted by descending severity");
      prev = s;
    }
    // tally must agree with findings
    if (res.tally) {
      const t = {};
      for (const f of res.findings) t[f.severity] = (t[f.severity] ?? 0) + 1;
      for (const k of Object.keys(res.tally)) {
        if ((res.tally[k] ?? 0) !== (t[k] ?? 0)) violation(where, `tally.${k}=${res.tally[k]} disagrees with the actual ${t[k] ?? 0}`);
      }
    }
    // ids must be unique (within a layer)
    const ids = res.findings.map((f) => f.id);
    if (new Set(ids).size !== ids.length) violation(where, `duplicate finding id: ${ids.join(",")}`);
  }

  // 5. aragami_layer_assess-specific contract
  if (toolName === "aragami_layer_assess") {
    if (!Array.isArray(res?.does_not_cover) || res.does_not_cover.length < 4) {
      violation(where, "does_not_cover has fewer than 4 entries");
    }
    if (typeof res?.recommended_channel !== "string" || !res.recommended_channel) {
      violation(where, "recommended_channel is empty");
    }
    if (!Array.isArray(res?.layer_model) || res.layer_model.length < 4) {
      violation(where, "layer_model is incomplete");
    }
    if (typeof res?.verdict !== "string" || !res.verdict) violation(where, "verdict is empty");
  }

  // 6. aragami_version-specific contract
  if (toolName === "aragami_version") {
    const ok = ["current", "outdated", "ahead", "check-failed", "unknown"];
    if (!ok.includes(res?.verdict)) violation(where, `illegal verdict: ${res?.verdict}`);
  }

  // 7. target-aware tools must always report a resolved target -- "auto" is an input, never
  // an output, and the payload branches on it, so an unresolved value would make the shape
  // of the result ambiguous.
  if (toolName === "aragami_audit" || toolName === "aragami_version") {
    if (res?.target !== "tor" && res?.target !== "firefox") {
      violation(where, `target was not resolved to tor/firefox: ${JSON.stringify(res?.target)}`);
    }
  }
  if (toolName === "aragami_env") {
    // both branches are always present, and found is the length of the list it summarises
    const tor = res?.targets?.tor, ff = res?.targets?.firefox;
    if (!Array.isArray(tor?.installs)) violation(where, "targets.tor.installs is not an array");
    else if (tor.found !== tor.installs.length) {
      violation(where, `targets.tor.found=${tor.found} disagrees with the ${tor.installs.length} install(s) listed`);
    }
    if (!Array.isArray(ff?.profiles)) violation(where, "targets.firefox.profiles is not an array");
    else if (ff.found !== ff.profiles.length) {
      violation(where, `targets.firefox.found=${ff.found} disagrees with the ${ff.profiles.length} profile(s) listed`);
    }
  }

  return res;
}

/** Run one tool call, catching exceptions (an exception is itself a contract breach). */
async function call(where, toolName, args) {
  const tool = TOOLS.find((t) => t.name === toolName);
  const key = `${toolName}`;
  counts[key] = (counts[key] ?? 0) + 1;
  checks++;
  try {
    const res = await tool.execute(args);
    return contract(where, toolName, res);
  } catch (e) {
    violation(where, `threw: ${(e && e.message) || e}`);
    return null;
  }
}

/* ====================== main flow ====================== */

const base = fs.mkdtempSync(path.join(os.tmpdir(), "tpa-matrix-"));
const F = buildAllFixtures(base);

console.log("== Fixtures ==");
console.log(`  good     ${F.good}`);
console.log(`  degraded ${F.degraded}`);
console.log(`  minimal  ${F.minimal}`);
console.log(`  baseline ${base}`);

/* ---------- 1. aragami_env ---------- */
console.log("\n== 1. aragami_env traversal ==");
{
  const t0 = Date.now();
  const r = await call("aragami_env/auto", "aragami_env", {});
  const autoTor = r?.targets?.tor, autoFF = r?.targets?.firefox;
  console.log(`  auto-discovery took ${Date.now() - t0} ms, found ${autoTor?.found ?? "?"} install(s) and ${autoFF?.found ?? "?"} profile(s)`);
  if (r && !r.environment?.mode) violation("aragami_env/auto", "environment.mode missing");

  for (const [name, p] of [["good", F.good], ["degraded", F.degraded], ["minimal", F.minimal], ["inconsistent", F.inconsistent], ["edge", F.edge]]) {
    const r2 = await call(`aragami_env/${name}`, "aragami_env", { install: p });
    const tor = r2?.targets?.tor;
    if (tor?.installs?.length !== 1) {
      violation(`aragami_env/${name}`, `an explicit path should find exactly 1, got ${tor?.installs?.length ?? "undefined"}`);
    }
    // an explicit Tor install must not pull in unrelated Tor Browser trees found on the machine
    if (r2 && tor?.found !== 1) violation(`aragami_env/${name}`, `targets.tor.found should be 1 for an explicit path, got ${tor?.found}`);
  }
}

/* ---------- 2. the full aragami_audit argument matrix ---------- */
console.log("\n== 2. aragami_audit matrix ==");
{
  const layers = ["all", "build", "transport", "crypto", "metadata", "endpoint"];
  const sevs = ["ok", "info", "warn", "critical"];
  const installs = [["good", F.good], ["degraded", F.degraded], ["minimal", F.minimal], ["inconsistent", F.inconsistent], ["edge", F.edge]];
  let n = 0;
  for (const [IN, p] of installs) {
    for (const layer of layers) {
      for (const sev of sevs) {
        n++;
        const where = `aragami_audit/${IN}/${layer}/${sev}`;
        const res = await call(where, "aragami_audit", { install: p, layer, min_severity: sev });
        if (!res || !Array.isArray(res.findings)) continue;

        // layer filtering must be exact
        if (layer !== "all" && !res.findings.every((f) => f.layer === layer)) {
          violation(where, "layer filter leaked");
        }
        // severity filtering must be exact
        const min = SEVERITY_ORDER[sev];
        if (!res.findings.every((f) => SEVERITY_ORDER[f.severity] >= min)) {
          violation(where, `an entry below min_severity(${sev}) appeared`);
        }
        // compare against the unfiltered result: a filtered result must be a subset of the whole
        if (layer === "all" && sev === "ok") {
          const full = res.findings.length;
          const filtered = await TOOLS.find((t) => t.name === "aragami_audit")
            .execute({ install: p, layer, min_severity: "warn" });
          if (filtered.findings.length > full) violation(where, "filtering produced more entries, not fewer");
        }
      }
    }
  }
  console.log(`  ${n} combinations completed (5 fixtures x 6 layers x 4 severities)`);
}

/* ---------- 3. aragami_version ---------- */
console.log("\n== 3. aragami_version traversal ==");
{
  for (const [name, p] of [["good", F.good], ["degraded", F.degraded], ["minimal", F.minimal], ["inconsistent", F.inconsistent], ["edge", F.edge]]) {
    const r = await call(`aragami_version/${name}/offline`, "aragami_version", { install: p, online: false });
    if (r?.via !== undefined) violation(`aragami_version/${name}/offline`, "offline mode still reports via (meaning it really went online)");
    if (r?.latest !== null) violation(`aragami_version/${name}/offline`, "offline mode still returned latest");
    // The version payload is target-specific: the Tor branch carries the Firefox base it is
    // built on (null when the fixture has no prefs.js). The key must be present, not dropped.
    if (r?.target === "tor" && !("firefox_base" in r)) {
      violation(`aragami_version/${name}/offline`, "the Tor target no longer carries firefox_base");
    }
    if (r?.target === "firefox" && !("local_source" in r)) {
      violation(`aragami_version/${name}/offline`, "the Firefox target does not report where its local version came from");
    }
  }
  // bad proxy: must fail gracefully, must never throw
  const badProxy = await call("aragami_version/badproxy", "aragami_version", { online: true, proxy: "http://127.0.0.1:9" });
  if (badProxy?.verdict !== "check-failed") violation("aragami_version/badproxy", `expected check-failed, got ${badProxy?.verdict}`);
  if (typeof badProxy?.error !== "string" || badProxy.error.length < 8) {
    violation("aragami_version/badproxy", "the error message is too vague to diagnose");
  }
  // live network (the only outbound call; it may fail because of the network, but must not crash)
  const live = await call("aragami_version/live", "aragami_version", { online: true });
  const liveOk = live?.verdict === "current" || live?.verdict === "outdated" || live?.verdict === "ahead";
  console.log(`  online check: ${live?.verdict}  latest=${live?.latest ?? "-"}  via=${live?.via ?? "-"}`);
  if (liveOk) {
    checks++;
    if (!/^\d+\.\d+/.test(String(live.latest))) violation("aragami_version/live", `latest does not look like a version: ${live.latest}`);
  } else {
    console.log("  (the online check did not succeed; tolerated as an environment factor -- it only has to avoid crashing and report a diagnosable error)");
  }
}

/* ---------- 4. aragami_layer_assess, every boolean combination ---------- */
console.log("\n== 4. aragami_layer_assess full combination sweep ==");
{
  const caps = ["email-only", "can-install-tools", "signal-capable", "tor-capable"];
  const bools = [false, true];
  let n = 0, hardConflicts = 0, overEngineerWarns = 0;
  for (const content of bools) {
    for (const meta of bools) {
      for (const realtime of bools) {
        for (const noCopy of bools) {
          for (const seizable of bools) {
            for (const cap of caps) {
              n++;
              const args = {
                content_sensitive: content, metadata_sensitive: meta, realtime,
                counterpart_capability: cap,
                must_leave_no_third_party_copy: noCopy, endpoint_shared_or_seizable: seizable,
              };
              const r = await call(`assess/${content}${meta}${realtime}${noCopy}${seizable}/${cap}`, "aragami_layer_assess", args);
              if (meta && realtime && (r?.warnings ?? []).some((w) => w.includes("HARD CONFLICT"))) hardConflicts++;
              if (content && !meta && (r?.warnings ?? []).some((w) => w.includes("most conspicuous signature"))) overEngineerWarns++;
            }
          }
        }
      }
    }
  }
  console.log(`  ${n} combinations completed (2^5 boolean combinations x 4 counterpart capabilities)`);
  checks++;
  if (hardConflicts === 0) violation("assess", "no combination triggered the hard-conflict warning");
  checks++;
  if (overEngineerWarns === 0) violation("assess", "no combination triggered the over-engineering discouragement");
}

/* ---------- 5. hostile / malformed input ---------- */
console.log("\n== 5. malformed-input robustness ==");
{
  const hostile = [
    ["install=empty string", "aragami_audit", { install: "" }],
    ["install=null", "aragami_audit", { install: null }],
    ["install=number", "aragami_audit", { install: 12345 }],
    ["install=object", "aragami_audit", { install: { a: 1 } }],
    ["install=nonexistent path", "aragami_audit", { install: "C:\\no\\such\\tor\\here" }],
    ["layer=bogus value", "aragami_audit", { install: F.good, layer: "bogus" }],
    ["min_severity=bogus value", "aragami_audit", { install: F.good, min_severity: "bogus" }],
    ["layer=null", "aragami_audit", { install: F.good, layer: null }],
    ["env/install=empty string", "aragami_env", { install: "" }],
    ["ver/online=string", "aragami_version", { install: F.good, online: "no" }],
    ["ver/proxy=number", "aragami_version", { install: F.good, online: false, proxy: 99 }],
    ["assess/no arguments", "aragami_layer_assess", {}],
    ["assess/fields are strings", "aragami_layer_assess", { content_sensitive: "yes", metadata_sensitive: "no" }],
    ["assess/bogus capability", "aragami_layer_assess", { counterpart_capability: "bogus" }],
    ["assess/all null", "aragami_layer_assess", { content_sensitive: null, metadata_sensitive: null, realtime: null }],
    ["assess/extra fields", "aragami_layer_assess", { metadata_sensitive: true, __proto__: "x", extra: 1 }],
  ];
  for (const [label, toolName, args] of hostile) {
    await call(`hostile/${label}`, toolName, args);
  }
  console.log(`  ${hostile.length} hostile inputs completed (requirement: no throw, no broken contract)`);
}

/* ---------- summary ---------- */
const totalCalls = Object.values(counts).reduce((a, b) => a + b, 0);
console.log("\n== Summary ==");
for (const [k, v] of Object.entries(counts)) console.log(`  ${k.padEnd(20)} ${v} call(s)`);
console.log(`\n  total tool calls   ${totalCalls}`);
console.log(`  contract checks    ${checks}`);
console.log(`  violations         ${bad}`);

try { fs.rmSync(base, { recursive: true, force: true }); console.log("\n  \u001b[90mfixtures cleaned up\u001b[0m"); } catch {}

if (bad) {
  console.log("\n  violation list (up to 40):");
  for (const v of violations) console.log(`    - ${v}`);
  process.exit(1);
}
console.log("\n  all traversals passed");
