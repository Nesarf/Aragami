#!/usr/bin/env node
/**
 * Aragami - self-test (semantic correctness).
 *
 * Division of labour with matrix:
 *   selftest   asserts "a specific check fires" (should this branch report, and at what severity)
 *   matrix     asserts "whatever you throw at it, the output contract holds" (contract invariance + robustness)
 *   net        asserts "the network-layer protocol behaves correctly" (local mock server)
 *   coverage   reports "which lines were never executed" (the evidence for traversal)
 *
 * Fixtures come from test/fixtures.mjs (shared, never inlined here -- a duplicated fixture
 * means two sources of truth that drift apart on their own).
 * Everything is synthesized in a temp directory, so this self-test does not depend on Tor
 * actually being installed on this machine.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildAllFixtures } from "./fixtures.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

// On Windows an ESM dynamic import must use a file:// URL; a bare absolute path raises
// ERR_UNSUPPORTED_ESM_URL_SCHEME.
const { parseTorrc, parsePrefs, discoverInstalls, cmpVer, detectEnvironment, TOOLS, safeStringify } = await import(
  pathToFileURL(path.join(root, "lib", "core.mjs")).href
);

let pass = 0, fail = 0;
const failures = [];
function check(name, ok, detail = "") {
  if (ok) { console.log(`  \u001b[32m[ok]\u001b[0m ${name}`); pass++; }
  else { console.log(`  \u001b[31m[FAIL]\u001b[0m ${name}  ${detail}`); fail++; failures.push(`${name} ${detail}`); }
}
function section(t) { console.log(`\n\u001b[35m== ${t} ==\u001b[0m`); }
const T = (name) => TOOLS.find((t) => t.name === name);

/* ====================== A. unit ====================== */

section("A1. torrc parsing");
{
  const t = `
# comment line
SocksPort 9150
Bridge snowflake 192.0.2.4:80 ABC url=https://x/ fronts=a.com,b.com utls-imitate=hellorandomizedalpn
Bridge snowflake 192.0.2.3:80 DEF fingerprint=DEF
UseBridges 1
ClientOnionAuthDir C:\\Tor Browser\\Browser\\TorBrowser\\Data\\Tor\\onion-auth
ClientTransportPlugin obfs2,obfs3,obfs4,scramblesuit exec lyrebird.exe   # trailing comment
`;
  const { entries } = parseTorrc(t);
  check("Bridge lines parsed: 2", entries.Bridge?.length === 2, `actual ${entries.Bridge?.length}`);
  check("UseBridges = 1", entries.UseBridges?.[0] === "1");
  check("ClientOnionAuthDir keeps the backslash path",
    entries.ClientOnionAuthDir?.[0]?.includes("onion-auth"), entries.ClientOnionAuthDir?.[0]);
  check("trailing comment stripped (ClientTransportPlugin)",
    !entries.ClientTransportPlugin?.[0]?.includes("#"), entries.ClientTransportPlugin?.[0]);
  check("comment line ignored (no '#' key)", !("#" in entries));
  check("empty text does not throw", parseTorrc("").order.length === 0);
  check("null does not throw", parseTorrc(null).order.length === 0);
}

section("A2. prefs.js parsing");
{
  const t = `
user_pref("torbrowser.settings.bridges.enabled", true);
user_pref("torbrowser.settings.bridges.builtin_type", "snowflake");
user_pref("extensions.lastTorBrowserVersion", "15.0.21");
user_pref("browser.startup.homepage_override.mstone", "140.15.0");
user_pref("some.number", 42);
user_pref("some.off", false);
`;
  const p = parsePrefs(t);
  check("boolean parsed as true", p["torbrowser.settings.bridges.enabled"] === true);
  check("string value unquoted", p["torbrowser.settings.bridges.builtin_type"] === "snowflake");
  check("version string correct", p["extensions.lastTorBrowserVersion"] === "15.0.21");
  check("number parsed as a number", p["some.number"] === 42);
  check("false parsed as a boolean", p["some.off"] === false);
  check("empty text returns an empty object", Object.keys(parsePrefs("")).length === 0);
}

section("A3. cmpVer version comparison");
{
  check("equal -> 0", cmpVer("15.0.21", "15.0.21") === 0);
  check("older vs newer -> -1", cmpVer("15.0.21", "15.0.22") === -1);
  check("newer vs older -> 1", cmpVer("15.1.0", "15.0.22") === 1);
  check("different segment counts still compare (10.0 vs 10.0.1)", cmpVer("10.0", "10.0.1") === -1);
  check("numeric compare, not lexicographic (9 vs 10)", cmpVer("15.9.0", "15.10.0") === -1);
  check("non-numeric segments treated as 0, no throw", (() => { try { cmpVer("x.y", "0.0"); return true; } catch { return false; } })());
}

section("A4. tool contract");
{
  check("4 tools", TOOLS.length === 4, `actual ${TOOLS.length}`);
  for (const t of TOOLS) {
    check(`${t.name} has a description`, typeof t.description === "string" && t.description.length > 20);
    check(`${t.name} schema is an object`, t.inputSchema?.type === "object");
    check(`${t.name} execute is a function`, typeof t.execute === "function");
  }
}

/* ====================== B. integration (shared fixtures) ====================== */

const base = fs.mkdtempSync(path.join(os.tmpdir(), "tpa-selftest-"));
const F = buildAllFixtures(base);

section("B1. install discovery and de-duplication");
{
  const installs = discoverInstalls(F.good);
  check("discovers an install from an explicit path", installs.length === 1, `found ${installs.length}`);
  check("reads Tor Browser version 15.0.20", installs[0]?.tor_browser_version === "15.0.20");
  check("reads Firefox base 140.15.0", installs[0]?.firefox_version === "140.15.0");
  check("channel is release", installs[0]?.channel === "release");

  // On a case-insensitive filesystem (Windows, and macOS by default) two spellings denote
  // the same directory, and the tool must collapse them into one install. On Linux they are
  // two different paths and the aliased one does not exist, so the correct answer is
  // nothing at all. Asserting the Windows behaviour unconditionally demanded that the tool
  // resolve a directory that genuinely is not there, which is why this failed under CI.
  const alias = /[A-Z]/.test(F.good) ? F.good.toLowerCase() : F.good.toUpperCase();
  const aliasIsSameDir = fs.existsSync(alias);
  const a2 = discoverInstalls(alias);
  if (aliasIsSameDir) {
    check("case-variant alias normalizes to the same path",
      a2.length === 1 && a2[0].root.toLowerCase() === installs[0].root.toLowerCase(),
      JSON.stringify(a2.map((i) => i.root)));
  } else {
    check("case-variant alias on a case-sensitive filesystem resolves to nothing",
      a2.length === 0, JSON.stringify(a2.map((i) => i.root)));
  }

  const outside = discoverInstalls();
  const mixed = discoverInstalls(F.good).some(
    (i) => outside.length && i.root.toLowerCase() === outside[0].root.toLowerCase()
      && outside[0].root.toLowerCase() !== F.good.toLowerCase()
  );
  check("explicit path does not mix in other installs", !mixed, `auto-discovery found ${outside.length} on this machine`);

  check("non-string arguments do not throw", (() => {
    try { discoverInstalls(12345); discoverInstalls({}); discoverInstalls(null); return true; }
    catch { return false; }
  })());

  check("minimal fixture (missing torrc/state/prefs) is still discovered", discoverInstalls(F.minimal).length === 1);
}

section("B2. full audit (good fixture)");
const audit = await T("aragami_audit").execute({ install: F.good });
{
  const ids = (audit.findings ?? []).map((f) => f.id);
  check("audit did not error", !audit.error, audit.error);
  check("carries boundary_notice (>= 4 entries)", (audit.boundary_notice ?? []).length >= 4);
  check("applied_filter is echoed back", audit.applied_filter?.layer === "all" && audit.applied_filter?.min_severity === "ok",
    JSON.stringify(audit.applied_filter));

  check("hit: bridges enabled", ids.includes("bridges"));
  check("hit: built-in bridges", ids.includes("bridge-blend"));
  check("hit: domain fronting", ids.includes("fronting"));
  check("hit: uTLS fingerprint impersonation", ids.includes("utls"));
  check("hit: quickstart timing hint", ids.includes("quickstart"));
  // The previous label claimed "7 kinds" while the fixture loads 5, and the assertion only
  // checked for path residue -- a label that lied about what was verified. Assert the exact
  // set instead, so the claim and the check now agree.
  const pt = (audit.findings ?? []).find((f) => f.id === "pt-list");
  const expectedPTs = ["obfs2", "obfs3", "obfs4", "scramblesuit", "webtunnel"];
  const gotPTs = [...(pt?.evidence?.plugins ?? [])].sort();
  check("PT list parsed correctly (exact names, no path residue)",
    JSON.stringify(gotPTs) === JSON.stringify(expectedPTs) && gotPTs.every((x) => !x.includes(".exe")),
    JSON.stringify(pt?.evidence));

  check("hit: state file retained", ids.includes("state-file"));
  const guards = (audit.findings ?? []).find((f) => f.id === "state-guards");
  check("guard count is 3", guards?.evidence?.guards === 3, `actual ${guards?.evidence?.guards}`);
  check("guard sets include bridges", (guards?.evidence?.sets ?? []).includes("bridges"),
    JSON.stringify(guards?.evidence?.sets));
  check("state-no-guards is not falsely reported", !ids.includes("state-no-guards"));
  check("hit: pt_state residue", ids.includes("pt-state"));
  const pts = (audit.findings ?? []).find((f) => f.id === "pt-state");
  check("pt_state file count is 2", pts?.evidence?.files?.length === 2, JSON.stringify(pts?.evidence));

  check("hit: client authorization directory configured", ids.includes("onion-auth-configured"));
  check("hit: authorization directory is empty", ids.includes("onion-auth-empty"));
  check("hit: profile first-use time", ids.includes("profile-times"));
  check("hit: session checkpoints", ids.includes("session-checkpoints"));
  check("hit: browsing history database", ids.includes("places"));
  check("hit: persistent install", ids.includes("persistence"));
  check("hit: inner Tor version", ids.includes("tor-version"));
  check("hs-keys not falsely reported (no onion service private key)", !ids.includes("hs-keys"));

  check("tally has warn > 0", (audit.tally?.warn ?? 0) > 0, JSON.stringify(audit.tally));
  check("effective torrc reads UseBridges", (audit.torrc_effective?.UseBridges ?? []).includes("1"));
  check("effective torrc reads 2 bridges", audit.torrc_effective?.Bridge_count === 2);
}

section("B3. layer and severity filtering");
{
  const onlyMeta = await T("aragami_audit").execute({ install: F.good, layer: "metadata" });
  check("layer=metadata returns the metadata layer only", (onlyMeta.findings ?? []).every((f) => f.layer === "metadata"));
  check("layer=metadata still has content", (onlyMeta.findings ?? []).length > 0);

  const onlyWarn = await T("aragami_audit").execute({ install: F.good, min_severity: "warn" });
  check("min_severity=warn leaves only warn/critical",
    (onlyWarn.findings ?? []).every((f) => f.severity === "warn" || f.severity === "critical"));

  const all = await T("aragami_audit").execute({ install: F.good, min_severity: "ok" });
  check("min_severity=ok includes positive findings", (all.findings ?? []).some((f) => f.severity === "ok"));
  check("ok-level finding count > 0", (all.tally?.ok ?? 0) > 0, JSON.stringify(all.tally));

  // A typo must fall back to the default and be echoed back, not silently return empty.
  const typo = await T("aragami_audit").execute({ install: F.good, layer: "metdata", min_severity: "warning" });
  check("layer typo falls back to all", typo.applied_filter?.layer === "all", JSON.stringify(typo.applied_filter));
  check("min_severity typo falls back to ok", typo.applied_filter?.min_severity === "ok");
  check("a typo does not return an empty result", (typo.findings ?? []).length > 0);
}

section("B4. degraded fixture (deprecated PT + authorization key + onion service private key)");
{
  const a2 = await T("aragami_audit").execute({ install: F.degraded });
  const ids2 = (a2.findings ?? []).map((f) => f.id);
  check("hit: deprecated PT warning", ids2.includes("deprecated-pt"), ids2.join(","));
  check("hit: authorization key present", ids2.includes("onion-auth-keys"));
  const k = (a2.findings ?? []).find((f) => f.id === "onion-auth-keys");
  check("key count is 1", k?.evidence?.files?.length === 1, JSON.stringify(k?.evidence));
  check("hit: onion service private key warning", ids2.includes("hs-keys"));
  check("state guards not falsely reported (this fixture has no Guard line)", !ids2.includes("state-guards"));
  check("hit: no guard records", ids2.includes("state-no-guards"));
  check("uTLS not falsely reported (this fixture has no utls-imitate)", !ids2.includes("utls"));
  check("domain fronting not falsely reported", !ids2.includes("fronting"));
}

section("B5. inconsistent fixture (UseBridges on but no Bridge lines)");
{
  const a3 = await T("aragami_audit").execute({ install: F.inconsistent });
  const b = (a3.findings ?? []).find((f) => f.id === "bridges");
  check("bridges check hit", !!b);
  check("judged warn", b?.severity === "warn", b?.severity);
  check("title points at the missing Bridge lines", /no Bridge lines/i.test(b?.title ?? ""), b?.title);
  check("evidence marks bridge_count=0", b?.evidence?.bridge_count === 0, JSON.stringify(b?.evidence));
}

section("B6. minimal fixture (null safety with missing files)");
{
  const a4 = await T("aragami_audit").execute({ install: F.minimal });
  check("audit did not error", !a4.error, a4.error);
  check("still carries boundary_notice", (a4.boundary_notice ?? []).length >= 4);
  check("findings is an array", Array.isArray(a4.findings));
  // With no torrc there is still a bridges conclusion -- but it must be the "not enabled"
  // info, never an "bridges enabled" ok (that would be the false positive).
  const nb = (a4.findings ?? []).find((f) => f.id === "bridges");
  check("no torrc reports \"bridges not enabled\" instead of claiming they are on",
    nb?.severity === "info" && /not enabled/i.test(nb?.title ?? ""), JSON.stringify({ s: nb?.severity, t: nb?.title }));
  check("no state does not falsely report guards", !(a4.findings ?? []).some((f) => f.id === "state-guards"));
  check("channel alpha is read", a4.install?.channel === "alpha", a4.install?.channel);
  const e = await T("aragami_env").execute({ install: F.minimal });
  check("aragami_env reads a version even for a minimal install",
    e.targets?.tor?.installs?.[0]?.tor_browser_version === "14.0.0",
    JSON.stringify({ found: e.targets?.tor?.found, version: e.targets?.tor?.installs?.[0]?.tor_browser_version }));
  check("aragami_env reports the explicit path under the Tor branch only (1 of 1)",
    e.targets?.tor?.found === 1 && e.targets?.tor?.installs?.length === 1, JSON.stringify(e.targets?.tor?.found));
}

section("B7. environment-dependent branches (system drive / user-directory residue)");
{
  const savedDrive = process.env.SystemDrive;
  // The tool resolves the user directory with os.homedir(), which reads USERPROFILE on
  // Windows and HOME elsewhere. Setting only USERPROFILE made these assertions pass on the
  // machine they were written on and silently do nothing on Linux, which is where CI runs --
  // the residue checks then found nothing and failed. Both names are set so the test
  // exercises whatever this platform actually resolves.
  const savedHome = { USERPROFILE: process.env.USERPROFILE, HOME: process.env.HOME };
  const setHome = (dir) => { process.env.USERPROFILE = dir; process.env.HOME = dir; };
  const fixtureDrive = path.parse(F.good).root.replace(/\\$/, "");

  try {
    // branch 1: the install lives on the system drive
    process.env.SystemDrive = fixtureDrive;
    const onSys = await T("aragami_audit").execute({ install: F.good, layer: "endpoint" });
    const d1 = (onSys.findings ?? []).find((f) => f.id === "disk-location");
    check("disk-location hit", !!d1);
    check("judged info (same volume)", d1?.severity === "info", d1?.severity);
    check("title names the system drive", /Installed on the system drive/i.test(d1?.title ?? ""), d1?.title);

    // branch 2: the install is not on the system drive
    process.env.SystemDrive = fixtureDrive.toLowerCase() === "c:" ? "D:" : "C:";
    const offSys = await T("aragami_audit").execute({ install: F.good, layer: "endpoint" });
    const d2 = (offSys.findings ?? []).find((f) => f.id === "disk-location");
    check("judged ok (not the system drive)", d2?.severity === "ok", d2?.severity);
    check("title names the non-system drive", /not the system drive/i.test(d2?.title ?? ""), d2?.title);

    // branch 3: Tor residue exists in the user directory
    const fakeHome = path.join(base, "fakehome");
    fs.mkdirSync(path.join(fakeHome, "AppData", "Roaming", "Tor Browser"), { recursive: true });
    fs.mkdirSync(path.join(fakeHome, "Desktop", "Tor Browser"), { recursive: true });
    setHome(fakeHome);
    const traced = await T("aragami_audit").execute({ install: F.good, layer: "endpoint" });
    const t2 = (traced.findings ?? []).find((f) => f.id === "stray-traces");
    check("stray-traces hit", !!t2, JSON.stringify((traced.findings ?? []).map((f) => f.id)));
    check("judged warn", t2?.severity === "warn", t2?.severity);
    check("residue path count is 2", t2?.evidence?.traces?.length === 2, JSON.stringify(t2?.evidence?.traces));

    // a clean user directory -> must report no residue
    const cleanHome = path.join(base, "cleanhome");
    fs.mkdirSync(cleanHome, { recursive: true });
    setHome(cleanHome);
    const clean = await T("aragami_audit").execute({ install: F.good, layer: "endpoint" });
    check("clean user directory reports no residue",
      !(clean.findings ?? []).some((f) => f.id === "stray-traces"),
      JSON.stringify((clean.findings ?? []).map((f) => f.id)));
  } finally {
    if (savedDrive === undefined) delete process.env.SystemDrive; else process.env.SystemDrive = savedDrive;
    for (const [k, v] of Object.entries(savedHome)) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
  }
}

section("B8. version check");
{
  const v = T("aragami_version");
  const offline = await v.execute({ install: F.good, online: false });
  check("offline mode reports the local version only", offline.installed === "15.0.20" && offline.latest === null);
  check("offline mode verdict=unknown", offline.verdict === "unknown");
  check("offline mode makes no network call (no via)", offline.via === undefined);
  check("the report names a resolved target (\"auto\" is an input, never an output)",
    offline.target === "tor" || offline.target === "firefox", String(offline.target));

  const bad = await v.execute({ online: true, proxy: "http://127.0.0.1:9" });
  check("bad proxy is caught gracefully", bad.verdict === "check-failed" && typeof bad.error === "string",
    JSON.stringify({ v: bad.verdict, e: bad.error }));
  check("failure message carries diagnosable detail (not just \"fetch failed\")",
    typeof bad.error === "string" && bad.error.length > 8, bad.error);
  check("failure still carries boundary_notice", (bad.boundary_notice ?? []).length >= 4);
}

section("B9. layer assessment discipline");
{
  const t = T("aragami_layer_assess");
  const r1 = await t.execute({ content_sensitive: true, metadata_sensitive: false });
  check("content-only -> warns off excessive tradecraft",
    (r1.warnings ?? []).some((w) => w.includes("most conspicuous signature")), JSON.stringify(r1.warnings));
  check("content-only -> no metadata-layer method recommended (no Nym/mixnet)",
    !/Nym|mixnet|SimpleX|Cwtch/i.test(r1.recommended_channel ?? ""), r1.recommended_channel);
  check("content-only -> recommends content-layer encryption",
    /encrypt/i.test(r1.recommended_channel ?? ""), r1.recommended_channel);

  // neither layer sensitive -> must say plainly that an ordinary channel is fine
  const r0 = await t.execute({ content_sensitive: false, metadata_sensitive: false });
  check("neither layer sensitive -> recommends an ordinary channel", /No special channel needed/i.test(r0.recommended_channel ?? ""), r0.recommended_channel);

  const r2 = await t.execute({ metadata_sensitive: true, realtime: true });
  check("metadata + realtime -> reports a hard conflict", (r2.warnings ?? []).some((w) => w.includes("HARD CONFLICT")));

  const r3 = await t.execute({ metadata_sensitive: true, counterpart_capability: "email-only" });
  check("email-only -> states the design ceiling", (r3.warnings ?? []).some((w) => w.includes("caps the design")));

  const r4 = await t.execute({ endpoint_shared_or_seizable: true });
  check("seizable endpoint -> points at the endpoint layer", (r4.warnings ?? []).some((w) => w.includes("cryptography cannot reach")));

  const r5 = await t.execute({ must_leave_no_third_party_copy: true, counterpart_capability: "email-only" });
  check("no copy + email-only -> points out the contradiction", (r5.warnings ?? []).some((w) => w.includes("re-evaluate")));

  for (const [i, r] of [r1, r2, r3, r4, r5].entries()) {
    check(`assessment ${i + 1} lists what it does not cover`, (r.does_not_cover ?? []).length >= 4);
    check(`assessment ${i + 1} does not claim safety`, !/you are safe|now safe|guaranteed safe|\bis safe\b/i.test(safeStringify(r)));
    check(`assessment ${i + 1} carries the boundary notice`, (r.boundary_notice ?? []).length >= 4);
    check(`assessment ${i + 1} includes the four-layer model`, (r.layer_model ?? []).length >= 4);
  }
}

section("B10. CLI end-to-end");
{
  const cli = path.join(root, "cli", "index.mjs");
  const run = (args) => {
    try {
      return { out: execFileSync(process.execPath, [cli, ...args], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } }), code: 0 };
    } catch (e) { return { out: String(e.stdout ?? "") + String(e.stderr ?? ""), code: e.status ?? 1 }; }
  };

  const help = run([]);
  check("no arguments prints usage (exit code 1)", help.code === 1 && help.out.includes("Tools:"));

  const env = run(["aragami_env", "--install", F.good]);
  check("aragami_env output is valid JSON", (() => { try { JSON.parse(env.out); return true; } catch { return false; } })());
  check("aragami_env exit code 0", env.code === 0);

  const human = run(["aragami_audit", "--install", F.good, "--human"]);
  check("--human layout takes effect", human.out.includes("Boundary notice") && human.out.includes("Metadata layer"));
  check("--human is not JSON", !human.out.trimStart().startsWith("{"));

  const filtered = run(["aragami_audit", "--install", F.good, "--layer", "crypto", "--human"]);
  check("--layer filtering works in the CLI", filtered.out.includes("Content / authorization layer") && !filtered.out.includes("Transport layer"));

  const assess = run(["aragami_layer_assess", "--metadata_sensitive", "true", "--human"]);
  check("boolean argument is parsed as true in the CLI", assess.out.includes("metadata sensitivity"), assess.out.slice(0, 120));

  const bad = run(["no_such_tool"]);
  check("unknown tool exits 1", bad.code === 1);
}

section("B11. proofreading regressions (locks down the fixed traps)");
{
  // trap 1: with deprecated transports appearing MIXED, the old logic counted only the first
  // kind -> missed report
  const e1 = await T("aragami_audit").execute({ install: F.edge });
  const dp = (e1.findings ?? []).find((f) => f.id === "deprecated-pt");
  check("mixed deprecated transports are still judged \"all deprecated\"", !!dp, JSON.stringify((e1.findings ?? []).map((f) => f.id)));
  check("deprecated list contains both kinds", (dp?.evidence?.deprecated ?? []).length === 2, JSON.stringify(dp?.evidence));

  // trap 2: cache freshness used to be a tautological ternary, always emitting one sentence
  const cache = (e1.findings ?? []).find((f) => f.id.startsWith("cache-") && f.evidence?.stale === true);
  check("caches older than 90 days are marked stale", !!cache, JSON.stringify((e1.findings ?? []).map((f) => f.id)));
  check("idle-cache wording mentions sitting unused for a long time", /Not updated for a long time/.test(cache?.detail ?? ""), cache?.detail);

  const fresh = (await T("aragami_audit").execute({ install: F.good })).findings
    .find((f) => f.id.startsWith("cache-") && f.evidence?.stale === false);
  check("fresh cache is marked stale=false", !!fresh);
  check("fresh-cache wording differs from the idle one", /Updated recently/.test(fresh?.detail ?? ""), fresh?.detail);
  check("the two wordings really are different", cache?.detail !== fresh?.detail);

  // trap 3: a 0-byte sessionCheckpoints used to be reported as "present"
  check("0-byte sessionCheckpoints is not reported as present",
    !(e1.findings ?? []).some((f) => f.id === "session-checkpoints"));

  // trap 4: when nothing is sensitive it must not say "this is a content-layer problem"
  const r0 = await T("aragami_layer_assess").execute({});
  check("no sensitivity at all -> verdict says no special tradecraft is warranted",
    /no special tradecraft/.test(r0.verdict ?? ""), r0.verdict);
  check("LAYER_MODEL solved_by_this_tool are all booleans",
    r0.layer_model.every((l) => typeof l.solved_by_this_tool === "boolean"));
  check("LAYER_MODEL has a tool_role for every layer",
    r0.layer_model.every((l) => typeof l.tool_role === "string" && l.tool_role));

  // trap 5: the mode decision used to match the whole argv (including the full cwd path)
  // against "mcp", so a project living under a directory containing mcp made the CLI
  // misreport itself. It now inspects only the entry script's directory, and reports a
  // neutral "mode" rather than the name of whatever program is hosting it.
  {
    const savedArgv1 = process.argv[1];
    try {
      process.argv[1] = path.join(root, "cli", "index.mjs");
      check("cli entry -> mode=cli", detectEnvironment().mode === "cli", detectEnvironment().mode);

      process.argv[1] = path.join(root, "mcp", "index.mjs");
      check("mcp entry -> mode=mcp", detectEnvironment().mode === "mcp", detectEnvironment().mode);

      // regression point: the directory name contains "mcp" but the entry point is under
      // cli/, so it must not be misjudged
      process.argv[1] = path.join(root, "mcp-probe-dir", "cli", "index.mjs");
      check("directory name contains mcp but entry is under cli/ -> still cli",
        detectEnvironment().mode === "cli", detectEnvironment().mode);
    } finally {
      process.argv[1] = savedArgv1;
    }
  }
}

section("B12. CLI error path still carries the boundary notice");
{
  const cli = path.join(root, "cli", "index.mjs");
  let out = "", code = 0;
  try {
    // --target tor is explicit on purpose: "auto" now falls back to Firefox, so a nonexistent
    // Tor path alone would audit a Firefox profile and never reach the error branch this
    // section exists to cover.
    out = execFileSync(process.execPath, [cli, "aragami_audit", "--target", "tor", "--install", path.join(base, "no-such-install"), "--human"],
      { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } });
  } catch (e) { out = String(e.stdout ?? "") + String(e.stderr ?? ""); code = e.status ?? 1; }
  void code;
  check("the error is printed", /No Tor Browser install found|x /.test(out), out.slice(0, 140));
  check("the error path still prints the boundary notice", out.includes("Boundary notice"), out.slice(0, 200));
  check("the error path still contains the core disclaimer", out.includes("A clean audit is NOT proof of safety"), out.slice(0, 300));
}

section("B13. traverser self-check");
{
  // The traversers must be verifiable too: run matrix and net and confirm they pass on their
  // own. (coverage is not run here -- it would re-run all three traversers, recursively slow.)
  for (const s of ["test/matrix.mjs", "test/net.mjs"]) {
    let ok = false, out = "";
    try {
      out = execFileSync(process.execPath, [path.join(root, s)], {
        encoding: "utf8", env: { ...process.env, NO_COLOR: "1" }, timeout: 300000,
      });
      ok = true;
    } catch (e) { out = String(e.stdout ?? "") + String(e.stderr ?? ""); }
    check(`${s} passes on its own`, ok, out.split("\n").filter((l) => l.includes("[FAIL]")).slice(0, 3).join(" | "));
  }
}

/* ====================== cleanup ====================== */
try { fs.rmSync(base, { recursive: true, force: true }); console.log("\n  \u001b[90mTemporary fixtures cleaned up\u001b[0m"); } catch {}

section("Summary");
console.log(`\n  passed ${pass} / ${pass + fail}`);
if (fail) { console.log("\n  Failed checks:"); for (const f of failures) console.log(`    - ${f}`); }
process.exit(fail === 0 ? 0 : 1);
