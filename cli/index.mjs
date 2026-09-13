#!/usr/bin/env node
// Aragami - command-line driver for the shared core.
//
// Usage:
//   node cli/index.mjs <tool> [--key value | --key=value | '{"json":...}']
//   node cli/index.mjs                    # print usage and the tool list
//
// Output is JSON by default (easy for a program to consume); add --human for readable layout.
// This runs the exact same TOOLS[].execute as the MCP stdio server - there is no second implementation.

import { TOOLS, safeStringify, VERSION } from "../lib/core.mjs";

const C = {
  reset: "\x1b[0m", bold: "\x1b[1m",
  red: "\x1b[31m", green: "\x1b[32m", yellow: "\x1b[33m",
  magenta: "\x1b[35m", cyan: "\x1b[36m", gray: "\x1b[90m",
};
const noColor = !process.stdout.isTTY || process.env.NO_COLOR;
const c = (k, s) => (noColor ? String(s) : `${C[k]}${s}${C.reset}`);

const SEV_STYLE = {
  critical: ["red", "!!"],
  warn: ["yellow", "! "],
  info: ["cyan", "  "],
  ok: ["green", "+ "],
};

const LAYER_LABEL = {
  build: "Build layer",
  transport: "Transport layer",
  crypto: "Content / authorization layer",
  metadata: "Metadata layer (where things actually go wrong)",
  endpoint: "Endpoint layer",
};

function coerceValue(v) {
  if (v === "true") return true;
  if (v === "false") return false;
  if (v === "null") return null;
  if (v !== "" && Number.isFinite(Number(v))) return Number(v);
  return v;
}

function parseTokens(tokens) {
  const flags = {};
  const json = {};
  const positionals = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.startsWith("--")) {
      const body = t.slice(2);
      const eq = body.indexOf("=");
      if (eq >= 0) {
        flags[body.slice(0, eq)] = coerceValue(body.slice(eq + 1));
      } else {
        const next = tokens[i + 1];
        if (next !== undefined && !next.startsWith("--")) {
          flags[body] = coerceValue(next);
          i++;
        } else {
          flags[body] = true;
        }
      }
    } else {
      let parsed = null;
      try { parsed = JSON.parse(t); } catch { /* not JSON */ }
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) Object.assign(json, parsed);
      else positionals.push(t);
    }
  }
  return { flags, json, positionals };
}

/* --------------------------- human-readable layout */

function hr(title) {
  const line = "-".repeat(Math.max(0, 62 - title.length));
  return "\n" + c("magenta", `-- ${title} `) + c("gray", line);
}

function human(result, toolName) {
  const L = [];
  if (result.error) {
    // The error path must carry the boundary notice too: the always-present rule does not
    // depend on success or failure.
    L.push(c("red", `x ${result.error}`));
    L.push(hr("Boundary notice"));
    for (const b of result.boundary_notice ?? []) L.push(c("gray", `  ${b}`));
    return L.join("\n");
  }

  if (toolName === "aragami_version") {
    L.push(hr(`Version freshness - ${result.target ?? "?"}`));
    L.push(`  Installed  ${c("bold", result.installed ?? "unknown")}   (channel ${result.channel ?? "?"}${result.firefox_base ? `, Firefox base ${result.firefox_base}` : ""})`);
    if (result.local_source) L.push(c("gray", `  Local from ${result.local_source}`));
    L.push(`  Latest     ${result.latest ?? "not queried"}`);
    const vmap = {
      current: ["green", "up to date"],
      outdated: ["yellow", "behind the latest release - please update"],
      ahead: ["cyan", "newer than the official release (alpha or a local build?)"],
      "check-failed": ["red", "online check failed"],
      unknown: ["gray", "undetermined"],
    };
    const [col, txt] = vmap[result.verdict] ?? ["gray", result.verdict ?? "unknown"];
    L.push(`  Verdict    ${c(col, txt)}${result.delta ? c("gray", `  ${result.delta}`) : ""}`);
    if (result.error) L.push(c("gray", `  (${result.error})`));
  } else if (toolName === "aragami_env") {
    L.push(hr("Environment"));
    const e = result.environment ?? {};
    L.push(`  mode ${c("bold", e.mode)}  ${e.platform}/${e.arch}  node ${e.node}`);
    const tg = result.targets ?? {};
    L.push(hr(`Tor Browser installs (${tg.tor?.found ?? 0})`));
    for (const i of tg.tor?.installs ?? []) {
      L.push(`  ${c("bold", i.root)}`);
      L.push(c("gray", `      Tor Browser ${i.tor_browser_version ?? "?"}  (${i.channel ?? "?"}, ${i.architecture ?? "?"})  Firefox base ${i.firefox_version ?? "?"}  drive ${i.drive ?? "?"}`));
    }
    L.push(hr(`Firefox profiles (${tg.firefox?.found ?? 0})`));
    for (const p of tg.firefox?.profiles ?? []) {
      const tag = p.is_install_default ? "  <- in use" : (p.is_default ? "  <- legacy default marker" : "");
      L.push(`  ${c("bold", p.profile_dir)}`);
      L.push(c("gray", `      ${p.name ?? "?"}  last used with ${p.last_version ?? "?"}${tag}`));
    }
  } else if (toolName === "aragami_audit") {
    if (result.target === "tor") {
      const inst = result.install ?? {};
      L.push(hr(`Tor Browser posture audit - ${inst.root ?? ""}`));
      L.push(c("gray", `  Tor Browser ${inst.tor_browser_version ?? "?"}  |  Firefox base ${inst.firefox_version ?? "?"}  |  drive ${inst.drive ?? "?"}`));
    } else {
      L.push(hr(`Firefox posture audit - ${result.profile ?? ""}`));
      L.push(c("gray", `  ${result.profiles_found ?? 0} profile(s) discovered on this machine`));
    }
    const t = result.tally ?? {};
    L.push("  " + ["critical", "warn", "info", "ok"].map((k) => c(SEV_STYLE[k][0], `${k} ${t[k] ?? 0}`)).join("   "));

    const byLayer = {};
    for (const f of result.findings ?? []) (byLayer[f.layer] ??= []).push(f);
    for (const [layer, fs] of Object.entries(byLayer)) {
      L.push(hr(LAYER_LABEL[layer] ?? layer));
      for (const f of fs) {
        const [col, mark] = SEV_STYLE[f.severity] ?? ["gray", "? "];
        L.push(`  ${c(col, mark)}${c("bold", f.title)}`);
        L.push(c("gray", `      ${f.detail}`));
      }
    }
  } else if (toolName === "aragami_layer_assess") {
    L.push(hr("Layer assessment"));
    L.push(`  Recommended channel  ${c("bold", result.recommended_channel)}`);
    if (result.steps?.length) {
      L.push(hr("What to do"));
      for (const s of result.steps) L.push(`  ${c("green", "->")} ${s}`);
    }
    if (result.warnings?.length) {
      L.push(hr("Warnings"));
      for (const w of result.warnings) L.push(`  ${c("yellow", "!")} ${w}`);
    }
    L.push(hr("What this does NOT cover"));
    for (const d of result.does_not_cover ?? []) L.push(`  ${c("red", "x")} ${d}`);
    L.push("");
    L.push(`  ${c("bold", result.verdict)}`);
  } else {
    return safeStringify(result, 2);
  }

  L.push(hr("Boundary notice"));
  for (const b of result.boundary_notice ?? []) L.push(c("gray", `  ${b}`));
  return L.join("\n");
}

/* --------------------------- main */

const argv = process.argv.slice(2);
const cmd = argv[0];

if (!cmd || cmd === "--help" || cmd === "-h" || cmd === "help") {
  console.log(`Aragami ${VERSION} - Tor Browser static posture audit

Usage:
  node cli/index.mjs <tool> [--key value | --key=value | '{"json":...}']
  node cli/index.mjs <tool> --human        # human-readable layout
  node cli/index.mjs <tool> <path>         # the first positional is treated as --install <path>

Tools:`);
  // Column width follows the longest tool name (aragami_layer_assess is 20 chars), so the
  // table stays aligned without a hardcoded pad. Long summaries are cut at a word boundary
  // rather than mid-word, since this is the first thing a user reads.
  const nameWidth = Math.max(...TOOLS.map((t) => t.name.length)) + 2;
  for (const t of TOOLS) {
    let s = t.description.split(".")[0].replace(/[.,;:]$/, "");
    if (s.length > 56) {
      s = s.slice(0, 56);
      const sp = s.lastIndexOf(" ");
      if (sp > 20) s = s.slice(0, sp);
      s += "...";
    } else {
      s += ".";
    }
    console.log(`  ${t.name.padEnd(nameWidth)} ${s}`);
  }
  console.log(`
Examples:
  node cli/index.mjs aragami_env --human
  node cli/index.mjs aragami_audit --human
  node cli/index.mjs aragami_audit --layer metadata --min_severity warn --human
  node cli/index.mjs aragami_audit --target firefox --human
  node cli/index.mjs aragami_version --human
  node cli/index.mjs aragami_layer_assess --metadata_sensitive true --realtime true --human

Notes: this tool reads files only, never starts Tor, and does not use the network
       (except aragami_version's public release lookup, which --online false disables).
       A clean audit is not proof of safety.`);
  process.exit(cmd ? 0 : 1);
}

const tool = TOOLS.find((t) => t.name === cmd);
if (!tool) {
  console.error(`Unknown tool: ${cmd}. Available: ${TOOLS.map((t) => t.name).join(", ")}`);
  process.exit(1);
}

const { flags, json, positionals } = parseTokens(argv.slice(1));
const wantHuman = flags.human === true || flags.human === "true";
delete flags.human;

const args = { ...json, ...flags };
if (positionals.length && !args.install) args.install = positionals[0];

// Wrapped rather than using top-level await: the bundled entry point is emitted as
// CommonJS so it can be embedded in a single-file executable, and esbuild cannot lower
// top-level await to CommonJS.
async function main() {
  try {
    const result = await tool.execute(args);
    console.log(wantHuman ? human(result, cmd) : safeStringify(result, 2));
  } catch (e) {
    console.error(`Execution failed: ${(e && e.message) || e}`);
    process.exit(1);
  }
}

main();
