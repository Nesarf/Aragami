#!/usr/bin/env node
/**
 * Bundle the entry points into self-contained files.
 *
 * Why this exists: the MCP SDK pulls in 95 packages and 16 MB. Shipping that inside a
 * portable zip makes the artifact large and slow to build, and a single-file executable is
 * impossible without it. Bundling reduces the payload to a single file, and the same output
 * feeds both the portable distribution and the Node SEA executable.
 *
 * The bundled entry points are build artifacts, not source: `npm i -g aragami` and running
 * from a checkout both keep using cli/index.mjs and mcp/index.mjs directly.
 *
 * Usage:
 *   node packaging/bundle.mjs                          # tools: dist/cli.mjs + dist/mcp.mjs
 *   node packaging/bundle.mjs --entry sea              # dist/aragami.mjs, CLI + MCP in one file
 *   node packaging/bundle.mjs --entry sea --bake-target tor
 *
 * `--bake-target` exists because a single-file executable cannot export an environment
 * variable to itself. ARAGAMI_TARGET is replaced with a literal at build time, so each
 * per-target executable opens with that target by default. An explicit --target argument
 * still overrides it, because resolveTarget() checks the argument before the default.
 */

import { build } from "esbuild";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

function arg(name, fallback = null) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : fallback;
}

// CommonJS is the default because a single-file executable is loaded as CommonJS, and
// Node's SEA loader decides that from the executable's extension, not from the payload.
const format = arg("--format", "cjs");
const outdir = path.join(root, arg("--outdir", "dist"));
const entry = arg("--entry", "tools");
const bakeTarget = arg("--bake-target");

if (!["cjs", "esm"].includes(format)) {
  console.error(`unsupported format: ${format}`);
  process.exit(2);
}

if (bakeTarget && !["tor", "firefox"].includes(bakeTarget)) {
  console.error(`unsupported bake target: ${bakeTarget}`);
  process.exit(2);
}
if (!["tools", "sea"].includes(entry)) {
  console.error(`unsupported entry set: ${entry}`);
  process.exit(2);
}

const ext = format === "cjs" ? ".cjs" : ".mjs";

fs.mkdirSync(outdir, { recursive: true });

const options = {
  bundle: true,
  platform: "node",
  // Use the requested format. This was hardcoded to "esm" when the script was rewritten,
  // which silently produced ESM content under a .cjs extension -- the file then failed to
  // load with "Cannot use import statement outside a module".
  format,
  // Node 18 is the declared floor, so nothing newer may be emitted.
  target: "node18",
  // Keep the output readable: this is a security tool, and a minified blob would defeat
  // inspection. That matters more here than a few kilobytes.
  minify: false,
  sourcemap: false,
  legalComments: "none",
  logLevel: "warning",
  // No code splitting: everything must land in one file for the executable path.
  splitting: false,
  // The CJS output has no import.meta, and lib/emblem.mjs reads it to find the seal beside
  // the module. esbuild says so on every build. The read is type-guarded there and the bundle
  // carries the seal inline, so the warning is expected and the information belongs in that
  // comment rather than in a line of build output that is always there and never actionable.
  // Only this diagnostic is silenced: everything else still reports.
  logOverride: { "empty-import-meta": "silent" },
};

if (entry === "sea") {
  options.entryPoints = [path.join(root, "packaging", "sea-entry.mjs")];
  options.outfile = path.join(outdir, "aragami" + ext);
} else {
  options.entryPoints = {
    cli: path.join(root, "cli", "index.mjs"),
    mcp: path.join(root, "mcp", "index.mjs"),
  };
  options.outdir = outdir;
  options.outExtension = { ".js": ext };
}

// The emblem rides in the bundle as well as beside it. The single-file executable has no
// files next to it, so a disk read there would find nothing; lib/emblem.mjs reads this
// identifier behind a typeof guard, which is what lets one source work both bundled and
// unbundled. An absent file inlines the empty string, which the guard treats as "not
// inlined" and which sends the loader to disk -- the same behaviour as no define at all,
// so a checkout without an emblem still builds.
const emblemPath = path.join(root, "Aragami");
const emblemText = fs.existsSync(emblemPath) ? fs.readFileSync(emblemPath, "utf8") : "";
options.define = { __ARAGAMI_EMBLEM__: JSON.stringify(emblemText) };

if (bakeTarget) {
  options.define["process.env.ARAGAMI_TARGET"] = JSON.stringify(bakeTarget);
}

const result = await build(options);
if (result.errors?.length) {
  for (const e of result.errors) console.error(e.text);
  process.exit(1);
}

const produced = entry === "sea"
  ? [options.outfile]
  : ["cli", "mcp"].map((name) => path.join(outdir, name + ext));
for (const f of produced) {
  const st = fs.statSync(f);
  const suffix = bakeTarget ? `  (default target: ${bakeTarget})` : "";
  console.log(`  ${path.relative(root, f)}  ${(st.size / 1024).toFixed(0)} KB${suffix}`);
}

/*
  The bundle is run, not merely measured.

  A size and an exit code of zero from esbuild say the file was written; they say nothing
  about whether it loads. One defect lived in exactly that gap: lib/emblem.mjs read
  import.meta.url at module scope, esbuild replaced import.meta with an empty object under
  the CJS format, and fileURLToPath(undefined) threw on load -- so both bundled entry points
  failed to start while every artifact still built, uploaded and installed. Nothing in the
  pipeline executed the thing being shipped until it reached a user.

  So the CLI bundle is invoked here, on a verb that touches no network and no configuration.
  The check is deliberately about loading rather than about output: the contract of the
  output belongs to the suites, and this is only asking whether the file runs at all.

  The SEA entry is not run because the blob it needs does not exist yet at this point, and
  pack-sea.ps1 exercises it after injection.
*/
if (entry !== "sea") {
  const cliBundle = path.join(outdir, "cli" + ext);
  const r = spawnSync(process.execPath, [cliBundle, "aragami_env"], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } });
  if (r.status !== 0) {
    console.error(`  the bundled CLI did not start (exit ${r.status})`);
    const detail = String(r.stderr ?? "").trim().split("\n").slice(0, 4);
    for (const line of detail) console.error(`    ${line}`);
    process.exit(1);
  }
  console.log("  the bundled CLI starts");
}
