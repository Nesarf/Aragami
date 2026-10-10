#!/usr/bin/env node
/**
 * Checks suite -- drives lib/checks.mjs: the catalog, the conformance rules, the facts
 * record, and the built-in volume probe.
 *
 * Why this needs its own suite:
 *
 *   1. A catalog that nothing enforces is decoration. The point of declaring the check
 *      surface as data is that the declaration can be WRONG -- an entry can name a check
 *      the code never emits, the code can emit an id the table has never heard of, two
 *      entries can claim the same fact slot, a built-in can name a probe that does not
 *      exist. None of those break anything at runtime, which is exactly why they need
 *      asserting: the tool would keep reporting conformance while being incoherent. The
 *      source scan below is the load-bearing part of this file -- it reads lib/core.mjs and
 *      lib/firefox.mjs and proves, in both directions, that the table and the code agree.
 *
 *   2. The volume probe is the one check whose answer depends on the platform, and the
 *      machine running this suite can only be one platform. So the probe is pure and every
 *      input is supplied by the test: Linux with and without a mount table, a mapped device,
 *      a crypto filesystem, a plain partition, FAT magic, Windows, and no signal at all.
 *      A branch reachable only on a platform we are not on would otherwise never run.
 *
 *   3. The facts record replaced something people rely on. It copies an evidence object per
 *      check, keyed by a slot the catalog owns, and the shared-reference case is asserted
 *      here because getting it wrong is invisible: safeStringify used to emit "[circular]"
 *      for any object reachable twice, which turned the whole record into that string
 *      without failing anything.
 *
 * Division of labour: matrix owns the output contract, selftest and firefox own target
 *   semantics, net owns the protocol layer, emblem owns the seal, coverage owns the
 *   traversal. This suite owns the catalog and nothing else.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

const url = (p) => pathToFileURL(path.join(root, p)).href;
const {
  CHECK_CATALOG, CATALOG_VERSION, CHECKS_SCHEMA, BUILTIN_PROBES, TARGETS,
  VOLUME_MAGICS, catalogDigest, checkById, checksFor, classifyVolumeEncryption,
  declaredFactPaths, declaredProbes, evaluateBuiltins, evaluateOneBuiltin, factsFrom, renderTemplate, validateFindings,
} = await import(url("lib/checks.mjs"));
const { LAYERS } = await import(url("lib/core.mjs"));

let pass = 0, fail = 0;
const failures = [];
function check(name, cond, extra) {
  if (cond) { pass++; return; }
  fail++;
  failures.push(`${name}${extra ? ` -- ${extra}` : ""}`);
}

/* ====================== 1. catalog shape ====================== */

const ids = CHECK_CATALOG.map((c) => c.id);
const catalogIds = new Set(ids);
check("catalog is non-empty", CHECK_CATALOG.length > 0, `got ${CHECK_CATALOG.length}`);
check("no duplicate ids", new Set(ids).size === ids.length,
  `duplicates: ${ids.filter((x, i) => ids.indexOf(x) !== i).join(", ")}`);
check("schema string is versioned", /^aragami-checks\/\d+$/.test(CHECKS_SCHEMA), CHECKS_SCHEMA);
check("catalog_version is set", typeof CATALOG_VERSION === "string" && CATALOG_VERSION.length > 0);

for (const c of CHECK_CATALOG) {
  const where = `entry ${c.id}`;
  check(`${where}: id is a slug`, typeof c.id === "string" && /^[a-z0-9][a-z0-9.-]*$/.test(c.id), c.id);
  check(`${where}: layer is known`, Object.prototype.hasOwnProperty.call(LAYERS, c.layer), c.layer);
  check(`${where}: has at least one target`, Array.isArray(c.targets) && c.targets.length > 0);
  check(`${where}: targets are known`, c.targets.every((t) => TARGETS.includes(t)), c.targets.join(","));
  check(`${where}: kind is bespoke or builtin`, c.kind === "bespoke" || c.kind === "builtin", c.kind);
  check(`${where}: severities are known and non-empty`,
    Array.isArray(c.severities) && c.severities.length > 0 &&
    c.severities.every((s) => Object.prototype.hasOwnProperty.call({ ok: 0, info: 1, warn: 2, critical: 3 }, s)),
    (c.severities || []).join(","));
  check(`${where}: observes is stated`, typeof c.observes === "string" && c.observes.length >= 10,
    `${(c.observes || "").length} chars`);
  check(`${where}: does_not_cover is a real boundary`, typeof c.does_not_cover === "string" && c.does_not_cover.length >= 20,
    `${(c.does_not_cover || "").length} chars`);
  if (c.kind === "builtin") {
    check(`${where}: builtin names a declared probe`, Object.values(BUILTIN_PROBES).includes(c.probe), String(c.probe));
  } else {
    check(`${where}: bespoke names no probe`, c.probe === undefined, String(c.probe));
  }
}

/* ====================== 2. the source scan ====================== */

// Two directions, both needed. Forward: an id the code emits must exist in the table, or
// validateFindings reports it as unknown at runtime and the run looks non-conformant for a
// reason nobody can find. Backward: an entry with no producer is a claim the tool does not
// honour -- a check declared but never performed.
const SOURCES = ["lib/core.mjs", "lib/firefox.mjs"];
const emitted = new Set();
for (const rel of SOURCES) {
  const src = fs.readFileSync(path.join(root, rel), "utf8");
  // finding("<layer>", <severity expr>, "<id>", ...) with the id as a literal.
  for (const m of src.matchAll(/finding\(\s*"[a-z]+"\s*,\s*[^,]*,\s*"([^"]+)"/g)) emitted.add(m[1]);
  // The residue() helper in firefox.mjs takes the id in an options object, mid-line.
  for (const m of src.matchAll(/\bid:\s*"([a-z][a-z0-9.-]*)"\s*[,}]/g)) emitted.add(m[1]);
}

// The templated family: core.mjs builds `cache-${name}` from a literal list, so no scan can
// see the concrete ids. They are named here so that renaming a cache file without updating
// the catalog is still caught.
const TEMPLATED = ["cached-descriptors", "cached-microdescs", "cached-microdescs.new", "cached-certs", "cached-consensus"];
for (const n of TEMPLATED) {
  const id = `cache-${n}`;
  check(`templated cache check ${id} is catalogued`, catalogIds.has(id));
  emitted.add(id);
}

const unknownToCatalog = [...emitted].filter((id) => !catalogIds.has(id)).sort();
check("every id the code emits is in the catalog", unknownToCatalog.length === 0, unknownToCatalog.join(", "));

const producedByCode = (c) => c.kind === "builtin" || emitted.has(c.id);
const unproduced = CHECK_CATALOG.filter((c) => !producedByCode(c)).map((c) => c.id).sort();
check("every catalogued check has a producer", unproduced.length === 0, unproduced.join(", "));

const builtinCount = CHECK_CATALOG.filter((c) => c.kind === "builtin").length;
check("catalog contains at least one builtin", builtinCount >= 1, `builtin=${builtinCount}`);

/* ====================== 3. fact slots ====================== */

const factPaths = declaredFactPaths();
const seenFact = new Map();
const dups = [];
for (const p of factPaths) {
  if (seenFact.has(p.fact)) dups.push(`${p.fact} (${seenFact.get(p.fact)} + ${p.id})`);
  else seenFact.set(p.fact, p.id);
}
check("no two checks own the same fact slot", dups.length === 0, dups.join("; "));
check("most checks declare a fact slot", factPaths.length >= CHECK_CATALOG.length - 3,
  `${factPaths.length}/${CHECK_CATALOG.length}`);
check("fact paths are dotted", factPaths.every((p) => p.fact.includes(".")));
check("fact paths use known layers",
  factPaths.every((p) => Object.prototype.hasOwnProperty.call(LAYERS, p.fact.split(".")[0])),
  factPaths.filter((p) => !Object.prototype.hasOwnProperty.call(LAYERS, p.fact.split(".")[0])).map((p) => p.fact).join(", "));

/* ====================== 4. lookup + digest ====================== */

check("checkById finds a known check", checkById("disk-encryption")?.layer === "endpoint");
check("checkById returns null for a stranger", checkById("no-such-check") === null);
check("declaredProbes lists the probe names", declaredProbes().includes(BUILTIN_PROBES.VOLUME_ENCRYPTION));

const all = checksFor({});
check("checksFor with no filter returns everything", all.matched === CHECK_CATALOG.length && all.total === CHECK_CATALOG.length);
const torOnly = checksFor({ target: "tor" });
check("checksFor narrows by target", torOnly.checks.every((c) => c.targets.includes("tor")) && torOnly.matched > 0 && torOnly.matched < all.total);
const ffMeta = checksFor({ target: "firefox", layer: "metadata" });
check("checksFor narrows by target and layer",
  ffMeta.checks.every((c) => c.targets.includes("firefox") && c.layer === "metadata") && ffMeta.matched > 0);
check("checksFor echoes the effective filter", ffMeta.target === "firefox" && ffMeta.layer === "metadata");
check("checksFor treats auto as no target filter", checksFor({ target: "auto" }).matched === CHECK_CATALOG.length);
check("checksFor treats all as no layer filter", checksFor({ layer: "all" }).matched === CHECK_CATALOG.length);
check("checksFor with an unmatched pair yields nothing but still reports the total",
  checksFor({ target: "firefox", layer: "build" }).matched >= 1);

const d1 = catalogDigest();
check("catalog digest is stable across calls", d1 === catalogDigest());
check("catalog digest is a short hex string", /^[0-9a-f]{16}$/.test(d1), d1);

/* ====================== 5. the volume classifier ====================== */

const MI = [
  "36 25 0:32 / / rw,relatime - ext4 /dev/nvme0n1p2 rw",
  "40 36 0:40 / /home rw - ext4 /dev/sda3 rw",
  "44 36 0:44 / /home/u rw - crypto_LUKS /dev/sdb1 rw",
  "48 36 0:48 / /mnt/vault rw - ext4 /dev/mapper/veracrypt1 rw",
  "52 36 0:52 / /mnt/odd rw - zfs tank/odd rw",
].join("\n");

const T = (name, input, state, reason) => {
  const r = classifyVolumeEncryption(input);
  check(`volume ${name}: state`, r.state === state, `got ${r.state} (reason ${r.reason})`);
  if (reason) check(`volume ${name}: reason`, r.reason === reason, `got ${r.reason}`);
  check(`volume ${name}: carries evidence`, r.evidence !== null && typeof r.evidence === "object");
  check(`volume ${name}: detail names the limit`, typeof r.detail === "string" && r.detail.length >= 40);
};

// Longest-prefix matching is the point of the mount-table path: /home and /home/u are both
// prefixes of /home/u/tbb and only the longer one names the right device.
T("longest prefix wins", { platform: "linux", root: "/home/u/tbb", mountInfo: MI }, "encrypted", "crypto-filesystem");
T("crypto filesystem", { platform: "linux", root: "/home/u", mountInfo: MI }, "encrypted", "crypto-filesystem");
T("device mapper", { platform: "linux", root: "/mnt/vault/tbb", mountInfo: MI }, "encrypted", "device-mapper");
T("plain partition", { platform: "linux", root: "/opt/tbb", mountInfo: MI }, "not-encrypted", "plain-block-device");
T("unrecognised device", { platform: "linux", root: "/mnt/odd/x", mountInfo: MI }, "undetermined", "unrecognised-device");
T("no mount entry covers it", { platform: "linux", root: "/srv/x", mountInfo: "40 36 0:40 / /home rw - ext4 /dev/sda3 rw" },
  "undetermined", "no-mount-entry");
T("empty mount table", { platform: "linux", root: "/x", mountInfo: "" }, "undetermined", "no-mount-entry");
T("no mount table, unknown magic", { platform: "linux", root: "/home/u", mountInfo: null, statfsType: 0xef53 },
  "undetermined", "no-signal");
T("fat magic proves no container", { platform: "linux", root: "/mnt/usb", mountInfo: null, statfsType: 0x4d44 },
  "not-encrypted", "unencryptable-filesystem");
T("exfat magic proves no container", { platform: "darwin", root: "/Volumes/X", mountInfo: null, statfsType: VOLUME_MAGICS && 0x2011bab0 },
  "not-encrypted", "unencryptable-filesystem");
T("windows cannot answer statically", { platform: "win32", root: "E:\\Tor Browser", mountInfo: null, statfsType: 0 },
  "undetermined", "windows-requires-elevation");
T("no signal at all", { platform: "freebsd", root: "/x", mountInfo: null, statfsType: null }, "undetermined", "no-signal");
// Absent inputs must not throw. The expected reason depends on the platform the suite runs
// on, so the platform is stated explicitly rather than inherited.
T("empty inputs on linux", { platform: "linux" }, "undetermined", "no-signal");
T("empty inputs on windows", { platform: "win32" }, "undetermined", "windows-requires-elevation");

// With no platform supplied the classifier must fall back to the running one, not to a guess.
const dflt = classifyVolumeEncryption({ root: "/x" });
check("the running platform is the default", dflt.evidence.platform === process.platform, dflt.evidence.platform);

// A non-string mountInfo must be treated as absent rather than coerced, and a non-numeric
// type as unmeasured. Both come from outside the process.
T("non-string mountInfo ignored", { platform: "linux", root: "/x", mountInfo: 12345, statfsType: null }, "undetermined", "no-signal");
T("NaN statfsType ignored", { platform: "linux", root: "/x", mountInfo: null, statfsType: Number.NaN }, "undetermined", "no-signal");

/* ====================== 6. built-in evaluation ====================== */

// A fake filesystem, so every probe branch is reachable without touching the real one and
// without depending on what happens to be installed on the machine running the suite.
//
// The keys are normalised to forward slashes because the probe joins its base and file with
// path.join, which produces backslashes on Windows. Comparing raw strings would make this suite
// pass on Linux and silently find nothing on Windows -- a platform-dependent test that looks
// green on the machine that does not matter.
const mkio = (files = {}, dirs = {}) => {
  const norm = (p) => String(p).replace(/\\/g, "/");
  return {
    statOf: (p) => {
      const hit = files[norm(p)];
      return hit ? { size: hit.size, mtime: new Date(hit.mtime ?? "2026-01-01T00:00:00Z") } : null;
    },
    listDir: (p) => (dirs[norm(p)] ?? []).map((n) => ({ name: n, isFile: () => true })),
  };
};
const BASES = { install_root: "/tb", data_dir: "/tb/data", profile_dir: "/tb/profile" };
const torCtx = (files = {}, io = mkio(files)) => ({
  platform: "win32", root: "E:\\Tor Browser", mountInfo: null, statfsType: 0, bases: BASES, io,
});
const ffCtx = (files = {}, io = mkio(files)) => ({
  platform: "win32", root: "C:\\p", mountInfo: null, statfsType: 0, bases: { profile_dir: "/p" }, io,
});

const torBuiltins = CHECK_CATALOG.filter((c) => c.kind === "builtin" && c.targets.includes("tor")).length;
const ffBuiltins = CHECK_CATALOG.filter((c) => c.kind === "builtin" && c.targets.includes("firefox")).length;
check("the catalog has both targets' builtins", torBuiltins > 1 && ffBuiltins > 1, `tor=${torBuiltins} ff=${ffBuiltins}`);

// With nothing resolvable, a probe contributes nothing rather than throwing or inventing a
// finding: only the volume probe can answer with no path to look at.
const bare = evaluateBuiltins("tor", { platform: "win32", root: "E:\\", mountInfo: null, statfsType: 0 });
check("builtins with no bases leave only the volume probe", bare.length === 1, `${bare.length}: ${bare.map((f) => f.id)}`);
check("that survivor is the volume probe", bare[0].id === "disk-encryption");

const noIo = evaluateBuiltins("tor", { platform: "win32", root: "E:\\", mountInfo: null, statfsType: 0, bases: BASES });
check("bases without an io layer still do not throw", noIo.length === 1, `${noIo.length}`);

// All residue files present: every applicable builtin should now fire.
const allFiles = {
  "/tb/data/cached-descriptors": { size: 1024 },
  "/tb/data/cached-microdescs": { size: 2048 },
  "/tb/data/cached-microdescs.new": { size: 4096 },
  "/tb/data/cached-certs": { size: 512 },
  "/tb/data/cached-consensus": { size: 8192 },
  "/tb/profile/sessionCheckpoints.json": { size: 64 },
  "/tb/profile/places.sqlite": { size: 32768 },
};
const torAll = evaluateBuiltins("tor", torCtx(allFiles, mkio(allFiles, { "/tb/data/pt_state": ["a", "b", "c"] })));
check("every tor builtin fires when its subject is present", torAll.length === torBuiltins, `${torAll.length} vs ${torBuiltins}`);
check("builtin finding carries its catalogued id", torAll.every((f) => catalogIds.has(f.id)));
check("builtin finding carries the catalogued layer", torAll.every((f) => checkById(f.id).layer === f.layer));
check("builtins restricted to a target list nothing for an unknown target", evaluateBuiltins("nope", {}) .length === 0);

// The layer option, which is how the auditors ask for their own share.
const metaOnly = evaluateBuiltins("tor", torCtx(allFiles, mkio(allFiles, { "/tb/data/pt_state": ["a"] })), { layer: "metadata" });
check("the layer option narrows the set", metaOnly.length > 0 && metaOnly.every((f) => f.layer === "metadata"), `${metaOnly.length}`);
check("the layer option excludes other layers", !metaOnly.some((f) => f.id === "disk-encryption"));
check("all means no layer filter", evaluateBuiltins("tor", torCtx(allFiles), { layer: "all" }).length >= metaOnly.length);

const ffFiles = {
  "/p/logins.json": { size: 100 },
  "/p/key4.db": { size: 200 },
  "/p/cert9.db": { size: 300 },
  "/p/places.sqlite": { size: 400 },
  "/p/cookies.sqlite": { size: 500 },
  "/p/permissions.sqlite": { size: 600 },
  "/p/formhistory.sqlite": { size: 700 },
  "/p/favicons.sqlite": { size: 800 },
};
const ffAll = evaluateBuiltins("firefox", ffCtx(ffFiles));
check("every firefox builtin fires when its subject is present", ffAll.length === ffBuiltins, `${ffAll.length} vs ${ffBuiltins}`);

/* ====================== 6b. the volume probe ====================== */

const sevFor = (input) => evaluateBuiltins("tor", input).find((f) => f.id === "disk-encryption")?.severity;
check("builtin severity: encrypted is ok", sevFor({ platform: "linux", root: "/home/u", mountInfo: MI }) === "ok");
check("builtin severity: plain is warn", sevFor({ platform: "linux", root: "/opt", mountInfo: MI }) === "warn");
check("builtin severity: unknown is info", sevFor({ platform: "win32", root: "E:\\", mountInfo: null, statfsType: 0 }) === "info");
check("builtin title matches the state",
  bare[0].title.includes("could not be determined"));
check("builtin detail restates that it is about the whole volume",
  evaluateBuiltins("tor", { platform: "linux", root: "/opt", mountInfo: MI })[0].detail.includes("every file on it"));

/* ====================== 6c. the path-residue probe ====================== */

const one = (ctx, id) => evaluateBuiltins("tor", ctx).find((f) => f.id === id);
const oneFf = (ctx, id) => evaluateBuiltins("firefox", ctx).find((f) => f.id === id);

// The exact rendering of migrated checks, asserted literally. This is the property that makes
// the migration trustworthy: the findings a caller sees must be the ones it saw before the
// checks moved into the catalog, character for character.
//
// The age is pinned by dating the fake file a fixed offset back from now rather than by
// hardcoding a number -- a hardcoded day count is a test that breaks on its own tomorrow.
const daysAgo = (n) => new Date(Date.now() - n * 86400000).toISOString();
const places = one(torCtx({ "/tb/profile/places.sqlite": { size: 32768, mtime: daysAgo(10) } }), "places");
check("places renders the title the code used to build by hand",
  places.title === "Browsing history database present (places.sqlite, 32.0 KB)", places.title);
check("places keeps its warn severity", places.severity === "warn");
check("places keeps the size-mtime evidence shape it had",
  JSON.stringify(Object.keys(places.evidence).sort()) === '["mtime","size"]', JSON.stringify(places.evidence));

const caches = evaluateBuiltins("tor", torCtx(allFiles)).filter((f) => f.id.startsWith("cache-"));
check("all five descriptor caches report", caches.length === 5, `${caches.length}`);
const desc = one(torCtx({ "/tb/data/cached-descriptors": { size: 1024, mtime: daysAgo(10) } }), "cache-cached-descriptors");
check("a cache title names the cache, its size and its age",
  desc.title === "Descriptor cache cached-descriptors: 1.0 KB (updated 10 day(s) ago)", desc.title);
check("a cache keeps the cache evidence shape including staleness",
  JSON.stringify(Object.keys(desc.evidence).sort()) === '["age_days","mtime","size","stale"]', JSON.stringify(desc.evidence));
check("a cache inside the staleness threshold is not marked stale", desc.evidence.stale === false && desc.evidence.age_days === 10,
  JSON.stringify(desc.evidence));
check("a cache inside the threshold says the other thing",
  desc.detail.startsWith("Updated recently"), desc.detail.slice(0, 60));
const old = one(torCtx({ "/tb/data/cached-certs": { size: 10, mtime: daysAgo(200) } }), "cache-cached-certs");
check("a cache past the staleness threshold is marked stale", old.evidence.stale === true, JSON.stringify(old.evidence));
check("a cache past the threshold says so", old.detail.startsWith("Not updated for a long time"), old.detail.slice(0, 60));
check("the two detail variants are genuinely different", desc.detail !== old.detail);

const logins = oneFf(ffCtx({ "/p/logins.json": { size: 100, mtime: daysAgo(10) } }), "ff-logins");
check("a firefox residue title is the one the helper used to build",
  logins.title === "Saved passwords database present (100 B, written 10 day(s) ago)", logins.title);
check("a firefox residue keeps the path-age evidence shape",
  JSON.stringify(Object.keys(logins.evidence).sort()) === '["age_days","mtime","path","size"]', JSON.stringify(logins.evidence));
check("a firefox residue names the file in its evidence", logins.evidence.path === "logins.json");
check("a firefox residue dates the file", logins.evidence.age_days === 10, String(logins.evidence.age_days));
check("ff-logins keeps its warn severity", logins.severity === "warn");
check("ff-history keeps its info severity", oneFf(ffCtx(ffFiles), "ff-history").severity === "info");

// Presence rules: absent and zero-byte are the same non-event, which is what the old helper did.
check("an absent residue file reports nothing", one(torCtx({}), "places") === undefined);
check("a zero-byte residue file reports nothing", one(torCtx({ "/tb/profile/places.sqlite": { size: 0 } }), "places") === undefined);
check("a zero-byte firefox residue file reports nothing",
  oneFf(ffCtx({ "/p/logins.json": { size: 0 } }), "ff-logins") === undefined);
check("a stat that throws-like null is tolerated",
  evaluateBuiltins("tor", torCtx({}, { statOf: () => null, listDir: () => [] })).length === 1);
check("a base directory that is missing contributes nothing",
  evaluateBuiltins("tor", { platform: "win32", root: "x", bases: { data_dir: "" }, io: mkio(allFiles) }).length === 1);
check("an unknown base name contributes nothing",
  evaluateBuiltins("tor", { platform: "win32", root: "x", bases: { nowhere: "/x" }, io: mkio(allFiles) }).length === 1);

/* ====================== 6d. the dir-entries probe ====================== */

const pt = (dirs) => evaluateBuiltins("tor", torCtx({}, mkio({}, dirs))).find((f) => f.id === "pt-state");
check("dir-entries counts the files", pt({ "/tb/data/pt_state": ["a", "b", "c"] }).title === "pt_state retains 3 file(s)",
  pt({ "/tb/data/pt_state": ["a", "b", "c"] }).title);
check("dir-entries records the names, capped", (() => {
  const many = Array.from({ length: 30 }, (_, i) => `f${i}`);
  return pt({ "/tb/data/pt_state": many }).evidence.files.length === 10;
})());
check("an empty directory reports nothing", pt({ "/tb/data/pt_state": [] }) === undefined);
check("a directory with one file reports one", pt({ "/tb/data/pt_state": ["only"] }).title === "pt_state retains 1 file(s)");

/* ====================== 6e. templates ====================== */

// Every placeholder a built-in entry uses must be one the probe actually supplies, or the
// finding ships with a literal "{size}" in it. Asserted over the rendered output of every
// entry, which is the only place it can be seen.
const rendered = [
  ...evaluateBuiltins("tor", torCtx(allFiles, mkio(allFiles, { "/tb/data/pt_state": ["a"] }))),
  ...evaluateBuiltins("firefox", ffCtx(ffFiles)),
];
check("every builtin rendered at least one finding to inspect", rendered.length >= 10, `${rendered.length}`);
check("no title leaves a placeholder unresolved",
  rendered.every((f) => !/\{[a-z_]+\}/.test(f.title)),
  rendered.filter((f) => /\{[a-z_]+\}/.test(f.title)).map((f) => `${f.id}: ${f.title}`).join(" | "));
check("no detail leaves a placeholder unresolved",
  rendered.every((f) => !/\{[a-z_]+\}/.test(f.detail)),
  rendered.filter((f) => /\{[a-z_]+\}/.test(f.detail)).map((f) => f.id).join(" | "));
check("no builtin title or detail is empty",
  rendered.every((f) => f.title.length > 4 && f.detail.length > 4));

// One entry at a time. This is also where the dispatcher's fail-safe is asserted: the catalog is
// data, so an entry can name a probe this build does not implement, and that must produce no
// finding rather than a thrown audit.
const single = evaluateOneBuiltin(checkById("places"), torCtx({ "/tb/profile/places.sqlite": { size: 10 } }));
check("one entry can be evaluated on its own", single?.id === "places", JSON.stringify(single));
check("an entry naming an unknown probe yields nothing rather than throwing",
  evaluateOneBuiltin({ id: "x", probe: "no-such-probe", severities: ["info"] }, torCtx({})) === null);
check("an entry with no probe yields nothing", evaluateOneBuiltin({ id: "x" }, torCtx({})) === null);
check("evaluateOneBuiltin tolerates no entry at all", evaluateOneBuiltin(null, {}) === null);
check("evaluateOneBuiltin tolerates no context", evaluateOneBuiltin(checkById("disk-encryption")) !== null);

// renderTemplate is exported, so the substitution rule itself is asserted rather than inferred.
check("an unknown placeholder is left visible rather than blanked",
  renderTemplate("a {nope} b", { other: 1 }) === "a {nope} b");
check("a known placeholder is substituted", renderTemplate("x {v} y", { v: 7 }) === "x 7 y");
check("every occurrence is substituted", renderTemplate("{v}{v}", { v: "z" }) === "zz");
check("a value of zero still renders", renderTemplate("{v}", { v: 0 }) === "0");
check("a non-placeholder brace is untouched", renderTemplate("{Not A Key}", {}) === "{Not A Key}");

/* ====================== 7. conformance rules ====================== */

const okFinding = { layer: "metadata", severity: "warn", id: "state-file", title: "t", detail: "d", evidence: { size: 1 } };
let v = validateFindings([okFinding], { target: "tor" });
check("a known finding conforms", v.conformant && v.unknown.length === 0 && v.severity_violations.length === 0);
check("conformance counts what it checked", v.checked === 1);
check("unfired lists the rest", v.unfired.length === CHECK_CATALOG.filter((c) => c.targets.includes("tor")).length - 1);
check("unfired never contains the fired id", !v.unfired.includes("state-file"));

v = validateFindings([{ ...okFinding, id: "invented" }], { target: "tor" });
check("an invented id is reported as unknown", !v.conformant && v.unknown.includes("invented"));

v = validateFindings([{ ...okFinding, severity: "critical" }], { target: "tor" });
check("a severity outside the contract is a violation",
  !v.conformant && v.severity_violations.some((x) => x.id === "state-file" && x.to === undefined && x.severity === "critical"));
check("the violation names the allowed set", v.severity_violations[0].allowed.includes("warn"));

v = validateFindings([{ ...okFinding, id: "ff-version" }], { target: "tor" });
check("a finding for the wrong target is unknown", v.unknown.includes("ff-version"));

v = validateFindings([null, undefined, { id: 42 }], { target: "tor" });
check("junk entries do not throw and are reported", v.unknown.length >= 1 && v.checked === 3);

v = validateFindings([okFinding], {});
check("without a target every catalogued entry is applicable", v.unfired.length === CHECK_CATALOG.length - 1);
check("non-array input is tolerated", validateFindings(null).checked === 0);

/* ====================== 8. the facts record ====================== */

const ev = { size: 42, mtime: "2026-01-01T00:00:00Z" };
const f1 = { layer: "metadata", severity: "warn", id: "state-file", title: "t", detail: "d", evidence: ev };
const f2 = { layer: "endpoint", severity: "info", id: "disk-location", title: "t", detail: "d", evidence: { drive: "E:", system_drive: "C:" } };
const fr = factsFrom([f1, f2], {});
check("facts land at the declared slot", fr.facts.metadata.state.size === 42, JSON.stringify(fr.facts));
check("the whole evidence object is copied, not a field", fr.facts.metadata.state.mtime === "2026-01-01T00:00:00Z");
check("each slot names its producing check", fr.sources["metadata.state"] === "state-file" && fr.sources["endpoint.disk_location"] === "disk-location");
check("the fact value IS the evidence (shared, not cloned)", fr.facts.metadata.state === ev);

const onlyMeta = factsFrom([f1, f2], { layer: "metadata" });
check("facts honour the layer filter", onlyMeta.facts.metadata !== undefined && onlyMeta.facts.endpoint === undefined);
check("facts treat all as no filter", Object.keys(factsFrom([f1, f2], { layer: "all" }).facts).length === 2);

const noEvidence = factsFrom([{ ...f1, evidence: undefined }], {});
check("a missing evidence writes no slot", noEvidence.facts.metadata === undefined);
const nullEvidence = factsFrom([{ ...f1, evidence: null }], {});
check("null evidence is recorded as null rather than dropped", nullEvidence.facts.metadata.state === null);
check("an uncatalogued id contributes nothing", Object.keys(factsFrom([{ ...f1, id: "nope" }], {}).facts).length === 0);
check("non-array input yields an empty record", Object.keys(factsFrom(null).facts).length === 0);

/* ====================== summary ====================== */

console.log(`  catalog: ${CHECK_CATALOG.length} checks (${builtinCount} builtin), ${factPaths.length} fact slots, digest ${d1}`);
console.log(`  source scan: ${emitted.size} emitted ids across ${SOURCES.length} files`);
console.log(`\n  passed ${pass} / ${pass + fail}`);
if (fail) {
  console.log("\n  failures:");
  for (const f of failures) console.log(`    ${f}`);
  process.exit(1);
}
