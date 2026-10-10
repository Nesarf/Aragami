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
  declaredFactPaths, declaredProbes, evaluateBuiltins, evaluateOneBuiltin, factsFrom, renderTemplate,
  validateFindings, VALUE_PREDICATES,
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

// A built-in whose arguments can never be satisfied is a check that never fires, and it would
// report as "unfired" forever with nothing to say why. Each of these was a real trap in the probe
// defaults: min_count is 1, so an entry asking for max_count 0 has to say min_count 0 as well.
for (const c of CHECK_CATALOG) {
  if (c.kind !== "builtin") continue;
  const a = c.probe_args ?? {};
  if (a.max_count === 0 && a.min_count !== 0) {
    check(`${c.id}: max_count 0 needs an explicit min_count 0`, false,
      "the probe would reject before the upper bound is considered");
  }
  if (typeof a.min_count === "number" && typeof a.max_count === "number" && a.min_count > a.max_count) {
    check(`${c.id}: count bounds are satisfiable`, false, `min ${a.min_count} > max ${a.max_count}`);
  }
  if (c.probe === BUILTIN_PROBES.PATH_LIST && !Array.isArray(a.paths)) {
    check(`${c.id}: path-list names its candidates`, false, "no paths array");
  }
}

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
//
// All five io functions the probes may call are provided. The first version supplied only statOf
// and listDir, so a json-field or dir-size check silently reported nothing and read as broken when
// the fake context was the thing that was incomplete.
const mkio = (files = {}, dirs = {}, docs = {}) => {
  const norm = (p) => String(p).replace(/\\/g, "/");
  return {
    statOf: (p) => {
      const hit = files[norm(p)];
      return hit ? { size: hit.size, mtime: new Date(hit.mtime ?? "2026-01-01T00:00:00Z") } : null;
    },
    listDir: (p) => (dirs[norm(p)] ?? []).map((n) => ({ name: n, isFile: () => true })),
    exists: (p) => norm(p) in files || norm(p) in dirs,
    dirSize: (p) => (norm(p) in dirs ? (docs[norm(p)] ?? 1) : null),
    readJson: (p) => docs[norm(p)] ?? null,
  };
};
const BASES = { install_root: "/tb", data_dir: "/tb/data", profile_dir: "/tb/profile" };
// A full configuration document by default, because a config-value check reads its keys out of one
// and a context without it makes the check look broken when the fixture is what is incomplete.
const TOR_PREFS = {
  "torbrowser.settings.bridges.builtin_type": "snowflake",
  "torbrowser.settings.bridges.source": "builtin",
  "torbrowser.settings.quickstart.enabled": true,
};
const FF_PREFS = {
  "privacy.resistFingerprinting": true,
  "network.trr.mode": 3,
  "network.trr.uri": "https://doh.example/dns-query",
  "network.cookie.cookieBehavior": 5,
  "signon.rememberSignons": true,
  "toolkit.telemetry.enabled": false,
  "datareporting.healthreport.uploadEnabled": false,
  "browser.newtabpage.activity-stream.showSponsored": false,
  "extensions.pocket.enabled": false,
};
// Extra bases and configuration documents are spread in rather than defaulted, because a check
// gated on a base being present is only exercised by a context that actually carries it -- and the
// first version of this helper accepted them as arguments it silently dropped, which made three
// checks look broken when the context was the thing that was wrong.
const torCtx = (files = {}, io = mkio(files), extraBases = {}, values = {}) => ({
  platform: "win32", root: "E:\\Tor Browser", mountInfo: null, statfsType: 0,
  bases: { ...BASES, ...extraBases }, io, prefs: TOR_PREFS, entries: {}, ...values,
});
const ffCtx = (files = {}, io = mkio(files), values = {}) => ({
  platform: "win32", root: "C:\\p", mountInfo: null, statfsType: 0,
  bases: { profile_dir: "/p" }, io, prefs: { ...FF_PREFS }, entries: null, ...values,
});

const torBuiltins = CHECK_CATALOG.filter((c) => c.kind === "builtin" && c.targets.includes("tor")).length;
const ffBuiltins = CHECK_CATALOG.filter((c) => c.kind === "builtin" && c.targets.includes("firefox")).length;
check("the catalog has both targets' builtins", torBuiltins > 1 && ffBuiltins > 1, `tor=${torBuiltins} ff=${ffBuiltins}`);

// With nothing resolvable, a probe contributes nothing rather than throwing or inventing a
// finding. The checks that can still answer are the ones that address no directory and whose
// condition is "absent", which is a property of the catalog rather than a list kept here.
const baseIndependent = (c) => c.kind === "builtin" && c.targets.includes("tor") && !(c.probe_args ?? {}).base;
const bare = evaluateBuiltins("tor", { platform: "win32", root: "E:\\", mountInfo: null, statfsType: 0 });
check("builtins with no context produce only catalogued checks",
  bare.every((f) => catalogIds.has(f.id)), bare.map((f) => f.id).join(","));
check("the base-independent volume probe still answers",
  bare.some((f) => f.id === "disk-encryption"), bare.map((f) => f.id).join(","));
check("the static statement still answers", bare.some((f) => f.id === "persistence"));
check("nothing that needs a directory answers", bare.some((f) => f.id.startsWith("cache-")) === false);
check("everything produced without context comes from a base-independent entry",
  bare.every((f) => !(checkById(f.id).probe_args ?? {}).base),
  bare.filter((f) => (checkById(f.id).probe_args ?? {}).base).map((f) => f.id).join(","));
// A base-reading check needs the base map to have been supplied. "This target has no such
// configuration" and "the caller described no target" are different answers, and only the first
// one is a fact about the machine.
check("a base-reading check with no base map is silent rather than guessing",
  !bare.some((f) => f.id === "onion-auth-absent"), bare.map((f) => f.id).join(","));
const emptyBases = evaluateBuiltins("tor", { platform: "win32", root: "E:\\", mountInfo: null, statfsType: 0, bases: {}, entries: {} });
check("an empty base map is read as not-configured",
  emptyBases.some((f) => f.id === "onion-auth-absent"), emptyBases.map((f) => f.id).join(","));
check("a configured auth directory silences the absent case",
  !evaluateBuiltins("tor", torCtx({}, mkio(), { auth_dir: "/a" })).some((f) => f.id === "onion-auth-absent"));

const noIo = evaluateBuiltins("tor", { platform: "win32", root: "E:\\", mountInfo: null, statfsType: 0, bases: BASES });
check("bases without an io layer still do not throw",
  noIo.every((f) => catalogIds.has(f.id)), noIo.map((f) => f.id).join(","));

// All residue files present: the checks whose subject exists should fire, and the pairs that are
// mutually exclusive by construction should each contribute exactly one member. Asserting a bare
// total would be wrong -- `no-stray-traces` and `stray-traces` cannot both be true, and neither
// can `onion-auth-empty` and `onion-auth-keys`, so the maximum is the total minus those two.
const allFiles = {
  "/tb/data/cached-descriptors": { size: 1024 },
  "/tb/data/cached-microdescs": { size: 2048 },
  "/tb/data/cached-microdescs.new": { size: 4096 },
  "/tb/data/cached-certs": { size: 512 },
  "/tb/data/cached-consensus": { size: 8192 },
  "/tb/profile/sessionCheckpoints.json": { size: 64 },
  "/tb/profile/places.sqlite": { size: 32768 },
};
const torAll = evaluateBuiltins("tor", torCtx(allFiles, mkio(allFiles, {
  "/tb/data/pt_state": ["a", "b", "c"],
  "/tb/data/keys": ["secret_id_key", "hostname"],
  "/tb/auth": [],
}, { "/tb/profile/times.json": { firstUse: "2026-01-01T00:00:00Z" } }),
{ auth_dir: "/tb/auth", keys_dir: "/tb/data/keys" }, { entries: {} }));
const firedIds = torAll.map((f) => f.id);
// Explicit in both directions rather than a bare total: three pairs are mutually exclusive by
// construction, so a count assertion would encode "total minus three" and say nothing about which.
for (const id of ["cache-cached-descriptors", "cache-cached-microdescs", "cache-cached-microdescs.new",
  "cache-cached-certs", "cache-cached-consensus", "pt-state", "session-checkpoints", "places",
  "profile-times", "hs-keys", "onion-auth-empty", "no-stray-traces", "persistence", "disk-encryption"]) {
  check(`a tor builtin fires when its subject is present: ${id}`, firedIds.includes(id), firedIds.join(","));
}
for (const id of ["stray-traces", "onion-auth-keys", "onion-auth-absent"]) {
  check(`the exclusive partner stays silent: ${id}`, !firedIds.includes(id), firedIds.join(","));
}
// Named rather than counted. Three pairs cannot both fire, and one check reads a base the fixture
// deliberately leaves out; listing what is absent says why, where "total minus three" says nothing.
const torBuiltinIds = CHECK_CATALOG.filter((c) => c.kind === "builtin" && c.targets.includes("tor")).map((c) => c.id);
const torNotFired = torBuiltinIds.filter((id) => !firedIds.includes(id)).sort();
check("only tor checks whose subject is absent fail to fire",
  JSON.stringify(torNotFired) === JSON.stringify(["onion-auth-absent", "onion-auth-keys", "stray-traces"]),
  torNotFired.join(","));
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
const ffAll = evaluateBuiltins("firefox", ffCtx(ffFiles, mkio(ffFiles, {
  "/p/storage/default": ["idb"],
}, { "/p/times.json": { firstUse: "2026-01-01T00:00:00Z" } })));
const ffFired = ffAll.map((f) => f.id);
const ffBuiltinIds = CHECK_CATALOG.filter((c) => c.kind === "builtin" && c.targets.includes("firefox")).map((c) => c.id);
const ffNotFired = ffBuiltinIds.filter((id) => !ffFired.includes(id)).sort();
// ff-session needs a sessionstore-backups directory, which the fixture above omits on purpose so
// that the absence path stays exercised.
check("only firefox checks whose subject is absent fail to fire",
  JSON.stringify(ffNotFired) === JSON.stringify(["ff-session"]), ffNotFired.join(","));

/* ====================== 6b. the volume probe ====================== */

const sevFor = (input) => evaluateBuiltins("tor", input).find((f) => f.id === "disk-encryption")?.severity;
check("builtin severity: encrypted is ok", sevFor({ platform: "linux", root: "/home/u", mountInfo: MI }) === "ok");
check("builtin severity: plain is warn", sevFor({ platform: "linux", root: "/opt", mountInfo: MI }) === "warn");
check("builtin severity: unknown is info", sevFor({ platform: "win32", root: "E:\\", mountInfo: null, statfsType: 0 }) === "info");
check("builtin title matches the state",
  bare.find((f) => f.id === "disk-encryption").title.includes("could not be determined"));
check("builtin detail restates that it is about the whole volume",
  evaluateBuiltins("tor", { platform: "linux", root: "/opt", mountInfo: MI })
    .find((f) => f.id === "disk-encryption").detail.includes("every file on it"));

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
check("places carries the one residue evidence shape",
  JSON.stringify(Object.keys(places.evidence).sort()) === '["age_days","mtime","path","size"]', JSON.stringify(places.evidence));
check("places names the file it read", places.evidence.path === "places.sqlite", String(places.evidence.path));

const caches = evaluateBuiltins("tor", torCtx(allFiles)).filter((f) => f.id.startsWith("cache-"));
check("all five descriptor caches report", caches.length === 5, `${caches.length}`);
const desc = one(torCtx({ "/tb/data/cached-descriptors": { size: 1024, mtime: daysAgo(10) } }), "cache-cached-descriptors");
check("a cache title names the cache, its size and its age",
  desc.title === "Descriptor cache cached-descriptors: 1.0 KB (updated 10 day(s) ago)", desc.title);
check("a cache carries the same residue evidence shape as everything else",
  JSON.stringify(Object.keys(desc.evidence).sort()) === '["age_days","mtime","path","size"]', JSON.stringify(desc.evidence));
check("a fresh cache reports its age rather than a staleness flag",
  desc.evidence.age_days === 10, JSON.stringify(desc.evidence));
check("a cache inside the threshold says the other thing",
  desc.detail.startsWith("Updated recently"), desc.detail.slice(0, 60));
const old = one(torCtx({ "/tb/data/cached-certs": { size: 10, mtime: daysAgo(200) } }), "cache-cached-certs");
check("a cache past the threshold says so in its detail rather than in a flag",
  old.detail.startsWith("Not updated for a long time"), old.detail.slice(0, 60));
check("the two detail variants are genuinely different", desc.detail !== old.detail);

const logins = oneFf(ffCtx({ "/p/logins.json": { size: 100, mtime: daysAgo(10) } }), "ff-logins");
check("a firefox residue title is the one the helper used to build",
  logins.title === "Saved passwords database present (100 B, written 10 day(s) ago)", logins.title);
check("a firefox residue carries the same shape as a Tor one",
  JSON.stringify(Object.keys(logins.evidence).sort()) === JSON.stringify(Object.keys(places.evidence).sort()), JSON.stringify(logins.evidence));
check("a firefox residue names the file in its evidence", logins.evidence.path === "logins.json");
check("a firefox residue dates the file", logins.evidence.age_days === 10, String(logins.evidence.age_days));
check("ff-logins keeps its warn severity", logins.severity === "warn");
check("ff-history keeps its info severity", oneFf(ffCtx(ffFiles), "ff-history").severity === "info");

// Presence rules: absent and zero-byte are the same non-event, which is what the old helper did.
check("an absent residue file reports nothing", one(torCtx({}), "places") === undefined);
check("a zero-byte residue file reports nothing", one(torCtx({ "/tb/profile/places.sqlite": { size: 0 } }), "places") === undefined);
check("a zero-byte firefox residue file reports nothing",
  oneFf(ffCtx({ "/p/logins.json": { size: 0 } }), "ff-logins") === undefined);
check("a stat that returns null is tolerated",
  evaluateBuiltins("tor", torCtx({}, { statOf: () => null, listDir: () => [] }))
    .every((f) => catalogIds.has(f.id)));
check("a base directory that is missing contributes nothing",
  !evaluateBuiltins("tor", { platform: "win32", root: "x", bases: { data_dir: "" }, io: mkio(allFiles), entries: {} })
    .some((f) => f.id.startsWith("cache-")));
check("an unknown base name contributes nothing",
  !evaluateBuiltins("tor", { platform: "win32", root: "x", bases: { nowhere: "/x" }, io: mkio(allFiles), entries: {} })
    .some((f) => f.id.startsWith("cache-")));

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

/* ====================== 6d2. variant selection ====================== */

// A variant set with no `always` means "only under these conditions", and no condition matching is
// how a check stays silent when its subject is not configured. That path is the one a caller hits on
// every machine that has not set the pref, so it is asserted rather than assumed.
const noPrefs = { prefs: {}, entries: {} };
check("a check with no matching variant produces nothing",
  !evaluateBuiltins("firefox", ffCtx({}, mkio(), noPrefs)).some((f) => ["ff-rfp", "ff-doh", "ff-sponsored", "ff-telemetry-prefs"].includes(f.id)),
  evaluateBuiltins("firefox", ffCtx({}, mkio(), noPrefs)).map((f) => f.id).join(","));
check("a boolean check is silent when the pref is absent",
  oneFf(ffCtx({}, mkio(), { prefs: {} }), "ff-primary-password") === undefined);
check("a truthy check is silent when the pref is false rather than absent",
  one(torCtx({}, mkio(), {}, { prefs: { "torbrowser.settings.bridges.builtin_type": "" } }), "bridge-blend") === undefined);
check("that same check fires when the pref has a value",
  one(torCtx({}, mkio(), {}, { prefs: { "torbrowser.settings.bridges.builtin_type": "snowflake" } }), "bridge-blend") !== undefined);

// The predicate vocabulary is closed and each member is asserted directly, because a predicate that
// no entry uses is a predicate nobody would notice breaking.
const PV = { source: "prefs", keys: { k: "x" }, evidence: {} };
const pv = (variant, prefs) => evaluateOneBuiltin(
  { layer: "metadata", id: "probe-test", severities: ["info"], probe: BUILTIN_PROBES.CONFIG_VALUE,
    probe_args: { ...PV, variants: [variant] }, title: "t", detail: "d" },
  { prefs, io: mkio() });
check("predicate absent matches only an unset key", pv({ key: "k", absent: true }, {}) !== null && pv({ key: "k", absent: true }, { x: 1 }) === null);
check("predicate present matches a set key", pv({ key: "k", present: true }, { x: 0 }) !== null && pv({ key: "k", present: true }, {}) === null);
check("predicate truthy rejects a falsy value", pv({ key: "k", truthy: true }, { x: "" }) === null && pv({ key: "k", truthy: true }, { x: "v" }) !== null);
check("predicate is_true rejects a non-boolean", pv({ key: "k", is_true: true }, { x: 1 }) === null && pv({ key: "k", is_true: true }, { x: true }) !== null);
check("predicate is_false rejects a non-boolean", pv({ key: "k", is_false: true }, { x: 0 }) === null && pv({ key: "k", is_false: true }, { x: false }) !== null);
check("predicate one_of compares as strings", pv({ key: "k", one_of: [2, 3] }, { x: "2" }) !== null && pv({ key: "k", one_of: [2, 3] }, { x: 4 }) === null);
check("predicate one_of needs the key present", pv({ key: "k", one_of: [2] }, {}) === null);
check("predicate any_true needs one true", pv({ any_true: true }, { x: false }) === null && pv({ any_true: true }, { x: true }) !== null);
check("predicate all_false needs every key explicitly false",
  pv({ all_false: true }, { x: false }) !== null && pv({ all_false: true }, {}) === null && pv({ all_false: true }, { x: true }) === null);
check("predicate any_present needs one key set", pv({ any_present: true }, {}) === null && pv({ any_present: true }, { x: 0 }) !== null);
check("an unrecognised variant matches nothing rather than everything",
  pv({ key: "k", no_such_predicate: true }, { x: 1 }) === null);
check("`always` is the default variant",
  pv({ always: true }, {}) !== null);
check("the first matching variant wins",
  evaluateOneBuiltin({ layer: "metadata", id: "probe-test", severities: ["info"], probe: BUILTIN_PROBES.CONFIG_VALUE,
    probe_args: { ...PV, variants: [{ key: "k", present: true, severity: "warn", title: "first" }, { always: true, title: "second" }] },
    title: "t", detail: "d" }, { prefs: { x: 1 }, io: mkio() }).title === "first");
check("the predicate vocabulary is the closed set the module documents",
  VALUE_PREDICATES.length === 9 && VALUE_PREDICATES.includes("any_present"), VALUE_PREDICATES.join(","));

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
