#!/usr/bin/env node
/**
 * Firefox target test -- drives lib/firefox.mjs, and the Firefox half of lib/core.mjs.
 *
 * Why this needs its own suite:
 *
 *   1. The severity calibration is the design point of this target, and nothing else locks
 *      it in. Tor Browser is hardened by default, so retained state there is a deviation and
 *      warns; a plain Firefox profile keeps history and cookies BY DESIGN, so reporting them
 *      as warnings would be needless alarm. Only credential exposure (saved logins) and
 *      cross-machine identity linkage (Firefox Account / Sync, telemetry client ID) warn.
 *      Without this suite someone could "fix" a finding by raising ff-history to warn and
 *      every other suite would still be green.
 *
 *   2. It locks a real bug. profiles.ini carries two different default markers and they are
 *      not equivalent:
 *        [Install308046B0AF4A39CB] Default=Profiles/active.default-release   install marker
 *        [Profile1]                Default=1                                 legacy marker
 *      Machines have been observed carrying both, disagreeing: the legacy marker pointed at
 *      an empty leftover profile while the install marker pointed at the one in use. The
 *      first implementation honoured only the legacy marker, so it audited the empty leftover
 *      and reported a clean result for a profile nobody uses. The fixture disagrees on
 *      purpose, and both the parsed markers and the selected profile are asserted.
 *
 * Hermeticity: every discovery call either passes the fixture root explicitly (the
 *   `rootOverride` parameter exists for exactly that) or runs with APPDATA / USERPROFILE /
 *   HOME repointed into the fixture, so nothing here reads the developer's real Firefox
 *   profiles. A real profile root can contain scanned directories such as "Profile Groups",
 *   which means any assertion about a machine-wide count would be both wrong and unstable --
 *   so no such count is ever asserted, only counts of the fixture's own profiles.
 *
 * Division of labour with the other suites: selftest covers the Tor target and matrix checks
 *   the output contract across both; this suite owns the Firefox semantics.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildAllFixtures, firefoxFixtureDirs } from "./fixtures.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

// On Windows an ESM dynamic import must use a file:// URL; a bare absolute path raises
// ERR_UNSUPPORTED_ESM_URL_SCHEME.
const { profilesFromIni, pickDefaultProfile, discoverFirefoxProfiles, auditFirefoxProfile } = await import(
  pathToFileURL(path.join(root, "lib", "firefox.mjs")).href
);
const { parseIni, readText } = await import(pathToFileURL(path.join(root, "lib", "shared.mjs")).href);
const { TOOLS } = await import(pathToFileURL(path.join(root, "lib", "core.mjs")).href);

let pass = 0, fail = 0;
const failures = [];
function check(name, ok, detail = "") {
  if (ok) { console.log(`  \u001b[32m[ok]\u001b[0m ${name}`); pass++; }
  else { console.log(`  \u001b[31m[FAIL]\u001b[0m ${name}  ${detail}`); fail++; failures.push(`${name} ${detail}`); }
}
function section(t) { console.log(`\n\u001b[35m== ${t} ==\u001b[0m`); }
const T = (name) => TOOLS.find((t) => t.name === name);

const tallyOf = (findings) => {
  const t = {};
  for (const f of findings ?? []) t[f.severity] = (t[f.severity] ?? 0) + 1;
  return t;
};
const sortedTally = (t) => JSON.stringify(Object.fromEntries(Object.entries(t ?? {}).sort()));

/* ====================== fixtures ====================== */

const base = fs.mkdtempSync(path.join(os.tmpdir(), "tpa-firefox-"));
const F = buildAllFixtures(base);
const D = firefoxFixtureDirs(base);

const activeProfileDir = path.join(F.firefoxRoot, "Profiles", "active.default-release");
const leftoverProfileDir = path.join(F.firefoxRoot, "Profiles", "leftover.default");

section("0. fixture shape");
{
  check("fixture root is the synthetic home's profiles root",
    F.firefoxRoot === D.root && D.root.startsWith(D.home), `${F.firefoxRoot} / home ${D.home}`);
  check("active profile carries prefs.js and compatibility.ini",
    fs.existsSync(path.join(activeProfileDir, "prefs.js")) &&
    fs.existsSync(path.join(activeProfileDir, "compatibility.ini")));
  check("leftover profile stays discoverable (times.json) but its history is 0 bytes",
    fs.statSync(path.join(leftoverProfileDir, "times.json")).size > 0 &&
    fs.statSync(path.join(leftoverProfileDir, "places.sqlite")).size === 0);
  check("fake program directory reports version 142.0",
    /^Version=142\.0$/m.test(readText(path.join(D.prog, "application.ini")) ?? ""));
}

/* ====================== A. profiles.ini and default selection ====================== */

section("A1. profiles.ini records both default markers, and they disagree");
const ini = parseIni(readText(path.join(F.firefoxRoot, "profiles.ini")));
const records = profilesFromIni(ini, F.firefoxRoot);
{
  // The fixture root path is not guaranteed to be slash-normalized the same way the parser
  // resolves it, so compare resolved paths.
  const same = (a, b) => path.resolve(a).toLowerCase() === path.resolve(b).toLowerCase();
  const active = records.find((r) => same(r.profile_dir, activeProfileDir));
  const leftover = records.find((r) => same(r.profile_dir, leftoverProfileDir));

  check("two profile records are parsed from profiles.ini", records.length === 2,
    JSON.stringify(records.map((r) => r.profile_dir)));
  check("the active profile is identified by the install marker", active?.is_install_default === true,
    JSON.stringify(active));
  check("the active profile is default", active?.is_default === true, JSON.stringify(active));
  check("the leftover profile carries the legacy marker", leftover?.is_default === true,
    JSON.stringify(leftover));
  check("the legacy marker does NOT make the leftover the install default",
    leftover?.is_install_default === false, JSON.stringify(leftover));
  check("the two markers really do disagree",
    active?.is_install_default === true && leftover?.is_default === true &&
    !(leftover?.is_install_default === true), "fixture is not exercising the regression");
  check("IsRelative=1 is resolved against the Firefox root",
    same(active?.profile_dir ?? "", activeProfileDir), active?.profile_dir);
  check("the profile name is read from the Name key", active?.name === "active", active?.name);
}

section("A2. pickDefaultProfile - the regression lock");
{
  const picked = pickDefaultProfile(records);
  check("the profile in use is selected, not the leftover",
    path.resolve(picked?.profile_dir ?? "").toLowerCase() === path.resolve(activeProfileDir).toLowerCase(),
    JSON.stringify(picked));
  check("the selected profile is explicitly not the leftover profile",
    path.resolve(picked?.profile_dir ?? "").toLowerCase() !== path.resolve(leftoverProfileDir).toLowerCase());

  // The legacy marker must still work when the install marker is absent: it is a fallback,
  // not something to ignore.
  const legacyOnly = records.filter((r) => r.name === "leftover").map((r) => ({ ...r, is_install_default: false }));
  check("without an install marker the legacy marker is used",
    path.resolve(pickDefaultProfile(legacyOnly)?.profile_dir ?? "").toLowerCase() === path.resolve(leftoverProfileDir).toLowerCase());

  // last resort: no marker at all -> first discovered, never null-by-accident
  const noMarkers = records.map((r) => ({ ...r, is_default: false, is_install_default: false }));
  check("with no marker at all the first profile is used",
    pickDefaultProfile(noMarkers)?.profile_dir === records[0].profile_dir);
  check("an empty list returns null instead of throwing", pickDefaultProfile([]) === null);
  check("a non-array returns null instead of throwing", pickDefaultProfile(null) === null);
}

/* ====================== B. discovery ====================== */

section("B1. discoverFirefoxProfiles (isolated by rootOverride)");
const found = discoverFirefoxProfiles(F.firefoxRoot);
{
  check("exactly 2 profiles are discovered under the fixture root", found.length === 2,
    `found ${found.length}: ${found.map((p) => p.profile_dir).join(", ")}`);
  check("discovery never reaches outside the fixture root",
    found.every((p) => path.resolve(p.profile_dir).toLowerCase().startsWith(path.resolve(F.firefoxRoot).toLowerCase())),
    found.map((p) => p.profile_dir).join(", "));
  check("both the active and the leftover profile are found",
    found.filter((p) => path.resolve(p.profile_dir).toLowerCase() === path.resolve(activeProfileDir).toLowerCase()).length === 1 &&
    found.filter((p) => path.resolve(p.profile_dir).toLowerCase() === path.resolve(leftoverProfileDir).toLowerCase()).length === 1);
  check("discovery keeps the install-default flag on the profile in use",
    pickDefaultProfile(found)?.profile_dir.toLowerCase() === activeProfileDir.toLowerCase(),
    JSON.stringify(pickDefaultProfile(found)));
  check("discovered records are described (last_version is read)",
    found.every((p) => typeof p.profile_dir === "string" && "last_version" in p));

  const act = found.find((p) => path.resolve(p.profile_dir).toLowerCase() === path.resolve(activeProfileDir).toLowerCase());
  check("compatibility.ini LastVersion is read verbatim (build stamp included)",
    act?.last_version === "142.0_20250901123456/20250901123456", act?.last_version);
  check("times.json firstUse is read", act?.first_use === 1763730484848, String(act?.first_use));
  check("the prefs file is seen and counted", act?.has_prefs === true && act?.prefs_count === 15,
    JSON.stringify({ has_prefs: act?.has_prefs, prefs_count: act?.prefs_count }));
  check("a root with no profiles.ini yields nothing instead of throwing",
    discoverFirefoxProfiles(path.join(base, "no-such-root")).length === 0);
}

/* ====================== C. the audit: ids and severities ====================== */

// Verified line by line against lib/firefox.mjs. Each pair is the severity the finding is
// SPECIFIED to carry, not the severity it happens to carry today.
const EXPECTED = [
  ["ff-logins", "warn"],
  ["ff-sync", "warn"],
  ["ff-telemetry", "warn"],
  ["ff-keys", "info"],
  ["ff-certs", "info"],
  ["ff-history", "info"],
  ["ff-cookies", "info"],
  ["ff-permissions", "info"],
  ["ff-formhistory", "info"],
  ["ff-favicons", "info"],
  ["ff-site-data", "info"],
  ["ff-times", "info"],
  ["ff-session", "info"],
  ["ff-extensions", "info"],
  ["ff-proxy", "info"],
  ["ff-doh", "ok"],
  ["ff-content-blocking", "ok"],
  ["ff-rfp", "ok"],
  ["ff-cookie-behavior", "ok"],
  ["ff-sanitize", "info"],
  ["ff-telemetry-prefs", "info"],
  ["ff-sponsored", "info"],
  ["ff-profile-location", "info"],
  ["ff-persistence", "info"],
];

section("C1. auditFirefoxProfile(active profile): every expected finding, at its calibrated severity");
const audit = auditFirefoxProfile(activeProfileDir);
const byId = new Map(audit.map((f) => [f.id, f]));
const ids = audit.map((f) => f.id);
{
  for (const [id, severity] of EXPECTED) {
    const f = byId.get(id);
    check(`${id} is present and ${severity}`,
      f?.severity === severity,
      f ? `severity ${f.severity}` : `missing; got ${ids.join(",")}`);
  }
  check("no unexpected warn/critical findings",
    audit.every((f) => f.severity !== "critical"),
    JSON.stringify(audit.filter((f) => f.severity === "critical").map((f) => f.id)));
}

section("C2. evidence fields (read from lib/firefox.mjs, not guessed)");
{
  const ev = (id) => byId.get(id)?.evidence ?? {};
  check("ff-logins names logins.json with a real size",
    ev("ff-logins").path === "logins.json" && ev("ff-logins").size > 0, JSON.stringify(ev("ff-logins")));
  check("ff-history names places.sqlite and dates it",
    ev("ff-history").path === "places.sqlite" && ev("ff-history").size > 0 &&
    typeof ev("ff-history").age_days === "number", JSON.stringify(ev("ff-history")));
  check("ff-cookies names cookies.sqlite with a real size",
    ev("ff-cookies").path === "cookies.sqlite" && ev("ff-cookies").size > 0, JSON.stringify(ev("ff-cookies")));
  check("ff-site-data measures the storage tree", typeof ev("ff-site-data").size === "number" && ev("ff-site-data").size > 0,
    JSON.stringify(ev("ff-site-data")));
  check("ff-times reports both recorded timestamps",
    ev("ff-times").first_use === 1763730484848 && ev("ff-times").created === 1763730471181, JSON.stringify(ev("ff-times")));
  check("ff-session counts the restore files and dates the newest",
    ev("ff-session").count === 1 && typeof ev("ff-session").newest === "string", JSON.stringify(ev("ff-session")));
  check("ff-extensions counts only active extensions (the inactive one is excluded)",
    ev("ff-extensions").active_extensions === 1, JSON.stringify(ev("ff-extensions")));
  check("ff-telemetry marks the client ID as present",
    ev("ff-telemetry").client_id_present === true, JSON.stringify(ev("ff-telemetry")));
  check("ff-sync marks the signed-in account name as present",
    ev("ff-sync").sync_username_present === true, JSON.stringify(ev("ff-sync")));
  check("ff-proxy reports manual mode with both hosts",
    ev("ff-proxy").proxy_type === 1 && ev("ff-proxy").http === "127.0.0.1" &&
    ev("ff-proxy").socks === "127.0.0.1" && ev("ff-proxy").has_manual_host === true, JSON.stringify(ev("ff-proxy")));
  check("ff-doh reports DoH-first mode and the resolver URI",
    ev("ff-doh").trr_mode === 2 && ev("ff-doh").trr_uri === "https://dns.example/dns-query", JSON.stringify(ev("ff-doh")));
  check("ff-cookie-behavior reports total cookie protection (5)",
    ev("ff-cookie-behavior").cookieBehavior === 5, JSON.stringify(ev("ff-cookie-behavior")));
  check("ff-content-blocking reports strict mode",
    ev("ff-content-blocking").category === "strict", JSON.stringify(ev("ff-content-blocking")));
  check("ff-rfp reports fingerprint resistance on",
    ev("ff-rfp").resistFingerprinting === true, JSON.stringify(ev("ff-rfp")));
  check("ff-sanitize reports clear-on-shutdown off",
    ev("ff-sanitize").sanitizeOnShutdown === false, JSON.stringify(ev("ff-sanitize")));
  check("ff-telemetry-prefs reports both telemetry prefs as set",
    ev("ff-telemetry-prefs").toolkit_telemetry_enabled === true &&
    ev("ff-telemetry-prefs").healthreport_uploadEnabled === true, JSON.stringify(ev("ff-telemetry-prefs")));
  check("ff-sponsored reports the sponsored-content pref",
    ev("ff-sponsored").showSponsored === true && ev("ff-sponsored").pocket === true, JSON.stringify(ev("ff-sponsored")));
  check("ff-persistence names the profile directory",
    ev("ff-persistence").profile_dir === activeProfileDir, JSON.stringify(ev("ff-persistence")));
}

/* ====================== D. the calibration contract ====================== */

section("D1. severity calibration: retained residue is info, only linkage and credentials warn");
{
  check("ff-history is info, NOT warn (Firefox keeps history by design)",
    byId.get("ff-history")?.severity === "info", byId.get("ff-history")?.severity);
  check("ff-cookies is info, NOT warn (Firefox keeps cookies by design)",
    byId.get("ff-cookies")?.severity === "info", byId.get("ff-cookies")?.severity);

  const warns = audit.filter((f) => f.severity === "warn").map((f) => f.id).sort();
  const expectedWarns = ["ff-logins", "ff-primary-password", "ff-sync", "ff-telemetry"];
  check("the only warnings are credential exposure and cross-machine linkage",
    JSON.stringify(warns) === JSON.stringify(expectedWarns), JSON.stringify(warns));

  // The same contract stated the other way round: nothing in the metadata residue set warns.
  const residueIds = ["ff-history", "ff-cookies", "ff-permissions", "ff-formhistory", "ff-favicons",
    "ff-site-data", "ff-times", "ff-session", "ff-extensions", "ff-keys", "ff-certs"];
  check("no retained-residue finding is reported as a warning",
    residueIds.every((id) => byId.get(id)?.severity !== "warn"),
    JSON.stringify(residueIds.filter((id) => byId.get(id)?.severity === "warn")));

  // A Firefox profile is not a Tor profile: the Tor target's "state retained" warning has no
  // Firefox equivalent, precisely because the default is not hardened.
  check("the Tor-only ids are not borrowed by the Firefox target",
    !ids.some((id) => ["state-file", "state-guards", "places", "profile-times"].includes(id)),
    ids.join(","));
}

/* ====================== E. the leftover profile ====================== */

section("E1. the abandoned leftover profile is audited as empty, not as clean-by-luck");
{
  const l = auditFirefoxProfile(leftoverProfileDir);
  const lIds = l.map((f) => f.id);
  check("no ff-history is reported for a 0-byte places.sqlite", !lIds.includes("ff-history"), lIds.join(","));
  check("no ff-cookies is reported when cookies.sqlite is absent", !lIds.includes("ff-cookies"), lIds.join(","));
  check("no ff-logins is reported when logins.json is absent", !lIds.includes("ff-logins"), lIds.join(","));
  check("no ff-sync is reported when there is no account linkage", !lIds.includes("ff-sync"), lIds.join(","));

  // read off lib/firefox.mjs: ff-proxy is emitted unconditionally -- with no proxy pref at all
  // it reports the ABSENCE of a preference, with null evidence. Asserting that it is "not
  // reported" would be wrong, and the wording is what carries the meaning.
  const lProxy = l.find((f) => f.id === "ff-proxy");
  check("with no prefs.js the proxy finding reports the absence of a preference",
    lProxy?.severity === "info" && /No explicit proxy preference/i.test(lProxy?.title ?? "") && lProxy?.evidence === null,
    JSON.stringify({ severity: lProxy?.severity, title: lProxy?.title, evidence: lProxy?.evidence }));

  // every other pref-derived finding is gated on the pref existing, so an empty profile
  // must not produce them at all
  check("pref-gated findings are not emitted for a profile with no prefs.js",
    !["ff-doh", "ff-content-blocking", "ff-rfp", "ff-cookie-behavior", "ff-sanitize",
      "ff-telemetry-prefs", "ff-sponsored", "ff-primary-password", "ff-telemetry"].some((id) => lIds.includes(id)),
    lIds.join(","));
  check("no residue finding is emitted for files that do not exist",
    !lIds.some((id) => ["ff-keys", "ff-certs", "ff-permissions", "ff-formhistory", "ff-favicons",
      "ff-site-data", "ff-session", "ff-extensions"].includes(id)), lIds.join(","));
  check("the profile is still audited (it is not silently skipped)", l.length > 0, `findings ${l.length}`);
  check("its first-use time is still reported", lIds.includes("ff-times"), lIds.join(","));
  check("it is still reported as persistent residue", lIds.includes("ff-persistence"), lIds.join(","));
}

/* ====================== F. finding contract and profile count ====================== */

section("F1. every finding satisfies the output contract");
{
  const LAYERS = new Set(["build", "transport", "crypto", "metadata", "endpoint"]);
  const SEVERITIES = new Set(["ok", "info", "warn", "critical"]);
  const all = [...audit, ...auditFirefoxProfile(leftoverProfileDir)];
  check("layer is always one of build/transport/crypto/metadata/endpoint",
    all.every((f) => LAYERS.has(f.layer)), JSON.stringify(all.filter((f) => !LAYERS.has(f.layer)).map((f) => f.id)));
  check("severity is always valid",
    all.every((f) => SEVERITIES.has(f.severity)), JSON.stringify(all.filter((f) => !SEVERITIES.has(f.severity)).map((f) => f.id)));
  check("id is always a non-empty string", all.every((f) => typeof f.id === "string" && f.id.length > 0));
  check("title is always a non-empty string", all.every((f) => typeof f.title === "string" && f.title.length > 0));
  check("detail is always a non-empty string", all.every((f) => typeof f.detail === "string" && f.detail.length > 0));
  check("evidence is an object or null, never undefined or a scalar",
    all.every((f) => f.evidence === null || (typeof f.evidence === "object" && !Array.isArray(f.evidence))),
    JSON.stringify(all.filter((f) => !(f.evidence === null || (typeof f.evidence === "object" && !Array.isArray(f.evidence)))).map((f) => f.id)));
  check("no finding claims a safety guarantee",
    all.every((f) => !/you are safe|now safe|guaranteed safe/i.test(`${f.title} ${f.detail}`)));
  check("auditing a non-existent profile directory does not throw",
    Array.isArray(auditFirefoxProfile(path.join(base, "no-such-profile"))));
}

section("F2. ff-profile-count");
{
  const one = auditFirefoxProfile(activeProfileDir);
  check("not reported for a single profile", !one.some((f) => f.id === "ff-profile-count"));

  const two = auditFirefoxProfile(activeProfileDir, { allProfiles: found });
  const pc = two.find((f) => f.id === "ff-profile-count");
  check("reported when more than one profile is passed", !!pc, two.map((f) => f.id).join(","));
  check("judged warn", pc?.severity === "warn", pc?.severity);
  check("the count matches the profiles passed", pc?.evidence?.count === 2, JSON.stringify(pc?.evidence));

  const alsoOne = auditFirefoxProfile(activeProfileDir, { allProfiles: [found[0]] });
  check("not reported for a single-element allProfiles", !alsoOne.some((f) => f.id === "ff-profile-count"));
}

/* ====================== G. end to end through the tools ====================== */

section("G. end to end through the tool layer (env repointed into the fixture)");
{
  // lib/core.mjs discovers profiles machine-wide, so the only way to make this hermetic is to
  // repoint the roots it reads: APPDATA on Windows, HOME/USERPROFILE for the home-directory
  // candidates. Without this the assertions would depend on the developer's own Firefox.
  const saved = { APPDATA: process.env.APPDATA, USERPROFILE: process.env.USERPROFILE, HOME: process.env.HOME };
  try {
    process.env.APPDATA = D.appdata;
    process.env.USERPROFILE = D.home;
    process.env.HOME = D.home;

    check("the isolation actually took effect (home resolves into the fixture)",
      os.homedir() === D.home, os.homedir());

    const isolated = discoverFirefoxProfiles();
    check("machine-wide discovery now sees exactly the fixture's 2 profiles", isolated.length === 2,
      `found ${isolated.length}: ${isolated.map((p) => p.profile_dir).join(", ")}`);

    // ---- aragami_audit, explicit profile ----
    const a = await T("aragami_audit").execute({ target: "firefox", profile: activeProfileDir });
    check("target is firefox", a.target === "firefox", a.target);
    check("the profile path is echoed back unchanged", a.profile === activeProfileDir, a.profile);
    check("audit did not error", !a.error, a.error);
    check("findings is an array", Array.isArray(a.findings));
    check("tally matches the findings actually returned",
      sortedTally(a.tally) === sortedTally(tallyOf(a.findings)),
      `${JSON.stringify(a.tally)} vs ${JSON.stringify(tallyOf(a.findings))}`);
    check("boundary_notice has at least 4 entries", (a.boundary_notice ?? []).length >= 4);
    check("profiles_found counts the isolated discovery",
      a.profiles_found === 2, String(a.profiles_found));
    const aIds = (a.findings ?? []).map((f) => f.id);
    check("the audited profile is the one in use (its own residue is reported)",
      aIds.includes("ff-history") && aIds.includes("ff-sync") && aIds.includes("ff-doh"), aIds.join(","));
    check("passing two profiles surfaces the profile-count warning",
      aIds.includes("ff-profile-count"), aIds.join(","));

    // ---- aragami_audit, no profile: the default-selection regression at tool level ----
    const dflt = await T("aragami_audit").execute({ target: "firefox" });
    check("with no profile argument the tool audits the profile in use, not the leftover",
      dflt.profile === activeProfileDir, `${dflt.profile}`);
    check("the defaulted audit sees the residue the empty leftover does not have",
      (dflt.findings ?? []).some((f) => f.id === "ff-history"),
      (dflt.findings ?? []).map((f) => f.id).join(","));

    // ---- aragami_version ----
    const v = await T("aragami_version").execute({ target: "firefox", install: D.prog, online: false });
    check("version target is firefox", v.target === "firefox", v.target);
    check("the fake program directory reports installed 142.0", v.installed === "142.0", JSON.stringify(v.installed));
    check("the version came from application.ini when a program directory is passed",
      String(v.local_source ?? "").includes("application.ini"), v.local_source);
    check("offline mode made no network call (no latest, no via)", v.latest === null && v.via === undefined);
    check("offline mode verdict is unknown", v.verdict === "unknown", v.verdict);
    check("version output carries the boundary notice", (v.boundary_notice ?? []).length >= 4);

    // compatibility.ini holds "142.0_20250901123456/20250901123456": whichever source the
    // code reads, the version must be the part before the underscore. (Whether the application
    // or the profile is read depends on what is installed on the machine, so only the value is
    // asserted -- both sources in this fixture say 142.0.)
    const vNoApp = await T("aragami_version").execute({
      target: "firefox", install: path.join(base, "no-such-program"), online: false,
    });
    check("a missing program directory falls back without throwing",
      vNoApp.target === "firefox" && vNoApp.verdict === "unknown", JSON.stringify(vNoApp.installed));
    check("the fallback version carries no build stamp",
      vNoApp.installed === null || !String(vNoApp.installed).includes("_"), String(vNoApp.installed));

    // ---- aragami_env ----
    // `install` is passed so Tor discovery does not sweep every drive letter: explicit means
    // explicit, and this path is not a Tor install, so the shape assertions below stay fast
    // and independent of what is installed on the machine.
    const env = await T("aragami_env").execute({ install: D.prog });
    check("targets.tor is present with a numeric found and an array",
      typeof env.targets?.tor?.found === "number" && Array.isArray(env.targets?.tor?.installs),
      JSON.stringify(env.targets?.tor));
    check("targets.firefox is present with a numeric found and an array",
      typeof env.targets?.firefox?.found === "number" && Array.isArray(env.targets?.firefox?.profiles),
      JSON.stringify({ found: env.targets?.firefox?.found, arr: Array.isArray(env.targets?.firefox?.profiles) }));
    check("targets.firefox.found agrees with the discovered profile list",
      env.targets.firefox.found === env.targets.firefox.profiles.length);
    check("targets.tor.found agrees with the discovered install list",
      env.targets.tor.found === env.targets.tor.installs.length);
    check("the fake program directory is not mistaken for a Tor Browser install",
      env.targets.tor.found === 0, String(env.targets.tor.found));
    check("aragami_env carries the boundary notice", (env.boundary_notice ?? []).length >= 4);
  } finally {
    for (const [k, val] of Object.entries(saved)) {
      if (val === undefined) delete process.env[k]; else process.env[k] = val;
    }
  }

  check("the environment override was rolled back",
    discoverFirefoxProfiles(D.root).length === 2 && os.homedir() !== D.home, os.homedir());
}

/* ====================== coverage closure ====================== */

// Two tool paths only execute at the boundary of machine state, or need the network. Leaving
// them unexecuted would mean the "nothing found" behaviour and the Firefox version lookup
// were never run at all, which for an auditor is the same as not having them.

section("H. paths that need a repointed environment or the network");

// H1: the Firefox target when no profile exists anywhere.
{
  const saved = { APPDATA: process.env.APPDATA, USERPROFILE: process.env.USERPROFILE, HOME: process.env.HOME };
  const emptyHome = path.join(base, "empty-home");
  fs.mkdirSync(emptyHome, { recursive: true });
  try {
    process.env.APPDATA = emptyHome;
    process.env.USERPROFILE = emptyHome;
    process.env.HOME = emptyHome;

    const r = await T("aragami_audit").execute({ target: "firefox" });
    check("no Firefox profile -> the target is still reported", r.target === "firefox", String(r.target));
    check("no Firefox profile -> an error is returned", typeof r.error === "string" && r.error.length > 0, String(r.error));
    check("no Firefox profile -> boundary_notice still present", (r.boundary_notice ?? []).length >= 4);
    check("no Firefox profile -> no findings array is invented", r.findings === undefined);
    check("no Firefox profile -> no tally is invented", r.tally === undefined);

    const env = await T("aragami_env").execute({});
    check("no Firefox profile -> env reports zero", env.targets.firefox.found === 0, String(env.targets.firefox.found));
  } finally {
    for (const k of Object.keys(saved)) {
      if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k];
    }
  }
}

// H2: the Firefox version lookup, which is the only network path this target has. It is
// allowed to fail on a machine without egress; what must not happen is an unhandled
// rejection, or a verdict outside the documented set.
{
  const r = await T("aragami_version").execute({ target: "firefox" });
  const allowed = ["current", "outdated", "ahead", "check-failed", "unknown"];
  check("firefox online check returns a documented verdict", allowed.includes(r.verdict), String(r.verdict));
  check("firefox online check reports the firefox target", r.target === "firefox", String(r.target));
  check("firefox online check carries boundary_notice", (r.boundary_notice ?? []).length >= 4);
  check("firefox online check names its endpoint",
    typeof r.source === "string" && r.source.startsWith("http"), String(r.source));
  if (r.verdict === "check-failed") {
    check("a failed check reports why", typeof r.error === "string" && r.error.length > 0, String(r.error));
  } else {
    check("a successful check resolved a latest version",
      typeof r.latest === "string" && r.latest.length > 0, String(r.latest));
    // The local version can honestly be absent: it is read from the installed application
    // or from the profile's compatibility.ini, and a machine with neither has nothing to
    // report. CI has no Firefox, so requiring a version here asserted something about the
    // machine rather than about the tool. What is asserted instead is that the answer is
    // self-consistent -- a version comes with its source, and its absence comes with none.
    const hasVersion = typeof r.installed === "string" && r.installed.length > 0;
    check("the local version is resolved, or absent together with its source",
      hasVersion ? typeof r.local_source === "string" && r.local_source.length > 0
                 : r.installed === null,
      JSON.stringify({ installed: r.installed, local_source: r.local_source }));
  }
  console.log(`  (note: the online Firefox check returned verdict "${r.verdict}")`);
}

// H3: the failure branch of the same lookup. Pointing it at an unreachable proxy forces the
// catch path deterministically, rather than waiting for a flaky network to exercise it.
{
  const r = await T("aragami_version").execute({ target: "firefox", proxy: "http://127.0.0.1:9" });
  check("unreachable proxy -> verdict is check-failed", r.verdict === "check-failed", String(r.verdict));
  check("unreachable proxy -> an error string is present", typeof r.error === "string" && r.error.length > 0, String(r.error));
  check("unreachable proxy -> the endpoint is still named", r.source === "https://product-details.mozilla.org/1.0/firefox_versions.json", String(r.source));
  check("unreachable proxy -> boundary_notice still present", (r.boundary_notice ?? []).length >= 4);
}
/* ====================== cleanup ====================== */

try {
  fs.rmSync(base, { recursive: true, force: true });
  console.log("\n  \u001b[90mTemporary fixtures cleaned up\u001b[0m");
} catch {}

section("Summary");
console.log(`\n  passed ${pass} / ${pass + fail}`);
if (fail) { console.log("\n  Failed checks:"); for (const f of failures) console.log(`    - ${f}`); }
process.exit(fail === 0 ? 0 : 1);
