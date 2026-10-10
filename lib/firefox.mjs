/**
 * Aragami - Firefox target
 *
 * The second audit target. A plain Firefox profile is a different object from a Tor
 * Browser install, and the calibration is deliberately different too:
 *
 *   Tor Browser is hardened by default, so retained state there is a deviation and is
 *   reported as a warning. Firefox is NOT hardened by default, so retained history and
 *   cookies are EXPECTED. Reporting them as warnings would be needless alarm, which the
 *   design discipline forbids.
 *
 *   What earns a warning in a Firefox profile is anything that links the profile to an
 *   identity beyond this machine, or that hands over credentials:
 *     - a signed-in account (profile <-> account linkage)
 *     - a telemetry client ID (a stable identifier that survives everywhere)
 *     - saved passwords
 *
 * Like the Tor target, this reads files only. It never starts Firefox and never opens a
 * network connection. SQLite databases are reported by presence, size and age -- parsing
 * rows would mean shipping a SQLite dependency and mutating the profile, and the class of
 * finding here is "this residue exists", not "here is what you visited".
 */

import path from "node:path";
import os from "node:os";
import {
  exists, statOf, readText, readJson, listDir, dirSize,
  fmtBytes, fmtTime, finding, parseIni, parsePrefs, probeInputsFor,
} from "./shared.mjs";
import { evaluateBuiltins } from "./checks.mjs";

/* ------------------------------------------------ profile discovery */

/** Candidate roots, in the order the platforms put them. */
function profileRoots() {
  const home = os.homedir();
  const out = [];
  if (process.env.APPDATA) out.push(path.join(process.env.APPDATA, "Mozilla", "Firefox"));
  out.push(path.join(home, "AppData", "Roaming", "Mozilla", "Firefox"));   // Windows
  out.push(path.join(home, ".mozilla", "firefox"));                        // Linux
  out.push(path.join(home, "Library", "Application Support", "Firefox"));  // macOS
  out.push(path.join(home, "snap", "firefox", "common", ".mozilla", "firefox")); // snap
  out.push(path.join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox")); // flatpak
  return [...new Set(out)];
}

function isProfileDir(p) {
  return exists(path.join(p, "prefs.js")) ||
         exists(path.join(p, "times.json")) ||
         exists(path.join(p, "places.sqlite"));
}

/**
 * Turn a parsed profiles.ini into profile records.
 *
 * Two different default markers exist and they are not equivalent:
 *
 *   [Profile1]                  Default=1                 <- legacy: "this is the default profile"
 *   [Install308046B0AF4A39CB]   Default=Profiles/xxx       <- authoritative: the profile the app opens
 *
 * A machine can carry both, and they can disagree -- observed in practice, where the legacy
 * marker pointed at an empty leftover profile while the install marker pointed at the one
 * actually in use. The install marker wins, because auditing the wrong profile is worse than
 * auditing none: it reports a clean result for a profile nobody uses.
 *
 * IsRelative=1 means the Path is relative to the Firefox root; IsRelative=0 is absolute.
 */
export function profilesFromIni(ini, root) {
  const key = (p) => {
    const r = path.resolve(p);
    return process.platform === "win32" ? r.toLowerCase() : r;
  };

  const installDefaults = new Set();
  for (const [section, body] of Object.entries(ini)) {
    if (!/^Install/i.test(section)) continue;
    if (body.Default) installDefaults.add(key(path.join(root, body.Default)));
  }

  const out = [];
  for (const [section, body] of Object.entries(ini)) {
    if (!/^Profile\d+$/i.test(section)) continue;
    const rel = String(body.IsRelative ?? "1") === "1";
    const raw = body.Path;
    if (!raw) continue;
    const dir = rel ? path.join(root, raw) : raw;
    const isInstallDefault = installDefaults.has(key(dir));
    out.push({
      name: body.Name ?? section,
      profile_dir: dir,
      is_install_default: isInstallDefault,
      is_default: isInstallDefault || String(body.Default) === "1",
      from: "profiles.ini",
    });
  }
  return out;
}

/**
 * Choose the profile an audit should default to: the one the application actually opens
 * first, then the legacy default marker, then whatever was discovered first.
 */
export function pickDefaultProfile(profiles) {
  if (!Array.isArray(profiles) || profiles.length === 0) return null;
  return profiles.find((p) => p.is_install_default)
      ?? profiles.find((p) => p.is_default)
      ?? profiles[0];
}

/**
 * Discover every Firefox profile this machine exposes.
 *
 * Prefers profiles.ini (authoritative). Falls back to scanning the Profiles/ directory,
 * which matters for portable installs and for profiles whose ini entry was removed
 * without deleting the directory -- exactly the forgotten residue this tool cares about.
 */
export function discoverFirefoxProfiles(rootOverride) {
  // `rootOverride` exists for testability: without it the discovery can only read the
  // machine's real profile root, and a suite that has to audit the developer's own Firefox
  // is neither hermetic nor safe to run anywhere. Same pattern as readWininetProxy(exec).
  const roots = (typeof rootOverride === "string" && rootOverride.trim())
    ? [rootOverride]
    : profileRoots();
  const found = new Map();
  const add = (rec) => {
    if (!rec?.profile_dir) return;
    if (!isProfileDir(rec.profile_dir)) return;
    const key = process.platform === "win32"
      ? path.resolve(rec.profile_dir).toLowerCase()
      : path.resolve(rec.profile_dir);
    if (!found.has(key)) found.set(key, rec);
  };

  for (const root of roots) {
    if (!exists(root)) continue;
    const ini = parseIni(readText(path.join(root, "profiles.ini")));
    for (const rec of profilesFromIni(ini, root)) add({ ...rec, root });

    const pdir = path.join(root, "Profiles");
    for (const e of listDir(pdir)) {
      if (!e.isDirectory()) continue;
      add({ name: e.name.replace(/\.[0-9a-f]+$/i, ""), profile_dir: path.join(pdir, e.name), is_default: false, from: "scan", root });
    }
    // some layouts keep profiles directly under the root
    for (const e of listDir(root)) {
      if (!e.isDirectory() || e.name === "Profiles" || e.name === "Crash Reports") continue;
      add({ name: e.name, profile_dir: path.join(root, e.name), is_default: false, from: "scan", root });
    }
  }

  return [...found.values()].map((r) => ({ ...r, ...describeFirefoxProfile(r.profile_dir) }));
}

/** Locate a Firefox program directory so the application version can be read. */
function firefoxInstallCandidates() {
  const home = os.homedir();
  const out = [];
  if (process.platform === "win32") {
    for (const d of "CDEFGHIJ") {
      out.push(`${d}:\\Program Files\\Mozilla Firefox`);
      out.push(`${d}:\\Program Files (x86)\\Mozilla Firefox`);
    }
  } else if (process.platform === "darwin") {
    out.push("/Applications/Firefox.app/Contents/Resources");
  } else {
    out.push("/usr/lib/firefox", "/usr/lib64/firefox", "/usr/share/firefox", "/opt/firefox");
  }
  out.push(path.join(home, "firefox"));
  return out;
}

/**
 * Locate the Firefox application and its version. `explicit` may point at a program
 * directory; otherwise the platform candidates are tried. Returns null when Firefox is
 * not installed on this machine -- which is different from "this profile is unused".
 */
export function findFirefoxApplication(explicit) {
  const dirs = [];
  if (typeof explicit === "string" && explicit.trim()) dirs.push(explicit);
  dirs.push(...firefoxInstallCandidates());
  for (const c of dirs) {
    const ini = readText(path.join(c, "application.ini"));
    if (!ini) continue;
    const v = (ini.match(/^Version=(.+)$/m) || [])[1]?.trim();
    if (v) return { version: v, dir: c };
  }
  return null;
}

/** Describe one profile with file-level facts only. */
export function describeFirefoxProfile(dir) {
  const compat = parseIni(readText(path.join(dir, "compatibility.ini")));
  const times = readJson(path.join(dir, "times.json"));
  const prefs = parsePrefs(readText(path.join(dir, "prefs.js")));

  return {
    profile_dir: dir,
    last_version: compat.Compatibility?.LastVersion ?? null,
    last_profile_dir: compat.Compatibility?.LastPlatformDir ?? null,
    first_use: times?.firstUse ?? times?.created ?? null,
    has_prefs: exists(path.join(dir, "prefs.js")),
    // a lightweight fact set the caller can filter on without re-reading files
    prefs_count: Object.keys(prefs).length,
  };
}

/* ------------------------------------------------ helpers */

const MB = 1024 * 1024;

// The residue files this profile leaves behind -- logins.json, key4.db, cert9.db, places.sqlite,
// cookies.sqlite, permissions.sqlite, formhistory.sqlite, favicons.sqlite -- used to be reported
// by a `residue()` helper called eight times from here. They are built-in checks now: their
// titles, why-text, severities and boundaries are catalog entries in lib/checks.mjs, and the
// path-residue probe reads exactly the same files with the same "present and non-empty" rule.
// Removing the helper rather than leaving it beside the catalog removes the possibility of two
// implementations drifting apart.

const asBool = (v) => v === true;
const asBoolOrNull = (v) => (typeof v === "boolean" ? v : null);

/* ------------------------------------------------ the audit */

/**
 * Audit one Firefox profile.
 * @param {string} profileDir
 * @param {object=} opts { allProfiles }
 * @returns {Array<object>} findings
 */
export function auditFirefoxProfile(profileDir, opts = {}) {
  const out = [];
  const prefs = parsePrefs(readText(path.join(profileDir, "prefs.js")));
  const get = (k) => prefs[k];

  /* ---- build layer ---- */

  const compat = parseIni(readText(path.join(profileDir, "compatibility.ini")));
  const lastVer = compat.Compatibility?.LastVersion ?? null;
  const app = findFirefoxApplication();
  const appVersion = app?.version ?? null;
  const appDir = app?.dir ?? null;
  out.push(finding("build", appVersion || lastVer ? "info" : "warn", "ff-version",
    appVersion ? `Firefox application version ${appVersion}` : (lastVer ? `Firefox not found; profile last used with ${lastVer}` : "Could not determine a Firefox version"),
    appVersion
      ? `Read from ${path.join(appDir, "application.ini")}.`
      : "No Firefox program directory was found. The profile still reports the version it was last used with, which is enough to spot a stale profile but not a stale install.",
    { application_version: appVersion, profile_last_version: lastVer, application_dir: appDir }));

  /* ---- transport layer ---- */

  // network.proxy.type: 0 = no proxy, 1 = manual, 2 = PAC, 4 = auto-detect, 5 = system
  const proxyType = get("network.proxy.type");
  const proxyLabels = { 0: "no proxy", 1: "manual", 2: "PAC", 4: "auto-detect", 5: "system proxy" };
  if (proxyType === undefined) {
    out.push(finding("transport", "info", "ff-proxy", "No explicit proxy preference in this profile",
      "Firefox is using its default. Nothing here says whether the system routes traffic through a proxy.", null));
  } else {
    const manual = String(get("network.proxy.http") ?? "") + String(get("network.proxy.socks") ?? "");
    // ff-proxy stays bespoke on purpose. Its evidence carries `has_manual_host`, which is DERIVED
    // from two other prefs rather than read, and expressing that in the catalog would need a way to
    // combine values -- at which point the table is a programming language with worse error
    // messages than the five lines it replaced. This is where the declarative boundary sits.
    out.push(finding("transport", "info", "ff-proxy",
      `Proxy mode: ${proxyLabels[proxyType] ?? `unknown (${proxyType})`}`,
      proxyType === 0
        ? "Direct connections. This is Firefox's default and says nothing about network-level routing."
        : "A proxy is configured in the profile. Note that a browser proxy does not cover other applications on the machine.",
      { proxy_type: proxyType, http: get("network.proxy.http") ?? null, socks: get("network.proxy.socks") ?? null,
        has_manual_host: manual.length > 0 }));
  }

  // network.trr.mode: 0 off, 1 race, 2 DoH first, 3 DoH only, 5 off by choice

  /* ---- content / authorization layer ---- */

  // ff-logins, ff-keys, ff-certs and ff-primary-password are built-in checks (catalog: lib/checks.mjs).

  /* ---- metadata layer ---- */

  // ff-history, ff-cookies, ff-permissions, ff-formhistory, ff-favicons, ff-site-data, ff-times
  // and ff-session are built-in checks.

  // Telemetry client ID -- a stable identifier, which is why this is a warning
  const drState = readJson(path.join(profileDir, "datareporting", "state.json"));
  const upload = get("datareporting.healthreport.uploadEnabled");
  if (drState || upload !== undefined) {
    const cid = drState?.clientID ?? drState?.clientId ?? null;
    out.push(finding("metadata", cid ? "warn" : "info", "ff-telemetry",
      cid ? "Telemetry client ID present" : "Telemetry state present",
      cid
        ? "A client ID is a stable pseudonymous identifier: it survives profile resets of history and cookies, and it is the kind of value that links this browser to an account elsewhere. If the profile is meant to be unattributable, this must be cleared."
        : "Firefox records telemetry state in the profile. Whether anything is uploaded depends on the prefs below.",
      { client_id_present: !!cid, upload_enabled: asBoolOrNull(upload) }));
  }

  // Firefox Account / Sync -- profile <-> account linkage
  const signedIn = readJson(path.join(profileDir, "signedInUser.json"));
  const syncUser = get("services.sync.username");
  const accountRoot = get("identity.fxaccounts.account.device.name") ?? get("services.sync.account");
  if (signedIn || syncUser || accountRoot) {
    out.push(finding("metadata", "warn", "ff-sync",
      "Firefox Sync / account linkage present",
      "This profile is tied to a Firefox Account. That is a direct, server-side link between the profile, an email address and every other device on the account -- so local hygiene cannot make the profile unattributable while the linkage exists.",
      { signed_in_user_file: !!signedIn, sync_username_present: !!syncUser, account_root_present: !!accountRoot }));
  }

  const ext = readJson(path.join(profileDir, "extensions.json"));
  if (ext) {
    const addons = (ext.addons ?? []).filter((a) => a.type === "extension" && a.active !== false);
    out.push(finding("metadata", "info", "ff-extensions",
      `${addons.length} active extension(s)`,
      "Extensions are code with access to this profile, and each one is an account or vendor relationship. They also make the profile distinguishable when combined.",
      { active_extensions: addons.length, ids: addons.map((a) => a.id).slice(0, 12) }));
  }

  /* ---- endpoint layer ---- */

  const drive = path.parse(profileDir).root.replace(/\\$/, "");
  const systemDrive = (process.env.SystemDrive ?? "C:").replace(/\\$/, "");
  out.push(finding("endpoint", "info", "ff-profile-location",
    `Profile lives on drive ${drive}`,
    drive.toUpperCase() === systemDrive.toUpperCase()
      ? "The profile sits on the system volume, so formatting or imaging the system handles it too. That is convenient for the owner and equally convenient for anyone else."
      : "The profile is on a separate volume from the system.",
    { drive, system_drive: systemDrive }));

  // ff-persistence is a built-in check.

  const all = opts.allProfiles;
  if (Array.isArray(all) && all.length > 1) {
    out.push(finding("endpoint", "warn", "ff-profile-count",
      `${all.length} Firefox profiles on this machine`,
      "Every profile is a separate identity and a separate residue set. Forgetting one is the usual way a cleanup looks complete and is not.",
      { count: all.length, dirs: all.map((p) => p.profile_dir) }));
  }

  /* ---- posture (preferences that reduce exposure) ---- */

  const cbCat = get("browser.contentblocking.category");
  const tp = get("privacy.trackingprotection.enabled");
  const cbKnown = cbCat !== undefined || tp !== undefined;
  if (cbKnown) {
    const strict = cbCat === "strict";
    const standard = cbCat === "standard";
    out.push(finding("transport", strict || asBool(tp) ? "ok" : "info", "ff-content-blocking",
      `Content blocking: ${cbCat ?? (asBool(tp) ? "custom tracking protection" : "default")}`,
      strict
        ? "Strict mode. This is the strongest built-in setting, at the cost of breaking some sites."
        : standard
          ? "Standard mode, Firefox's default. It blocks some trackers; it is not a privacy configuration on its own."
          : "Content blocking is at its default. Tracking protection reduces what follows you between sites, which matters directly for the linkage this audit reports elsewhere.",
      { category: cbCat ?? null, tracking_protection: asBoolOrNull(tp) }));
  }

  // ff-rfp and ff-cookie-behavior are built-in checks.

  const sanitizeOnShutdown = get("privacy.sanitize.sanitizeOnShutdown");
  if (sanitizeOnShutdown !== undefined) {
    const on = asBool(sanitizeOnShutdown);
    const clears = on
      ? Object.entries(prefs).filter(([k, v]) => k.startsWith("privacy.clearOnShutdown") && v === true).map(([k]) => k.replace("privacy.clearOnShutdown.", ""))
      : [];
    out.push(finding("endpoint", on ? "ok" : "info", "ff-sanitize",
      on ? `Clear-on-shutdown enabled (${clears.length ? clears.join(", ") : "no categories selected"})` : "Clear-on-shutdown disabled",
      on
        ? "Residue is removed when the browser closes. Everything this audit reports above will still be present while the browser is running, and a hard kill skips it."
        : "Nothing is cleared on shutdown. Firefox's default keeps history, cookies, caches and site data indefinitely.",
      { sanitizeOnShutdown: asBoolOrNull(sanitizeOnShutdown), clearing: clears }));
  }

  // ff-telemetry-prefs and ff-sponsored are built-in checks.

  // ---- built-in checks (catalog: lib/checks.mjs) ----
  //
  // The catalogued checks for this target run at the end of the profile audit rather than in the
  // tool layer, so that a caller using this function directly gets exactly the findings the CLI
  // returns. The residue-file checks are among them; the volume probe reads nothing in the profile.
  out.push(...evaluateBuiltins("firefox", probeInputsFor(profileDir, { profile_dir: profileDir }, { prefs })));

  return out;
}

