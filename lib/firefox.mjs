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
  fmtBytes, fmtTime, daysSince, finding, parseIni, parsePrefs,
} from "./shared.mjs";

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

/** Report a single residue file (presence, size, age). */
function residue(out, dir, rel, { layer = "metadata", severity = "info", id, title, why, missing = null }) {
  const p = path.join(dir, rel);
  const s = statOf(p);
  if (!s || s.size === 0) {
    if (missing) out.push(finding(layer, "ok", id, missing.title, missing.why, { path: rel }));
    return;
  }
  const age = daysSince(s.mtime);
  out.push(finding(layer, severity, id,
    `${title} (${fmtBytes(s.size)}, written ${age} day(s) ago)`,
    why,
    { path: rel, size: s.size, mtime: s.mtime.toISOString(), age_days: age }));
}

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
    out.push(finding("transport", "info", "ff-proxy",
      `Proxy mode: ${proxyLabels[proxyType] ?? `unknown (${proxyType})`}`,
      proxyType === 0
        ? "Direct connections. This is Firefox's default and says nothing about network-level routing."
        : "A proxy is configured in the profile. Note that a browser proxy does not cover other applications on the machine.",
      { proxy_type: proxyType, http: get("network.proxy.http") ?? null, socks: get("network.proxy.socks") ?? null,
        has_manual_host: manual.length > 0 }));
  }

  // network.trr.mode: 0 off, 1 race, 2 DoH first, 3 DoH only, 5 off by choice
  const trrMode = get("network.trr.mode");
  const trrLabels = { 0: "off", 1: "race against system DNS", 2: "DoH first", 3: "DoH only", 5: "off by explicit choice" };
  if (trrMode !== undefined) {
    const good = trrMode === 2 || trrMode === 3;
    out.push(finding("transport", good ? "ok" : "info", "ff-doh",
      `DNS over HTTPS: ${trrLabels[trrMode] ?? `unknown (${trrMode})`}`,
      good
        ? "DoH is active, which keeps DNS queries away from the local resolver. Note that the DoH provider itself sees every lookup, so the provider matters."
        : "DoH is not active; DNS goes to the system resolver. On an untrusted network that is a visible channel.",
      { trr_mode: trrMode, trr_uri: get("network.trr.uri") ?? null, trr_custom: get("network.trr.custom_uri") ?? null }));
  }

  /* ---- content / authorization layer ---- */

  residue(out, profileDir, "logins.json", {
    layer: "crypto", severity: "warn", id: "ff-logins",
    title: "Saved passwords database present",
    why: "logins.json holds the encrypted entry set for saved logins, with key4.db beside it. This is the highest-value file in a Firefox profile: whoever obtains the profile directory and the primary password (or cracks a weak one) obtains every saved credential. If this profile was ever used for anything that matters, treat those credentials as disclosed unless a strong primary password is set.",
  });

  const remember = get("signon.rememberSignons");
  if (remember !== undefined) {
    const on = asBool(remember);
    out.push(finding("crypto", on ? "warn" : "ok", "ff-primary-password",
      on ? "Password saving is enabled" : "Password saving is disabled",
      on
        ? "Firefox will offer to store credentials. This audit cannot tell whether a primary password is set -- prefs.js does not record it -- so confirm from the profile itself if it matters. Without one, the stored logins are only as safe as the machine."
        : "Firefox will not store new credentials. Anything already in logins.json is unaffected by this setting.",
      { signon_rememberSignons: asBoolOrNull(remember) }));
  }

  residue(out, profileDir, "key4.db", {
    layer: "crypto", severity: "info", id: "ff-keys",
    title: "Firefox key material present",
    why: "key4.db is the NSS key database that protects saved logins and client certificates.",
  });
  residue(out, profileDir, "cert9.db", {
    layer: "crypto", severity: "info", id: "ff-certs",
    title: "Client certificate store present",
    why: "cert9.db can hold client certificates used to authenticate to services. Their presence is itself an identifier of which services this profile talks to.",
  });

  /* ---- metadata layer ---- */

  residue(out, profileDir, "places.sqlite", {
    severity: "info", id: "ff-history",
    title: "Browsing history and bookmarks database present",
    why: "Firefox keeps history here by design, so its presence is expected rather than a misconfiguration. It still records what this profile has visited, and it is the first file examined if the machine is taken.",
  });
  residue(out, profileDir, "cookies.sqlite", {
    severity: "info", id: "ff-cookies",
    title: "Cookie database present",
    why: "Persistent session cookies. For a signed-in profile these can be replayed to impersonate the session without the password.",
  });
  residue(out, profileDir, "permissions.sqlite", {
    severity: "info", id: "ff-permissions",
    title: "Per-site permission grants present",
    why: "Records which sites were granted camera, microphone, geolocation, notifications and so on. The list reveals which services this profile actually uses.",
  });
  residue(out, profileDir, "formhistory.sqlite", {
    severity: "info", id: "ff-formhistory",
    title: "Form history present",
    why: "Previously typed form values, including anything entered into a field that was not marked as a password field.",
  });
  residue(out, profileDir, "favicons.sqlite", {
    severity: "info", id: "ff-favicons",
    title: "Favicon cache present",
    why: "Small, but it survives history clearing and is a recognisable list of visited sites.",
  });

  const storageSize = dirSize(path.join(profileDir, "storage", "default"));
  if (storageSize) {
    out.push(finding("metadata", "info", "ff-site-data",
      `Site storage present (${fmtBytes(storageSize)})`,
      "IndexedDB, service worker caches and similar per-origin storage. It is not cleared by clearing history, and it can identify the sites this profile has used.",
      { size: storageSize }));
  }

  const times = readJson(path.join(profileDir, "times.json"));
  if (times) {
    const first = times.firstUse ?? times.created;
    out.push(finding("metadata", "info", "ff-times",
      `Profile records a first-use time (${fmtTime(first)})`,
      "Not an exposure by itself, but it dates the profile and cannot be removed without resetting the profile.",
      { first_use: times.firstUse, created: times.created }));
  }

  const sessDir = path.join(profileDir, "sessionstore-backups");
  const sessFiles = listDir(sessDir).filter((e) => e.isFile());
  if (sessFiles.length) {
    const newest = sessFiles.map((e) => statOf(path.join(sessDir, e.name))).filter(Boolean)
      .sort((a, b) => b.mtime - a.mtime)[0];
    out.push(finding("metadata", "info", "ff-session",
      `${sessFiles.length} session restore file(s) present`,
      "Session backups contain the open tab set and, in some builds, form and scroll state. They survive a crash and are worth clearing before handing a machine over.",
      { count: sessFiles.length, newest: newest ? newest.mtime.toISOString() : null }));
  }

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

  out.push(finding("endpoint", "info", "ff-persistence",
    "This profile is persistent",
    "Everything on disk survives across sessions. Cryptography cannot help here: only full-disk encryption or an amnesic environment changes this.",
    { profile_dir: profileDir }));

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

  const rfp = get("privacy.resistFingerprinting");
  if (rfp !== undefined) {
    out.push(finding("transport", asBool(rfp) ? "ok" : "info", "ff-rfp",
      `Fingerprint resistance: ${asBool(rfp) ? "enabled" : "disabled"}`,
      asBool(rfp)
        ? "privacy.resistFingerprinting is on. Note that it changes the profile's own fingerprint, so it is a deviation from the default population unless many others run the same configuration."
        : "Fingerprint resistance is off. A default Firefox is highly distinguishable by its own configuration, which undercuts any attempt to look unremarkable.",
      { resistFingerprinting: asBoolOrNull(rfp) }));
  }

  const cookieBehavior = get("network.cookie.cookieBehavior");
  if (cookieBehavior !== undefined) {
    // 0 accept all, 1 block third-party, 2 block all, 4 block cross-site trackers, 5 total cookie protection
    const labels = { 0: "accept all", 1: "block third-party", 2: "block all", 3: "block from unvisited", 4: "block cross-site trackers", 5: "total cookie protection" };
    const good = cookieBehavior === 4 || cookieBehavior === 5;
    out.push(finding("transport", good ? "ok" : "info", "ff-cookie-behavior",
      `Cookie policy: ${labels[cookieBehavior] ?? `unknown (${cookieBehavior})`}`,
      good
        ? "Cross-site tracking cookies are partitioned or blocked."
        : "Cookies from other sites are accepted, which is what makes cross-site tracking work in the first place.",
      { cookieBehavior }));
  }

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

  const telemetryEnabled = get("toolkit.telemetry.enabled");
  const healthreport = get("datareporting.healthreport.uploadEnabled");
  if (telemetryEnabled !== undefined || healthreport !== undefined) {
    const off = asBool(telemetryEnabled) === false && asBool(healthreport) === false;
    out.push(finding("metadata", off ? "ok" : "info", "ff-telemetry-prefs",
      off ? "Telemetry upload disabled in prefs" : "Telemetry prefs leave upload possible",
      off
        ? "Both toolkit.telemetry.enabled and datareporting.healthreport.uploadEnabled are false. The client ID may still exist on disk; see the telemetry finding above."
        : "At least one telemetry preference still allows reporting. Confirm the current defaults for your build, since Mozilla has changed how these prefs interact.",
      { toolkit_telemetry_enabled: asBoolOrNull(telemetryEnabled), healthreport_uploadEnabled: asBoolOrNull(healthreport) }));
  }

  const sponsored = get("browser.newtabpage.activity-stream.showSponsored");
  const pocket = get("extensions.pocket.enabled");
  if (sponsored !== undefined || pocket !== undefined) {
    const anyOn = asBool(sponsored) || asBool(pocket);
    out.push(finding("metadata", anyOn ? "info" : "ok", "ff-sponsored",
      anyOn ? "Sponsored content or Pocket is enabled" : "Sponsored content and Pocket are disabled",
      anyOn
        ? "These features contact Mozilla-operated endpoints and are tied to the browser. They are not a leak of local residue, but they are remote relationships worth knowing about."
        : "No Mozilla content endpoints are enabled from this profile.",
      { showSponsored: asBoolOrNull(sponsored), pocket: asBoolOrNull(pocket) }));
  }

  return out;
}

