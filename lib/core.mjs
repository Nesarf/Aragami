/**
 * Aragami - core
 *
 * Pure Node beyond the MCP SDK. The CLI and the MCP stdio server share this
 * single TOOLS[].execute -- there is deliberately no second implementation.
 *
 * ===================================================================
 * DESIGN DISCIPLINE (inherited from the original threat-model analysis; do not soften)
 * ===================================================================
 *
 * 1. This tool performs a STATIC audit only: it reads files, never starts Tor, and
 *    never touches the network. The single outbound call is the version lookup,
 *    which only queries Tor Project's public release metadata.
 *
 * 2. This tool cannot address traffic correlation, endpoint compromise, or anything
 *    that happens after decryption. Every response MUST carry boundary_notice --
 *    that is not decoration.
 *
 * 3. Separating the layers is the whole reason this tool exists:
 *      content layer  -- encryption; answers "can they read it"
 *      metadata layer -- the focus of this audit; answers "can they link it"
 *      endpoint layer -- cryptography cannot reach here; only isolation and hygiene can
 *      social layer   -- people, always the largest variable
 *    Payload encryption helps the metadata layer by roughly zero. Any output that
 *    conflates the two is wrong.
 *
 * 4. An auditor can only report STATIC RESIDUE AND CONFIGURATION POSTURE.
 *    It must never say "you are safe now".
 */

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { httpsGetJson, detectProxy } from "./net.mjs";
import {
  exists, statOf, readText, readJson, listDir,
  fmtBytes, fmtTime, daysSince, finding, parseTorrc, parsePrefs,
} from "./shared.mjs";
import { discoverFirefoxProfiles, auditFirefoxProfile, findFirefoxApplication, pickDefaultProfile } from "./firefox.mjs";
import { inspectEmblem, readShippedEmblem } from "./emblem.mjs";

// Re-exported so callers and tests can keep importing the parsers from the core.
export { parseTorrc, parsePrefs };

export const VERSION = "0.1.0";

/** Safe serialization: tolerates BigInt and circular references (all output goes through this). */
export function safeStringify(value, indent = 0) {
  const seen = new WeakSet();
  return JSON.stringify(
    value,
    (_k, v) => {
      if (typeof v === "bigint") return v.toString();
      if (typeof v === "object" && v !== null) {
        if (seen.has(v)) return "[circular]";
        seen.add(v);
      }
      return v;
    },
    indent
  );
}

/* ------------------------------------------------ constants */

export const LAYERS = {
  build: { key: "build", label: "Build", question: "Are you running a version with known holes?" },
  transport: { key: "transport", label: "Transport", question: "What does the traffic look like on the wire - can it be fingerprinted or blocked?" },
  crypto: { key: "crypto", label: "Content / authorization", question: "Who can read the content, and who can even reach the destination?" },
  metadata: { key: "metadata", label: "Metadata", question: "Who talks to whom, when, and how often - content encryption cannot see this layer" },
  endpoint: { key: "endpoint", label: "Endpoint", question: "What has this machine left behind, and what happens if it is taken?" },
  social: { key: "social", label: "Social", question: "People." },
};

export const SEVERITY_ORDER = { ok: 0, info: 1, warn: 2, critical: 3 };

/** Known pluggable transports and how well they blend in. */
export const PT_KNOWLEDGE = {
  obfs4: { blend: "medium", note: "Randomized traffic that looks unlike common protocols; published traffic-analysis research targets it" },
  webtunnel: { blend: "high", note: "Mimics an ordinary HTTPS website; the mainstay of censorship circumvention since 2024" },
  meek_lite: { blend: "high", note: "Domain fronting; depends on CDN cooperation, and availability has declined in recent years" },
  conjure: { blend: "high", note: "Refraction networking - borrows unused address space from ISPs" },
  snowflake: { blend: "high", note: "Connects over WebRTC to real volunteer browsers; the exit is a volunteer, not a relay" },
  scramblesuit: { blend: "low", note: "Obsolete; do not rely on it alone" },
  obfs2: { blend: "low", note: "Deprecated" },
  obfs3: { blend: "low", note: "Deprecated" },
};

export const BOUNDARY_NOTICE = [
  "This tool performs a static audit only: it reads files, never launches the application under audit, and never touches the network (except the version lookup).",
  "It does NOT address: traffic correlation and timing analysis, endpoint compromise (malware / device seizure), or anything that happens after decryption.",
  "It protects [configuration posture and static residue]. It is NOT an anti-tracking tool.",
  "A clean audit is NOT proof of safety. Treating it as one is a misuse.",
];

/* ------------------------------------------------ install discovery */

// The drive-letter sweep is DELIBERATELY bounded: A/B are legacy floppies, and probing
// further letters can block for a long time when a disconnected network drive is mapped.
// Pass an explicit `install` to audit anywhere else.
const DRIVE_LETTERS = "CDEFGHIJ".split("");

function candidateRoots() {
  const out = [];
  const home = os.homedir();
  for (const d of DRIVE_LETTERS) {
    out.push(`${d}:\\Tor Browser`);
    out.push(`${d}:\\tor browser`);
  }
  out.push(path.join(home, "Desktop", "Tor Browser"));
  out.push(path.join(home, "Documents", "Tor Browser"));
  out.push("C:\\Program Files\\Tor Browser");
  out.push("C:\\Program Files (x86)\\Tor Browser");
  return out;
}

/** Is this directory a Tor Browser install root (contains Browser/tbb_version.json)? */
function isInstallRoot(p) {
  return exists(path.join(p, "Browser", "tbb_version.json")) ||
         exists(path.join(p, "Browser", "firefox.exe"));
}

/** Shallow one-level sweep of a drive root looking for Tor directories. */
function shallowScanRoot(driveRoot) {
  const found = [];
  for (const e of listDir(driveRoot)) {
    if (!e.isDirectory()) continue;
    if (!/tor/i.test(e.name)) continue;
    const p = path.join(driveRoot, e.name);
    if (isInstallRoot(p)) found.push(p);
    else {
      // one level deeper
      for (const e2 of listDir(p)) {
        if (!e2.isDirectory()) continue;
        const p2 = path.join(p, e2.name);
        if (isInstallRoot(p2)) found.push(p2);
      }
    }
  }
  return found;
}

/**
 * Normalize a path into a de-duplication key.
 * Windows filesystems are case-insensitive -- without this, C:\Tor Browser and
 * C:\tor browser are counted as two separate installs (hit in practice).
 */
function canonKey(p) {
  let r;
  try { r = fs.realpathSync.native(p); }
  catch { try { r = fs.realpathSync(p); } catch { r = path.resolve(p); } }
  return process.platform === "win32" ? r.toLowerCase() : r;
}

/**
 * Discover every Tor Browser install on this machine.
 *
 * When `explicit` is given, only that path is considered (no full-drive sweep).
 * Otherwise candidate paths plus a shallow drive sweep are used.
 * @param {string=} explicit install root
 * @returns {Array<object>} results of describeInstall
 */
export function discoverInstalls(explicit) {
  const hits = new Map();
  const add = (p, how) => {
    // Ignore anything that is not a string: path.join throws on number/object, and tool
    // arguments come from untrusted callers (the matrix traverser crashed it with 12345 and {}).
    if (typeof p !== "string" || !p.trim()) return;
    if (!isInstallRoot(p)) return;
    let real;
    try { real = fs.realpathSync.native(p); } catch { real = path.resolve(p); }
    const key = canonKey(p);
    if (!hits.has(key)) hits.set(key, { root: real, found_by: how });
  };

  // Explicit means explicit: the caller said "audit this one", so do not go sweeping whole
  // drives (slow, and it mixes unrelated installs into the result - hit in practice).
  if (typeof explicit === "string" && explicit.trim()) {
    add(explicit, "explicit");
    return [...hits.values()].map((h) => describeInstall(h.root, h.found_by));
  }

  for (const c of candidateRoots()) {
    if (exists(c)) add(c, "candidate");
  }
  for (const d of DRIVE_LETTERS) {
    const dr = `${d}:\\`;
    if (!exists(dr)) continue;
    for (const p of shallowScanRoot(dr)) add(p, "scan");
  }

  return [...hits.values()].map((h) => describeInstall(h.root, h.found_by));
}

/** Read the structured facts about one install. */
export function describeInstall(root) {
  const browserDir = path.join(root, "Browser");
  const tbb = readJson(path.join(browserDir, "tbb_version.json"));
  const dataDir = path.join(browserDir, "TorBrowser", "Data");
  const torDataDir = path.join(dataDir, "Tor");
  const profileDir = path.join(dataDir, "Browser", "profile.default");

  const appIni = readText(path.join(browserDir, "application.ini")) || "";
  const fxVersion = (appIni.match(/^Version=(.+)$/m) || [])[1]?.trim() || null;

  return {
    root,
    browser_dir: browserDir,
    data_dir: torDataDir,
    profile_dir: profileDir,
    tor_browser_version: tbb?.version ?? null,
    channel: tbb?.channel ?? null,
    architecture: tbb?.architecture ?? null,
    firefox_version: fxVersion,
    drive: path.parse(root).root.replace(/\\$/, ""),
  };
}

/* ------------------------------------------------ per-layer checks */

function auditBuild(inst, stateText) {
  const out = [];
  const tb = inst.tor_browser_version;
  out.push(finding("build", tb ? "ok" : "warn", "tb-version",
    tb ? `Tor Browser version ${tb}` : "Could not determine the Tor Browser version",
    tb ? `channel ${inst.channel ?? "?"} / arch ${inst.architecture ?? "?"} / Firefox base ${inst.firefox_version ?? "?"}`
       : "Neither Browser/tbb_version.json nor application.ini was found; the install may be incomplete or modified.",
    { tor_browser_version: tb, channel: inst.channel, firefox: inst.firefox_version }));

  const torVer = (stateText?.match(/^TorVersion\s+(.+)$/m) || [])[1]?.trim();
  if (torVer) {
    out.push(finding("build", "info", "tor-version", `Inner Tor version: ${torVer}`,
      "The version of tor.exe. Tor Browser releases usually advance the Firefox base and Tor itself together; either one lagging is worth noticing.",
      { aragami_version: torVer }));
  }
  return out;
}

function auditTransport(entries, prefs) {
  const out = [];
  const bridges = entries.Bridge ?? [];
  const useBridges = (entries.UseBridges ?? []).some((v) => v.trim() === "1");
  const pts = entries.ClientTransportPlugin ?? [];

  // bridge overview
  const kinds = {};
  for (const b of bridges) {
    const k = (b.match(/^(\S+)/) || [, "?"])[1].toLowerCase();
    kinds[k] = (kinds[k] ?? 0) + 1;
  }
  const kindList = Object.entries(kinds).map(([k, n]) => `${k}x${n}`).join(", ");

  if (useBridges && bridges.length > 0) {
    const worst = Math.min(...Object.keys(kinds).map((k) => ({ high: 2, medium: 1, low: 0 }[PT_KNOWLEDGE[k]?.blend] ?? 1)));
    out.push(finding("transport", worst >= 1 ? "ok" : "warn", "bridges",
      `Bridges enabled (${kindList})`,
      "Bridges take the fact that you use Tor out of the public relay list - the first step of circumvention. " +
      (worst >= 1 ? "The chosen types have decent cover." : "But the chosen type offers poor cover; consider adding webtunnel/snowflake."),
      { bridges: kinds, count: bridges.length }));
  } else if (useBridges) {
    out.push(finding("transport", "warn", "bridges", "UseBridges is on but there are no Bridge lines",
      "The configuration is self-inconsistent; Tor may fail to start or fall back to a direct connection.", { use_bridges: true, bridge_count: 0 }));
  } else {
    out.push(finding("transport", "info", "bridges", "Bridges not enabled (connecting directly to public relays)",
      "This is normal on an unblocked network and gives the largest anonymity set. Bridges are required in a censored environment.",
      { use_bridges: false }));
  }

  // built-in vs custom bridges -- the key to blending in
  const builtinType = prefs["torbrowser.settings.bridges.builtin_type"];
  const bridgeSource = prefs["torbrowser.settings.bridges.source"];
  if (builtinType) {
    out.push(finding("transport", "ok", "bridge-blend",
      `Using built-in bridges (${builtinType})`,
      "Built-in bridges are byte-identical to everyone else who picked the same option - which is exactly the point: " +
      "your configuration lines are not a distinguishing feature. A custom bridge would stand out of the crowd.",
      { builtin_type: builtinType, source: bridgeSource }));
  }

  // uTLS fingerprint impersonation
  const utls = bridges.filter((b) => /utls-imitate=/.test(b)).map((b) => (b.match(/utls-imitate=(\S+)/) || [])[1]);
  if (utls.length) {
    out.push(finding("transport", "ok", "utls",
      `uTLS fingerprint impersonation detected (${[...new Set(utls)].join(", ")})`,
      "Makes the TLS ClientHello look like a common browser, defeating handshake-fingerprint identification. A genuine anti-fingerprinting measure.",
      { utls_imitate: [...new Set(utls)] }));
  }

  // domain fronting
  const fronts = bridges.filter((b) => /fronts=/.test(b)).map((b) => (b.match(/fronts=(\S+)/) || [])[1]);
  if (fronts.length) {
    out.push(finding("transport", "ok", "fronting",
      "Domain fronting detected (fronts=)",
      "Disguises the SNI as a high-reputation domain, defeating SNI-based blocking.",
      { fronts: [...new Set(fronts)].slice(0, 4) }));
  }

  // available pluggable transports
  if (pts.length) {
    const names = new Set();
    for (const p of pts) {
      const first = p.split(/\s+/)[0] ?? "";
      for (const nm of first.split(",")) if (nm) names.add(nm);
    }
    out.push(finding("transport", "info", "pt-list",
      `Pluggable transports loaded: ${[...names].join(", ")}`,
      "Available is not the same as in use; the entry above shows which bridge types are actually enabled.",
      { plugins: [...names], raw: pts }));
  }

  // deprecated transports
  const deprecated = Object.keys(kinds).filter((k) => PT_KNOWLEDGE[k]?.blend === "low");
  // Sum ALL deprecated kinds rather than looking only at the first one: otherwise a mix
  // such as obfs2x2 + obfs3x1 is missed (3 != 2).
  const deprecatedCount = deprecated.reduce((sum, k) => sum + kinds[k], 0);
  if (deprecatedCount > 0 && deprecatedCount === bridges.length) {
    out.push(finding("transport", "warn", "deprecated-pt",
      `The only transports in use are deprecated: ${deprecated.join(", ")}`,
      "obfs2/obfs3/scramblesuit are no longer considered effective protection and are easy to identify.",
      { deprecated }));
  }

  // quickstart (timing predictability)
  if (prefs["torbrowser.settings.quickstart.enabled"] === true) {
    out.push(finding("transport", "info", "quickstart",
      "Quickstart enabled (connects on launch)",
      "Convenient, but it anchors connection times to your usage habits, which over time forms a predictable temporal pattern. Manual connection is more controllable if timing matters to you.",
      { quickstart: true }));
  }

  return out;
}

function auditCrypto(entries, inst) {
  const out = [];
  const authDir = (entries.ClientOnionAuthDir ?? [])[0];

  if (authDir) {
    const keys = listDir(authDir).filter((e) => e.isFile() && /\.auth_private$/i.test(e.name));
    out.push(finding("crypto", "ok", "onion-auth-configured",
      "Onion service client authorization directory configured",
      "A v3 onion address is itself a public key (you cannot connect without knowing it); client authorization adds another layer - " +
      "only a key holder can make that service respond. This is genuine conditional reachability, with no change to the Tor protocol.",
      { dir: authDir, key_files: keys.length }));

    if (keys.length === 0) {
      out.push(finding("crypto", "info", "onion-auth-empty",
        "Client authorization directory is empty (ready but unused)",
        "Not an error - it just means no contact/service keys have been added yet. Drop *.auth_private files in when you need it.",
        { dir: authDir }));
    } else {
      out.push(finding("crypto", "info", "onion-auth-keys",
        `${keys.length} client authorization key(s) present`,
        "These keys are themselves sensitive assets: whoever holds one can reach the corresponding service.",
        { files: keys.map((k) => k.name) }));
    }
  } else {
    out.push(finding("crypto", "info", "onion-auth-absent",
      "Onion service client authorization not configured",
      "If you need a drop point that only specific people can reach, this is the simplest and most robust mechanism.",
      null));
  }

  // onion service private keys
  const keysDir = path.join(inst.data_dir, "keys");
  const hsKeys = listDir(keysDir);
  if (hsKeys.length) {
    out.push(finding("crypto", "warn", "hs-keys",
      `Onion service private key directory present (${hsKeys.length} entries)`,
      "If this machine hosts a .onion service, taking these keys means complete takeover of the service. Confirm you really need to host it persistently here.",
      { dir: keysDir, entries: hsKeys.map((e) => e.name).slice(0, 10) }));
  }

  return out;
}

/**
 * Metadata layer - the reason this tool exists.
 * Content encryption cannot see this layer at all, and this is where things actually go wrong.
 */
function auditMetadata(inst) {
  const out = [];
  const dd = inst.data_dir;

  // state: guard selection and usage residue
  const statePath = path.join(dd, "state");
  const st = statOf(statePath);
  const stateText = readText(statePath);
  if (st) {
    const lastWritten = (stateText?.match(/^LastWritten\s+(.+)$/m) || [])[1]?.trim() ?? null;
    // Modern Tor (0.4.x) writes  Guard in=default rsa_id=... nickname=...
    // Legacy writes EntryGuard ... . Both must be recognized - matching only the legacy
    // form produces a false "no guards" report (hit in practice).
    const guardLines = (stateText?.match(/^Guard\s+in=\S+/gm) ?? []).length
                     + (stateText?.match(/^EntryGuard[^\s]*/gm) ?? []).length;
    const guardSets = [...new Set((stateText?.match(/^Guard\s+in=\S+/gm) ?? [])
      .map((s) => s.replace(/^Guard\s+in=/, "")))];
    const bridgeLines = (stateText?.match(/^Bridge[^\s]*/gm) ?? []).length;
    const circBins = (stateText?.match(/^CircuitBuildTimeBin/gm) ?? []).length;

    out.push(finding("metadata", "warn", "state-file",
      `state file retained (${fmtBytes(st.size)}, last written ${fmtWritten(lastWritten)})`,
      "state records guard selection, bridge usage and circuit build-time distribution - the single most sensitive file in a Tor client. " +
      "Content encryption does nothing for it. If the device is seized, it can reconstruct the outline of your connection history.",
      { size: st.size, last_written: lastWritten, mtime: st.mtime.toISOString(), guards: guardLines, state_bridge_lines: bridgeLines, circuit_bins: circBins }));

    if (guardLines === 0) {
      out.push(finding("metadata", circBins > 0 ? "warn" : "info", "state-no-guards",
        "No guard records found in state",
        circBins > 0
          ? "Circuit build times exist but no guard entries. This tool makes no assertion - confirm by hand: did circuits ever build successfully? Was state reset or cleared?"
          : "This install may never have built a circuit successfully.",
        { guards: 0, circuit_bins: circBins }));
    } else {
      out.push(finding("metadata", "warn", "state-guards",
        `state records ${guardLines} guard(s)${guardSets.length ? ` (sets: ${guardSets.join(", ")})` : ""}`,
        "Guards are the metadata most directly tied to who you are - they bind you to an entry observation point. Content encryption does nothing here. " +
        "The guard set accumulates over time: the more it accumulates, the larger the surface that can be correlated retroactively.",
        { guards: guardLines, sets: guardSets }));
    }
  }

  // descriptor caches
  for (const name of ["cached-descriptors", "cached-microdescs", "cached-microdescs.new", "cached-certs", "cached-consensus"]) {
    const p = path.join(dd, name);
    const s = statOf(p);
    if (!s || s.size === 0) continue;
    const d = daysSince(s.mtime);
    const stale = d != null && d > 90;
    out.push(finding("metadata", "info", `cache-${name}`,
      `Descriptor cache ${name}: ${fmtBytes(s.size)} (updated ${d} day(s) ago)`,
      (stale
        ? "Not updated for a long time - this install has been idle. Idle residue is still a forensic asset: "
        : "Updated recently, so it has genuinely been in use. ") +
      "It does not identify you directly, but combined with state and timestamps it outlines a usage pattern.",
      { size: s.size, mtime: s.mtime.toISOString(), age_days: d, stale }));
  }

  // pt_state
  const ptd = path.join(dd, "pt_state");
  const ptFiles = listDir(ptd).filter((e) => e.isFile());
  if (ptFiles.length) {
    out.push(finding("metadata", "info", "pt-state",
      `pt_state retains ${ptFiles.length} file(s)`,
      "State residue from pluggable transports (bridge/endpoint caches).",
      { files: ptFiles.map((e) => e.name).slice(0, 10) }));
  }

  // profile usage-time fingerprints
  const timesPath = path.join(inst.profile_dir, "times.json");
  const times = readJson(timesPath);
  if (times) {
    const first = times.firstUse ?? times.created;
    out.push(finding("metadata", "warn", "profile-times",
      `Browser profile records a first-use time (${fmtTime(first)})`,
      "Not a privacy leak in itself, but it is hard evidence of when this machine started using Tor, and the overall outline of usage cannot be erased. " +
      "If the existence of the activity itself must leave no trace, a persistent install cannot do it - that requires an amnesic environment.",
      { first_use: times.firstUse, created: times.created }));
  }

  const scp = path.join(inst.profile_dir, "sessionCheckpoints.json");
  const ss = statOf(scp);
  if (ss && ss.size > 0) {   // consistent with places: 0 bytes does not count as "present"
    out.push(finding("metadata", "info", "session-checkpoints",
      "Session checkpoints present (sessionCheckpoints.json)",
      "Window/tab restore state. If you used it for anything sensitive, this file may indirectly reflect what kinds of targets you visited.",
      { size: ss.size, mtime: ss.mtime.toISOString() }));
  }

  // history and downloads
  const hist = path.join(inst.profile_dir, "places.sqlite");
  const hs = statOf(hist);
  if (hs && hs.size > 0) {
    out.push(finding("metadata", "warn", "places",
      `Browsing history database present (places.sqlite, ${fmtBytes(hs.size)})`,
      "Tor Browser clears this on exit by default, so its presence means either it never exited cleanly or the cleanup did not take effect. Confirm by hand.",
      { size: hs.size, mtime: hs.mtime.toISOString() }));
  }

  return out;
}

function fmtWritten(s) {
  return s ? s : "unknown";
}

function auditEndpoint(inst) {
  const out = [];

  const drive = inst.drive;
  const systemDrive = (process.env.SystemDrive ?? "C:").replace(/\\$/, "");
  if (drive && drive.toUpperCase() !== systemDrive.toUpperCase()) {
    out.push(finding("endpoint", "ok", "disk-location",
      `Installed on drive ${drive} (not the system drive)`,
      "Separated from the system drive: easier to handle as a whole, and no Tor data lands in the system temp directory.",
      { drive, system_drive: systemDrive }));
  } else {
    out.push(finding("endpoint", "info", "disk-location",
      `Installed on the system drive ${drive}`,
      "Not an error, but keeping Tor on the same volume as the system means formatting or forensics will handle them together.",
      { drive, system_drive: systemDrive }));
  }

  // system / user-directory traces
  const home = os.homedir();
  const traces = [];
  for (const p of [
    path.join(home, "AppData", "Roaming", "Tor Browser"),
    path.join(home, "AppData", "Local", "Tor Browser"),
    path.join(home, "Desktop", "Tor Browser"),
    path.join(home, "Documents", "Tor Browser"),
    path.join(home, "Downloads", "Tor Browser"),
    path.join(os.tmpdir(), "Tor Browser"),
  ]) {
    // Windows paths are case-insensitive: a plain string compare can mistake the install's
    // own directory for a stray copy.
    const norm = (x) => (process.platform === "win32" ? path.resolve(x).toLowerCase() : path.resolve(x));
    if (exists(p) && norm(p) !== norm(inst.root)) traces.push(p);
  }
  if (traces.length === 0) {
    out.push(finding("endpoint", "ok", "no-stray-traces",
      "No Tor residue in user or temp directories",
      "Roaming/Local/Desktop/Documents/Downloads/temp are all clean; data lives only in the designated install.",
      { checked: home }));
  } else {
    out.push(finding("endpoint", "warn", "stray-traces",
      `Found ${traces.length} stray Tor cop(y/ies) in user directories`,
      "Extra copies fragment your cleanup surface: you think you removed one, another remains.",
      { traces }));
  }

  // persistent vs amnesic
  out.push(finding("endpoint", "info", "persistence",
    "This install is persistent (not amnesic)",
    "Everything on disk survives across sessions: state, descriptor caches, the profile, and possibly downloads. " +
    "Cryptography cannot help here at all - only environment isolation (an amnesic OS) or full-disk encryption manages it.",
    { root: inst.root }));

  return out;
}

/* ------------------------------------------------ environment probe */

export function detectEnvironment() {
  const env = {
    mode: "cli",
    platform: process.platform,
    arch: process.arch,
    node: process.version,
    homedir: os.homedir(),
    system_drive: process.env.SystemDrive ?? null,
    temp: os.tmpdir(),
  };
  // Which entry point is running: the MCP stdio server, or the CLI. Only the entry script's
  // directory is inspected, never the whole argv (which includes the absolute cwd) -
  // otherwise a project living under any directory containing "mcp" would make the CLI
  // report itself as mcp.
  const entry = (process.argv[1] ?? "").replace(/\\/g, "/").toLowerCase();
  if (/\/mcp\//.test(entry)) env.mode = "mcp";
  return env;
}

/* ------------------------------------------------ version freshness */

export const TOR_VERSION_ENDPOINTS = {
  release: "https://aus1.torproject.org/torbrowser/update_3/release/downloads.json",
  alpha: "https://aus1.torproject.org/torbrowser/update_3/alpha/downloads.json",
};

/** Mozilla publishes the current Firefox versions as one small JSON document. */
export const FIREFOX_VERSION_ENDPOINT = "https://product-details.mozilla.org/1.0/firefox_versions.json";
export const FIREFOX_CHANNEL_KEYS = {
  release: "LATEST_FIREFOX_VERSION",
  esr: "FIREFOX_ESR",
  beta: "LATEST_FIREFOX_RELEASED_DEVEL_VERSION",
  nightly: "FIREFOX_NIGHTLY",
};

export function cmpVer(a, b) {
  const pa = String(a).split(".").map((x) => parseInt(x, 10) || 0);
  const pb = String(b).split(".").map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d > 0 ? 1 : -1;
  }
  return 0;
}

/* ------------------------------------------------ layer-mismatch assessment (the framework) */

/**
 * Four-layer model. Any assessment must state clearly that a problem in one layer
 * cannot be solved by a control from another.
 */
export const LAYER_MODEL = [
  {
    layer: "content", label: "Content",
    question: "Can anyone read the content itself?",
    answers_with: "End-to-end encryption (age / PGP / Signal Double Ratchet / AES-GCM)",
    solved_by_this_tool: false,
    tool_role: "none",
    note: "The layer that is already solved best. Ordinary tooling suffices; it is not the bottleneck.",
  },
  {
    layer: "metadata", label: "Metadata",
    question: "Can anyone tell who talks to whom, when, and how often?",
    answers_with: "Mixnet (Loopix/Nym), metadata-hiding messengers (SimpleX/Cwtch), asynchronous mailboxes, onion services, cover traffic",
    solved_by_this_tool: false,          // this tool does NOT solve the metadata layer: it only audits static residue
    tool_role: "audits_static_residue",
    note: "Content encryption helps this layer by roughly zero. This is where most approaches go wrong.",
  },
  {
    layer: "endpoint", label: "Endpoint",
    question: "What has this machine left behind, and what happens if it is taken?",
    answers_with: "Environment isolation (Qubes/Whonix/Tails), full-disk encryption, minimal persistent state",
    solved_by_this_tool: false,
    tool_role: "none",
    note: "Cryptography cannot reach this layer. An auditor can tell you what residue exists; it cannot remove it for you.",
  },
  {
    layer: "social", label: "Social",
    question: "What will people say, keep, or be asked?",
    answers_with: "No technical solution",
    solved_by_this_tool: false,
    tool_role: "none",
    note: "The most common point of failure in public cases. All any tool can say here is: it cannot help you.",
  },
];

/* ------------------------------------------------ TOOLS */

// Shared filter normalization. Unknown values fall back to defaults, and the filter that
// actually took effect is echoed back - otherwise a caller's typo silently yields an empty
// result with no explanation (a usability defect found by the matrix traverser).
function applyFilter(findings, args) {
  const effLayer = (typeof args.layer === "string" && (args.layer === "all" || LAYERS[args.layer]))
    ? args.layer : "all";
  const effSev = (typeof args.min_severity === "string" && args.min_severity in SEVERITY_ORDER)
    ? args.min_severity : "ok";
  const minSev = SEVERITY_ORDER[effSev];
  let out = findings;
  if (effLayer !== "all") out = out.filter((f) => f.layer === effLayer);
  out = out.filter((f) => SEVERITY_ORDER[f.severity] >= minSev);
  out.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);
  return { findings: out, layer: effLayer, min_severity: effSev };
}

/**
 * Pick the target.
 *
 * An explicit argument always wins. Otherwise ARAGAMI_TARGET sets the build default, which
 * is what makes per-target artifacts possible without forking the code: the tor launcher
 * exports ARAGAMI_TARGET=tor and the firefox launcher exports firefox, and both run the
 * same core. Only when neither is present does auto-detection apply, preferring Tor
 * Browser and falling back to Firefox.
 */
function resolveTarget(requested, torInstalls, ffProfiles) {
  if (requested === "tor" || requested === "firefox") return requested;
  const fromEnv = process.env.ARAGAMI_TARGET;
  if (fromEnv === "tor" || fromEnv === "firefox") return fromEnv;
  if (torInstalls.length > 0) return "tor";
  if (ffProfiles.length > 0) return "firefox";
  return "tor";
}

/** proxy argument semantics: undefined = auto, false/"none" = force direct, else the URL. */
function resolveProxyArg(p) {
  return p === undefined ? undefined : (p === false || p === "none" ? null : p);
}

const tallyOf = (findings) => {
  const t = {};
  for (const f of findings) t[f.severity] = (t[f.severity] ?? 0) + 1;
  return t;
};

/**
 * Local Firefox version: the installed application first, then what the profile last used
 * with. compatibility.ini writes "142.0_20250901123456/20250901123456", so the version has
 * to be cut at the underscore.
 */
function resolveFirefoxLocal(explicitInstall, profiles) {
  const app = findFirefoxApplication(explicitInstall);
  if (app) return { version: app.version, from: `application.ini at ${app.dir}` };
  const p = profiles.find((x) => x.is_default) ?? profiles[0];
  const lv = p?.last_version ?? null;
  if (lv) return {
    version: String(lv).split("_")[0],
    from: `compatibility.ini in ${p.profile_dir} (the version this profile was last used with, not necessarily what is installed)`,
  };
  return { version: null, from: null };
}

const TOOLS = [
  {
    name: "aragami_env",
    description:
      "Probe the runtime environment and discover every supported target on this machine: Tor Browser installs and " +
      "Firefox profiles. Read-only, no network. Run this first to obtain the install or profile path the other tools take.",
    inputSchema: {
      type: "object",
      properties: {
        install: { type: "string", description: "Optional: a Tor Browser install root to use directly" },
      },
    },
    async execute(args = {}) {
      const torInstalls = discoverInstalls(args.install);
      const ffProfiles = discoverFirefoxProfiles();
      return {
        environment: detectEnvironment(),
        targets: {
          tor: { found: torInstalls.length, installs: torInstalls },
          firefox: { found: ffProfiles.length, profiles: ffProfiles },
        },
        // The emblem travels with the tool as a sealed statement of what it is named after. It
        // is reported here because this is the tool that answers what is running, and it is
        // reported as structure only: this process holds no key and must not imply otherwise.
        emblem: inspectEmblem(readShippedEmblem()),
        boundary_notice: BOUNDARY_NOTICE,
      };
    },
  },

  {
    name: "aragami_audit",
    description:
      "Full static posture audit of one target across five layers. For Tor Browser: build versions, bridges/pluggable " +
      "transports/uTLS/domain fronting, onion client authorization and service keys, state guard residue and descriptor " +
      "caches, disk location and stray copies. For Firefox: application version, proxy and DoH and content-blocking " +
      "prefs, saved logins and key material, history and cookies and site data and telemetry ID and account linkage, " +
      "profile location and persistence. Reads files only; launches nothing and uses no network. " +
      "Severity is calibrated per target rather than shared: Tor Browser is hardened by default, so retained state there " +
      "is a deviation and is reported as a warning, whereas a plain Firefox profile retains data by design, so only " +
      "cross-machine identity linkage and credential exposure earn a warning. " +
      "Findings are grouped by layer and sorted by severity. A clean audit is not safety - see boundary_notice.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          enum: ["auto", "tor", "firefox"],
          description: "Which target to audit; auto prefers Tor Browser and falls back to Firefox",
        },
        install: { type: "string", description: "Tor Browser install root; auto-discovered when omitted" },
        profile: { type: "string", description: "Firefox profile directory; defaults to the profile marked default, else the first one found" },
        layer: {
          type: "string",
          enum: ["all", "build", "transport", "crypto", "metadata", "endpoint"],
          description: "Restrict output to one layer; defaults to all",
        },
        min_severity: {
          type: "string",
          enum: ["ok", "info", "warn", "critical"],
          description: "Minimum severity to report; defaults to ok (everything, including positive findings)",
        },
      },
    },
    async execute(args = {}) {
      const torInstalls = discoverInstalls(args.install);
      const ffProfiles = discoverFirefoxProfiles();
      const target = resolveTarget(args.target, torInstalls, ffProfiles);

      if (target === "tor") {
        if (torInstalls.length === 0) {
          return {
            target,
            error: "No Tor Browser install found. Use aragami_env to see the scan scope, or pass an explicit install path.",
            boundary_notice: BOUNDARY_NOTICE,
          };
        }
        const inst = torInstalls[0];
        const torrc = parseTorrc(readText(path.join(inst.data_dir, "torrc")));
        const defaults = parseTorrc(readText(path.join(inst.data_dir, "torrc-defaults")));
        const prefs = parsePrefs(readText(path.join(inst.profile_dir, "prefs.js")));
        const stateText = readText(path.join(inst.data_dir, "state"));
        const merged = {
          entries: { ...defaults.entries, ...torrc.entries },
          order: [...defaults.order, ...torrc.order],
        };
        const f = applyFilter([
          ...auditBuild(inst, stateText),
          ...auditTransport(merged.entries, prefs),
          ...auditCrypto(merged.entries, inst),
          ...auditMetadata(inst),
          ...auditEndpoint(inst),
        ], args);
        return {
          target,
          install: inst,
          applied_filter: { layer: f.layer, min_severity: f.min_severity },
          tally: tallyOf(f.findings),
          findings: f.findings,
          torrc_effective: {
            UseBridges: merged.entries.UseBridges ?? null,
            Bridge_count: (merged.entries.Bridge ?? []).length,
            ClientOnionAuthDir: merged.entries.ClientOnionAuthDir ?? null,
            ClientTransportPlugin_count: (merged.entries.ClientTransportPlugin ?? []).length,
            SocksPort: merged.entries.SocksPort ?? null,
            ControlPort: merged.entries.ControlPort ?? null,
          },
          boundary_notice: BOUNDARY_NOTICE,
        };
      }

      // ---- Firefox ----
      if (ffProfiles.length === 0) {
        return {
          target,
          error: "No Firefox profile found. Use aragami_env to see the scan scope, or pass an explicit profile path.",
          boundary_notice: BOUNDARY_NOTICE,
        };
      }
      let profileDir = args.profile;
      if (typeof profileDir !== "string" || !profileDir.trim()) {
        profileDir = pickDefaultProfile(ffProfiles).profile_dir;
      }
      const f = applyFilter(auditFirefoxProfile(profileDir, { allProfiles: ffProfiles }), args);
      return {
        target,
        profile: profileDir,
        profiles_found: ffProfiles.length,
        applied_filter: { layer: f.layer, min_severity: f.min_severity },
        tally: tallyOf(f.findings),
        findings: f.findings,
        boundary_notice: BOUNDARY_NOTICE,
      };
    },
  },

  {
    name: "aragami_version",
    description:
      "Check version freshness for the selected target. For Tor Browser it reads the local tbb_version.json and compares " +
      "it against Tor Project's official release metadata; for Firefox it reads the installed application (falling back to " +
      "the version the profile was last used with) and compares it against Mozilla's published current versions, honouring " +
      "the release / esr / beta / nightly channel. This is the only network call the tool makes; it reads public version " +
      "information only and never touches the audited application. It uses the local proxy automatically (environment " +
      "variables or the Windows system proxy); override with the proxy argument.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          enum: ["auto", "tor", "firefox"],
          description: "Which target to check; auto prefers Tor Browser and falls back to Firefox",
        },
        install: { type: "string", description: "Tor Browser install root, or a Firefox program directory; auto-discovered when omitted" },
        online: { type: "boolean", description: "Whether to check online; defaults to true. false reports the local version only." },
        proxy: { type: "string", description: 'Proxy URL (e.g. http://127.0.0.1:8080 or socks5://127.0.0.1:1080). Auto-detected when omitted; pass "none" to force a direct connection.' },
      },
    },
    async execute(args = {}) {
      const torInstalls = discoverInstalls(args.install);
      const ffProfiles = discoverFirefoxProfiles();
      const target = resolveTarget(args.target, torInstalls, ffProfiles);
      const result = {
        target,
        installed: null,
        channel: null,
        latest: null,
        verdict: "unknown",
        boundary_notice: BOUNDARY_NOTICE,
      };

      if (target === "tor") {
        const inst = torInstalls[0] ?? null;
        result.installed = inst?.tor_browser_version ?? null;
        result.channel = inst?.channel ?? "release";
        result.firefox_base = inst?.firefox_version ?? null;
        if (args.online === false) {
          result.note = "Online check skipped as requested.";
          return result;
        }
        const url = TOR_VERSION_ENDPOINTS[result.channel] ?? TOR_VERSION_ENDPOINTS.release;
        try {
          const { json: j, via } = await httpsGetJson(url, { timeoutMs: 15000, proxy: resolveProxyArg(args.proxy) });
          result.latest = j.version ?? null;
          result.source = url;
          result.via = via;
          result.proxy_detected = detectProxy();
          if (result.installed && result.latest) {
            const c = cmpVer(result.installed, result.latest);
            result.verdict = c === 0 ? "current" : c < 0 ? "outdated" : "ahead";
            result.delta = c < 0 ? `${result.installed} -> ${result.latest}` : null;
          }
        } catch (e) {
          result.verdict = "check-failed";
          result.error = String(e.message ?? e);
          result.source = url;
        }
        return result;
      }

      // ---- Firefox ----
      const local = resolveFirefoxLocal(args.install, ffProfiles);
      result.installed = local.version;
      result.channel = "release";
      result.local_source = local.from;
      if (args.online === false) {
        result.note = "Online check skipped as requested.";
        return result;
      }
      try {
        const { json: j, via } = await httpsGetJson(FIREFOX_VERSION_ENDPOINT, { timeoutMs: 15000, proxy: resolveProxyArg(args.proxy) });
        result.latest = j[FIREFOX_CHANNEL_KEYS[result.channel]] ?? null;
        result.available_channels = Object.fromEntries(
          Object.entries(FIREFOX_CHANNEL_KEYS).map(([k, key]) => [k, j[key] ?? null]));
        result.source = FIREFOX_VERSION_ENDPOINT;
        result.via = via;
        result.proxy_detected = detectProxy();
        if (result.installed && result.latest) {
          const c = cmpVer(result.installed, result.latest);
          result.verdict = c === 0 ? "current" : c < 0 ? "outdated" : "ahead";
          result.delta = c < 0 ? `${result.installed} -> ${result.latest}` : null;
        }
      } catch (e) {
        result.verdict = "check-failed";
        result.error = String(e.message ?? e);
        result.source = FIREFOX_VERSION_ENDPOINT;
      }
      return result;
    },
  },
  {
    name: "aragami_layer_assess",
    description:
      "Layered threat assessment. Given scenario characteristics, decide which layer of protection is needed, recommend a delivery channel, " +
      "and explicitly list what the method does NOT cover. This tool is built to say no: it refuses to manufacture false confidence. " +
      "Whenever a scenario lands in the metadata or endpoint layer it points at the real answer (mixnet / environment isolation / no technical solution) " +
      "rather than piling on more onion configuration.",
    inputSchema: {
      type: "object",
      properties: {
        content_sensitive: { type: "boolean", description: "Does the content itself need protection (what happens if it is read)" },
        metadata_sensitive: { type: "boolean", description: "Does the fact of communicating need protection (what happens if who-talks-to-whom is known)" },
        realtime: { type: "boolean", description: "Is realtime / near-realtime round-trip required" },
        counterpart_capability: {
          type: "string",
          enum: ["email-only", "can-install-tools", "signal-capable", "tor-capable"],
          description: "The upper bound of the counterpart's tooling - this usually caps the whole design",
        },
        must_leave_no_third_party_copy: { type: "boolean", description: "Must no third party retain a copy" },
        endpoint_shared_or_seizable: { type: "boolean", description: "Can the endpoint be accessed by others or seized" },
      },
    },
    async execute(args = {}) {
      const content = args.content_sensitive === true;
      const meta = args.metadata_sensitive === true;
      const realtime = args.realtime === true;
      const cap = args.counterpart_capability ?? "email-only";
      const noCopy = args.must_leave_no_third_party_copy === true;
      const seizable = args.endpoint_shared_or_seizable === true;

      const warnings = [];
      const does_not_cover = [];
      const steps = [];

      // -- core discipline: layer-mismatch detection --
      if (content && !meta) {
        steps.push("Content layer only: ordinary end-to-end encryption suffices (age / 7z+AES / Proton encrypted email).");
        warnings.push("Do not pile high-risk tradecraft onto a purely content-sensitive scenario - that itself is the most conspicuous signature.");
      }
      if (meta) {
        warnings.push("You declared metadata sensitivity. Note: content encryption helps the metadata layer by roughly zero.");
        steps.push("The metadata layer needs: a mixnet (Nym) or a metadata-hiding messenger (SimpleX / Cwtch), not a wrapper around email.");
      }
      if (meta && realtime) {
        warnings.push(
          "[HARD CONFLICT] Realtime round-trips directly oppose metadata protection. Realtime communication couples both endpoints' timing tightly, " +
          "which is the perfect material for end-to-end timing correlation. If metadata protection is genuinely required, you must accept asynchrony " +
          "(mailbox / dead-drop model, where the receiver fetches on its own schedule).");
        steps.push("Convert realtime into asynchronous: use a drop point / mailbox model so that send and fetch are decoupled in time.");
      }
      if (cap === "email-only") {
        warnings.push("The counterpart only has email - this caps the design hard: PGP, OnionShare and Tor are all unusable for an ordinary mailbox user.");
        steps.push("What email can realistically carry: Proton/Tutanota encrypted-to-external mail (zero tooling for them), or a password-protected archive with the passphrase sent out of band.");
      }
      if (noCopy) {
        steps.push("No third-party copy: OnionShare (ephemeral onion, file stays on your machine) or send directly over Signal/SimpleX, bypassing email entirely.");
        if (cap === "email-only") warnings.push('But the counterpart is email-only, so "no third-party copy" is not achievable - re-evaluate their capability.');
      }
      if (seizable) {
        warnings.push(
          "The endpoint may be accessed or seized. This is the layer cryptography cannot reach: a coerced endpoint, a keylogger, " +
          "and already-decrypted copies cannot be fixed by any transport-layer design.");
        steps.push("The endpoint layer only yields to environment isolation (Qubes+Whonix / an amnesic OS) and full-disk encryption - and you must assume that a seized device means disclosed content.");
      }

      // -- disclaimer that must always be present --
      does_not_cover.push("Traffic correlation and timing analysis (the adversary only needs to line up entry and exit times; reading the content is unnecessary)");
      does_not_cover.push("Endpoint compromise: malware, keyloggers, device seizure");
      does_not_cover.push("What happens after decryption: the recipient read it, kept a copy, talked about it, met someone - the most common failure in public cases");
      does_not_cover.push("People (the social layer has no technical solution)");

      const recommended_channel =
        !content && !meta ? "No special channel needed (ordinary email is fine)"
        : meta && cap === "tor-capable" ? "Nym mixnet, or SimpleX / Cwtch; email for notification only"
        : meta ? "Prefer SimpleX (no user identifiers); if the counterpart only uses email, email transport is acceptable but must be asynchronous"
        : noCopy ? "OnionShare, or Signal / SimpleX"
        : cap === "email-only" ? "Proton / Tutanota encrypted-to-external mail, passphrase sent out of band"
        : "Signal / SimpleX with an encrypted attachment, passphrase sent out of band";

      return {
        input: { content_sensitive: content, metadata_sensitive: meta, realtime, counterpart_capability: cap,
                 must_leave_no_third_party_copy: noCopy, endpoint_shared_or_seizable: seizable },
        layer_model: LAYER_MODEL,
        recommended_channel,
        steps,
        warnings,
        does_not_cover,
        verdict:
          !content && !meta && !seizable && !noCopy
            ? "No sensitivity was declared - no special tradecraft is warranted. Applying high-risk tradecraft to low-sensitivity content is itself the most conspicuous signature."
          : meta || seizable
            ? 'This scenario cannot be solved by "configuring Tor/encryption better". Follow the warnings above to the layer that actually addresses it.'
            : "This scenario is a content-layer problem; ordinary encryption is enough and no high-intensity tradecraft is needed.",
        boundary_notice: BOUNDARY_NOTICE,
      };
    },
  },
];

export { TOOLS };
export default { TOOLS, VERSION };