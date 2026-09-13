/**
 * Shared test fixtures: synthetic Tor Browser install trees, plus one synthetic Firefox
 * home directory (profiles root + program directory).
 *
 * Why this is a separate module: selftest, matrix and firefox all need them, and duplicating
 * a fixture means leaving two sources of truth that drift apart.
 *
 * The fixtures are deliberately shaped into several forms so that different code paths are
 * forced open - `minimal` in particular simulates missing files and exists to catch
 * null-safety gaps, and the Firefox fixture's profiles.ini carries two disagreeing default
 * markers to catch profile misselection.
 *
 * All fixture data is ASCII on purpose, to keep the suite portable and diff-friendly.
 */

import fs from "node:fs";
import path from "node:path";

function write(p, s) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, s, "utf8");
}

/** Binary residue: same parent-directory guarantee as write(), for SQLite databases. */
function writeBytes(p, buf) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, buf);
}

function layout(root) {
  return {
    root,
    browser: path.join(root, "Browser"),
    torData: path.join(root, "Browser", "TorBrowser", "Data", "Tor"),
    profile: path.join(root, "Browser", "TorBrowser", "Data", "Browser", "profile.default"),
  };
}

/**
 * Well-configured: built-in Snowflake bridges + domain fronting + uTLS + guards +
 * an authorization directory (empty).
 * Expected: utls and fronting hit; no deprecated-transport warning.
 */
export function makeGoodFixture(base) {
  const L = layout(path.join(base, "Good"));
  fs.mkdirSync(L.torData, { recursive: true });
  fs.mkdirSync(L.profile, { recursive: true });
  fs.mkdirSync(path.join(L.torData, "onion-auth"), { recursive: true });

  write(path.join(L.browser, "tbb_version.json"),
    JSON.stringify({ version: "15.0.20", architecture: "windows-x86_64", channel: "release" }));
  write(path.join(L.browser, "application.ini"), "[App]\nVendor=Tor Project\nVersion=140.15.0\n");

  write(path.join(L.torData, "torrc"), [
    "Bridge snowflake 192.0.2.4:80 ABCDEF fronts=a.example.com,b.example.com utls-imitate=hellorandomizedalpn",
    "Bridge snowflake 192.0.2.3:80 123456",
    `ClientOnionAuthDir ${path.join(L.torData, "onion-auth")}`,
    `DataDirectory ${L.torData}`,
    "UseBridges 1",
  ].join("\n") + "\n");

  write(path.join(L.torData, "torrc-defaults"),
    "ClientTransportPlugin obfs2,obfs3,obfs4,scramblesuit,webtunnel exec lyrebird.exe\n");

  write(path.join(L.torData, "state"), [
    "# Tor state file last generated on 2026-09-12 22:21:44 local time",
    "LastWritten 2026-09-12 14:21:44",
    "TorVersion Tor 0.4.9.11",
    "Guard in=default rsa_id=AAAA nickname=alpha",
    "Guard in=default rsa_id=BBBB nickname=beta",
    "Guard in=bridges rsa_id=CCCC nickname=gamma",
    "CircuitBuildTimeBin 715 1",
    "CircuitBuildTimeBin 765 1",
  ].join("\n") + "\n");

  fs.writeFileSync(path.join(L.torData, "cached-microdescs"), Buffer.alloc(4096));
  fs.writeFileSync(path.join(L.torData, "cached-certs"), Buffer.alloc(512));
  // pt_state residue: covers the core pt-state branch
  write(path.join(L.torData, "pt_state", "snowflake.state"), "dummy-pt-state\n");
  write(path.join(L.torData, "pt_state", "conjure.state"), "dummy-pt-state\n");

  write(path.join(L.profile, "prefs.js"), [
    'user_pref("torbrowser.settings.bridges.enabled", true);',
    'user_pref("torbrowser.settings.bridges.builtin_type", "snowflake");',
    'user_pref("torbrowser.settings.bridges.source", 0);',
    'user_pref("torbrowser.settings.quickstart.enabled", true);',
  ].join("\n") + "\n");
  write(path.join(L.profile, "times.json"),
    JSON.stringify({ firstUse: 1763730484848, created: 1763730471181 }));
  write(path.join(L.profile, "sessionCheckpoints.json"), JSON.stringify({ windows: [] }));
  fs.writeFileSync(path.join(L.profile, "places.sqlite"), Buffer.alloc(2048));

  return L.root;
}

/**
 * Degraded: the only transport is deprecated obfs2, no uTLS / no domain fronting,
 * a key in the authorization directory, and no guards in state.
 * Expected: deprecated-pt / onion-auth-keys / state-no-guards hit; utls must not hit.
 */
export function makeDegradedFixture(base) {
  const L = layout(path.join(base, "Degraded"));
  fs.mkdirSync(L.torData, { recursive: true });
  fs.mkdirSync(L.profile, { recursive: true });

  write(path.join(L.browser, "tbb_version.json"),
    JSON.stringify({ version: "15.0.22", channel: "release" }));
  write(path.join(L.browser, "application.ini"), "[App]\nVersion=140.15.0\n");
  write(path.join(L.torData, "torrc"), [
    "SocksPort 9150",
    "Bridge obfs2 1.2.3.4:80 AAA",
    "UseBridges 1",
    `ClientOnionAuthDir ${path.join(L.torData, "onion-auth")}`,
  ].join("\n") + "\n");
  write(path.join(L.torData, "torrc-defaults"), "ClientTransportPlugin obfs2,obfs3 exec old.exe\n");
  write(path.join(L.torData, "state"), "LastWritten 2026-01-01 00:00:00\n");
  write(path.join(L.profile, "prefs.js"), 'user_pref("torbrowser.settings.bridges.enabled", true);\n');
  write(path.join(L.torData, "onion-auth", "a.auth_private"),
    "x.onion:descriptor:x25519:BASE64KEY\n");
  // onion service private key (triggers the hs-keys warning)
  write(path.join(L.torData, "keys", "secret_id_key"), "dummy\n");

  return L.root;
}

/**
 * Minimal: only tbb_version.json. torrc / state / prefs / profile are all absent.
 * Purpose: null safety - any missing guard blows up here.
 */
export function makeMinimalFixture(base) {
  const L = layout(path.join(base, "Minimal"));
  write(path.join(L.browser, "tbb_version.json"),
    JSON.stringify({ version: "14.0.0", channel: "alpha" }));
  return L.root;
}

/**
 * Self-inconsistent: UseBridges is on but there are no Bridge lines.
 * Purpose: covers the core "configuration is self-inconsistent" branch, which previously
 * had no fixture reaching it.
 */
export function makeInconsistentFixture(base) {
  const L = layout(path.join(base, "Inconsistent"));
  fs.mkdirSync(L.torData, { recursive: true });
  write(path.join(L.browser, "tbb_version.json"),
    JSON.stringify({ version: "15.0.20", channel: "release" }));
  write(path.join(L.torData, "torrc"), "UseBridges 1\nSocksPort 9150\n");
  return L.root;
}

/**
 * Edge fixture - locks down several traps fixed during proofreading:
 *   - deprecated transports appearing MIXED (obfs2x2 + obfs3x1): the old logic counted
 *     only the first kind and therefore missed it
 *   - a descriptor cache older than 90 days: verifies idle and active produce different
 *     text, rather than a tautological ternary
 *   - a 0-byte sessionCheckpoints.json: must not count as "present"
 */
export function makeEdgeFixture(base) {
  const L = layout(path.join(base, "Edge"));
  fs.mkdirSync(L.torData, { recursive: true });
  fs.mkdirSync(L.profile, { recursive: true });

  write(path.join(L.browser, "tbb_version.json"),
    JSON.stringify({ version: "15.0.20", channel: "release" }));
  write(path.join(L.torData, "torrc"), [
    "UseBridges 1",
    "Bridge obfs2 1.1.1.1:80 AAA",
    "Bridge obfs2 2.2.2.2:80 BBB",
    "Bridge obfs3 3.3.3.3:80 CCC",
  ].join("\n") + "\n");
  write(path.join(L.torData, "state"), "LastWritten 2026-01-01 00:00:00\n");

  // stale cache: push mtime 200 days into the past
  const stale = path.join(L.torData, "cached-microdescs");
  fs.writeFileSync(stale, Buffer.alloc(1024));
  const old = new Date(Date.now() - 200 * 86400000);
  fs.utimesSync(stale, old, old);

  // 0-byte sessionCheckpoints: must not be reported as present
  fs.writeFileSync(path.join(L.profile, "sessionCheckpoints.json"), "");

  return L.root;
}

/* ------------------------------------------------ Firefox fixture */

/**
 * Directory layout of the Firefox fixture, in one place.
 *
 * The profile root is deliberately placed *inside a synthetic home* rather than directly
 * under `base`:
 *
 *   <base>/FFHome/AppData/Roaming/Mozilla/Firefox/    <- the profiles root (what is returned)
 *   <base>/FFHome/                                    <- HOME / USERPROFILE for the suite
 *   <base>/FFHome/AppData/Roaming/                    <- APPDATA for the suite
 *   <base>/FFProg/                                    <- a fake program directory
 *
 * Why: lib/firefox.mjs finds profiles through APPDATA and the home directory, and
 * lib/core.mjs calls discoverFirefoxProfiles() without an override. A suite that wants to
 * drive those machine-wide paths end to end must be able to repoint them, so the fixture has
 * to be shaped like a home directory that those paths can be pointed at -- otherwise the
 * suite would read the developer's real Firefox profiles and its result would depend on
 * whatever happens to be installed. Exported because the builder and the suite must agree on
 * the paths instead of each spelling them out (two spellings drift apart).
 */
export function firefoxFixtureDirs(base) {
  const home = path.join(base, "FFHome");
  const appdata = path.join(home, "AppData", "Roaming");
  return {
    home,
    appdata,
    root: path.join(appdata, "Mozilla", "Firefox"),
    prog: path.join(base, "FFProg"),
  };
}

/**
 * Firefox: one profile in use plus one abandoned leftover, and a profiles.ini whose two
 * default markers DISAGREE.
 *
 * What each part is for:
 *
 *   - profiles.ini carries both markers on purpose:
 *       [Install308046B0AF4A39CB] Default=Profiles/active.default-release   install marker
 *       [Profile1]                Default=1                                 legacy marker
 *     This is a regression case, not decoration. Real machines were observed carrying both,
 *     disagreeing: the legacy marker pointed at an empty leftover while the install marker
 *     pointed at the profile actually in use. The first implementation honoured only the
 *     legacy marker and therefore audited the empty leftover -- reporting a clean result for
 *     a profile nobody uses, which is worse than reporting nothing.
 *
 *   - the active profile holds residue of every kind, all files non-empty, including the
 *     0-byte trap in reverse: a 0-byte places.sqlite (in the leftover) must NOT be reported
 *     as retained history, because "present" means "has content".
 *
 *   - the leftover profile holds only times.json and a 0-byte places.sqlite, so it stays
 *     discoverable (isProfileDir accepts it) while being empty of everything that matters.
 *
 *   - FFProg is a fake program directory so the version path can be exercised without a real
 *     Firefox: application.ini reports 142.0, and compatibility.ini writes the same 142.0
 *     behind a build stamp ("142.0_<build>/<build>") so the version has to be cut at the
 *     underscore. Both sources agree on 142.0, which is what makes an assertion on "142.0"
 *     hold whichever one the code reads.
 *
 * @param {string} base
 * @returns {string} the Firefox profiles root
 */
export function makeFirefoxFixture(base) {
  const L = firefoxFixtureDirs(base);
  const active = path.join(L.root, "Profiles", "active.default-release");
  const leftover = path.join(L.root, "Profiles", "leftover.default");

  write(path.join(L.root, "profiles.ini"), [
    "[Install308046B0AF4A39CB]",
    "Default=Profiles/active.default-release",
    "Locked=1",
    "",
    "[Profile1]",
    "Name=leftover",
    "IsRelative=1",
    "Path=Profiles/leftover.default",
    "Default=1",
    "",
    "[Profile0]",
    "Name=active",
    "IsRelative=1",
    "Path=Profiles/active.default-release",
    "",
    "[General]",
    "StartWithLastProfile=1",
    "Version=2",
    "",
  ].join("\n"));

  /* ---- the profile in use: residue of every kind, all files non-empty ---- */

  fs.mkdirSync(active, { recursive: true });
  for (const name of [
    "places.sqlite", "cookies.sqlite", "favicons.sqlite", "permissions.sqlite",
    "formhistory.sqlite", "logins.json", "key4.db", "cert9.db",
  ]) {
    writeBytes(path.join(active, name), Buffer.alloc(2048, 0x41));
  }

  write(path.join(active, "times.json"),
    JSON.stringify({ firstUse: 1763730484848, created: 1763730471181 }));

  // LastVersion carries the build stamp the real format uses: the version is the part
  // before the underscore, what follows is the build ID.
  write(path.join(active, "compatibility.ini"),
    "[Compatibility]\nLastVersion=142.0_20250901123456/20250901123456\nLastPlatformDir=C:\\Program Files\\Mozilla Firefox\n");

  writeBytes(path.join(active, "sessionstore-backups", "recovery.jsonlz4"), Buffer.alloc(1024, 0x42));

  write(path.join(active, "datareporting", "state.json"),
    JSON.stringify({ clientID: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", sessionID: "s", enabled: true }));

  write(path.join(active, "extensions.json"),
    JSON.stringify({
      addons: [
        { id: "uBlock0@raymondhill.net", type: "extension", active: true, version: "1.0" },
        { id: "langpack-en-US@firefox.mozilla.org", type: "locale", active: true },
        { id: "old-addon@example.test", type: "extension", active: false },
      ],
    }));

  writeBytes(path.join(active, "storage", "default", "https+++example.com", "ls", "data.sqlite"),
    Buffer.alloc(512, 0x43));

  write(path.join(active, "prefs.js"), [
    'user_pref("network.proxy.type", 1);',
    'user_pref("network.proxy.http", "127.0.0.1");',
    'user_pref("network.proxy.socks", "127.0.0.1");',
    'user_pref("network.trr.mode", 2);',
    'user_pref("network.trr.uri", "https://dns.example/dns-query");',
    'user_pref("signon.rememberSignons", true);',
    'user_pref("services.sync.username", "someone@example.com");',
    'user_pref("datareporting.healthreport.uploadEnabled", true);',
    'user_pref("toolkit.telemetry.enabled", true);',
    'user_pref("browser.contentblocking.category", "strict");',
    'user_pref("privacy.resistFingerprinting", true);',
    'user_pref("network.cookie.cookieBehavior", 5);',
    'user_pref("privacy.sanitize.sanitizeOnShutdown", false);',
    'user_pref("browser.newtabpage.activity-stream.showSponsored", true);',
    'user_pref("extensions.pocket.enabled", true);',
    "",
  ].join("\n"));

  /* ---- the abandoned leftover: discoverable, but empty ---- */

  fs.mkdirSync(leftover, { recursive: true });
  writeBytes(path.join(leftover, "places.sqlite"), Buffer.alloc(0));
  write(path.join(leftover, "times.json"),
    JSON.stringify({ firstUse: 1600000000000, created: 1600000000000 }));

  /* ---- a fake program directory, so the version path needs no real Firefox ---- */

  write(path.join(L.prog, "application.ini"),
    "[App]\nVendor=Mozilla\nName=Firefox\nVersion=142.0\nBuildID=20250901123456\n");

  return L.root;
}

/** Build every fixture at once; returns { root, good, degraded, minimal, inconsistent, edge, firefoxRoot } */
export function buildAllFixtures(base) {
  fs.mkdirSync(base, { recursive: true });
  return {
    root: base,
    good: makeGoodFixture(base),
    degraded: makeDegradedFixture(base),
    minimal: makeMinimalFixture(base),
    inconsistent: makeInconsistentFixture(base),
    edge: makeEdgeFixture(base),
    firefoxRoot: makeFirefoxFixture(base),
  };
}
