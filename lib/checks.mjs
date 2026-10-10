/**
 * Aragami - check catalog
 *
 * The audit's check surface, declared as DATA rather than buried in the audit functions.
 *
 * WHY THIS EXISTS (and what it deliberately is not)
 * -------------------------------------------------
 * The idea is borrowed from signature-rule engines: the set of checks a tool performs should
 * be a reviewable, versionable artifact rather than something you can only learn by reading
 * control flow. What is borrowed is the IDEA. There is no rule language, no expression
 * evaluator, and no `eval`: a prose-and-policy table cannot be turned into an injection
 * surface the way a pattern language can, and the probes this tool needs are semantic
 * (parse a torrc, read a pref, classify a volume), not textual pattern matches.
 *
 * So each entry declares WHAT a check reads, HOW BAD it is allowed to report, and WHAT IT
 * DOES NOT COVER -- and names how it is produced:
 *
 *   kind: "bespoke"    a hand-written evaluator in lib/core.mjs or lib/firefox.mjs names this
 *                      id. The catalog constrains it but does not generate it.
 *   kind: "builtin"    the catalog fully determines the check: it names one of BUILTIN_PROBES,
 *                      and evaluateBuiltins() runs it. Adding another check of a shape that
 *                      already exists is therefore a data change and nothing else.
 *
 * `severities` is a CONTRACT, not an observation: it is the set of severities this check is
 * allowed to emit. An audit that emits something outside its set is reported as a
 * conformance violation rather than silently accepted, which is what makes the table
 * enforced rather than decorative.
 *
 * Every entry carries `does_not_cover`. The project's standing rule is that a boundary claim
 * which is false in its first line is worse than no claim at all, so each check states its
 * own limit rather than leaving it to the shared boundary notice.
 */

import { createHash } from "node:crypto";
import path from "node:path";
import { daysSince, fmtBytes } from "./shared.mjs";

export const CHECKS_SCHEMA = "aragami-checks/1";

/** Bumped when the catalog's wording changes; the structural digest is what baselines compare. */
export const CATALOG_VERSION = "1";

export const TARGETS = ["tor", "firefox"];

/** Probes the catalog can name and evaluateBuiltins() knows how to run. */
export const BUILTIN_PROBES = {
  VOLUME_ENCRYPTION: "volume-encryption",
  PATH_RESIDUE: "path-residue",
  DIR_ENTRIES: "dir-entries",
};

/* =====================================================================
 * The catalog
 *
 * Fields:
 *   id            stable identifier; findings carry it and baselines key on it
 *   layer         build | transport | crypto | metadata | endpoint
 *   targets       which target produces this check
 *   kind          "bespoke" | "builtin"
 *   severities    allowed severity set (the contract)
 *   observes      the static input it reads (one line)
 *   does_not_cover  its own boundary (one line)
 *   fact          optional dotted path: where its evidence lands in the facts record
 *   probe         builtin only: which BUILTIN_PROBES entry it runs
 *   probe_args    builtin only: the probe's own arguments (base, file, evidence shape, ...)
 *   title         builtin only: the finding title, as a template
 *   detail        builtin only: the finding detail, as a template
 *   detail_if_stale  builtin only: used instead of `detail` when the probe reports staleness
 *
 * Templates substitute `{name}`-style placeholders from a fixed set the probe provides
 * (name, size, age, count, path, mtime). An unknown placeholder is left visible rather than
 * blanked, so a typo shows up in the output instead of producing a silently empty sentence --
 * and the suite asserts that no entry leaves a placeholder unresolved.
 *
 * The prose for a built-in check lives HERE, not in the evaluator. That is the whole point of
 * the distinction: a built-in check's behaviour, wording and severity are all reviewable in one
 * table, and adding another check of a shape that already exists is a data change and nothing
 * else.
 * ===================================================================== */

export const CHECK_CATALOG = [
  /* ---------------------------------------------------------------- Tor: build */
  {
    id: "tb-version", layer: "build", targets: ["tor"], kind: "bespoke", severities: ["ok", "warn"],
    observes: "Browser/tbb_version.json and Browser/application.ini",
    does_not_cover: "Whether the installed build is authentic: a modified install can carry an unmodified version file.",
    fact: "build.tor_browser_version",
  },
  {
    id: "tor-version", layer: "build", targets: ["tor"], kind: "bespoke", severities: ["info"],
    observes: "the TorVersion line in the Data/Tor/state file",
    does_not_cover: "Whether tor.exe matches the version the state file claims; nothing here hashes a binary.",
    fact: "build.tor_version",
  },
  /* ---------------------------------------------------------------- Tor: transport */
  {
    id: "bridges", layer: "transport", targets: ["tor"], kind: "bespoke", severities: ["ok", "warn", "info"],
    observes: "UseBridges and Bridge lines across torrc-defaults merged with torrc",
    does_not_cover: "Whether any bridge is reachable: this tool never connects to one.",
    fact: "transport.bridges",
  },
  {
    id: "bridge-blend", layer: "transport", targets: ["tor"], kind: "bespoke", severities: ["ok"],
    observes: "torbrowser.settings.bridges.builtin_type and .source in prefs.js",
    does_not_cover: "Whether the built-in set is still distributed to new clients; that changes upstream, not here.",
    fact: "transport.bridge_builtin_type",
  },
  {
    id: "utls", layer: "transport", targets: ["tor"], kind: "bespoke", severities: ["ok"],
    observes: "utls-imitate= parameters on Bridge lines",
    does_not_cover: "Whether the impersonated fingerprint still matches the current real browser.",
    fact: "transport.utls",
  },
  {
    id: "fronting", layer: "transport", targets: ["tor"], kind: "bespoke", severities: ["ok"],
    observes: "fronts= parameters on Bridge lines",
    does_not_cover: "Whether the fronting domain still permits it; CDN policy can withdraw that at any time.",
    fact: "transport.fronts",
  },
  {
    id: "pt-list", layer: "transport", targets: ["tor"], kind: "bespoke", severities: ["info"],
    observes: "ClientTransportPlugin lines",
    does_not_cover: "Which of the loaded transports is actually in use; loaded is not enabled.",
    fact: "transport.plugins",
  },
  {
    id: "deprecated-pt", layer: "transport", targets: ["tor"], kind: "bespoke", severities: ["warn"],
    observes: "the set of bridge types in use against the known-obsolete list",
    does_not_cover: "Whether a non-obsolete type is genuinely effective today; that is a research question, not a config fact.",
    fact: "transport.deprecated_pt",
  },
  {
    id: "quickstart", layer: "transport", targets: ["tor"], kind: "bespoke", severities: ["info"],
    observes: "torbrowser.settings.quickstart.enabled in prefs.js",
    does_not_cover: "Whether connect-on-launch actually correlates with anything: this reports the setting, not a traffic pattern.",
    fact: "transport.quickstart",
  },
  /* ---------------------------------------------------------------- Tor: crypto */
  {
    id: "onion-auth-configured", layer: "crypto", targets: ["tor"], kind: "bespoke", severities: ["ok"],
    observes: "ClientOnionAuthDir and the *.auth_private files inside it",
    does_not_cover: "Whether the corresponding service still exists or still trusts these keys.",
    fact: "crypto.client_auth_dir",
  },
  {
    id: "onion-auth-empty", layer: "crypto", targets: ["tor"], kind: "bespoke", severities: ["info"],
    observes: "the count of *.auth_private files in ClientOnionAuthDir",
    does_not_cover: "Why the directory is empty; an unused mechanism and a broken one look identical here.",
    fact: "crypto.client_auth_keys",
  },
  {
    id: "onion-auth-keys", layer: "crypto", targets: ["tor"], kind: "bespoke", severities: ["info"],
    observes: "the names of the *.auth_private files present",
    does_not_cover: "Whether these keys are still needed; unused key material is still key material.",
    fact: "crypto.client_auth_key_names",
  },
  {
    id: "onion-auth-absent", layer: "crypto", targets: ["tor"], kind: "bespoke", severities: ["info"],
    observes: "the absence of ClientOnionAuthDir from the effective configuration",
    does_not_cover: "Whether the caller needs conditional reachability at all.",
  },
  {
    id: "hs-keys", layer: "crypto", targets: ["tor"], kind: "bespoke", severities: ["warn"],
    observes: "the Data/Tor/keys directory",
    does_not_cover: "Whether the hosted service is still published, or whether these keys are still valid.",
    fact: "crypto.hs_keys",
  },
  /* ---------------------------------------------------------------- Tor: metadata */
  {
    id: "state-file", layer: "metadata", targets: ["tor"], kind: "bespoke", severities: ["warn"],
    observes: "size and LastWritten of Data/Tor/state",
    does_not_cover: "What the guard and bridge records actually refer to; the audit deliberately does not resolve them.",
    fact: "metadata.state",
  },
  {
    id: "state-no-guards", layer: "metadata", targets: ["tor"], kind: "bespoke", severities: ["info", "warn"],
    observes: "the guard and CircuitBuildTimeBin line counts in the state file",
    does_not_cover: "Whether circuits ever built successfully; absence of guard records is not proof of absence of use.",
    fact: "metadata.state_guard_absence",
  },
  {
    id: "state-guards", layer: "metadata", targets: ["tor"], kind: "bespoke", severities: ["warn"],
    observes: "Guard in= / EntryGuard lines and their guard sets in the state file",
    does_not_cover: "Whether those guards were ever actually used for traffic.",
    fact: "metadata.state_guards",
  },
  {
    id: "cache-cached-descriptors", layer: "metadata", targets: ["tor"], kind: "builtin", severities: ["info"],
    probe: BUILTIN_PROBES.PATH_RESIDUE,
    probe_args: { base: "data_dir", file: "cached-descriptors", evidence: "cache", min_size: 1, stale_days: 90 },
    title: "Descriptor cache {name}: {size} (updated {age} day(s) ago)",
    detail: "Updated recently, so it has genuinely been in use. It does not identify you directly, but combined with state and timestamps it outlines a usage pattern.",
    detail_if_stale: "Not updated for a long time - this install has been idle. Idle residue is still a forensic asset: It does not identify you directly, but combined with state and timestamps it outlines a usage pattern.",
    observes: "presence, size and age of Data/Tor/cached-descriptors",
    does_not_cover: "Whether the cached relays were ever contacted; a cache proves contact with the directory authorities, not with a peer.",
    fact: "metadata.caches.descriptors",
  },
  {
    id: "cache-cached-microdescs", layer: "metadata", targets: ["tor"], kind: "builtin", severities: ["info"],
    probe: BUILTIN_PROBES.PATH_RESIDUE,
    probe_args: { base: "data_dir", file: "cached-microdescs", evidence: "cache", min_size: 1, stale_days: 90 },
    title: "Descriptor cache {name}: {size} (updated {age} day(s) ago)",
    detail: "Updated recently, so it has genuinely been in use. It does not identify you directly, but combined with state and timestamps it outlines a usage pattern.",
    detail_if_stale: "Not updated for a long time - this install has been idle. Idle residue is still a forensic asset: It does not identify you directly, but combined with state and timestamps it outlines a usage pattern.",
    observes: "presence, size and age of Data/Tor/cached-microdescs",
    does_not_cover: "Same limit as the other descriptor caches: contact with authorities, not with peers.",
    fact: "metadata.caches.microdescs",
  },
  {
    id: "cache-cached-microdescs.new", layer: "metadata", targets: ["tor"], kind: "builtin", severities: ["info"],
    probe: BUILTIN_PROBES.PATH_RESIDUE,
    probe_args: { base: "data_dir", file: "cached-microdescs.new", evidence: "cache", min_size: 1, stale_days: 90 },
    title: "Descriptor cache {name}: {size} (updated {age} day(s) ago)",
    detail: "Updated recently, so it has genuinely been in use. It does not identify you directly, but combined with state and timestamps it outlines a usage pattern.",
    detail_if_stale: "Not updated for a long time - this install has been idle. Idle residue is still a forensic asset: It does not identify you directly, but combined with state and timestamps it outlines a usage pattern.",
    observes: "presence, size and age of Data/Tor/cached-microdescs.new",
    does_not_cover: "Same limit as the other descriptor caches: contact with authorities, not with peers.",
    fact: "metadata.caches.microdescs_new",
  },
  {
    id: "cache-cached-certs", layer: "metadata", targets: ["tor"], kind: "builtin", severities: ["info"],
    probe: BUILTIN_PROBES.PATH_RESIDUE,
    probe_args: { base: "data_dir", file: "cached-certs", evidence: "cache", min_size: 1, stale_days: 90 },
    title: "Descriptor cache {name}: {size} (updated {age} day(s) ago)",
    detail: "Updated recently, so it has genuinely been in use. It does not identify you directly, but combined with state and timestamps it outlines a usage pattern.",
    detail_if_stale: "Not updated for a long time - this install has been idle. Idle residue is still a forensic asset: It does not identify you directly, but combined with state and timestamps it outlines a usage pattern.",
    observes: "presence, size and age of Data/Tor/cached-certs",
    does_not_cover: "Nothing here is identifying on its own; it dates directory-authority contact only.",
    fact: "metadata.caches.certs",
  },
  {
    id: "cache-cached-consensus", layer: "metadata", targets: ["tor"], kind: "builtin", severities: ["info"],
    probe: BUILTIN_PROBES.PATH_RESIDUE,
    probe_args: { base: "data_dir", file: "cached-consensus", evidence: "cache", min_size: 1, stale_days: 90 },
    title: "Descriptor cache {name}: {size} (updated {age} day(s) ago)",
    detail: "Updated recently, so it has genuinely been in use. It does not identify you directly, but combined with state and timestamps it outlines a usage pattern.",
    detail_if_stale: "Not updated for a long time - this install has been idle. Idle residue is still a forensic asset: It does not identify you directly, but combined with state and timestamps it outlines a usage pattern.",
    observes: "presence, size and age of Data/Tor/cached-consensus",
    does_not_cover: "A consensus snapshot is public data; its presence dates activity rather than revealing a destination.",
    fact: "metadata.caches.consensus",
  },
  {
    id: "pt-state", layer: "metadata", targets: ["tor"], kind: "builtin", severities: ["info"],
    probe: BUILTIN_PROBES.DIR_ENTRIES,
    probe_args: { base: "data_dir", file: "pt_state", max_names: 10 },
    title: "pt_state retains {count} file(s)",
    detail: "State residue from pluggable transports (bridge/endpoint caches).",
    observes: "the file count under Data/Tor/pt_state",
    does_not_cover: "What the transport state contains; this reports residue, not its meaning.",
    fact: "metadata.pt_state",
  },
  {
    id: "profile-times", layer: "metadata", targets: ["tor"], kind: "bespoke", severities: ["warn"],
    observes: "firstUse / created in the browser profile's times.json",
    does_not_cover: "Whether the recorded time is the true first use; a copied profile carries the original timestamp.",
    fact: "metadata.profile_times",
  },
  {
    id: "session-checkpoints", layer: "metadata", targets: ["tor"], kind: "builtin", severities: ["info"],
    probe: BUILTIN_PROBES.PATH_RESIDUE,
    probe_args: { base: "profile_dir", file: "sessionCheckpoints.json", evidence: "size-mtime", min_size: 1 },
    title: "Session checkpoints present (sessionCheckpoints.json)",
    detail: "Window/tab restore state. If you used it for anything sensitive, this file may indirectly reflect what kinds of targets you visited.",
    observes: "presence and size of sessionCheckpoints.json in the profile",
    does_not_cover: "What the restored tabs were; the audit reads the file's existence, never its contents.",
    fact: "metadata.session_checkpoints",
  },
  {
    id: "places", layer: "metadata", targets: ["tor"], kind: "builtin", severities: ["warn"],
    probe: BUILTIN_PROBES.PATH_RESIDUE,
    probe_args: { base: "profile_dir", file: "places.sqlite", evidence: "size-mtime", min_size: 1 },
    title: "Browsing history database present (places.sqlite, {size})",
    detail: "Tor Browser clears this on exit by default, so its presence means either it never exited cleanly or the cleanup did not take effect. Confirm by hand.",
    observes: "presence and size of places.sqlite in the profile",
    does_not_cover: "Whether the database still holds rows: an allocated but empty database looks the same as a populated one from the outside.",
    fact: "metadata.places",
  },
  /* ---------------------------------------------------------------- Tor: endpoint */
  {
    id: "disk-location", layer: "endpoint", targets: ["tor"], kind: "bespoke", severities: ["ok", "info"],
    observes: "the drive letter of the install root against SystemDrive",
    does_not_cover: "Whether that drive is encrypted or removable; see disk-encryption.",
    fact: "endpoint.disk_location",
  },
  {
    id: "no-stray-traces", layer: "endpoint", targets: ["tor"], kind: "bespoke", severities: ["ok"],
    observes: "six named locations under the user profile and the temp directory",
    does_not_cover: "Copies anywhere else on the machine: this is a fixed list, not a filesystem-wide search.",
  },
  {
    id: "stray-traces", layer: "endpoint", targets: ["tor"], kind: "bespoke", severities: ["warn"],
    observes: "six named locations under the user profile and the temp directory",
    does_not_cover: "Copies anywhere else on the machine: this is a fixed list, not a filesystem-wide search.",
    fact: "endpoint.stray_traces",
  },
  {
    id: "persistence", layer: "endpoint", targets: ["tor"], kind: "bespoke", severities: ["info"],
    observes: "nothing on disk; it restates that this install design is persistent",
    does_not_cover: "Whether persistence is acceptable for the caller's threat model. Only an amnesic environment changes it.",
    fact: "endpoint.persistence",
  },
  {
    id: "disk-encryption", layer: "endpoint", targets: ["tor", "firefox"], kind: "builtin",
    severities: ["ok", "info", "warn"], probe: BUILTIN_PROBES.VOLUME_ENCRYPTION,
    observes: "the mount table (Linux) or the filesystem type reported for the volume root (other platforms)",
    does_not_cover:
      "On Windows a static audit cannot read BitLocker state at all without elevation, so undetermined is reported rather than a guess; " +
      "elsewhere a whole-disk container that has already been unlocked is indistinguishable from an unencrypted volume.",
    fact: "endpoint.volume_encryption",
  },

  /* ---------------------------------------------------------------- Firefox */
  {
    id: "ff-version", layer: "build", targets: ["firefox"], kind: "bespoke", severities: ["info", "warn"],
    observes: "application.ini of the installed Firefox, falling back to compatibility.ini in the profile",
    does_not_cover: "Whether that build is authentic or current; see aragami_version for freshness.",
    fact: "build.firefox_version",
  },
  {
    id: "ff-proxy", layer: "transport", targets: ["firefox"], kind: "bespoke", severities: ["info"],
    observes: "network.proxy.type and the manual proxy prefs",
    does_not_cover: "How traffic is actually routed; other applications on the machine are unaffected by a browser proxy.",
    fact: "transport.proxy_mode",
  },
  {
    id: "ff-doh", layer: "transport", targets: ["firefox"], kind: "bespoke", severities: ["ok", "info"],
    observes: "network.trr.mode",
    does_not_cover: "Whether the chosen DoH provider is trustworthy; it sees every lookup.",
    fact: "transport.doh_mode",
  },
  {
    id: "ff-content-blocking", layer: "transport", targets: ["firefox"], kind: "bespoke", severities: ["ok", "info"],
    observes: "browser.contentblocking.category and tracking protection prefs",
    does_not_cover: "What a given site actually serves; blocking is not isolation.",
    fact: "transport.content_blocking",
  },
  {
    id: "ff-rfp", layer: "transport", targets: ["firefox"], kind: "bespoke", severities: ["ok", "info"],
    observes: "privacy.resistFingerprinting",
    does_not_cover: "Whether the resulting fingerprint blends in; enabling it is itself a deviation from the default population.",
    fact: "transport.resist_fingerprinting",
  },
  {
    id: "ff-cookie-behavior", layer: "transport", targets: ["firefox"], kind: "bespoke", severities: ["ok", "info"],
    observes: "network.cookie.cookieBehavior",
    does_not_cover: "First-party tracking, which no cookie policy addresses.",
    fact: "transport.cookie_behavior",
  },
  {
    id: "ff-logins", layer: "crypto", targets: ["firefox"], kind: "builtin", severities: ["warn"],
    probe: BUILTIN_PROBES.PATH_RESIDUE,
    probe_args: { base: "profile_dir", file: "logins.json", evidence: "path-age", min_size: 1 },
    title: "Saved passwords database present ({size}, written {age} day(s) ago)",
    detail: "logins.json holds the encrypted entry set for saved logins, with key4.db beside it. This is the highest-value file in a Firefox profile: whoever obtains the profile directory and the primary password (or cracks a weak one) obtains every saved credential. If this profile was ever used for anything that matters, treat those credentials as disclosed unless a strong primary password is set.",
    observes: "presence, size and age of logins.json",
    does_not_cover: "Whether a primary password is set; prefs.js does not record that, so the file's strength is not determinable here.",
    fact: "crypto.saved_logins",
  },
  {
    id: "ff-keys", layer: "crypto", targets: ["firefox"], kind: "builtin", severities: ["info"],
    probe: BUILTIN_PROBES.PATH_RESIDUE,
    probe_args: { base: "profile_dir", file: "key4.db", evidence: "path-age", min_size: 1 },
    title: "Firefox key material present ({size}, written {age} day(s) ago)",
    detail: "key4.db is the NSS key database that protects saved logins and client certificates.",
    observes: "presence, size and age of key4.db",
    does_not_cover: "The strength of the primary password protecting it.",
    fact: "crypto.key_db",
  },
  {
    id: "ff-certs", layer: "crypto", targets: ["firefox"], kind: "builtin", severities: ["info"],
    probe: BUILTIN_PROBES.PATH_RESIDUE,
    probe_args: { base: "profile_dir", file: "cert9.db", evidence: "path-age", min_size: 1 },
    title: "Client certificate store present ({size}, written {age} day(s) ago)",
    detail: "cert9.db can hold client certificates used to authenticate to services. Their presence is itself an identifier of which services this profile talks to.",
    observes: "presence, size and age of cert9.db",
    does_not_cover: "Which services the certificates authenticate to; only their existence is read.",
    fact: "crypto.cert_db",
  },
  {
    id: "ff-primary-password", layer: "crypto", targets: ["firefox"], kind: "bespoke", severities: ["warn", "ok"],
    observes: "signon.rememberSignons",
    does_not_cover: "Whether a primary password is actually set: this preference does not record it.",
    fact: "crypto.password_saving",
  },
  {
    id: "ff-history", layer: "metadata", targets: ["firefox"], kind: "builtin", severities: ["info"],
    probe: BUILTIN_PROBES.PATH_RESIDUE,
    probe_args: { base: "profile_dir", file: "places.sqlite", evidence: "path-age", min_size: 1 },
    title: "Browsing history and bookmarks database present ({size}, written {age} day(s) ago)",
    detail: "Firefox keeps history here by design, so its presence is expected rather than a misconfiguration. It still records what this profile has visited, and it is the first file examined if the machine is taken.",
    observes: "presence, size and age of places.sqlite",
    does_not_cover: "Which sites were visited; the audit reads file metadata, never the database contents.",
    fact: "metadata.history",
  },
  {
    id: "ff-cookies", layer: "metadata", targets: ["firefox"], kind: "builtin", severities: ["info"],
    probe: BUILTIN_PROBES.PATH_RESIDUE,
    probe_args: { base: "profile_dir", file: "cookies.sqlite", evidence: "path-age", min_size: 1 },
    title: "Cookie database present ({size}, written {age} day(s) ago)",
    detail: "Persistent session cookies. For a signed-in profile these can be replayed to impersonate the session without the password.",
    observes: "presence, size and age of cookies.sqlite",
    does_not_cover: "Which sessions are live; a cookie database is replayable regardless of the sites' own expiry policy.",
    fact: "metadata.cookies",
  },
  {
    id: "ff-permissions", layer: "metadata", targets: ["firefox"], kind: "builtin", severities: ["info"],
    probe: BUILTIN_PROBES.PATH_RESIDUE,
    probe_args: { base: "profile_dir", file: "permissions.sqlite", evidence: "path-age", min_size: 1 },
    title: "Per-site permission grants present ({size}, written {age} day(s) ago)",
    detail: "Records which sites were granted camera, microphone, geolocation, notifications and so on. The list reveals which services this profile actually uses.",
    observes: "presence, size and age of permissions.sqlite",
    does_not_cover: "Which grants are still meaningful; only the file's existence and size are read.",
    fact: "metadata.permissions",
  },
  {
    id: "ff-formhistory", layer: "metadata", targets: ["firefox"], kind: "builtin", severities: ["info"],
    probe: BUILTIN_PROBES.PATH_RESIDUE,
    probe_args: { base: "profile_dir", file: "formhistory.sqlite", evidence: "path-age", min_size: 1 },
    title: "Form history present ({size}, written {age} day(s) ago)",
    detail: "Previously typed form values, including anything entered into a field that was not marked as a password field.",
    observes: "presence, size and age of formhistory.sqlite",
    does_not_cover: "What was typed; the audit does not read form values.",
    fact: "metadata.formhistory",
  },
  {
    id: "ff-favicons", layer: "metadata", targets: ["firefox"], kind: "builtin", severities: ["info"],
    probe: BUILTIN_PROBES.PATH_RESIDUE,
    probe_args: { base: "profile_dir", file: "favicons.sqlite", evidence: "path-age", min_size: 1 },
    title: "Favicon cache present ({size}, written {age} day(s) ago)",
    detail: "Small, but it survives history clearing and is a recognisable list of visited sites.",
    observes: "presence, size and age of favicons.sqlite",
    does_not_cover: "Which sites the icons belong to; the file is treated as residue only.",
    fact: "metadata.favicons",
  },
  {
    id: "ff-site-data", layer: "metadata", targets: ["firefox"], kind: "bespoke", severities: ["info"],
    observes: "the total size of storage/default",
    does_not_cover: "Which origins own that storage; clearing history does not clear it, which is the point being made.",
    fact: "metadata.site_data",
  },
  {
    id: "ff-times", layer: "metadata", targets: ["firefox"], kind: "bespoke", severities: ["info"],
    observes: "firstUse / created in times.json",
    does_not_cover: "Whether the timestamp is the true first use; a copied profile carries the original value.",
    fact: "metadata.firefox_profile_times",
  },
  {
    id: "ff-session", layer: "metadata", targets: ["firefox"], kind: "bespoke", severities: ["info"],
    observes: "the count of sessionstore files and the newest mtime",
    does_not_cover: "What the restored tabs were; only the file set is read.",
    fact: "metadata.session_store",
  },
  {
    id: "ff-telemetry", layer: "metadata", targets: ["firefox"], kind: "bespoke", severities: ["warn", "info"],
    observes: "datareporting/state.json for a client ID",
    does_not_cover: "Whether that ID has ever been transmitted; the audit sees the local record only.",
    fact: "metadata.telemetry_client_id",
  },
  {
    id: "ff-sync", layer: "metadata", targets: ["firefox"], kind: "bespoke", severities: ["warn"],
    observes: "signedInUser.json, prefs.js sync username, and the account root",
    does_not_cover: "What the account is; the linkage is reported, the identity is not resolved.",
    fact: "metadata.sync_linked",
  },
  {
    id: "ff-extensions", layer: "metadata", targets: ["firefox"], kind: "bespoke", severities: ["info"],
    observes: "extensions.json for active extensions",
    does_not_cover: "What an extension does with its access; installing is trusting.",
    fact: "metadata.active_extensions",
  },
  {
    id: "ff-telemetry-prefs", layer: "metadata", targets: ["firefox"], kind: "bespoke", severities: ["ok", "info"],
    observes: "toolkit.telemetry.enabled and datareporting.healthreport.uploadEnabled",
    does_not_cover: "How these prefs interact in the caller's specific build; Mozilla has changed that more than once.",
    fact: "metadata.telemetry_upload_disabled",
  },
  {
    id: "ff-sponsored", layer: "metadata", targets: ["firefox"], kind: "bespoke", severities: ["info", "ok"],
    observes: "the sponsored-content and Pocket prefs",
    does_not_cover: "Whether any such content was ever shown or clicked.",
    fact: "metadata.sponsored_enabled",
  },
  {
    id: "ff-profile-location", layer: "endpoint", targets: ["firefox"], kind: "bespoke", severities: ["info"],
    observes: "the drive letter of the profile directory against SystemDrive",
    does_not_cover: "Whether that drive is encrypted or removable; see disk-encryption.",
    fact: "endpoint.firefox_profile_location",
  },
  {
    id: "ff-persistence", layer: "endpoint", targets: ["firefox"], kind: "bespoke", severities: ["info"],
    observes: "nothing on disk; it restates that a profile directory is persistent",
    does_not_cover: "Whether persistence matters for the caller's threat model.",
    fact: "endpoint.firefox_persistence",
  },
  {
    id: "ff-profile-count", layer: "endpoint", targets: ["firefox"], kind: "bespoke", severities: ["warn"],
    observes: "the number of discovered Firefox profiles",
    does_not_cover: "Whether the other profiles are in use or stale; only their existence is counted.",
    fact: "endpoint.profile_count",
  },
  {
    id: "ff-sanitize", layer: "endpoint", targets: ["firefox"], kind: "bespoke", severities: ["ok", "info"],
    observes: "privacy.clearOnShutdown.* prefs and the sanitize flag",
    does_not_cover: "What happens on a hard kill; an unclean exit skips shutdown clearing entirely.",
    fact: "endpoint.clear_on_shutdown",
  },
];

/* ------------------------------------------------ lookup */

const BY_ID = new Map(CHECK_CATALOG.map((c) => [c.id, c]));

/** One catalog entry by id, or null. */
export function checkById(id) {
  return BY_ID.get(id) ?? null;
}

/**
 * The declared surface, optionally narrowed by target and layer.
 * Unknown filters are reported as `unmatched` rather than silently returning nothing.
 */
export function checksFor({ target, layer } = {}) {
  const wantTarget = typeof target === "string" && target !== "auto" ? target : null;
  const wantLayer = typeof layer === "string" && layer !== "all" ? layer : null;
  const out = CHECK_CATALOG.filter(
    (c) => (!wantTarget || c.targets.includes(wantTarget)) && (!wantLayer || c.layer === wantLayer)
  );
  return {
    total: CHECK_CATALOG.length,
    matched: out.length,
    target: wantTarget,
    layer: wantLayer,
    checks: out,
  };
}

/**
 * Structural digest: ids, layers, targets, kinds, severity contracts and fact paths --
 * deliberately NOT the prose. Baselines record this so that editing a description does not
 * invalidate a stored baseline, while adding, removing or re-scoping a check does.
 */
export function catalogDigest() {
  const structural = CHECK_CATALOG.map((c) => ({
    id: c.id,
    layer: c.layer,
    targets: [...c.targets].sort(),
    kind: c.kind,
    severities: [...c.severities].sort(),
    fact: c.fact ?? null,
    probe: c.probe ?? null,
  }));
  structural.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return createHash("sha256").update(JSON.stringify(structural)).digest("hex").slice(0, 16);
}

/* ------------------------------------------------ conformance */

/**
 * Check the findings a run produced against the catalog.
 *
 * `unknown` and `severity_violations` mean the code and the catalog disagree, which is a
 * defect in this repository rather than in the audited machine. `unfired` is informational:
 * a check that did not fire is normal (its subject was absent), and it is reported so that a
 * check which can never fire is at least visible.
 */
export function validateFindings(findings, { target } = {}) {
  const list = Array.isArray(findings) ? findings : [];
  const unknown = [];
  const severity_violations = [];
  const fired = new Set();

  for (const f of list) {
    const id = f?.id;
    fired.add(id);
    const entry = BY_ID.get(id);
    if (!entry) { unknown.push(id); continue; }
    if (target && !entry.targets.includes(target)) {
      unknown.push(id);
      continue;
    }
    if (!entry.severities.includes(f.severity)) {
      severity_violations.push({ id, severity: f.severity, allowed: entry.severities });
    }
  }

  const applicable = target ? CHECK_CATALOG.filter((c) => c.targets.includes(target)) : CHECK_CATALOG;
  // Families registered once per member are listed by their own id, so a plain set difference
  // is enough; nothing here needs to know that cache-* share a loop.
  const unfired = applicable.filter((c) => !fired.has(c.id)).map((c) => c.id);

  return {
    checked: list.length,
    unknown: [...new Set(unknown)].sort(),
    severity_violations,
    unfired,
    conformant: unknown.length === 0 && severity_violations.length === 0,
  };
}

/* ------------------------------------------------ facts */

const setPath = (obj, dotted, value) => {
  const parts = dotted.split(".");
  let cur = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    if (typeof cur[parts[i]] !== "object" || cur[parts[i]] === null) cur[parts[i]] = {};
    cur = cur[parts[i]];
  }
  cur[parts[parts.length - 1]] = value;
};

/**
 * Build the judgement-free fact record out of the evidence of the checks that fired.
 *
 * This is the "observed facts" surface: what the audit READ, as opposed to what it CONCLUDED.
 * Findings carry severity and opinion; facts carry neither, which is what makes the record
 * safe to compare, store, or query.
 *
 * A declared `fact` path names a SLOT, and the value placed in it is the check's whole
 * evidence object -- nothing is cherry-picked and nothing is synthesised, so every value in
 * the record can be traced straight back to the check that read it. The path is therefore a
 * stable schema name rather than a field path into the evidence.
 *
 * Each path is owned by exactly one check (asserted by the catalog tests). That is what makes
 * the record order-independent: with a shared path, whichever check happened to be evaluated
 * last would silently win.
 *
 * `layer` narrows the record the same way it narrows findings.
 */
export function factsFrom(findings, { layer } = {}) {
  const wantLayer = typeof layer === "string" && layer !== "all" ? layer : null;
  const facts = {};
  const sources = {};
  for (const f of Array.isArray(findings) ? findings : []) {
    const entry = BY_ID.get(f?.id);
    if (!entry?.fact) continue;
    if (wantLayer && f.layer !== wantLayer) continue;
    if (f.evidence === undefined) continue;
    setPath(facts, entry.fact, f.evidence);
    sources[entry.fact] = f.id;
  }
  return { facts, sources };
}

/**
 * Declared fact paths, so a test can prove no two checks own the same slot (a silent
 * overwrite would make the record depend on evaluation order).
 */
export function declaredFactPaths() {
  return CHECK_CATALOG.filter((c) => c.fact).map((c) => ({ id: c.id, fact: c.fact }));
}

/* =====================================================================
 * Built-in probes
 * ===================================================================== */

/**
 * Filesystem magics that PROVE a volume cannot carry whole-disk encryption: a FAT/exFAT
 * volume has no room for the container metadata such an encryption scheme needs.
 * Reported by statfs on POSIX; libuv leaves the field at 0 on Windows, which is why the
 * Windows path reports undetermined instead of guessing.
 */
export const VOLUME_MAGICS = {
  0x4d44: "FAT",
  0x2011bab0: "exFAT",
};

const PLAIN_BLOCK_DEVICE = /^\/dev\/(sd|hd|vd|nvme\d+n\d+|mmcblk\d+|xvd)/;
const MAPPED_DEVICE = /^\/dev\/(mapper|dm-)/;

/**
 * Classify whether the volume holding `root` is encrypted at rest.
 *
 * PURE on purpose: every input is passed in, so each branch is reachable from a test without
 * needing the matching platform. The caller does the reading.
 *
 * @param {{platform?:string, root?:string, mountInfo?:string|null, statfsType?:number|null}} input
 * @returns {{state:string, reason:string, detail:string, evidence:object}}
 */
export function classifyVolumeEncryption(input = {}) {
  const platform = input.platform ?? process.platform;
  const root = input.root ?? null;
  // An empty string means "the table was read and was empty"; null means "it could not be
  // read at all". Collapsing the two lets a missing mount table fall through to a positive
  // claim about the device, which is the one direction this must never guess in.
  const hasMountTable = typeof input.mountInfo === "string";
  const mountInfo = hasMountTable ? input.mountInfo : null;
  const statfsType = typeof input.statfsType === "number" && Number.isFinite(input.statfsType)
    ? input.statfsType : null;

  const evidence = { platform, root, signal: null, device: null, fs_type: null };

  if (hasMountTable) {
    const hit = longestMount(mountInfo, root);
    if (hit) {
      evidence.signal = "mount-table";
      evidence.device = hit.device;
      evidence.fs_type = hit.fsType;
      if (hit.fsType && /^crypto_/i.test(hit.fsType)) {
        return {
          state: "encrypted", reason: "crypto-filesystem",
          detail: `The mount table reports ${hit.device} as ${hit.fsType}, so this volume is encrypted at rest. Note that it is unlocked for as long as the machine is running, which is exactly when an audit can see it.`,
          evidence,
        };
      }
      if (MAPPED_DEVICE.test(hit.device)) {
        return {
          state: "encrypted", reason: "device-mapper",
          detail: `${hit.device} is a device-mapper target rather than a plain partition, which is the usual shape of an unlocked whole-disk container. The audit cannot tell which cipher or key is behind it.`,
          evidence,
        };
      }
      if (PLAIN_BLOCK_DEVICE.test(hit.device)) {
        return {
          state: "not-encrypted", reason: "plain-block-device",
          detail: `${hit.device} is a plain block device mounted directly as ${hit.fsType || "a filesystem"}. A filesystem mounted straight off a partition has no whole-disk layer underneath it, so this residue is readable by anyone who takes the disk.`,
          evidence,
        };
      }
      return {
        state: "undetermined", reason: "unrecognised-device",
        detail: `The mount table maps ${root} to ${hit.device} (${hit.fsType || "type unknown"}), which is neither a plain partition nor a mapped device. This audit does not guess.`,
        evidence,
      };
    }
    evidence.signal = "mount-table";
    return {
      state: "undetermined", reason: "no-mount-entry",
      detail: `No mount entry covers ${root ?? "the audit root"}; the volume backing it could not be identified from the mount table.`,
      evidence,
    };
  }

  if (statfsType !== null && VOLUME_MAGICS[statfsType]) {
    evidence.signal = "filesystem-magic";
    evidence.fs_type = VOLUME_MAGICS[statfsType];
    return {
      state: "not-encrypted", reason: "unencryptable-filesystem",
      detail: `The volume reports as ${VOLUME_MAGICS[statfsType]}. A ${VOLUME_MAGICS[statfsType]} filesystem cannot carry a whole-disk encryption container, so this residue is readable by anyone who takes the disk.`,
      evidence,
    };
  }

  if (platform === "win32") {
    evidence.signal = "none";
    return {
      state: "undetermined", reason: "windows-requires-elevation",
      detail:
        "On Windows the encryption state of a volume is not readable by a static, unprivileged audit: it lives behind BitLocker's WMI provider, " +
        "and this tool reads files without spawning anything. Run manage-bde -status from an elevated prompt to answer it by hand. " +
        "This is reported as undetermined rather than assumed to be fine.",
      evidence,
    };
  }

  evidence.signal = statfsType === null ? "none" : "filesystem-magic";
  evidence.fs_type = statfsType === null ? null : `unknown magic 0x${statfsType.toString(16)}`;
  return {
    state: "undetermined", reason: "no-signal",
    detail:
      `No usable signal for ${root ?? "the audit root"}: the filesystem type is ${evidence.fs_type ?? "unavailable"} and no mount entry was supplied. ` +
      "An unlocked container and an unencrypted volume look identical from here.",
    evidence,
  };
}

/**
 * Find the mount entry whose mount point is the longest prefix of `root`.
 * Longest-prefix matters: /home and / are both prefixes of /home/u, and picking the wrong one
 * reports the wrong device.
 */
function longestMount(mountInfo, root) {
  if (!root) return null;
  const norm = (p) => (p.length > 1 ? p.replace(/\/+$/, "") : p);
  const target = norm(root.replace(/\\/g, "/"));
  let best = null;
  for (const line of mountInfo.split("\n")) {
    // mountinfo: id parent major:minor root mountpoint options... - fstype source superopts
    const f = line.trim().split(/\s+/);
    if (f.length < 10) continue;
    const sep = f.indexOf("-");
    if (sep < 0 || sep + 2 >= f.length) continue;
    const mp = norm(f[4].replace(/\\040/g, " "));
    if (target !== mp && !target.startsWith(mp === "/" ? "/" : `${mp}/`)) continue;
    if (!best || mp.length > best.mountPoint.length) {
      best = { mountPoint: mp, fsType: f[sep + 1], device: f[sep + 2] };
    }
  }
  return best;
}

/** Exported for the catalog tests: which probe names the catalog actually references. */
export function declaredProbes() {
  return [...new Set(CHECK_CATALOG.filter((c) => c.probe).map((c) => c.probe))].sort();
}

/** Substitute `{name}`-style placeholders. Unknown keys are left visible on purpose. */
export function renderTemplate(text, vars) {
  return String(text).replace(/\{([a-z_]+)\}/g, (whole, key) =>
    Object.prototype.hasOwnProperty.call(vars, key) ? String(vars[key]) : whole);
}

/**
 * Evidence shapes.
 *
 * Three exist because three exist in the audited output already, and a refactor that also
 * changed what the tool reports would be two changes wearing one coat -- the suites could no
 * longer be read as proof that the migration itself was faithful. Unifying them is a separate
 * decision with its own reasoning, not a side effect of this one.
 */
const EVIDENCE = {
  "size-mtime": (r) => ({ size: r.size, mtime: r.mtimeIso }),
  "path-age": (r) => ({ path: r.rel, size: r.size, mtime: r.mtimeIso, age_days: r.age }),
  cache: (r) => ({ size: r.size, mtime: r.mtimeIso, age_days: r.age, stale: r.stale }),
};

/**
 * Run one catalog entry against a context. Returns null when the check has nothing to report.
 *
 * Exported as well as used internally: evaluating a single entry is how a new probe can be
 * tested in isolation, and how a caller can dry-run one check without auditing a whole target.
 * An entry naming a probe this build does not implement returns null rather than throwing --
 * the catalog is data, and data can be wrong without the audit falling over.
 */
export function evaluateOneBuiltin(entry, ctx = {}) {
  // Guarded once, here, rather than per branch: the catalog is data, and a null or malformed
  // entry must produce no finding instead of taking the audit down. Guarding only the first
  // branch was the mistake the suite caught -- a null entry reached the second one and threw.
  if (entry === null || typeof entry !== "object") return null;
  const args = entry.probe_args ?? {};
  const io = ctx.io ?? {};
  const bases = ctx.bases ?? {};

  if (entry.probe === BUILTIN_PROBES.VOLUME_ENCRYPTION) {
    const r = classifyVolumeEncryption(ctx);
    return {
      layer: entry.layer,
      id: entry.id,
      severity: r.state === "encrypted" ? "ok" : r.state === "not-encrypted" ? "warn" : "info",
      title:
        r.state === "encrypted" ? "Volume is encrypted at rest (determined)"
        : r.state === "not-encrypted" ? "Volume is not encrypted at rest (determined)"
        : "Volume encryption could not be determined",
      detail:
        r.detail +
        " This concerns the volume as a whole, so it applies to every file on it, not only to this target.",
      evidence: { state: r.state, reason: r.reason, ...r.evidence },
    };
  }

  if (entry.probe === BUILTIN_PROBES.PATH_RESIDUE) {
    const dir = bases[args.base];
    if (typeof dir !== "string" || !dir) return null;
    const full = path.join(dir, args.file);
    const st = io.statOf ? io.statOf(full) : null;
    if (!st || st.size < (args.min_size ?? 1)) return null;
    const age = daysSince(st.mtime);
    const stale = args.stale_days != null && age != null && age > args.stale_days;
    const shape = EVIDENCE[args.evidence] ?? EVIDENCE["size-mtime"];
    const vars = {
      name: args.name ?? args.file,
      size: fmtBytes(st.size),
      age,
      path: args.file,
      mtime: st.mtime.toISOString(),
    };
    return {
      layer: entry.layer,
      id: entry.id,
      severity: args.severity ?? entry.severities[0],
      title: renderTemplate(entry.title, vars),
      detail: renderTemplate(stale && entry.detail_if_stale ? entry.detail_if_stale : entry.detail, vars),
      evidence: shape({ rel: args.file, size: st.size, mtimeIso: st.mtime.toISOString(), age, stale }),
    };
  }

  if (entry.probe === BUILTIN_PROBES.DIR_ENTRIES) {
    const dir = bases[args.base];
    if (typeof dir !== "string" || !dir) return null;
    const full = path.join(dir, args.file);
    const entries = (io.listDir ? io.listDir(full) : []).filter((e) => e.isFile());
    if (entries.length < (args.min_count ?? 1)) return null;
    const names = entries.map((e) => e.name).slice(0, args.max_names ?? 10);
    return {
      layer: entry.layer,
      id: entry.id,
      severity: args.severity ?? entry.severities[0],
      title: renderTemplate(entry.title, { count: entries.length, name: args.file }),
      detail: renderTemplate(entry.detail, { count: entries.length }),
      evidence: { files: names },
    };
  }

  return null;
}

/**
 * Run every built-in check the catalog declares for `target`, optionally narrowed to one layer.
 *
 * `ctx` is passed straight through to the probes, so this stays pure and a test can drive every
 * branch without touching the real filesystem.
 */
export function evaluateBuiltins(target, ctx = {}, opts = {}) {
  const wantLayer = typeof opts.layer === "string" && opts.layer !== "all" ? opts.layer : null;
  const out = [];
  for (const entry of CHECK_CATALOG) {
    if (entry.kind !== "builtin") continue;
    if (target && !entry.targets.includes(target)) continue;
    if (wantLayer && entry.layer !== wantLayer) continue;
    const r = evaluateOneBuiltin(entry, ctx);
    if (!r) continue;
    out.push(r);
  }
  return out;
}
