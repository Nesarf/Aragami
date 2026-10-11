# Aragami

[![release](https://github.com/Nesarf/Aragami/actions/workflows/release.yml/badge.svg)](https://github.com/Nesarf/Aragami/actions/workflows/release.yml)

**A portable static posture auditor for Tor Browser and Firefox.**

One pure-Node head (`lib/core.mjs`), two interfaces (MCP stdio server + CLI), sharing the same single `TOOLS[].execute` -- no second implementation.

> *Aragami* -- the uninvited deity, a wrathful god. It does not fight for you; it only points out, one item at a time, the traces already left on your machine.
> The name is about "being visible": **an auditor does not create safety, it merely leaves residue nowhere to hide.**

---

## 1. What it is, and what it is **not**

This section has to come first. **This tool is designed to say "no".**

### What it does

| Layer | What is audited |
|---|---|
| **Build layer** | Tor Browser: version, channel, Firefox base, bundled Tor version. Firefox: application version, and the version the profile was last used with |
| **Transport layer** | Tor: bridge configuration, pluggable transport inventory, **uTLS fingerprint mimicry**, **domain fronting**, built-in vs. custom bridges, deprecated PTs, Quick Start timing. Firefox: proxy mode, DNS over HTTPS, content blocking, fingerprint resistance, cookie policy |
| **Content/authorization layer** | Tor: onion service client authorization, whether `.onion` service private keys exist. Firefox: saved-login database, key material, client certificate store |
| **Metadata layer** | Tor: the **guard set** in `state`, descriptor cache, PT state, profile first-use time, session checkpoints, browsing history. Firefox: history and cookies, per-site permissions, form history, site storage, telemetry client ID, account linkage, extensions |
| **Endpoint layer** | Where the install or profile lives, user/temp directory residue, how many profiles exist, persistent vs. amnesic, and whether the volume holding it is encrypted at rest (to the extent a static, unprivileged audit can tell -- see `disk-encryption` in `aragami_checks`) |

Two questions sit **outside** an audit, and both are served by looking at the surface rather
than at your machine:

- **What can this tool even see?** `aragami_checks` prints the declared check surface, one
  entry per check, each stating what it reads and what it explicitly does not cover.
- **What would travel with this directory?** `aragami_handoff` scans a folder you are about to
  give someone else and reports the key-shaped names, residue and build artefacts that would go
  with it -- by name only, never by reading contents, and it says so where it reports.
- **Did anything move?** `aragami_baseline` captures the audit as a set of per-check
  fingerprints and diffs a later run against it. Posture at rest and posture *drift* are
  different questions, and only the second one catches a guard set quietly growing.

**Read-only, entirely.** It does not start Tor, does not touch configuration, does not write
any file -- a baseline is handed back to the caller to store, never written by the tool. The
only network action is the version check (which can be turned off).

### What it does **not** do

Every tool, on every path -- error paths included -- carries this notice verbatim:

```
This tool performs a static audit only: it reads files, never launches the application
under audit, and never touches the network (except the version lookup).
It does NOT address: traffic correlation and timing analysis, endpoint compromise
(malware / device seizure), or anything that happens after decryption.
It protects [configuration posture and static residue]. It is NOT an anti-tracking tool.
A clean audit is NOT proof of safety. Treating it as one is a misuse.
```

The rest of this section is this README explaining that notice, not repeating it.

- **Traffic correlation and timing analysis**: an adversary does not need to read the content, only to line up the entry and exit timings. **Content encryption helps the metadata layer by roughly zero.**
- **Live protocol queries and reachability tests**: refused rather than merely absent, and the two are refused for different reasons. Querying Tor's ControlPort is refused because an audit that depends on whether a service happens to be running stops being deterministic, and determinism is what the baseline and drift feature rests on. Testing whether a configured bridge is reachable is refused because **the check would be the harm**: dialing a bridge from your address, at a moment of your choosing, manufactures exactly the metadata an adversary needs to find and fingerprint that bridge's use. See discipline 18.
- **Endpoint compromise**: malware, keyloggers, a seized device. Cryptography cannot reach this layer.
- **What happens after decryption**: the recipient read it, kept a copy, said something, met someone -- the most common point of failure in public cases.
- **People**: no technical solution exists. This is the one layer `aragami_layer_assess` will not recommend anything for, and the one `aragami_audit` never reports a finding under.

> A clean audit is not a licence to relax. To address the metadata layer, the direction that
> works is a mixnet (Nym) or a metadata-hiding messenger (SimpleX / Cwtch) -- not more
> configuration piled onto Tor. That advice is this document's, not the tool's.

### The emblem

`Aragami` -- the bare name, no extension, at the repository root and inside every package -- is
a sealed statement of the work the project takes its name from. It is a short ASCII envelope
holding an AES-256-GCM seal over a few lines of text about that work: title, artist, album,
duration, format, and two digests.

The single-file executable has no files beside it to read, so the seal is also inlined into the
bundle at build time. The file is the copy a person can find and read the shape of; the inline is
what the executable reports from. Both paths are exercised -- the suite passes an inlined value
to the loader, and the bundle is run from a directory with no seal in it before it is shipped.

The key is derived from the work's own content digest, so **the seal opens only where the work
itself is present**. That is the whole of it, and it is worth being exact about what that does
and does not mean:

- It is **not** a secret, a credential, or a security control, and nothing here depends on it
  for safety. Anyone holding the source work can derive the key; the repository alone cannot.
- What GCM adds is **tamper-evidence**: an altered seal fails to open rather than opening to
  something else. The suite asserts exactly that, along with a wrong source, an altered
  nonce, an altered tag, and a swapped payload.
- No audio is carried in the repository or in any package, and the project distributes none.
  The default target is Tor Browser and the emblem belongs to a piece of music; a project
  about what you leave behind should not be the thing that leaves a copy.

`aragami_env` reports it as `emblem`, in structure only -- `present`, `sealed`, `format`,
`cipher`, `kdf`, `opens_with`. It never reports contents, because it holds no key. Sealing is
done by `packaging/emblem.mjs`, which reads the work, derives the text from the work's own
metadata rather than from the machine or the moment, and writes the envelope:

```
node packaging/emblem.mjs seal <source-work>    # writes Aragami
node packaging/emblem.mjs open <source-work>    # prints the statement
node packaging/emblem.mjs verify                # structure only, no key needed
```

---

## 2. Why a tool, not a document

Wrap an analysis in a plugin and the plugin only returns an essay -- but a reader can already read an essay, which is zero gain.

So this carries only the two **executable** pieces:

1. **Posture audit** -- static, reproducible, with concrete artifacts (which file, how large, how long ago it was written)
2. **Layer arbitration** -- `aragami_layer_assess` encodes "which layer's problem calls for which layer's countermeasure" as a program. Its core capability is **recognizing layer mismatch and raising an alarm**: real-time round trips and metadata protection are in hard conflict; pure content sensitivity should not be wrapped in high-risk tradecraft.

Point 2 matters especially: an advisor that only dispenses advice manufactures false confidence. This tool's `does_not_cover` field is **permanent**, not an optional decoration.

---

## 3. Installation

### Dependencies

```bash
npm install          # only @modelcontextprotocol/sdk
```

Node >= 18 (`fetch` and WebCrypto are required). Zero other runtime dependencies -- the proxy tunnel is implemented from the stdlib.

### Prebuilt packages

Every artifact is produced **per target**, so a download can carry a default. `ARAGAMI_TARGET`
selects that default; an explicit `--target` argument always overrides it, which is what keeps a
target-specific build from becoming a target-*locked* one.

| Form | Runtime it needs | Verified by |
|---|---|---|
| Portable `.zip` + `.cmd` launchers | **Node.js >= 18 on the host** | Extracted, all six launchers run from a foreign working directory |
| `.msi` (WiX, perMachine, x64) | **Node.js >= 18 on the host** | `msiexec /i /qn` real install as an administrator: payload under `Program Files`, a registration the 64-bit registry view can see, the `bin` directory on the machine `PATH`, the launcher then run **by name from that PATH** and answering with the schema it should, and `msiexec /x /qn` leaving the machine unmodified -- the `PATH` is compared against a snapshot taken before the install rather than eyeballed. The installer's own images are checked by reading them back out of the built package |
| Single-file `.exe` (Node SEA) | **nothing** | Run with Node removed from `PATH`; CLI and `--mcp` both answer |
| `winget` manifests | (installs the MSI, so Node) | `winget validate` 3/3, recorded SHA matches the MSI it was generated from |
| `npm` package | **Node.js >= 18** | `npm pack`, global install into a scratch prefix, both commands run |
| Linux `.tar.gz` + `install.sh` | **Node.js >= 18 on the host** | `./install.sh` executed for real, six wrappers installed, target pinning and `--uninstall` checked |
| `.deb` | `nodejs (>= 18)` | `dpkg-deb` accepted it, then `dpkg -i` and run |
| `.rpm` | `nodejs >= 18` | `rpm -i` and run; `Conflicts` refuses a second variant correctly |
| AppImage | **nothing** | Run on a distribution with no node and no `libnode`; CLI and `--mcp` both answer |
| Flatpak | **nothing** | `flatpak install` and `run`; the bundled interpreter reports its version while `command -v node` finds nothing |
| Snap (classic) | **nothing** | `snap install --classic` and `run`; same check as the Flatpak |

Four forms carry their own runtime and the rest use the host's, and the difference is worth
knowing before picking one. Carrying a runtime costs size: the Linux tarball is ~170 KB, the
MSI ~1.1 MB, and the self-contained ones are 16 MB (Flatpak) to 40 MB (AppImage) to 90 MB (the
single-file executable). A runtime that works anywhere cannot share libraries with the machine
that built it. That is not a theoretical distinction: the AppImage used to copy the `node` that
happened to be on `PATH`, which on a distribution that ships node as a shared library produced
an artifact that only ran on machines with that library.

The MSI is the outlier among the host-runtime forms, and it is worth knowing why it is five times
the size of the tarball that carries the same code: 216 KB without an installer UI, 1140 KB with
one. Of that increase, 535 KB is the two dialog images and 389 KB is the dialog set and its
custom-action library. A wizard is not free, and an MSI is not automatically the small option.
`packaging/linux/fetch-node.sh` fetches the official self-contained build, pinned to a version
and checked against its published SHA256, and both the AppImage and the snap use it.

`confinement` for the snap is `classic`, which asks the user to opt in with `--classic`. The
alternative was measured rather than assumed: under strict confinement the `home` interface
excludes hidden files, so `~/.mozilla` is unreachable and the Firefox target cannot work at
all. A strict snap would install cleanly and then be unable to do the one thing it exists for.

Build them yourself with the scripts in `packaging/` -- each one stages a bundle and then wraps
it, so no form re-implements the tool. `-Target all` means the neutral package that auto-detects
at runtime, in every one of them; the pinned `-tor` and `-firefox` variants are separate calls.

```powershell
pwsh packaging/pack-portable.ps1       -Target firefox
pwsh packaging/pack-msi.ps1            -Target tor
pwsh packaging/pack-sea.ps1            -Target firefox
pwsh packaging/linux/build-tarball.ps1 -Target firefox
pwsh packaging/linux/build-deb.ps1     -Target firefox
```

### MCP setup

Aragami speaks MCP over stdio, so any MCP-capable client can run it: point the client at
`mcp/index.mjs` and it will discover the four tools.

```json
{
  "mcpServers": {
    "Aragami": {
      "command": "node",
      "args": ["/path/to/Aragami/mcp/index.mjs"]
    }
  }
}
```

If the client registers servers through a CLI, the equivalent is:

```bash
<client> mcp add Aragami -- node /path/to/Aragami/mcp/index.mjs
```

Installing from npm also exports the server as `aragami-mcp`, so the command can simply be
`aragami-mcp`.

### CLI

```bash
node cli/index.mjs                       # usage and tool list
node cli/index.mjs aragami_env --human
node cli/index.mjs aragami_audit --human
node cli/index.mjs aragami_audit --target firefox --human
node cli/index.mjs aragami_audit --layer metadata --min_severity warn --human
node cli/index.mjs aragami_version --human
node cli/index.mjs aragami_checks --target tor --layer endpoint --human
node cli/index.mjs aragami_baseline > baseline.json
node cli/index.mjs aragami_baseline --mode diff --baseline_path baseline.json --human
node cli/index.mjs aragami_layer_assess --metadata_sensitive true --realtime true --human
```

Output is JSON by default (easy for a program to consume); `--human` switches to a human-readable layout.

---

## 4. Tool reference

Every tool takes an optional `target` (`auto` | `tor` | `firefox`), where `auto` prefers Tor
Browser and falls back to Firefox. `ARAGAMI_TARGET` sets the same default from the environment,
which is how the per-target packages pin one without forking the code; an explicit argument
always wins over both.

Note that **two different layer taxonomies** appear in this document and they are not the same
thing. The audit tags each finding with one of six layers -- `build`, `transport`, `crypto`
(shown as "Content / authorization"), `metadata`, `endpoint`, `social` -- and `aragami_audit`'s
`layer` parameter accepts the first five, because nothing is ever reported under `social`: there
is no technical solution to it, so there is nothing to find. Section 5 describes the separate
four-layer *model* that `aragami_layer_assess` reasons over.

### `aragami_env`
Probes the runtime environment and discovers every supported target: Tor Browser installs under `targets.tor`, Firefox profiles under `targets.firefox`. **Run this first to get a path for the other tools.**

| Parameter | Description |
|---|---|
| `install` | Optional: a Tor Browser install root to use directly instead of auto-discovery |

The response also carries `emblem`, the structure of the seal described in [The emblem](#the-emblem). It reports shape and never contents: this process holds no key.

### `aragami_audit`
The full static audit.

| Parameter | Description |
|---|---|
| `target` | `auto` \| `tor` \| `firefox` |
| `install` | Tor Browser install root; **when given explicitly, only that one location is audited**, otherwise auto-discovery |
| `profile` | Firefox profile directory; defaults to the profile the application opens, else the first found |
| `layer` | `all` \| `build` \| `transport` \| `crypto` \| `metadata` \| `endpoint` |
| `min_severity` | `ok` \| `info` \| `warn` \| `critical`; **default `ok` (everything shown, including positive findings)** |

Returns `findings` grouped by layer, each carrying `layer / severity / id / title / detail / evidence`.

### `aragami_version`
Checks the version in use against the vendor's own published metadata, and reports how far behind
it is. Both targets are supported:

| Target | Local version read from | Compared against |
|---|---|---|
| `tor` | `tbb_version.json` in the install | the Tor Project release endpoint (`aus1.torproject.org`), per channel |
| `firefox` | `application.ini` in the program directory, else the profile's `compatibility.ini` | `product-details.mozilla.org/1.0/firefox_versions.json` |

A local version can honestly be absent -- a machine may have neither installed -- in which case
`installed` and `local_source` are both null rather than one of them being invented.

| Parameter | Description |
|---|---|
| `target` | `auto` \| `tor` \| `firefox` |
| `install` | Tor Browser install root, or a Firefox program directory; auto-discovered when omitted |
| `online` | Whether to check online; **default `true`**. `false` reports the local version only |
| `proxy` | Proxy URL, e.g. `http://127.0.0.1:8080` or `socks5://127.0.0.1:1080` |

**It routes through the local proxy automatically**: first the `HTTPS_PROXY` / `ALL_PROXY` environment variables, then the Windows system proxy (WinINET `ProxyServer`). Override with `proxy`, or pass `"none"` to force a direct connection.

> Why this is needed: Node's built-in `fetch` **does not read the system proxy**, so on a network that requires one it goes straight to `UND_ERR_CONNECT_TIMEOUT`. This implements HTTP CONNECT and SOCKS5 tunnelling from the stdlib.

### `aragami_layer_assess`
Layer arbitration. Takes scenario characteristics, returns a recommended channel + steps + warnings + a **non-coverage list**.

| Parameter | Description |
|---|---|
| `content_sensitive` | Does the content itself need protection (what happens if it is read) |
| `metadata_sensitive` | Does the fact of communicating need protection (what happens if who-talks-to-whom is known) |
| `realtime` | Is a realtime / near-realtime round trip required |
| `counterpart_capability` | `email-only` \| `can-install-tools` \| `signal-capable` \| `tor-capable`. The upper bound of the counterpart's tooling -- this usually caps the whole design |
| `must_leave_no_third_party_copy` | Must no third party retain a copy |
| `endpoint_shared_or_seizable` | Can the endpoint be accessed by others or seized |

Key behaviors:
- `metadata_sensitive + realtime` -> reports a **hard conflict** (real time couples the two ends' clocks tightly, which is perfect material for timing correlation)
- `content_sensitive` and not metadata-sensitive -> **discourages** over-tradecraft (high-risk tradecraft is itself the most conspicuous signature)
- `counterpart_capability: email-only` -> points out that the ceiling on the approach is pressed very low
- every assessment carries `does_not_cover`

### `aragami_checks`
Query the check surface as data. Lists every check this build performs, what each one reads,
and -- per check -- **what that check does not cover**. It reads nothing and audits nothing.

| Parameter | Description |
|---|---|
| `target` | `tor` \| `firefox` -- restrict to the checks one target produces |
| `layer` | `all` \| `build` \| `transport` \| `crypto` \| `metadata` \| `endpoint` |
| `id` | Look up a single check instead of listing |

Key behaviors:
- The surface is a declared catalog rather than something you can only learn by reading control flow, and each entry carries its own boundary text -- the shared `boundary_notice` deliberately does not enumerate per-check limits
- An audit response reports the catalog version, a structural digest, and whether the run **conformed** to it (`unknown` ids, severities outside a check's declared set). A mismatch is a defect in this repository, never a statement about your machine
- Also reports which checks did not fire. That is not an error: a check whose subject is absent does not fire

### `aragami_baseline`
Posture **drift**. A single audit answers "what does the configuration look like now"; it
cannot answer "did anything move since last week". `mode=capture` records the current audit;
`mode=diff` compares a stored record against a fresh audit.

| Parameter | Description |
|---|---|
| `mode` | `capture` (default) \| `diff` |
| `baseline` | A previously captured baseline; a capture *response* is accepted as well as a bare record |
| `baseline_path` | Path to a baseline JSON file to read instead |
| `target`, `install`, `profile` | Which target to audit, as in `aragami_audit` |

Key behaviors:
- **A baseline stores fingerprints, never evidence.** This is load-bearing: the audit's own argument is that state files, guard sets, key filenames and paths are the sensitive residue, so a baseline that recorded them would be a tidy copy of exactly what the tool tells you not to keep. Each entry keeps a digest of the evidence -- enough to detect a change, useless to anyone who obtains the file
- The diff **refuses rather than guesses**: two records from different installs or profiles differ in almost every line, and their difference is not drift, so that is reported as `subject-mismatch` instead of a number that looks like an answer
- A moved check catalog is **not** drift. When the surface changed, the comparison is restricted to the checks both records carry, and the difference is flagged separately
- Accepts a capture response as well as a bare record, so redirecting a capture straight to a file works
- Stateless: nothing is written anywhere. You keep the baseline and hand it back

### `aragami_handoff`

What would travel with a directory you are about to give someone else. Point it at the directory and
it reports what it finds **by name**, and nothing else.

| Parameter | Description |
|---|---|
| `path` | The directory about to be handed over |
| `tor_install` | Optional: a Tor Browser install root to use for the onion-authorization part, instead of the one that would be discovered |
| `layer`, `min_severity` | Filters, as in `aragami_audit` |

It looks for five things, all of them catalog data rather than code -- see `aragami_checks` for the
per-check limits, which are stated by each check rather than summarized here:

- **Key-shaped names**: `id_rsa`, `*.pem`, `*.kdbx`, `.env`, `credentials.json`, `known_hosts` and similar, anywhere in the tree
- **Editor and OS residue**: `Thumbs.db`, `.DS_Store`, `desktop.ini`, swap and backup files
- **Version-control entry**: `.git`, `.hg`, `.svn` -- a repository carries every revision, including the ones deleted from the working tree
- **Build and dependency artefacts**: `node_modules`, `__pycache__`, `target`, `dist`
- **OnionShare presence**: whether a share can be started from this machine at all

When a Tor Browser install is present, its **onion client authorization state** is included, because
that is the other half of preparing a delivery: it answers who can reach the service the package is
being sent over. Those checks are declared for this target as well and are gated on the bases a Tor
install supplies, so with none present they stay silent rather than reporting an absence they cannot
establish -- and the response names whichever install was used.

**The limit that matters most here**: it reads names and sizes, **never file contents**. A key
pasted into `notes.txt`, or a password inside a spreadsheet, is invisible to it. So a scan that
finds nothing is **not** a clean bill of health; it means nothing matched a name. The CLI says so at
the point where a reader would otherwise take silence for approval.

---

## 5. The four-layer model

```
Content layer   Can anyone else read the content itself?
                -> End-to-end encryption. The best-solved layer; not the bottleneck.

Metadata layer  Can anyone else learn who talks to whom, when, and how often?
                -> mixnet / metadata-hiding messenger / asynchronous mailbox / onion service.
                -> [Content encryption helps this layer by roughly zero] -- where the vast majority of approaches go wrong.

Endpoint layer  What did this machine in your hands leave behind? What if it is taken?
                -> Environment isolation / full-disk encryption. Cryptography cannot reach it.

Social layer    What will people say, keep, or be asked?
                -> No technical solution.
```

What `aragami_audit` examines is the **static residue of the metadata layer and the endpoint layer** (the remaining layers get posture-compliance checks only).

---

## 6. Measured baseline

Results from a run on this machine (Windows, Tor Browser installed on a non-system drive,
network requiring a proxy). A snapshot rather than a specification: the version numbers and the
guard count are what this install had, and the cache sizes in particular grow every time the
browser is used, so they will not match a later run. The point of the section is the shape of
the output and which layers speak up, not the arithmetic.

```
Build layer          Tor Browser 15.0.21 / Firefox 140.15.0 / Tor 0.4.9.11
                     version check -> outdated: 15.0.21 -> 15.0.22
Transport layer      Snowflake bridges x2 (built-in type), uTLS mimicry hellorandomizedalpn,
                     domain fronting fronts=, lyrebird ships 8 PTs, Conjure
Authorization layer  ClientOnionAuthDir configured (empty directory = feature ready, not enabled)
Metadata layer       state 11.9 KB: 22 guards (sets default + bridges), 266 circuit build timings,
                     descriptor cache 35.5 MB + 8.4 MB, profile first use 2025-11-21,
                     places.sqlite 5.0 MB (browsing history present -- worth a manual check)
Endpoint layer       Drive E, no residue in user or temp directories, persistent install
```

---

## 7. Verification

```bash
npm test              # all traversers, exit code 0
npm run test:cov      # coverage report (--gap prints the uncovered lines in detail)
npm run test:net      # network-layer protocol behavior only
npm run test:matrix   # contract traversal only
npm run test:emblem   # the seal only; needs no source work
```

| Traverser | What it asserts | Scale |
|---|---|---|
| `test/selftest.mjs` | **Semantic correctness** (Tor target): should this branch report at all, and at what severity. Also owns the serializer: sharing is not circularity, `toJSON` is honoured, `undefined` behaves as it does natively, and runs `aragami_handoff` against a real directory rather than a fake one | **227 items** |
| `test/matrix.mjs` | **Contract invariance + robustness**: however it is called, the output contract does not break | **277 calls / 557 contract checks / 0 violations** |
| `test/net.mjs` | **Protocol behavior**: local mock proxy / SOCKS5 / a real TLS handshake over the tunnel / echo / HTTP servers | **54 items** |
| `test/firefox.mjs` | **Semantic correctness** (Firefox target): profile discovery, retention findings, and the credential-exposure line | **142 items** |
| `test/emblem.mjs` | **The seal**: opening with the source work, and refusing a wrong source, an altered payload, tag or nonce, or a swapped container. Built on a synthetic stream, because the claim under test is that a machine *without* the work cannot open it | **94 items** |
| `test/checks.mjs` | **The catalog against the code, in both directions**: every id the code emits is catalogued, every catalogued check has a producer, no two checks own the same fact slot, every entry states a boundary, no template leaves a placeholder unresolved. Plus every branch of every probe, driven through an injected filesystem so a branch reachable only on another platform still runs, every value predicate asserted directly, and the literal rendering of migrated checks checked character for character | **800 items** |
| `test/baseline.mjs` | **Drift, and the privacy claim**: key-order-independent fingerprints, every refusal branch, and the assertion that a captured baseline contains **no** evidence -- built with a marked value that must not appear in the output. Tested over parsed values, not raw JSON, because `JSON.stringify` escapes backslashes and a substring test would pass for the wrong reason | **110 items** |
| `test/mcp-smoke.mjs` | **The portable half**: a real MCP client sees exactly the core's tools, and every response names a versioned schema. Its calls are aimed at a synthetic install, so it does not depend on what the runner has | **63 items** |
| `test/coverage.mjs` | **Evidence of the traversal**: which lines were never executed | **2569/2580 = 99.6%** on Windows; the Linux continuous integration runner is lower and is the figure the gate is set against |

Coverage is a property of the environment as much as of the code, and both numbers are given
because quoting only the higher one would be misleading -- but the two environments differ by
platform *and* by proxy, which is why each row says which. The tunnel's success path, writing a
request after the TLS handshake and reading the response back, used to be entered only where a
proxy was reachable, so the runner never ran it and the gate had to be set to that floor rather
than to the code. `test/certs/` now lets the suite drive a real handshake over the tunnel, so
that path is covered wherever the suite runs and the gate is back to 97.

What remains uncovered is `detectProxy` and only `detectProxy`. With a proxy variable set it
returns inside the loop, so line 92's platform test needs a machine with no proxy variable at
all, and line 93, `readWininetProxy`, needs Windows. Windows therefore reports 190/190 -- its
proxy arrives through WinINET, not the environment -- while Linux reports 189/190 with no proxy
variable and 188/190 with one. None of that is a behavioural difference between platforms: the
same code runs, and only the fixture that reaches it differs.

`selftest`, `matrix`, `firefox` and `emblem` use **synthetic fixtures** (`test/fixtures.mjs`: good / degraded / minimal / self-inconsistent / boundary, for both targets; the emblem suite assembles its own FLAC stream from known field values), so they **do not depend on whether Tor Browser or Firefox is actually installed on this machine** and reproduce on any machine. `net` uses local mock servers and depends on neither the public internet nor a real proxy. The emblem suite additionally depends on no source work being present, which is the condition it is testing.

The `matrix` contract includes: serializable, `boundary_notice` permanent, **no safety assertions may appear**, finding fields complete, ordered by descending severity, `tally` consistent with reality, layer and severity filtering exact, `does_not_cover` non-empty, and 16 sets of malformed input must not throw.

**Coverage is measured on Windows and Linux, because one platform is not enough.** Windows alone reports 11 uncovered lines and Linux alone reports 40, but the two sets barely overlap: each platform covers the branches the other cannot reach -- the Windows drive-letter scan and WinINET proxy read are unreachable on Linux, and the `/usr/lib/firefox` candidates are unreachable on Windows. Only **5 lines are never executed anywhere**, and they are named in [`PROOFREADING.md`](./PROOFREADING.md) rather than papered over. The first Linux run also failed three suites, all of them test-portability defects that CI would have hit on its first run; those are recorded there too, together with every defect found during traversal and proofreading.

---

## 8. Design discipline (read this before changing anything)

1. **Read-only**. Does not start Tor, does not change configuration, does not write files. The only networking is the version check, and it must be switchable off.
2. **`boundary_notice` is permanent**. Every return of every tool carries it -- **error paths included**. Do not make it optional.
3. **The auditor makes no unfounded assertions**. For example: guard entries in Tor 0.4.x are written `Guard in=default rsa_id=...`, and in the old style `EntryGuard ...`. Recognizing only one format produces a false "no guards" **false positive** -- this trap was hit in practice. When unsure, emit `info` and say plainly "please confirm manually".
4. **Positive findings must be shown**. Default `min_severity: ok`. Hiding `ok` makes the report look one-sided and creates needless alarm.
5. **No second implementation**. The MCP server and the CLI share the same single `TOOLS[].execute`.
6. **`aragami_layer_assess` never claims safety**. It must be able to say loudly "I do not solve this".
7. **Line coverage is not branch coverage**. When a ternary branch on a line is never taken, that line still counts as covered -- a tautological ternary (`x ? "a" : "a"`) is **invisible to coverage** and can only be caught by human proofreading. Coverage is necessary evidence, not sufficient evidence.
8. **Tests must not pass for the wrong reason**. During one proofreading round, a blackhole-timeout test "passed" because the port was wrong, so it never actually reached the TLS timeout branch under test -- coverage is what dragged it into the light. Assertions must target the exact behavior, not "if there is an error, count it as a pass".
9. **Fixtures are shared**. `test/fixtures.mjs` is the single source of truth. Inlining a copy means two sources of truth that drift apart on their own.
10. **Filter parameters must be echoed back**. An unknown value falls back to the default, and the filter that actually took effect goes into `applied_filter` -- otherwise a caller who mistypes just gets an empty result and no idea why.
11. **A boundary claim that is false in its first line is worse than no claim at all.** Every check therefore states its own limit in the catalog (`does_not_cover`), and a boundary that cannot be honoured must be removed rather than softened. The `disk-encryption` check exists in this spirit: on Windows a static, unprivileged audit genuinely cannot read a volume's encryption state, so it reports `undetermined` and names the command that answers it, instead of guessing in either direction.
12. **A stored baseline must never contain evidence.** It keeps one fingerprint per check. A baseline that recorded guard names, key filenames or paths would be a tidy copy of exactly the residue this tool tells you not to keep -- and it would diff just as well, so nothing but this rule stops it.
13. **Declared data and code must agree in both directions.** `test/checks.mjs` scans the sources and requires that every id the code emits is in the catalog *and* that every catalogued check has a producer. A table that nothing enforces is decoration.
14. **Serialization must not confuse sharing with circularity.** The same evidence object is reachable from both `findings` and `facts`; a serializer that tracks every object ever visited rather than the ancestors of the current path turns the second view into `"[circular]"` and silently drops the data (see D35 in `PROOFREADING.md`).
15. **The output order is a contract.** Findings sort by descending severity, then by layer in the order `LAYERS` declares them, then by id. Before this, ties kept ASSEMBLY order, so moving a check from one function to another silently changed where a finding appeared while every one of its fields stayed identical -- which is exactly what happened during the catalog migration. An order that can be recomputed from the findings themselves cannot drift.
16. **One evidence shape per probe.** Every `path-residue` finding carries `{path, size, mtime, age_days}`. Three shapes used to exist because three pieces of code had each built its own; they were unified only after the migration had been proven field-for-field, so that the suites could still distinguish a faithful move from a broken one. `stale` was dropped rather than carried: it is derivable from `age_days` and the entry's own threshold, and a recorded fact that can be recomputed is a fact that can disagree with its input.
17. **Accept what the caller actually has.** `aragami_baseline` takes a capture *response* as well as a bare record, because redirecting a capture to a file is the obvious workflow and what lands in the file is the response.
18. **Dynamic checks are refused, and the two kinds are refused for different reasons.** Querying Tor's ControlPort is refused for a **structural** reason: an audit whose result depends on whether a service happens to be running is no longer deterministic, and determinism is precisely what the baseline and drift feature rests on -- a capture that cannot be reproduced cannot be diffed. Testing whether a configured bridge is reachable is refused for an **operational** reason that has nothing to do with scope: **dialing a bridge from the auditor manufactures the metadata the audited user is trying to avoid.** Tor's protection against traffic correlation rests on a user's traffic not being distinguishable or linkable; a connection to a bridge, from that user's address, at a moment of that user's choosing, is exactly the observable pattern an adversary needs to find and fingerprint that bridge's use. Such a check would not merely risk harm, it would **be** the harm. Where a dynamic answer is genuinely needed, the tool does what `disk-encryption` already does: report `undetermined` and **name the command that answers it**, leaving the decision to create traffic with whoever owns the consequences.

---

## 9. Next steps

- **The declarative boundary, and where it sits.** Forty-two of the sixty-three checks are built from catalog data by nine probes (`volume-encryption`, `path-residue`, `path-list`, `dir-entries`, `dir-size`, `json-field`, `config-value`, `static`, `tree-match`). Adding another check of an existing shape is a data change and nothing else. The remaining twenty-one stay `bespoke` because their judgement is compositional -- an aggregate over Bridge lines, a derived category, a merge of three sources, or an evidence field computed from two others. Expressing that as data would need a way to combine predicates, and a data file that can combine predicates is a programming language with worse error messages and worse tooling than the JavaScript it replaced. `config-value` is deliberately the edge of what is allowed: nine fixed predicates, one per variant, first match wins, no nesting.

- **Adding a probe is a design decision; adding a check is not.** The probe vocabulary is the part that needs an argument. A new probe should be added when a *shape* recurs -- a path, a directory, a field, a size, a value comparison -- and not to avoid writing ten lines of logic once.

- Release pipeline (GitHub Release / npm) -- note that `npmjs.com` is hard to reach from mainland China, so **the Git channel is the primary channel**

## License

MIT
