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
| **Endpoint layer** | Where the install or profile lives, user/temp directory residue, how many profiles exist, persistent vs. amnesic |

**Read-only, entirely.** It does not start Tor, does not touch configuration, does not write any file. The only network action is the version check (which can be turned off).

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
| `.msi` (WiX, perMachine) | **Node.js >= 18 on the host** | `msiexec /i` real install, registry entry, launcher run from a path containing spaces and parentheses, `msiexec /x` clean removal |
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
MSI ~188 KB, and the self-contained ones are 16 MB (Flatpak) to 40 MB (AppImage) to 90 MB (the
single-file executable). A runtime that works anywhere cannot share libraries with the machine
that built it. That is not a theoretical distinction: the AppImage used to copy the `node` that
happened to be on `PATH`, which on a distribution that ships node as a shared library produced
an artifact that only ran on machines with that library.
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
| `test/selftest.mjs` | **Semantic correctness** (Tor target): should this branch report at all, and at what severity | **165 items** |
| `test/matrix.mjs` | **Contract invariance + robustness**: however it is called, the output contract does not break | **277 calls / 557 contract checks / 0 violations** |
| `test/net.mjs` | **Protocol behavior**: local mock proxy / SOCKS5 / a real TLS handshake over the tunnel / echo / HTTP servers | **54 items** |
| `test/firefox.mjs` | **Semantic correctness** (Firefox target): profile discovery, retention findings, and the credential-exposure line | **142 items** |
| `test/emblem.mjs` | **The seal**: opening with the source work, and refusing a wrong source, an altered payload, tag or nonce, or a swapped container. Built on a synthetic stream, because the claim under test is that a machine *without* the work cannot open it | **94 items** |
| `test/coverage.mjs` | **Evidence of the traversal**: which lines were never executed | **1608/1619 = 99.3%** on Windows; the Linux continuous integration runner is lower and is the figure the gate is set against |

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

---

## 9. Next steps

- Interlock with a delivery-preparation workflow: before handing off a sensitive package, verify OnionShare availability and onion client authorization state

- Release pipeline (GitHub Release / npm) -- note that `npmjs.com` is hard to reach from mainland China, so **the Git channel is the primary channel**

## License

MIT
