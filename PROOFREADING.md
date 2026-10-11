# Proofreading record

This file records the verification work behind the test suite: what each traverser
asserts, which defect classes have been caught and are now regression-locked, and -- just
as importantly -- what remains honestly untested.

It is deliberately **not shipped in the npm tarball** (see the `files` field in
`package.json`).

The method used was: **test -> traverse -> proofread -> traverse -> test**.

---

## 1. The traversers

| Traverser | What it asserts | Size |
|---|---|---|
| `test/selftest.mjs` | **Semantic correctness**, Tor target: whether a branch should report at all, and at which severity | 165 checks |
| `test/matrix.mjs` | **Contract invariance + robustness**: no matter how it is called, the output contract does not break | 277 calls / 557 contract checks |
| `test/net.mjs` | **Protocol behavior**: local mock proxy / SOCKS5 / a real TLS handshake over the tunnel / echo / HTTP server | 54 checks |
| `test/firefox.mjs` | **Semantic correctness**, Firefox target: profile discovery and the retention / credential-exposure split | 142 checks |
| `test/emblem.mjs` | **The seal**: that it opens with the source work, and that it does not open with a wrong source, an altered payload, tag or nonce, or a swapped container; plus every rejection branch of the envelope and the FLAC reader's fields against a synthetic stream | 94 checks |
| `test/coverage.mjs` | **Evidence of traversal**: which lines were never executed | 1608/1619 = 99.3% on Windows; see the platform notes below |

The `matrix` contract includes: serializable, `boundary_notice` always present, **no safety
claim may appear**, complete finding fields, sorted by descending severity, `tally`
consistent with the actual output, unique ids, exact layer/severity filtering, non-empty
`does_not_cover`, and no exceptions from 16 classes of malformed input.

### Where the coverage came from

`lib/net.mjs` was the weakest area when the suite was first assembled. It had been
verified by a single live call, which left the entire SOCKS5 block, `dechunk`, the direct
path, and the CONNECT-rejection branch never executed -- around 55% line coverage on a
module that speaks two proxy protocols. `test/net.mjs` exists to close that, and the
network layer now sits at 100% alongside the core.

The general lesson is worth stating plainly: for an auditing tool, **an unverified branch
is a guarantee that does not exist**. Coverage gaps are therefore recorded below as
defects, not as chores.

---

## 2. Defects caught by traversal

### 2.1 Contract violations (caught by matrix)

| # | Symptom | Root cause | Fix | Regression assertion |
|---|---|---|---|---|
| D1 | `install` passed `12345` or `{}` throws immediately | `path.join` throws on a non-string; the argument comes from an untrusted caller | Added a non-string guard to `discoverInstalls` | selftest B1 / matrix malformed-input group |
| D2 | A typo in a filter argument (`layer: "metdata"`) silently returns an empty result | An unknown value participates in filtering with no observable feedback | Sanitize and fall back + echo `applied_filter` | selftest B3 |

### 2.2 Coverage gaps (caught by coverage -- paths that were never executed)

| # | Symptom | Explanation | Fix | Regression assertion |
|---|---|---|---|---|
| D3 | `lib/net.mjs` line coverage was only 55.5%: the entire SOCKS5 block, `dechunk`, the direct path, and the CONNECT-rejection branch were **never executed** | The module had been verified by exactly one live call | Added `test/net.mjs`: local mock HTTP CONNECT proxy / SOCKS5 server / TLS over the tunnel / TCP echo / HTTP JSON server, with no dependency on the external network or a real proxy | 54 checks, 190/190 on Windows and 189/190 off it |
| D4 | Five branches in `lib/core.mjs` were **unreachable by any fixture**: `UseBridges` enabled but no bridge lines, leftover `pt_state`, an installation on the system drive, leftovers in the user profile, and the non-`win32` early return | The fixtures only covered the "good" and "degraded" shapes | Added `inconsistent` / `edge` fixtures, merged `pt_state` into the good fixture; covered the system-drive and leftover branches by injecting the `SystemDrive` / `USERPROFILE` environment variables (measured: `os.homedir()` does read them at call time) | selftest B5 / B7 / B11 |
| D5 | The **equality branch** of `cmpVer` was never reached, because no fixture version was exactly equal to the latest | The function was not exported, so it could not be unit tested | Exported `cmpVer` and added unit tests | selftest A3 |

---

## 3. Defects caught by close reading

### Core logic

| # | Symptom | Fix | Regression assertion |
|---|---|---|---|
| D6 | `evidence.plugins` held the **raw config lines** (including `.exe` paths), which does not match the field name | Split into `plugins` (parsed transport names) + `raw` (original lines) | selftest B2 |
| D7 | **Wrong deprecated-transport count**: `bridges.length === kinds[deprecated[0]]` compared only the first kind, so a mix such as `obfs2 x2 + obfs3 x1` was **under-reported** | Sum the totals of all deprecated kinds | selftest B11 (edge fixture) |
| D8 | **Tautological ternary** `d > 90 ? "info" : "info"` -- cache freshness had no effect on the output whatsoever | Replaced with a `stale` flag + wording branches (idle and active get different explanations) | selftest B11 |
| D9 | **Dead code**: `dlDir` was computed and then discarded with `void dlDir` | Removed | -- |
| D10 | **Orphaned JSDoc**: the doc block for `discoverInstalls` was stuck above `canonKey`, leaving both functions' docs misplaced | Moved back into place | -- |
| D11 | `evidence.bridges` meant two conflicting things (a **line count** in state, a **kind count** in transport) | Renamed the state-side one to `state_bridge_lines` | -- |
| D12 | Leftover-path comparison was **case-sensitive** on Windows, and could misjudge an installation's own directory as leftovers | Lowercase normalization on win32 | selftest B7 |
| D13 | `detectEnvironment` matched the **entire argv** (including the full cwd path) against `"mcp"`, so with the project in a directory whose name contains "mcp" the CLI was misdetected | Look only at the directory of the entry script | selftest B11 |
| D14 | `LAYER_MODEL.solved_by_this_tool` mixed in the string `"partial"`, inconsistent with the boolean type of the other layers | All booleans + added a `tool_role` field | selftest B11 |
| D15 | The `aragami_layer_assess` parameter was named `a`, inconsistent with `args` on the other tools | Unified to `args` | -- |
| D16 | A 0-byte `sessionCheckpoints.json` was reported as "present" (`places.sqlite` already had a size check; this one was missed) | Added `size > 0` | selftest B11 |
| D17 | With nothing sensitive declared at all, the verdict still said "this is a content-layer problem" | Added a branch: state plainly that no special treatment is needed | selftest B11 |

### Network layer

| # | Symptom | Fix | Regression assertion |
|---|---|---|---|
| D22 | `httpsGetOverSocket` set `servername` unconditionally, which **violates RFC 6066** for IP targets, and Node raised `DEP0123` | Omit `servername` for IP targets | test/net.mjs C2 (warning gone) |
| D23 | The `catch` branch of the registry read was **untestable**: on Windows, clearing `PATH` does not stop `reg.exe` from being found (measured) | Extracted the pure function `parseWininetRegistry`, plus `readWininetProxy` with an injectable executor | test/net.mjs A4/A5 |

### CLI

| # | Symptom | Fix | Regression assertion |
|---|---|---|---|
| D18 | **The error path dropped the boundary notice** -- a direct violation of the "`boundary_notice` always present" rule | Print it on error branches too | selftest B12 |
| D19 | A missing verdict printed `undefined` | Fall back to "unknown" | -- |
| D20 | The color table had dead keys `dim` / `blue` | Removed | -- |
| D21 | The tool table in `--help` had a hardcoded column width and cut summaries mid-word | Width derived from the longest tool name; summaries cut at a word boundary | -- |

### Packaging

> Found by building each artifact and then installing and running it, which is a different
> instrument from reading the code. Several of these had been visible in the source the whole
> time and read as correct; they only became wrong when something executed.

| # | Symptom | Fix | Regression assertion |
|---|---|---|---|
| D24 | The `.deb`'s wrappers installed as mode `0666`, so the package installed cleanly and then failed with `Permission denied` | The mode is stated rather than inherited: `mktar.py` builds the inner archive instead of `tar` | `mktar.py --check` reads the modes back out of the finished archive |
| D25 | `install.sh` was committed as `100644`, so `./install.sh` failed while the README told the reader to run exactly that | Git index set to `100755`; the tarball is built by `mktar.py` so it survives being built on Windows | `mktar.py --check` on the tarball |
| D26 | The tarball had the same `0666` problem as the `.deb`. It survived because the first fix went into the `.deb`'s own builder | One builder for both forms | as above |
| D27 | **The AppImage carried a runtime that only worked on the machine that built it.** `cp "$(command -v node)"` copied the distribution's `node`, which links against `libnode.so.127`; the artifact reported `libnode.so.127: cannot open shared object file` on a clean Ubuntu with no such library. Nothing in the source said this was wrong -- it read as "bundle a runtime" -- and it took running the AppImage on a *second* machine to see it | `packaging/linux/fetch-node.sh` fetches the official self-contained Node build, pinned to a version and verified against its published SHA256. Shared with the snap, which needs the same binary under the same rule | The AppImage is run on a distribution with no node and no `libnode`, in `Known boundaries` terms rather than as a unit test |
| D28 | The snap could not use the distribution's `nodejs` at all: it aborts on `Cannot load externalized builtin: /usr/share/nodejs/...` because the distribution build resolves some builtins through absolute host paths | Same shared fetch as D27 | The snap is installed and run with no node on the host |
| D29 | `pack-sea.ps1` alone read `-Target all` as "every variant" while five other scripts read it as "the neutral package", so the workflow called it once and the others three times -- both correct, for different reasons | One meaning across all six; the workflow calls each three times | Rebuilt and confirmed: three calls, three executables, right baked target each |
| D30 | The commit that fixed the `.deb` also introduced a syntax error in `pack-sea.ps1` (`[string]$TempDir,` with nothing after it) | Trailing comma removed | `Parser::ParseFile` over every packaging script |
| D31 | **Both bundled entry points failed to start, and every artifact still built.** `lib/emblem.mjs` read `import.meta.url` at module scope to locate the seal beside the module. esbuild replaces `import.meta` with an empty object under the `cjs` format, so `fileURLToPath(undefined)` threw during load -- `dist/cli.cjs` and `dist/mcp.cjs` both exited 1 with `ERR_INVALID_ARG_TYPE` before reaching a single verb. The bundler had warned about it on every build (`"import.meta" is not available with the "cjs" output format`), and the warning was read as noise because a bundle that builds and passes its size check looks finished | The read is type-guarded and the directory is null in the bundle, which does not need it: the seal is inlined there. `emblemCandidates` also gained the entry point's own directory, since the shipped layout is `<package>/dist/<entry>` and the module directory is exactly what a bundle cannot report | `packaging/bundle.mjs` now **runs** the CLI bundle and fails the build if it does not start, and the SEA bundle was run from a directory with no seal beside it to confirm the inline is what answers |
| D32 | **Adding a sixth suite disarmed the guard that publishes the coverage status.** The status step decided failure with `grep -qE "Summary: suites [0-4]/5"`, a pattern that hardcodes both the count and the total. With six suites the report reads `suites 5/6`, which does not match `/5`, so the guard could not fire at all -- replayed against the new shape, `6/6`, `5/6`, `4/6` and even `0/6` every one of them produced `success`. The `aragami/coverage` status exists so that a failure is readable from outside a public repository without a token, and it would have reported green for a run in which every suite failed. It went unnoticed because the guard is the only thing that reads it: the suite's own failures were still reported correctly by the report text the status carried | The status compares the passed count against the total instead of matching a shape, so the number of suites is no longer written down anywhere in the guard, and an absent or unparseable report counts as failure rather than as a pass | The guard was replayed against `6/6`, `5/6`, `4/6`, `0/6` and an empty report: only `6/6` yields success |
| D33 | **`dependabot.yml` was rejected outright, silently ending version updates.** The `cooldown` block carried `semver-major-days`, `semver-minor-days` and `semver-patch-days`, which npm accepts and `github-actions` does not. Dependabot does not ignore an unsupported key: it refuses the entire file -- "the property '#/updates/0/cooldown/semver-major-days' is not supported for the package ecosystem 'github-actions'" -- and stops proposing updates for **both** ecosystems. Every workflow run stayed green throughout, because the config is not read by the pipeline; the only signal was the `.github/dependabot.yml` check, which reports as a failing check rather than as a failing run and is easy to read past | The `github-actions` entry keeps `default-days` alone, with the reason in the comment; the semver split stays on the npm entry, where it is supported | The file is parsed on every verification and each entry's `cooldown` keys are checked against the ecosystem they belong to |
| D34 | **Ninety-day artifact retention, on artifacts with a one-run lifetime.** The build outputs are uploaded so the publish job can attach them, which happens inside the same run, after which the release is the durable copy. The default retention of ninety days meant every rebuild added roughly 175 MB that nothing would read again: 55 artifacts and 2.9 GB had accumulated, and the repository's own release page was carrying less data than its discard pile | `retention-days: 1` on the windows and linux uploads, and 14 on the coverage report, which is half a kilobyte and is the diagnostic to reach for after a failed gate | The value is stated in the workflow, and the artifact count is checked as part of the release verification |

The numbering in this file is a shared namespace across every section, and these seven were
first written as D22--D28 without checking that the Network layer had already reached D23. Two
of them collided. They are D24--D30 now, and the collision was found by counting the defined
identifiers rather than by reading, which is the only way that class of mistake shows up: a
duplicate number reads as perfectly normal in isolation, in both places.

---

## 4. Problems with the tests themselves

> A lying test is more dangerous than a buggy product. This section records where the
> **tests** were wrong, not the code.

| # | Symptom | Explanation |
|---|---|---|
| T1 | **The blackhole-timeout test passed for the wrong reason** | It used `https://127.0.0.1/...` (default port 443), the mock proxy's connection to 443 was refused, and the error actually came from the CONNECT stage -- **the TLS timeout branch was never reached at all**. Coverage caught it. Switched to an explicit port pointing at a blackhole server |
| T2 | selftest inlined a copy of a fixture, duplicating `test/fixtures.mjs` | A duplicated fixture means two sources of truth that drift apart independently. Extracted a shared module |
| T3 | Three assertions were written wrong | The PT inventory checked the wrong field; "bridges not enabled" under the minimal fixture was misjudged as a false positive; the content-layer recommendation was tested against a word that does not appear in the output |
| T4 | The mode assertion was written wrong | The original field reported the name of whatever program was hosting the process, so a subprocess inherited the parent's marker and reported that -- correct for that design, but it put host-specific names into a public tool. The field is now a neutral `mode` (`cli` vs `mcp`) derived purely from the entry script's directory, and the assertion tests that decision directly |
| T5 | **Flaky failure**: `direct connection returns JSON -> fetch failed (bad port)` | On Windows the dynamic port range can start at **1024** (measured with `netsh`; the usual default is 49152), while undici keeps a blacklist of "unsafe ports" (4045 / 4190 / 6000 / 6665-6669 / 10080 ...). A random port hits one roughly 0.3% of the time -- 1 hit in 300 samples, on port 4190. Fix: `listenForFetch()` detects a blacklisted port and retries on a new one; eight consecutive runs confirmed no recurrence |
| T6 | Another case of **passing for the wrong reason** | The "direct connection fails" test originally used port `9`, and **9 is itself on the blacklist**, so the error obtained was `bad port` rather than the expected "connection refused". Changed to take a port that fetch accepts and then close it, and to assert `!/bad port/` to lock down the intent |

The selftest PT assertion was also carrying a label that claimed "7 kinds" while the good
fixture loads 5, and it only checked for path residue -- a label that lied about what was
verified. It now asserts the exact expected set. This is the same failure mode as rule 8 of
the README's design discipline.

---

## 5. Known boundaries (honestly untested)

1. **Coverage is line coverage, not branch coverage.** When a ternary branch within a line
   is never reached, that line still counts as covered -- so **D8 (the tautological ternary)
   was found by human reading, and coverage cannot catch it**. This point cannot be skipped
   when reading the coverage number.
2. **The full TLS-over-tunnel round trip** is covered only by cross-checking against the
   live version lookup in `matrix`; there is no standalone test certificate fixture.
   Reproducing that path offline would require introducing a static test certificate
   (`.gitattributes` already reserves `*.pem binary`).
3. **The WinINET branch of `detectProxy`** is unreachable on non-Windows platforms (early
   return when `process.platform !== "win32"`). The parsing and the fallback of
   `readWininetProxy` are covered by injection, but the step of actually reading the
   registry is only executed on Windows.
4. **Traversers assert contracts and invariants**, which is not a proof that the audit
   conclusions are correct. That is covered by the semantic assertions in selftest, and
   semantic assertions still depend on the design of the fixtures -- situations the
   fixtures did not imagine are situations the tests cannot imagine either.
5. **Only one path has been exercised over the live network**: the official Tor Project
   release endpoint through a WinINET system proxy. The alpha channel, live SOCKS5, and
   proxy-authentication scenarios have not been verified in a real environment, though the
   protocol layer is covered by mocks.
6. **Coverage is platform dependent, and a single platform overstates what is missing.**
   Measured on Windows this file used to claim 11 uncovered lines. Measured on Linux the
   number is 40 -- and the two sets barely overlap, because each platform covers the branches
   the other cannot reach:

   | Measured on | Coverage | Uncovered, and why that platform cannot reach it |
   |---|---|---|
   | Windows | 1488/1499 = 99.3% | the macOS/Linux Firefox install candidates; the "no Firefox installed" branches |
   | Linux | 1459/1499 = 97.3% | the Windows drive-letter scan, the WinINET proxy read, the `C:\Program Files` candidates |
   | **Neither** | **1494/1499 = 99.7%** | the truth: only 5 lines are never executed anywhere |

   The five that neither platform reaches are `lib/core.mjs` 687--689 (the version read from a
   profile's `compatibility.ini`, which needs a profile that has one and an application that
   is not installed) and `lib/firefox.mjs` 163--164 (the macOS application path). Everything
   else in either list is exercised on the other platform, which is the argument for running
   the suite on both rather than treating one machine's number as the project's.

   None of them is covered by pretending otherwise. Pointing `findFirefoxApplication` at an
   empty directory does not reach the "not installed" line, because it then falls through to
   the platform candidates and finds the real install; an assertion written against that
   would pass for the wrong reason, which rule 6 of the design discipline forbids.

   The user-visible half of the same path **is** covered: `test/firefox.mjs` asserts the
   no-profile case end to end by repointing `APPDATA` / `USERPROFILE` / `HOME` at an empty
   directory, so what a user sees when Firefox has no profile is verified even though the
   "Firefox is not installed" line underneath it is not.

7. **The suite was only ever run on one platform, and that hid four real failures.** Running
   it on Linux for the first time failed `selftest` (161/165), `firefox` (141/142) and
   `mcp-smoke` (27/29). None of those was a defect in the tool -- `lib/` resolves the user
   directory with `os.homedir()`, which is the correct portable call -- but each was a real
   defect in the tests, and each would have failed CI on its first run:

   | Assertion | Why it was wrong |
   |---|---|
   | `case-variant alias normalizes to the same path` | asserted Windows path case-insensitivity as universal; on Linux the aliased path genuinely does not exist |
   | the `stray-traces` group | set only `USERPROFILE`, which `os.homedir()` reads on Windows and ignores everywhere else |
   | `a successful check resolved the local version` | required an installed Firefox, so it asserted a property of the machine rather than of the tool |
   | `audit returns findings` | same, for an installed Tor Browser |
   | `offline mode returns a local version` | same |

   The fixes assert the contract instead: a version is either a non-empty string or absent
   together with its source; an audit either returns findings or a structured error; the
   case-variant expectation follows from whether the filesystem is actually case-insensitive.
   `mcp-smoke.mjs` already carried a comment making exactly this point about `aragami_env`
   ("assert the shape, not a machine-wide count") -- the lesson had been learned once and not
   applied to the neighbouring calls, which is its own small lesson about comments.

8. **Coverage depended on whether the machine has a proxy, and the fix was a certificate.**
   `lib/net.mjs`'s `httpsGetOverSocket` -- writing the request after the tunnel's TLS
   handshake, and reading the response back -- is entered only when a proxy is configured, so
   on a machine without one it was never executed. That was the entire difference between the
   two environments:

   | Environment | net.mjs | total |
   |---|---|---|
   | Linux, with a proxy configured | 188/190 | 1459/1499 = 97.3% |
   | Linux, the same code with no proxy (the CI runner) | 164/190 | 1436/1499 = 95.8% |

   Both rows are Linux, so the two numbers differ only by the proxy variable -- which is the
   point of quoting them as a pair rather than one of them.

   The 26 lines were `net.mjs` 93, 196--204, 211--221 and 262--266. This file's own header said
   why: a full TLS-over-tunnel round trip needs a test certificate, and there wasn't one, so
   the only thing covering those lines was the live version lookup, which goes through the
   tunnel only when there is a tunnel to go through.

   `test/certs/` now holds a certificate for 127.0.0.1 and `test/net.mjs` runs a mock TLS
   server behind the mock CONNECT proxy. The trust cannot be arranged from inside the process --
   `NODE_EXTRA_CA_CERTS` is read at startup -- so the suite re-executes itself once with the
   variable set rather than letting that one test behave differently depending on how the file
   was invoked. The child inherits `NODE_V8_COVERAGE` and `coverage.mjs` merges overlapping
   ranges by taking the highest count, so nothing is lost to the extra process.

   | Environment | net.mjs | Uncovered on `net.mjs` | total |
   |---|---|---|---|
   | Windows, system proxy in WinINET | 190/190 | -- | 1488/1499 = 99.3% |
   | Linux, no proxy variable set | 189/190 | 93 | 1455/1499 = 97.1% |
   | Linux, proxy variable set | 188/190 | 92--93 | 1459/1499 = 97.3% |

   Three rows rather than two because platform and proxy are separate variables, and the first
   version of this table paired a Windows total with a Linux `net.mjs` count, which reads as one
   environment and is not. `detectProxy` accounts for the middle column exactly: it returns at
   line 89 when a proxy variable is set, so line 92's platform test is reached only where there
   is no variable to return from, and line 93, `readWininetProxy`, only on Windows. Off Windows
   189/190 is therefore the ceiling, and Linux reports one line lower *with* a proxy than
   without for a reason that has nothing to do with the tunnel.

   `net.mjs` measuring 190/190 on Windows is not an artifact of a proxy variable in the
   environment -- there is none, in the process or at user or machine scope. It is WinINET:
   `ProxyEnable=1` with `ProxyServer=127.0.0.1:8080`, and `detectProxy` reports back
   `source: "wininet:ProxyServer"`. That is the same mechanism the pre-fix Windows number came
   from, which is why Windows was never the environment that exposed this gap.

   The gate is back to 97, and it is now about regressions rather than about whether a proxy
   happened to be running. The runner itself reports 1461/1499 = 97.5% -- six lines above the
   local Linux figure, because a GitHub runner has Firefox installed and this machine does not,
   which is the platform effect of item 6 rather than the proxy effect of this one. The gate is
   set below both.

   Two things this leaves on the record. Any coverage figure quoted from a single machine is a
   figure about that machine -- the numbers above are quoted per environment for that reason,
   and the README carries both. And the certificate is a committed private key: it is for
   127.0.0.1 only, it grants nothing, and it is there so a local mock can complete a handshake.
   A suite that made those assertions pass by turning verification off would be worse than one
   that skipped them, so `test/net.mjs` asserts that `NODE_TLS_REJECT_UNAUTHORIZED` is unset
   alongside them.

---

## 6. Reproduce

```bash
npm test              # 54 + 277 calls, 0 violations + 60 + 142 + 195 + 94 + 735 + 113, exit code 0
npm run test:cov      # coverage report; --gap prints the detail of uncovered lines
npm run test:net      # network layer only
npm run test:matrix   # contract traversal only
npm run test:emblem    # the seal only; needs no source work
```

Everything described in this file is reproducible on any machine: `selftest`, `matrix`,
`firefox` and `emblem` use **synthetic fixtures** and do not depend on whether Tor Browser or
Firefox is actually installed, and `net` uses local mock servers rather than the external
network. The emblem suite goes one step further than the others on purpose: it never reads the
sealed work, because the claim it tests is that a machine without that work cannot open the
seal. A fixture that supplied the real bytes would test the opposite of the design.

One number above is machine dependent, and it is the coverage figure, which counts lines that
only execute on one platform. The Linux CI runner reports 97.5% and this Windows machine
reports 99.6%; neither figure is a superset of the other, so the README quotes both and the gate
sits at 97, below both. It fails when a path stops running, not when a different machine ran the
suite. The 11 lines uncovered on Windows are unchanged from before the catalog work while 961
meaningful lines were added, so the new modules carry no gap: `lib/checks.mjs` is 572/572 and
`lib/baseline.mjs` is 185/185 and `lib/checks.mjs` is 707/707. The four remaining lines in `core.mjs` (`resolveTarget`'s final
fallback and `resolveFirefoxLocal`'s profile path) need a machine with neither Tor Browser nor
Firefox installed, and the five in `firefox.mjs` are the macOS and Linux application paths.

---

## 7. Defects caught while adding the check catalog, the facts record and the baseline

All five were found by building the feature and reading what came out, rather than by testing
what was already believed to be true. Each is recorded with the shape of the mistake, because
the shapes repeat.

### D35. `safeStringify` confused a shared reference with a circular one

The audit response hands the **same** evidence object to `findings` and to `facts`. The
serializer tracked every object it had ever visited in a `WeakSet` and replaced any repeat with
the string `"[circular]"` -- so the second view of every shared object came out as that string,
and the facts record was in its entirety a set of `"[circular]"` markers. Nothing threw, nothing
failed, and `JSON.parse` was perfectly happy with it.

`JSON.stringify`'s replacer cannot see the ancestors of the current path, which is why the
original could not tell the two cases apart; the fix is a recursive walk that adds an object on
the way down and removes it on the way back, so only genuine self-reference is marked.

Found by printing a real response and reading it. The suites had only ever asserted that the
output was *serializable*, which it was.

### D36. Two suites pinned the tool count to a literal

`test/selftest.mjs` asserted `TOOLS.length === 4`, and `test/mcp-smoke.mjs` asserted a tool count
of 4. Adding two tools broke both, which is what they were for -- but they broke as a **number
mismatch** rather than as the property that actually matters. Replaced with what should have
been asserted all along: the MCP server exposes *exactly* the core's tools, names are unique,
every name matches `aragami_[a-z_]+`, and every description is passed through unchanged. A
hardcoded count also goes stale silently in the other direction -- it cannot tell you that one
tool disappeared and another appeared in its place.

### D37. The baseline could not be used the way anyone would actually use it

`aragami_baseline` in capture mode returns a **response**: `mode`, `baseline`, `audit_summary`,
`note`. Storing it by redirecting the output to a file is the obvious workflow, and what lands
in that file is the response, not the record. Passing that file to `--mode diff` failed with
`Unsupported baseline schema "aragami-baseline-report/1"` -- a message that describes the
symptom and gives no hint of the cause.

`unwrapBaseline` now accepts a response that carries a well-formed baseline inside it, for both
the inline and the file argument. Anything else still passes through to validation, which
refuses with a reason.

### D38. An empty mount table was treated as no mount table

The volume probe read `/proc/self/mountinfo` and tested it for truthiness. `""` is falsy, so a
table that was read successfully and happened to be empty fell through to the platform default
instead of being reported as "read it, and nothing covers this path". The two cases are
different and only one of them is a measurement: `null` means the read failed, `""` means it
succeeded and found nothing. The presence test is now on the type rather than on truthiness.

### D39. A privacy assertion passed for the wrong reason

The baseline's central claim is that it stores fingerprints and never evidence, and the test for
it was:

```js
check("no path reached a check entry", !JSON.stringify(b1.checks).includes(SECRET_PATH));
```

This can never fail on the platform where it most needs to hold. `SECRET_PATH` is
`E:\Tor Browser\...`; `JSON.stringify` escapes backslashes to `\\`, so the serialized text does
not contain the substring even when the path is sitting right there in the file. The assertion
now collects the string leaves of the **parsed** record and tests those, which is independent of
both escaping and key order. Re-verified against a baseline captured from a real install: 69
string leaves under `checks`, none of them a path, a guard name or a key filename.

The general shape: a negative assertion about serialized text is a test of the escaping as much
as of the content, and on Windows it passes for free.

### D40. The declared fact slot names described scalars that hold objects

The catalog's `fact` field started out as a path into the evidence (`metadata.state_size`), then
the record was changed to place the check's **whole evidence object** at that path so that no
two checks could silently overwrite each other. That left nineteen slot names reading like
scalars while holding `{size, mtime, last_written, guards, circuit_bins}` -- a documented schema
whose names lie about its own shape. Renamed to group labels (`metadata.state`, `transport.bridges`),
and the uniqueness of the 56 slots is now asserted by the suite.

### D41. Sixteen checks moved from code into the catalog, and the suites could not see it

The residue-style checks -- five `cache-*`, `pt-state`, `session-checkpoints`, `places`, the eight
Firefox residue files -- were rewritten as catalog entries driven by two new probes
(`path-residue`, `dir-entries`). The risk in a change like this is not that it breaks loudly; it
is that the numbers move and nobody notices which characters changed. Three things guard it:

1. The suites pin the specific evidence keys and per-id severities of the migrated checks, so a
   changed shape fails immediately rather than looking plausible.
2. `test/checks.mjs` asserts the **literal** rendered title of a migrated check, with the age
   pinned by dating a fake file a fixed offset back from now -- a hardcoded day count would have
   been a test that breaks on its own tomorrow, which is how the first version of this assertion
   was written.
3. The previous commit is the pre-migration code, so both can be run against the same real
   installation and compared field by field. `git worktree add --detach` at `HEAD` and an
   `aragami_audit` from each side gives: **Tor 23/23 and Firefox 21/21 findings identical in
   layer, severity, id, title, detail and evidence.** The only difference is the position of the
   migrated checks among findings of equal severity on the Firefox side, because they now run at
   the end of their auditor instead of where the `residue()` calls sat. Every field is the same;
   the array order within one severity is not, and the ordering tiebreak is an accident of
   assembly rather than a contract -- named in README section 9 rather than papered over.

### D42. The probe dispatcher guarded only its first branch

`evaluateOneBuiltin` was written as three branches on `entry.probe`. The first used `entry?.probe`
and the rest used `entry.probe`, so a null entry -- which the catalog tests construct, because the
catalog is data and data can be wrong -- reached the second branch and threw `Cannot read
properties of null`. Caught by the suite that was written for the new export, one call after the
export was added. The guard is now a single early return at the top of the function, with a
comment saying why per-branch guarding was the mistake.

The general shape: optional chaining applied to the first use of a value and not the rest is a
pattern that reads as defensive and is not, because it moves the failure rather than preventing it.

### D43. A security tool was carrying four advisories, and only one of them ships

`gh` reported the push with a banner: *"GitHub found 1 vulnerability on Nesarf/Aragami's default
branch (1 moderate)."* `npm audit` reported **four**, including one critical the banner did not
mention:

| package | version | severity | advisory |
|---|---|---|---|
| `proxy-addr` | 2.0.7 | **critical** | IP spoofing via IPv4-mapped IPv6 trust subnet (GHSA-jqcg-44mw-7w3h) |
| `ip-address` | 10.7.0 | moderate | `isInSubnet()` / `isHostInSubnet()` admit an address outside the range (GHSA-j6r3-76f7-8jcv) |
| `ip-address` | 10.7.0 | moderate | `Address6` parse diagnostic is unbounded in the input length (GHSA-h3mg-xc3c-68pw) |
| `fast-uri` | 3.1.7 | moderate | host case normalisation via percent-encoded octets (GHSA-hrr3-gc8f-f4qj) |

All four arrive through `@modelcontextprotocol/sdk`, and the interesting question is not the count
but **which of them reach a user**. That is a measurement, not a guess -- grep the built bundle:

    ip-address          0 occurrences in dist/mcp.cjs
    proxy-addr          0 occurrences in dist/mcp.cjs
    express-rate-limit  0 occurrences in dist/mcp.cjs
    express             2 occurrences (a string, not the module)
    fast-uri            6 occurrences   <-- this one ships

The first three come from the SDK's HTTP transport, and this tool only ever uses the stdio
transport, so esbuild never reaches them. `fast-uri` arrives through the schema validation that the
stdio path *does* use, so it is in the artifact users download. An advisory count is therefore not
by itself a statement about exposure, and the bundle was inspected rather than assumed.

`npm audit fix` resolved all four inside the existing semver ranges (`ip-address` 10.7.0 -> 10.7.3,
`proxy-addr` 2.0.7 -> 2.0.8, `fast-uri` 3.1.7 -> 3.1.8) with no change to `package.json`; the
runtime dependency count is still one.

The shape worth keeping: **a public advisory banner on a security tool costs more than the
advisory**, because it is the first thing a visitor sees, and the cheap fix is `npm audit fix`
rather than an argument about reachability. Fix first, then measure which part was reachable and
write that down.
---

## 9. Defects caught giving the installer an icon and a user interface

### D50. A habit, three times over: a double hyphen is not legal inside an XML comment

Every document in this project uses a double hyphen as a dash. XML comments cannot contain one, and
the MSI template is XML. The build refused twice in one sitting, each time naming a line in the
generated `.wxs` rather than the comment that caused it.

Recorded because the failure mode is quiet in the wrong direction: the comment is *prose*, so
nothing about writing it suggests a syntax rule, and the person most likely to paste one in is
whoever is documenting the file. `test/selftest.mjs` now asserts that no comment in the template
contains a double hyphen, which turns a build-time failure into a one-second local check.

### D51. `UIRef` is not how a WiX 4+ extension's dialog set is referenced

`<UIRef Id="WixUI_Minimal" />` is the WiX 3 form, and the form nearly every example still shows.
Under WiX 5 it fails with `WIX0094: The identifier 'WixUI:WixUI_Minimal' is inaccessible due to its
protection level`, which reads like a permissions problem and is a namespace one: WiX 4 moved
extension elements into their own namespace, so the dialog set is an *element*.

```xml
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs"
     xmlns:ui="http://wixtoolset.org/schemas/v4/wxs/ui">
  <ui:WixUI Id="WixUI_Minimal" />
```

Found by decoding the namespace URI out of the extension assembly: its strings are UTF-16, so a
plain `grep` over the DLL finds nothing and a UTF-16 decode finds it immediately.

### D52. A guard that carried its own copy of the rule it was guarding

The line-ending assertion added in the previous round listed the extensions it considered binary,
and `.bmp` was not among them, so the two installer bitmaps were reported as text files with CRLF
endings, a byte pair that occurs in them by chance. The fix is not to add `.bmp` to that list: it is
to **read the list out of `.gitattributes`**, which is the file git itself obeys. Two copies of the
same rule drift, which is a discipline entry this project already had.

### D53. The extension had to be pinned, and a successful build proves less than it looks

`wix extension add -g WixToolset.UI.wixext` installs the newest release, which was 7.0.0 against a
WiX 5 toolchain; the resulting error complains about the extension's internal package layout rather
than about versions. `pack-msi.ps1` therefore names `WixToolset.UI.wixext/5.0.2`.

This is also why the negative control mattered more than the build. A **successful** build is not
evidence that the committed images are the ones in the package: the UI extension ships default
bitmaps under the same stream names, so `WixUI_Bmp_Banner` and `WixUI_Bmp_Dialog` would be present
either way. Pointing the two variables at a nonexistent file makes the build fail with
`WIX0103: Cannot find the Binary file ... referenced from src/ext/UI/wixlib/Common.wxs(6)`, which is
what proves the extension consumes them, and therefore that the extracted package carries our
artwork rather than its defaults.

Also verified without installing, since installing needs elevation this session does not have: the
built package's `Property` table carries `ARPPRODUCTICON = AragamiIcon`, its `Icon` table carries a
stream of that name, and its `Dialog` table carries the nineteen dialogs of `WixUI_Minimal`.
### D54. A build that only worked because of something done by hand

Naming the extension in the build command is not enough. `wix build -ext <name>` resolves an
extension that is **already installed**; it does not fetch a missing one. Locally the extension was
present because it had been added by hand while finding out which reference form WiX 5 wanted, so
the build worked, and the release failed on a runner where nothing had added it: `WIX0144: The
extension 'WixToolset.UI.wixext/5.0.2' could not be found. Checked paths: WixToolset.UI.wixext/5.0.2`.

`pack-msi.ps1` now ensures the extension is present before it builds, which makes the local build
and the release build do the same thing. The fix was verified by removing the extension and running
the script, which is the CI condition reproduced exactly, rather than by trusting that a working
local build meant a working release.

The shape: **a prerequisite satisfied by hand is a prerequisite that will be missing somewhere
else**, and the local build cannot tell you which of its inputs came from the sources and which
came from your session.
---

## 10. Defects caught by installing the installer and looking at it

Every one of these was invisible to the build, to the suites, and to reading the package's tables.
They were found by running the thing on a machine with administrator rights and looking at the
result, which is the only place an installer's mistakes are visible. The starting point was a
correction from the user: this session *was* elevated, and the earlier claim that it was not had
been assumed rather than measured.

### D55. The dialog bitmap was full-bleed, so the wizard's text could not be read

The WiX dialog set draws its text **on** the dialog bitmap. The first composition filled all of
493x312 with the artwork, so on the page shown while the installer prepares, the words sat on a
high-contrast illustration and were unreadable.

The extension's own default answers what the layout expects: art on the **left**, plain light on
the **right**. The same image is used both as a full background and as a side panel, and only a
composition with a quiet half survives both. This is not discoverable from the schema or the
documentation; it is discoverable in about four seconds by looking at a screenshot.

### D56. Enabling the UI put a fake licence agreement in the installer

`WixUI_Minimal` has a licence page, and the extension ships **Lorem ipsum** as its default text.
Adding the dialog set therefore presented every user with a placeholder legal agreement, which is
worse than having no licence page at all. `WixUILicenseRtf` now points at an RTF generated from
`LICENSE`, and a check strips the RTF control words and compares the result with `LICENSE` word for
word -- a substring test is the wrong tool, because re-wrapping splits phrases across lines.

### D57. The left panel was anisotropically scaled, and the user saw it before any check did

The panel was drawn by cropping a **square** out of the artwork and resizing it to 150x312, which
compresses it horizontally to about 48%. The figure read as stretched vertically. Nothing in the
build objects: both steps are valid image operations and the output is a valid bitmap of the
required size.

The fix is to take the crop **at the target aspect ratio** in the artwork's own pixels and scale it
down uniformly, and the generator now asserts that both ratios agree rather than trusting that they
do. The wider lesson is the one worth keeping: **the user caught this, not a test.** A visual
property needs a visual check, and the cheap version of that check -- look at the thing once --
should not be skipped just because the build is green.

### D58. The package was x86, so it installed beside the 32-bit programs

`wix build` defaults to an Intel (32-bit) package. A 32-bit package cannot honour
`ProgramFiles64Folder`: the directory resolves to `Program Files (x86)` and the product registers in
the 32-bit half of the registry. Nothing in the repository could show this -- the build succeeds, CI
only builds, and the summary information stream that records the platform is not something anyone
reads. It took an actual install.

Worth recording about the process rather than only the defect: the README had claimed a real install
had been verified, and its wording mentioned "a path containing spaces and parentheses". The
parentheses were `Program Files (x86)`. **A symptom had been written down as a test case**, which is
what happens when the observation and the expectation arrive at the same time.

### D59. The verification script was wrong twice, in the ways verification scripts usually are

- The launcher check failed with "'aragami' is not recognized". The installer had done its job; the
  test ran in a shell whose `PATH` predated the install. A machine `PATH` change does not reach a
  process that is already running, so the test was measuring the session rather than the product.
- It asserted a `DisplayIcon` registry value. That is how a non-MSI entry advertises its icon; an
  MSI product's Add/Remove icon comes from the `ARPPRODUCTICON` property and the cached package.
  The absence was correct and the check was wrong.

Both were fixed before anything was concluded from them, and the second is the reason the final
script asserts the icon where it can actually be read -- the package's own tables -- instead of
repeating a working check somewhere it does not work.
---

## 11. Defects caught building the hand-off target

### D60. Reusing a check against a target it was not written for made it invent an answer

`aragami_handoff` reuses the three built-in onion-authorization checks rather than restating them,
which is the point of the catalog: they are declared for `handoff` as well as `tor`, and they are
gated on the bases a Tor install supplies. With no Tor install the bases are absent and they should
stay silent.

`onion-auth-absent` did not. It reads `bases.auth_dir`, and a base map that simply **lacks** that
key looks identical to a Tor install whose torrc **names no authorization directory** -- so pointing
the hand-off tool at a directory on a machine with no Tor at all produced the finding "Onion service
client authorization not configured". Nothing had been asked, and the tool answered.

The two cases are genuinely different claims:

    a Tor install was read, and its torrc names no ClientOnionAuthDir   -> not configured
    no Tor install was read at all                                      -> cannot say

The existing guard (`if (fromBase && !ctx.bases) return null`) only caught the second case when the
whole base map was absent, which is not how the hand-off context is built -- it always supplies a
map, because it always has a directory to describe.

**The fix is a precondition, not a predicate.** A variant names one key and asks one question about
it; `present` and `absent` cannot be combined, and deliberately so -- composition is where a data
table becomes a programming language. So `config-value` gained `require_base`: the name of a base
that must be present for the check to be able to answer *at all*, checked before any variant runs.
`onion-auth-absent` declares `require_base: "data_dir"`. It is a guard of exactly the kind the probe
already had, and it keeps the closed predicate vocabulary closed.

This is the same class as D38, where an empty mount table was read as "no encryption" because the
code tested truthiness rather than type. Both are the tool answering a question it had not been
given the information to answer, and both were found by exercising a path nobody had exercised.

The test that had encoded the old belief -- "an empty base map is read as not-configured" -- was
rewritten rather than deleted, and now asserts both halves separately: a described install with no
auth directory **is** reported, and an empty base map **is not**.

### D61. A fixture can pass an assertion for the wrong reason, and only a control catches it

The depth bound of the new `tree-match` probe was asserted with "a file beyond the bound is not
reported". The fixture that built the deep tree was written with nested joins and a `replace()` and
never produced a chain at all -- so nothing was found, and the assertion passed while testing
nothing.

The control added alongside it -- the same tree with `max_depth` raised, which **must** find the
file -- failed immediately and reported "the fixture is wrong, not the bound".

The rule worth keeping: **an assertion that something is absent needs a companion that shows it can
be present.** D59 records the other two shapes this took in the same project (a `PATH` that predated
the install, and a `DisplayIcon` value that MSI never writes); this one is the first where the
assertion was correct and the fixture was not.





---

## 8. Defects caught migrating the rest of the checks into the catalog

The second migration moved twenty more checks -- the four shape-only ones and the value-comparison
ones -- taking declarative coverage from 17 of 58 to 37 of 58. Everything below was found by
building it, and two of them are mistakes of mine rather than of the code that was there before.

### D44. `min_count` defaulted to 1, so `max_count: 0` could never match

`onion-auth-empty` expresses "the directory is configured but holds no keys" as `max_count: 0`. The
probe checked the lower bound first, and the lower bound defaulted to 1 -- so the check could never
fire, on any machine, ever. The suite caught it because that check is one the fixtures pin.

The fix is one field (`min_count: 0`), but the shape is worth keeping: **a default that makes one
of the two bounds unreachable turns a check into decoration**, and nothing about reading the entry
suggests it. `test/checks.mjs` now asserts it directly for every catalog entry -- an entry asking
for `max_count: 0` must say `min_count: 0`, and no entry may have `min_count > max_count`.

### D45. A whole layer's built-in checks were never evaluated

`bridge-blend` and `quickstart` are transport-layer checks. When they moved into the catalog they
were removed from `auditTransport` -- and nothing added a transport-layer `evaluateBuiltins` call,
because crypto, metadata and endpoint each had one and transport did not. Both checks simply
stopped running. The suite caught it: two assertions that had passed for months went red.

**A check that is catalogued but never reached is worse than a check that is missing**, because the
catalog still claims it and `unfired` in the audit report quietly lists it as "did not fire" --
which is indistinguishable from "fired and had nothing to say".

### D46. The cookie-policy labels were written from memory, not copied

`ff-cookie-behavior` renders a label per numeric preference value. Moving it into the catalog meant
retyping the label table, and I typed a different one: `2: "block all third-party"` where the code
says `"block all"`, `3: "block all"` where it says `"block from unvisited"`, `4: "block trackers"`
where it says `"block cross-site trackers"`, `5: "block trackers and partition third-party"` where
it says `"total cookie protection"`.

Every one of them is a plausible description of the same setting, which is what makes this the
dangerous kind of mistake: the output would have been *wrong but reasonable*, and no suite asserts
the label text. It was caught by reading the block being replaced instead of recalling it.

The rule this is an instance of: **when moving a literal, copy it.** A migration that retypes data
is a migration that can silently change it, and the only defence is that the fidelity comparison at
the end compares rendered output rather than structure.

### D47. Two dead `dir-size` branches, one shadowing the other

Writing the dir-size probe twice left two identical branch bodies in `evaluateOneBuiltin`, one
behind the other. The first one won every time, so the second was unreachable -- and because the
two differed in a single line (whether `file` was optional), the first also silently ignored a fix
that had been made in the second. Coverage found them: 25 lines of `lib/checks.mjs` at 97.6%.

### D48. The placeholder pattern rejected camelCase, so evidence kept its braces

`renderTemplate` and `renderEvidence` matched `\{([a-z_]+)\}`, which is fine for
`{trr_mode_label}` and wrong for `{cookieBehavior}`. The substitution silently did nothing and the
finding shipped with `"cookieBehavior": "{cookieBehavior}"` as its evidence value. Both patterns now
accept `[A-Za-z_][A-Za-z0-9_]*`.

The shape: **a template engine with a narrower pattern than its inputs fails open**, producing
output that looks like a template and reads as data. The suite now asserts that no rendered title
or detail leaves a placeholder unresolved, which is the assertion that would have caught it without
a fixture that happened to use a camelCase key.

### D49. An earlier statement of the coverage was wrong

The commit message for `57f3b99` says "Twenty-two of fifty-eight checks are declarative". The
number was seventeen. It was written from memory while the count lived one command away, and the
tests only assert the set -- nothing pinned the total, so nothing objected.

Corrected here and in the README rather than quietly, because the count is the figure a reader uses
to judge whether the migration is worth doing. It is now asserted: `test/checks.mjs` prints the
builtin and total counts on every run, so the number in the prose can be checked against the number
in the output.
