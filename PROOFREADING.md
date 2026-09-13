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
npm test              # 54 + 277 calls, 0 violations + 142 + 29 + 165 + 94, exit code 0
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
only execute on one platform. The Linux CI runner reports 1461/1499 = 97.5% and this Windows
machine reports 1488/1499 = 99.3%; neither figure is a superset of the other, so the README
quotes both and the gate sits at 97, below both. It fails when a path stops running, not when a
different machine ran the suite. Both figures here predate the emblem suite; the denominators
above are the current ones.
