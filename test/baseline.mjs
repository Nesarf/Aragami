#!/usr/bin/env node
/**
 * Baseline suite -- drives lib/baseline.mjs: canonical form, fingerprints, capture and drift.
 *
 * Why this needs its own suite:
 *
 *   1. The privacy claim is load-bearing and invisible. The module's central design decision
 *      is that a baseline stores FINGERPRINTS and never evidence, because a baseline that
 *      recorded guard names, key filenames or paths would be a tidy copy of exactly the
 *      residue the audit tells you not to keep. Nothing about a working baseline reveals
 *      whether that decision was honoured: a version that dumped the evidence into the file
 *      would compare and diff just as well. So the assertion below builds an audit whose
 *      evidence carries a recognisable marker, captures a baseline, and requires the marker
 *      to be ABSENT from the serialized result. That is the only way the claim can be tested
 *      rather than asserted in a comment.
 *
 *   2. Drift has more ways to refuse than to answer, and every refusal is a case where a
 *      plausible-looking diff would be wrong. Two records from different installs differ in
 *      almost every line and their difference is not drift; a moved check catalog makes
 *      checks appear and disappear without the machine having changed; a hostile baseline
 *      argument must produce a refusal rather than a crash. Each branch is asserted with an
 *      input that violates exactly that condition.
 *
 *   3. A fingerprint that is not stable is worse than none. The canonical form is asserted
 *      for key-order independence, which is the specific way this would rot: callers build
 *      evidence objects in whatever order the code happens to run, so an order-sensitive
 *      digest would report drift on every run while looking perfectly reasonable.
 *
 * Division of labour: matrix owns the output contract, selftest and firefox own target
 *   semantics, checks owns the catalog, coverage owns the traversal. This suite owns the
 *   baseline and nothing else.
 */

import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";
import fs from "node:fs";
import os from "node:os";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const B = await import(pathToFileURL(path.join(root, "lib/baseline.mjs")).href);
const { BASELINE_SCHEMA, canonical, fingerprintOf, baselineFrom, subjectOf, validateBaseline, diffBaselines, unwrapBaseline } = B;

let pass = 0, fail = 0;
const failures = [];
function check(name, cond, extra) {
  if (cond) { pass++; return; }
  fail++;
  failures.push(`${name}${extra ? ` -- ${extra}` : ""}`);
}

/* ====================== fixtures ====================== */

// A marker that must never reach a baseline. It stands in for a guard nickname, a key
// filename, a path -- anything the audit reports as sensitive residue.
const SECRET = "GuardNickname-ZZZTOP-42";
const SECRET_PATH = "E:\\Tor Browser\\Browser\\TorBrowser\\Data\\Tor";

const torAudit = (overrides = {}) => ({
  schema: "aragami-audit/1",
  tool_version: "0.1.0",
  target: "tor",
  tally: { warn: 1, info: 1 },
  install: { root: SECRET_PATH },
  checks: { catalog_version: "1", catalog_digest: "aaaaaaaaaaaaaaaa" },
  findings: [
    { layer: "metadata", severity: "warn", id: "state-file", title: "state", detail: "d",
      evidence: { size: 4096, guards: 22, nickname: SECRET, path: SECRET_PATH } },
    { layer: "endpoint", severity: "info", id: "disk-location", title: "disk", detail: "d",
      evidence: { drive: "E:", system_drive: "C:" } },
  ],
  ...overrides,
});

const ffAudit = () => ({
  schema: "aragami-audit/1",
  tool_version: "0.1.0",
  target: "firefox",
  tally: { info: 1 },
  profile: "C:\\Users\\x\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\abc.default",
  checks: { catalog_version: "1", catalog_digest: "aaaaaaaaaaaaaaaa" },
  findings: [
    { layer: "build", severity: "info", id: "ff-version", title: "v", detail: "d",
      evidence: { application_version: "142.0" } },
  ],
});

/* ====================== 1. canonical form ====================== */

check("canonical: primitives", canonical(1) === "1" && canonical("a") === '"a"' && canonical(true) === "true");
check("canonical: null and undefined agree", canonical(null) === "null" && canonical(undefined) === "null");
check("canonical: key order does not matter",
  canonical({ a: 1, b: 2 }) === canonical({ b: 2, a: 1 }),
  `${canonical({ a: 1, b: 2 })} vs ${canonical({ b: 2, a: 1 })}`);
check("canonical: nested key order does not matter",
  canonical({ x: { a: 1, b: 2 } }) === canonical({ x: { b: 2, a: 1 } }));
check("canonical: array order DOES matter",
  canonical([1, 2]) !== canonical([2, 1]));
check("canonical: arrays keep their order", canonical([1, 2, 3]) === "[1,2,3]");
check("canonical: distinct values stay distinct", canonical({ a: 1 }) !== canonical({ a: 2 }));

/* ====================== 2. fingerprints ====================== */

const fp1 = fingerprintOf({ a: 1, b: 2 });
const fp2 = fingerprintOf({ b: 2, a: 1 });
check("fingerprint is deterministic", fp1 === fingerprintOf({ a: 1, b: 2 }));
check("fingerprint ignores key order", fp1 === fp2, `${fp1} vs ${fp2}`);
check("fingerprint changes with the value", fp1 !== fingerprintOf({ a: 1, b: 3 }));
check("fingerprint is a short hex string", /^[0-9a-f]{16}$/.test(fp1), fp1);
check("fingerprint of nothing is defined", /^[0-9a-f]{16}$/.test(fingerprintOf(undefined)));
check("fingerprint of null differs from undefined's canonical partner by fixing it",
  fingerprintOf(null) === fingerprintOf(undefined));

// Unserialisable input (a BigInt is fine via canonical's JSON.stringify? it throws) must not
// blow up the capture: a baseline may not be able to fail the audit that produced it.
const cyclic = { n: 1 }; cyclic.self = cyclic;
let threw = false;
let cycFp = null;
try { cycFp = fingerprintOf(cyclic); } catch { threw = true; }
check("a cyclic evidence object does not throw", !threw);
check("a cyclic evidence object still fingerprints", typeof cycFp === "string" && cycFp.length === 16, String(cycFp));

const bigintFp = fingerprintOf({ n: 10n });
check("BigInt evidence fingerprints without throwing", /^[0-9a-f]{16}$/.test(bigintFp));

/* ====================== 3. capture ====================== */

const b1 = baselineFrom(torAudit(), { now: new Date("2026-09-14T10:00:00Z") });
check("baseline names its schema", b1.schema === BASELINE_SCHEMA);
check("baseline records the target", b1.target === "tor");
check("baseline records the subject", b1.subject === SECRET_PATH);
check("baseline records the capture time", b1.captured_at === "2026-09-14T10:00:00.000Z");
check("baseline records the tool version", b1.tool_version === "0.1.0");
check("baseline records the catalog version and digest",
  b1.catalog_version === "1" && b1.catalog_digest === "aaaaaaaaaaaaaaaa");
check("baseline carries the tally", b1.tally?.warn === 1);
check("baseline counts its checks", b1.check_count === 2, String(b1.check_count));
check("baseline keys checks by id", Object.keys(b1.checks).sort().join(",") === "disk-location,state-file");
check("baseline entry has layer, severity and fingerprint",
  typeof b1.checks["state-file"].layer === "string" &&
  b1.checks["state-file"].severity === "warn" &&
  /^[0-9a-f]{16}$/.test(b1.checks["state-file"].fingerprint));

// ---- the privacy claim ----
//
// Asserted over the PARSED record, not over the raw JSON text: JSON.stringify escapes
// backslashes, so a Windows path could sit in the file and still not match a plain
// `serialized.includes(path)`. A string-substring test against raw JSON would pass for the
// wrong reason on exactly the platform this is most likely to be run on.
const stringLeaves = (v, out = []) => {
  if (typeof v === "string") out.push(v);
  else if (v !== null && typeof v === "object") for (const k of Object.keys(v)) stringLeaves(v[k], out);
  return out;
};
const checkLeaves = stringLeaves(b1.checks);
const nonSubjectLeaves = stringLeaves({ ...b1, subject: null });

const serialized = JSON.stringify(b1);
check("PRIVACY: the baseline does not contain the residue marker", !serialized.includes(SECRET),
  "an evidence value reached the baseline");
check("PRIVACY: no check entry carries the subject path", !checkLeaves.some((s) => s.includes("Tor Browser")),
  checkLeaves.filter((s) => s.includes("Tor Browser")).join(" | "));
check("PRIVACY: nothing outside the subject field names the install",
  !nonSubjectLeaves.some((s) => s.includes("Tor Browser")),
  nonSubjectLeaves.filter((s) => s.includes("Tor Browser")).join(" | "));
check("PRIVACY: no evidence key survives anywhere in the record",
  !nonSubjectLeaves.some((s) => s.includes("nickname") || s.includes("guards")),
  nonSubjectLeaves.join(" | "));
check("the subject is recorded where it belongs", b1.subject === SECRET_PATH,
  String(b1.subject));

const b1b = baselineFrom(torAudit(), { now: new Date("2026-09-14T10:00:00Z") });
check("capture is deterministic for the same audit and time", JSON.stringify(b1) === JSON.stringify(b1b));

const later = baselineFrom(torAudit(), { now: new Date("2026-09-15T10:00:00Z") });
check("only the timestamp moves when nothing else does",
  later.captured_at !== b1.captured_at && later.checks["state-file"].fingerprint === b1.checks["state-file"].fingerprint);

check("a firefox audit keys on the profile", baselineFrom(ffAudit(), {}).subject === ffAudit().profile);
check("an empty audit still produces a usable baseline",
  baselineFrom({ target: "tor", findings: [] }, {}).check_count === 0);
check("findings without an id are skipped",
  baselineFrom({ target: "tor", findings: [{ layer: "x", severity: "ok" }, null] }, {}).check_count === 0);
check("baselineFrom tolerates a missing findings array", baselineFrom({}, {}).check_count === 0);
check("baselineFrom tolerates null", baselineFrom(null, {}).check_count === 0);

// Worst severity wins when an id appears twice, because that is the conservative reading.
const worsened = baselineFrom({
  target: "tor",
  findings: [
    { layer: "metadata", severity: "info", id: "state-file", evidence: { a: 1 } },
    { layer: "metadata", severity: "warn", id: "state-file", evidence: { a: 2 } },
  ],
}, {});
check("the worst severity of a repeated id is kept", worsened.checks["state-file"].severity === "warn",
  worsened.checks["state-file"].severity);

check("subjectOf reads the install root for tor", subjectOf(torAudit()) === SECRET_PATH);
check("subjectOf reads the profile for firefox", subjectOf(ffAudit()) === ffAudit().profile);
check("subjectOf tolerates junk", subjectOf(null) === null && subjectOf(42) === null);

/* ====================== 4. accept what a caller actually has ====================== */

// Redirecting the capture output to a file is the obvious way to keep a baseline, and what
// lands in that file is the whole RESPONSE, not the bare record. Refusing it would make the
// natural workflow fail on the first attempt with a schema error that does not explain itself.
const captureResponse = {
  schema: "aragami-baseline-report/1",
  tool_version: "0.1.0",
  mode: "capture",
  baseline: b1,
  audit_summary: { target: "tor", subject: SECRET_PATH },
  boundary_notice: ["...", "...", "...", "..."],
};
check("a capture response is unwrapped to its record", unwrapBaseline(captureResponse) === b1);
check("a bare record passes through unchanged", unwrapBaseline(b1) === b1);
check("junk passes through so validation can explain it", unwrapBaseline({ a: 1 }).a === 1);
check("null passes through", unwrapBaseline(null) === null);
check("an array passes through", Array.isArray(unwrapBaseline([1, 2])));
check("a response whose baseline is malformed is NOT unwrapped",
  unwrapBaseline({ baseline: { schema: "nope" } }).baseline.schema === "nope");
check("a response with no baseline of its own is not mistaken for one",
  unwrapBaseline({ schema: BASELINE_SCHEMA, checks: {} }).schema === BASELINE_SCHEMA);

const wrappedDiff = diffBaselines(unwrapBaseline(captureResponse), baselineFrom(torAudit(), {}));
check("a wrapped baseline diffs like a bare one", wrappedDiff.verdict === "no-drift", wrappedDiff.verdict);

/* ====================== 5. validation ====================== */

const V = (b, why) => check(why, validateBaseline(b).ok === false && typeof validateBaseline(b).reason === "string");
V(null, "validate: null is refused");
V(42, "validate: a number is refused");
V([], "validate: an array is refused");
V({}, "validate: a missing schema is refused");
V({ schema: "something-else/9" }, "validate: a foreign schema is refused");
V({ schema: BASELINE_SCHEMA }, "validate: a missing checks object is refused");
V({ schema: BASELINE_SCHEMA, checks: [] }, "validate: an array of checks is refused");
V({ schema: BASELINE_SCHEMA, checks: {} }, "validate: an empty checks object is refused");
V({ schema: BASELINE_SCHEMA, checks: { a: 1 } }, "validate: a non-object entry is refused");
V({ schema: BASELINE_SCHEMA, checks: { a: {} } }, "validate: an entry without a fingerprint is refused");
V({ schema: BASELINE_SCHEMA, checks: { a: { fingerprint: 1, severity: "ok" } } }, "validate: a non-string fingerprint is refused");
V({ schema: BASELINE_SCHEMA, checks: { a: { fingerprint: "x" } } }, "validate: an entry without a severity is refused");
check("validate: a real baseline passes", validateBaseline(b1).ok === true);
check("validate: a refusal explains itself", /schema/i.test(validateBaseline({}).reason));

/* ====================== 5. drift ====================== */

const dNoDrift = diffBaselines(b1, baselineFrom(torAudit(), { now: new Date("2026-09-20T00:00:00Z") }));
check("no change is no-drift", dNoDrift.verdict === "no-drift", dNoDrift.verdict);
check("no-drift is comparable", dNoDrift.comparable === true);
check("no-drift counts the unchanged checks", dNoDrift.summary.unchanged === 2, JSON.stringify(dNoDrift.summary));
check("no-drift has empty lists",
  dNoDrift.added.length === 0 && dNoDrift.removed.length === 0 && dNoDrift.changed.length === 0 && dNoDrift.severity_moved.length === 0);
check("no-drift reports both timestamps",
  dNoDrift.baseline.captured_at === b1.captured_at && dNoDrift.current.captured_at !== b1.captured_at);

// A changed evidence value is drift even when the severity is identical.
const changedAudit = torAudit();
changedAudit.findings[0] = { ...changedAudit.findings[0], evidence: { size: 8192, guards: 30, nickname: SECRET, path: SECRET_PATH } };
const dChanged = diffBaselines(b1, baselineFrom(changedAudit, {}));
check("a changed fingerprint is drift", dChanged.verdict === "drift");
check("the changed check is named", dChanged.changed.length === 1 && dChanged.changed[0].id === "state-file", JSON.stringify(dChanged.changed));
check("the changed entry carries its layer", dChanged.changed[0].layer === "metadata");

// A check that stops firing.
const fewer = torAudit();
fewer.findings = [fewer.findings[1]];
const dRemoved = diffBaselines(b1, baselineFrom(fewer, {}));
check("a check that stops firing is removed", dRemoved.removed.includes("state-file"), JSON.stringify(dRemoved));
check("the surviving check is unchanged", dRemoved.summary.unchanged === 1);

// A check that starts firing.
const more = torAudit();
more.findings = [...more.findings, { layer: "crypto", severity: "warn", id: "hs-keys", evidence: { dir: SECRET_PATH } }];
const dAdded = diffBaselines(b1, baselineFrom(more, {}));
check("a new check is added", dAdded.added.includes("hs-keys"), JSON.stringify(dAdded));

// Severity movement, in both directions.
const sevUp = torAudit();
sevUp.findings[0] = { ...sevUp.findings[0], severity: "critical" };
const dUp = diffBaselines(b1, baselineFrom(sevUp, {}));
check("a severity increase is reported", dUp.severity_moved.some((x) => x.id === "state-file" && x.direction === "worsened"),
  JSON.stringify(dUp.severity_moved));
check("the move names both ends", dUp.severity_moved[0].from === "warn" && dUp.severity_moved[0].to === "critical");

const sevDown = torAudit();
sevDown.findings[0] = { ...sevDown.findings[0], severity: "info" };
const dDown = diffBaselines(b1, baselineFrom(sevDown, {}));
check("a severity decrease is reported as improved", dDown.severity_moved.some((x) => x.direction === "improved"));
check("a severity move with the same evidence is not also a content change", dDown.changed.length === 0);

// ---- refusals ----
const dSubject = diffBaselines(b1, baselineFrom(ffAudit(), {}));
check("a different subject refuses to diff", dSubject.verdict === "subject-mismatch" && dSubject.comparable === false,
  dSubject.verdict);
check("the refusal names both subjects",
  dSubject.subjects.baseline === SECRET_PATH && dSubject.subjects.current === ffAudit().profile);
check("a refused diff produces no lists", dSubject.added.length === 0 && dSubject.summary === null);

const otherTor = torAudit({ install: { root: "F:\\Other\\Tor Browser" } });
const dTarget = diffBaselines(b1, baselineFrom(otherTor, {}));
check("a different install is a subject mismatch too", dTarget.verdict === "subject-mismatch", dTarget.verdict);

const dInvalid = diffBaselines(null, b1);
check("an unusable baseline is refused", dInvalid.verdict === "invalid-baseline" && dInvalid.comparable === false);
check("the refusal says which side was bad", /Baseline:/.test(dInvalid.reason), dInvalid.reason);
const dInvalid2 = diffBaselines(b1, { schema: "nope" });
check("an unusable current side is refused too", dInvalid2.verdict === "invalid-baseline" && /Current:/.test(dInvalid2.reason));

// A moved catalog must not read as drift.
const otherCatalog = baselineFrom(torAudit({ checks: { catalog_version: "2", catalog_digest: "bbbbbbbbbbbbbbbb" } }), {});
const dCatalog = diffBaselines(b1, otherCatalog);
check("a catalog change is flagged", dCatalog.catalog_changed === true);
check("a catalog change is not itself drift", dCatalog.verdict === "no-drift", dCatalog.verdict);
check("a catalog change explains itself", typeof dCatalog.note === "string" && dCatalog.note.includes("catalog"));
check("an unchanged catalog is not flagged",
  diffBaselines(b1, baselineFrom(torAudit(), {})).catalog_changed === false);

// A record from a newer baseline schema is refused, not half-read.
const dSchema = diffBaselines({ ...b1, schema: "aragami-baseline/99" }, b1);
check("a future schema version is refused", dSchema.verdict === "invalid-baseline", dSchema.verdict);

// Same subject, different target. This is the one refusal that a subject check alone cannot
// catch, so the two records are built by hand: baselineFrom would never produce this pair.
const samePlace = { schema: BASELINE_SCHEMA, subject: "X", checks: b1.checks };
const dTargetOnly = diffBaselines({ ...samePlace, target: "tor" }, { ...samePlace, target: "firefox" });
check("the same subject under a different target is refused", dTargetOnly.verdict === "target-mismatch", dTargetOnly.verdict);
check("the target refusal names both targets", /tor/.test(dTargetOnly.reason) && /firefox/.test(dTargetOnly.reason),
  dTargetOnly.reason);
check("the target refusal still reports both subjects", dTargetOnly.subjects.baseline === "X");
check("a missing target on either side is not a mismatch",
  diffBaselines({ ...samePlace }, { ...samePlace, target: "tor" }).verdict === "no-drift");

// The diff must not leak evidence either.
check("PRIVACY: the diff report does not contain the residue marker", !JSON.stringify(dChanged).includes(SECRET));

/* ====================== 6. the tool surface ====================== */
// The functions above are the mechanism; these are the two ways a caller actually reaches it
// through aragami_baseline. The branches below are the ones a caller hits by accident -- a
// target with nothing to audit, a path that is not there, a file that is not JSON -- and each
// has to produce a stated refusal rather than a thrown error.
const { TOOLS } = await import(pathToFileURL(path.join(root, "lib", "core.mjs")).href);
const baselineTool = TOOLS.find((t) => t.name === "aragami_baseline");
check("the baseline tool exists", typeof baselineTool?.execute === "function");

const noTarget = await baselineTool.execute({ target: "tor", install: path.join(root, "no", "such", "install") });
check("an audit with nothing to audit is reported, not thrown",
  typeof noTarget.error === "string" && noTarget.mode === "capture", JSON.stringify(noTarget).slice(0, 160));
const noTargetDiff = await baselineTool.execute({ mode: "diff", target: "tor", install: path.join(root, "no", "such", "install") });
check("the error path still names its mode", noTargetDiff.mode === "diff");

const tmpFile = path.join(os.tmpdir(), `aragami-baseline-${process.pid}.json`);
fs.writeFileSync(tmpFile, JSON.stringify(b1), "utf8");
const viaPath = await baselineTool.execute({ mode: "diff", baseline_path: tmpFile });
// Whether this diffs clean depends on what is installed on the machine running the suite, so
// the assertion is about the FILE-READING branch rather than about the verdict: the point is
// that a valid file is read and handed to the diff instead of being reported as unreadable.
check("a valid baseline file is read rather than refused",
  !String(viaPath.reason ?? "").includes("Could not read"), String(viaPath.reason));
check("reading a valid file reaches the diff",
  ["no-drift", "drift", "subject-mismatch", "target-mismatch"].includes(viaPath.verdict), String(viaPath.verdict));

// The full round trip -- capture, write, read back, diff against the same machine -- only
// means anything where there is something to audit, so it is asserted either way: a clean
// diff where a target exists, and an honest error where one does not.
const cap = await baselineTool.execute({});
fs.writeFileSync(tmpFile, JSON.stringify(cap.baseline ?? {}), "utf8");
const self = await baselineTool.execute({ mode: "diff", baseline_path: tmpFile });
if (cap.baseline) {
  check("capture, write, read back and diff against the same machine is no-drift",
    self.verdict === "no-drift", `${self.verdict}: ${JSON.stringify(self.summary)}`);
} else {
  check("capture with nothing to audit reports an error instead of a baseline",
    typeof cap.error === "string" && self.verdict === "invalid-baseline", String(cap.error));
}

const badPath = await baselineTool.execute({ mode: "diff", baseline_path: path.join(os.tmpdir(), "aragami-not-here-xyz.json") });
check("an unreadable baseline path is refused", badPath.verdict === "invalid-baseline" && badPath.comparable === false,
  badPath.verdict);
check("the refusal names the path it tried", String(badPath.reason).includes("aragami-not-here-xyz"), badPath.reason);

fs.writeFileSync(tmpFile, "not json at all", "utf8");
const notJson = await baselineTool.execute({ mode: "diff", baseline_path: tmpFile });
check("a file that is not JSON is refused", notJson.verdict === "invalid-baseline", notJson.verdict);

// The end-to-end shape of how this is actually used: capture, redirect, hand the file back.
const fullCapture = await baselineTool.execute({});
if (fullCapture.baseline) {
  fs.writeFileSync(tmpFile, JSON.stringify(fullCapture), "utf8");
  const fromEnvelopeFile = await baselineTool.execute({ mode: "diff", baseline_path: tmpFile });
  check("a file holding a whole capture response diffs against the same machine",
    fromEnvelopeFile.verdict === "no-drift", `${fromEnvelopeFile.verdict}: ${JSON.stringify(fromEnvelopeFile.summary)}`);
  const fromEnvelopeInline = await baselineTool.execute({ mode: "diff", baseline: fullCapture });
  check("a capture response passed inline diffs too", fromEnvelopeInline.verdict === "no-drift",
    fromEnvelopeInline.verdict);
} else {
  check("a file holding a whole capture response diffs against the same machine", typeof fullCapture.error === "string");
  check("a capture response passed inline diffs too", typeof fullCapture.error === "string");
}
fs.rmSync(tmpFile, { force: true });

const noBaseline = await baselineTool.execute({ mode: "diff" });
check("diff without a baseline refuses", noBaseline.verdict === "no-baseline" && noBaseline.comparable === false);
check("the no-baseline refusal tells the caller what to pass",
  String(noBaseline.reason).includes("baseline_path"), noBaseline.reason);
check("the no-baseline refusal still reports the current state",
  typeof noBaseline.current?.captured_at === "string");

/* ====================== summary ====================== */

console.log(`  baseline schema ${BASELINE_SCHEMA}; capture/diff exercised over ${Object.keys(b1.checks).length} checks per record`);
console.log(`\n  passed ${pass} / ${pass + fail}`);
if (fail) {
  console.log("\n  failures:");
  for (const f of failures) console.log(`    ${f}`);
  process.exit(1);
}
