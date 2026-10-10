/**
 * Aragami - posture baseline and drift
 *
 * The idea is borrowed from integrity-baseline tools: posture at rest is one question, and
 * posture DRIFT is a different, often more useful one. A single audit tells you what the
 * configuration looks like now; it cannot tell you that a guard set quietly grew, a profile
 * gained a Sync linkage, or a residue file appeared since last week.
 *
 * Two properties make this fit a static auditor rather than turning it into a monitor:
 *
 *   1. It stays one-shot and stateless. There is no daemon, no database and no schedule. The
 *      caller captures a baseline whenever it likes, keeps it wherever it likes, and hands it
 *      back when it wants a comparison. This module never writes a file.
 *
 *   2. A baseline stores FINGERPRINTS, never evidence. This is a deliberate and load-bearing
 *      choice: the audit's whole argument is that state, guard sets, key filenames and paths
 *      are the sensitive residue. A baseline that recorded them would be a new forensic asset
 *      -- a tidy summary of exactly what the tool tells you not to keep. So each entry keeps
 *      a digest of the evidence, which is enough to detect a change and useless to an
 *      adversary who obtains it.
 *
 * What this cannot do, stated plainly: a fingerprint change says something moved, not what
 * moved or whether it matters. The audit that produced it is where the meaning lives, which
 * is why a diff always carries the boundary notice too.
 */

import { createHash } from "node:crypto";

export const BASELINE_SCHEMA = "aragami-baseline/1";

/** Digest length. Long enough that a collision is not a practical concern for this use. */
const DIGEST_CHARS = 16;

/**
 * Canonical JSON: object keys sorted recursively, so a fingerprint depends on the values and
 * not on the order a caller happened to build the object in.
 */
export function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value ?? null);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
}

/**
 * Fingerprint of one finding's evidence.
 *
 * Evidence is arbitrary caller-adjacent data, so anything unsupported (functions, symbols,
 * cycles) degrades to a stable marker rather than throwing: a baseline must not be able to
 * fail the audit that produced it.
 */
export function fingerprintOf(evidence) {
  let text;
  try {
    text = canonical(evidence ?? null);
  } catch {
    text = "[unserialisable]";
  }
  return createHash("sha256").update(text).digest("hex").slice(0, DIGEST_CHARS);
}

/**
 * Build a baseline out of an audit result.
 *
 * @param {object} audit result of aragami_audit
 * @param {{now?:Date}} opts
 */
export function baselineFrom(audit, opts = {}) {
  const findings = Array.isArray(audit?.findings) ? audit.findings : [];
  const now = opts.now instanceof Date ? opts.now : new Date();
  const checks = {};
  for (const f of findings) {
    if (!f || typeof f.id !== "string") continue;
    // Last write wins only if a run ever emitted the same id twice; in practice an id is
    // emitted once per run, and keeping the worst severity is the conservative choice.
    const prev = checks[f.id];
    if (!prev || sevRank(f.severity) > sevRank(prev.severity)) {
      checks[f.id] = { layer: f.layer, severity: f.severity, fingerprint: fingerprintOf(f.evidence) };
    }
  }
  return {
    schema: BASELINE_SCHEMA,
    target: audit?.target ?? null,
    subject: subjectOf(audit),
    captured_at: now.toISOString(),
    tool_version: audit?.tool_version ?? null,
    catalog_version: audit?.checks?.catalog_version ?? null,
    catalog_digest: audit?.checks?.catalog_digest ?? null,
    tally: audit?.tally ?? null,
    check_count: Object.keys(checks).length,
    checks,
  };
}

/** The audited subject: what a drift comparison is only meaningful within. */
export function subjectOf(audit) {
  if (!audit || typeof audit !== "object") return null;
  if (audit.target === "firefox") return audit.profile ?? null;
  return audit.install?.root ?? null;
}

const SEV = { ok: 0, info: 1, warn: 2, critical: 3 };
const sevRank = (s) => SEV[s] ?? -1;

/**
 * Accept a capture RESPONSE as well as a bare baseline record.
 *
 * Redirecting the capture output to a file is the obvious way to keep a baseline, and what
 * lands in that file is the whole response -- mode, baseline, audit_summary, note. Refusing it
 * would make the natural workflow fail on the first try with a schema error that says nothing
 * about what the caller did wrong, so a response that carries a well-formed baseline inside it
 * is unwrapped instead. Anything else is passed through unchanged and refused by
 * validateBaseline with a reason.
 */
export function unwrapBaseline(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return value;
  const inner = value.baseline;
  if (inner !== null && typeof inner === "object" && !Array.isArray(inner) && inner.schema === BASELINE_SCHEMA) {
    return inner;
  }
  return value;
}

/**
 * Validate a caller-supplied baseline.
 *
 * The argument comes from outside, so it is treated as hostile input: a wrong shape must
 * produce a clear refusal, never a crash or a nonsense diff.
 */
export function validateBaseline(b) {
  if (b === null || typeof b !== "object" || Array.isArray(b)) {
    return { ok: false, reason: "A baseline must be a JSON object." };
  }
  if (b.schema !== BASELINE_SCHEMA) {
    return { ok: false, reason: `Unsupported baseline schema ${JSON.stringify(b.schema ?? null)}; this build produces ${BASELINE_SCHEMA}.` };
  }
  if (b.checks === null || typeof b.checks !== "object" || Array.isArray(b.checks)) {
    return { ok: false, reason: "The baseline has no checks object." };
  }
  const count = Object.keys(b.checks).length;
  if (count === 0) {
    return { ok: false, reason: "The baseline records no checks, so nothing could be compared against it." };
  }
  // A baseline is data, not code: anything non-plain inside it is refused rather than walked.
  for (const [id, v] of Object.entries(b.checks)) {
    if (typeof id !== "string" || v === null || typeof v !== "object" || Array.isArray(v)) {
      return { ok: false, reason: `The baseline entry for ${JSON.stringify(id)} is not an object.` };
    }
    if (typeof v.fingerprint !== "string" || typeof v.severity !== "string") {
      return { ok: false, reason: `The baseline entry for ${JSON.stringify(id)} lacks a fingerprint or severity.` };
    }
  }
  return { ok: true };
}

/**
 * Compare two baselines and describe the drift.
 *
 * Deliberately refuses in two situations rather than producing a number that looks like an
 * answer: an unusable baseline, and a subject mismatch (the two records describe different
 * installs or profiles, so their difference is not drift).
 *
 * A catalog change is NOT a refusal. When the check surface moved, the comparison is
 * restricted to the checks both records actually carry, and the ids present on only one side
 * are listed separately -- otherwise every catalog edit would silently read as drift.
 */
export function diffBaselines(base, current) {
  const v = validateBaseline(base);
  const cur = validateBaseline(current);
  if (!v.ok) return refusal("invalid-baseline", `Baseline: ${v.reason}`);
  if (!cur.ok) return refusal("invalid-baseline", `Current: ${cur.reason}`);

  const baseSubject = base.subject ?? null;
  const curSubject = current.subject ?? null;
  if (baseSubject !== curSubject) {
    return {
      ...refusal("subject-mismatch",
        "The baseline and the current audit describe different subjects. Drift is only meaningful within one install or profile."),
      subjects: { baseline: baseSubject, current: curSubject },
    };
  }
  if (base.target && current.target && base.target !== current.target) {
    return {
      ...refusal("target-mismatch",
        `The baseline is for ${base.target} and the current audit is for ${current.target}.`),
      subjects: { baseline: baseSubject, current: curSubject },
    };
  }

  const catalogChanged = base.catalog_digest !== current.catalog_digest;
  const baseIds = Object.keys(base.checks);
  const curIds = Object.keys(current.checks);
  const baseSet = new Set(baseIds);
  const curSet = new Set(curIds);

  const added = curIds.filter((id) => !baseSet.has(id)).sort();
  const removed = baseIds.filter((id) => !curSet.has(id)).sort();

  const changed = [];
  const severity_moved = [];
  let unchanged = 0;
  for (const id of curIds) {
    if (!baseSet.has(id)) continue;
    const a = base.checks[id];
    const b = current.checks[id];
    const ra = sevRank(a.severity);
    const rb = sevRank(b.severity);
    if (ra !== rb) {
      severity_moved.push({
        id,
        from: a.severity,
        to: b.severity,
        direction: rb > ra ? "worsened" : "improved",
      });
    }
    if (a.fingerprint !== b.fingerprint) {
      changed.push({ id, layer: b.layer ?? a.layer ?? null, severity: b.severity });
    } else if (ra === rb) {
      unchanged++;
    }
  }
  severity_moved.sort((x, y) => (x.id < y.id ? -1 : 1));
  changed.sort((x, y) => (x.id < y.id ? -1 : 1));

  const driftCount = added.length + removed.length + changed.length + severity_moved.length;

  return {
    verdict: driftCount === 0 ? "no-drift" : "drift",
    comparable: true,
    catalog_changed: catalogChanged,
    baseline: {
      schema: base.schema,
      captured_at: base.captured_at ?? null,
      tool_version: base.tool_version ?? null,
      catalog_digest: base.catalog_digest ?? null,
      check_count: baseIds.length,
    },
    current: {
      schema: current.schema,
      captured_at: current.captured_at ?? null,
      tool_version: current.tool_version ?? null,
      catalog_digest: current.catalog_digest ?? null,
      check_count: curIds.length,
    },
    subject: baseSubject,
    summary: {
      added: added.length,
      removed: removed.length,
      changed: changed.length,
      severity_moved: severity_moved.length,
      unchanged,
    },
    added,
    removed,
    changed,
    severity_moved,
    note: catalogChanged
      ? "The check catalog differs between these two records, so only checks present in both were compared. " +
        "A check that appears on one side only is listed under added or removed and is not evidence that the machine changed."
      : null,
  };
}

function refusal(verdict, reason) {
  return {
    verdict,
    comparable: false,
    reason,
    baseline: null,
    current: null,
    summary: null,
    added: [],
    removed: [],
    changed: [],
    severity_moved: [],
  };
}
