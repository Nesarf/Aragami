/**
 * The emblem: a sealed statement of what this project is named after.
 *
 * WHAT THIS IS. `Aragami`, at the repository root and in every package, is an
 * AES-256-GCM seal over a short text describing the work the project takes its
 * name from. The key is derived from that work's own content digest, so the
 * seal opens only where the work itself is present.
 *
 * WHAT THIS IS NOT, stated plainly because this project's rules require it. No
 * confidentiality is claimed and none is provided: anyone holding the source
 * work can derive the key and open the seal, which is the entire design. The
 * repository alone cannot open it, and that is the only access property worth
 * naming. The GCM tag means a modified seal fails to open rather than opening
 * to something else, so the emblem is tamper-evident. It is not a credential,
 * not an authorization, and not a security control, and nothing in the tool
 * should be made to depend on it for safety.
 *
 * The key material is never stored. Only the salt, nonce and tag are, none of
 * which are secret.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";

export const EMBLEM_FORMAT = "aragami-emblem/1";
/** The digest the key is derived from, named so a reader knows what to hold. */
export const EMBLEM_KEY_SOURCE = "source-sha256";
export const EMBLEM_KDF = "hkdf-sha256";
export const EMBLEM_CIPHER = "aes-256-gcm";
export const EMBLEM_FILE = "Aragami";

const SALT_BYTES = 16;
const NONCE_BYTES = 12;
const KEY_BYTES = 32;

/**
 * The seal, inlined at bundle time for the single-file executable, which has no
 * files beside it to read. In a normal ESM run the identifier is undeclared and
 * `typeof` reports that without throwing; esbuild's `define` substitutes the
 * literal in the bundle, where the string is then the operand of typeof. Both
 * paths are intended, and neither is a fallback that hides a failure: if the
 * inlined value is absent the loader below reads from disk, and if that fails
 * too the emblem is simply reported as absent.
 */
const INLINED = typeof __ARAGAMI_EMBLEM__ !== "undefined" ? __ARAGAMI_EMBLEM__ : null;

/**
 * The directory this module lives in, or null when the environment does not say.
 *
 * The CJS bundle has no import.meta: esbuild substitutes an empty object for it, so the
 * property reads as undefined instead of the expression throwing. This used to be a bare
 * `fileURLToPath(import.meta.url)` at module scope, which threw on load and stopped the
 * bundled CLI and MCP from starting at all -- the bundler warned, the warning was treated
 * as noise, and nothing exercised the built entry point. Checking the type rather than
 * trusting it costs one comparison and makes the module loadable in both worlds.
 *
 * Null is not a degraded state here. The bundle carries the seal inline and never needs the
 * directory; only an unbundled run does, and there import.meta is present.
 */
const META_URL = import.meta.url;
const MODULE_DIR = typeof META_URL === "string" ? path.dirname(fileURLToPath(META_URL)) : null;

/**
 * Where the seal may sit.
 *
 *   lib/../Aragami         repository layout, and the source install
 *   lib/Aragami            a flat install
 *   <entry>/../Aragami     the bundled layout: <package>/dist/<entry>
 *   <entry>/Aragami        a bundle placed beside the seal
 *   cwd/Aragami            a caller that keeps the file in its working directory
 *
 * The entry-point candidates matter because the bundle is the shipped artifact and the
 * module directory is the one thing it cannot report. A single-file executable has no file
 * path at all, which is what the inline above is for.
 */
function emblemCandidates() {
  const out = [];
  if (MODULE_DIR) out.push(path.join(MODULE_DIR, "..", EMBLEM_FILE), path.join(MODULE_DIR, EMBLEM_FILE));
  const entry = process.argv[1];
  if (typeof entry === "string" && entry) {
    const dir = path.dirname(entry);
    out.push(path.join(dir, "..", EMBLEM_FILE), path.join(dir, EMBLEM_FILE));
  }
  out.push(path.join(process.cwd(), EMBLEM_FILE));
  return out;
}

/**
 * Read the shipped seal. Returns the text, or null when there is not one.
 *
 * `inlined` and `candidates` are seams, not options. The bundle substitutes a
 * string for INLINED, and the suite passes each of these so that both the
 * inlined path and the nothing-anywhere path are executed rather than merely
 * existing -- the second is a real state, reached by any package built without
 * an emblem, and the tool reports it as absence instead of failing.
 *
 * Passing an empty string for `inlined` means "not inlined" and falls through
 * to the candidate paths, which is what a bundle built with nothing to inline
 * will do.
 */
export function readShippedEmblem(inlined = INLINED, candidates = emblemCandidates()) {
  if (typeof inlined === "string" && inlined.trim()) return inlined;
  for (const p of candidates) {
    try {
      if (fs.statSync(p).isFile()) return fs.readFileSync(p, "utf8");
    } catch {
      // Not there. That is an answer, not an error.
    }
  }
  return null;
}

/**
 * Parse the envelope. Never throws: a malformed file is a fact to report, and
 * reporting it must not take the caller down.
 */
export function parseEmblem(text) {
  let doc;
  try {
    doc = JSON.parse(String(text ?? ""));
  } catch {
    return null;
  }
  if (!doc || typeof doc !== "object") return null;
  if (doc.format !== EMBLEM_FORMAT) return null;
  for (const k of ["salt", "nonce", "tag", "payload"]) {
    if (typeof doc[k] !== "string" || !doc[k].trim()) return null;
  }
  if (!/^[0-9a-f]+$/i.test(doc.salt) || doc.salt.length !== SALT_BYTES * 2) return null;
  if (!/^[0-9a-f]+$/i.test(doc.nonce) || doc.nonce.length !== NONCE_BYTES * 2) return null;
  if (!/^[0-9a-f]+$/i.test(doc.tag) || doc.tag.length !== 16 * 2) return null;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(doc.payload)) return null;
  return doc;
}

/**
 * What can be said about the seal without opening it. Deliberately limited to
 * structure: everything here is readable by anyone, so nothing here may be
 * phrased as though it were evidence of authenticity. Authenticity is only
 * established by opening, and opening requires the source work.
 */
export function inspectEmblem(text) {
  const doc = parseEmblem(text);
  if (!doc) {
    return {
      present: text != null,
      sealed: false,
      opens_with: EMBLEM_KEY_SOURCE,
      reason: text == null ? "no emblem was found" : "the emblem is present but not in a recognized format",
    };
  }
  return {
    present: true,
    sealed: true,
    format: doc.format,
    cipher: typeof doc.cipher === "string" ? doc.cipher : null,
    kdf: typeof doc.kdf === "string" ? doc.kdf : null,
    opens_with: typeof doc.key === "string" ? doc.key : EMBLEM_KEY_SOURCE,
    note:
      "The repository can report the shape of the seal but cannot open it. The key comes from " +
      "the source work's own digest, so the seal opens only where that work is present.",
  };
}

/** SHA-256 of an arbitrary buffer, as lowercase hex. */
export function digestOf(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

function deriveKey(sourceSha256Hex, saltHex) {
  const ikm = Buffer.from(String(sourceSha256Hex).trim().toLowerCase(), "hex");
  if (ikm.length !== 32) throw new Error("source digest must be a 32-byte SHA-256, as hex");
  return Buffer.from(hkdfSync("sha256", ikm, Buffer.from(saltHex, "hex"), Buffer.from(EMBLEM_FORMAT, "utf8"), KEY_BYTES));
}

/**
 * Seal `plaintext` under a key derived from `sourceSha256Hex`. The salt and
 * nonce may be supplied so that a test can pin them; production callers leave
 * both out and take the random ones.
 */
export function sealEmblem(plaintext, sourceSha256Hex, opts = {}) {
  const salt = opts.salt ?? randomBytes(SALT_BYTES);
  const nonce = opts.nonce ?? randomBytes(NONCE_BYTES);
  const key = deriveKey(sourceSha256Hex, salt.toString("hex"));
  const c = createCipheriv("aes-256-gcm", key, nonce);
  const body = Buffer.concat([c.update(Buffer.from(String(plaintext), "utf8")), c.final()]);
  return JSON.stringify({
    format: EMBLEM_FORMAT,
    cipher: EMBLEM_CIPHER,
    kdf: EMBLEM_KDF,
    key: EMBLEM_KEY_SOURCE,
    salt: salt.toString("hex"),
    nonce: nonce.toString("hex"),
    tag: c.getAuthTag().toString("hex"),
    payload: body.toString("base64"),
  }, null, 2) + "\n";
}

/**
 * Open the seal. Throws when the source does not match, when the text has been
 * altered, or when the envelope is malformed -- three different causes behind
 * one observable failure, which is what GCM gives and what the caller reports.
 */
export function openEmblem(text, sourceSha256Hex) {
  const doc = parseEmblem(text);
  if (!doc) throw new Error("not a recognized emblem");
  const key = deriveKey(sourceSha256Hex, doc.salt);
  const d = createDecipheriv("aes-256-gcm", key, Buffer.from(doc.nonce, "hex"));
  d.setAuthTag(Buffer.from(doc.tag, "hex"));
  const out = Buffer.concat([d.update(Buffer.from(doc.payload, "base64")), d.final()]);
  return out.toString("utf8");
}

/**
 * Does this source open this seal? Used where the answer is wanted without the
 * plaintext -- the caller gets a boolean and no way to leak the contents by
 * printing an exception.
 */
export function emblemOpensWith(text, sourceSha256Hex) {
  try {
    openEmblem(text, sourceSha256Hex);
    return true;
  } catch {
    return false;
  }
}

/** Constant-time comparison, for callers that check a digest against a known one. */
export function digestsEqual(a, b) {
  const x = Buffer.from(String(a), "utf8");
  const y = Buffer.from(String(b), "utf8");
  return x.length === y.length && timingSafeEqual(x, y);
}
