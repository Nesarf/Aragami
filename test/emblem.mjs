#!/usr/bin/env node
/**
 * Emblem suite -- drives lib/emblem.mjs, and the sealer in packaging/emblem.mjs.
 *
 * Why this needs its own suite:
 *
 *   1. The seal is the one thing in this project that is sealed rather than read. Every other
 *      suite asserts what the auditor reports about files it can open; here the claim is that
 *      a file CANNOT be opened without the source work, and a claim of that shape is only
 *      worth anything if the failure is tested. So the negative cases carry most of this file:
 *      wrong source, altered payload, altered tag, altered nonce, altered format. A seal that
 *      opened for the wrong reason would look identical to a working one from the outside.
 *
 *   2. The envelope's validation is a list of rejections. Each branch below corresponds to one
 *      condition in parseEmblem, and each is asserted with an input that violates exactly that
 *      condition and satisfies every earlier one -- so a check cannot pass because an earlier
 *      check rejected first. Without this, a later guard could be deleted and the suite would
 *      stay green while the envelope accepted anything.
 *
 *   3. The FLAC reader is the part that had a real defect. The block header is one byte of
 *      flags and type followed by a three-byte length; reading that length as four bytes
 *      silently swallowed the first byte of block data and produced a plausible-looking but
 *      wrong reading (57344 Hz, eight channels) that no assertion here would have caught had
 *      the fixture been the real work rather than a synthetic one. The fixture below is built
 *      with known field values, and every field the reader derives is asserted against them.
 *
 * Hermeticity: nothing here reads the source work. The fixture is a synthetic FLAC assembled
 *   in a temp directory from known values, so this suite reproduces on any machine and in CI,
 *   where the real work does not exist. The shipped `Aragami` is asserted only for its shape --
 *   that it parses and is sealed -- never for its contents, which by design cannot be recovered
 *   here.
 *
 * Division of labour: matrix owns the output contract, selftest and firefox own target
 *   semantics, net owns the protocol layer, coverage owns the traversal. This suite owns the
 *   emblem and nothing else.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

const emblem = await import(pathToFileURL(path.join(root, "lib", "emblem.mjs")).href);
const {
  EMBLEM_FORMAT, EMBLEM_FILE, digestOf, digestsEqual, emblemOpensWith, inspectEmblem,
  openEmblem, parseEmblem, readShippedEmblem, sealEmblem,
} = emblem;

let pass = 0, fail = 0;
const failures = [];
function check(name, ok, detail = "") {
  if (ok) { console.log(`  \u001b[32m[ok]\u001b[0m ${name}`); pass++; }
  else { console.log(`  \u001b[31m[FAIL]\u001b[0m ${name}  ${detail}`); fail++; failures.push(`${name} ${detail}`); }
}
function section(t) { console.log(`\n\u001b[35m== ${t} ==\u001b[0m`); }

const base = fs.mkdtempSync(path.join(os.tmpdir(), "tpa-emblem-"));
const TMP = (n) => path.join(base, n);
const le32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n, 0); return b; };

/* ====================== a synthetic source work ====================== */

const FIXTURE = {
  sampleRate: 44100, channels: 2, bits: 16, samples: 10606344,
  streamMd5: "5dc0c11e39e6db0e6b365c34971eec1f",
  vendor: "reference libFLAC 1.3.2 20170101",
  tags: ["ALBUM=World Fragments", "ARTIST=xi", "TITLE=Aragami", "TRACKNUMBER=1"],
};

/** STREAMINFO with the fixture's fields, at their specified offsets within the block. */
function streamInfoBlock() {
  const d = Buffer.alloc(34);
  d.writeUInt16BE(4096, 0);
  d.writeUInt16BE(4096, 2);
  // bytes 4-9 are the min/max frame size and stay zero: this fixture has no audio frames.
  const sr = FIXTURE.sampleRate, ch = FIXTURE.channels, bits = FIXTURE.bits, n = FIXTURE.samples;
  d[10] = (sr >> 12) & 0xff;
  d[11] = (sr >> 4) & 0xff;
  d[12] = ((sr & 0x0f) << 4) | (((ch - 1) & 0x07) << 1) | (((bits - 1) >> 4) & 0x01);
  d[13] = (((bits - 1) & 0x0f) << 4) | (Math.floor(n / 4294967296) & 0x0f);
  d.writeUInt32BE(n % 4294967296, 14);
  Buffer.from(FIXTURE.streamMd5, "hex").copy(d, 18);
  return d;
}

function vorbisCommentBlock() {
  const v = Buffer.from(FIXTURE.vendor, "utf8");
  const parts = [le32(v.length), v, le32(FIXTURE.tags.length)];
  for (const t of FIXTURE.tags) { const b = Buffer.from(t, "utf8"); parts.push(le32(b.length), b); }
  return Buffer.concat(parts);
}

/** Assemble a native FLAC stream: marker, then metadata blocks, the last one flagged. */
function buildFlac(blocks) {
  const out = [Buffer.from("fLaC", "latin1")];
  blocks.forEach((b, i) => {
    const hdr = Buffer.alloc(4);
    hdr[0] = (i === blocks.length - 1 ? 0x80 : 0x00) | b.type;
    hdr[1] = (b.data.length >> 16) & 0xff;
    hdr[2] = (b.data.length >> 8) & 0xff;
    hdr[3] = b.data.length & 0xff;
    out.push(hdr, b.data);
  });
  return Buffer.concat(out);
}

const sourcePath = TMP("source.flac");
const source = buildFlac([
  { type: 0, data: streamInfoBlock() },
  { type: 4, data: vorbisCommentBlock() },
  { type: 1, data: Buffer.alloc(16) },
]);
fs.writeFileSync(sourcePath, source);
const sourceDigest = digestOf(source);
const otherDigest = digestOf(Buffer.from("not the work"));

/* ====================== A. digest ====================== */

section("A1. digestOf");
{
  // The published SHA-256 of "abc": a known vector, so a silent change of algorithm is caught.
  check("sha256 of 'abc' matches the published vector",
    digestOf(Buffer.from("abc")) === "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    digestOf(Buffer.from("abc")));
  check("the source digest is 64 hex characters", /^[0-9a-f]{64}$/.test(sourceDigest), sourceDigest);
  check("digestsEqual: equal", digestsEqual(sourceDigest, sourceDigest) === true);
  check("digestsEqual: unequal", digestsEqual(sourceDigest, otherDigest) === false);
  check("digestsEqual: different lengths do not throw", digestsEqual("ab", "abc") === false);
}

/* ====================== B. seal and open ====================== */

section("B1. seal/open round trip");
const salt = Buffer.alloc(16, 0x11);
const nonce = Buffer.alloc(12, 0x22);
const plaintext = "Aragami\n\n  the work this project is named after\n";
const sealed = sealEmblem(plaintext, sourceDigest, { salt, nonce });
{
  const doc = JSON.parse(sealed);
  check("the envelope names its format", doc.format === EMBLEM_FORMAT, doc.format);
  check("the envelope names the cipher", doc.cipher === "aes-256-gcm", doc.cipher);
  check("the envelope names the kdf", doc.kdf === "hkdf-sha256", doc.kdf);
  check("the envelope names what the key comes from", doc.key === "source-sha256", doc.key);
  check("the salt is the one supplied", doc.salt === salt.toString("hex"), doc.salt);
  check("the nonce is the one supplied", doc.nonce === nonce.toString("hex"), doc.nonce);
  check("the tag is 16 bytes", /^[0-9a-f]{32}$/.test(doc.tag), doc.tag);
  check("the payload does not contain the plaintext", !sealed.includes("named after"));
  check("the whole envelope is ASCII", [...sealed].every((c) => c.codePointAt(0) < 128));
  check("the same inputs seal to the same bytes",
    sealEmblem(plaintext, sourceDigest, { salt, nonce }) === sealed);

  check("opening with the source recovers the plaintext exactly", openEmblem(sealed, sourceDigest) === plaintext);
  check("emblemOpensWith: the source opens it", emblemOpensWith(sealed, sourceDigest) === true);
  check("emblemOpensWith: another digest does not", emblemOpensWith(sealed, otherDigest) === false);
  check("a random salt produces a different envelope",
    sealEmblem(plaintext, sourceDigest) !== sealed);
}

/* ====================== C. what must not open ====================== */

section("C1. the seal refuses what it should");
{
  const throws = (fn) => { try { fn(); return false; } catch { return true; } };

  check("a wrong source digest throws", throws(() => openEmblem(sealed, otherDigest)));
  check("a truncated source digest throws", throws(() => openEmblem(sealed, "ab")));

  const doc = JSON.parse(sealed);
  const flip = (s) => {
    const b = Buffer.from(s, "base64");
    b[0] ^= 0x01;
    return b.toString("base64");
  };
  const alter = (k, v) => JSON.stringify({ ...doc, [k]: v });

  check("an altered payload byte throws", throws(() => openEmblem(alter("payload", flip(doc.payload)), sourceDigest)));
  check("an altered tag throws", throws(() => openEmblem(alter("tag", "0".repeat(32)), sourceDigest)));
  check("an altered nonce throws", throws(() => openEmblem(alter("nonce", "0".repeat(24)), sourceDigest)));
  check("an altered salt throws", throws(() => openEmblem(alter("salt", "0".repeat(32)), sourceDigest)));
  check("a container swap throws rather than recovering the other plaintext",
    throws(() => openEmblem(sealEmblem("other", otherDigest, { salt, nonce }), sourceDigest)));

  // Cutting the payload short must fail the GCM tag, not decode partially.
  const short = Buffer.from(doc.payload, "base64").slice(0, 8).toString("base64");
  check("a truncated payload throws", throws(() => openEmblem(alter("payload", short), sourceDigest)));
}

/* ====================== D. envelope validation ====================== */

section("D1. parseEmblem accepts and rejects");
{
  const good = JSON.parse(sealed);
  const ok = (o) => parseEmblem(JSON.stringify(o)) !== null;
  const no = (o) => parseEmblem(JSON.stringify(o)) === null;

  check("the envelope it just produced parses", ok(good));
  // Each input below breaks exactly one condition and satisfies every earlier one, so the
  // branch it exercises is the only one that can reject it.
  check("non-JSON text is rejected", parseEmblem("not json") === null);
  check("the empty string is rejected", parseEmblem("") === null);
  check("null is rejected", parseEmblem(null) === null);
  check("a JSON array is rejected", no([]));
  check("a JSON string is rejected", no("aragami"));
  check("a different format name is rejected", no({ ...good, format: "aragami-emblem/2" }));
  check("a missing salt is rejected", no({ ...good, salt: undefined }));
  check("an empty salt is rejected", no({ ...good, salt: "" }));
  check("a short salt is rejected", no({ ...good, salt: "aa" }));
  check("a non-hex salt is rejected", no({ ...good, salt: "z".repeat(32) }));
  check("a short nonce is rejected", no({ ...good, nonce: "aa" }));
  check("a non-hex nonce is rejected", no({ ...good, nonce: "z".repeat(24) }));
  check("a short tag is rejected", no({ ...good, tag: "aa" }));
  check("a non-hex tag is rejected", no({ ...good, tag: "z".repeat(32) }));
  check("a missing payload is rejected", no({ ...good, payload: undefined }));
  check("a non-base64 payload is rejected", no({ ...good, payload: "not base64!!" }));
  check("the cipher field is not required to parse", ok({ ...good, cipher: undefined, kdf: undefined, key: undefined }));
}

/* ====================== E. inspection without the key ====================== */

section("E1. inspectEmblem says only what it can know");
{
  const absent = inspectEmblem(null);
  check("absent: present is false", absent.present === false);
  check("absent: sealed is false", absent.sealed === false);
  check("absent: it names what would open it", absent.opens_with === "source-sha256");

  const broken = inspectEmblem("{ this is not an envelope }");
  check("malformed: present is true", broken.present === true);
  check("malformed: sealed is false", broken.sealed === false);
  check("malformed: the reason is stated", /recognized format/.test(broken.reason), broken.reason);

  const good = inspectEmblem(sealed);
  check("valid: present is true", good.present === true);
  check("valid: sealed is true", good.sealed === true);
  check("valid: the format is reported", good.format === EMBLEM_FORMAT);
  check("valid: the cipher is reported", good.cipher === "aes-256-gcm");
  check("valid: the key source is reported", good.opens_with === "source-sha256");
  check("valid: the note does not claim the repository can open it",
    /cannot open it/.test(good.note), good.note);
  // The report must carry no key material and no plaintext.
  const json = JSON.stringify(good);
  check("the report carries no salt, nonce, tag or payload",
    !/salt|nonce|tag|payload/.test(json), json);
}

/* ====================== F. the shipped emblem ====================== */

section("F1. the shipped Aragami");
{
  const shipped = readShippedEmblem();
  check("the shipped emblem is found", typeof shipped === "string" && shipped.length > 0);
  check("it sits at the repository root under the bare name",
    fs.existsSync(path.join(root, EMBLEM_FILE)), path.join(root, EMBLEM_FILE));
  check("it has no file extension", path.extname(EMBLEM_FILE) === "", EMBLEM_FILE);

  const doc = parseEmblem(shipped);
  check("it parses as an envelope", doc !== null);
  check("it is sealed", inspectEmblem(shipped).sealed === true);
  // The design claim, stated as an assertion: the repository alone cannot open it, because
  // the key is the source work's digest and nothing in the repository is that digest.
  check("no digest derivable from the repository opens it",
    emblemOpensWith(shipped, digestOf(Buffer.from(shipped))) === false &&
    emblemOpensWith(shipped, otherDigest) === false);
  check("it is small enough to travel in every package",
    Buffer.byteLength(shipped, "utf8") < 4096, String(Buffer.byteLength(shipped, "utf8")));
  check("it is ASCII", [...shipped].every((c) => c.codePointAt(0) < 128));

  // The bundled single-file executable has no file beside it to read, so the seal is inlined
  // at bundle time. That path is a seam on this function, and the seam is exercised here
  // rather than left to the one caller that reaches it in production.
  check("an inlined seal is preferred over the one on disk",
    readShippedEmblem(sealed) === sealed);
  check("an empty inline falls through to disk rather than sealing nothing",
    readShippedEmblem("") === shipped);
  // A package built without an emblem must report absence, not fail, and the absence has to
  // survive a path that does not exist -- which is what a read of a missing file throws.
  check("with no emblem anywhere the result is null, not an exception",
    readShippedEmblem("", [TMP("no-such-Aragami"), TMP("also-missing")]) === null);
  check("absence is reported as absent rather than malformed",
    inspectEmblem(readShippedEmblem("", [TMP("no-such-Aragami")])).present === false);
}

/* ====================== G. the sealer, end to end ====================== */

section("G1. packaging/emblem.mjs seal / open / verify");
{
  const cli = path.join(root, "packaging", "emblem.mjs");
  const outFile = TMP("sealed.json");
  const run = (args) => execFileSync(process.execPath, [cli, ...args], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } });
  const runFails = (args) => { try { run(args); return false; } catch { return true; } };

  const sealOut = run(["seal", sourcePath, outFile]);
  check("seal reports the digest it keyed on", sealOut.includes(sourceDigest), sealOut.trim());
  check("seal wrote the file", fs.existsSync(outFile));
  check("seal did not print the source path", !sealOut.includes(base), sealOut.trim());

  const text = fs.readFileSync(outFile, "utf8");
  check("the sealed file parses", parseEmblem(text) !== null);

  const opened = run(["open", sourcePath, outFile]);
  // Every field the reader derives is asserted against the fixture's known value.
  check("the reader recovered the title", opened.includes("Aragami"), "");
  check("the reader recovered the artist and album",
    opened.includes("xi") && opened.includes("World Fragments"));
  check("the reader recovered the track number", /track\s+1\b/.test(opened), "");
  check("the reader recovered the sample rate", opened.includes("44100 Hz"), "");
  check("the reader recovered the channel count", opened.includes("2 channels"), "");
  check("the reader recovered the bit depth", opened.includes("16 bit"), "");
  check("the reader recovered the sample count", opened.includes(String(FIXTURE.samples)), "");
  check("the reader recovered the stream MD5", opened.includes(FIXTURE.streamMd5), "");
  check("the reader carried the source digest", opened.includes(sourceDigest), "");
  // The statement is about the work, not about the run: no path and no timestamp may appear.
  check("the statement carries no path from this machine", !opened.includes(base) && !opened.includes(os.tmpdir()), "");
  check("the statement carries no year-like timestamp", !/\b20\d\d-\d\d-\d\d\b/.test(opened), "");
  check("the statement says it does not carry audio", /does not distribute the work/.test(opened), "");

  const verifyOut = run(["verify", outFile]);
  check("verify reports it sealed", /"sealed": true/.test(verifyOut), verifyOut.trim().split("\n")[0]);

  check("opening with the wrong file fails", runFails(["open", path.join(root, "README.md"), outFile]));

  // A single altered byte in the seal must make open fail rather than return something else.
  // The byte is XORed rather than overwritten so that the change is guaranteed even if the
  // first byte already held the value it is being set to.
  const tampered = TMP("tampered.json");
  const tdoc = JSON.parse(text);
  const pbytes = Buffer.from(tdoc.payload, "base64");
  pbytes[0] ^= 0xff;
  tdoc.payload = pbytes.toString("base64");
  fs.writeFileSync(tampered, JSON.stringify(tdoc));
  check("opening a tampered seal fails", runFails(["open", sourcePath, tampered]));
  check("verify on a tampered seal still reports the shape",
    run(["verify", tampered]).includes("\"sealed\": true"));

  // A source that is not a FLAC must be refused, not guessed at.
  const notFlac = TMP("not-a-flac.bin");
  fs.writeFileSync(notFlac, Buffer.from("this is not a FLAC stream at all"));
  check("sealing a non-FLAC fails", runFails(["seal", notFlac, TMP("never.json")]));
  check("a missing source file fails", runFails(["seal", TMP("does-not-exist.flac"), TMP("never.json")]));

  // A FLAC with no STREAMINFO is structurally impossible but must be refused rather than
  // read as zeroes, so the guard is exercised directly.
  const bare = TMP("bare-flac.flac");
  fs.writeFileSync(bare, buildFlac([{ type: 1, data: Buffer.alloc(8) }]));
  check("a FLAC with no STREAMINFO fails", runFails(["seal", bare, TMP("never.json")]));

  check("no verb prints usage and exits non-zero", runFails([]));
}

/* ====================== summary ====================== */

try { fs.rmSync(base, { recursive: true, force: true }); console.log("\n  \u001b[90mtemporary fixtures cleaned up\u001b[0m"); } catch {}

console.log(`\n  passed ${pass} / ${pass + fail}`);
if (fail) {
  console.log("\n  failures:");
  for (const f of failures) console.log(`    ${f}`);
  process.exit(1);
}
