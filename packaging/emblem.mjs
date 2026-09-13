#!/usr/bin/env node
/**
 * Seal and open the emblem.
 *
 *   node packaging/emblem.mjs seal   <path-to-source-work> [<out-file>]
 *   node packaging/emblem.mjs open   <path-to-source-work> [<in-file>]
 *   node packaging/emblem.mjs verify [<in-file>]
 *
 * The source work is read here and only here. Its bytes are turned into a
 * digest, and the digest is the key material; the audio itself is never copied,
 * never encoded, and never referenced by path in anything this writes. What
 * lands in `Aragami` is a short ASCII text about the work, sealed, and the
 * parameters needed to try the seal again.
 *
 * The plaintext this composes is deliberately free of anything belonging to the
 * machine or the moment: no source path, no timestamp, no hostname. Two people
 * sealing the same work produce the same text, which is the point of a
 * statement about the work rather than about the run.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  EMBLEM_FILE,
  digestOf,
  inspectEmblem,
  openEmblem,
  parseEmblem,
  readShippedEmblem,
  sealEmblem,
} from "../lib/emblem.mjs";

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const die = (msg) => {
  process.stderr.write(`emblem: ${msg}\n`);
  process.exit(1);
};

/* ---------------------------------- FLAC ---------------------------------- */

const rd24 = (b, o) => (b[o] << 16) | (b[o + 1] << 8) | b[o + 2];

const BLOCK_NAMES = {
  0: "STREAMINFO", 1: "PADDING", 2: "APPLICATION", 3: "SEEKTABLE",
  4: "VORBIS_COMMENT", 5: "CUESHEET", 6: "PICTURE",
};

/**
 * Read the metadata of a native FLAC stream. The block header is one byte of
 * flags and type followed by a three-byte big-endian length, so the length is
 * read from the header byte itself and masked; the data then starts four bytes
 * in. Getting that off by one is easy and silent -- it produced a 57344 Hz,
 * eight-channel reading before it was corrected -- so the fields below are
 * taken at their offsets within the block data, not from the header.
 */
function readFlac(buf) {
  if (buf.length < 8 || buf.slice(0, 4).toString("latin1") !== "fLaC") {
    die("the source work is not a native FLAC stream (no fLaC marker)");
  }
  const out = { streaminfo: null, tags: {}, picture: null, audio_offset: 0 };
  let off = 4;
  while (off + 4 <= buf.length) {
    const hdr = buf[off];
    const last = (hdr & 0x80) !== 0;
    const type = hdr & 0x7f;
    const len = rd24(buf, off + 1);
    const d = off + 4;

    if (type === 0 && len >= 34) {
      const sr = (buf[d + 10] << 12) | (buf[d + 11] << 4) | (buf[d + 12] >> 4);
      out.streaminfo = {
        min_block: buf.readUInt16BE(d),
        max_block: buf.readUInt16BE(d + 2),
        sample_rate: sr,
        channels: ((buf[d + 12] >> 1) & 0x07) + 1,
        bits: (((buf[d + 12] & 1) << 4) | (buf[d + 13] >> 4)) + 1,
        samples: (buf[d + 13] & 0x0f) * 4294967296 + buf.readUInt32BE(d + 14),
        md5: buf.slice(d + 18, d + 34).toString("hex"),
      };
    } else if (type === 4) {
      let o = d;
      const vl = buf.readUInt32LE(o); o += 4;
      out.tags.vendor = buf.slice(o, o + vl).toString("utf8"); o += vl;
      const n = buf.readUInt32LE(o); o += 4;
      for (let i = 0; i < n; i++) {
        const l = buf.readUInt32LE(o); o += 4;
        const kv = buf.slice(o, o + l).toString("utf8"); o += l;
        const eq = kv.indexOf("=");
        if (eq > 0) out.tags[kv.slice(0, eq).toUpperCase()] = kv.slice(eq + 1);
      }
    } else if (type === 6) {
      let o = d + 4;
      const ml = buf.readUInt32BE(o); o += 4;
      o += ml;
      const dl = buf.readUInt32BE(o); o += 4;
      o += dl;
      out.picture = { width: buf.readUInt32BE(o), height: buf.readUInt32BE(o + 4), bytes: buf.readUInt32BE(o + 16) };
    }
    off = d + len;
    out.audio_offset = off;
    if (last) break;
  }
  if (!out.streaminfo) die("the source work has no STREAMINFO block");
  if (!BLOCK_NAMES[0]) die("unreachable");
  return out;
}

const clock = (sec) => `${Math.floor(sec / 60)}:${String(Math.round(sec % 60)).padStart(2, "0")}`;

/**
 * Compose the statement. Every line here is derived from the work's own
 * metadata or its bytes, so the text is a property of the work and not of
 * whoever ran this.
 */
function composeText(flac, digest) {
  const s = flac.streaminfo;
  const t = flac.tags;
  const rows = [
    ["title", t.TITLE],
    ["artist", t.ARTIST],
    ["album", t.ALBUM],
    ["track", t.TRACKNUMBER ? (t.TRACKTOTAL ? `${t.TRACKNUMBER} of ${t.TRACKTOTAL}` : t.TRACKNUMBER) : null],
    ["date", t.DATE],
    ["duration", `${clock(s.samples / s.sample_rate)} (${(s.samples / s.sample_rate).toFixed(2)} s)`],
    ["audio", `FLAC, ${s.sample_rate} Hz, ${s.channels} channel${s.channels === 1 ? "" : "s"}, ${s.bits} bit`],
    ["samples", String(s.samples)],
    ["cover", flac.picture ? `${flac.picture.width}x${flac.picture.height}, ${Math.round(flac.picture.bytes / 1024)} KB` : null],
  ].filter(([, v]) => v != null && v !== "");

  // The two digests are longer than any tag name, so the column is widened to
  // fit "streaminfo" and every row pads to it rather than the other way round.
  const width = Math.max(10, ...rows.map(([k]) => k.length));
  const lines = [
    "Aragami",
    "",
    "  the work this project is named after",
    "",
    ...rows.map(([k, v]) => `  ${k.padEnd(width)}  ${v}`),
    "",
    `  ${"streaminfo".padEnd(width)}  ${s.md5}`,
    `  ${"digest".padEnd(width)}  ${digest}`,
    "",
    "  This seal opens only where the work above is present. It carries no audio,",
    "  and the repository that ships it does not distribute the work.",
  ];
  return lines.join("\n") + "\n";
}

/* ---------------------------------- verbs --------------------------------- */

function resolveFile(flag, fallback) {
  return path.resolve(flag ?? fallback);
}

function readSource(p) {
  let buf;
  try {
    buf = fs.readFileSync(p);
  } catch (e) {
    die(`cannot read the source work: ${e.message}`);
  }
  return { buf, digest: digestOf(buf) };
}

function cmdSeal(argv) {
  const p = resolveFile(argv[0], null);
  if (!p || !argv[0]) die("seal needs the path to the source work");
  const out = resolveFile(argv[1], path.join(REPO, EMBLEM_FILE));
  const { buf, digest } = readSource(p);
  const flac = readFlac(buf);
  const plaintext = composeText(flac, digest);
  const sealed = sealEmblem(plaintext, digest);
  fs.writeFileSync(out, sealed, "utf8");
  process.stdout.write(`sealed ${path.basename(out)} from ${path.basename(p)} (${buf.length} bytes)\n`);
  process.stdout.write(`  digest ${digest}\n`);
  process.stdout.write(`  seal   ${Buffer.byteLength(sealed, "utf8")} bytes\n`);
}

function cmdOpen(argv) {
  const p = resolveFile(argv[0], null);
  if (!p || !argv[0]) die("open needs the path to the source work");
  const inFile = resolveFile(argv[1], path.join(REPO, EMBLEM_FILE));
  const text = fs.existsSync(inFile) ? fs.readFileSync(inFile, "utf8") : readShippedEmblem();
  if (!text) die(`no emblem found at ${inFile}`);
  const { digest } = readSource(p);
  let plain;
  try {
    plain = openEmblem(text, digest);
  } catch {
    die("the seal did not open: the source work does not match it, or the seal has been altered");
  }
  process.stdout.write(plain);
}

function cmdVerify(argv) {
  const inFile = resolveFile(argv[0], path.join(REPO, EMBLEM_FILE));
  const text = fs.existsSync(inFile) ? fs.readFileSync(inFile, "utf8") : readShippedEmblem();
  const report = inspectEmblem(text);
  process.stdout.write(JSON.stringify(report, null, 2) + "\n");
  if (!report.sealed) process.exit(1);
  const doc = parseEmblem(text);
  process.stdout.write(`  envelope ok: ${doc.format}, ${doc.cipher} over ${doc.kdf}, keyed by ${doc.key}\n`);
}

const [verb, ...rest] = process.argv.slice(2);
if (verb === "seal") cmdSeal(rest);
else if (verb === "open") cmdOpen(rest);
else if (verb === "verify") cmdVerify(rest);
else {
  process.stderr.write(
    "usage:\n" +
    "  node packaging/emblem.mjs seal   <source-work> [<out-file>]\n" +
    "  node packaging/emblem.mjs open   <source-work> [<in-file>]\n" +
    "  node packaging/emblem.mjs verify [<in-file>]\n"
  );
  process.exit(2);
}
