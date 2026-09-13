/**
 * Aragami - shared helpers
 *
 * Primitives used by every audit target. Extracted from the core so that the Tor and
 * Firefox targets can share them without importing each other (which would be a cycle).
 *
 * Everything here is deliberately small and dependency-free: this module is the floor the
 * rest of the tool stands on.
 */

import fs from "node:fs";

/* ------------------------------------------------ filesystem */

export function exists(p) {
  try { fs.accessSync(p); return true; } catch { return false; }
}

export function statOf(p) {
  try { return fs.statSync(p); } catch { return null; }
}

export function readText(p, limit = 4 * 1024 * 1024) {
  try {
    const st = fs.statSync(p);
    if (!st.isFile()) return null;
    const fd = fs.openSync(p, "r");
    const len = Math.min(st.size, limit);
    const buf = Buffer.alloc(len);
    fs.readSync(fd, buf, 0, len, 0);
    fs.closeSync(fd);
    return buf.toString("utf8");
  } catch { return null; }
}

export function readJson(p) {
  const t = readText(p, 512 * 1024);
  if (t == null) return null;
  try { return JSON.parse(t); } catch { return null; }
}

export function listDir(p) {
  try { return fs.readdirSync(p, { withFileTypes: true }); } catch { return []; }
}

/** Total size of a directory tree, with a cap so a runaway directory cannot hang the audit. */
export function dirSize(p, maxEntries = 20000) {
  let total = 0, seen = 0;
  const walk = (dir) => {
    for (const e of listDir(dir)) {
      if (seen++ > maxEntries) return;
      const full = `${dir}/${e.name}`;
      if (e.isDirectory()) walk(full);
      else {
        const s = statOf(full);
        if (s) total += s.size;
      }
    }
  };
  if (!exists(p)) return null;
  walk(p);
  return total;
}

/* ------------------------------------------------ formatting */

export function fmtBytes(n) {
  if (n == null) return "-";
  const u = ["B", "KB", "MB", "GB"];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${u[i]}`;
}

export function fmtTime(d) {
  if (!d) return "-";
  const dt = d instanceof Date ? d : new Date(d);
  return dt.toISOString().replace("T", " ").slice(0, 16) + " UTC";
}

export function daysSince(d) {
  if (!d) return null;
  return Math.floor((Date.now() - new Date(d).getTime()) / 86400000);
}

/* ------------------------------------------------ findings */

export function finding(layer, severity, id, title, detail, evidence) {
  return { layer, severity, id, title, detail, evidence: evidence ?? null };
}

/* ------------------------------------------------ parsers */

/**
 * Parse INI-style configuration. Returns { section: { key: value }, ... }.
 * Keys before the first section header land at the top level.
 */
export function parseIni(text) {
  const out = {};
  let cur = null;
  for (const raw of (text ?? "").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const sec = line.match(/^\[(.+)\]$/);
    if (sec) { cur = sec[1]; out[cur] = out[cur] ?? {}; continue; }
    const eq = line.indexOf("=");
    if (eq < 0) continue;
    const k = line.slice(0, eq).trim();
    const v = line.slice(eq + 1).trim();
    if (cur === null) out[k] = v;
    else out[cur][k] = v;
  }
  return out;
}

/**
 * Parse torrc-style configuration. Returns { entries: {Name: [values]}, order: [...] }.
 * Handles inline comments and quoted values.
 */
export function parseTorrc(text) {
  const entries = Object.create(null);
  const order = [];
  if (!text) return { entries, order };

  for (let raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const m = line.match(/^([A-Za-z][A-Za-z0-9_]*)\s+(.*)$/);
    if (!m) continue;
    const name = m[1];
    let val = m[2].trim();
    // strip trailing comments on unquoted values
    if (!val.startsWith('"')) {
      const i = val.indexOf(" #");
      if (i >= 0) val = val.slice(0, i).trim();
    }
    if (val.startsWith('"') && val.endsWith('"')) val = val.slice(1, -1);
    if (!entries[name]) { entries[name] = []; order.push(name); }
    entries[name].push(val);
  }
  return { entries, order };
}

/** Parse a Firefox prefs.js into a plain object. Values keep their JS type. */
export function parsePrefs(text) {
  const prefs = Object.create(null);
  if (!text) return prefs;
  const re = /user_pref\("([^"]+)",\s*([\s\S]*?)\);\s*$/gm;
  let m;
  while ((m = re.exec(text)) !== null) {
    let v = m[2].trim();
    if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
    else if (v === "true") v = true;
    else if (v === "false") v = false;
    else if (/^-?\d+$/.test(v)) v = Number(v);
    prefs[m[1]] = v;
  }
  return prefs;
}
