/**
 * Aragami - net
 *
 * A minimal network layer that exists to serve exactly one action: the version lookup.
 *
 * Why it exists:
 *   This machine (and many restricted networks) cannot reach the internet directly, and
 *   Node's built-in fetch **does not read the system proxy**. PowerShell's
 *   Invoke-WebRequest honours the WinINET system proxy so it works, while Node's direct
 *   connection fails with UND_ERR_CONNECT_TIMEOUT -- hit in practice.
 *   Rather than pull in undici as a dependency, the HTTP CONNECT and SOCKS5 tunnels are
 *   implemented here with the standard library only.
 *
 * Discipline:
 *   - Only called from aragami_version, and only against Tor Project's public version endpoint.
 *   - Reads and sends no local state; the only request headers are User-Agent and Accept.
 *   - Callers may pass proxy: null to force a direct connection, or skip the check entirely.
 */

import http from "node:http";
import net from "node:net";
import tls from "node:tls";
import { execFileSync } from "node:child_process";

/* ------------------------- proxy detection */

/**
 * Normalize the many ways a proxy can be written:
 *   "127.0.0.1:8080" | "http://127.0.0.1:8080" | "http=x:1;https=y:2" | "socks5://x:1"
 */
export function normalizeProxy(raw) {
  let v = String(raw).trim();
  if (!v) return null;
  if (v.includes("=")) {
    const parts = {};
    for (const seg of v.split(";")) {
      const i = seg.indexOf("=");
      if (i > 0) parts[seg.slice(0, i).trim().toLowerCase()] = seg.slice(i + 1).trim();
    }
    v = parts.https || parts.http || parts.socks || Object.values(parts)[0] || "";
    if (!v) return null;
  }
  if (!/^[a-z0-9+.-]+:\/\//i.test(v)) v = "http://" + v;
  let u;
  try { u = new URL(v); } catch { return null; }
  if (!u.port) u.port = u.protocol.startsWith("socks") ? "1080" : "8080";
  return { protocol: u.protocol.replace(":", ""), host: u.hostname, port: Number(u.port), raw: v };
}

const WININET_KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

/**
 * Parse WinINET proxy settings out of `reg query` output. Pure function, so every
 * malformed input is directly testable.
 * Returns null both for "proxy enabled but unusable" and "proxy not enabled"; the caller
 * treats both as no proxy.
 */
export function parseWininetRegistry(out) {
  if (!out) return null;
  const en = /ProxyEnable\s+REG_DWORD\s+0x([0-9a-f]+)/i.exec(out);
  if (!en || parseInt(en[1], 16) !== 1) return null;
  const srv = /ProxyServer\s+REG_SZ\s+(.+)/i.exec(out);
  if (!srv) return null;
  const p = normalizeProxy(srv[1]);
  return p ? { ...p, source: "wininet:ProxyServer" } : null;
}

/**
 * Read the WinINET proxy. `exec` is injectable so the "registry unreadable" fallback path
 * can actually be exercised in tests. (On Windows, clearing PATH does not stop reg.exe
 * from being found in System32, so the branch is unreachable via environment alone --
 * verified empirically.)
 */
export function readWininetProxy(exec) {
  const run = exec ?? ((cmd, args) => execFileSync(cmd, args, { encoding: "utf8", windowsHide: true }));
  try {
    return parseWininetRegistry(run("reg", ["query", WININET_KEY]));
  } catch {
    return null; // an unreadable registry is not fatal: treat it as no proxy and let the caller decide
  }
}

/** Environment variables first, then the Windows system proxy (WinINET settings). */
export function detectProxy() {
  for (const k of ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy"]) {
    const v = process.env[k];
    if (v && v.trim()) {
      const p = normalizeProxy(v);
      if (p) return { ...p, source: `env:${k}` };
    }
  }
  if (process.platform !== "win32") return null;
  return readWininetProxy();
}

/* ------------------------- tunnels */

function connectViaHttpConnect(proxy, host, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: proxy.host,
      port: proxy.port,
      method: "CONNECT",
      path: `${host}:${port}`,
      headers: { Host: `${host}:${port}` },
      timeout: timeoutMs,
    });
    req.on("timeout", () => { req.destroy(new Error(`HTTP CONNECT timed out (${proxy.host}:${proxy.port})`)); });
    req.on("error", reject);
    req.on("connect", (res, socket) => {
      if (res.statusCode !== 200) {
        socket.destroy();
        reject(new Error(`HTTP CONNECT rejected: ${res.statusCode} ${res.statusMessage}`));
        return;
      }
      resolve(socket);
    });
    req.end();
  });
}

/** SOCKS5 tunnel (no authentication) */
function connectViaSocks5(proxy, host, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: proxy.host, port: proxy.port });
    let stage = 0;
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`SOCKS5 timed out (${proxy.host}:${proxy.port})`));
    }, timeoutMs);

    const fail = (e) => { clearTimeout(timer); socket.destroy(); reject(e); };
    socket.on("error", fail);

    socket.on("connect", () => socket.write(Buffer.from([0x05, 0x01, 0x00])));

    socket.on("data", (buf) => {
      if (stage === 0) {
        if (buf.length < 2 || buf[0] !== 0x05) return fail(new Error("Invalid SOCKS5 handshake response"));
        if (buf[1] !== 0x00) return fail(new Error("SOCKS5 requires authentication, which this tool does not support"));
        stage = 1;
        const h = Buffer.from(host, "utf8");
        const p = Buffer.from([(port >> 8) & 0xff, port & 0xff]);
        socket.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, h.length]), h, p]));
        return;
      }
      if (stage === 1) {
        if (buf.length < 2 || buf[1] !== 0x00) return fail(new Error(`SOCKS5 connect failed (REP=${buf[1]})`));
        clearTimeout(timer);
        socket.removeAllListeners("data");
        resolve(socket);
      }
    });
  });
}

/** Open a TCP tunnel to host:port through the proxy; resolves to a raw socket. */
export async function openTunnel(proxy, host, port, timeoutMs = 15000) {
  if (proxy.protocol.startsWith("socks")) {
    return connectViaSocks5(proxy, host, port, timeoutMs);
  }
  return connectViaHttpConnect(proxy, host, port, timeoutMs);
}

/* ------------------------- HTTP over TLS */

export function dechunk(buf) {
  const parts = [];
  let i = 0;
  while (i < buf.length) {
    const j = buf.indexOf("\r\n", i);
    if (j < 0) break;
    const size = parseInt(buf.toString("ascii", i, j).split(";")[0].trim(), 16);
    if (!Number.isFinite(size) || size <= 0) break;
    i = j + 2;
    parts.push(buf.subarray(i, i + size));
    i += size + 2;
  }
  return Buffer.concat(parts);
}

/** Run one HTTPS GET over an already-open raw socket; returns { status, body, head }. */
function httpsGetOverSocket(socket, target, timeoutMs, userAgent) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`TLS/HTTP read timed out (${timeoutMs}ms)`));
    }, timeoutMs);

    const fail = (e) => { clearTimeout(timer); socket.destroy(); reject(e); };

    // RFC 6066: SNI must not be an IP literal. Omit servername for IP targets, otherwise
    // Node raises DEP0123 (observed in testing).
    const tlsOpts = net.isIP(target.hostname) ? { socket } : { socket, servername: target.hostname };
    const tlsSocket = tls.connect(tlsOpts, () => {
      const req =
        `GET ${target.pathname}${target.search} HTTP/1.1\r\n` +
        `Host: ${target.hostname}\r\n` +
        `User-Agent: ${userAgent}\r\n` +
        `Accept: application/json, text/plain, */*\r\n` +
        `Accept-Encoding: identity\r\n` +
        `Connection: close\r\n\r\n`;
      tlsSocket.write(req);
    });

    tlsSocket.on("error", fail);

    const chunks = [];
    tlsSocket.on("data", (d) => chunks.push(d));
    tlsSocket.on("end", () => {
      clearTimeout(timer);
      const all = Buffer.concat(chunks);
      const sep = all.indexOf("\r\n\r\n");
      if (sep < 0) return reject(new Error("HTTP response has no header terminator"));
      const head = all.toString("ascii", 0, sep);
      const bodyRaw = all.subarray(sep + 4);
      const status = parseInt((head.match(/^HTTP\/\d\.\d\s+(\d+)/) || [])[1] ?? "0", 10);
      const isChunked = /transfer-encoding:\s*chunked/i.test(head);
      const body = isChunked ? dechunk(bodyRaw) : bodyRaw;
      resolve({ status, body, head });
    });
  });
}

/**
 * Fetch JSON. Prefers a direct connection (built-in fetch); falls back to -- or is forced
 * onto -- a proxy tunnel.
 * Errors always carry their cause, so a failure is never just a bare "fetch failed"
 * (hit in practice, and impossible to diagnose).
 */
export async function httpsGetJson(url, opts = {}) {
  const { timeoutMs = 15000, userAgent = "Aragami", proxy: proxyOpt } = opts;
  const target = new URL(url);

  // proxy semantics: undefined = auto-detect; null/false = force direct; string = use it
  let proxy;
  if (proxyOpt === undefined) proxy = detectProxy();
  else if (!proxyOpt) proxy = null;
  else proxy = normalizeProxy(proxyOpt);

  // direct first
  if (!proxy) {
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), timeoutMs);
      const res = await fetch(url, {
        signal: ctrl.signal,
        headers: { "user-agent": userAgent, accept: "application/json, text/plain, */*" },
      });
      clearTimeout(t);
      if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
      return { json: await res.json(), via: "direct" };
    } catch (e) {
      const cause = e?.cause?.code || e?.cause?.message || "";
      throw new Error(`Direct connection failed: ${e?.message || e}${cause ? ` (${cause})` : ""}`);
    }
  }

  // through the proxy
  const socket = await openTunnel(proxy, target.hostname, target.port || 443, timeoutMs);
  const { status, body } = await httpsGetOverSocket(socket, target, timeoutMs, userAgent);
  if (status !== 200) throw new Error(`HTTP ${status}`);
  let json;
  try { json = JSON.parse(body.toString("utf8")); }
  catch { throw new Error(`Response is not valid JSON (${body.length} bytes)`); }
  return { json, via: `proxy:${proxy.protocol}://${proxy.host}:${proxy.port} (${proxy.source})` };
}
