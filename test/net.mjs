#!/usr/bin/env node
/**
 * Network-layer test -- drives lib/net.mjs end to end using local mock servers.
 *
 * Why this needs its own suite:
 *   Coverage traversal showed net.mjs at only 55.5% -- the entire SOCKS5 block, dechunk,
 *   the direct path and the CONNECT rejection branches had never been executed. The network
 *   layer was originally written to put out a fire (Node's fetch does not read the system
 *   proxy) and had only ever been validated by a single live call, which is not enough for a
 *   module that handles proxy protocols.
 *
 * Approach: no dependence on the external network and no dependence on a real proxy.
 *   Start a mock HTTP CONNECT proxy / mock SOCKS5 server / TCP echo server / HTTP JSON server
 *   locally, then verify the tunnel handshakes, the rejection paths, the timeout paths and the
 *   pure parsing functions.
 *
 * Covered here now, and why it needed a mechanism: a full TLS-over-tunnel round trip. The
 *   proxy path through httpsGetOverSocket -- writing the request after the handshake, reading
 *   the response back, and httpsGetJson's success branch -- only executes when there is a
 *   proxy to go through, so on a machine without one it was never reached and the coverage
 *   gate had to be set to the proxy-less floor. The fixture below needs a certificate the
 *   system store does not know, and tls.connect validates by default, correctly.
 *
 *   The trust cannot be arranged from inside the process: NODE_EXTRA_CA_CERTS is read at
 *   startup. Rather than let this one test behave differently depending on how the file was
 *   invoked, the suite re-executes itself once with the variable set. The child inherits
 *   NODE_V8_COVERAGE and coverage.mjs merges overlapping ranges by taking the highest count,
 *   so `node test/net.mjs`, `npm test` and the coverage traversal all run the same code the
 *   same way and none of them loses coverage to the extra process.
 *
 *   The certificate and key under test/certs/ are for 127.0.0.1 only, are committed on
 *   purpose, and grant nothing: they exist so a local mock server can complete a handshake.
 */

import net from "node:net";
import http from "node:http";
import tls from "node:tls";
import path from "node:path";
import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const CERT = path.join(here, "certs", "loopback-test-cert.pem");
const KEY = path.join(here, "certs", "loopback-test-key.pem");

if (!process.env.ARAGAMI_LOOPBACK_CA) {
  // An existing NODE_EXTRA_CA_CERTS is replaced rather than extended, because whether Node
  // accepts a list of paths there varies by version and a list that is silently ignored would
  // make the TLS test fail for a reason that has nothing to do with the code. This suite talks
  // only to loopback fixtures, so nothing it does needs anyone else's extra CAs.
  const child = spawnSync(process.execPath, [fileURLToPath(import.meta.url), ...process.argv.slice(2)], {
    stdio: "inherit",
    env: { ...process.env, ARAGAMI_LOOPBACK_CA: "1", NODE_EXTRA_CA_CERTS: CERT },
  });
  process.exit(child.status === null ? 1 : child.status);
}

const { normalizeProxy, dechunk, detectProxy, parseWininetRegistry, readWininetProxy, openTunnel, httpsGetJson } = await import(
  pathToFileURL(path.join(root, "lib", "net.mjs")).href
);

let pass = 0, fail = 0;
const failures = [];
function check(name, ok, detail = "") {
  if (ok) { console.log(`  \u001b[32m[ok]\u001b[0m ${name}`); pass++; }
  else { console.log(`  \u001b[31m[FAIL]\u001b[0m ${name}  ${detail}`); fail++; failures.push(`${name} ${detail}`); }
}
function section(t) { console.log(`\n\u001b[35m== ${t} ==\u001b[0m`); }

const openServers = [];
function listen(server) {
  return new Promise((res) => {
    server.listen(0, "127.0.0.1", () => { openServers.push(server); res(server.address().port); });
  });
}
function closeAll() {
  for (const s of openServers) { try { s.close(); } catch {} }
}

/* ================== A. pure functions ================== */

section("A1. normalizeProxy");
{
  const c1 = normalizeProxy("127.0.0.1:3128");
  check("bare host:port -> http", c1?.protocol === "http" && c1.host === "127.0.0.1" && c1.port === 3128, JSON.stringify(c1));

  const c2 = normalizeProxy("http://10.0.0.1:8080");
  check("a scheme is recognized as-is", c2?.protocol === "http" && c2.host === "10.0.0.1" && c2.port === 8080);

  const c3 = normalizeProxy("socks5://127.0.0.1:1080");
  check("socks5 protocol recognized", c3?.protocol === "socks5" && c3.port === 1080, JSON.stringify(c3));

  const c4 = normalizeProxy("http=a.com:1;https=b.com:2");
  check("WinINET multi-segment form prefers https", c4?.host === "b.com" && c4.port === 2, JSON.stringify(c4));

  const c5 = normalizeProxy("http=a.com:1");
  check("WinINET with only an http segment uses http", c5?.host === "a.com" && c5.port === 1, JSON.stringify(c5));

  const c6 = normalizeProxy("socks=x.com:9");
  check("WinINET socks segment", c6?.host === "x.com" && c6.port === 9, JSON.stringify(c6));

  const c7 = normalizeProxy("myhost");
  check("a default port is supplied when none is given", c7?.port === 8080, JSON.stringify(c7));

  check("empty string -> null", normalizeProxy("") === null);
  check("whitespace only -> null", normalizeProxy("   ") === null);
  check("malformed string -> null", normalizeProxy("http://not a host::") === null);
}

section("A2. dechunk");
{
  const b = (s) => Buffer.from(s, "latin1");
  check("single chunk", dechunk(b("5\r\nhello\r\n0\r\n\r\n")).toString() === "hello");
  check("multiple chunks", dechunk(b("3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n")).toString() === "abcdef");
  check("with extension parameters", dechunk(b("5;ext=1\r\nhello\r\n0\r\n\r\n")).toString() === "hello");
  check("empty input -> empty", dechunk(b("")).length === 0);
  check("malformed (no terminator) does not throw", (() => { try { dechunk(b("zz\r\nxx")); return true; } catch { return false; } })());
  check("a zero size stops immediately", dechunk(b("0\r\n\r\njunk")).length === 0);
}

section("A3. detectProxy environment variables");
{
  const saved = { ...process.env };
  try {
    delete process.env.HTTPS_PROXY; delete process.env.https_proxy;
    delete process.env.ALL_PROXY; delete process.env.all_proxy;
    delete process.env.HTTP_PROXY; delete process.env.http_proxy;
    process.env.HTTPS_PROXY = "http://env-proxy.test:3128";
    const p = detectProxy();
    check("HTTPS_PROXY is honoured", p?.host === "env-proxy.test" && p?.port === 3128, JSON.stringify(p));
    check("the source is labelled env", String(p?.source).startsWith("env:"), p?.source);

    process.env.HTTPS_PROXY = "socks5://socks.test:1080";
    const p2 = detectProxy();
    check("socks5 in the environment is recognized too", p2?.protocol === "socks5", JSON.stringify(p2));
  } finally {
    process.env = saved;
  }
}

section("A4. parseWininetRegistry");
{
  const ON = "HKCU\\Software\\...\\Internet Settings\r\n    ProxyEnable    REG_DWORD    0x1\r\n    ProxyServer    REG_SZ    127.0.0.1:3128\r\n";
  const OFF = "    ProxyEnable    REG_DWORD    0x0\r\n    ProxyServer    REG_SZ    127.0.0.1:3128\r\n";
  check("enabled with a server -> proxy parsed", parseWininetRegistry(ON)?.port === 3128, JSON.stringify(parseWininetRegistry(ON)));
  check("ProxyEnable=0 -> null", parseWininetRegistry(OFF) === null);
  check("missing ProxyServer -> null", parseWininetRegistry("    ProxyEnable    REG_DWORD    0x1\r\n") === null);
  check("empty input -> null", parseWininetRegistry("") === null);
  check("null input -> null", parseWininetRegistry(null) === null);
  check("no ProxyEnable line -> null", parseWininetRegistry("arbitrary content") === null);
  check("the HTTP multi-segment form is parsed", parseWininetRegistry("    ProxyEnable    REG_DWORD    0x1\r\n    ProxyServer    REG_SZ    http=a:1;https=b:2\r\n")?.host === "b", JSON.stringify(parseWininetRegistry("    ProxyEnable    REG_DWORD    0x1\r\n    ProxyServer    REG_SZ    http=a:1;https=b:2\r\n")));
}

section("A5. readWininetProxy fallback path (injectable executor)");
{
  // This path cannot be forced on a real Windows machine through environment variables
  // (clearing PATH still does not stop reg.exe from being found), so the executor is made
  // injectable -- otherwise this catch could never be reached by a test.
  const threw = readWininetProxy(() => { throw Object.assign(new Error("spawn reg ENOENT"), { code: "ENOENT" }); });
  check("returns null instead of throwing when reg is not executable", threw === null, JSON.stringify(threw));

  const empty = readWininetProxy(() => "");
  check("returns null when reg output is empty", empty === null);

  const good = readWininetProxy(() => "    ProxyEnable    REG_DWORD    0x1\r\n    ProxyServer    REG_SZ    p.test:8080\r\n");
  check("normal injected output is parsed", good?.host === "p.test" && good?.port === 8080, JSON.stringify(good));

  const malformed = readWininetProxy(() => "ProxyEnable REG_DWORD 0x1\r\nProxyServer REG_SZ :::bad:::\r\n");
  check("returns null when reg output is malformed", malformed === null, JSON.stringify(malformed));
}

/* ================== B. tunnels (local mocks) ================== */

function makeEchoServer() {
  return net.createServer((s) => { s.on("data", (d) => s.write(d)); s.on("error", () => {}); });
}

function makeBlackHoleServer() {
  // accepts the connection but never responds -- used to trigger the TLS/read timeout
  return net.createServer((s) => { s.on("error", () => {}); });
}

function makeTlsServer({ status = 200, body = JSON.stringify({ ok: true }) } = {}) {
  // An HTTP response over TLS, which is what httpsGetOverSocket parses. Plain HTTP inside the
  // TLS layer rather than a real HTTPS client path, because the function under test writes the
  // request itself and reads the raw response.
  return tls.createServer({ cert: fs.readFileSync(CERT), key: fs.readFileSync(KEY) }, (s) => {
    let buf = "";
    const onData = (d) => {
      buf += d.toString("latin1");
      if (!buf.includes("\r\n\r\n")) return;
      s.removeListener("data", onData);
      const reason = status === 200 ? "OK" : "Error";
      s.write(
        `HTTP/1.1 ${status} ${reason}\r\n` +
        "Content-Type: application/json\r\n" +
        `Content-Length: ${Buffer.byteLength(body)}\r\n` +
        "Connection: close\r\n\r\n" + body
      );
      s.end();
    };
    s.on("data", onData);
    s.on("error", () => {});
  });
}

function makeConnectProxy({ reject = false } = {}) {
  return net.createServer((client) => {
    let buf = "";
    const onData = (d) => {
      buf += d.toString("latin1");
      if (!buf.includes("\r\n\r\n")) return;
      client.removeListener("data", onData);
      const first = buf.split("\r\n")[0];
      const m = /^CONNECT\s+([^:\s]+):(\d+)/i.exec(first);
      if (!m || reject) {
        client.write("HTTP/1.1 403 Forbidden\r\n\r\n");
        client.end();
        return;
      }
      const up = net.connect({ host: m[1], port: Number(m[2]) }, () => {
        client.write("HTTP/1.1 200 Connection established\r\n\r\n");
        client.pipe(up); up.pipe(client);
      });
      up.on("error", () => client.destroy());
    };
    client.on("data", onData);
    client.on("error", () => {});
  });
}

function makeSocks5Server({ requireAuth = false, rep = 0x00 } = {}) {
  return net.createServer((c) => {
    let stage = 0;
    let buf = Buffer.alloc(0);
    c.on("error", () => {});
    c.on("data", (d) => {
      buf = Buffer.concat([buf, d]);
      if (stage === 0) {
        if (buf.length < 2) return;
        const nm = buf[1];
        if (buf.length < 2 + nm) return;
        buf = buf.subarray(2 + nm);
        if (requireAuth) { c.write(Buffer.from([0x05, 0x02])); return; }
        c.write(Buffer.from([0x05, 0x00]));
        stage = 1;
        return;
      }
      if (stage === 1) {
        if (buf.length < 5) return;
        const atyp = buf[3];
        let host, need;
        if (atyp === 0x01) { host = `${buf[4]}.${buf[5]}.${buf[6]}.${buf[7]}`; need = 10; }
        else if (atyp === 0x03) { const len = buf[4]; host = buf.subarray(5, 5 + len).toString(); need = 5 + len + 2; }
        else { c.destroy(); return; }
        if (buf.length < need) return;
        const port = buf.readUInt16BE(need - 2);
        if (rep !== 0x00) {
          c.write(Buffer.from([0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
          c.end();
          return;
        }
        const up = net.connect({ host, port }, () => {
          c.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
          c.pipe(up); up.pipe(c);
        });
        up.on("error", () => c.destroy());
        stage = 2;
      }
    });
  });
}

/** One echo round trip over the tunnel socket, proving the tunnel really carries data */
function echoRoundTrip(socket, msg = "ping", timeoutMs = 3000) {
  return new Promise((resolve) => {
    const t = setTimeout(() => { socket.destroy(); resolve(null); }, timeoutMs);
    socket.once("data", (d) => { clearTimeout(t); socket.destroy(); resolve(d.toString()); });
    socket.on("error", () => { clearTimeout(t); resolve(null); });
    socket.write(msg);
  });
}

/**
 * Obtain a port that "Node's fetch will not blacklist".
 *
 * Why this is needed: on this machine the Windows dynamic port range starts at 1024
 * (measured with netsh, not the commonly quoted 49152), while undici keeps a blacklist of
 * "unsafe ports" (4045 / 4190 / 6000 / 6665-6669 / 10080 ...). A random port collides with
 * it about 0.3% of the time -- 1 hit in 300 sampled attempts (port 4190), which surfaces as
 * `fetch failed (bad port)` and makes the test fail intermittently. On a collision, take
 * another port and start over.
 */
async function listenForFetch(makeServer) {
  for (let i = 0; i < 20; i++) {
    const srv = makeServer();
    const port = await listen(srv);
    try {
      await fetch(`http://127.0.0.1:${port}/__fetchable_probe`, { signal: AbortSignal.timeout(3000) });
      return { port, server: srv };
    } catch (e) {
      const msg = `${e?.message ?? ""} ${e?.cause?.message ?? ""}`;
      if (/bad port/i.test(msg)) {
        await new Promise((r) => srv.close(r));
        const idx = openServers.indexOf(srv);
        if (idx >= 0) openServers.splice(idx, 1);
        continue;
      }
      return { port, server: srv }; // any other error means the port itself is usable
    }
  }
  throw new Error("20 consecutive attempts all landed on a port blacklisted by fetch -- the environment is abnormal");
}

section("B1. HTTP CONNECT tunnel");
{
  const echoPort = await listen(makeEchoServer());
  const proxyPort = await listen(makeConnectProxy());
  const proxy = normalizeProxy(`http://127.0.0.1:${proxyPort}`);

  try {
    const sock = await openTunnel(proxy, "127.0.0.1", echoPort, 3000);
    check("CONNECT handshake succeeds and returns a socket", !!sock && typeof sock.write === "function");
    const back = await echoRoundTrip(sock);
    check("the tunnel carries data in both directions", back === "ping", `got ${JSON.stringify(back)}`);
  } catch (e) {
    check("CONNECT handshake succeeds and returns a socket", false, String(e.message));
  }

  const rejectPort = await listen(makeConnectProxy({ reject: true }));
  const rejectProxy = normalizeProxy(`http://127.0.0.1:${rejectPort}`);
  let errMsg = "";
  try {
    await openTunnel(rejectProxy, "127.0.0.1", echoPort, 3000);
  } catch (e) { errMsg = String(e.message); }
  check("a rejected CONNECT is reported as an error", errMsg.includes("rejected"), errMsg);
  check("the rejection message carries the status code", /403/.test(errMsg), errMsg);

  let connErr = "";
  try {
    await openTunnel(normalizeProxy("http://127.0.0.1:9"), "127.0.0.1", echoPort, 2000);
  } catch (e) { connErr = String(e.message); }
  check("an unreachable proxy is reported as an error", connErr.length > 0, connErr);
}

section("B2. SOCKS5 tunnel");
{
  const echoPort = await listen(makeEchoServer());

  const s5Port = await listen(makeSocks5Server());
  const s5 = normalizeProxy(`socks5://127.0.0.1:${s5Port}`);
  try {
    const sock = await openTunnel(s5, "127.0.0.1", echoPort, 3000);
    const back = await echoRoundTrip(sock, "socks");
    check("SOCKS5 handshake + domain addressing succeeds", back === "socks", `got ${JSON.stringify(back)}`);
  } catch (e) {
    check("SOCKS5 handshake + domain addressing succeeds", false, String(e.message));
  }

  const authPort = await listen(makeSocks5Server({ requireAuth: true }));
  let authErr = "";
  try { await openTunnel(normalizeProxy(`socks5://127.0.0.1:${authPort}`), "127.0.0.1", echoPort, 3000); }
  catch (e) { authErr = String(e.message); }
  check("SOCKS5 demanding authentication is reported as an error", authErr.includes("authentication"), authErr);

  const failPort = await listen(makeSocks5Server({ rep: 0x05 }));
  let repErr = "";
  try { await openTunnel(normalizeProxy(`socks5://127.0.0.1:${failPort}`), "127.0.0.1", echoPort, 3000); }
  catch (e) { repErr = String(e.message); }
  check("SOCKS5 with REP!=0 is reported as an error", repErr.includes("REP=5"), repErr);

  // accepts the connection but never responds -> must be bounded by timeoutMs, must not hang
  const mutePort = await listen(net.createServer(() => { /* accept only, never answer */ }));
  let toErr = "";
  const ts = Date.now();
  try { await openTunnel(normalizeProxy(`socks5://127.0.0.1:${mutePort}`), "127.0.0.1", echoPort, 1200); }
  catch (e) { toErr = String(e.message); }
  check("SOCKS5 with no response times out instead of hanging", /timed out/.test(toErr), toErr);
  check("the timeout is bounded by timeoutMs", Date.now() - ts < 6000, `took ${Date.now() - ts}ms`);
}

/* ================== C. httpsGetJson ================== */

section("C1. direct path");
{
  const { port } = await listenForFetch(() => http.createServer((req, res) => {
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ version: "9.9.9", path: req.url }));
  }));

  try {
    const r = await httpsGetJson(`http://127.0.0.1:${port}/probe.json`, { proxy: null, timeoutMs: 3000 });
    check("a direct connection returns JSON", r.json?.version === "9.9.9", JSON.stringify(r.json));
    check("via is labelled direct", r.via === "direct", r.via);
    check("the query string / path is passed through", r.json?.path === "/probe.json", r.json?.path);
  } catch (e) {
    check("a direct connection returns JSON", false, String(e.message));
  }

  // dead port: take a port fetch accepts, then close it, so that the failure is a REFUSED
  // CONNECTION rather than a blacklist hit -- port 9 is itself on the blacklist, so using it
  // would make the assertion pass for the wrong reason.
  const dead = await listenForFetch(() => http.createServer(() => {}));
  await new Promise((r) => dead.server.close(r));

  let directErr = "";
  try { await httpsGetJson(`http://127.0.0.1:${dead.port}/x.json`, { proxy: null, timeoutMs: 1500 }); }
  catch (e) { directErr = String(e.message); }
  check("a failed direct connection reports an error with a clear prefix", directErr.includes("Direct connection failed"), directErr);
  check("the direct failure message carries cause detail", directErr.length > 12, directErr);
  check("the failure comes from the connection layer, not a blacklisted port", !/bad port/i.test(directErr), directErr);
}

section("C2. failure surface of the proxied path");
{
  // proxy reachable but the target is a black-hole service: the TLS handshake hangs -> the timeout branch fires
  const bhPort = await listen(makeBlackHoleServer());
  const proxyPort = await listen(makeConnectProxy());
  let tErr = "";
  const t0 = Date.now();
  try {
    // must point at the black-hole server with an EXPLICIT port: with the default 443 the
    // proxy would fail to connect to 443 first and the error would come from the CONNECT
    // stage rather than the TLS stage -- the assertion would then pass for the wrong reason.
    await httpsGetJson(`https://127.0.0.1:${bhPort}/never.json`, {
      proxy: `http://127.0.0.1:${proxyPort}`,
      timeoutMs: 1200,
    });
  } catch (e) { tErr = String(e.message); }
  const elapsed = Date.now() - t0;
  check("through a proxy against a black-hole target, the TLS read timeout fires", /timed out/.test(tErr), tErr);
  check("the timeout is bounded by timeoutMs (it does not drag on to the default)", elapsed < 6000, `took ${elapsed}ms`);

  let pErr = "";
  try {
    await httpsGetJson("https://example.invalid/x.json", { proxy: "http://127.0.0.1:9", timeoutMs: 1500 });
  } catch (e) { pErr = String(e.message); }
  check("an unreachable proxy is reported as an error", pErr.length > 0, pErr);
}

/* ================== E. TLS over the tunnel ================== */

section("E. TLS over the tunnel (the proxy path, with a real handshake)");
{
  const tlsPort = await listen(makeTlsServer({ body: JSON.stringify({ ok: true, n: 1 }) }));
  const proxyPort = await listen(makeConnectProxy());

  // This is the path a machine without a proxy never reaches: httpsGetJson goes direct, and
  // the whole of httpsGetOverSocket's success branch stays unexecuted.
  const r = await httpsGetJson(`https://127.0.0.1:${tlsPort}/probe.json`, {
    proxy: `http://127.0.0.1:${proxyPort}`,
    timeoutMs: 4000,
  });
  check("through a proxy, a TLS round trip returns parsed JSON", r?.json?.ok === true, JSON.stringify(r?.json));
  check("the result names the proxy it went through", /^proxy:http:\/\/127\.0\.0\.1:/.test(r?.via ?? ""), String(r?.via));

  const s500Port = await listen(makeTlsServer({ status: 500, body: "{}" }));
  let e500 = "";
  try {
    await httpsGetJson(`https://127.0.0.1:${s500Port}/x.json`, { proxy: `http://127.0.0.1:${proxyPort}`, timeoutMs: 4000 });
  } catch (e) { e500 = String(e.message); }
  check("a non-200 through the tunnel is reported as an HTTP error", /HTTP 500/.test(e500), e500);

  const badPort = await listen(makeTlsServer({ body: "not json at all" }));
  let eBad = "";
  try {
    await httpsGetJson(`https://127.0.0.1:${badPort}/x.json`, { proxy: `http://127.0.0.1:${proxyPort}`, timeoutMs: 4000 });
  } catch (e) { eBad = String(e.message); }
  check("a non-JSON 200 through the tunnel is reported, not accepted", /not valid JSON/.test(eBad), eBad);

  // The assertions above are only worth anything if the certificate was actually verified. If
  // anyone makes them pass by turning verification off, this says so rather than letting the
  // suite look stronger than it is.
  check("the handshake succeeded through trust, not by disabling verification",
    !process.env.NODE_TLS_REJECT_UNAUTHORIZED,
    "NODE_TLS_REJECT_UNAUTHORIZED is set: the TLS checks above would pass without a trusted certificate");
}

/* ================== summary ================== */

closeAll();
section("Summary");
console.log(`\n  passed ${pass} / ${pass + fail}`);
if (fail) { console.log("\n  failed checks:"); for (const f of failures) console.log(`    - ${f}`); }
process.exit(fail === 0 ? 0 : 1);
