#!/usr/bin/env node
'use strict';

/**
 * asset-proxy.js — fetch a remote asset and diagnose why it fails.
 *
 * Zero dependencies. Node 18+.
 *
 *   node asset-proxy.js
 *   PORT=8080 TARGET_URL='https://example.com/x.jpg' node asset-proxy.js
 *
 * Endpoints:
 *   GET /health              liveness
 *   GET /image               streams the asset to you (the actual proxy)
 *   GET /fetch               fetches once, returns JSON: status, headers, timings
 *   GET /fetch?profile=none  pick a header profile (none|ua|browser|referer)
 *   GET /fetch?family=4      force IPv4 (or 6)
 *   GET /diagnose            THE ONE YOU WANT — full matrix of tests
 */

const http = require('http');
const https = require('https');
const dnsp = require('dns').promises;
const net = require('net');
const { URL } = require('url');

const PORT = Number(process.env.PORT) || 3000;
const TARGET_URL =
  process.env.TARGET_URL ||
  'https://www.tui.se/cdn/media/sys_master/h07/h51/15866047922206/740-425-RIU-TUI-walk-to-beach.jpg';
const TIMEOUT_MS = Number(process.env.TIMEOUT_MS) || 15000;
const MAX_REDIRECTS = 5;

// ---------------------------------------------------------------------------
// Header profiles. The difference between these is usually the whole story.
// ---------------------------------------------------------------------------

const PROFILES = {
  // What Node sends by default: Host + Connection, nothing else.
  none: {},

  // Just a browser UA. Defeats the laziest bot filters.
  ua: {
    'User-Agent':
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 ' +
      '(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
  },

  // A full, believable Chrome image request.
  browser: {
    'User-Agent':
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 ' +
      '(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
    Accept: 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
    'Accept-Language': 'sv-SE,sv;q=0.9,en-US;q=0.8,en;q=0.7',
    'Accept-Encoding': 'gzip, deflate, br',
    'Sec-Fetch-Dest': 'image',
    'Sec-Fetch-Mode': 'no-cors',
    'Sec-Fetch-Site': 'same-origin',
    'sec-ch-ua': '"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"macOS"',
    Connection: 'keep-alive',
  },

  // Same, plus a Referer from the origin site. Hotlink protection cares.
  referer: null, // filled in below
};

PROFILES.referer = { ...PROFILES.browser, Referer: 'https://www.tui.se/' };

// ---------------------------------------------------------------------------
// One HTTP(S) request, instrumented.
// ---------------------------------------------------------------------------

function requestOnce(urlStr, opts = {}) {
  const {
    headers = {},
    family, // 4, 6, or undefined (let the OS choose)
    method = 'GET',
    timeout = TIMEOUT_MS,
    collectBody = true,
    maxBodyBytes = 2048,
  } = opts;

  return new Promise((resolve) => {
    const url = new URL(urlStr);
    const isHttps = url.protocol === 'https:';
    const lib = isHttps ? https : http;

    const t0 = process.hrtime.bigint();
    const marks = {};
    const ms = (t) => Number(t - t0) / 1e6;

    const reqOpts = {
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname + url.search,
      method,
      headers: { Host: url.hostname, ...headers },
      timeout,
      servername: url.hostname, // explicit SNI
      // Node 20 races v4/v6 by default; pin it so the test means something.
      autoSelectFamily: family === undefined,
    };
    if (family) reqOpts.family = family;

    const req = lib.request(reqOpts);
    let settled = false;
    const done = (payload) => {
      if (settled) return;
      settled = true;
      req.destroy();
      resolve(payload);
    };

    req.on('socket', (socket) => {
      socket.on('lookup', (err, address, fam) => {
        marks.dns = ms(process.hrtime.bigint());
        marks.resolvedIp = address;
        marks.resolvedFamily = fam;
        if (err) marks.dnsError = err.message;
      });
      socket.on('connect', () => {
        marks.tcpConnect = ms(process.hrtime.bigint());
      });
      socket.on('secureConnect', () => {
        marks.tlsHandshake = ms(process.hrtime.bigint());
        marks.tls = {
          protocol: socket.getProtocol(),
          cipher: socket.getCipher() && socket.getCipher().name,
          authorized: socket.authorized,
          authorizationError: socket.authorizationError
            ? String(socket.authorizationError)
            : null,
        };
        const cert = socket.getPeerCertificate();
        if (cert && cert.subject) {
          marks.tls.subjectCN = cert.subject.CN;
          marks.tls.issuerCN = cert.issuer && cert.issuer.CN;
          marks.tls.validTo = cert.valid_to;
          marks.tls.san = cert.subjectaltname;
        }
      });
    });

    req.on('response', (res) => {
      marks.ttfb = ms(process.hrtime.bigint());
      const chunks = [];
      let bytes = 0;

      res.on('data', (c) => {
        bytes += c.length;
        if (collectBody && Buffer.concat(chunks).length < maxBodyBytes) chunks.push(c);
      });

      res.on('end', () => {
        marks.total = ms(process.hrtime.bigint());
        const body = Buffer.concat(chunks);
        done({
          ok: res.statusCode >= 200 && res.statusCode < 400,
          statusCode: res.statusCode,
          statusMessage: res.statusMessage,
          headers: res.headers,
          bytes,
          bodyPreview: sniffBody(res.headers, body, maxBodyBytes),
          timings: marks,
        });
      });

      res.on('error', (err) =>
        done({ ok: false, error: describeError(err), timings: marks }),
      );
    });

    req.on('timeout', () =>
      done({
        ok: false,
        error: { code: 'ETIMEDOUT', message: `no response within ${timeout}ms` },
        timings: marks,
      }),
    );

    req.on('error', (err) =>
      done({ ok: false, error: describeError(err), timings: marks }),
    );

    req.end();
  });
}

function sniffBody(headers, buf, max) {
  if (!buf.length) return null;
  const ct = String(headers['content-type'] || '');
  if (ct.startsWith('image/')) {
    return { kind: 'image', magic: buf.subarray(0, 4).toString('hex') };
  }
  // Error pages are the interesting case — Akamai/Cloudflare say why here.
  return {
    kind: 'text',
    text: buf.subarray(0, max).toString('utf8').replace(/\s+/g, ' ').trim(),
  };
}

function describeError(err) {
  return {
    code: err.code || null,
    errno: err.errno || null,
    syscall: err.syscall || null,
    message: err.message,
    // Certificate problems surface here and mean something very specific.
    cert: err.cert ? { subject: err.cert.subject, issuer: err.cert.issuer } : undefined,
  };
}

// Follow redirects manually so each hop is visible.
async function fetchFollowing(urlStr, opts = {}) {
  const hops = [];
  let current = urlStr;

  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const res = await requestOnce(current, opts);
    hops.push({ url: current, ...res });

    const loc = res.headers && res.headers.location;
    if (res.statusCode >= 300 && res.statusCode < 400 && loc) {
      current = new URL(loc, current).toString();
      continue;
    }
    return { final: res, finalUrl: current, hops };
  }
  return { final: hops[hops.length - 1], finalUrl: current, hops, error: 'too many redirects' };
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

async function resolveAll(hostname) {
  const out = { hostname, a: [], aaaa: [], cname: null, errors: {} };

  await Promise.all([
    dnsp.resolve4(hostname).then(
      (r) => (out.a = r),
      (e) => (out.errors.a = e.code || e.message),
    ),
    dnsp.resolve6(hostname).then(
      (r) => (out.aaaa = r),
      (e) => (out.errors.aaaa = e.code || e.message),
    ),
    dnsp.resolveCname(hostname).then(
      (r) => (out.cname = r),
      (e) => (out.errors.cname = e.code || e.message),
    ),
  ]);

  out.servers = dnsp.getServers();
  return out;
}

function tcpProbe(host, port, timeout = 5000) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const sock = net.connect({ host, port, timeout });
    const finish = (result) => {
      sock.destroy();
      resolve({ host, port, ...result, ms: Date.now() - t0 });
    };
    sock.once('connect', () => finish({ reachable: true }));
    sock.once('timeout', () => finish({ reachable: false, error: 'timeout' }));
    sock.once('error', (e) => finish({ reachable: false, error: e.code || e.message }));
  });
}

async function diagnose(urlStr) {
  const url = new URL(urlStr);
  const port = Number(url.port) || (url.protocol === 'https:' ? 443 : 80);

  const report = {
    target: urlStr,
    startedAt: new Date().toISOString(),
    node: process.version,
    env: {
      // A proxy set in the environment is a very common cause of this exact
      // symptom — the shell you test from has it, the service does not.
      HTTP_PROXY: process.env.HTTP_PROXY || process.env.http_proxy || null,
      HTTPS_PROXY: process.env.HTTPS_PROXY || process.env.https_proxy || null,
      NO_PROXY: process.env.NO_PROXY || process.env.no_proxy || null,
      NODE_TLS_REJECT_UNAUTHORIZED: process.env.NODE_TLS_REJECT_UNAUTHORIZED || null,
      NODE_EXTRA_CA_CERTS: process.env.NODE_EXTRA_CA_CERTS || null,
    },
  };

  // 1. DNS
  report.dns = await resolveAll(url.hostname);

  // 2. Raw TCP reachability, per resolved IP
  const ips = [...report.dns.a, ...report.dns.aaaa];
  report.tcp = await Promise.all(ips.slice(0, 8).map((ip) => tcpProbe(ip, port)));

  // 3. Header profiles, sequential so results are comparable
  report.profiles = {};
  for (const name of Object.keys(PROFILES)) {
    const r = await fetchFollowing(urlStr, { headers: PROFILES[name] });
    report.profiles[name] = {
      statusCode: r.final.statusCode ?? null,
      error: r.final.error ?? null,
      bytes: r.final.bytes ?? 0,
      contentType: r.final.headers ? r.final.headers['content-type'] : null,
      redirects: r.hops.length - 1,
      finalUrl: r.finalUrl !== urlStr ? r.finalUrl : undefined,
      bodyPreview: r.final.bodyPreview,
      timings: r.final.timings,
      // CDN fingerprints — tells you who is actually refusing you.
      cdn: r.final.headers ? pickCdnHeaders(r.final.headers) : null,
    };
  }

  // 4. Address family. Broken IPv6 egress is a top-3 cause here.
  report.addressFamily = {};
  for (const fam of [4, 6]) {
    if (fam === 6 && report.dns.aaaa.length === 0) {
      report.addressFamily.ipv6 = { skipped: 'no AAAA record' };
      continue;
    }
    const r = await requestOnce(urlStr, { headers: PROFILES.browser, family: fam });
    report.addressFamily[fam === 4 ? 'ipv4' : 'ipv6'] = {
      statusCode: r.statusCode ?? null,
      error: r.error ?? null,
      resolvedIp: r.timings.resolvedIp,
      timings: r.timings,
    };
  }

  // 5. TLS detail from the browser-profile attempt
  const tlsSample = await requestOnce(urlStr, {
    headers: PROFILES.browser,
    method: 'HEAD',
    collectBody: false,
  });
  report.tls = tlsSample.timings.tls || { error: tlsSample.error };

  report.verdict = verdict(report);
  report.finishedAt = new Date().toISOString();
  return report;
}

function pickCdnHeaders(h) {
  const keys = [
    'server',
    'via',
    'x-cache',
    'x-cache-remote',
    'x-served-by',
    'cf-ray',
    'akamai-grn',
    'x-akamai-request-id',
    'x-amz-cf-id',
    'x-request-id',
    'set-cookie',
    'x-frame-options',
  ];
  const out = {};
  for (const k of keys) if (h[k] !== undefined) out[k] = h[k];
  return Object.keys(out).length ? out : null;
}

/** Plain-English reading of the report. */
function verdict(r) {
  const notes = [];
  const p = r.profiles;

  if (r.dns.a.length === 0 && r.dns.aaaa.length === 0) {
    notes.push(
      'DNS did not resolve at all. Check /etc/resolv.conf and whether this host uses ' +
        'a split-horizon or VPC resolver that cannot see public records.',
    );
    return notes;
  }

  const anyTcp = r.tcp.some((t) => t.reachable);
  if (!anyTcp) {
    notes.push(
      'DNS resolves but no TCP connection succeeded to any IP. This is a network path ' +
        'problem, not an HTTP one — security group egress, NACL, firewall, or missing NAT ' +
        'gateway for a private subnet.',
    );
    return notes;
  }

  const codes = Object.fromEntries(
    Object.entries(p).map(([k, v]) => [k, v.statusCode || (v.error && v.error.code)]),
  );

  const anyOk = Object.values(p).some((v) => v.statusCode === 200);
  const noneOk = !anyOk;

  if (noneOk && Object.values(p).every((v) => v.error && v.error.code === 'ETIMEDOUT')) {
    notes.push(
      'TCP connects but HTTP never responds. Typical of a firewall that permits the ' +
        'handshake then drops, or an egress proxy that must be used but is not configured.',
    );
  }

  if (p.none.statusCode !== 200 && p.browser.statusCode === 200) {
    notes.push(
      'Fails with no headers, succeeds with browser headers. The CDN is doing bot ' +
        'filtering on User-Agent. Send a realistic User-Agent and Accept from your service.',
    );
  }

  if (p.browser.statusCode !== 200 && p.referer.statusCode === 200) {
    notes.push(
      'Succeeds only when a Referer is sent. This is hotlink protection — set ' +
        'Referer: https://www.tui.se/ on the outbound request.',
    );
  }

  if (noneOk && [401, 403].includes(p.referer.statusCode)) {
    notes.push(
      `All profiles return ${p.referer.statusCode}. Headers are not the issue — the CDN is ` +
        'rejecting this source IP. Datacenter/cloud ranges are commonly blocked by bot ' +
        'management (Akamai, Cloudflare), and geo-rules may require a Swedish/EU exit IP. ' +
        'Read bodyPreview for the reference number and ask TUI to allowlist, or route via ' +
        'a NAT/egress IP that is permitted.',
    );
  }

  if (noneOk && p.referer.statusCode === 404) {
    notes.push(
      'A 404 from every profile suggests the asset path is genuinely gone or the CDN ' +
        'serves different objects per region. Verify the URL is still live from a browser.',
    );
  }

  if (p.referer.statusCode === 429 || p.browser.statusCode === 429) {
    notes.push('Rate limited (429). Back off and cache the asset locally.');
  }

  const v4 = r.addressFamily.ipv4 || {};
  const v6 = r.addressFamily.ipv6 || {};
  if (v4.statusCode === 200 && v6.error) {
    notes.push(
      'Works over IPv4 but fails over IPv6. Your host has AAAA records available but no ' +
        'working IPv6 egress. Fix the routing, or pin Node to IPv4 ' +
        '(autoSelectFamily / family: 4 / --dns-result-order=ipv4first).',
    );
  }

  if (r.env.HTTPS_PROXY || r.env.HTTP_PROXY) {
    notes.push(
      'A proxy is set in the environment. Note that Node core (https.request) ignores ' +
        'HTTPS_PROXY unless you wire in an agent — curl honours it, so curl succeeding ' +
        'while Node fails on the same box is expected.',
    );
  }

  if (r.tls && r.tls.authorized === false) {
    notes.push(
      `TLS certificate not trusted: ${r.tls.authorizationError}. Likely a TLS-intercepting ` +
        'middlebox, or a container image missing the CA bundle (install ca-certificates).',
    );
  }

  if (anyOk && notes.length === 0) {
    notes.push(
      'The asset fetched successfully from this host. If production still fails, the ' +
        'difference is environmental — compare egress IP, DNS resolver, and proxy env vars ' +
        'between this process and the failing one.',
    );
  }

  notes.push(`status by profile: ${JSON.stringify(codes)}`);
  return notes;
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

function json(res, code, obj) {
  const body = JSON.stringify(obj, null, 2);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const q = url.searchParams;
  const target = q.get('url') || TARGET_URL;

  try {
    if (url.pathname === '/health') {
      return json(res, 200, { ok: true, target: TARGET_URL, uptime: process.uptime() });
    }

    if (url.pathname === '/' ) {
      return json(res, 200, {
        target: TARGET_URL,
        endpoints: {
          '/image': 'stream the asset through this server',
          '/fetch': 'one attempt, JSON result (?profile=none|ua|browser|referer, ?family=4|6)',
          '/diagnose': 'full diagnostic matrix — start here',
          '/health': 'liveness',
        },
      });
    }

    if (url.pathname === '/diagnose') {
      const report = await diagnose(target);
      return json(res, 200, report);
    }

    if (url.pathname === '/fetch') {
      const profile = q.get('profile') || 'browser';
      if (!PROFILES[profile]) {
        return json(res, 400, { error: `unknown profile`, valid: Object.keys(PROFILES) });
      }
      const family = q.get('family') ? Number(q.get('family')) : undefined;
      const r = await fetchFollowing(target, { headers: PROFILES[profile], family });
      return json(res, r.final.ok ? 200 : 502, {
        target,
        profile,
        family: family || 'auto',
        result: r.final,
        hops: r.hops.map((h) => ({ url: h.url, status: h.statusCode, location: h.headers && h.headers.location })),
      });
    }

    if (url.pathname === '/image') {
      return streamAsset(target, q.get('profile') || 'browser', res);
    }

    return json(res, 404, { error: 'not found', try: '/diagnose' });
  } catch (err) {
    return json(res, 500, { error: err.message, stack: err.stack });
  }
});

/** Pipe the upstream asset straight to the client, preserving content type. */
function streamAsset(urlStr, profileName, res, depth = 0) {
  if (depth > MAX_REDIRECTS) {
    return json(res, 508, { error: 'too many redirects' });
  }

  const url = new URL(urlStr);
  const lib = url.protocol === 'https:' ? https : http;
  const headers = { Host: url.hostname, ...(PROFILES[profileName] || PROFILES.browser) };
  // We are decoding nothing ourselves, so do not ask for br/gzip on a binary.
  delete headers['Accept-Encoding'];

  const upstream = lib.request(
    {
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + url.search,
      method: 'GET',
      headers,
      timeout: TIMEOUT_MS,
      servername: url.hostname,
    },
    (up) => {
      if (up.statusCode >= 300 && up.statusCode < 400 && up.headers.location) {
        up.resume();
        return streamAsset(new URL(up.headers.location, urlStr).toString(), profileName, res, depth + 1);
      }

      if (up.statusCode !== 200) {
        const chunks = [];
        up.on('data', (c) => chunks.length < 20 && chunks.push(c));
        up.on('end', () =>
          json(res, 502, {
            error: 'upstream refused',
            upstreamStatus: up.statusCode,
            upstreamHeaders: up.headers,
            body: Buffer.concat(chunks).toString('utf8').slice(0, 2000),
            hint: 'run /diagnose for the reason',
          }),
        );
        return;
      }

      res.writeHead(200, {
        'Content-Type': up.headers['content-type'] || 'application/octet-stream',
        'Content-Length': up.headers['content-length'],
        'Cache-Control': 'public, max-age=3600',
      });
      up.pipe(res);
    },
  );

  upstream.on('timeout', () => {
    upstream.destroy();
    if (!res.headersSent) json(res, 504, { error: 'upstream timeout', ms: TIMEOUT_MS });
  });

  upstream.on('error', (err) => {
    if (!res.headersSent) json(res, 502, { error: 'upstream error', detail: describeError(err) });
  });

  upstream.end();
}

server.listen(PORT, () => {
  console.log(`listening on http://localhost:${PORT}`);
  console.log(`target:   ${TARGET_URL}`);
  console.log(`start at: http://localhost:${PORT}/diagnose`);
});
