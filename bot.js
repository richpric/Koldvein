#!/usr/bin/env node
'use strict';

/*
 * bot.js — Koldvein Telegram bot
 * Env: BOT_TOKEN, MINI_APP_URL, HUB_DOMAIN, ADMIN_CHAT_ID, BOT_NOTIFY_SECRET, BOT_NOTIFY_PORT
 */

const http = require('node:http');

const BOT_TOKEN     = process.env.BOT_TOKEN || '';
const MINI_APP_URL  = process.env.MINI_APP_URL || '';
const HUB_DOMAIN    = process.env.HUB_DOMAIN || '';
const ADMIN_CHAT_ID = String(process.env.ADMIN_CHAT_ID || '7072004980');
const NOTIFY_SECRET = process.env.BOT_NOTIFY_SECRET || '';
const NOTIFY_PORT   = Number(process.env.BOT_NOTIFY_PORT || 3099);

const log = (...a) => console.log('[' + new Date().toISOString() + ']', ...a);
const err = (...a) => console.error('[' + new Date().toISOString() + ']', ...a);

if (!BOT_TOKEN)  { err('[bot] BOT_TOKEN missing'); process.exit(1); }
if (!/^\d+:[A-Za-z0-9_-]{30,}$/.test(BOT_TOKEN)) { err('[bot] BOT_TOKEN bad format'); process.exit(1); }
if (!MINI_APP_URL) { err('[bot] MINI_APP_URL missing'); process.exit(1); }

function loadCtor() {
  let m;
  try { m = require('node-telegram-bot-api'); } catch (e) { err('node-telegram-bot-api missing:', e.message); return null; }
  if (typeof m === 'function') return m;
  if (m && typeof m.default === 'function') return m.default;
  if (m && typeof m.Bot === 'function') return m.Bot;
  return null;
}
const TelegramBot = loadCtor();
if (!TelegramBot) process.exit(1);

const bot = new TelegramBot(BOT_TOKEN, { polling: false });

function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
function money(n) { const v = Number(n); return Number.isFinite(v) ? v.toLocaleString('en-US') : String(n ?? '—'); }
function fmtTime(iso) { try { return new Date(iso).toUTCString(); } catch { return String(iso || ''); } }

function buildNotify(p) {
  const o = p.order || {}, u = p.user || {}, plan = p.plan || {};
  const isIran = o.provider === 'iran';
  const amount = isIran
    ? `<b>${esc(money(o.payAmount))}</b> <code>IRT</code> · ${esc(o.network || 'DONITO')}`
    : `<b>${esc(o.payAmount)}</b> <code>USDT</code> · ${esc(o.network || 'TRC20')}`;
  const L = [
    p.kind === 'slave_ready' ? '<b>🖥 New slave ready</b>' : '<b>💸 Payment received</b>', '',
  ];
  if (p.kind === 'slave_ready') {
    L.push(`<b>Name</b> · ${esc(p.slave.name)}`);
    L.push(`<b>IP</b> · <code>${esc(p.slave.ip)}</code>`);
    L.push(`<b>Cores</b> · ${esc(p.slave.cores)}`);
    return L.join('\n');
  }
  L.push(`<b>Plan</b> · ${esc(plan.name || o.planName || '—')}`);
  L.push(`<b>Amount</b> · ${amount}`);
  L.push(`<b>Method</b> · ${isIran ? 'Donito (Iran)' : 'USDT (TRC20)'}`);
  L.push(`<b>Status</b> · ${p.kind === 'delivered' ? '✅ Delivered' : '⏳ Paid, delivering…'}`);
  L.push('', `<b>User</b> · <code>${esc(u.username || '—')}</code>`);
  L.push(`<b>Order</b> · <code>${esc(o.id || '—')}</code>`);
  if (o.txHash) L.push(`<b>Ref</b> · <code>${esc(String(o.txHash).slice(0, 24))}…</code>`);
  if (o.paidAt) L.push(`<b>Paid</b> · ${esc(fmtTime(o.paidAt))}`);
  if (o.deliveredAt) L.push(`<b>Delivered</b> · ${esc(fmtTime(o.deliveredAt))}`);
  return L.join('\n');
}

async function sendToAdmin(html) {
  try { await bot.sendMessage(ADMIN_CHAT_ID, html, { parse_mode: 'HTML', disable_web_page_preview: true }); return true; }
  catch (e) { err('[bot] admin notify failed:', e.message); return false; }
}

let notifyServer = null;
function startNotifyServer() {
  if (notifyServer) return;
  notifyServer = http.createServer((req, res) => {
    if (req.method !== 'POST' || req.url !== '/internal/notify') { res.writeHead(404); return res.end('not found'); }
    if (!NOTIFY_SECRET) { res.writeHead(503); return res.end('disabled'); }
    if (req.headers['x-notify-secret'] !== NOTIFY_SECRET) { res.writeHead(401); return res.end('unauthorized'); }
    let buf = '';
    req.on('data', c => { buf += c; if (buf.length > 65536) req.destroy(); });
    req.on('end', async () => {
      let body = {};
      try { body = JSON.parse(buf || '{}'); } catch {}
      const ok = await sendToAdmin(buildNotify(body));
      res.writeHead(ok ? 200 : 500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok }));
    });
  });
  notifyServer.on('error', e => err('[bot] notify server:', e.message));
  notifyServer.listen(NOTIFY_PORT, '127.0.0.1', () => log('[bot] notify listening on 127.0.0.1:' + NOTIFY_PORT));
}

function registerHandlers() {
  bot.onText(/^\/start(?:@\w+)?(?:\s|$)/, async msg => {
    const chatId = msg.chat.id;
    const text = 'Welcome to Koldvein L7 hub';
    const isHttps = /^https:\/\//i.test(MINI_APP_URL);
    const kb = isHttps
      ? { inline_keyboard: [[{ text: '🚀 Open Mini App', web_app: { url: MINI_APP_URL } }]] }
      : { inline_keyboard: [[{ text: '🚀 Open Mini App', url: MINI_APP_URL }]] };
    try { await bot.sendMessage(chatId, text, { reply_markup: kb }); }
    catch (e) {
      err('start failed:', e.message);
      try { await bot.sendMessage(chatId, text + '\n\n' + MINI_APP_URL); } catch {}
    }
  });
  bot.on('message', async msg => {
    if (!msg.text || msg.text.startsWith('/')) return;
    const isHttps = /^https:\/\//i.test(MINI_APP_URL);
    const kb = isHttps
      ? { inline_keyboard: [[{ text: '🚀 Open Mini App', web_app: { url: MINI_APP_URL } }]] }
      : { inline_keyboard: [[{ text: '🚀 Open Mini App', url: MINI_APP_URL }]] };
    try { await bot.sendMessage(msg.chat.id, 'Welcome to Koldvein L7 hub', { reply_markup: kb }); } catch {}
  });
  bot.on('polling_error', e => {
    const code = (e && e.response && e.response.statusCode) || 0;
    const desc = (e && e.response && e.response.body && e.response.body.description) || e.message || '';
    if (code === 401) { err('FATAL 401'); try { bot.stopPolling(); } catch {} process.exit(1); }
    else if (code === 409) err('CONFLICT another polling instance');
    else if (code === 400 && /webhook/i.test(desc)) {
      err('removing webhook');
      bot.deleteWebHook().then(() => log('webhook removed')).catch(() => {});
    } else err('polling error (' + code + '):', desc);
  });
}

bot.getMe()
  .then(me => {
    log('[bot] @' + me.username + ' (' + me.id + ')');
    return bot.setMyCommands([{ command: 'start', description: 'Open Koldvein' }])
      .catch(e => err('setMyCommands:', e.message));
  })
  .then(() => {
    registerHandlers();
    bot.startPolling({ restart: true, interval: 2000, params: { timeout: 10 } });
    log('[bot] polling started');
    startNotifyServer();
  })
  .catch(e => { err('FATAL:', e.message); process.exit(1); });

function shutdown(sig) {
  log(sig + ' received');
  try { bot.stopPolling(); } catch {}
  try { notifyServer && notifyServer.close(); } catch {}
  setTimeout(() => process.exit(0), 500);
}
process.on('SIGINT',  () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
