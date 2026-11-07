#!/usr/bin/env node
'use strict';

const fs     = require('node:fs');
const path   = require('node:path');
const crypto = require('node:crypto');
const https  = require('node:https');
const http   = require('node:http');

/* ============================================================
 * PLANS — insertion order is UI order
 * price = USD for USDT, iranPrice = Toman for Donito
 * maxThreads was REMOVED. Threads now come from slave cores × 8.
 * ============================================================ */
const PLANS = {
  rookie: {
    id: 'rookie', name: 'Rookie Plan', tagline: '30 Days', days: 30,
    price: 1.99, iranPrice: 5000,
    maxDuration: 120, maxRate: 128, maxConcurrent: 1, cooldown: 30,
    features: ['30 days access','120s max duration','30s cooldown','1 concurrent session']
  },
  starter: {
    id: 'starter', name: 'Starter Plan', tagline: '30 Days', days: 30,
    price: 4.99, iranPrice: 20000,
    maxDuration: 180, maxRate: 160, maxConcurrent: 1, cooldown: 15,
    features: ['30 days access','180s max duration','15s cooldown','1 concurrent session']
  },
  standard: {
    id: 'standard', name: 'Standard Plan', tagline: '30 Days', days: 30,
    price: 9.99, iranPrice: 200000,
    maxDuration: 300, maxRate: 200, maxConcurrent: 1, cooldown: 10,
    features: ['30 days access','300s max duration','10s cooldown','1 concurrent session']
  },
  advanced: {
    id: 'advanced', name: 'Advanced Plan', tagline: '30 Days', days: 30,
    price: 9.99, iranPrice: 2000000,
    maxDuration: 600, maxRate: 256, maxConcurrent: 2, cooldown: 10,
    features: ['30 days access','600s max duration','10s cooldown','2 concurrent sessions']
  },
  priv: {
    id: 'priv', name: 'Priv Plan', tagline: '30 Days', days: 30,
    price: 29.99, iranPrice: 50000000,
    maxDuration: 1800, maxRate: 512, maxConcurrent: 3, cooldown: 10,
    features: ['30 days access','1800s max duration','10s cooldown','3 concurrent sessions']
  }
};

const DONITO_PAGE_URL = 'https://donito.me/privflood';
const CHECK_INTERVAL_MS = 5000;

const I18N_FA = {
  dir:'rtl', completePayment:'تکمیل پرداخت', payWithDonito:'پرداخت با دونیتو',
  followSteps:'مراحل زیر را دنبال کنید',
  step1:'روی «کپی مبلغ دقیق» در پایین بزنید ({amount} تومان).',
  step2:'VPN خود را خاموش کنید (این مرحله الزامی است).',
  step3:'روی «باز کردن دونیتو» بزنید و مبلغ کپی‌شده را در کادر کمک مالی وارد کنید.',
  step4:'کمک مالی را در دونیتو تکمیل کنید.',
  step5:'به این صفحه برگردید و روی «پرداخت کردم — بررسی کن» بزنید.',
  amountToSend:'مبلغ قابل پرداخت', copyAmount:'کپی مبلغ دقیق',
  openDonito:'باز کردن دونیتو → کمک مالی', opensNewTab:'donito.me/privflood در تب جدید باز می‌شود',
  orderStatus:'وضعیت سفارش', waiting:'در انتظار پرداخت… (سفارش {id})',
  checkNow:'↻ پرداخت کردم — بررسی کن', cancel:'لغو',
  copyDone:'مبلغ کپی شد', copyFail:'کپی ناموفق بود',
  checking:'در حال بررسی وضعیت پرداخت…', paidDelivering:'پرداخت شناسایی شد! در حال فعال‌سازی…',
  delivered:'✓ اشتراک با موفقیت فعال شد!', error:'خطا: {msg}',
  pendingBanner:'شما یک سفارش در انتظار پرداخت دارید ({plan} · {amount} تومان).',
  cancelPending:'لغو سفارش در انتظار', cancelConfirm:'سفارش در انتظار لغو شود؟', cancelled:'سفارش لغو شد'
};

module.exports = function initPayments(ctx) {
  const { DATA_DIR, readUsers, writeUsers, audit, safeUser, app, auth, admin } = ctx;

  const PAYMENTS_FILE = path.join(DATA_DIR, 'payments.json');
  const ORDERS_FILE   = path.join(DATA_DIR, 'orders.json');

  const NOTIFY_HOST   = process.env.BOT_NOTIFY_HOST   || '127.0.0.1';
  const NOTIFY_PORT   = Number(process.env.BOT_NOTIFY_PORT || 3099);
  const NOTIFY_SECRET = process.env.BOT_NOTIFY_SECRET || '';

  function notifyBot(payload) {
    if (!NOTIFY_SECRET) return;
    const body = JSON.stringify(payload || {});
    const req = http.request({
      host: NOTIFY_HOST, port: NOTIFY_PORT, path: '/internal/notify',
      method: 'POST', timeout: 4000,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        'X-Notify-Secret': NOTIFY_SECRET,
      },
    }, res => res.resume());
    req.on('timeout', () => { try { req.destroy(); } catch {} });
    req.on('error', e => console.error('[payments][notify]', e.message));
    req.end(body);
  }

  /* ---------- payment config ---------- */
  function loadCfg() { try { return JSON.parse(fs.readFileSync(PAYMENTS_FILE, 'utf8')); } catch { return null; } }
  function saveCfg(c) {
    const tmp = PAYMENTS_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(c, null, 2) + '\n', { mode: 0o600 });
    fs.renameSync(tmp, PAYMENTS_FILE);
  }
  let CFG = loadCfg() || { wallet: '', donitoToken: '', createdAt: new Date().toISOString() };
  if (typeof CFG.wallet !== 'string') CFG.wallet = '';
  if (typeof CFG.donitoToken !== 'string') CFG.donitoToken = '';
  saveCfg(CFG);

  const isWalletConfigured = () => /^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(CFG.wallet || '');
  const isDonitoConfigured = () => typeof CFG.donitoToken === 'string' && CFG.donitoToken.length >= 8;

  /* ---------- orders ---------- */
  let _orders = (() => { try { return JSON.parse(fs.readFileSync(ORDERS_FILE, 'utf8')); } catch { return []; } })();
  function saveOrders() {
    const tmp = ORDERS_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(_orders, null, 2) + '\n', { mode: 0o600 });
    fs.renameSync(tmp, ORDERS_FILE);
  }

  const lastOrderCheck = new Map();
  const lastUserCheck  = new Map();
  function checkThrottle(username, orderId) {
    const now = Date.now();
    const since = Math.max(lastUserCheck.get(username) || 0, lastOrderCheck.get(orderId) || 0);
    if (now - since < CHECK_INTERVAL_MS) return CHECK_INTERVAL_MS - (now - since);
    lastUserCheck.set(username, now);
    lastOrderCheck.set(orderId, now);
    return 0;
  }

  function uniqueUsdtAmount(basePrice) {
    const baseCents = Math.round(basePrice * 100);
    const nonce = crypto.randomInt(1, 9999);
    return ((baseCents + nonce / 10000) / 100).toFixed(4);
  }
  function uniqueIranAmount(basePrice) {
    const base = Math.round(basePrice);
    const used = new Set(_orders.filter(o => o.provider === 'iran' && o.status === 'pending' && o.payAmount).map(o => Number(o.payAmount)));
    for (let i = 1; i <= 500; i++) if (!used.has(base + i)) return String(base + i);
    return String(base + crypto.randomInt(1000, 9000));
  }
  function makeOrderId() {
    return 'ORD' + Date.now().toString(36).toUpperCase() + crypto.randomBytes(3).toString('hex').toUpperCase();
  }

  function httpGetJson(url, timeoutMs) {
    return new Promise((resolve, reject) => {
      let req;
      try {
        const u = new URL(url);
        req = https.get({
          host: u.hostname, port: 443, path: u.pathname + u.search, timeout: timeoutMs,
          headers: { 'User-Agent': 'KoldveinPayments/2', 'Accept': 'application/json' },
        }, r => {
          let buf = '';
          r.on('data', c => buf += c);
          r.on('end', () => { try { resolve(JSON.parse(buf)); } catch (e) { reject(new Error('bad JSON: ' + buf.slice(0, 200))); } });
        });
      } catch (e) { return reject(e); }
      req.on('timeout', () => { try { req.destroy(); } catch {} reject(new Error('timeout ' + url)); });
      req.on('error', reject);
    });
  }

  const USDT_CONTRACT = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t';

  async function fetchIncomingUsdt(wallet) {
    const url = 'https://apilist.tronscanapi.com/api/token_trc20/transfers?limit=50&start=0&sort=-timestamp&count=true&relatedAddress=' + encodeURIComponent(wallet);
    const data = await httpGetJson(url, 15000);
    const list = (data && (data.token_transfers || data.data)) || [];
    return list.filter(t => {
      const to = t.to_address || t.to || '';
      const contract = (t.tokenInfo && (t.tokenInfo.tokenId || t.tokenInfo.address)) || t.contract_address || '';
      return String(contract).toLowerCase() === USDT_CONTRACT.toLowerCase() &&
             String(to).toLowerCase() === String(wallet).toLowerCase();
    }).map(t => {
      const dec = Number((t.tokenInfo && t.tokenInfo.decimals) || 6);
      const raw = t.quant || t.amount || '0';
      return { txHash: t.transaction_id || t.hash, amount: Number(raw) / Math.pow(10, dec), timestamp: Number(t.block_ts || 0) };
    });
  }

  async function fetchDonito() {
    if (!isDonitoConfigured()) return [];
    const url = 'https://donito.me/api/v1/thirdparty/' + encodeURIComponent(CFG.donitoToken) + '/donations/recent';
    const data = await httpGetJson(url, 15000);
    if (!data || !Array.isArray(data.data)) return [];
    return data.data.map(d => ({
      id: String(d.id || ''), amount: Number(d.amount || 0),
      currency: d.currency_type || 'IRT', createdAt: d.created_at ? Date.parse(d.created_at) : 0,
    }));
  }

  /* ---------- delivery ---------- */
  function applyPlanToUser(username, plan, meta) {
    const users = readUsers();
    const i = users.findIndex(u => u.username.toLowerCase() === String(username).toLowerCase());
    if (i < 0) return { ok: false, error: 'user_not_found' };
    const u = users[i];
    if (u.role === 'admin') return { ok: false, error: 'admin_not_purchasable' };

    const now = Date.now();
    const curExp = u.expiresAt ? Date.parse(u.expiresAt) : 0;
    const base = Math.max(now, Number.isFinite(curExp) ? curExp : 0);
    u.role = 'user';
    u.expiresAt    = new Date(base + plan.days * 86400000).toISOString();
    u.maxDuration  = plan.maxDuration || 0;
    u.maxRate      = plan.maxRate || 0;
    u.maxConcurrent= plan.maxConcurrent || 0;
    u.cooldown     = plan.cooldown !== undefined ? plan.cooldown : u.cooldown;
    u.planId       = plan.id;
    u.planName     = plan.name;
    u.planDays     = plan.days;
    u.lastPurchase = {
      planId: plan.id, planName: plan.name, price: plan.price, iranPrice: plan.iranPrice,
      at: new Date().toISOString(), extendsFrom: u.expiresAt,
      orderId: meta.orderId, provider: meta.provider, payAmount: meta.payAmount,
      network: meta.network, txHash: meta.txHash,
    };
    writeUsers(users);
    audit('plan_delivered', 'payments', { username, planId: plan.id });

    notifyBot({
      kind: 'delivered',
      order: { id: meta.orderId, planId: plan.id, planName: plan.name, provider: meta.provider,
               payAmount: meta.payAmount, network: meta.network, txHash: meta.txHash,
               paidAt: u.lastPurchase.at, deliveredAt: new Date().toISOString() },
      user: { username: u.username },
      plan: { id: plan.id, name: plan.name, days: plan.days },
    });
    return { ok: true, user: safeUser(u) };
  }

  function findPending(username) {
    return _orders.find(o =>
      o.username.toLowerCase() === String(username).toLowerCase() &&
      o.status === 'pending' && (Date.now() - o.createdAt) < 3600000) || null;
  }

  function viewOrder(o) {
    if (!o) return null;
    const isIran = o.provider === 'iran';
    const v = {
      id: o.id, planId: o.planId, planName: o.planName, provider: o.provider,
      payAmount: o.payAmount, priceUsd: o.priceUsd, priceIran: o.priceIran,
      currency: o.currency, network: o.network, wallet: o.wallet, donitoUrl: o.donitoUrl,
      status: o.status, createdAt: o.createdAt, paidAt: o.paidAt,
      deliveredAt: o.deliveredAt, txHash: o.txHash, error: o.error || null,
    };
    if (isIran) {
      v.i18n = { lang: 'fa', dir: 'rtl', completePayment: I18N_FA.completePayment,
        payWithDonito: I18N_FA.payWithDonito + ' — ' + o.planName,
        followSteps: I18N_FA.followSteps,
        steps: [
          I18N_FA.step1.replace('{amount}', Number(o.payAmount).toLocaleString()),
          I18N_FA.step2, I18N_FA.step3, I18N_FA.step4, I18N_FA.step5,
        ],
        amountToSend: I18N_FA.amountToSend, copyAmount: I18N_FA.copyAmount,
        openDonito: I18N_FA.openDonito, opensNewTab: I18N_FA.opensNewTab,
        orderStatus: I18N_FA.orderStatus, checkNow: I18N_FA.checkNow, cancel: I18N_FA.cancel,
      };
    }
    return v;
  }

  function createOrder(username, planId, provider) {
    const plan = PLANS[planId];
    if (!plan) throw new Error('Unknown plan');
    if (provider !== 'usdt' && provider !== 'iran') throw new Error('Invalid provider');
    if (provider === 'usdt' && !isWalletConfigured()) throw new Error('Global payments not configured');
    if (provider === 'iran' && !isDonitoConfigured()) throw new Error('Iran payments not configured');
    const pending = findPending(username);
    if (pending) {
      const e = new Error('You already have a pending order.');
      e.code = 'PENDING_EXISTS'; e.pendingOrder = viewOrder(pending);
      throw e;
    }
    const order = {
      id: makeOrderId(), username, planId: plan.id, planName: plan.name, provider,
      priceUsd: provider === 'usdt' ? plan.price : null,
      priceIran: provider === 'iran' ? plan.iranPrice : null,
      payAmount: provider === 'usdt' ? uniqueUsdtAmount(plan.price) : uniqueIranAmount(plan.iranPrice),
      currency: provider === 'usdt' ? 'USDT' : 'IRT',
      network:  provider === 'usdt' ? 'TRC20' : 'DONITO',
      wallet:   provider === 'usdt' ? CFG.wallet : null,
      donitoUrl: provider === 'iran' ? DONITO_PAGE_URL : null,
      status: 'pending', createdAt: Date.now(), paidAt: null, txHash: null, deliveredAt: null,
    };
    _orders.push(order);
    if (_orders.length > 500) _orders = _orders.slice(-500);
    saveOrders();
    audit('order_created', username, { orderId: order.id, planId: plan.id, provider });
    return order;
  }

  function markPaid(order, ref) {
    order.status = 'paid';
    order.paidAt = Date.now();
    order.txHash = ref;
    saveOrders();

    notifyBot({
      kind: 'paid',
      order: { id: order.id, planId: order.planId, planName: order.planName,
               provider: order.provider, payAmount: order.payAmount,
               network: order.network, txHash: order.txHash,
               paidAt: new Date(order.paidAt).toISOString() },
      user: { username: order.username },
      plan: PLANS[order.planId] || { id: order.planId, name: order.planName },
    });

    const plan = PLANS[order.planId];
    if (!plan) { order.status = 'error'; order.error = 'plan_missing'; saveOrders(); return; }
    const r = applyPlanToUser(order.username, plan, {
      orderId: order.id, provider: order.provider,
      payAmount: order.payAmount, network: order.network, txHash: order.txHash,
    });
    if (r.ok) { order.status = 'delivered'; order.deliveredAt = Date.now(); saveOrders(); }
    else       { order.status = 'error'; order.error = r.error; saveOrders(); }
  }

  let polling = false;
  async function pollOnce() {
    if (polling) return;
    const pending = _orders.filter(o => o.status === 'pending');
    if (!pending.length) return;
    polling = true;
    try {
      const usdtPending = pending.filter(o => o.provider === 'usdt');
      if (usdtPending.length && isWalletConfigured()) {
        try {
          const transfers = await fetchIncomingUsdt(CFG.wallet);
          const usedTx = new Set(_orders.filter(o => o.txHash).map(o => String(o.txHash).toLowerCase()));
          for (const order of usdtPending) {
            const target = Number(order.payAmount);
            for (const t of transfers) {
              if (usedTx.has(String(t.txHash).toLowerCase())) continue;
              if (Math.abs(t.amount - target) < 0.00005) {
                if (t.timestamp && t.timestamp < order.createdAt - 300000) continue;
                usedTx.add(String(t.txHash).toLowerCase());
                markPaid(order, t.txHash);
                break;
              }
            }
          }
        } catch (e) { console.warn('[payments] usdt poll:', e.message); }
      }
      const iranPending = pending.filter(o => o.provider === 'iran');
      if (iranPending.length && isDonitoConfigured()) {
        try {
          const donations = await fetchDonito();
          const usedIds = new Set(_orders.filter(o => o.provider === 'iran' && o.txHash).map(o => String(o.txHash)));
          for (const order of iranPending) {
            const target = Number(order.payAmount);
            for (const d of donations) {
              if (!d.id || usedIds.has(d.id)) continue;
              if (d.currency !== 'IRT' || d.amount !== target) continue;
              if (d.createdAt && d.createdAt < order.createdAt - 300000) continue;
              usedIds.add(d.id);
              markPaid(order, d.id);
              break;
            }
          }
        } catch (e) { console.warn('[payments] donito poll:', e.message); }
      }
    } finally { polling = false; }
  }

  let pollInterval = null;
  function startPoller() {
    if (pollInterval) return;
    if (!isWalletConfigured() && !isDonitoConfigured()) {
      console.log('[payments] no provider — poller idle');
      return;
    }
    setTimeout(() => pollOnce().catch(() => {}), 8000);
    pollInterval = setInterval(() => pollOnce().catch(() => {}), 60000);
    pollInterval.unref();
    console.log('[payments] poller running (usdt=' + isWalletConfigured() + ', donito=' + isDonitoConfigured() + ')');
  }

  /* ---------- routes ---------- */
  app.get('/api/plans', (_req, res) => {
    res.json({
      plans: Object.values(PLANS),
      providers: { usdt: isWalletConfigured(), iran: isDonitoConfigured() },
      donitoUrl: DONITO_PAGE_URL, network: 'TRC20', currency: 'USDT',
      checkIntervalMs: CHECK_INTERVAL_MS,
    });
  });

  app.get('/api/orders/pending', auth, (req, res) => {
    res.json({ pendingOrder: viewOrder(findPending(req.session.user.username)) });
  });

  app.post('/api/orders', auth, (req, res) => {
    if (req.session.user.role === 'admin') return res.status(400).json({ error: 'Admins already have access.' });
    const body = req.body || {};
    const planId = String(body.planId || '');
    const provider = String(body.provider || 'usdt').toLowerCase();
    if (provider !== 'usdt' && provider !== 'iran') return res.status(400).json({ error: 'Invalid provider' });
    if (!PLANS[planId]) return res.status(400).json({ error: 'Unknown plan' });
    if (provider === 'usdt' && !isWalletConfigured()) return res.status(503).json({ error: 'Global not configured' });
    if (provider === 'iran' && !isDonitoConfigured()) return res.status(503).json({ error: 'Iran not configured' });
    try {
      const o = createOrder(req.session.user.username, planId, provider);
      res.json({ order: viewOrder(o) });
    } catch (e) {
      if (e.code === 'PENDING_EXISTS') return res.status(409).json({ error: e.message, code: 'PENDING_EXISTS', pendingOrder: e.pendingOrder });
      res.status(400).json({ error: e.message });
    }
  });

  app.get('/api/orders', auth, (req, res) => {
    res.json({
      orders: _orders.filter(o => o.username === req.session.user.username)
        .sort((a, b) => b.createdAt - a.createdAt).slice(0, 20)
        .map(o => ({ id: o.id, planId: o.planId, planName: o.planName, provider: o.provider,
                     payAmount: o.payAmount, priceUsd: o.priceUsd, priceIran: o.priceIran,
                     status: o.status, createdAt: o.createdAt, paidAt: o.paidAt,
                     deliveredAt: o.deliveredAt, txHash: o.txHash })),
    });
  });

  app.get('/api/orders/:id', auth, (req, res) => {
    const o = _orders.find(x => x.id === req.params.id);
    if (!o) return res.status(404).json({ error: 'not found' });
    if (o.username !== req.session.user.username && req.session.user.role !== 'admin') return res.status(403).json({ error: 'forbidden' });
    res.json({ order: viewOrder(o) });
  });

  app.post('/api/orders/:id/cancel', auth, (req, res) => {
    const o = _orders.find(x => x.id === req.params.id);
    if (!o) return res.status(404).json({ error: 'not found' });
    if (o.username !== req.session.user.username && req.session.user.role !== 'admin') return res.status(403).json({ error: 'forbidden' });
    if (o.status !== 'pending') return res.status(400).json({ error: 'Only pending can be cancelled' });
    o.status = 'cancelled'; o.cancelledAt = Date.now(); saveOrders();
    res.json({ ok: true });
  });

  app.post('/api/orders/:id/check', auth, async (req, res) => {
    const o = _orders.find(x => x.id === req.params.id);
    if (!o) return res.status(404).json({ error: 'not found' });
    if (o.username !== req.session.user.username && req.session.user.role !== 'admin') return res.status(403).json({ error: 'forbidden' });
    if (o.status !== 'pending') return res.json({ order: { id: o.id, status: o.status, deliveredAt: o.deliveredAt, txHash: o.txHash } });
    const wait = checkThrottle(req.session.user.username, o.id);
    if (wait > 0) return res.status(429).json({ error: 'Please wait', retryAfterMs: wait });
    await pollOnce().catch(() => {});
    const fresh = _orders.find(x => x.id === o.id);
    res.json({ order: { id: fresh.id, status: fresh.status, deliveredAt: fresh.deliveredAt, txHash: fresh.txHash, error: fresh.error || null } });
  });

  /* ---------- public API ---------- */
  return {
    PLANS, isWalletConfigured, isDonitoConfigured, CHECK_INTERVAL_MS,
    setWallet(w) {
      if (!/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(w)) throw new Error('Invalid TRC20 address');
      CFG.wallet = w; CFG.updatedAt = new Date().toISOString(); saveCfg(CFG);
      if (!pollInterval) startPoller();
    },
    setDonitoToken(t) {
      if (typeof t !== 'string' || t.length < 8) throw new Error('Invalid token');
      CFG.donitoToken = t; CFG.updatedAt = new Date().toISOString(); saveCfg(CFG);
      if (!pollInterval) startPoller();
    },
    startPoller, pollOnce,
    getPlans: () => Object.values(PLANS),
  };
};
