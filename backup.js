#!/usr/bin/env node
'use strict';

/*
 * backup.js — rolling snapshot backups every 2 minutes.
 * Each tick creates a fresh folder `backups/YYYY-MM-DDTHH-MM-SS/` with copies of every data file.
 * Keeps last 30 snapshots (about 1 hour of history) then prunes the oldest.
 */

const fs   = require('node:fs');
const path = require('node:path');

module.exports = function initBackup(ctx) {
  const { DATA_DIR } = ctx;
  const BACKUP_DIR = path.join(DATA_DIR, 'backups');
  const KEEP     = 30;
  const INTERVAL = 2 * 60 * 1000;

  fs.mkdirSync(BACKUP_DIR, { recursive: true, mode: 0o700 });

  const FILES = [
    'users.json', 'slaves.json', 'orders.json', 'payments.json',
    'blacklist.json', 'global.json', 'sessions.json', 'audit.log',
  ];

  let timer = null;

  function tick() {
    try {
      const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
      const dir   = path.join(BACKUP_DIR, stamp);
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      for (const file of FILES) {
        const src = path.join(DATA_DIR, file);
        if (!fs.existsSync(src)) continue;
        try { fs.copyFileSync(src, path.join(dir, file)); } catch (e) {}
      }
      const dirs = fs.readdirSync(BACKUP_DIR)
        .filter(d => /^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}$/.test(d))
        .sort();
      while (dirs.length > KEEP) {
        const old = dirs.shift();
        try { fs.rmSync(path.join(BACKUP_DIR, old), { recursive: true, force: true }); } catch {}
      }
    } catch (e) {
      console.error('[backup] tick failed:', e.message);
    }
  }

  function start() {
    if (timer) return;
    tick();
    timer = setInterval(tick, INTERVAL);
    timer.unref();
    console.log('[backup] started (interval=' + INTERVAL/1000 + 's, keep=' + KEEP + ')');
  }

  function stop() {
    if (timer) { clearInterval(timer); timer = null; }
  }

  return { start, stop, tick, BACKUP_DIR };
};
