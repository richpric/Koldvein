#!/usr/bin/env node
'use strict';

const fs       = require('node:fs');
const path     = require('node:path');
const net      = require('node:net');
const crypto   = require('node:crypto');
const { Client } = require('ssh2');

const VERSION          = '2.6.0';
const THREADS_PER_CORE = 8;
const SCRIPT_NAME      = 'K0ldvein.js';
const C_RUSH_SCRIPT    = 'c-rush.js';
const PROXY_NAME       = 'ppp.txt';
const BOOT_TIMEOUT     = 20 * 60 * 1000;
const CONNECT_RETRIES  = 3;
const RETRY_DELAYS     = [3000, 8000, 15000];
const MIN_FREE_MB      = 200;
const CLEANUP_BELOW_MB = 250;
const HEALTH_STRIKES   = 5;
const HEALTH_SOFT      = 3;
const MAX_SAFE_CORES   = 256;
const MAX_SAFE_THREADS = MAX_SAFE_CORES * THREADS_PER_CORE;

module.exports = function initSlaves(ctx) {
  console.log('[slaves] v' + VERSION + ' loaded');
  const { DATA_DIR, SCRIPT_DIR, audit, notifyBot } = ctx;
  const HUB_DIR        = SCRIPT_DIR || __dirname;
  const LOCAL_SCRIPT   = path.join(HUB_DIR, SCRIPT_NAME);
  const LOCAL_C_RUSH   = path.join(HUB_DIR, C_RUSH_SCRIPT);
  const LOCAL_PROXY    = path.join(HUB_DIR, PROXY_NAME);
  const HAS_C_RUSH     = fs.existsSync(LOCAL_C_RUSH);
  const SLAVES_FILE    = path.join(DATA_DIR, 'slaves.json');
  const LOG_DIR        = path.join(DATA_DIR, 'slave-logs');

  fs.mkdirSync(LOG_DIR, { recursive: true, mode: 0o700 });

  console.log('[slaves] hub files: K0ldvein=' + fs.existsSync(LOCAL_SCRIPT) + ' c-rush=' + HAS_C_RUSH + ' proxy=' + fs.existsSync(LOCAL_PROXY));

  let slaves = [];
  try { slaves = JSON.parse(fs.readFileSync(SLAVES_FILE, 'utf8')); } catch { slaves = []; }

  let dirty = false;
  for (const s of slaves) {
    if (s.passphrase === undefined) { s.passphrase = null; dirty = true; }
    if (s._healthFails === undefined) { s._healthFails = 0; dirty = true; }
    if (s.bootstrapStage === undefined) { s.bootstrapStage = null; dirty = true; }
    if (s.status === 'bootstrapping') {
      const age = Date.now() - (s.bootstrapStartedAt || 0);
      if (!s.bootstrapStartedAt || age > BOOT_TIMEOUT) {
        s.status = 'failed';
        s.lastError = !s.bootstrapStartedAt ? 'Bootstrap interrupted (hub restart)' : 'Bootstrap timeout';
        s.bootstrapStage = null;
        delete s.bootstrapStartedAt;
        dirty = true;
      }
    }
    if (s.status === 'ready' && (!Number.isInteger(s.cores) || s.cores < 1 || s.cores > MAX_SAFE_CORES)) {
      s.status = 'failed';
      s.lastError = 'Invalid core count stored (' + s.cores + '). Click Repair.';
      s.cores = 0;
      dirty = true;
    }
  }
  if (dirty) save();

  function save() {
    const tmp = SLAVES_FILE + '.' + process.pid + '.' + Date.now() + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(slaves, null, 2) + '\n', { mode: 0o600 });
    fs.renameSync(tmp, SLAVES_FILE);
  }

  if (!fs.existsSync(LOCAL_SCRIPT) || !fs.existsSync(LOCAL_PROXY)) {
    console.error('[slaves] MISSING ' + SCRIPT_NAME + ' or ' + PROXY_NAME + ' in ' + HUB_DIR);
  }
  if (!HAS_C_RUSH) {
    console.warn('[slaves] ' + C_RUSH_SCRIPT + ' not found in ' + HUB_DIR + ' — C-Flood method unavailable');
  }

  function logFile(id) { return path.join(LOG_DIR, id + '.log'); }
  function logReset(slave) { try { fs.writeFileSync(logFile(slave.id), ''); } catch {} }
  function logAppend(slave, msg) {
    const line = '[' + new Date().toISOString() + '] ' + msg + '\n';
    try { fs.appendFileSync(logFile(slave.id), line); } catch {}
    console.log('[slaves] ' + slave.name + ' ' + msg);
  }
  function logRead(id, lines) {
    try {
      const raw = fs.readFileSync(logFile(id), 'utf8');
      if (!lines) return raw;
      return raw.split('\n').slice(-lines).join('\n');
    } catch { return ''; }
  }

  function validateKey(raw, passphrase) {
    let k = String(raw || '').trim();
    if (!k) throw new Error('Private key is empty');
    if (k.startsWith('PuTTY-User-Key-File-')) throw new Error('PuTTY .ppk detected — convert to OpenSSH');
    if (/^(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-|ssh-dsa)\s/.test(k)) throw new Error('This is a PUBLIC key — paste the PRIVATE key');
    k = k.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    const hasOpenSSH  = k.includes('-----BEGIN OPENSSH PRIVATE KEY-----');
    const hasRSA      = k.includes('-----BEGIN RSA PRIVATE KEY-----');
    const hasEC       = k.includes('-----BEGIN EC PRIVATE KEY-----');
    const hasPKCS8    = k.includes('-----BEGIN PRIVATE KEY-----');
    const hasEnc      = k.includes('-----BEGIN ENCRYPTED PRIVATE KEY-----');
    const hasDSA      = k.includes('-----BEGIN DSA PRIVATE KEY-----');
    if (!(hasOpenSSH || hasRSA || hasEC || hasPKCS8 || hasEnc || hasDSA)) {
      throw new Error('Key format not recognized. Starts with: "' + k.slice(0, 40) + '"');
    }
    if (hasEnc && !passphrase) throw new Error('Encrypted key — provide passphrase');
    k = k.split('\n').map(l => l.replace(/[ \t]+$/, '')).join('\n');
    if (!k.endsWith('\n')) k += '\n';
    return k;
  }

  function connectOnce(slave, timeoutMs) {
    return new Promise((resolve, reject) => {
      const c = new Client();
      const cfg = {
        host: slave.ip,
        port: Number(slave.port) || 22,
        username: slave.username,
        readyTimeout: timeoutMs || 60000,
        keepaliveInterval: 10000,
        keepaliveCountMax: 6,
      };
      if (slave.authType === 'key' && slave.privateKey) {
        try { cfg.privateKey = validateKey(slave.privateKey, slave.passphrase); }
        catch (e) { return reject(new Error('Key: ' + e.message)); }
        if (slave.passphrase) cfg.passphrase = String(slave.passphrase);
        cfg.tryKeyboard = false;
      } else if (slave.password) {
        cfg.password = String(slave.password);
        cfg.tryKeyboard = true;
      } else {
        return reject(new Error('No credentials configured'));
      }
      c.once('ready', () => resolve(c));
      c.once('error', err => reject(new Error(err.message || String(err))));
      try { c.connect(cfg); } catch (e) { reject(new Error('connect: ' + e.message)); }
    });
  }

  async function connectRetry(slave, timeoutMs) {
    let lastErr;
    for (let i = 0; i < CONNECT_RETRIES; i++) {
      try {
        return await connectOnce(slave, timeoutMs);
      } catch (e) {
        lastErr = e;
        const portAlive = await new Promise(res => {
          const sock = net.connect(Number(slave.port) || 22, slave.ip, () => { sock.end(); res(true); });
          sock.setTimeout(3000);
          sock.on('error', () => res(false));
          sock.on('timeout', () => { sock.destroy(); res(false); });
        });
        if (!portAlive) throw new Error('Port ' + (slave.port || 22) + ' on ' + slave.ip + ' unreachable: ' + e.message);
        if (i < CONNECT_RETRIES - 1) {
          const d = RETRY_DELAYS[i] || 15000;
          logAppend(slave, 'connect retry ' + (i + 1) + '/' + CONNECT_RETRIES + ' in ' + (d / 1000) + 's: ' + e.message);
          await new Promise(r => setTimeout(r, d));
        }
      }
    }
    throw lastErr;
  }

  function exec(conn, cmd, timeoutMs) {
    timeoutMs = timeoutMs || 60000;
    return new Promise((resolve, reject) => {
      let out = '', err = '';
      const tm = setTimeout(() => {
        try { conn.end(); } catch {}
        reject(new Error('Command timed out after ' + Math.round(timeoutMs / 1000) + 's. Last output: ' + (out.slice(-300) || '(none)')));
      }, timeoutMs);
      conn.exec(cmd, (e, stream) => {
        if (e) { clearTimeout(tm); return reject(e); }
        stream.on('data', d => { out += d.toString(); });
        stream.stderr.on('data', d => { err += d.toString(); });
        stream.on('close', code => { clearTimeout(tm); resolve({ code, stdout: out, stderr: err }); });
        stream.on('error', err2 => { clearTimeout(tm); reject(err2); });
      });
    });
  }

  function sftpUpload(conn, files) {
    return new Promise((resolve, reject) => {
      conn.sftp((err, sftp) => {
        if (err) return reject(new Error('SFTP init: ' + err.message));
        const q = files.slice();
        const next = () => {
          if (!q.length) { try { sftp.end(); } catch {} return resolve(); }
          const f = q.shift();
          const size = fs.statSync(f.local).size;
          sftp.fastPut(f.local, f.remote, e => {
            if (e) { try { sftp.end(); } catch {} return reject(new Error('Upload ' + path.basename(f.local) + ': ' + e.message)); }
            sftp.stat(f.remote, (e2, st) => {
              if (e2) { try { sftp.end(); } catch {} return reject(new Error('Stat ' + f.remote + ': ' + e2.message)); }
              if (st.size !== size) { try { sftp.end(); } catch {} return reject(new Error('Size mismatch: ' + st.size + ' vs ' + size)); }
              next();
            });
          });
        };
        next();
      });
    });
  }

  async function stagePreflight(slave, conn) {
    logAppend(slave, 'preflight: probing shell + resources');

    const cmd =
      'echo "__PF_UID=$(id -u)"; ' +
      'echo "__PF_ARCH=$(uname -m)"; ' +
      'echo "__PF_CORES=$(nproc)"; ' +
      'echo "__PF_RAM=$(free -m | awk \'NR==2{print $2}\')"; ' +
      'echo "__PF_DISK=$(df -Pm / | awk \'NR==2{print $4}\')"; ' +
      'echo "__PF_DISKTOT=$(df -Pm / | awk \'NR==2{print $2}\')"; ' +
      'echo "__PF_END"';

    const r = await exec(conn, cmd, 25000);
    if (!r.stdout.includes('__PF_END')) {
      throw new Error('Shell not responding. stdout=' + JSON.stringify(r.stdout.slice(0, 300)) + ' stderr=' + JSON.stringify(r.stderr.slice(0, 200)));
    }

    const pick = (tag) => {
      const re = new RegExp('__PF_' + tag + '=([^\\n]*)');
      const m = r.stdout.match(re);
      return m ? m[1].trim() : '';
    };

    const rawUid       = pick('UID');
    const rawArch      = pick('ARCH');
    const rawCores     = pick('CORES');
    const rawRam       = pick('RAM');
    const rawDisk      = pick('DISK');
    const rawDiskTot   = pick('DISKTOT');

    logAppend(slave, 'preflight raw: uid="' + rawUid + '" arch="' + rawArch + '" cores="' + rawCores + '" ram="' + rawRam + '" disk="' + rawDisk + '/' + rawDiskTot + '"');

    const uid       = parseInt(rawUid, 10);
    const coresRaw  = parseInt(rawCores, 10);
    const ramMb     = parseInt(rawRam, 10) || 512;
    const diskFree  = parseInt(rawDisk, 10) || 0;
    const diskTotal = parseInt(rawDiskTot, 10) || 0;
    const arch      = rawArch;

    if (!Number.isFinite(uid) || uid < 0) {
      throw new Error('Cannot determine uid (raw: "' + rawUid + '")');
    }
    if (!arch || !/^(x86_64|amd64|aarch64|arm64|armv7l|i686)$/.test(arch)) {
      throw new Error('Unsupported architecture: "' + arch + '" (raw preflight output: ' + JSON.stringify(r.stdout.slice(0, 400)) + ')');
    }
    if (!Number.isInteger(coresRaw) || coresRaw < 1) {
      throw new Error('Cannot determine CPU cores (raw: "' + rawCores + '")');
    }
    if (coresRaw > MAX_SAFE_CORES) {
      throw new Error('CPU core count suspiciously high (' + coresRaw + '), refusing');
    }

    const cores = coresRaw;
    slave.cores = cores;

    logAppend(slave, 'preflight: uid=' + uid + ' arch=' + arch + ' cores=' + cores + ' ram=' + ramMb + 'MB disk=' + diskFree + '/' + diskTotal + 'MB');

    if (diskFree < CLEANUP_BELOW_MB) {
      logAppend(slave, 'preflight: low disk (' + diskFree + 'MB) — cleaning');
      await exec(conn,
        'apt-get clean >/dev/null 2>&1 || true; ' +
        'rm -rf /var/cache/apt/archives/*.deb /var/cache/apt/archives/partial/* >/dev/null 2>&1 || true; ' +
        'journalctl --vacuum-size=50M >/dev/null 2>&1 || true; ' +
        'rm -rf /var/tmp/* >/dev/null 2>&1 || true; ' +
        'find /tmp -maxdepth 1 -type f -mtime +1 -delete >/dev/null 2>&1 || true', 60000);
      const r2 = await exec(conn, 'df -Pm / | awk \'NR==2{print $4}\'', 15000);
      const newFree = parseInt((r2.stdout || '').trim(), 10) || 0;
      logAppend(slave, 'preflight: freed ' + Math.max(0, newFree - diskFree) + 'MB, now ' + newFree + 'MB');
      if (newFree < MIN_FREE_MB) {
        let top = '';
        try { const t = await exec(conn, 'du -xh --max-depth=2 / 2>/dev/null | sort -h | tail -8', 30000); top = (t.stdout || '').trim(); } catch {}
        throw new Error('SLAVE disk low on ' + slave.ip + ' (' + newFree + 'MB free, need ' + MIN_FREE_MB + 'MB)' + (top ? '. Top: ' + top.slice(0, 400) : ''));
      }
    }

    return { uid, arch, cores, ramMb };
  }

  async function stageNode(slave, conn) {
    logAppend(slave, 'node: checking existing install');
    const cur = await exec(conn, 'node --version 2>/dev/null || true; echo __END__', 15000);
    const m = cur.stdout.match(/v(\d+)\.(\d+)\.(\d+)/);
    if (m && parseInt(m[1], 10) >= 20) { logAppend(slave, 'node: ' + m[0] + ' present'); return m[0]; }

    logAppend(slave, 'node: installing prerequisites');
    const pre = await exec(conn,
      'set -e; export DEBIAN_FRONTEND=noninteractive; ' +
      'apt-get update -qq; ' +
      'apt-get install -y -qq -o DPkg::Lock::Timeout=300 ' +
        '-o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-confdef ' +
        'curl ca-certificates gnupg lsb-release; ' +
      'echo __PREREQ_OK__', 300000);
    if (!pre.stdout.includes('__PREREQ_OK__')) throw new Error('apt prerequisites: ' + (pre.stderr || pre.stdout).slice(-400));

    logAppend(slave, 'node: adding NodeSource repo');
    const repo = await exec(conn,
      'set -e; mkdir -p /usr/share/keyrings; ' +
      'curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /usr/share/keyrings/nodesource.gpg; ' +
      'echo "deb [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" > /etc/apt/sources.list.d/nodesource.list; ' +
      'echo __REPO_OK__', 90000);
    if (!repo.stdout.includes('__REPO_OK__')) throw new Error('NodeSource repo: ' + (repo.stderr || repo.stdout).slice(-400));

    logAppend(slave, 'node: installing nodejs (2-4 min)');
    const inst = await exec(conn,
      'set -e; export DEBIAN_FRONTEND=noninteractive; ' +
      'apt-get update -qq; ' +
      'apt-get install -y -qq -o DPkg::Lock::Timeout=300 nodejs; ' +
      'node --version; echo __INSTALL_OK__', 420000);
    if (!inst.stdout.includes('__INSTALL_OK__')) throw new Error('nodejs install: ' + (inst.stderr || inst.stdout).slice(-400));
    const ver = inst.stdout.match(/v(\d+)\.(\d+)\.(\d+)/);
    if (!ver || parseInt(ver[1], 10) < 20) throw new Error('Expected Node 20+, got v' + (ver ? ver[1] : '?'));
    const finalV = 'v' + ver[1] + '.' + ver[2] + '.' + ver[3];
    logAppend(slave, 'node: ' + finalV);
    return finalV;
  }

  async function stageUpload(slave, conn, uid) {
    logAppend(slave, 'upload: preparing directory');
    const home = uid === 0 ? '/root' : ((await exec(conn, 'echo $HOME', 10000)).stdout.trim() || '/tmp');
    const remoteDir = home + '/koldvein';
    const mk = await exec(conn, 'rm -rf ' + remoteDir + ' && mkdir -p ' + remoteDir + ' && cd ' + remoteDir + ' && test -w . && echo __WRITABLE__', 20000);
    if (!mk.stdout.includes('__WRITABLE__')) throw new Error('Cannot create ' + remoteDir + ': ' + (mk.stderr || mk.stdout).slice(-200));

    const files = [
      { local: LOCAL_SCRIPT, remote: remoteDir + '/' + SCRIPT_NAME },
      { local: LOCAL_PROXY,  remote: remoteDir + '/' + PROXY_NAME  },
    ];
    if (HAS_C_RUSH) {
      files.push({ local: LOCAL_C_RUSH, remote: remoteDir + '/' + C_RUSH_SCRIPT });
    }

    logAppend(slave, 'upload: ' + files.length + ' file(s) via SFTP');
    await sftpUpload(conn, files);
    logAppend(slave, 'upload: done');
    return remoteDir;
  }

  async function stageVerify(slave, conn, remoteDir) {
    logAppend(slave, 'verify: files + syntax');
    const filesList = [SCRIPT_NAME, PROXY_NAME].concat(HAS_C_RUSH ? [C_RUSH_SCRIPT] : []);
    const missingCheck = filesList.map(f => 'test -s ' + f).join(' && ') + ' || { echo __MISSING__; exit 1; }';
    const syntaxChecks = ['node --check ' + SCRIPT_NAME].concat(HAS_C_RUSH ? ['node --check ' + C_RUSH_SCRIPT] : []).join(' && ');
    const r = await exec(conn,
      'cd ' + remoteDir + ' && (' + missingCheck + '); (' + syntaxChecks + ') 2>&1; RC=$?; echo "RC:$RC"; exit $RC', 30000);
    if (r.stdout.includes('__MISSING__')) throw new Error('Files missing after upload');
    if (!/RC:0/.test(r.stdout)) throw new Error('syntax check: ' + (r.stderr || r.stdout).slice(-300));
    logAppend(slave, 'verify: OK (' + filesList.length + ' files)');
  }

  async function stageDeps(slave, conn, remoteDir) {
    logAppend(slave, 'deps: hpack colors node-bash-title axios');
    const r = await exec(conn,
      'cd ' + remoteDir + ' && ' +
      'npm install hpack colors node-bash-title axios --no-audit --no-fund --loglevel=error 2>&1 | tail -6; ' +
      'node -e "require(\'hpack\');require(\'colors\');require(\'node-bash-title\');require(\'axios\');console.log(\'__DEPS_OK__\')" 2>&1', 400000);
    if (!r.stdout.includes('__DEPS_OK__')) throw new Error('deps install: ' + (r.stdout.slice(-500) || r.stderr.slice(-500)));
    logAppend(slave, 'deps: OK');
  }

  async function stageLimits(slave, conn) {
    await exec(conn,
      'grep -q "\\* soft nofile 65535" /etc/security/limits.conf || echo "* soft nofile 65535" | tee -a /etc/security/limits.conf >/dev/null; ' +
      'grep -q "\\* hard nofile 65535" /etc/security/limits.conf || echo "* hard nofile 65535" | tee -a /etc/security/limits.conf >/dev/null; ' +
      'echo __LIMITS_OK__', 15000);
    logAppend(slave, 'limits: OK');
  }

  async function bootstrap(slave) {
    slave.status = 'bootstrapping';
    slave.lastError = null;
    slave.bootstrapStage = 'connect';
    slave.bootstrapStartedAt = Date.now();
    slave._healthFails = 0;
    save();
    logReset(slave);
    logAppend(slave, 'bootstrap started (v' + VERSION + ')');

    if (!fs.existsSync(LOCAL_SCRIPT) || !fs.existsSync(LOCAL_PROXY)) {
      slave.status = 'failed';
      slave.lastError = 'Hub missing ' + SCRIPT_NAME + ' or ' + PROXY_NAME;
      slave.bootstrapStage = null;
      delete slave.bootstrapStartedAt;
      save();
      return;
    }

    if (slave.authType === 'key') {
      try { validateKey(slave.privateKey, slave.passphrase); }
      catch (e) {
        slave.status = 'failed';
        slave.lastError = 'Key: ' + e.message;
        slave.bootstrapStage = null;
        delete slave.bootstrapStartedAt;
        save();
        return;
      }
    }

    let conn;
    try {
      conn = await connectRetry(slave, 60000);
      logAppend(slave, 'connected');

      const info = await stagePreflight(slave, conn);
      slave.cores = info.cores;
      slave.ramMb = info.ramMb;

      slave.bootstrapStage = 'node'; save();
      await stageNode(slave, conn);

      slave.bootstrapStage = 'upload'; save();
      const remoteDir = await stageUpload(slave, conn, info.uid);

      slave.bootstrapStage = 'verify'; save();
      await stageVerify(slave, conn, remoteDir);

      slave.bootstrapStage = 'deps'; save();
      await stageDeps(slave, conn, remoteDir);

      slave.bootstrapStage = 'limits'; save();
      await stageLimits(slave, conn);

      slave.kdir = remoteDir;
      slave.status = 'ready';
      slave.lastCheck = new Date().toISOString();
      slave.lastError = null;
      slave.bootstrapStage = null;
      slave._healthFails = 0;
      delete slave.bootstrapStartedAt;
      save();
      audit('slave_ready', 'system', { id: slave.id, cores: info.cores, has_c_rush: HAS_C_RUSH });
      if (notifyBot) notifyBot({ kind: 'slave_ready', slave: { name: slave.name, ip: slave.ip, cores: info.cores } });
      logAppend(slave, 'READY (' + info.cores + 'c · ' + (info.cores * THREADS_PER_CORE) + ' threads · methods=' + (HAS_C_RUSH ? 'koldvein,c-flood' : 'koldvein') + ')');
    } catch (e) {
      slave.status = 'failed';
      slave.lastError = (slave.bootstrapStage ? '[' + slave.bootstrapStage + '] ' : '') + String(e.message || e).slice(0, 800);
      slave.bootstrapStage = null;
      delete slave.bootstrapStartedAt;
      save();
      audit('slave_failed', 'system', { id: slave.id, error: slave.lastError });
      logAppend(slave, 'FAILED: ' + slave.lastError);
    } finally {
      try { conn && conn.end(); } catch {}
    }
  }

  async function addSlave(input) {
    const slave = {
      id: crypto.randomUUID(),
      name: String(input.name || input.ip || 'slave'),
      ip: String(input.ip).trim(),
      port: Number(input.port) || 22,
      username: String(input.username || 'root').trim(),
      authType: input.authType === 'key' ? 'key' : 'password',
      password:   input.authType === 'key' ? null : String(input.password || ''),
      privateKey: input.authType === 'key' ? String(input.privateKey || '') : null,
      passphrase: input.authType === 'key' && input.passphrase ? String(input.passphrase) : null,
      cores: 0, ramMb: 0, kdir: '',
      status: 'bootstrapping',
      createdAt: new Date().toISOString(),
      lastCheck: null, lastError: null,
      bootstrapStage: 'connect',
      bootstrapStartedAt: Date.now(),
      _healthFails: 0,
    };
    if (slave.authType === 'password' && !slave.password) throw new Error('Password required');
    if (slave.authType === 'key'      && !slave.privateKey) throw new Error('Private key required');
    if (slave.authType === 'key') {
      try { validateKey(slave.privateKey, slave.passphrase); }
      catch (e) { throw new Error('Private key invalid: ' + e.message); }
    }
    slaves.push(slave); save();
    audit('slave_added', 'admin', { id: slave.id, ip: slave.ip });
    bootstrap(slave);
    return slave;
  }

  async function removeSlave(id) {
    const i = slaves.findIndex(s => s.id === id);
    if (i < 0) return false;
    slaves.splice(i, 1); save();
    try { fs.unlinkSync(logFile(id)); } catch {}
    audit('slave_removed', 'admin', { id });
    return true;
  }

  async function rebootstrapSlave(id) {
    const slave = slaves.find(s => s.id === id);
    if (!slave) throw new Error('Slave not found');
    if (slave.status === 'bootstrapping') throw new Error('Already bootstrapping');
    logAppend(slave, 're-bootstrap requested');
    bootstrap(slave);
    return slave;
  }

  function shq(s) {
    const str = String(s);
    if (/^[a-zA-Z0-9_@%+=:,.\/-]+$/.test(str)) return str;
    return "'" + str.replace(/'/g, "'\\''") + "'";
  }

  async function launchOnSlave(slaveId, opts) {
    const slave = slaves.find(s => s.id === slaveId);
    if (!slave) throw new Error('Slave not found');
    if (slave.status !== 'ready') throw new Error('Slave ' + slave.name + ' not ready (' + slave.status + ')');
    if (!slave.kdir) throw new Error('Slave directory unknown');

    if (!Number.isInteger(slave.cores) || slave.cores < 1 || slave.cores > MAX_SAFE_CORES) {
      throw new Error('Slave ' + slave.name + ' has invalid core count (' + slave.cores + '). Click Repair.');
    }

    const methodFile = String(opts.methodFile || SCRIPT_NAME);
    if (!/^[A-Za-z0-9._-]+\.js$/.test(methodFile)) {
      throw new Error('Invalid method file: ' + methodFile);
    }
    const args = Array.isArray(opts.args) ? opts.args.map(a => String(a)) : null;
    if (!args || !args.length) throw new Error('No launch args provided');

    const expectedThreads = slave.cores * THREADS_PER_CORE;

    const sid   = 'kold_' + crypto.randomBytes(6).toString('hex');
    const log   = '/tmp/' + sid + '.log';
    const pidF  = '/tmp/' + sid + '.pid';

    const quotedArgs = args.map(shq).join(' ');
    const cmd =
      'cd ' + slave.kdir + ' && { ' +
      'setsid nohup node ' + shq(methodFile) + ' ' + quotedArgs +
      ' </dev/null >' + log + ' 2>&1 & ' +
      'PID=$!; ' +
      'echo $PID > ' + pidF + '; ' +
      'sleep 1; ' +
      'if kill -0 $PID 2>/dev/null; then echo "STARTED:$PID"; else echo "DIED"; cat ' + log + ' | tail -8; fi; ' +
      '}';

    let conn;
    try {
      conn = await connectRetry(slave, 30000);
      const r = await exec(conn, cmd, 45000);
      const m = /STARTED:(\d+)/.exec(r.stdout || '');
      if (!m) throw new Error('launch failed: ' + ((r.stdout || '') + (r.stderr || '')).slice(-500).trim());
      const pid = parseInt(m[1], 10);
      logAppend(slave, 'launched ' + methodFile + ' pid=' + pid);
      return {
        slaveId, slaveName: slave.name, pid, log, sid,
        cores: slave.cores, threads: expectedThreads,
        methodFile
      };
    } finally {
      try { conn && conn.end(); } catch {}
    }
  }

  async function checkProcess(slaveId, pid) {
    const slave = slaves.find(s => s.id === slaveId);
    if (!slave) return { alive: false, reason: 'slave_removed' };
    let conn;
    try {
      conn = await connectOnce(slave, 15000);
      const r = await exec(conn,
        'kill -0 ' + Number(pid) + ' 2>/dev/null && echo ALIVE || ' +
        'kill -0 -' + Number(pid) + ' 2>/dev/null && echo ALIVE_GROUP || echo DEAD', 15000);
      return { alive: /ALIVE/.test(r.stdout || '') };
    } catch (e) {
      return { alive: false, reason: e.message };
    } finally {
      try { conn && conn.end(); } catch {}
    }
  }

  async function stopProcess(slaveId, pid) {
    const slave = slaves.find(s => s.id === slaveId);
    if (!slave) return false;
    let conn;
    try {
      conn = await connectOnce(slave, 15000);
      await exec(conn, '(kill -9 -' + Number(pid) + ' 2>/dev/null || kill -9 ' + Number(pid) + ' 2>/dev/null); true', 15000);
      return true;
    } catch { return false; }
    finally { try { conn && conn.end(); } catch {} }
  }

  async function healthCheckOne(slave) {
    if (slave.status === 'bootstrapping' || slave.status === 'failed') return false;
    let conn;
    try {
      conn = await connectRetry(slave, 30000);
      const files = [SCRIPT_NAME, PROXY_NAME].concat(HAS_C_RUSH ? [C_RUSH_SCRIPT] : []);
      const checks = files.map(f => 'test -f ' + f).join(' && ');
      const r = await exec(conn,
        'cd ' + (slave.kdir || '/root/koldvein') + ' && node --version >/dev/null 2>&1 && ' +
        checks + ' && echo HEALTHY', 20000);
      slave.lastCheck = new Date().toISOString();
      slave._healthFails = 0;
      if (r.stdout.includes('HEALTHY')) {
        slave.status = 'ready';
        slave.lastError = null;
      } else {
        slave.status = 'unhealthy';
        slave.lastError = 'Files missing on slave';
      }
    } catch (e) {
      slave.lastCheck = new Date().toISOString();
      slave._healthFails = (slave._healthFails || 0) + 1;
      if (slave._healthFails >= HEALTH_STRIKES) {
        slave.status = 'offline';
        slave.lastError = String(e.message || '').slice(0, 200);
      } else if (slave._healthFails >= HEALTH_SOFT && slave.status === 'ready') {
        slave.status = 'unhealthy';
        slave.lastError = 'Check failed ' + slave._healthFails + '×: ' + String(e.message || '').slice(0, 150);
      }
    } finally {
      try { conn && conn.end(); } catch {}
      save();
    }
    return slave.status === 'ready';
  }

  async function healthCheckAll() { await Promise.allSettled(slaves.map(healthCheckOne)); }

  function listSlaves() {
    return slaves.map(s => {
      const cores = (Number.isInteger(s.cores) && s.cores >= 1 && s.cores <= MAX_SAFE_CORES) ? s.cores : 0;
      return {
        id: s.id, name: s.name, ip: s.ip, port: s.port, username: s.username,
        cores, ramMb: s.ramMb, status: s.status,
        lastCheck: s.lastCheck, lastError: s.lastError,
        bootstrapStage: s.bootstrapStage || null,
        authType: s.authType,
        threads: cores * THREADS_PER_CORE,
      };
    });
  }
  const getReadySlaves = () => slaves.filter(s => s.status === 'ready' && Number.isInteger(s.cores) && s.cores >= 1);
  const totalThreads   = () => getReadySlaves().reduce((a, s) => a + s.cores * THREADS_PER_CORE, 0);
  const getById        = id => slaves.find(s => s.id === id);

  return {
    addSlave, removeSlave, rebootstrapSlave,
    listSlaves, getReadySlaves, getById, totalThreads,
    launchOnSlave, checkProcess, stopProcess, healthCheckAll,
    THREADS_PER_CORE, SCRIPT_NAME,
    HAS_C_RUSH, C_RUSH_SCRIPT,
  };
};