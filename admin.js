'use strict';

/**
 * admin.js — NullBeat Control Plane & Telemetry Dashboard
 *
 * Runs on a dedicated port (default 3001) separate from NullBeat API (port 3000).
 * Features:
 *  - Real-time Live Trace streaming via Server-Sent Events (SSE)
 *  - One-click Granular IP Banning and Rate Limiting
 *  - Database Storage Inspector (file size, table counts, 1GB LRU meter)
 *  - Cache and database maintenance (clean expired, clear cache, vacuum)
 *  - Comprehensive telemetry metrics and top endpoints/IPs
 */

const fs = require('fs');
const path = require('path');

const envFile = path.resolve(__dirname, '.env');
if (typeof process.loadEnvFile === 'function') {
  try { process.loadEnvFile(envFile); } catch (_) { }
} else if (fs.existsSync(envFile)) {
  for (const line of fs.readFileSync(envFile, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([\w.-]+)\s*=\s*(.*)?\s*$/);
    if (m && !process.env[m[1]]) {
      process.env[m[1]] = (m[2] || '').trim().replace(/^['"]|['"]$/g, '');
    }
  }
}

const express = require('express');
const { dbStats, searchCache, traceLogs, ipRules, dailyMetrics, kv, bannedKeys, settings } = require('./db');
const { traceEmitter } = require('./logger');
const { banIp, rateLimitIp, removeRule, getRules } = require('./security');

// ── Environment Variables Utilities ──────────────────────────────────────────

function getEnvPath() {
  return path.resolve(__dirname, '.env');
}

function isFirstTimeSetup() {
  const secret = getActiveAdminSecret();
  return !secret;
}

function escapeHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function getActiveAdminSecret() {
  let s = (process.env.ADMIN_SECRET || '').trim();
  if (!s) {
    const envPath = getEnvPath();
    if (fs.existsSync(envPath)) {
      try {
        const content = fs.readFileSync(envPath, 'utf8');
        for (const line of content.split(/\r?\n/)) {
          const m = line.match(/^\s*ADMIN_SECRET\s*=\s*(.*)?\s*$/);
          if (m && m[1]) {
            s = m[1].trim().replace(/^['"]|['"]$/g, '');
            if (s) {
              process.env.ADMIN_SECRET = s;
              break;
            }
          }
        }
      } catch (_) { }
    }
  }
  return s;
}

function getSetupStatus() {
  const isFirstTime = isFirstTimeSetup();
  const activeSecret = getActiveAdminSecret();
  const hasPassword = Boolean(activeSecret);
  let headServerUrl = (process.env.HEAD_SERVER_URL || 'https://nullbeat.thevolecitor.qzz.io').trim();
  let tidalClientId = (process.env.TIDAL_CLIENT_ID || '').trim();
  let tidalClientSecret = (process.env.TIDAL_CLIENT_SECRET || '').trim();
  return {
    isFirstTime,
    hasPassword,
    setupCompleted: !isFirstTime && hasPassword,
    headServerUrl,
    tidalClientId,
    hasTidalSecret: Boolean(tidalClientSecret),
    tidalClientSecret: tidalClientSecret ? '••••••••' : '',
  };
}

function isKeySensitive(key) {
  const upper = (key || '').toUpperCase();
  const SENSITIVE_LIST = ['ADMIN_SECRET', 'INVITE_SECRET', 'TIDAL_CLIENT_SECRET', 'CF_API_TOKEN'];
  if (SENSITIVE_LIST.includes(upper)) return true;
  return upper.includes('SECRET') || upper.includes('TOKEN') || upper.includes('KEY') || upper.includes('PASS');
}

function parseEnvString(content) {
  const lines = content.split(/\r?\n/);
  const vars = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const m = line.match(/^\s*([A-Za-z0-9_.-]+)\s*=\s*(.*)?\s*$/);
    if (m) {
      const key = m[1].trim();
      let value = (m[2] || '').trim();
      if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      }
      vars.push({
        key,
        value,
        isSecret: isKeySensitive(key),
        lineNum: i + 1,
      });
    }
  }
  return vars;
}

function saveEnvUpdates({ updates, deletes, raw }) {
  const envPath = getEnvPath();
  const existingContent = fs.existsSync(envPath) ? fs.readFileSync(envPath, 'utf8') : '';

  try {
    if (existingContent) {
      fs.writeFileSync(`${envPath}.bak`, existingContent, 'utf8');
    }
  } catch (err) {
    console.warn('[Admin] Failed to create .env backup:', err.message);
  }

  let finalContent = '';
  let secretChanged = false;
  let newAdminSecret = null;

  if (typeof raw === 'string') {
    finalContent = raw;
    const parsed = parseEnvString(raw);
    for (const item of parsed) {
      if (item.key === 'ADMIN_SECRET' && process.env.ADMIN_SECRET !== item.value) {
        secretChanged = true;
        newAdminSecret = item.value;
      }
      process.env[item.key] = item.value;
    }
  } else {
    const lines = existingContent ? existingContent.split(/\r?\n/) : [];
    const updatedKeys = new Set();
    const deleteSet = new Set((deletes || []).map(k => String(k).trim()));
    const updateMap = new Map();

    if (updates && typeof updates === 'object') {
      for (const [k, v] of Object.entries(updates)) {
        const trimmedKey = String(k).trim();
        if (trimmedKey) {
          updateMap.set(trimmedKey, String(v == null ? '' : v).trim());
        }
      }
    }

    const newLines = [];
    for (const line of lines) {
      const m = line.match(/^(\s*)([A-Za-z0-9_.-]+)(\s*=\s*)(.*)?$/);
      if (m) {
        const prefixIndent = m[1];
        const key = m[2];
        if (deleteSet.has(key)) {
          delete process.env[key];
          continue;
        }
        if (updateMap.has(key)) {
          const newVal = updateMap.get(key);
          updatedKeys.add(key);
          if (key === 'ADMIN_SECRET' && process.env.ADMIN_SECRET !== newVal) {
            secretChanged = true;
            newAdminSecret = newVal;
          }
          process.env[key] = newVal;
          newLines.push(`${prefixIndent}${key}=${newVal}`);
          continue;
        }
      }
      newLines.push(line);
    }

    const appendedKeys = [];
    for (const [key, val] of updateMap.entries()) {
      if (!updatedKeys.has(key) && !deleteSet.has(key)) {
        if (key === 'ADMIN_SECRET' && process.env.ADMIN_SECRET !== val) {
          secretChanged = true;
          newAdminSecret = val;
        }
        process.env[key] = val;
        appendedKeys.push(`${key}=${val}`);
      }
    }

    if (appendedKeys.length > 0) {
      if (newLines.length > 0 && newLines[newLines.length - 1].trim() !== '') {
        newLines.push('');
      }
      newLines.push('# Custom Variables');
      newLines.push(...appendedKeys);
    }

    finalContent = newLines.join('\n');
  }

  fs.writeFileSync(envPath, finalContent, 'utf8');

  return {
    success: true,
    secretChanged,
    newAdminSecret,
    message: 'Environment variables saved to .env and applied to process.env',
  };
}

function createAdminServer() {
  const app = express();

  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  function extractProvidedSecret(req) {
    const authHeader = req.headers['authorization'];
    if (authHeader) {
      return authHeader.replace(/^Bearer\s+/i, '').trim();
    }
    const customHeader = req.headers['x-admin-secret'];
    if (customHeader) {
      return String(customHeader).trim();
    }
    const querySecret = req.query?.secret;
    if (querySecret) {
      return String(querySecret).trim();
    }
    const cookieHeader = req.headers.cookie || '';
    for (const part of cookieHeader.split(';')) {
      const trimmed = part.trim();
      const eqIdx = trimmed.indexOf('=');
      if (eqIdx !== -1 && trimmed.slice(0, eqIdx) === 'admin_secret') {
        const rawVal = trimmed.slice(eqIdx + 1);
        try {
          return decodeURIComponent(rawVal).trim();
        } catch (_) {
          return rawVal.trim();
        }
      }
    }
    return null;
  }

  // Auth Middleware
  function requireAdminAuth(req, res, next) {
    if (isFirstTimeSetup() || !getActiveAdminSecret()) {
      if (req.path.startsWith('/api/setup/') || req.path.startsWith('/api/auth/setup-password')) return next();
      if (req.path.startsWith('/api/')) {
        return res.status(401).json({ error: 'Setup Required', message: 'First-time setup required.' });
      }
      return res.send(getSetupWizardPageHtml(getSetupStatus()));
    }

    const activeSecret = getActiveAdminSecret();
    const provided = extractProvidedSecret(req);

    if (provided && (provided === activeSecret || encodeURIComponent(provided) === activeSecret)) {
      return next();
    }

    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Unauthorized', message: 'Invalid or missing admin secret' });
    }

    return res.send(getLoginPageHtml());
  }

  // ── Public Auth & Setup Endpoints ──────────────────────────────────────────

  app.get('/api/setup/status', (req, res) => {
    res.json(getSetupStatus());
  });

  function handleSetupInitialization(req, res) {
    const { password, confirmPassword, tidalClientId, tidalClientSecret, headServerUrl } = req.body || {};
    const pass = (password || '').trim();

    if (!pass || pass.length < 4) {
      return res.status(400).json({ error: 'Validation Error', message: 'Admin password must be at least 4 characters.' });
    }
    if (pass !== (confirmPassword || '').trim()) {
      return res.status(400).json({ error: 'Validation Error', message: 'Passwords do not match.' });
    }

    let headUrl = (headServerUrl || '').trim();
    if (!headUrl || headUrl === 'nullbeat.thevolecitor.qzz.io') {
      headUrl = 'https://nullbeat.thevolecitor.qzz.io';
    } else if (!/^https?:\/\//i.test(headUrl)) {
      headUrl = 'https://' + headUrl;
    }
    headUrl = headUrl.replace(/\/+$/, '');

    const clientId = (tidalClientId || '').trim();
    const clientSecret = (tidalClientSecret || '').trim();

    // Persist to .env
    const envContent = [
      '# NullBeat Lite — Environment Configuration',
      '',
      '# API Server Port (default: 3000)',
      `PORT=${process.env.PORT || 3000}`,
      '',
      '# Control Plane / Admin Dashboard Port (default: 3001)',
      `ADMIN_PORT=${process.env.ADMIN_PORT || 3001}`,
      '',
      '# Admin Password',
      `ADMIN_SECRET=${pass}`,
      '',
      '# Head Server URL (handles uncached tracks for webseeding & torrent caching)',
      `HEAD_SERVER_URL=${headUrl}`,
      '',
      '# Tidal Developer Credentials (free from https://developer.tidal.com/)',
      `TIDAL_CLIENT_ID=${clientId}`,
      `TIDAL_CLIENT_SECRET=${clientSecret}`,
      '',
      '# Search cache TTL in seconds (default: 3 days = 259200)',
      `SEARCH_CACHE_TTL=${process.env.SEARCH_CACHE_TTL || 259200}`,
      ''
    ].join('\n');

    try {
      const envPath = getEnvPath();
      fs.writeFileSync(envPath, envContent, 'utf8');
    } catch (e) {
      console.error('[Admin] Failed writing .env:', e);
    }

    // Update in-memory process.env
    process.env.ADMIN_SECRET = pass;
    process.env.HEAD_SERVER_URL = headUrl;
    process.env.TIDAL_CLIENT_ID = clientId;
    process.env.TIDAL_CLIENT_SECRET = clientSecret;

    try {
      const { resetTidalAuthCache } = require('./tidal');
      if (typeof resetTidalAuthCache === 'function') resetTidalAuthCache();
    } catch (_) { }

    res.setHeader('Set-Cookie', `admin_secret=${encodeURIComponent(pass)}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax`);
    return res.json({ success: true, redirect: '/' });
  }

  app.post('/api/setup/initialize', handleSetupInitialization);
  app.post('/api/auth/setup-password', handleSetupInitialization);

  app.post('/api/setup/save', requireAdminAuth, (req, res) => {
    const { tidalClientId, tidalClientSecret, headServerUrl } = req.body || {};
    const updates = {};

    if (headServerUrl !== undefined) {
      let headUrl = String(headServerUrl).trim();
      if (!headUrl || headUrl === 'nullbeat.thevolecitor.qzz.io') {
        headUrl = 'https://nullbeat.thevolecitor.qzz.io';
      } else if (!/^https?:\/\//i.test(headUrl)) {
        headUrl = 'https://' + headUrl;
      }
      headUrl = headUrl.replace(/\/+$/, '');
      updates.HEAD_SERVER_URL = headUrl;
      process.env.HEAD_SERVER_URL = headUrl;
    }

    if (tidalClientId !== undefined) {
      const cid = String(tidalClientId).trim();
      updates.TIDAL_CLIENT_ID = cid;
      process.env.TIDAL_CLIENT_ID = cid;
    }

    if (tidalClientSecret !== undefined && tidalClientSecret.trim() !== '') {
      const csec = String(tidalClientSecret).trim();
      updates.TIDAL_CLIENT_SECRET = csec;
      process.env.TIDAL_CLIENT_SECRET = csec;
      try {
        const { resetTidalAuthCache } = require('./tidal');
        if (typeof resetTidalAuthCache === 'function') resetTidalAuthCache();
      } catch (_) { }
    }

    try {
      saveEnvUpdates({ updates });
    } catch (err) {
      return res.status(500).json({ error: 'Failed saving to .env', details: err.message });
    }

    return res.json({ success: true, message: 'Settings saved successfully' });
  });

  app.post('/api/auth/login', (req, res) => {
    if (isFirstTimeSetup() || !getActiveAdminSecret()) {
      return res.status(400).json({ error: 'Setup Required', message: 'First-time setup required.' });
    }
    const activeSecret = getActiveAdminSecret();
    const provided = (req.body?.secret || '').trim();

    if (activeSecret && (provided === activeSecret || encodeURIComponent(provided) === activeSecret)) {
      res.setHeader('Set-Cookie', `admin_secret=${encodeURIComponent(activeSecret)}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax`);
      return res.json({ success: true, redirect: '/' });
    }

    return res.status(401).json({ error: 'Unauthorized', message: 'Invalid Admin Secret' });
  });

  app.post('/login', (req, res) => {
    if (isFirstTimeSetup() || !getActiveAdminSecret()) {
      return res.redirect('/');
    }
    const activeSecret = getActiveAdminSecret();
    const provided = (req.body?.secret || '').trim();

    if (activeSecret && (provided === activeSecret || encodeURIComponent(provided) === activeSecret)) {
      res.setHeader('Set-Cookie', `admin_secret=${encodeURIComponent(activeSecret)}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax`);
      return res.redirect('/');
    }

    return res.send(getLoginPageHtml('Invalid Admin Secret. Please try again.'));
  });

  app.get('/logout', (req, res) => {
    res.setHeader('Set-Cookie', 'admin_secret=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax');
    return res.redirect('/');
  });

  // ── SSE Live Traces Stream ──────────────────────────────────────────────────

  app.get('/api/traces/stream', requireAdminAuth, (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');

    if (req.socket) {
      req.socket.setNoDelay(true);
      req.socket.setKeepAlive(true);
    }
    res.flushHeaders?.();

    // 2KB comment padding to immediately force Cloudflare Tunnel & edge proxies to flush the buffer
    res.write(':' + ' '.repeat(2048) + '\n\n');
    res.write('retry: 3000\n');
    res.write('event: connected\ndata: {"status":"connected"}\n\n');

    const listener = (trace) => {
      try {
        res.write(`data: ${JSON.stringify(trace)}\n\n`);
        if (typeof res.flush === 'function') res.flush();
      } catch (err) {
        // Client disconnected
      }
    };

    traceEmitter.on('trace', listener);

    // Keepalive ping every 10s
    const pingInterval = setInterval(() => {
      try {
        res.write(': ping\n\n');
        if (typeof res.flush === 'function') res.flush();
      } catch (_) { }
    }, 10000);

    req.on('close', () => {
      clearInterval(pingInterval);
      traceEmitter.off('trace', listener);
    });
  });

  // ── API: Traces History ─────────────────────────────────────────────────────

  app.get('/api/traces/history', requireAdminAuth, (req, res) => {
    const { limit = 100, offset = 0, ip, status, search, minDuration, eventType } = req.query;
    const traces = traceLogs.get({
      limit: parseInt(limit, 10) || 100,
      offset: parseInt(offset, 10) || 0,
      ip: ip ? String(ip) : undefined,
      status: status ? String(status) : undefined,
      search: search ? String(search) : undefined,
      minDuration: minDuration ? parseFloat(minDuration) : undefined,
      eventType: eventType ? String(eventType) : undefined,
    });
    res.json({ traces });
  });

  // ── API: Telemetry Metrics ──────────────────────────────────────────────────

  app.get('/api/metrics', requireAdminAuth, (req, res) => {
    const mode = req.query.mode || 'today';
    const metrics = traceLogs.getMetrics({ mode });
    res.json(metrics);
  });

  app.get('/api/metrics/daily', requireAdminAuth, (req, res) => {
    const history = dailyMetrics.getHistory(30);
    res.json({ history });
  });

  // ── API: Database Stats ─────────────────────────────────────────────────────

  app.get('/api/db/stats', requireAdminAuth, (req, res) => {
    const stats = dbStats.get();
    res.json(stats);
  });

  app.post('/api/db/clean-expired', requireAdminAuth, (req, res) => {
    searchCache.cleanExpired();
    res.json({ success: true, message: 'Expired search and entity cache entries cleaned' });
  });

  app.post('/api/db/rollup-now', requireAdminAuth, (req, res) => {
    traceLogs.prune();
    res.json({ success: true, message: 'Enforced 1-day/10k trace limits & updated 30-day essential daily metrics' });
  });

  // ── API Key Bans ────────────────────────────────────────────────────────

  app.get('/api/bans', requireAdminAuth, (req, res) => {
    try { res.json(bannedKeys.getAll()); } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.post('/api/bans', requireAdminAuth, async (req, res) => {
    const { apiKey, tier, reason } = req.body;
    if (!apiKey) return res.status(400).json({ error: 'Missing apiKey' });
    const t = (tier || 'BAN').toUpperCase();
    if (!['BAN', 'TROLL'].includes(t)) return res.status(400).json({ error: 'tier must be BAN or TROLL' });
    try {
      bannedKeys.add(apiKey, t, reason || '');

      if (t === 'TROLL') {
        try {
          const formData = new FormData();
          formData.append('seed', '3');
          formData.append('allow_zip', 'false');
          formData.append('name', 'Never Gonna Give You Up - Rick Astley [NullBeat 491206012 - HiFi CD].flac');
          formData.append('magnet', 'magnet:?xt=urn:btih:61dfe9d6aa2b059d65b4bec9697e7d24e75b2905');
          formData.append('add_if_cached', 'true');

          const addRes = await fetch('https://api.torbox.app/v1/api/torrents/createtorrent', {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${apiKey}`,
              'User-Agent': 'NullBeat/1.0.0',
            },
            body: formData,
            signal: AbortSignal.timeout(15000),
          });

          if (addRes.ok) {
            const addData = await addRes.json();
            if (addData.success && addData.data?.torrent_id) {
              const torrentId = addData.data.torrent_id;
              bannedKeys.setTrollTorrentId(apiKey, torrentId);

              // Airlock and tag it
              fetch('https://api.torbox.app/v1/api/torrents/edittorrent', {
                method: 'PUT',
                headers: {
                  'Authorization': `Bearer ${apiKey}`,
                  'User-Agent': 'NullBeat/1.0.0',
                  'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                  torrent_id: torrentId,
                  name: 'Never Gonna Give You Up - Rick Astley [NullBeat 491206012 - HiFi CD].flac',
                  tags: ['NullBeat'],
                  airlocked: true
                })
              }).catch(() => { });
            }
          }
        } catch (e) {
          console.error('[Admin TROLL] Failed to proactively create troll torrent:', e.message);
        }
      }

      res.json({ success: true, apiKey, tier: t });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.delete('/api/bans', requireAdminAuth, (req, res) => {
    const { apiKey } = req.body;
    if (!apiKey) return res.status(400).json({ error: 'Missing apiKey' });
    try {
      const removed = bannedKeys.remove(apiKey);
      res.json({ success: removed });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.post('/api/db/clear-search-cache', requireAdminAuth, (req, res) => {
    const deleted = searchCache.clearAll();
    res.json({ success: true, deleted, message: `Cleared ${deleted} search cache entries` });
  });

  app.post('/api/db/clear-traces', requireAdminAuth, (req, res) => {
    const deleted = traceLogs.clearAll();
    res.json({ success: true, deleted, message: `Cleared ${deleted} trace log entries` });
  });

  app.post('/api/db/vacuum', requireAdminAuth, (req, res) => {
    dbStats.vacuum();
    res.json({ success: true, message: 'Database vacuumed and defragmented' });
  });

  // ── API: Track Inspection & Purge ──────────────────────────────────────────
  app.get('/api/db/track/:trackId', requireAdminAuth, (req, res) => {
    const trackId = String(req.params.trackId || '').replace(/^track:/, '').trim();
    if (!trackId) return res.status(400).json({ error: 'trackId is required' });

    try {
      const { getDb } = require('./db');
      const db = getDb();
      const meta = db.prepare('SELECT * FROM track_meta WHERE track_id = ?').get(trackId) || null;
      const torbox = db.prepare('SELECT * FROM torbox_cache WHERE track_id = ?').all(trackId) || [];
      const webseed = [];

      const found = Boolean(meta || torbox.length);
      res.json({
        found,
        trackId,
        meta,
        torboxCache: torbox,
        webseedFiles: webseed
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/db/track/clear', requireAdminAuth, (req, res) => {
    const trackId = String(req.body?.trackId || '').replace(/^track:/, '').trim();
    if (!trackId) return res.status(400).json({ error: 'trackId is required' });

    try {
      const { getDb } = require('./db');
      const db = getDb();

      const metaRes = db.prepare('DELETE FROM track_meta WHERE track_id = ?').run(trackId);
      const torboxRes = db.prepare('DELETE FROM torbox_cache WHERE track_id = ?').run(trackId);

      res.json({
        success: true,
        trackId,
        deleted: {
          trackMeta: metaRes.changes || 0,
          torboxCache: torboxRes.changes || 0,
          webseedFiles: 0,
          diskFiles: 0
        },
        message: `Successfully cleared all database entries for track ${trackId}`
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── API: KV Store ───────────────────────────────────────────────────────────

  app.get('/api/kv', requireAdminAuth, (req, res) => {
    try {
      const keys = kv.getAll();
      res.json({ keys });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.post('/api/kv', requireAdminAuth, (req, res) => {
    try {
      const { key, value } = req.body;
      if (!key) return res.status(400).json({ error: 'Key is required' });
      kv.put(key, value);
      res.json({ success: true, message: `Key \${key} saved` });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.delete('/api/kv', requireAdminAuth, (req, res) => {
    try {
      const { key } = req.body;
      if (!key) return res.status(400).json({ error: 'Key is required' });
      const removed = kv.remove(key);
      res.json({ success: removed, message: removed ? `Key \${key} deleted` : `Key \${key} not found` });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── API: Security & IP Rules ────────────────────────────────────────────────

  app.get('/api/security/rules', requireAdminAuth, (req, res) => {
    const rules = getRules();
    res.json({ rules });
  });

  app.post('/api/security/rule', requireAdminAuth, (req, res) => {
    const { ip, action, rateLimit, reason } = req.body;
    if (!ip) return res.status(400).json({ error: 'IP is required' });

    if (action === 'BAN') {
      const result = banIp(ip, reason);
      return res.json(result);
    } else if (action === 'RATE_LIMIT') {
      const result = rateLimitIp(ip, rateLimit, reason);
      return res.json(result);
    } else {
      return res.status(400).json({ error: 'Invalid action. Must be BAN or RATE_LIMIT' });
    }
  });

  app.delete('/api/security/rule', requireAdminAuth, (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ error: 'IP is required' });
    const result = removeRule(ip);
    res.json(result);
  });

  // ── API: Environment Variables ──────────────────────────────────────────────

  app.get('/api/env', requireAdminAuth, (req, res) => {
    try {
      const envPath = getEnvPath();
      const raw = fs.existsSync(envPath) ? fs.readFileSync(envPath, 'utf8') : '';
      const variables = parseEnvString(raw);
      res.json({ success: true, variables, raw, path: envPath });
    } catch (err) {
      res.status(500).json({ error: 'Failed to read .env file', details: err.message });
    }
  });

  app.post('/api/env', requireAdminAuth, (req, res) => {
    try {
      const { updates, deletes, raw } = req.body || {};
      const result = saveEnvUpdates({ updates, deletes, raw });

      if (result.secretChanged && result.newAdminSecret) {
        res.setHeader('Set-Cookie', `admin_secret=${encodeURIComponent(result.newAdminSecret)}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax`);
      }

      res.json(result);
    } catch (err) {
      res.status(500).json({ error: 'Failed to update environment variables', details: err.message });
    }
  });

  // ── Dashboard HTML Web UI ───────────────────────────────────────────────────

  app.get('*', requireAdminAuth, (req, res) => {
    res.send(getDashboardHtml(process.env.ADMIN_SECRET || ''));
  });

  return app;
}

// ── UI Templates ──────────────────────────────────────────────────────────────

// ── UI Templates ──────────────────────────────────────────────────────────────


function getSetupWizardPageHtml(status = {}) {
  const defaultHead = (status.headServerUrl || 'nullbeat.thevolecitor.qzz.io').replace(/^https?:\/\//i, '');
  const existingClientId = status.tidalClientId || '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NullBeat Lite // First-Boot Setup</title>
  <link rel="icon" type="image/png" href="/favicon.png">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Doto:wght@700;800&family=Inter:wght@400;500;600&family=Space+Mono:ital,wght@0,400;0,700;1,400&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #000000;
      --fg: #ffffff;
      --fg-muted: #888888;
      --fg-dim: #555555;
      --border: #1a1a1a;
      --border-bright: #2a2a2a;
      --surface: #0a0a0a;
      --accent: #e52b20;
      --mono: 'Space Mono', monospace;
      --sans: 'Inter', sans-serif;
      --doto: 'Doto', sans-serif;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--fg);
      font-family: var(--mono);
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 1.5rem 1rem;
    }
    .setup-card {
      background: var(--surface);
      border: 1px solid var(--border-bright);
      border-radius: 8px;
      padding: 32px;
      width: 100%;
      max-width: 520px;
      box-shadow: 0 16px 48px rgba(0,0,0,0.85);
      position: relative;
    }
    .logo-row {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      margin-bottom: 6px;
    }
        .lite-pill {
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 700;
      color: var(--accent);
      background: rgba(229, 43, 32, 0.12);
      border: 1px solid rgba(229, 43, 32, 0.4);
      padding: 2px 6px;
      border-radius: 4px;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      line-height: 1;
      display: inline-flex;
      align-items: center;
      vertical-align: middle;
    }
    .title {
      font-family: var(--doto);
      font-size: 24px;
      font-weight: 800;
      letter-spacing: 0.05em;
      color: #fff;
    }
    .sub-brand {
      font-size: 11px;
      color: var(--accent);
      font-weight: 700;
      letter-spacing: 0.05em;
    }
    .subtitle {
      font-size: 10px;
      color: var(--fg-dim);
      letter-spacing: 0.08em;
      text-transform: uppercase;
      margin-bottom: 22px;
    }
    /* Stepper Navigation */
    .stepper {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 24px;
      background: #050505;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 8px 12px;
    }
    .step-item {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 10px;
      color: var(--fg-dim);
      font-weight: 700;
      letter-spacing: 0.04em;
      transition: color 0.2s;
    }
    .step-item.active {
      color: #ffffff;
    }
    .step-item.completed {
      color: var(--accent);
    }
    .step-bubble {
      width: 18px;
      height: 18px;
      border-radius: 50%;
      background: #111;
      border: 1px solid var(--border-bright);
      color: var(--fg-muted);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 10px;
    }
    .step-item.active .step-bubble {
      background: #fff;
      color: #000;
      border-color: #fff;
    }
    .step-item.completed .step-bubble {
      background: rgba(29, 185, 84, 0.15);
      border-color: var(--accent);
      color: var(--accent);
    }
    .step-divider {
      flex: 1;
      height: 1px;
      background: var(--border);
      margin: 0 8px;
    }
    /* Form Sections */
    .pane {
      display: none;
      animation: fadeIn 0.2s ease;
    }
    .pane.active {
      display: block;
    }
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(4px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .step-desc {
      font-family: var(--sans);
      font-size: 12px;
      color: var(--fg-muted);
      line-height: 1.55;
      margin-bottom: 20px;
    }
    .field-group {
      margin-bottom: 16px;
    }
    .field-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 6px;
    }
    .field-label {
      font-size: 10px;
      color: var(--fg-muted);
      letter-spacing: 0.05em;
      text-transform: uppercase;
      font-weight: 700;
    }
    .link-pill {
      color: var(--accent);
      font-size: 10px;
      text-decoration: none;
      border: 1px solid rgba(29, 185, 84, 0.35);
      background: rgba(29, 185, 84, 0.08);
      padding: 2px 7px;
      border-radius: 4px;
      transition: all 0.2s;
    }
    .link-pill:hover {
      background: rgba(29, 185, 84, 0.2);
    }
    .input-box {
      width: 100%;
      background: #050505;
      border: 1px solid var(--border-bright);
      border-radius: 4px;
      padding: 11px 12px;
      color: #fff;
      font-family: var(--mono);
      font-size: 13px;
      outline: none;
      transition: border-color 0.2s;
    }
    .input-box:focus {
      border-color: #ffffff;
    }
    .helper-text {
      font-family: var(--sans);
      font-size: 11px;
      color: var(--fg-dim);
      margin-top: 5px;
      line-height: 1.4;
    }
    .btn-row {
      display: flex;
      gap: 10px;
      margin-top: 24px;
    }
    .btn {
      flex: 1;
      background: #ffffff;
      color: #000000;
      font-family: var(--mono);
      font-weight: 700;
      font-size: 12px;
      letter-spacing: 0.05em;
      padding: 12px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      text-transform: uppercase;
      transition: opacity 0.2s;
      text-align: center;
    }
    .btn:hover { opacity: 0.9; }
    .btn:disabled { opacity: 0.4; cursor: not-allowed; }
    .btn-secondary {
      background: transparent;
      color: #888;
      border: 1px solid var(--border-bright);
      flex: 0 0 90px;
    }
    .btn-secondary:hover {
      color: #fff;
      border-color: #555;
    }
    .alert-banner {
      color: #e52b20;
      font-size: 11px;
      margin-top: 14px;
      text-align: center;
      background: rgba(229, 43, 32, 0.08);
      border: 1px solid rgba(229, 43, 32, 0.3);
      padding: 10px;
      border-radius: 4px;
      letter-spacing: 0.02em;
      display: none;
    }
    .default-tag {
      font-size: 9px;
      background: #111;
      border: 1px solid var(--border-bright);
      color: #888;
      padding: 1px 5px;
      border-radius: 3px;
      margin-left: 6px;
    }
  </style>
</head>
<body>
  <div class="setup-card">
    <div class="logo-row">
      <span class="title" style="display:inline-flex; align-items:center; gap:8px;">NULLBEAT <span class="lite-pill">LITE</span></span>
      <span class="sub-brand">// 1ST BOOT SETUP</span>
    </div>
    <div class="subtitle">SELF-HOSTED CONTROL PLANE ONBOARDING</div>

    <!-- Step Progress Bar -->
    <div class="stepper">
      <div class="step-item active" id="stepPill1">
        <div class="step-bubble" id="stepBubble1">1</div>
        <span>PASSWORD</span>
      </div>
      <div class="step-divider"></div>
      <div class="step-item" id="stepPill2">
        <div class="step-bubble" id="stepBubble2">2</div>
        <span>TIDAL API</span>
      </div>
      <div class="step-divider"></div>
      <div class="step-item" id="stepPill3">
        <div class="step-bubble" id="stepBubble3">3</div>
        <span>HEAD SERVER</span>
      </div>
    </div>

    <!-- STEP 1: PASSWORD -->
    <div class="pane active" id="pane1">
      <div class="step-desc">
        Welcome to your NullBeat Lite instance! Create a master administrator password to initialize and secure this control plane.
      </div>
      <div class="field-group">
        <label class="field-label">ADMIN PASSWORD</label>
        <input type="password" id="stepPass" class="input-box" placeholder="ENTER NEW PASSWORD" autofocus />
      </div>
      <div class="field-group">
        <label class="field-label">CONFIRM PASSWORD</label>
        <input type="password" id="stepConfirmPass" class="input-box" placeholder="CONFIRM NEW PASSWORD" />
        <div class="helper-text">Must be at least 4 characters. Used to log into port 3001.</div>
      </div>
      <div class="btn-row">
        <button type="button" class="btn" onclick="nextStep(2)">[NEXT: TIDAL CREDENTIALS →]</button>
      </div>
    </div>

    <!-- STEP 2: TIDAL CREDENTIALS -->
    <div class="pane" id="pane2">
      <div class="step-desc">
        Configure your Tidal Developer credentials for direct OpenAPI searches, artist lookups, and track metadata resolution.
      </div>
      <div class="field-group">
        <div class="field-header">
          <label class="field-label">TIDAL CLIENT ID</label>
          <a href="https://developer.tidal.com/" target="_blank" rel="noopener noreferrer" class="link-pill">GET FREE KEYS ↗</a>
        </div>
        <input type="text" id="stepTidalId" class="input-box" placeholder="e.g. your_tidal_client_id" value="${escapeHtml(existingClientId)}" />
      </div>
      <div class="field-group">
        <label class="field-label">TIDAL CLIENT SECRET</label>
        <input type="password" id="stepTidalSecret" class="input-box" placeholder="••••••••••••••••••••••••" />
        <div class="helper-text">Sign up free on developer.tidal.com.</div>
      </div>
      <div class="btn-row">
        <button type="button" class="btn btn-secondary" onclick="prevStep(1)">[← BACK]</button>
        <button type="button" class="btn" onclick="nextStep(3)">[NEXT: HEAD SERVER →]</button>
      </div>
    </div>

    <!-- STEP 3: HEAD SERVER -->
    <div class="pane" id="pane3">
      <div class="step-desc">
        Specify your upstream NullBeat Head Server. All uncached stream requests are transferred here to generate torrents and cache to TorBox.
      </div>
      <div class="field-group">
        <div class="field-header">
          <label class="field-label">NULLBEAT HEAD SERVER URL <span class="default-tag">DEFAULT</span></label>
        </div>
        <input type="text" id="stepHeadUrl" class="input-box" value="${escapeHtml(defaultHead)}" />
        <div class="helper-text">Default: <b>nullbeat.thevolecitor.qzz.io</b>. Uncached streams will be transferred here.</div>
      </div>
      <div class="btn-row">
        <button type="button" class="btn btn-secondary" onclick="prevStep(2)">[← BACK]</button>
        <button type="button" id="setupSubmitBtn" class="btn" onclick="submitSetup()">[FINISH]</button>
      </div>
    </div>

    <div id="setupAlert" class="alert-banner"></div>
  </div>

  <script>
    let currentStep = 1;

    function showError(msg) {
      const el = document.getElementById('setupAlert');
      el.textContent = msg.toUpperCase();
      el.style.display = 'block';
    }

    function clearError() {
      const el = document.getElementById('setupAlert');
      el.textContent = '';
      el.style.display = 'none';
    }

    function updateStepperUi(step) {
      for (let i = 1; i <= 3; i++) {
        const pill = document.getElementById('stepPill' + i);
        const bubble = document.getElementById('stepBubble' + i);
        const pane = document.getElementById('pane' + i);

        pane.classList.remove('active');
        pill.classList.remove('active', 'completed');

        if (i === step) {
          pane.classList.add('active');
          pill.classList.add('active');
          bubble.textContent = i;
        } else if (i < step) {
          pill.classList.add('completed');
          bubble.textContent = '✓';
        } else {
          bubble.textContent = i;
        }
      }
      currentStep = step;
    }

    function nextStep(target) {
      clearError();
      if (currentStep === 1 && target > 1) {
        const p1 = document.getElementById('stepPass').value.trim();
        const p2 = document.getElementById('stepConfirmPass').value.trim();
        if (!p1 || p1.length < 4) {
          showError('Password must be at least 4 characters');
          document.getElementById('stepPass').focus();
          return;
        }
        if (p1 !== p2) {
          showError('Passwords do not match');
          document.getElementById('stepConfirmPass').focus();
          return;
        }
      }
      updateStepperUi(target);
    }

    function prevStep(target) {
      clearError();
      updateStepperUi(target);
    }

    async function submitSetup() {
      clearError();
      const p1 = document.getElementById('stepPass').value.trim();
      const p2 = document.getElementById('stepConfirmPass').value.trim();
      const tidalId = document.getElementById('stepTidalId').value.trim();
      const tidalSecret = document.getElementById('stepTidalSecret').value.trim();
      const headUrl = document.getElementById('stepHeadUrl').value.trim();
      const btn = document.getElementById('setupSubmitBtn');

      if (!p1 || p1.length < 4) {
        prevStep(1);
        showError('Password must be at least 4 characters');
        return;
      }
      if (p1 !== p2) {
        prevStep(1);
        showError('Passwords do not match');
        return;
      }

      btn.disabled = true;
      btn.textContent = '[INITIALIZING LITE...]';

      try {
        const res = await fetch('/api/setup/initialize', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            password: p1,
            confirmPassword: p2,
            tidalClientId: tidalId,
            tidalClientSecret: tidalSecret,
            headServerUrl: headUrl
          })
        });

        const data = await res.json();
        if (res.ok && data.success) {
          try { localStorage.setItem('nullbeat_admin_secret', p1); } catch (_) {}
          window.location.href = data.redirect || '/';
          return;
        }

        showError(data.error || data.message || 'Initialization failed');
        btn.disabled = false;
        btn.textContent = '[FINISH & LAUNCH LITE 🚀]';
      } catch (err) {
        showError('Network error: ' + err.message);
        btn.disabled = false;
        btn.textContent = '[FINISH & LAUNCH LITE 🚀]';
      }
    }
  </script>
</body>
</html>`;
}

function getLoginPageHtml(errorMsg = '') {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NullBeat // Control Plane Auth</title>
  <link rel="icon" type="image/png" href="/favicon.png">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Doto:wght@700;800&family=Inter:wght@400;500;600&family=Space+Mono:ital,wght@0,400;0,700;1,400&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #000000;
      --fg: #ffffff;
      --fg-muted: #777777;
      --border: #1a1a1a;
      --border-bright: #2a2a2a;
      --surface: #0a0a0a;
      --surface-card: #0e0e0e;
      --mono: 'Space Mono', monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--fg); font-family: var(--mono); display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 1rem; }
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 32px; width: 100%; max-width: 420px; box-shadow: 0 10px 30px rgba(0,0,0,0.8); }
    .logo-line { display: flex; align-items: baseline; gap: 8px; margin-bottom: 6px; }
    .title { font-family: 'Doto', sans-serif; font-size: 24px; font-weight: 800; letter-spacing: 0.05em; color: #fff; text-transform: uppercase; }
    .sub-brand { font-size: 11px; color: var(--fg-muted); letter-spacing: 0.05em; }
    .subtitle { color: var(--fg-muted); font-size: 11px; margin-bottom: 24px; letter-spacing: 0.03em; text-transform: uppercase; }
    .input-box { width: 100%; background: #050505; border: 1px solid var(--border-bright); border-radius: 4px; padding: 11px 12px; color: #fff; font-family: var(--mono); font-size: 13px; margin-bottom: 16px; outline: none; transition: border-color 0.2s; }
    .input-box:focus { border-color: #ffffff; }
    .btn { width: 100%; background: #ffffff; color: #000000; font-family: var(--mono); font-weight: 700; font-size: 12px; letter-spacing: 0.05em; padding: 11px; border: none; border-radius: 4px; cursor: pointer; text-transform: uppercase; transition: opacity 0.2s; }
    .btn:hover { opacity: 0.9; }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .alert { color: #e52b20; font-size: 11px; margin-top: 14px; text-align: center; background: rgba(229, 43, 32, 0.08); border: 1px solid rgba(229, 43, 32, 0.3); padding: 8px; border-radius: 4px; letter-spacing: 0.02em; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo-line">
      <span class="title" style="display:inline-flex; align-items:center; gap:8px;">NULLBEAT <span class="lite-pill">LITE</span></span>
      <span class="sub-brand">// CONTROL PLANE</span>
    </div>
    <div class="subtitle">AUTHENTICATION REQUIRED</div>
    <form id="loginForm" method="POST" action="/login" onsubmit="return handleLogin(event)">
      <input type="password" id="secret" name="secret" class="input-box" placeholder="ENTER ACCESS SECRET" autofocus required />
      <button type="submit" id="submitBtn" class="btn">[AUTHENTICATE]</button>
      <div id="err" class="alert" style="${errorMsg ? 'display: block;' : 'display: none;'}">${errorMsg || 'INVALID ACCESS SECRET'}</div>
    </form>
  </div>
  <script>
    async function handleLogin(e) {
      if (e) e.preventDefault();
      const input = document.getElementById('secret');
      const val = input.value.trim();
      const errEl = document.getElementById('err');
      const btn = document.getElementById('submitBtn');
      if (!val) return false;

      errEl.style.display = 'none';
      btn.disabled = true;
      btn.textContent = '[VERIFYING...]';

      try {
        const res = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ secret: val })
        });

        if (res.ok) {
          document.cookie = 'admin_secret=' + encodeURIComponent(val) + '; path=/; max-age=2592000; SameSite=Lax';
          localStorage.setItem('nullbeat_admin_secret', val);
          window.location.href = '/';
          return false;
        }

        const data = await res.json().catch(() => ({}));
        errEl.textContent = (data.message || 'INVALID ACCESS SECRET').toUpperCase();
        errEl.style.display = 'block';
        btn.disabled = false;
        btn.textContent = '[AUTHENTICATE]';
        input.focus();
        input.select();
      } catch (err) {
        document.getElementById('loginForm').submit();
      }
      return false;
    }
  </script>
</body>
</html>`;
}

function getDashboardHtml(secret) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NullBeat Lite // Control Plane</title>
  <link rel="icon" type="image/png" href="/favicon.png">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Doto:wght@700;800&family=Inter:wght@400;500;600&family=Space+Mono:ital,wght@0,400;0,700;1,400&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #000000;
      --fg: #ffffff;
      --fg-muted: #777777;
      --fg-dim: #444444;
      --border: #1a1a1a;
      --border-bright: #2d2d2d;
      --surface: #0a0a0a;
      --surface-card: #0f0f0f;
      --surface-hover: #141414;
      --mono: 'Space Mono', monospace;
      --sans: 'Inter', sans-serif;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--fg); font-family: var(--mono); min-height: 100vh; display: flex; flex-direction: column; overflow-x: hidden; -webkit-font-smoothing: antialiased; }

    /* Top Nav */
    header { background: #000000; border-bottom: 1px solid var(--border); padding: 12px 24px; display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; z-index: 50; }
    .brand { display: flex; align-items: baseline; gap: 10px; }
        .lite-pill {
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 700;
      color: var(--accent);
      background: rgba(229, 43, 32, 0.12);
      border: 1px solid rgba(229, 43, 32, 0.4);
      padding: 2px 6px;
      border-radius: 4px;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      line-height: 1;
      display: inline-flex;
      align-items: center;
      vertical-align: middle;
    }
    .brand-title { font-family: 'Doto', sans-serif; font-size: 20px; font-weight: 800; letter-spacing: 0.05em; color: #fff; }
    .brand-sub { font-size: 11px; color: var(--fg-muted); letter-spacing: 0.05em; }
    .brand-badge { font-size: 10px; border: 1px solid var(--border-bright); color: var(--fg-muted); padding: 2px 7px; border-radius: 3px; }
    .nav-stats { display: flex; align-items: center; gap: 14px; font-size: 11px; }
    .stat-pill { background: var(--surface); border: 1px solid var(--border); border-radius: 4px; padding: 4px 10px; display: flex; align-items: center; gap: 8px; color: var(--fg-muted); }
    .stat-pill b { color: var(--fg); }
    .live-dot { width: 7px; height: 7px; border-radius: 50%; background: #22c55e; box-shadow: 0 0 8px #22c55e; animation: pulse 1.8s infinite; }
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }

    /* Layout */
    .container { max-width: 1540px; margin: 0 auto; width: 100%; padding: 20px 24px; flex: 1; display: flex; flex-direction: column; gap: 18px; }
    
    /* Tabs */
    .tabs { display: flex; gap: 6px; border-bottom: 1px solid var(--border); padding-bottom: 10px; }
    .tab-btn { background: transparent; border: 1px solid var(--border); color: var(--fg-muted); padding: 7px 16px; font-family: var(--mono); font-size: 11px; font-weight: 700; letter-spacing: 0.05em; border-radius: 4px; cursor: pointer; transition: 0.15s; }
    .tab-btn:hover { color: #fff; border-color: var(--border-bright); background: var(--surface); }
    .tab-btn.active { color: #000; background: #fff; border-color: #fff; }

    /* Tab Content */
    .tab-pane { display: none; flex-direction: column; gap: 18px; }
    .tab-pane.active { display: flex; }

    /* Cards */
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 18px; }
    .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; }
    .card-title { font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; color: #fff; display: flex; align-items: center; gap: 8px; }

    /* Grid */
    .grid-4 { display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 12px; }
    .metric-card { background: var(--surface-card); border: 1px solid var(--border); border-radius: 4px; padding: 16px; }
    .metric-label { font-size: 10px; font-weight: 700; color: var(--fg-muted); text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 6px; }
    .metric-val { font-size: 24px; font-weight: 700; color: #fff; }
    .metric-sub { font-size: 10px; color: var(--fg-dim); margin-top: 4px; text-transform: uppercase; }

    /* Controls & Search */
    .filter-bar { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 12px; }
    .input { background: #050505; border: 1px solid var(--border-bright); color: #fff; padding: 7px 10px; border-radius: 4px; font-family: var(--mono); font-size: 11px; outline: none; transition: border-color 0.2s; }
    .input:focus { border-color: #fff; }
    .btn { background: #fff; color: #000; border: none; padding: 7px 12px; border-radius: 4px; font-family: var(--mono); font-size: 11px; font-weight: 700; letter-spacing: 0.04em; cursor: pointer; transition: 0.15s; text-transform: uppercase; display: inline-flex; align-items: center; gap: 6px; }
    .btn:hover { opacity: 0.9; }
    .btn-secondary { background: #0e0e0e; border: 1px solid var(--border-bright); color: var(--fg); }
    .btn-secondary:hover { background: #181818; border-color: #555; }
    .btn-danger { background: rgba(229, 43, 32, 0.1); color: #ff5545; border: 1px solid rgba(229, 43, 32, 0.4); }
    .btn-danger:hover { background: #e52b20; color: #fff; }
    .btn-warning { background: rgba(234, 179, 8, 0.1); color: #fbbf24; border: 1px solid rgba(234, 179, 8, 0.4); }
    .btn-warning:hover { background: #eab308; color: #000; }
    .btn-sm { padding: 3px 7px; font-size: 10px; border-radius: 3px; }

    /* Table */
    .table-wrap { overflow-x: auto; max-height: 620px; position: relative; border: 1px solid var(--border); border-radius: 4px; }
    table { width: 100%; border-collapse: collapse; font-size: 11px; text-align: left; }
    th { background: #050505; padding: 9px 12px; color: var(--fg-muted); font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; position: sticky; top: 0; z-index: 10; border-bottom: 1px solid var(--border); }
    td { padding: 9px 12px; border-bottom: 1px solid #141414; }
    tr:hover td { background: var(--surface-hover); }

    /* Badges */
    .badge { padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 700; font-family: var(--mono); display: inline-block; letter-spacing: 0.04em; }
    .badge-2xx { border: 1px solid rgba(34, 197, 94, 0.6); color: #22c55e; background: rgba(34, 197, 94, 0.08); }
    .badge-3xx { border: 1px solid rgba(56, 189, 248, 0.6); color: #38bdf8; background: rgba(56, 189, 248, 0.08); }
    .badge-4xx { border: 1px solid rgba(234, 179, 8, 0.6); color: #fbbf24; background: rgba(234, 179, 8, 0.08); }
    .badge-5xx { border: 1px solid rgba(229, 43, 32, 0.6); color: #ff5545; background: rgba(229, 43, 32, 0.08); }
    .badge-neutral { border: 1px solid var(--border-bright); color: var(--fg-muted); background: #0a0a0a; }

    .method-get { color: #38bdf8; font-weight: 700; }
    .method-post { color: #e52b20; font-weight: 700; }
    .method-del { color: #ff5545; font-weight: 700; }

    .country-tag { border: 1px solid #222; padding: 1px 4px; border-radius: 3px; font-size: 9px; color: var(--fg-muted); margin-left: 4px; }
    .url-cell { max-width: 440px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #ddd; }

    /* Modal */
    .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.85); backdrop-filter: blur(2px); display: none; align-items: center; justify-content: center; z-index: 100; }
    .modal { background: #0a0a0a; border: 1px solid var(--border-bright); border-radius: 6px; padding: 20px; width: 100%; max-width: 520px; box-shadow: 0 10px 40px rgba(0,0,0,0.9); }
    .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; }
    .modal-close { background: none; border: 1px solid var(--border-bright); color: var(--fg-muted); padding: 2px 7px; border-radius: 3px; font-size: 11px; cursor: pointer; font-family: var(--mono); }
    .modal-close:hover { color: #fff; border-color: #fff; }
    .form-group { display: flex; flex-direction: column; gap: 5px; margin-bottom: 12px; }
    .form-label { font-size: 10px; font-weight: 700; color: var(--fg-muted); text-transform: uppercase; letter-spacing: 0.05em; }

    /* Progress bar */
    .progress-track { width: 100%; height: 8px; background: #121212; border-radius: 3px; overflow: hidden; border: 1px solid var(--border); margin: 8px 0; }
    .progress-fill { height: 100%; background: #ffffff; transition: width 0.3s ease; }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <span class="brand-title" style="display:inline-flex; align-items:center; gap:6px;">NULLBEAT <span class="lite-pill">LITE</span></span>
      <span class="brand-sub">// CONTROL PLANE</span>
    </div>
    <div class="nav-stats">
      <div class="stat-pill">
        <div id="liveIndicator" class="live-dot"></div>
        <span id="liveStatusText">LIVE STREAMING</span>
      </div>
      <div class="stat-pill">
        <span>DATABASE:</span>
        <b id="topDbSize">-- MB</b>
      </div>
      <button class="btn btn-secondary btn-sm" onclick="logout()">[LOGOUT]</button>
    </div>
  </header>

  <div class="container">
    <!-- Tabs -->
    <div class="tabs">
      <button class="tab-btn active" onclick="switchTab('traces')">[TRACES]</button>
      <button class="tab-btn" onclick="switchTab('metrics')">[TELEMETRY]</button>
      <button class="tab-btn" onclick="switchTab('security')">[FIREWALL]</button>
      <button class="tab-btn" onclick="switchTab('storage')">[STORAGE]</button>
      <button class="tab-btn" onclick="switchTab('env')">[ENV CONFIG]</button>
    </div>

    <!-- TAB 1: LIVE TRACES -->
    <div id="tab-traces" class="tab-pane active">
      <div class="card">
        <div class="card-header">
          <div class="card-title">REALTIME TRACE STREAM</div>
          <div style="display: flex; gap: 6px;">
            <button id="pauseBtn" class="btn btn-secondary btn-sm" onclick="togglePause()">[PAUSE]</button>
            <button class="btn btn-secondary btn-sm" onclick="clearTable()">[CLEAR VIEW]</button>
            <button class="btn btn-secondary btn-sm" onclick="loadHistory()">[LOAD PAST 100]</button>
          </div>
        </div>

        <div class="filter-bar">
          <input type="text" id="traceSearch" class="input" style="flex: 1; min-width: 200px;" placeholder="FILTER IP, URL, ROUTE..." oninput="applyFilters()" />
          <select id="traceEventFilter" class="input" onchange="applyFilters()">
            <option value="">ALL EVENT TYPES</option>
            <option value="search">SEARCHES</option>
            <option value="stream_direct">STREAMS (DIRECT)</option>
            <option value="stream_forwarded">STREAMS (HEAD SERVER)</option>
          </select>
          <select id="traceStatusFilter" class="input" onchange="applyFilters()">
            <option value="">ALL STATUS CODES</option>
            <option value="2xx">2xx SUCCESS</option>
            <option value="4xx">4xx CLIENT ERRORS</option>
            <option value="5xx">5xx SERVER ERRORS</option>
          </select>
          <select id="traceMethodFilter" class="input" onchange="applyFilters()">
            <option value="">ALL METHODS</option>
            <option value="GET">GET</option>
            <option value="POST">POST</option>
            <option value="DELETE">DELETE</option>
          </select>
          <label style="font-size: 11px; color: var(--fg-muted); display: flex; align-items: center; gap: 6px; cursor: pointer;">
            <input type="checkbox" id="autoscrollCheck" checked /> AUTO-SCROLL
          </label>
        </div>

        <div class="table-wrap">
          <table id="tracesTable">
            <thead>
              <tr>
                <th>TIME</th>
                <th>EVENT</th>
                <th>METHOD</th>
                <th>STATUS</th>
                <th>LATENCY</th>
                <th>CLIENT IP</th>
                <th>COUNTRY</th>
                <th>REQUEST URL</th>
                <th>RAY ID</th>
                <th>ACTIONS</th>
              </tr>
            </thead>
            <tbody id="tracesBody">
              <!-- Dynamically populated -->
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- TAB 2: METRICS & ANALYTICS -->
    <div id="tab-metrics" class="tab-pane">
      <div class="grid-4">
        <div class="metric-card">
          <div class="metric-label">TOTAL REQUESTS (TODAY)</div>
          <div class="metric-val" id="metricTotal">--</div>
          <div class="metric-sub">Processed through VPS server</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">AVG RESPONSE TIME</div>
          <div class="metric-val" id="metricLatency">-- ms</div>
          <div class="metric-sub">End-to-end execution</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">ERROR RATE</div>
          <div class="metric-val" id="metricErrorRate">--%</div>
          <div class="metric-sub">4xx / 5xx HTTP responses</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">ACTIVE FIREWALL RULES</div>
          <div class="metric-val" id="metricIpRules">--</div>
          <div class="metric-sub">Banned or rate-limited</div>
        </div>
      </div>

      <!-- Music Streaming & Search Telemetry -->
      <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; margin-top: 14px; margin-bottom: 14px;">
        <div class="metric-card">
          <div class="metric-label">TOTAL SEARCHES</div>
          <div class="metric-val" id="metricSearches">--</div>
          <div class="metric-sub" id="metricSearchesSub">TODAY: -- | ALL-TIME: --</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">TOTAL STREAMS (DIRECT)</div>
          <div class="metric-val" id="metricStreamsDirect">--</div>
          <div class="metric-sub" id="metricStreamsDirectSub">TODAY: -- | ALL-TIME: -- (TORBOX CACHE BYPASS)</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">TOTAL STREAMS (FORWARDED TO HEAD SERVER)</div>
          <div class="metric-val" id="metricStreamsForwarded">--</div>
          <div class="metric-sub" id="metricStreamsForwardedSub">TODAY: -- | ALL-TIME: -- (FORWARDED TO HEAD SERVER)</div>
        </div>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px;">
        <div class="card">
          <div class="card-title" style="margin-bottom: 12px;">TOP ENDPOINTS BY VOLUME</div>
          <table>
            <thead><tr><th>ROUTE</th><th>CALLS</th><th>AVG LATENCY</th></tr></thead>
            <tbody id="topRoutesBody"></tbody>
          </table>
        </div>
        <div class="card">
          <div class="card-title" style="margin-bottom: 12px;">MOST ACTIVE CLIENT IPS (TODAY)</div>
          <table>
            <thead><tr><th>CLIENT IP</th><th>COUNTRY</th><th>REQUESTS</th><th>ACTION</th></tr></thead>
            <tbody id="topIpsBody"></tbody>
          </table>
        </div>
      </div>

      <!-- 30-Day Essential Historical Aggregates -->
      <div class="card">
        <div class="card-header">
          <div class="card-title">30-DAY ESSENTIAL DAILY HISTORY</div>
          <span class="badge badge-neutral">
            TRACES: 1-DAY (10K MAX) | SUMMARY: 30-DAYS
          </span>
        </div>
        <table>
          <thead>
            <tr>
              <th>DATE</th>
              <th>REQUESTS</th>
              <th>SEARCHES</th>
              <th>STREAMS (DIRECT)</th>
              <th>STREAMS (HEAD SERVER)</th>
              <th>ERRORS</th>
              <th>AVG LATENCY</th>
              <th>TOP ENDPOINTS BREAKDOWN</th>
              <th>TOP CLIENT IPS</th>
            </tr>
          </thead>
          <tbody id="dailyMetricsBody">
            <!-- Populated dynamically -->
          </tbody>
        </table>
      </div>
    </div>

    <!-- TAB 3: IP FIREWALL & RULES -->
    <div id="tab-security" class="tab-pane">
      <div class="card">
        <div class="card-title" style="margin-bottom: 14px;">ADD IP FIREWALL RULE</div>
        <div style="display: grid; grid-template-columns: 1.5fr 1fr 1fr 2fr auto; gap: 10px; align-items: flex-end;">
          <div class="form-group" style="margin: 0;">
            <label class="form-label">CLIENT IP</label>
            <input type="text" id="ruleIpInput" class="input" placeholder="e.g. 192.168.1.50" />
          </div>
          <div class="form-group" style="margin: 0;">
            <label class="form-label">ACTION</label>
            <select id="ruleActionSelect" class="input" onchange="toggleRpmField()">
              <option value="BAN">BAN (403)</option>
              <option value="RATE_LIMIT">RATE LIMIT (429)</option>
            </select>
          </div>
          <div class="form-group" style="margin: 0;" id="rpmGroup">
            <label class="form-label">LIMIT (RPM)</label>
            <input type="number" id="ruleRpmInput" class="input" value="60" min="1" max="10000" disabled />
          </div>
          <div class="form-group" style="margin: 0;">
            <label class="form-label">REASON / NOTES</label>
            <input type="text" id="ruleReasonInput" class="input" placeholder="e.g. Abusive scraper" />
          </div>
          <button class="btn" onclick="submitRule()">[ENFORCE RULE]</button>
        </div>
      </div>

      <div class="card">
        <div class="card-title" style="margin-bottom: 14px;">ACTIVE IP FIREWALL RULES</div>
        <table>
          <thead>
            <tr>
              <th>IP ADDRESS</th>
              <th>ACTION</th>
              <th>RATE LIMIT</th>
              <th>REASON</th>
              <th>LAST UPDATED</th>
              <th>MANAGE</th>
            </tr>
          </thead>
          <tbody id="rulesTableBody">
            <!-- Populated dynamically -->
          </tbody>
        </table>
      </div>

      <!-- API KEY BANS -->
      <div class="card">
        <div class="card-header">
          <div class="card-title">API KEY BANS</div>
          <button class="btn btn-secondary btn-sm" onclick="refreshBans()">[REFRESH]</button>
        </div>
        <div class="filter-bar">
          <input type="text" id="banAddKey" class="input" style="width: 260px;" placeholder="API Key (UUID)" />
          <select id="banTier" class="input" style="width: 130px;">
            <option value="BAN">BAN (403)</option>
            <option value="TROLL">TROLL BAN</option>
          </select>
          <input type="text" id="banReason" class="input" style="flex:1;" placeholder="Reason (optional)" />
          <button class="btn btn-danger" onclick="applyBan()">[APPLY BAN]</button>
        </div>
        <div style="background: rgba(124,58,237,0.08); border: 1px solid rgba(124,58,237,0.3); border-radius: 4px; padding: 8px 14px; margin-top: 8px; font-size: 11px; color: #c4b5fd; line-height: 1.6;">
          <strong>BAN</strong> — all requests return 403.&nbsp;|
          <strong>TROLL</strong> — search → &ldquo;Never Gonna Give You Up&rdquo;, album → rickroll album, artist → Rick Astley, stream → NGGU torrent (created once in user&rsquo;s TorBox account).
        </div>
        <div class="table-wrap" style="max-height: 400px; margin-top: 10px;">
          <table>
            <thead><tr><th>API KEY</th><th>TIER</th><th>REASON</th><th>TROLL TORRENT ID</th><th>BANNED AT</th><th>ACTIONS</th></tr></thead>
            <tbody id="bansBody">
              <tr><td colspan="6" style="text-align:center;color:var(--fg-muted);padding:20px;">NO BANS ACTIVE</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- TAB 4: STORAGE & CACHE -->
    <div id="tab-storage" class="tab-pane">
      <div class="card">
        <div class="card-title" style="margin-bottom: 12px;">SQLITE DATABASE & CACHE LIMIT</div>
        <div style="display: flex; justify-content: space-between; font-size: 11px; margin-bottom: 4px;">
          <span>SEARCH CACHE DISK USAGE: <b id="meterSearchUsage">-- MB</b> / 1,024 MB (1 GB LIMIT)</span>
          <span id="meterSearchPercent">--%</span>
        </div>
        <div class="progress-track">
          <div id="meterProgressFill" class="progress-fill" style="width: 0%;"></div>
        </div>
        <div style="font-size: 10px; color: var(--fg-muted); margin-top: 6px; text-transform: uppercase;">
          STRICT 1GB LRU: OLDEST ACCESSED ENTRIES PURGED AT 1GB. ENTRIES EXCEEDING 7 DAYS ARE DISCARDED.
        </div>
      </div>

      <!-- Track Purge & Inspector Card -->
      <div class="card">
        <div class="card-header">
          <div class="card-title">TRACK CACHE & METADATA PURGE</div>
          <span class="badge badge-neutral">BY TRACK ID</span>
        </div>
        <div style="font-size: 11px; color: var(--fg-muted); margin-bottom: 12px; line-height: 1.5;">
          Search for any Track ID (e.g. <code style="color:#fff;">454253954</code>) to inspect and clear cached TorBox hashes, quality mappings, and Tidal metadata from SQLite.
        </div>
        <div style="display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin-bottom: 12px;">
          <input type="text" id="trackSearchId" class="input" style="width: 260px;" placeholder="ENTER TRACK ID (e.g. 454253954)" onkeydown="if(event.key==='Enter') searchTrackInfo()" />
          <button class="btn btn-secondary" onclick="searchTrackInfo()">[SEARCH / INSPECT]</button>
          <button class="btn btn-danger" id="trackClearBtn" onclick="clearTrackInfo()" style="display: none;">[PURGE ALL TRACK INFO]</button>
          <span id="trackSearchStatus" style="font-size: 11px; color: var(--fg-muted);"></span>
        </div>
        <div id="trackInfoResult" style="display: none; background: #0a0a0a; border: 1px solid var(--border-bright); border-radius: 4px; padding: 14px;">
          <!-- Dynamically populated -->
        </div>
      </div>

      <div class="card">
        <div class="card-title" style="margin-bottom: 12px;">DATABASE TABLE BREAKDOWN</div>
        <table>
          <thead><tr><th>TABLE</th><th>TOTAL RECORDS</th><th>DETAILS</th></tr></thead>
          <tbody id="dbTablesBody">
            <!-- Populated dynamically -->
          </tbody>
        </table>
      </div>

      <div class="card">
        <div class="card-title" style="margin-bottom: 12px;">MAINTENANCE & PURGE ACTIONS</div>
        <div style="display: flex; gap: 8px; flex-wrap: wrap;">
          <button class="btn btn-secondary" onclick="actionCleanExpired()">[CLEAN EXPIRED ENTRIES]</button>
          <button class="btn btn-secondary" onclick="actionRollupNow()">[ENFORCE 1D / 30D LIMITS]</button>
          <button class="btn btn-danger" onclick="actionClearSearchCache()">[PURGE SEARCH CACHE]</button>
          <button class="btn btn-secondary" onclick="actionClearTraces()">[PURGE ALL TRACES]</button>
          <button class="btn btn-secondary" onclick="actionVacuum()">[VACUUM DATABASE]</button>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <div class="card-title">KV STORE EDITOR (JSON)</div>
          <button class="btn btn-secondary btn-sm" onclick="refreshKvStore()">[RELOAD]</button>
        </div>
        <div class="table-wrap" style="max-height: 400px; margin-bottom: 14px;">
          <table>
            <thead><tr><th style="width: 200px;">KEY</th><th>VALUE PREVIEW</th><th style="width: 140px; text-align: right;">ACTIONS</th></tr></thead>
            <tbody id="kvStoreBody">
              <!-- Populated dynamically -->
            </tbody>
          </table>
        </div>
        <div style="display: flex; gap: 8px;">
          <input type="text" id="newKvKey" class="input" placeholder="NEW KEY" style="width: 200px;" />
          <button class="btn" onclick="openKvEditModal()">[CREATE / EDIT KEY]</button>
        </div>
      </div>
    </div>

    <!-- TAB 5: ENVIRONMENT CONFIGURATION -->
    <div id="tab-env" class="tab-pane">
      <div class="card">
        <div class="card-header">
          <div class="card-title">ENVIRONMENT CONFIGURATION (.ENV)</div>
          <div style="display: flex; gap: 6px;">
            <button class="btn btn-secondary btn-sm" onclick="refreshEnv()">[RELOAD]</button>
            <button id="toggleRawBtn" class="btn btn-secondary btn-sm" onclick="toggleRawEditor()">[RAW .ENV EDITOR]</button>
            <button class="btn btn-sm" onclick="saveAllEnv()">[SAVE ALL CHANGES]</button>
          </div>
        </div>

        <div style="background: #050505; border: 1px solid var(--border-bright); border-radius: 4px; padding: 10px 14px; font-size: 11px; color: var(--fg-muted); margin-bottom: 14px; line-height: 1.6;">
          <span style="color: #fff; font-weight: 700;">LIVE SYNCHRONIZATION:</span> Changes saved here are persisted to <code style="color: #fff;">.env</code> (auto-backed up to <code style="color: #fff;">.env.bak</code>) and dynamically synced to <code style="color: #fff;">process.env</code> in memory.<br>
          <span style="color: var(--fg-dim);">Note: Changing network ports (<code style="color: var(--fg-muted);">PORT</code>, <code style="color: var(--fg-muted);">ADMIN_PORT</code>) updates the file, but requires restarting the server process to re-bind listeners.</span>
        </div>

        <!-- Core Lite Settings Card -->
        <div class="card" style="margin-bottom: 14px; background: #050505; border: 1px solid var(--border-bright);">
          <div class="card-header" style="margin-bottom: 12px;">
            <div class="card-title" style="color: var(--accent);">CORE NULLBEAT LITE CONFIGURATION</div>
            <button class="btn btn-sm" onclick="saveCoreSettings()">[UPDATE CORE SETTINGS]</button>
          </div>
          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 14px;">
            <div>
              <label class="form-label" style="font-size: 10px; color: var(--fg-muted); font-weight: 700; text-transform: uppercase; margin-bottom: 6px; display: block;">
                HEAD SERVER URL (DEFAULT: nullbeat.thevolecitor.qzz.io)
              </label>
              <input type="text" id="coreHeadUrl" class="input" style="width: 100%; font-family: var(--mono);" placeholder="https://nullbeat.thevolecitor.qzz.io" />
              <div style="font-size: 10px; color: var(--fg-dim); margin-top: 4px;">Uncached stream queries are transferred to this upstream server.</div>
            </div>
            <div>
              <label class="form-label" style="font-size: 10px; color: var(--fg-muted); font-weight: 700; text-transform: uppercase; margin-bottom: 6px; display: block;">
                TIDAL CLIENT ID
              </label>
              <input type="text" id="coreTidalClientId" class="input" style="width: 100%; font-family: var(--mono);" placeholder="Tidal OpenAPI Client ID" />
              <div style="font-size: 10px; color: var(--fg-dim); margin-top: 4px;">Free from <a href="https://developer.tidal.com/" target="_blank" rel="noopener noreferrer" style="color: var(--accent); text-decoration: none;">developer.tidal.com ↗</a></div>
            </div>
            <div>
              <label class="form-label" style="font-size: 10px; color: var(--fg-muted); font-weight: 700; text-transform: uppercase; margin-bottom: 6px; display: block;">
                TIDAL CLIENT SECRET
              </label>
              <input type="password" id="coreTidalClientSecret" class="input" style="width: 100%; font-family: var(--mono);" placeholder="Leave empty to keep unchanged" />
              <div style="font-size: 10px; color: var(--fg-dim); margin-top: 4px;" id="coreSecretStatus">Secret status: checking...</div>
            </div>
          </div>
          <div id="coreSettingsAlert" style="margin-top: 10px; font-size: 11px; display: none;"></div>
        </div>

        <!-- Structured Form View -->
        <div id="envTableView">
          <div class="filter-bar" style="margin-bottom: 12px; justify-content: space-between;">
            <input type="text" id="envSearch" class="input" style="flex: 1; max-width: 340px;" placeholder="FILTER VARIABLE KEYS..." oninput="filterEnvTable()" />
            <div style="display: flex; gap: 6px;">
              <button class="btn btn-secondary btn-sm" onclick="showAddEnvModal()">[+ ADD VARIABLE]</button>
            </div>
          </div>

          <div class="table-wrap" style="max-height: 540px;">
            <table>
              <thead>
                <tr>
                  <th style="width: 260px;">VARIABLE KEY</th>
                  <th>CONFIGURED VALUE</th>
                  <th style="width: 170px; text-align: right;">ACTIONS</th>
                </tr>
              </thead>
              <tbody id="envTableBody">
                <!-- Populated dynamically -->
              </tbody>
            </table>
          </div>
        </div>

        <!-- Raw Editor View (Toggleable) -->
        <div id="envRawView" style="display: none; flex-direction: column; gap: 10px;">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <span style="font-size: 10px; color: var(--fg-muted); font-weight: 700; text-transform: uppercase;">DIRECT .ENV FILE EDITOR (PRESERVES ALL COMMENTS & FORMATTING)</span>
            <button class="btn btn-secondary btn-sm" onclick="toggleRawEditor()">[RETURN TO FORM VIEW]</button>
          </div>
          <textarea id="envRawTextarea" spellcheck="false" style="width: 100%; height: 420px; background: #000; border: 1px solid var(--border-bright); color: #fff; font-family: var(--mono); font-size: 11px; padding: 12px; border-radius: 4px; resize: vertical; line-height: 1.5; outline: none;"></textarea>
          <div style="display: flex; justify-content: flex-end; gap: 8px;">
            <button class="btn btn-secondary" onclick="toggleRawEditor()">[CANCEL]</button>
            <button class="btn" onclick="saveRawEnv()">[SAVE RAW .ENV]</button>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Detail Modal -->
  <div id="detailModal" class="modal-overlay" onclick="closeModal(event)">
    <div class="modal" style="max-width: 680px;" onclick="event.stopPropagation()">
      <div class="modal-header">
        <span id="detailModalTitle">TRACE / LOG DETAILS</span>
        <button class="modal-close" onclick="closeModal()">[CLOSE]</button>
      </div>
      <pre id="modalJson" style="background: #000000; border: 1px solid var(--border); padding: 12px; border-radius: 4px; font-size: 11px; font-family: var(--mono); overflow-x: auto; color: #ddd; max-height: 480px;"></pre>
    </div>
  </div>

  <!-- Add Env Modal -->
  <div id="addEnvModal" class="modal-overlay" onclick="closeAddEnvModal(event)">
    <div class="modal" style="max-width: 520px;" onclick="event.stopPropagation()">
      <div class="modal-header">
        <span>ADD ENVIRONMENT VARIABLE</span>
        <button class="modal-close" onclick="closeAddEnvModal()">[CLOSE]</button>
      </div>
      <div style="display: flex; flex-direction: column; gap: 12px; margin-top: 8px;">
        <div class="form-group" style="margin: 0;">
          <label class="form-label">VARIABLE NAME (KEY)</label>
          <input type="text" id="newEnvKey" class="input" style="width: 100%; text-transform: uppercase;" placeholder="e.g. HIFI_BACKENDS" />
        </div>
        <div class="form-group" style="margin: 0;">
          <label class="form-label">VALUE</label>
          <input type="text" id="newEnvVal" class="input" style="width: 100%;" placeholder="Variable value..." />
        </div>
        <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 8px;">
          <button class="btn btn-secondary btn-sm" onclick="closeAddEnvModal()">[CANCEL]</button>
          <button class="btn btn-sm" onclick="submitNewEnvVar()">[SAVE VARIABLE]</button>
        </div>
      </div>
    </div>
  </div>

  <!-- KV Edit Modal -->
  <div id="kvEditModal" class="modal-overlay" onclick="closeKvEditModal(event)">
    <div class="modal" style="max-width: 600px;" onclick="event.stopPropagation()">
      <div class="modal-header">
        <span>EDIT KV STORE ENTRY</span>
        <button class="modal-close" onclick="closeKvEditModal()">[CLOSE]</button>
      </div>
      <div style="display: flex; flex-direction: column; gap: 12px; margin-top: 8px;">
        <div class="form-group" style="margin: 0;">
          <label class="form-label">KEY</label>
          <input type="text" id="kvEditKey" class="input" style="width: 100%; font-weight: 700;" readonly />
        </div>
        <div class="form-group" style="margin: 0;">
          <label class="form-label">VALUE (JSON / STRING)</label>
          <textarea id="kvEditVal" class="input" style="width: 100%; height: 220px; font-family: var(--mono); font-size: 11px; line-height: 1.4; resize: vertical;"></textarea>
        </div>
        <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 8px;">
          <button class="btn btn-secondary btn-sm" onclick="closeKvEditModal()">[CANCEL]</button>
          <button class="btn btn-sm" onclick="saveKvEntry()">[SAVE ENTRY]</button>
        </div>
      </div>
    </div>
  </div>

  <script>
    let isPaused = false;
    let traceRows = [];
    const knownTraceIds = new Set();
    const MAX_ROWS = 200;

    let currentEnvVars = [];
    let isRawMode = false;

    
    function escapeHtml(str) {
      if (str == null) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    // Tab Switching
    function switchTab(tab) {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      if (window.event && window.event.target && window.event.target.classList) {
        window.event.target.classList.add('active');
      } else {
        const btn = Array.from(document.querySelectorAll('.tab-btn')).find(b => b.getAttribute('onclick')?.includes("'" + tab + "'"));
        if (btn) btn.classList.add('active');
      }
      const targetPane = document.getElementById('tab-' + tab);
      if (targetPane) targetPane.classList.add('active');

      if (tab === 'traces') loadHistory(false);
      if (tab === 'metrics') refreshMetrics();
      if (tab === 'security') {
        refreshRules();
        refreshBans();
      }
      if (tab === 'storage') refreshStorage();
      if (tab === 'env') refreshEnv();
    }

    // ── Environment Variables Tab Logic ──────────────────────────────────────────

    function refreshEnv() {
      fetch('/api/setup/status').then(r => r.json()).then(s => {
        const headInput = document.getElementById('coreHeadUrl');
        const cidInput = document.getElementById('coreTidalClientId');
        const secStatus = document.getElementById('coreSecretStatus');
        if (headInput) headInput.value = s.headServerUrl || 'https://nullbeat.thevolecitor.qzz.io';
        if (cidInput) cidInput.value = s.tidalClientId || '';
        if (secStatus) {
          secStatus.textContent = s.hasTidalSecret ? '✓ Tidal secret is configured in .env' : 'No Tidal secret set';
          secStatus.style.color = s.hasTidalSecret ? '#22c55e' : 'var(--fg-dim)';
        }
      }).catch(() => {});

      fetch('/api/env').then(r => r.json()).then(d => {
        if (!d.success) return console.warn('Failed to load env:', d.error);
        currentEnvVars = d.variables || [];
        const rawEl = document.getElementById('envRawTextarea');
        if (rawEl) rawEl.value = d.raw || '';
        renderEnvTable(currentEnvVars);
      }).catch(err => {
        console.error('Failed to fetch env:', err);
      });
    }

    function renderEnvTable(vars) {
      const tbody = document.getElementById('envTableBody');
      if (!tbody) return;
      if (!vars || vars.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3" style="color: var(--fg-muted); text-align: center; padding: 20px;">NO ENVIRONMENT VARIABLES CONFIGURED</td></tr>';
        return;
      }

      const SYSTEM_KEYS = [
        'PORT', 'ADMIN_PORT', 'ADMIN_SECRET', 'HEAD_SERVER_URL',
        'TIDAL_CLIENT_ID', 'TIDAL_CLIENT_SECRET', 'SEARCH_CACHE_TTL',
        'MAX_USERS', 'MAX_INVITE_POOL', 'INVITE_SECRET', 'ALLOWED_KEYS'
      ];

      tbody.innerHTML = vars.map(v => {
        const isSys = SYSTEM_KEYS.includes(v.key);
        const inputType = v.isSecret ? 'password' : 'text';
        const showBtn = v.isSecret
          ? '<button type="button" class="btn btn-secondary btn-sm" style="padding: 4px 8px;" onclick="toggleSecretVisibility(this)" title="Show/Hide value">[SHOW]</button>'
          : '';

        const badge = isSys
          ? '<span class="badge badge-neutral" style="font-size: 8px; margin-left: 6px;">[SYSTEM]</span>'
          : '<span class="badge badge-3xx" style="font-size: 8px; margin-left: 6px;">[CUSTOM]</span>';

        const deleteBtn = !isSys
          ? '<button type="button" class="btn btn-danger btn-sm" onclick="deleteEnvVar(this.dataset.key)" data-key="' + escapeHtml(v.key) + '">[DEL]</button>'
          : '';

        return '<tr class="env-row" data-key="' + escapeHtml(v.key.toLowerCase()) + '">' +
          '<td style="vertical-align: middle;">' +
            '<span style="font-weight: 700; color: #fff; letter-spacing: 0.04em;">' + escapeHtml(v.key) + '</span>' +
            badge +
          '</td>' +
          '<td style="vertical-align: middle;">' +
            '<div style="display: flex; gap: 6px; align-items: center;">' +
              '<input type="' + inputType + '" id="env_val_' + escapeHtml(v.key) + '" class="input" style="width: 100%; font-family: var(--mono);" value="' + escapeHtml(v.value) + '" data-orig="' + escapeHtml(v.value) + '" />' +
              showBtn +
            '</div>' +
          '</td>' +
          '<td style="text-align: right; vertical-align: middle; white-space: nowrap;">' +
            '<div style="display: inline-flex; gap: 4px;">' +
              '<button type="button" class="btn btn-sm" onclick="saveSingleEnv(this.dataset.key)" data-key="' + escapeHtml(v.key) + '">[APPLY]</button>' +
              deleteBtn +
            '</div>' +
          '</td>' +
        '</tr>';
      }).join('');
    }

    function toggleSecretVisibility(btn) {
      const input = btn.previousElementSibling;
      if (input.type === 'password') {
        input.type = 'text';
        btn.textContent = '[HIDE]';
      } else {
        input.type = 'password';
        btn.textContent = '[SHOW]';
      }
    }

    function filterEnvTable() {
      const q = (document.getElementById('envSearch')?.value || '').toLowerCase().trim();
      document.querySelectorAll('.env-row').forEach(row => {
        const k = row.dataset.key || '';
        row.style.display = !q || k.includes(q) ? '' : 'none';
      });
    }

    function showAddEnvModal() {
      document.getElementById('newEnvKey').value = '';
      document.getElementById('newEnvVal').value = '';
      document.getElementById('addEnvModal').style.display = 'flex';
      setTimeout(() => document.getElementById('newEnvKey').focus(), 50);
    }

    function closeAddEnvModal(e) {
      document.getElementById('addEnvModal').style.display = 'none';
    }

    function submitNewEnvVar() {
      const key = (document.getElementById('newEnvKey').value || '').trim().toUpperCase();
      const value = (document.getElementById('newEnvVal').value || '').trim();
      if (!key) return alert('Variable key is required');

      fetch('/api/env', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ updates: { [key]: value } })
      }).then(r => r.json()).then(d => {
        if (!d.success) return alert(d.error || 'Failed to save variable');
        closeAddEnvModal();
        refreshEnv();
      }).catch(err => alert('Error: ' + err.message));
    }

    function saveSingleEnv(key) {
      const input = document.getElementById('env_val_' + key);
      if (!input) return;
      const value = input.value.trim();

      fetch('/api/env', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ updates: { [key]: value } })
      }).then(r => r.json()).then(d => {
        if (!d.success) return alert(d.error || 'Failed to save variable');
        input.dataset.orig = value;
        alert('Saved ' + key + '=' + value);
        refreshEnv();
      }).catch(err => alert('Error: ' + err.message));
    }

    function deleteEnvVar(key) {
      if (!confirm('Are you sure you want to delete environment variable "' + key + '"?')) return;
      fetch('/api/env', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ deletes: [key] })
      }).then(r => r.json()).then(d => {
        if (!d.success) return alert(d.error || 'Failed to delete variable');
        refreshEnv();
      }).catch(err => alert('Error: ' + err.message));
    }

    function saveAllEnv() {
      const updates = {};
      document.querySelectorAll('.env-row input[id^="env_val_"]').forEach(input => {
        updates[input.id.replace('env_val_', '')] = input.value.trim();
      });

      fetch('/api/env', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ updates })
      }).then(r => r.json()).then(d => {
        if (!d.success) return alert(d.error || 'Failed to save environment variables');
        alert('All environment variables saved to .env & synced to process.env');
        refreshEnv();
      }).catch(err => alert('Error: ' + err.message));
    }

    function toggleRawEditor() {
      isRawMode = !isRawMode;
      document.getElementById('envTableView').style.display = isRawMode ? 'none' : 'block';
      document.getElementById('envRawView').style.display = isRawMode ? 'flex' : 'none';
      document.getElementById('toggleRawBtn').textContent = isRawMode ? '[FORM VIEW]' : '[RAW .ENV EDITOR]';
    }

    function saveRawEnv() {
      const raw = document.getElementById('envRawTextarea').value;
      fetch('/api/env', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw })
      }).then(r => r.json()).then(d => {
        if (!d.success) return alert(d.error || 'Failed to save raw .env');
        alert('Raw .env saved and synced!');
        toggleRawEditor();
        refreshEnv();
      }).catch(err => alert('Error: ' + err.message));
    }

    // Toggle Pause
    function togglePause() {
      isPaused = !isPaused;
      document.getElementById('pauseBtn').textContent = isPaused ? '[RESUME]' : '[PAUSE]';
      document.getElementById('liveStatusText').textContent = isPaused ? 'PAUSED' : 'LIVE STREAMING';
      document.getElementById('liveIndicator').style.background = isPaused ? '#eab308' : '#22c55e';
      document.getElementById('liveIndicator').style.boxShadow = isPaused ? '0 0 8px #eab308' : '0 0 8px #22c55e';
    }

    // Clear Table
    function clearTable() {
      traceRows = [];
      knownTraceIds.clear();
      document.getElementById('tracesBody').innerHTML = '';
    }

    // Connect SSE
    function startSSE() {
      if (window._activeEvtSource) {
        try { window._activeEvtSource.close(); } catch (_) {}
      }
      const adminSecret = localStorage.getItem('nullbeat_admin_secret') || '';
      const sseUrl = '/api/traces/stream' + (adminSecret ? '?secret=' + encodeURIComponent(adminSecret) : '');
      const evtSource = new EventSource(sseUrl);
      window._activeEvtSource = evtSource;

      evtSource.onopen = () => {
        const st = document.getElementById('liveStatusText');
        if (st) st.textContent = 'LIVE STREAMING';
        const ind = document.getElementById('liveIndicator');
        if (ind) {
          ind.style.background = '#22c55e';
          ind.style.boxShadow = '0 0 8px #22c55e';
        }
      };

      evtSource.onmessage = (e) => {
        if (isPaused) return;
        try {
          const trace = JSON.parse(e.data);
          addTraceRow(trace);
        } catch (err) {
          console.error('[Live Trace Error]:', err, e.data);
        }
      };

      evtSource.onerror = () => {
        const st = document.getElementById('liveStatusText');
        if (st) st.textContent = 'RECONNECTING...';
        const ind = document.getElementById('liveIndicator');
        if (ind) {
          ind.style.background = '#e52b20';
          ind.style.boxShadow = '0 0 8px #e52b20';
        }
      };

      evtSource.addEventListener('connected', () => {
        const st = document.getElementById('liveStatusText');
        if (st) st.textContent = 'LIVE STREAMING';
        const ind = document.getElementById('liveIndicator');
        if (ind) {
          ind.style.background = '#22c55e';
          ind.style.boxShadow = '0 0 8px #22c55e';
        }
      });

      if (!window._tracePollTimer) {
        window._tracePollTimer = setInterval(() => {
          if (!isPaused && document.visibilityState === 'visible') {
            loadHistory(false);
          }
        }, 10000);
      }
    }

    function addTraceRow(t, prepend = true) {
      if (t.id && knownTraceIds.has(t.id)) return;
      if (t.id) knownTraceIds.add(t.id);

      if (prepend) {
        traceRows.unshift(t);
        if (traceRows.length > MAX_ROWS) {
          const popped = traceRows.pop();
          if (popped && popped.id) knownTraceIds.delete(popped.id);
        }
      } else {
        traceRows.push(t);
        if (traceRows.length > MAX_ROWS) {
          const shifted = traceRows.shift();
          if (shifted && shifted.id) knownTraceIds.delete(shifted.id);
        }
      }

      const tbody = document.getElementById('tracesBody');
      if (!tbody) return;
      const tr = document.createElement('tr');
      tr.className = 'trace-row';
      tr.dataset.ip = t.ip || '';
      tr.dataset.url = t.url || '';
      tr.dataset.status = t.status || '';
      tr.dataset.method = t.method || '';
      tr.dataset.eventType = t.eventType || '';

      const statusCls = t.status >= 500 ? 'badge-5xx' : t.status >= 400 ? 'badge-4xx' : t.status >= 300 ? 'badge-3xx' : 'badge-2xx';
      const methodCls = t.method === 'GET' ? 'method-get' : t.method === 'POST' ? 'method-post' : 'method-del';
      const durationVal = Math.round(t.durationMs != null ? t.durationMs : (t.duration_ms != null ? t.duration_ms : 0));
      const durationColor = durationVal > 1000 ? '#ff5545' : durationVal > 300 ? '#fbbf24' : '#22c55e';
      const ray = t.rayId || t.ray_id || '';

      let eventBadge = '<span style="color: var(--fg-dim); font-size: 10px;">--</span>';
      if (t.eventType === 'search') {
        eventBadge = '<span class="badge badge-neutral" style="font-size: 9px; font-weight: 700;">[SEARCH]</span>';
      } else if (t.eventType === 'stream_direct') {
        eventBadge = '<span class="badge badge-2xx" style="font-size: 9px; font-weight: 700; background: #fff; color: #000;">[DIRECT]</span>';
      } else if (t.eventType === 'stream_forwarded') {
        eventBadge = '<span class="badge badge-3xx" style="font-size: 9px; font-weight: 700;">[HEAD SERVER]</span>';
      }

      const safeIp = escapeHtml(t.ip || '');
      const safeUrl = escapeHtml(t.url || '');
      const safeMethod = escapeHtml(t.method || '');
      const safeCountry = escapeHtml(t.country || 'XX');
      const safeRay = escapeHtml(ray ? (ray.slice(0, 10) + '...') : '--');
      const safeTime = escapeHtml(t.timeFormatted || new Date(t.timestamp).toLocaleTimeString());

      tr.innerHTML = 
        '<td style="color: var(--fg-muted); font-size: 10px;">' + safeTime + '</td>' +
        '<td>' + eventBadge + '</td>' +
        '<td><span class="' + methodCls + '">' + safeMethod + '</span></td>' +
        '<td><span class="badge ' + statusCls + '">' + t.status + '</span></td>' +
        '<td style="color: ' + durationColor + '; font-weight: 700;">' + durationVal + 'ms</td>' +
        '<td><span>' + safeIp + '</span></td>' +
        '<td><span class="country-tag">' + safeCountry + '</span></td>' +
        '<td class="url-cell" title="' + safeUrl + '">' + safeUrl + '</td>' +
        '<td style="color: var(--fg-dim); font-size: 10px;">' + safeRay + '</td>' +
        '<td>' +
          '<div style="display: flex; gap: 4px;">' +
            '<button class="btn btn-danger btn-sm action-ban-btn">[BAN]</button>' +
            '<button class="btn btn-warning btn-sm action-limit-btn">[LIMIT]</button>' +
            '<button class="btn btn-secondary btn-sm trace-view-btn">[VIEW]</button>' +
          '</div>' +
        '</td>';

      tr.querySelector('.action-ban-btn').onclick = () => quickBan(t.ip);
      tr.querySelector('.action-limit-btn').onclick = () => quickLimit(t.ip);
      tr.querySelector('.trace-view-btn').onclick = () => showDetails(t);

      if (prepend) {
        tbody.insertBefore(tr, tbody.firstChild);
        if (tbody.children.length > MAX_ROWS) tbody.removeChild(tbody.lastChild);
      } else {
        tbody.appendChild(tr);
        if (tbody.children.length > MAX_ROWS) tbody.removeChild(tbody.firstChild);
      }

      const autoCheck = document.getElementById('autoscrollCheck');
      if (autoCheck && autoCheck.checked && prepend) {
        const wrap = document.querySelector('#tab-traces .table-wrap');
        if (wrap) wrap.scrollTop = 0;
      }
    }

    function applyFilters() {
      const q = (document.getElementById('traceSearch')?.value || '').toLowerCase().trim();
      const eventFilter = document.getElementById('traceEventFilter')?.value || '';
      const statusFilter = document.getElementById('traceStatusFilter')?.value || '';
      const methodFilter = document.getElementById('traceMethodFilter')?.value || '';

      document.querySelectorAll('#tracesBody tr.trace-row').forEach(row => {
        const ip = (row.dataset.ip || '').toLowerCase();
        const url = (row.dataset.url || '').toLowerCase();
        const status = parseInt(row.dataset.status || '0', 10);
        const method = row.dataset.method || '';
        const eventType = row.dataset.eventType || '';

        let match = true;
        if (q && !ip.includes(q) && !url.includes(q)) match = false;
        if (eventFilter && eventType !== eventFilter) match = false;
        if (methodFilter && method !== methodFilter) match = false;
        if (statusFilter) {
          if (statusFilter === '2xx' && (status < 200 || status >= 300)) match = false;
          if (statusFilter === '4xx' && (status < 400 || status >= 500)) match = false;
          if (statusFilter === '5xx' && status < 500) match = false;
        }

        row.style.display = match ? '' : 'none';
      });
    }

    // Modal
    function showDetails(t) {
      document.getElementById('detailModalTitle').textContent = 'TRACE / LOG DETAILS';
      document.getElementById('modalJson').textContent = JSON.stringify(t, null, 2);
      document.getElementById('detailModal').style.display = 'flex';
    }
    function closeModal(e) {
      document.getElementById('detailModal').style.display = 'none';
    }

    // Quick Ban / Limit
    function quickBan(ip) {
      if (!confirm('Immediately BAN IP ' + ip + ' from accessing NullBeat (403 Forbidden)?')) return;
      fetch('/api/security/rule', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, action: 'BAN', reason: 'Admin one-click ban' })
      }).then(r => r.json()).then(d => {
        alert('IP ' + ip + ' is now banned.');
        refreshRules();
      });
    }

    function quickLimit(ip) {
      const rpm = prompt('Enter request limit per minute for ' + ip + ':', '30');
      if (!rpm) return;
      fetch('/api/security/rule', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, action: 'RATE_LIMIT', rateLimit: parseInt(rpm, 10), reason: 'Admin one-click rate limit' })
      }).then(r => r.json()).then(d => {
        alert('IP ' + ip + ' is now rate-limited to ' + rpm + ' req/min.');
        refreshRules();
      });
    }

    function loadHistory(clear = true) {
      fetch('/api/traces/history?limit=100')
        .then(r => r.json())
        .then(data => {
          if (clear) clearTable();
          (data.traces || []).reverse().forEach(t => addTraceRow(t, true));
        })
        .catch(err => console.error('Failed to load trace history:', err));
    }

    // Metrics
    function refreshMetrics() {
      fetch('/api/metrics?mode=today').then(r => r.json()).then(d => {
        document.getElementById('metricTotal').textContent = d.total || 0;
        document.getElementById('metricLatency').textContent = (d.avgLatency || 0) + ' ms';
        document.getElementById('metricErrorRate').textContent = (d.errorRate || 0) + '%';

        const todayVal = s => s?.today ?? s?.last24h ?? 0;

        document.getElementById('metricSearches').textContent = todayVal(d.searches);
        document.getElementById('metricSearchesSub').textContent = 'TODAY: ' + todayVal(d.searches) + ' | ALL-TIME: ' + (d.searches?.allTime || 0);

        document.getElementById('metricStreamsDirect').textContent = todayVal(d.streamsDirect);
        document.getElementById('metricStreamsDirectSub').textContent = 'TODAY: ' + todayVal(d.streamsDirect) + ' | ALL-TIME: ' + (d.streamsDirect?.allTime || 0) + ' (TORBOX CACHE BYPASS)';

        document.getElementById('metricStreamsForwarded').textContent = todayVal(d.streamsForwarded);
        document.getElementById('metricStreamsForwardedSub').textContent = 'TODAY: ' + todayVal(d.streamsForwarded) + ' | ALL-TIME: ' + (d.streamsForwarded?.allTime || 0) + ' (FORWARDED TO HEAD SERVER)';

        const rb = document.getElementById('topRoutesBody');
        if (rb) {
          rb.innerHTML = (d.topRoutes || []).map(r => 
            '<tr>' +
              '<td style="color: #fff; font-weight: 700;">' + escapeHtml(r.route || '/') + '</td>' +
              '<td><b>' + (r.count || 0) + '</b></td>' +
              '<td style="color: var(--fg-muted);">' + Math.round(r.avg_lat || 0) + ' ms</td>' +
            '</tr>'
          ).join('') || '<tr><td colspan="3" style="color: var(--fg-muted);">NO DATA AVAILABLE</td></tr>';
        }

        const ib = document.getElementById('topIpsBody');
        if (ib) {
          ib.innerHTML = (d.topIps || []).map(i => 
            '<tr>' +
              '<td style="color: #fff;">' + escapeHtml(i.ip) + '</td>' +
              '<td><span class="country-tag">' + escapeHtml(i.country || 'XX') + '</span></td>' +
              '<td><b>' + (i.count || 0) + '</b></td>' +
              '<td>' +
                '<button class="btn btn-danger btn-sm" onclick="quickBan(this.dataset.ip)" data-ip="' + escapeHtml(i.ip) + '">[BAN]</button>' +
              '</td>' +
            '</tr>'
          ).join('') || '<tr><td colspan="4" style="color: var(--fg-muted);">NO DATA AVAILABLE</td></tr>';
        }
      });

      fetch('/api/security/rules').then(r => r.json()).then(d => {
        const el = document.getElementById('metricIpRules');
        if (el) el.textContent = d.rules?.length || 0;
      });

      fetch('/api/metrics/daily').then(r => r.json()).then(d => {
        const db = document.getElementById('dailyMetricsBody');
        if (!db) return;
        db.innerHTML = (d.history || []).map(day => {
          const endpointsHtml = Object.entries(day.endpointHits || {})
            .slice(0, 6)
            .map(([ep, count]) => '<span class="badge badge-3xx" style="margin: 2px;">' + escapeHtml(ep) + ' (' + count + ')</span>')
            .join('') || '<span style="color: var(--fg-muted);">--</span>';

          const ipsHtml = (day.topIps || [])
            .slice(0, 5)
            .map(ip => '<span class="badge badge-neutral" style="margin: 2px;">' + escapeHtml(ip.ip) + ' (' + ip.hits + ')</span>')
            .join('') || '<span style="color: var(--fg-muted);">--</span>';

          const statusBadge = day.isFinalized
            ? '<span class="badge badge-neutral" style="font-size: 9px; margin-left: 6px;">[ARCHIVED]</span>'
            : '<span class="badge badge-2xx" style="font-size: 9px; margin-left: 6px;">[LIVE]</span>';

          return '<tr>' +
            '<td style="font-weight: 700; color: #fff; white-space: nowrap;">' + escapeHtml(day.date) + ' ' + statusBadge + '</td>' +
            '<td><b>' + (day.totalRequests || 0) + '</b></td>' +
            '<td><b>' + (day.totalSearches || 0) + '</b></td>' +
            '<td><span style="color: #fff; font-weight: 700;">' + (day.totalStreamsDirect || 0) + '</span></td>' +
            '<td><span style="color: var(--fg-muted);">' + (day.totalStreamsForwarded || 0) + '</span></td>' +
            '<td><span style="color: ' + (day.errorCount > 0 ? '#ff5545' : 'var(--fg-muted)') + ';">' + (day.errorCount || 0) + ' (' + (day.errorRate || 0) + '%)</span></td>' +
            '<td>' + (day.avgLatencyMs || 0) + ' ms</td>' +
            '<td>' + endpointsHtml + '</td>' +
            '<td>' + ipsHtml + '</td>' +
          '</tr>';
        }).join('') || '<tr><td colspan="9" style="color: var(--fg-muted); text-align: center;">NO DAILY HISTORICAL RECORDS AVAILABLE</td></tr>';
      });
    }

    function toggleRpmField() {
      const action = document.getElementById('ruleActionSelect')?.value;
      const rpmInput = document.getElementById('ruleRpmInput');
      if (rpmInput) {
        rpmInput.disabled = action !== 'RATE_LIMIT';
      }
    }

    // Security Rules
    function refreshRules() {
      fetch('/api/security/rules').then(r => r.json()).then(d => {
        const tb = document.getElementById('rulesTableBody');
        if (!tb) return;
        tb.innerHTML = (d.rules || []).map(r => 
          '<tr>' +
            '<td style="font-weight: 700; color: #fff;">' + escapeHtml(r.ip) + '</td>' +
            '<td><span class="badge ' + (r.action === 'BAN' ? 'badge-5xx' : 'badge-4xx') + '">' + escapeHtml(r.action) + '</span></td>' +
            '<td>' + (r.action === 'RATE_LIMIT' ? r.rate_limit + ' RPM' : 'PERMANENT') + '</td>' +
            '<td style="color: var(--fg-muted);">' + escapeHtml(r.reason || '--') + '</td>' +
            '<td style="color: var(--fg-dim); font-size: 10px;">' + new Date(r.updated_at).toLocaleString() + '</td>' +
            '<td><button class="btn btn-secondary btn-sm" onclick="removeIpRule(this.dataset.ip)" data-ip="' + escapeHtml(r.ip) + '">[REMOVE]</button></td>' +
          '</tr>'
        ).join('') || '<tr><td colspan="6" style="color: var(--fg-muted);">NO ACTIVE FIREWALL RULES. ALL IPS PERMITTED.</td></tr>';
      });
    }

    function submitRule() {
      const ip = document.getElementById('ruleIpInput').value.trim();
      const action = document.getElementById('ruleActionSelect').value;
      const rateLimit = parseInt(document.getElementById('ruleRpmInput').value, 10) || 60;
      const reason = document.getElementById('ruleReasonInput').value.trim();
      if (!ip) return alert('ENTER AN IP ADDRESS');

      fetch('/api/security/rule', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, action, rateLimit, reason })
      }).then(r => r.json()).then(() => {
        document.getElementById('ruleIpInput').value = '';
        document.getElementById('ruleReasonInput').value = '';
        refreshRules();
      });
    }

    function removeIpRule(ip) {
      if (!confirm('Remove firewall rule for ' + ip + '?')) return;
      fetch('/api/security/rule', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      }).then(r => r.json()).then(() => refreshRules());
    }

    // Storage
    function refreshStorage() {
      fetch('/api/db/stats').then(r => r.json()).then(d => {
        const topDb = document.getElementById('topDbSize');
        if (topDb) topDb.textContent = d.fileSizeMb + ' MB';
        const usage = document.getElementById('meterSearchUsage');
        if (usage) { if(d.searchCache.sizeMb > 1024) { usage.textContent = (d.searchCache.sizeMb/1024).toFixed(2) + ' GB' } else { usage.textContent = d.searchCache.sizeMb + ' MB' } }
        const pct = Math.min(100, Math.round((d.searchCache.sizeBytes / (1024 * 1024 * 1024)) * 100));
        const pctEl = document.getElementById('meterSearchPercent');
        if (pctEl) pctEl.textContent = pct + '%';
        const fillEl = document.getElementById('meterProgressFill');
        if (fillEl) fillEl.style.width = Math.max(1, pct) + '%';

        const tb = document.getElementById('dbTablesBody');
        if (tb) {
          tb.innerHTML = 
            '<tr>' +
              '<td><b>search_cache</b></td>' +
              '<td>' + d.searchCache.count + ' records</td>' +
              '<td>' + d.searchCache.sizeMb + ' MB</td>' +
            '</tr>' +
            '<tr>' +
              '<td><b>track_meta</b></td>' +
              '<td>' + (d.trackMeta ? d.trackMeta.count : 0) + ' tracks</td>' +
              '<td>Instant metadata index (ISRC, covers, duration)</td>' +
            '</tr>' +
            '<tr>' +
              '<td><b>torbox_cache</b></td>' +
              '<td>' + d.torboxCache.totalEntries + ' entries (' + d.torboxCache.uniqueTracks + ' unique tracks)</td>' +
              '<td>Indexed qualities</td>' +
            '</tr>' +
            '<tr>' +
              '<td><b>trace_logs</b></td>' +
              '<td>' + d.traceLogs.count + ' traces</td>' +
              '<td>Max 10,000 lines (FIFO, 1-day limit)</td>' +
            '</tr>' +
            '<tr>' +
              '<td><b>daily_metrics</b></td>' +
              '<td>' + d.dailyMetrics.count + ' days recorded</td>' +
              '<td>Daily hits, top IPs, latency, errors</td>' +
            '</tr>' +
            '<tr>' +
              '<td><b>stats_counters</b></td>' +
              '<td>' + (d.statsCounters ? d.statsCounters.count : 3) + ' counters</td>' +
              '<td>Persistent event counters (searches, direct/forwarded streams)</td>' +
            '</tr>' +
            '<tr>' +
              '<td><b>kv_store</b></td>' +
              '<td>' + d.kvStore.count + ' keys</td>' +
              '<td>User credentials & invitations</td>' +
            '</tr>' +
            '<tr>' +
              '<td><b>ip_rules</b></td>' +
              '<td>' + d.ipRules.count + ' rules</td>' +
              '<td>Active firewall rules</td>' +
            '</tr>';
        }
      });
      refreshKvStore();
    }

    function refreshKvStore() {
      fetch('/api/kv').then(r => r.json()).then(d => {
        const tb = document.getElementById('kvStoreBody');
        if (!tb) return;
        tb.innerHTML = (d.keys || []).map(k => {
          let preview = k.value;
          if (preview.length > 80) preview = preview.slice(0, 80) + '...';
          let parsedLen = '';
          try { 
            const p = JSON.parse(k.value);
            if (Array.isArray(p)) parsedLen = ' <span class="badge badge-neutral">[' + p.length + ' ITEMS]</span>';
            else if (typeof p === 'object' && p !== null) parsedLen = ' <span class="badge badge-neutral">[' + Object.keys(p).length + ' KEYS]</span>';
          } catch(e) {}
          
          return '<tr>' +
            '<td style="font-weight: 700; color: #fff;">' + escapeHtml(k.key) + '</td>' +
            '<td style="font-family: var(--mono); font-size: 10px; color: var(--fg-muted);">' + escapeHtml(preview) + parsedLen + '</td>' +
            '<td style="text-align: right;">' +
              '<button class="btn btn-secondary btn-sm" onclick="editKvEntry(this.dataset.key)" data-key="' + escapeHtml(k.key) + '">[EDIT]</button>' +
              '<button class="btn btn-danger btn-sm" onclick="deleteKvEntry(this.dataset.key)" data-key="' + escapeHtml(k.key) + '">[DEL]</button>' +
            '</td>' +
          '</tr>';
        }).join('') || '<tr><td colspan="3" style="color: var(--fg-muted);">NO KV STORE ENTRIES.</td></tr>';
        
        window._kvData = d.keys || [];
      });
    }

    function openKvEditModal(key = null, value = '') {
      if (!key) key = document.getElementById('newKvKey').value.trim();
      if (!key) return alert('Enter a KEY name first');
      
      let initialVal = value;
      if (!initialVal && window._kvData) {
        const existing = window._kvData.find(k => k.key === key);
        if (existing) {
          try { initialVal = JSON.stringify(JSON.parse(existing.value), null, 2); }
          catch(e) { initialVal = existing.value; }
        }
      }
      
      document.getElementById('kvEditKey').value = key;
      document.getElementById('kvEditVal').value = initialVal || '[]';
      document.getElementById('kvEditModal').style.display = 'flex';
    }

    function editKvEntry(key) {
      openKvEditModal(key);
    }

    function closeKvEditModal(e) {
      document.getElementById('kvEditModal').style.display = 'none';
    }

    function saveKvEntry() {
      const key = document.getElementById('kvEditKey').value.trim();
      let val = document.getElementById('kvEditVal').value.trim();
      if (!key) return;
      
      try {
        const parsed = JSON.parse(val);
        val = JSON.stringify(parsed);
      } catch(e) {
        if (!confirm('Warning: Value is not valid JSON. Save as raw string anyway?')) return;
      }
      
      fetch('/api/kv', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key, value: val })
      }).then(r => r.json()).then(d => {
        if (!d.success) return alert(d.error || 'Failed to save');
        closeKvEditModal();
        document.getElementById('newKvKey').value = '';
        refreshKvStore();
        alert(d.message);
      }).catch(err => alert('Error: ' + err.message));
    }

    function deleteKvEntry(key) {
      if (!confirm('Are you sure you want to delete KV entry: ' + key + '?')) return;
      fetch('/api/kv', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key })
      }).then(r => r.json()).then(d => {
        if (!d.success) return alert(d.error || 'Failed to delete');
        refreshKvStore();
        alert(d.message);
      });
    }

    function actionCleanExpired() {
      fetch('/api/db/clean-expired', { method: 'POST' }).then(r => r.json()).then(d => {
        alert(d.message);
        refreshStorage();
      });
    }

    function actionRollupNow() {
      fetch('/api/db/rollup-now', { method: 'POST' }).then(r => r.json()).then(d => {
        alert(d.message);
        refreshStorage();
        refreshMetrics();
      });
    }

    function actionClearSearchCache() {
      if (!confirm('Are you sure you want to clear ALL cached search, album, artist, and playlist results?')) return;
      fetch('/api/db/clear-search-cache', { method: 'POST' }).then(r => r.json()).then(d => {
        alert(d.message);
        refreshStorage();
      });
    }

    function actionClearTraces() {
      if (!confirm('Clear all stored trace logs?')) return;
      fetch('/api/db/clear-traces', { method: 'POST' }).then(r => r.json()).then(d => {
        alert(d.message);
        refreshStorage();
      });
    }

    function actionVacuum() {
      fetch('/api/db/vacuum', { method: 'POST' }).then(r => r.json()).then(d => {
        alert(d.message);
        refreshStorage();
      });
    }

    function logout() {
      document.cookie = 'admin_secret=; path=/; max-age=0';
      localStorage.removeItem('nullbeat_admin_secret');
      window.location.href = '/logout';
    }

    // ── Core Lite Settings ──────────────────────────────────────────────────────

    function saveCoreSettings() {
      const headUrl = (document.getElementById('coreHeadUrl')?.value || '').trim();
      const clientId = (document.getElementById('coreTidalClientId')?.value || '').trim();
      const clientSecret = (document.getElementById('coreTidalClientSecret')?.value || '').trim();
      const alertEl = document.getElementById('coreSettingsAlert');

      if (alertEl) {
        alertEl.style.display = 'block';
        alertEl.style.color = 'var(--fg-muted)';
        alertEl.textContent = 'SAVING CORE SETTINGS...';
      }

      fetch('/api/setup/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          headServerUrl: headUrl,
          tidalClientId: clientId,
          tidalClientSecret: clientSecret
        })
      })
      .then(r => r.json())
      .then(d => {
        if (d.success) {
          if (alertEl) {
            alertEl.style.color = '#22c55e';
            alertEl.textContent = '✓ Core settings saved and applied to runtime!';
            setTimeout(() => { alertEl.style.display = 'none'; }, 3000);
          }
          const secInput = document.getElementById('coreTidalClientSecret');
          if (secInput) secInput.value = '';
          refreshEnv();
        } else {
          if (alertEl) {
            alertEl.style.color = '#e52b20';
            alertEl.textContent = '✗ ERROR: ' + (d.error || 'Failed to save');
          }
        }
      })
      .catch(err => {
        if (alertEl) {
          alertEl.style.color = '#e52b20';
          alertEl.textContent = '✗ NETWORK ERROR: ' + err.message;
        }
      });
    }

    // ── Bans ─────────────────────────────────────────────────────────────────
    function refreshBans() {
      const secret = localStorage.getItem('nullbeat_admin_secret') || '';
      fetch('/api/bans', { headers: { 'x-admin-secret': secret } })
        .then(r => r.json())
        .then(rows => {
          const tbody = document.getElementById('bansBody');
          if (!Array.isArray(rows) || rows.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--fg-muted);padding:20px;">NO BANS ACTIVE</td></tr>';
            return;
          }
          tbody.innerHTML = rows.map(b => {
            const tierBadge = b.tier === 'TROLL'
              ? '<span style="background:#7c3aed;color:#fff;padding:2px 7px;border-radius:3px;font-size:10px;">&#127925; TROLL</span>'
              : '<span style="background:#dc2626;color:#fff;padding:2px 7px;border-radius:3px;font-size:10px;">&#128683; BAN</span>';
            const date = new Date(b.created_at).toLocaleString();
            const trollId = b.troll_torrent_id || '<span style="color:var(--fg-muted)">—</span>';
            return '<tr>' +
              '<td style="font-family:var(--mono);font-size:11px;">' + escapeHtml(b.api_key) + '</td>' +
              '<td>' + tierBadge + '</td>' +
              '<td>' + escapeHtml(b.reason || '—') + '</td>' +
              '<td style="font-family:var(--mono);font-size:11px;">' + trollId + '</td>' +
              '<td>' + date + '</td>' +
              '<td><button class="btn btn-danger btn-sm" onclick="liftBan(this.dataset.key)" data-key="' + escapeHtml(b.api_key) + '">[LIFT]</button></td>' +
              '</tr>';
          }).join('');
        })
        .catch(err => alert('Error loading bans: ' + err.message));
    }

    function applyBan() {
      const apiKey = document.getElementById('banAddKey').value.trim();
      const tier = document.getElementById('banTier').value;
      const reason = document.getElementById('banReason').value.trim();
      if (!apiKey) return alert('Enter an API key');
      const secret = localStorage.getItem('nullbeat_admin_secret') || '';
      fetch('/api/bans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-admin-secret': secret },
        body: JSON.stringify({ apiKey, tier, reason })
      })
      .then(r => r.json())
      .then(d => {
        if (d.error) return alert('Error: ' + d.error);
        document.getElementById('banAddKey').value = '';
        document.getElementById('banReason').value = '';
        refreshBans();
      })
      .catch(err => alert('Error: ' + err.message));
    }

    function liftBan(apiKey) {
      if (!confirm('Lift ban for ' + apiKey + '?')) return;
      const secret = localStorage.getItem('nullbeat_admin_secret') || '';
      fetch('/api/bans', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json', 'x-admin-secret': secret },
        body: JSON.stringify({ apiKey })
      })
      .then(r => r.json())
      .then(d => {
        if (d.error) return alert('Error: ' + d.error);
        refreshBans();
      })
      .catch(err => alert('Error: ' + err.message));
    }

    // ── Track Search & Purge ──────────────────────────────────────────────────
    function searchTrackInfo() {
      const idInput = document.getElementById('trackSearchId');
      const trackId = (idInput?.value || '').trim();
      const statusEl = document.getElementById('trackSearchStatus');
      const resultEl = document.getElementById('trackInfoResult');
      const clearBtn = document.getElementById('trackClearBtn');

      if (!trackId) {
        if (statusEl) {
          statusEl.textContent = 'Please enter a track ID';
          statusEl.style.color = '#eab308';
        }
        return;
      }

      if (statusEl) {
        statusEl.textContent = 'Searching database...';
        statusEl.style.color = 'var(--fg-muted)';
      }
      if (clearBtn) clearBtn.style.display = 'none';

      const secret = localStorage.getItem('nullbeat_admin_secret') || '';
      fetch('/api/db/track/' + encodeURIComponent(trackId), {
        headers: { 'x-admin-secret': secret }
      })
      .then(r => r.json())
      .then(data => {
        if (data.error) throw new Error(data.error);

        if (!data.found) {
          if (statusEl) {
            statusEl.textContent = 'No database records found for track ' + trackId;
            statusEl.style.color = '#eab308';
          }
          if (resultEl) resultEl.style.display = 'none';
          return;
        }

        if (statusEl) {
          statusEl.textContent = 'Found cached records!';
          statusEl.style.color = '#22c55e';
        }
        if (clearBtn) {
          clearBtn.style.display = 'inline-block';
          clearBtn.dataset.id = trackId;
        }

        renderTrackInfo(data);
      })
      .catch(err => {
        if (statusEl) {
          statusEl.textContent = 'Error: ' + err.message;
          statusEl.style.color = '#ef4444';
        }
        if (resultEl) resultEl.style.display = 'none';
      });
    }

    function renderTrackInfo(data) {
      var resultEl = document.getElementById('trackInfoResult');
      if (!resultEl) return;
      resultEl.style.display = 'block';

      var meta = data.meta;
      var torbox = data.torboxCache || [];
      var webseed = [];

      var metaHtml = '';
      if (meta) {
        var artImg = meta.artwork_url ? '<img src="' + escapeHtml(meta.artwork_url) + '" style="width: 64px; height: 64px; border-radius: 4px; object-fit: cover; border: 1px solid var(--border-bright);" />' : '';
        var durStr = meta.duration ? '<span>DUR: ' + Math.floor(meta.duration / 60) + ':' + String(meta.duration % 60).padStart(2, '0') + '</span>' : '';
        var hiResBadge = meta.is_hires ? '<span style="color:#eab308;font-weight:700;">[HI-RES]</span>' : '<span style="color:#38bdf8;">[LOSSLESS]</span>';
        var isrcStr = meta.isrc ? '<span>ISRC: ' + escapeHtml(meta.isrc) + '</span>' : '';

        metaHtml = '<div style="display: flex; gap: 14px; margin-bottom: 14px; align-items: flex-start;">' +
          artImg +
          '<div>' +
            '<div style="font-size: 14px; font-weight: 700; color: #fff;">' + escapeHtml(meta.title || 'Unknown Title') + '</div>' +
            '<div style="font-size: 12px; color: var(--fg-muted); margin-top: 2px;">' +
              escapeHtml(meta.artist || 'Unknown Artist') + (meta.album ? ' &mdash; ' + escapeHtml(meta.album) : '') +
            '</div>' +
            '<div style="font-size: 11px; color: var(--fg-dim); margin-top: 4px; display: flex; gap: 10px; font-family: var(--mono); flex-wrap: wrap;">' +
              '<span>TRACK ID: <b style="color:#fff;">' + escapeHtml(data.trackId) + '</b></span>' +
              isrcStr +
              durStr +
              hiResBadge +
            '</div>' +
          '</div>' +
        '</div>';
      } else {
        metaHtml = '<div style="font-size: 12px; color: var(--fg-muted); margin-bottom: 10px;">(No Tidal track_meta record in database)</div>';
      }

      var torboxHtml = '';
      if (torbox.length > 0) {
        var torboxRows = torbox.map(function(t) {
          return '<tr>' +
            '<td><span class="badge badge-2xx">' + escapeHtml(t.quality) + '</span></td>' +
            '<td style="font-family:var(--mono);">' + (t.size_mb ? t.size_mb + ' MB' : '—') + '</td>' +
            '<td style="font-family:var(--mono);font-size:10px;">' + escapeHtml(t.infohash || '—') + '</td>' +
            '<td style="font-size:10px;max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + escapeHtml(t.filename || '—') + '</td>' +
            '<td style="font-size:10px;">' + new Date(t.updated_at).toLocaleString() + '</td>' +
          '</tr>';
        }).join('');

        torboxHtml = '<div style="font-size: 11px; font-weight: 700; color: var(--fg-muted); margin-top: 10px; margin-bottom: 6px;">CACHED TORBOX QUALITIES (' + torbox.length + ')</div>' +
          '<table style="margin-bottom: 12px;">' +
            '<thead><tr><th>QUALITY</th><th>SIZE</th><th>INFOHASH</th><th>FILENAME</th><th>LAST UPDATED</th></tr></thead>' +
            '<tbody>' + torboxRows + '</tbody>' +
          '</table>';
      } else {
        torboxHtml = '<div style="font-size: 11px; color: var(--fg-dim); margin-bottom: 10px;">No TorBox cache entries for this track.</div>';
      }

      var webseedHtml = '';
      if (webseed.length > 0) {
        var wsRows = webseed.map(function(w) {
          return '<tr>' +
            '<td style="font-family:var(--mono);font-size:10px;">' + escapeHtml(w.file_id) + '</td>' +
            '<td><span class="badge badge-neutral">' + escapeHtml(w.quality) + '</span></td>' +
            '<td style="font-size:10px;">' + escapeHtml(w.filename) + '</td>' +
            '<td style="font-family:var(--mono);">' + escapeHtml(w.ext) + '</td>' +
            '<td style="font-size:10px;">' + new Date(w.created_at).toLocaleString() + '</td>' +
          '</tr>';
        }).join('');

        webseedHtml = '<div style="font-size: 11px; font-weight: 700; color: var(--fg-muted); margin-top: 10px; margin-bottom: 6px;">WEBSEED CACHE FILES (' + webseed.length + ')</div>' +
          '<table>' +
            '<thead><tr><th>FILE ID</th><th>QUALITY</th><th>FILENAME</th><th>EXT</th><th>CREATED</th></tr></thead>' +
            '<tbody>' + wsRows + '</tbody>' +
          '</table>';
      }

      resultEl.innerHTML = metaHtml + torboxHtml;
    }

    function clearTrackInfo() {
      const clearBtn = document.getElementById('trackClearBtn');
      const trackId = clearBtn?.dataset?.id || (document.getElementById('trackSearchId')?.value || '').trim();
      if (!trackId) return;

      if (!confirm('Are you sure you want to PURGE all database records and cache for Track ID ' + trackId + '?')) {
        return;
      }

      const statusEl = document.getElementById('trackSearchStatus');
      const resultEl = document.getElementById('trackInfoResult');
      if (statusEl) {
        statusEl.textContent = 'Purging track ' + trackId + '...';
        statusEl.style.color = '#ef4444';
      }

      const secret = localStorage.getItem('nullbeat_admin_secret') || '';
      fetch('/api/db/track/clear', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-admin-secret': secret },
        body: JSON.stringify({ trackId })
      })
      .then(r => r.json())
      .then(d => {
        if (d.error) throw new Error(d.error);
        if (statusEl) {
          statusEl.textContent = '✓ Cleared track ' + trackId + ' (meta: ' + d.deleted.trackMeta + ', torbox: ' + d.deleted.torboxCache + ')';
          statusEl.style.color = '#22c55e';
        }
        if (clearBtn) clearBtn.style.display = 'none';
        if (resultEl) resultEl.style.display = 'none';
        refreshDbStats();
      })
      .catch(err => {
        if (statusEl) {
          statusEl.textContent = 'Error: ' + err.message;
          statusEl.style.color = '#ef4444';
        }
      });
    }

    // Init Dashboard
    startSSE();
    loadHistory(true);
    refreshMetrics();
    refreshRules();
    refreshStorage();
    refreshEnv();

  </script>
</body>
</html>`;
}

module.exports = {
  createAdminServer,
  isFirstTimeSetup,
  getSetupStatus,
  getEnvPath,
};

