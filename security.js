'use strict';

/**
 * security.js — IP Firewall & Granular Rate Limiting
 *
 * Handles:
 *  - Real client IP extraction across Cloudflare Tunnels (cf-connecting-ip, etc.)
 *  - Instant IP Banning (HTTP 403)
 *  - Granular Per-IP Rate Limiting (HTTP 429)
 *  - In-memory synchronized cache for microsecond-level checks on every request
 */

const { ipRules } = require('./db');

// In-memory cache of rules: Map<ip, { action, rate_limit, reason, created_at, updated_at }>
let _rulesCache = new Map();
let _lastCacheRefresh = 0;

function refreshRulesCache() {
  try {
    const rules = ipRules.getAll();
    const map = new Map();
    for (const r of rules) {
      map.set(r.ip.trim().toLowerCase(), r);
    }
    _rulesCache = map;
    _lastCacheRefresh = Date.now();
  } catch (err) {
    console.error('[Security] Failed to refresh IP rules cache:', err.message);
  }
}

// Initial load
refreshRulesCache();

// Rate limiter sliding window: Map<ip, number[]> (array of timestamps in ms)
const _rateLimitWindows = new Map();

// Periodically clean up old rate limit timestamps every 2 minutes
setInterval(() => {
  const oneMinuteAgo = Date.now() - 60000;
  for (const [ip, timestamps] of _rateLimitWindows.entries()) {
    const active = timestamps.filter(t => t > oneMinuteAgo);
    if (active.length === 0) {
      _rateLimitWindows.delete(ip);
    } else {
      _rateLimitWindows.set(ip, active);
    }
  }
}, 2 * 60 * 1000).unref();

/**
 * Accurately extracts the real client IP, especially behind Cloudflare Tunnels or Reverse Proxies.
 */
function getClientIp(req) {
  // Cloudflare Tunnel passes client IP in CF-Connecting-IP
  const cfIp = req.headers['cf-connecting-ip'];
  if (cfIp) return String(cfIp).trim();

  // Nginx / Reverse proxy header
  const realIp = req.headers['x-real-ip'];
  if (realIp) return String(realIp).trim();

  // Standard X-Forwarded-For (take the first client IP)
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const first = forwarded.split(',')[0].trim();
    if (first) return first;
  }

  // Fallback to socket remoteAddress
  const sock = req.socket?.remoteAddress || req.ip || '127.0.0.1';
  return sock.replace(/^::ffff:/, ''); // Strip IPv6 prefix if present
}

/**
 * Extracts Cloudflare Country code (if routed via Cloudflare)
 */
function getClientCountry(req) {
  return req.headers['cf-ipcountry'] || 'XX';
}

/**
 * Security Middleware for Express
 */
function securityMiddleware(req, res, next) {
  const ip = getClientIp(req);
  const country = getClientCountry(req);
  req.clientIp = ip;
  req.clientCountry = country;

  // Refresh cache if stale (every 10s)
  if (Date.now() - _lastCacheRefresh > 10000) {
    refreshRulesCache();
  }

  const cleanIp = ip.toLowerCase();
  const rule = _rulesCache.get(cleanIp);

  if (rule) {
    // 1. Check IP Ban
    if (rule.action === 'BAN') {
      res.set('Content-Type', 'application/json');
      const banReason = rule.reason || 'Security policy violation';
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Your IP address has been banned by the administrator.',
        ip: ip,
        reason: banReason,
        notice: {
          level: 'error',
          title: 'IP Blocked',
          message: `Your IP has been blocked: ${banReason}`.slice(0, 120),
          duration: 8
        }
      });
    }

    // 2. Check Granular Rate Limit
    if (rule.action === 'RATE_LIMIT') {
      const limitRpm = rule.rate_limit || 60;
      const now = Date.now();
      const oneMinuteAgo = now - 60000;

      if (!_rateLimitWindows.has(cleanIp)) {
        _rateLimitWindows.set(cleanIp, []);
      }

      const timestamps = _rateLimitWindows.get(cleanIp).filter(t => t > oneMinuteAgo);
      if (timestamps.length >= limitRpm) {
        res.set('Retry-After', '60');
        res.set('Content-Type', 'application/json');
        return res.status(429).json({
          error: 'Too Many Requests',
          message: `Rate limit of ${limitRpm} requests/min exceeded for your IP.`,
          ip: ip,
          limit: limitRpm,
          retryAfterSeconds: 60,
          notice: {
            level: 'warning',
            title: 'Rate Limited',
            message: `Rate limit of ${limitRpm} req/min reached. Please wait a minute.`,
            duration: 6
          }
        });
      }

      timestamps.push(now);
      _rateLimitWindows.set(cleanIp, timestamps);
    }
  }

  next();
}

/**
 * Admin actions for IP management
 */
function banIp(ip, reason = 'Banned by admin') {
  if (!ip) throw new Error('IP address is required');
  const cleanIp = ip.trim();
  ipRules.set(cleanIp, 'BAN', 0, reason);
  refreshRulesCache();
  return { success: true, ip: cleanIp, action: 'BAN' };
}

function rateLimitIp(ip, rateLimitRpm = 60, reason = 'Rate limited by admin') {
  if (!ip) throw new Error('IP address is required');
  const cleanIp = ip.trim();
  const rpm = parseInt(rateLimitRpm, 10) || 60;
  ipRules.set(cleanIp, 'RATE_LIMIT', rpm, reason);
  refreshRulesCache();
  return { success: true, ip: cleanIp, action: 'RATE_LIMIT', rateLimit: rpm };
}

function removeRule(ip) {
  if (!ip) throw new Error('IP address is required');
  const cleanIp = ip.trim();
  ipRules.remove(cleanIp);
  refreshRulesCache();
  return { success: true, ip: cleanIp, removed: true };
}

function getRules() {
  return ipRules.getAll();
}

module.exports = {
  getClientIp,
  getClientCountry,
  securityMiddleware,
  banIp,
  rateLimitIp,
  removeRule,
  getRules,
  refreshRulesCache,
};
