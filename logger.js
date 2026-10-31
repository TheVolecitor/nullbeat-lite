'use strict';

/**
 * logger.js — Real-Time Request Tracer & Metrics Logger
 *
 * Captures all request/response telemetry:
 *  - Cloudflare Tunnel IP & Geo country
 *  - Latency in milliseconds
 *  - Status codes, Route paths, CF-Ray ID, User-Agent
 *  - Emits real-time events for Live Trace SSE streaming in the Admin Panel
 *  - Persists traces in SQLite (with automatic prune)
 */

const EventEmitter = require('node:events');
const { traceLogs } = require('./db');
const { getClientIp, getClientCountry } = require('./security');

const traceEmitter = new EventEmitter();
traceEmitter.setMaxListeners(200);

/**
 * Express Middleware to trace and log every incoming request
 */
function traceLoggerMiddleware(req, res, next) {
  const startHr = process.hrtime.bigint();
  const timestamp = Date.now();

  const ip = req.clientIp || getClientIp(req);
  const country = req.clientCountry || getClientCountry(req);
  const method = req.method;
  const url = req.originalUrl || req.url;

  // Do not log internal admin control plane endpoints to avoid feedback loops
  if (url.startsWith('/api/traces') || url.startsWith('/api/metrics') || url.startsWith('/api/db') || url.startsWith('/api/env') || url.startsWith('/api/security') || url.startsWith('/admin')) {
    return next();
  }

  const rayId = req.headers['cf-ray'] || '';
  const userAgent = req.headers['user-agent'] || '';

  // Intercept response finish
  res.on('finish', () => {
    const endHr = process.hrtime.bigint();
    const durationMs = Number(endHr - startHr) / 1e6; // Convert ns to ms
    const roundedDuration = Math.round(durationMs * 100) / 100;
    const status = res.statusCode;
    let route = req.path || '';
    if (req.route && req.route.path) {
      if (Array.isArray(req.route.path)) {
        route = req.route.path[0] || req.path || '';
      } else {
        route = String(req.route.path);
      }
    }
    const bytesSent = parseInt(res.get('Content-Length') || '0', 10);
    const eventType = res.locals.eventType || '';

    const trace = {
      timestamp,
      ip,
      country,
      method,
      url,
      route,
      status,
      durationMs: roundedDuration,
      userAgent,
      rayId,
      bytesSent,
      eventType,
      details: res.locals.traceDetails || null,
    };

    try {
      // 1. Insert into SQLite
      const info = traceLogs.insert(trace);
      const traceId = info?.lastInsertRowid ? Number(info.lastInsertRowid) : undefined;

      // 2. Broadcast to live SSE listeners
      traceEmitter.emit('trace', {
        ...trace,
        id: traceId,
        timeFormatted: new Date(timestamp).toLocaleTimeString(),
      });
    } catch (err) {
      console.error('[TraceLog Emit Error]:', err.message);
    }
  });

  next();
}

module.exports = {
  traceEmitter,
  traceLoggerMiddleware,
  getTraces: traceLogs.get,
  getMetrics: traceLogs.getMetrics,
};
