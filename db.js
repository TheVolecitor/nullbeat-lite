'use strict';

/**
 * db.js — NullBeat SQLite Database
 * 
 * Tables:
 *  1. kv_store      — stores registered keys
 *  2. search_cache  — caches raw Tidal search results (quality-agnostic)
 *  3. torbox_cache  — stores known TorBox cached qualities per track ID
 *
 * Requires Node.js 22.5+ (node:sqlite is built-in, no native addons needed).
 */

const path = require('path');
const fs = require('fs');

// Suppress the experimental SQLite warning
process.removeAllListeners('warning');
process.on('warning', (w) => { if (w.name !== 'ExperimentalWarning') process.stderr.write(String(w) + '\n'); });

let DatabaseSync;
try {
  DatabaseSync = require('node:sqlite').DatabaseSync;
} catch {
  // Fallback to better-sqlite3 (Node < 22 or experimental flag not set)
  const BetterSqlite3 = require('better-sqlite3');
  // Wrap better-sqlite3 to match node:sqlite API surface we use
  DatabaseSync = class extends BetterSqlite3 {
    prepare(sql) {
      const stmt = super.prepare(sql);
      return stmt;
    }
    exec(sql) { super.exec(sql); }
  };
}

const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const DB_PATH = path.join(DATA_DIR, 'nullbeat.db');
let _db;

function getDb() {
  if (_db) return _db;
  _db = new DatabaseSync(DB_PATH);
  // WAL mode for better concurrent read performance
  _db.exec('PRAGMA journal_mode = WAL');
  _db.exec('PRAGMA foreign_keys = ON');
  initSchema();
  importKvDumpIfPresent();
  populateTrackMetaFromSearchCache();
  return _db;
}

function initSchema() {
  const db = _db;
  db.exec(`
        CREATE TABLE IF NOT EXISTS settings (
      key        TEXT PRIMARY KEY,
      value      TEXT NOT NULL,
      updated_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS kv_store (
      key        TEXT PRIMARY KEY,
      value      TEXT NOT NULL,
      updated_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS search_cache (
      cache_key        TEXT PRIMARY KEY,
      result_json      TEXT NOT NULL,
      created_at       INTEGER NOT NULL,
      expires_at       INTEGER NOT NULL,
      last_accessed_at INTEGER NOT NULL DEFAULT 0,
      size_bytes       INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS torbox_cache (
      track_id   TEXT NOT NULL,
      quality    TEXT NOT NULL,
      infohash   TEXT NOT NULL DEFAULT '',
      filename   TEXT NOT NULL DEFAULT '',
      size_mb    REAL NOT NULL,
      updated_at INTEGER NOT NULL,
      PRIMARY KEY (track_id, quality)
    );

    CREATE TABLE IF NOT EXISTS ip_rules (
      ip          TEXT PRIMARY KEY,
      action      TEXT NOT NULL,          -- 'BAN' or 'RATE_LIMIT'
      rate_limit  INTEGER DEFAULT 60,     -- requests per minute (for RATE_LIMIT)
      reason      TEXT DEFAULT '',
      created_at  INTEGER NOT NULL,
      updated_at  INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS trace_logs (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp    INTEGER NOT NULL,
      ip           TEXT NOT NULL,
      country      TEXT NOT NULL DEFAULT 'XX',
      method       TEXT NOT NULL,
      url          TEXT NOT NULL,
      route        TEXT NOT NULL DEFAULT '',
      status       INTEGER NOT NULL,
      duration_ms  REAL NOT NULL,
      user_agent   TEXT DEFAULT '',
      ray_id       TEXT DEFAULT '',
      bytes_sent   INTEGER DEFAULT 0,
      event_type   TEXT NOT NULL DEFAULT '',
      details      TEXT DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS daily_metrics (
      date                   TEXT PRIMARY KEY,
      total_requests         INTEGER NOT NULL DEFAULT 0,
      total_searches         INTEGER NOT NULL DEFAULT 0,
      total_streams_direct   INTEGER NOT NULL DEFAULT 0,
      total_streams_forwarded INTEGER NOT NULL DEFAULT 0,
      error_count            INTEGER NOT NULL DEFAULT 0,
      avg_latency_ms         REAL NOT NULL DEFAULT 0,
      ingress_bytes          INTEGER NOT NULL DEFAULT 0,
      egress_bytes           INTEGER NOT NULL DEFAULT 0,
      peak_ingress_bps       INTEGER NOT NULL DEFAULT 0,
      peak_egress_bps        INTEGER NOT NULL DEFAULT 0,
      endpoint_hits          TEXT NOT NULL DEFAULT '{}',
      status_breakdown       TEXT NOT NULL DEFAULT '{}',
      top_ips                TEXT NOT NULL DEFAULT '[]',
      is_finalized           INTEGER NOT NULL DEFAULT 0,
      updated_at             INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS track_meta (
      track_id    TEXT PRIMARY KEY,
      title       TEXT NOT NULL DEFAULT '',
      artist      TEXT NOT NULL DEFAULT '',
      album       TEXT NOT NULL DEFAULT '',
      duration    INTEGER NOT NULL DEFAULT 0,
      isrc        TEXT NOT NULL DEFAULT '',
      artwork_url TEXT NOT NULL DEFAULT '',
      is_hires    INTEGER NOT NULL DEFAULT 0,
      hires_unavailable INTEGER NOT NULL DEFAULT 0,
      is_atmos    INTEGER NOT NULL DEFAULT 0,
      updated_at  INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS stats_counters (
      name       TEXT PRIMARY KEY,
      count      INTEGER NOT NULL DEFAULT 0,
      updated_at INTEGER NOT NULL
    );

    

    CREATE TABLE IF NOT EXISTS api_key_bans (
      api_key          TEXT PRIMARY KEY,
      tier             TEXT NOT NULL DEFAULT 'BAN',  -- 'BAN' | 'TROLL'
      troll_torrent_id TEXT NOT NULL DEFAULT '',     -- cached torrent_id for troll-ban
      reason           TEXT NOT NULL DEFAULT '',
      created_at       INTEGER NOT NULL
    );

    
  `);

  // Migrate: add columns to existing DB if they don't exist yet
  const tmCols = db.prepare("PRAGMA table_info(track_meta)").all().map(c => c.name);
  if (!tmCols.includes('hires_unavailable')) {
    db.exec("ALTER TABLE track_meta ADD COLUMN hires_unavailable INTEGER NOT NULL DEFAULT 0");
  }
  if (!tmCols.includes('is_atmos')) {
    db.exec("ALTER TABLE track_meta ADD COLUMN is_atmos INTEGER NOT NULL DEFAULT 0");
  }
  const cols = db.prepare("PRAGMA table_info(torbox_cache)").all().map(c => c.name);
  if (!cols.includes('infohash')) db.exec("ALTER TABLE torbox_cache ADD COLUMN infohash TEXT NOT NULL DEFAULT ''");
  if (!cols.includes('filename')) db.exec("ALTER TABLE torbox_cache ADD COLUMN filename TEXT NOT NULL DEFAULT ''");

  const scCols = db.prepare("PRAGMA table_info(search_cache)").all().map(c => c.name);
  if (!scCols.includes('last_accessed_at')) {
    db.exec("ALTER TABLE search_cache ADD COLUMN last_accessed_at INTEGER NOT NULL DEFAULT 0");
    db.exec("UPDATE search_cache SET last_accessed_at = created_at WHERE last_accessed_at = 0");
  }
  if (!scCols.includes('size_bytes')) {
    db.exec("ALTER TABLE search_cache ADD COLUMN size_bytes INTEGER NOT NULL DEFAULT 0");
    db.exec("UPDATE search_cache SET size_bytes = length(result_json) WHERE size_bytes = 0");
  }

  const tlCols = db.prepare("PRAGMA table_info(trace_logs)").all().map(c => c.name);
  if (!tlCols.includes('event_type')) {
    db.exec("ALTER TABLE trace_logs ADD COLUMN event_type TEXT NOT NULL DEFAULT ''");
  }

  const dmCols = db.prepare("PRAGMA table_info(daily_metrics)").all().map(c => c.name);
  if (!dmCols.includes('is_finalized')) {
    db.exec("ALTER TABLE daily_metrics ADD COLUMN is_finalized INTEGER NOT NULL DEFAULT 0");
  }
  if (!dmCols.includes('total_searches')) {
    db.exec("ALTER TABLE daily_metrics ADD COLUMN total_searches INTEGER NOT NULL DEFAULT 0");
  }
  if (!dmCols.includes('total_streams_direct')) {
    db.exec("ALTER TABLE daily_metrics ADD COLUMN total_streams_direct INTEGER NOT NULL DEFAULT 0");
  }
  if (!dmCols.includes('total_streams_forwarded')) {
    db.exec("ALTER TABLE daily_metrics ADD COLUMN total_streams_forwarded INTEGER NOT NULL DEFAULT 0");
  }
  if (!dmCols.includes('ingress_bytes')) {
    db.exec("ALTER TABLE daily_metrics ADD COLUMN ingress_bytes INTEGER NOT NULL DEFAULT 0");
  }
  if (!dmCols.includes('egress_bytes')) {
    db.exec("ALTER TABLE daily_metrics ADD COLUMN egress_bytes INTEGER NOT NULL DEFAULT 0");
  }
  if (!dmCols.includes('peak_ingress_bps')) {
    db.exec("ALTER TABLE daily_metrics ADD COLUMN peak_ingress_bps INTEGER NOT NULL DEFAULT 0");
  }
  if (!dmCols.includes('peak_egress_bps')) {
    db.exec("ALTER TABLE daily_metrics ADD COLUMN peak_egress_bps INTEGER NOT NULL DEFAULT 0");
  }

  // Create indexes after migrations ensure columns exist
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_search_cache_lru ON search_cache (last_accessed_at ASC);
    CREATE INDEX IF NOT EXISTS idx_search_cache_expires ON search_cache (expires_at, created_at);
    CREATE INDEX IF NOT EXISTS idx_track_meta_updated ON track_meta (updated_at DESC);
    CREATE INDEX IF NOT EXISTS idx_track_meta_isrc ON track_meta (isrc);
    CREATE INDEX IF NOT EXISTS idx_ip_rules_action ON ip_rules (action);
    CREATE INDEX IF NOT EXISTS idx_trace_logs_time ON trace_logs (timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_trace_logs_ip ON trace_logs (ip);
    CREATE INDEX IF NOT EXISTS idx_trace_logs_status ON trace_logs (status);
    CREATE INDEX IF NOT EXISTS idx_trace_logs_event_type ON trace_logs (event_type);
    CREATE INDEX IF NOT EXISTS idx_daily_metrics_date ON daily_metrics (date DESC);
    CREATE INDEX IF NOT EXISTS idx_api_key_bans_tier ON api_key_bans (tier);
  `);
}

// ── KV Import ─────────────────────────────────────────────────────────────────

function importKvDumpIfPresent() {
  const dumpPath = path.join(DATA_DIR, 'kv_dump.json');
  if (!fs.existsSync(dumpPath)) return;

  try {
    const raw = fs.readFileSync(dumpPath, 'utf8');
    const dump = JSON.parse(raw);
    const now = Date.now();

    for (const [key, value] of Object.entries(dump)) {
      const serialized = typeof value === 'string' ? value : JSON.stringify(value);
      kvPut(key, serialized);
    }

    fs.unlinkSync(dumpPath);
    console.log('[DB] Imported kv_dump.json into kv_store and deleted file.');
  } catch (err) {
    console.error('[DB] Failed to import kv_dump.json:', err.message);
  }
}


// ── Settings API (Lite Config — Deprecated in favor of strict .env) ─────────
function settingsGet(key, defaultVal = null) {
  return defaultVal;
}

function settingsSet(key, value) {
  return false;
}

function settingsGetAll() {
  return {};
}

// ── KV API ────────────────────────────────────────────────────────────────────

function kvGet(key) {
  const db = getDb();
  const row = db.prepare('SELECT value FROM kv_store WHERE key = ?').get(key);
  return row ? row.value : null;
}

function kvGetAll() {
  const db = getDb();
  return db.prepare('SELECT key, value, updated_at FROM kv_store ORDER BY key ASC').all();
}

function kvDelete(key) {
  const db = getDb();
  const info = db.prepare('DELETE FROM kv_store WHERE key = ?').run(key);
  return info.changes > 0;
}

function kvPut(key, value) {
  const db = getDb();
  const serialized = typeof value === 'string' ? value : JSON.stringify(value);
  db.prepare(
    'INSERT INTO kv_store (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at'
  ).run(key, serialized, Date.now());
}

// ── Search & Entity Cache API ─────────────────────────────────────────────────

const DEFAULT_TTL_SECONDS = 3 * 24 * 60 * 60;  // 3 days (259,200s)
const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000; // 7 days hard max-age
const MAX_CACHE_BYTES = 1024 * 1024 * 1024;    // 1 GB strict LRU limit

/**
 * Build a cache key from search parameters (quality-agnostic).
 * Badges are injected at read-time from torbox_cache.
 */
function buildSearchCacheKey(query, typeParam, limitParam, atmos = false) {
  return `search:${query.toLowerCase()}|${typeParam || 'all'}|${limitParam}${atmos ? '|atmos' : ''}`;
}

function getSearchCache(cacheKey) {
  const db = getDb();
  const now = Date.now();
  const minCreatedAt = now - SEVEN_DAYS_MS;

  const row = db.prepare(
    'SELECT result_json FROM search_cache WHERE cache_key = ? AND expires_at > ? AND created_at > ?'
  ).get(cacheKey, now, minCreatedAt);

  if (!row) return null;

  try {
    db.prepare('UPDATE search_cache SET last_accessed_at = ? WHERE cache_key = ?').run(now, cacheKey);
  } catch (e) { }

  return JSON.parse(row.result_json);
}

/**
 * Like getSearchCache but also returns createdAt for stale-while-revalidate.
 * Returns { data, createdAt } or null.
 */
function getSearchCacheWithMeta(cacheKey) {
  const db = getDb();
  const now = Date.now();
  const minCreatedAt = now - SEVEN_DAYS_MS;

  const row = db.prepare(
    'SELECT result_json, created_at FROM search_cache WHERE cache_key = ? AND expires_at > ? AND created_at > ?'
  ).get(cacheKey, now, minCreatedAt);

  if (!row) return null;

  try {
    db.prepare('UPDATE search_cache SET last_accessed_at = ? WHERE cache_key = ?').run(now, cacheKey);
  } catch (e) { }

  return { data: JSON.parse(row.result_json), createdAt: row.created_at };
}

function enforceCacheSizeLimit(db, newBytes = 0) {
  const totalRow = db.prepare('SELECT COALESCE(SUM(size_bytes), 0) as total FROM search_cache').get();
  let currentTotal = (totalRow ? totalRow.total : 0) + newBytes;

  if (currentTotal > MAX_CACHE_BYTES) {
    const targetBytes = Math.floor(MAX_CACHE_BYTES * 0.9); // Target 90% of 1GB to avoid constant churn
    const oldestStmt = db.prepare('SELECT cache_key, size_bytes FROM search_cache ORDER BY last_accessed_at ASC LIMIT 50');
    const deleteStmt = db.prepare('DELETE FROM search_cache WHERE cache_key = ?');

    let evictedCount = 0;
    while (currentTotal > targetBytes) {
      const rows = oldestStmt.all();
      if (!rows || rows.length === 0) break;
      for (const row of rows) {
        deleteStmt.run(row.cache_key);
        currentTotal -= row.size_bytes;
        evictedCount++;
        if (currentTotal <= targetBytes) break;
      }
    }
    if (evictedCount > 0) {
      console.log(`[DB LRU] Evicted ${evictedCount} entries to maintain 1GB limit (current: ${(currentTotal / (1024 * 1024)).toFixed(2)} MB).`);
    }
  }
}

function saveTracksMeta(tracks) {
  if (!tracks || tracks.length === 0) return;
  const db = getDb();
  const now = Date.now();
  const insert = db.prepare(`
    INSERT INTO track_meta (track_id, title, artist, album, duration, isrc, artwork_url, is_hires, hires_unavailable, is_atmos, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(track_id) DO UPDATE SET
      title             = CASE WHEN excluded.title != '' AND excluded.title != 'Unknown' THEN excluded.title ELSE track_meta.title END,
      artist            = CASE WHEN excluded.artist != '' AND excluded.artist != 'Unknown' THEN excluded.artist ELSE track_meta.artist END,
      album             = CASE WHEN excluded.album != '' AND excluded.album != 'Unknown' THEN excluded.album ELSE track_meta.album END,
      duration          = CASE WHEN excluded.duration > 0 THEN excluded.duration ELSE track_meta.duration END,
      isrc              = CASE WHEN excluded.isrc != '' THEN excluded.isrc ELSE track_meta.isrc END,
      artwork_url       = CASE WHEN excluded.artwork_url != '' THEN excluded.artwork_url ELSE track_meta.artwork_url END,
      is_hires          = excluded.is_hires,
      hires_unavailable = excluded.hires_unavailable,
      is_atmos          = excluded.is_atmos,
      updated_at        = excluded.updated_at
  `);

  const markHiresUnavail = db.prepare(`
    INSERT INTO torbox_cache (track_id, quality, infohash, filename, size_mb, updated_at)
    VALUES (?, 'Hi-Res', 'UNAVAILABLE', '', 0, ?)
    ON CONFLICT(track_id, quality) DO UPDATE SET
      infohash = CASE WHEN torbox_cache.infohash = '' OR torbox_cache.infohash = 'UNAVAILABLE' THEN 'UNAVAILABLE' ELSE torbox_cache.infohash END,
      updated_at = excluded.updated_at
  `);

  db.exec('BEGIN');
  try {
    for (const raw of tracks) {
      const t = raw?.item || raw;
      if (!t || !t.id) continue;
      const id = String(t.id).replace('track:', '');
      const title = t.title || t.name || '';
      const artist =
        t.artist?.name ||
        (typeof t.artist === 'string' ? t.artist : null) ||
        t.artists?.find(a => a?.type === 'MAIN')?.name ||
        t.artists?.[0]?.name ||
        t.album?.artist?.name ||
        (typeof t.album?.artist === 'string' ? t.album.artist : null) ||
        t.album?.artists?.[0]?.name ||
        '';
      const album =
        t.album?.title ||
        t.album?.name ||
        (typeof t.album === 'string' ? t.album : '') ||
        '';
      const duration = Number(t.duration) || 0;
      const isrc = t.isrc || '';
      const coverId = t.artworkURL || t.album?.cover || t.cover || '';
      let artworkUrl = '';
      if (coverId) {
        if (typeof coverId === 'string' && (coverId.startsWith('http://') || coverId.startsWith('https://'))) {
          artworkUrl = coverId;
        } else if (typeof coverId === 'string' && coverId.trim()) {
          artworkUrl = `https://resources.tidal.com/images/${coverId.replace(/-/g, '/')}/640x640.jpg`;
        }
      }

      const mediaTags = t.attributes?.mediaTags || t.mediaTags || [];
      const metaTags = t.mediaMetadata?.tags || t.tags || [];
      const allTags = [...(Array.isArray(mediaTags) ? mediaTags : []), ...(Array.isArray(metaTags) ? metaTags : [])];
      const audioModes = t.audioModes || t.attributes?.audioModes || [];
      const audioQuality = String(t.audioQuality || t.attributes?.audioQuality || '').toUpperCase();

      let hasHires = allTags.some(tag => {
        const u = String(tag).toUpperCase();
        return u === 'HIRES_LOSSLESS' || u === 'FLAC_HIRES' || u === 'HI_RES';
      }) || audioQuality.includes('HI_RES') || audioQuality.includes('HIRES') || audioModes.includes('HI_RES');

      if (typeof t.isHiRes === 'boolean' && allTags.length === 0 && !audioQuality) {
        hasHires = t.isHiRes;
      }

      const isHiResVal = hasHires ? 1 : 0;
      const hiresUnavailableVal = hasHires ? 0 : 1;
      const hasAtmos = typeof t.isAtmos === 'boolean'
        ? t.isAtmos
        : (allTags.some(tag => String(tag).toUpperCase() === 'DOLBY_ATMOS') || audioModes.includes('DOLBY_ATMOS'));
      const isAtmosVal = hasAtmos ? 1 : 0;

      insert.run(id, title, artist, album, duration, isrc, artworkUrl, isHiResVal, hiresUnavailableVal, isAtmosVal, now);

      if (!hasHires) {
        markHiresUnavail.run(id, now);
      }
    }
    db.exec('COMMIT');
  } catch (err) {
    try { db.exec('ROLLBACK'); } catch (_) { }
    console.error('[DB] saveTracksMeta error:', err.message);
  }
}

function populateTrackMetaFromSearchCache() {
  try {
    const countRow = _db.prepare('SELECT count(*) as count FROM track_meta').get();
    if (countRow && countRow.count > 0) return;
    const rows = _db.prepare('SELECT result_json FROM search_cache').all();
    const allTracks = [];
    for (const row of rows) {
      try {
        const data = JSON.parse(row.result_json);
        const list = Array.isArray(data) ? data : (data.tracks || data.items || []);
        for (const item of list) {
          const t = item?.item || item;
          if (t && t.id) allTracks.push(t);
        }
      } catch (_) { }
    }
    if (allTracks.length > 0) {
      saveTracksMeta(allTracks);
      console.log(`[DB] Indexed ${allTracks.length} track metadata entries into track_meta.`);
    }
  } catch (err) {
    console.error('[DB] populateTrackMeta error:', err.message);
  }
}

function setSearchCache(cacheKey, data, ttlSeconds = DEFAULT_TTL_SECONDS) {
  const db = getDb();
  const now = Date.now();
  const expiresAt = now + ttlSeconds * 1000;
  const resultJson = JSON.stringify(data);
  const sizeBytes = Buffer.byteLength(resultJson, 'utf8');

  // Enforce 1GB LRU limit before inserting
  enforceCacheSizeLimit(db, sizeBytes);

  db.prepare(`
    INSERT INTO search_cache (cache_key, result_json, created_at, expires_at, last_accessed_at, size_bytes)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(cache_key) DO UPDATE SET
      result_json      = excluded.result_json,
      created_at       = excluded.created_at,
      expires_at       = excluded.expires_at,
      last_accessed_at = excluded.last_accessed_at,
      size_bytes       = excluded.size_bytes
  `).run(cacheKey, resultJson, now, expiresAt, now, sizeBytes);

  // Auto-index tracks for fast batch lookup
  try {
    const list = Array.isArray(data) ? data : (data.tracks || data.items || []);
    if (list.length > 0) {
      saveTracksMeta(list);
    }
  } catch (_) { }
}

function cleanExpiredSearchCache() {
  const db = getDb();
  const now = Date.now();
  const minCreatedAt = now - SEVEN_DAYS_MS;
  const info = db.prepare('DELETE FROM search_cache WHERE expires_at <= ? OR created_at <= ?').run(now, minCreatedAt);
  if (info.changes > 0) {
    console.log(`[DB] Cleaned ${info.changes} expired/stale search cache entries.`);
  }
}

/**
 * Fast batch lookup of track metadata by track IDs (< 1ms, 0% CPU).
 * Returns Map<trackId, TrackMeta>.
 */
function findTracksInBatch(trackIds) {
  if (!trackIds || trackIds.length === 0) return new Map();
  const db = getDb();
  const idStrs = trackIds.map(id => String(id).replace('track:', '')).filter(Boolean);
  const result = new Map();
  if (idStrs.length === 0) return result;

  const CHUNK_SIZE = 400;
  for (let i = 0; i < idStrs.length; i += CHUNK_SIZE) {
    const chunk = idStrs.slice(i, i + CHUNK_SIZE);
    const placeholders = chunk.map(() => '?').join(',');
    const rows = db.prepare(
      `SELECT track_id, title, artist, album, duration, isrc, artwork_url, is_hires, is_atmos FROM track_meta WHERE track_id IN (${placeholders})`
    ).all(...chunk);

    for (const row of rows) {
      result.set(String(row.track_id), {
        id: String(row.track_id),
        title: row.title,
        artist: row.artist,
        album: row.album,
        duration: row.duration,
        isrc: row.isrc,
        artworkURL: row.artwork_url,
        isHiRes: Boolean(row.is_hires),
        isAtmos: Boolean(row.is_atmos),
      });
    }
  }
  return result;
}

/**
 * Scan search_cache / track_meta for existing metadata of a track by its ID.
 * Returns track metadata object or null.
 */
function findTrackInCache(trackId) {
  if (!trackId) return null;
  const db = getDb();
  const idStr = String(trackId).replace('track:', '');
  try {
    const row = db.prepare(
      `SELECT track_id, title, artist, album, duration, isrc, artwork_url, is_hires, is_atmos FROM track_meta WHERE track_id = ?`
    ).get(idStr);

    if (row && (row.title || row.artist)) {
      return {
        id: String(row.track_id),
        title: row.title,
        artist: row.artist,
        album: row.album,
        duration: row.duration,
        isrc: row.isrc,
        artworkURL: row.artwork_url,
        isHiRes: Boolean(row.is_hires),
        isAtmos: Boolean(row.is_atmos),
      };
    }
  } catch (_) { }
  return null;
}

/**
 * Find track in track_meta by exact ISRC.
 * Returns track metadata object or null.
 */
function findTrackByIsrc(isrc) {
  if (!isrc || typeof isrc !== 'string') return null;
  const cleanIsrc = isrc.trim().toUpperCase();
  if (!cleanIsrc) return null;
  const db = getDb();
  try {
    const row = db.prepare(
      `SELECT track_id, title, artist, album, duration, isrc, artwork_url, is_hires FROM track_meta WHERE upper(isrc) = ? LIMIT 1`
    ).get(cleanIsrc);

    if (row && row.track_id) {
      return {
        id: String(row.track_id),
        trackId: String(row.track_id),
        title: row.title,
        artist: row.artist,
        album: row.album,
        duration: row.duration,
        isrc: row.isrc,
        artworkURL: row.artwork_url,
        isHiRes: Boolean(row.is_hires),
      };
    }
  } catch (_) { }
  return null;
}

// ── TorBox Cache API ──────────────────────────────────────────────────────────

/**
 * Write a cache hit for a (trackId, quality) pair.
 * Called by injectCacheInfo after a live TorBox /checkcached call.
 *
 * @param {string} trackId
 * @param {string} quality  - label string: 'Hi-Res', 'HiFi CD', '320kbps', '96kbps'
 * @param {number} sizeMb
 * @param {string} infohash - TorBox true infohash (hex)
 * @param {string} filename - full filename e.g. "Track - Artist [NullBeat 123 - Hi-Res].flac"
 */


function isHiresUnavailable(trackId) {
  const cleanId = String(trackId).replace(/^track:/, '').trim();
  const db = getDb();
  try {
    const row = db.prepare('SELECT infohash FROM torbox_cache WHERE track_id = ? AND quality = ?').get(cleanId, 'Hi-Res');
    if (row && row.infohash === 'UNAVAILABLE') return true;
    const meta = db.prepare('SELECT is_hires, hires_unavailable FROM track_meta WHERE track_id = ?').get(cleanId);
    if (meta && (meta.hires_unavailable === 1 || meta.is_hires === 0)) return true;
  } catch (_) { }
  return false;
}

function markHiresUnavailable(trackId) {
  const cleanId = String(trackId).replace(/^track:/, '').trim();
  writeTorboxCache(cleanId, 'Hi-Res', 0, 'UNAVAILABLE', '');
  try {
    const db = getDb();
    db.prepare(`
      INSERT INTO track_meta (track_id, is_hires, hires_unavailable, updated_at)
      VALUES (?, 0, 1, ?)
      ON CONFLICT(track_id) DO UPDATE SET is_hires = 0, hires_unavailable = 1, updated_at = excluded.updated_at
    `).run(cleanId, Date.now());
  } catch (_) { }
}

function normalizeCacheQuality(q) {
  if (!q) return 'HiFi CD';
  const u = String(q).trim().toUpperCase();
  if (u === 'DOLBY ATMOS' || u === 'ATMOS' || u.includes('ATMOS')) return 'DOLBY ATMOS';
  if (u === 'HI-RES' || u === 'HIRES' || u.includes('HI-RES') || u.includes('HIRES')) return 'Hi-Res';
  if (u === 'HIFI CD' || u === 'CD' || u === 'LOSSLESS' || u.includes('16BIT') || u.includes('44.1')) return 'HiFi CD';
  if (u === '320KBPS AAC' || u === '320KBPS' || u === '320' || u === 'HIGH') return '320kbps AAC';
  if (u === '96KBPS' || u === '96' || u === 'LOW') return '96kbps';
  return q;
}

function writeTorboxCache(trackId, quality, sizeMb, infohash = '', filename = '') {
  const normQuality = normalizeCacheQuality(quality);
  const db = getDb();
  db.prepare(
    `INSERT INTO torbox_cache (track_id, quality, infohash, filename, size_mb, updated_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(track_id, quality) DO UPDATE SET
       infohash   = excluded.infohash,
       filename   = excluded.filename,
       size_mb    = excluded.size_mb,
       updated_at = excluded.updated_at`
  ).run(String(trackId), normQuality, infohash, filename, sizeMb, Date.now());
}

/**
 * Look up TorBox cache hits for a list of track IDs and apply
 * the best matching badge for the given quality chain.
 * Returns a Map<trackId, { label, sizeMb, infohash }> for the best cached quality.
 */
function lookupTorboxBadges(trackIds, qualityChain) {
  if (!trackIds || trackIds.length === 0 || !qualityChain || qualityChain.length === 0) {
    return new Map();
  }

  const QUALITY_LABELS = {
    ATMOS: 'DOLBY ATMOS',
    HI_RES_LOSSLESS: 'Hi-Res',
    LOSSLESS: 'HiFi CD',
    HIGH: '320kbps AAC',
    LOW: '96kbps',
  };

  const db = getDb();

  const placeholders = trackIds.map(() => '?').join(',');
  const rows = db.prepare(
    `SELECT track_id, quality, size_mb, infohash FROM torbox_cache WHERE track_id IN (${placeholders})`
  ).all(...trackIds.map(String));

  const metaRows = db.prepare(
    `SELECT track_id, is_hires FROM track_meta WHERE track_id IN (${placeholders})`
  ).all(...trackIds.map(String));

  const isHiresMap = new Map();
  for (const row of metaRows) {
    isHiresMap.set(row.track_id, Boolean(row.is_hires));
  }

  const byTrack = new Map();
  for (const row of rows) {
    if (!byTrack.has(row.track_id)) byTrack.set(row.track_id, []);
    byTrack.get(row.track_id).push({ quality: row.quality, sizeMb: row.size_mb, infohash: row.infohash });
  }

  const result = new Map();
  for (const [trackId, entries] of byTrack) {
    const isHiRes = isHiresMap.get(trackId) || false;

    for (const formatKey of qualityChain) {
      const label = QUALITY_LABELS[formatKey];
      if (!label) continue;
      const hit = entries.find(e => e.quality === label || (label === 'HiFi CD' && e.quality === '16bit/44.1khz'));
      if (hit) {
        if (!hit.infohash || hit.infohash === 'UNAVAILABLE' || hit.infohash.trim() === '') continue;

        // Prevent falling back to AAC if we requested FLAC, unless FLAC is explicitly proven unavailable
        if (qualityChain.includes('LOSSLESS') && (formatKey === 'HIGH' || formatKey === 'LOW')) {
          const losslessHit = entries.find(e => e.quality === 'HiFi CD' || e.quality === '16bit/44.1khz');
          if (!losslessHit || losslessHit.infohash !== 'UNAVAILABLE') break;
        }

        result.set(trackId, { label, sizeMb: hit.sizeMb, infohash: hit.infohash || '' });
        break;
      }
    }
  }

  return result;
}

/**
 * Look up the best cached entry for a single track ID that has a known infohash.
 * Used by the /stream handler to bypass Head Server when we can create directly via TorBox.
 *
 * Returns { quality, infohash, filename, sizeMb } or null.
 */
function lookupStreamHit(trackId, qualityChain) {
  if (!trackId || !qualityChain || qualityChain.length === 0) return null;

  const QUALITY_LABELS = {
    ATMOS: 'DOLBY ATMOS',
    HI_RES_LOSSLESS: 'Hi-Res',
    LOSSLESS: 'HiFi CD',
    HIGH: '320kbps AAC',
    LOW: '96kbps',
  };

  const db = getDb();
  const rows = db.prepare(
    `SELECT quality, infohash, filename, size_mb
     FROM torbox_cache
     WHERE track_id = ? AND infohash != ''`
  ).all(String(trackId));

  if (!rows || rows.length === 0) return null;

  const meta = findTrackInCache(trackId);
  const isHiRes = meta ? meta.isHiRes : false;

  for (const formatKey of qualityChain) {
    const label = QUALITY_LABELS[formatKey];
    if (!label) continue;
    const hit = rows.find(r => r.quality === label || (label === 'HiFi CD' && r.quality === '16bit/44.1khz'));
    if (hit) {
      if (hit.infohash === 'UNAVAILABLE') continue;

      if (qualityChain.includes('LOSSLESS') && (formatKey === 'HIGH' || formatKey === 'LOW')) {
        const losslessHit = rows.find(r => r.quality === 'HiFi CD' || r.quality === '16bit/44.1khz');
        if (!losslessHit || losslessHit.infohash !== 'UNAVAILABLE') return null;
      }

      return {
        quality: hit.quality,
        infohash: hit.infohash,
        filename: hit.filename,
        sizeMb: hit.size_mb,
      };
    }
  }

  return null;
}

function markAtmosUnavailable(trackId) {
  const cleanId = String(trackId).replace(/^track:/, '').trim();
  const db = getDb();
  try {
    db.prepare(`
      INSERT INTO torbox_cache (track_id, quality, size_mb, infohash, filename, updated_at)
      VALUES (?, 'DOLBY ATMOS', 0, 'UNAVAILABLE', '', ?)
      ON CONFLICT(track_id, quality) DO UPDATE SET
        infohash = CASE WHEN torbox_cache.infohash = '' OR torbox_cache.infohash = 'UNAVAILABLE' THEN 'UNAVAILABLE' ELSE torbox_cache.infohash END,
        updated_at = excluded.updated_at
    `).run(cleanId, Date.now());

    db.prepare(`
      UPDATE track_meta SET is_atmos = 0 WHERE track_id = ?
    `).run(cleanId);
  } catch (_) {}
}

function isAtmosUnavailable(trackId) {
  const cleanId = String(trackId).replace(/^track:/, '').trim();
  const db = getDb();
  try {
    const row = db.prepare('SELECT infohash FROM torbox_cache WHERE track_id = ? AND quality = ?').get(cleanId, 'DOLBY ATMOS');
    if (row && row.infohash === 'UNAVAILABLE') return true;
    const meta = db.prepare('SELECT is_atmos FROM track_meta WHERE track_id = ?').get(cleanId);
    if (meta && meta.is_atmos === 0) return true;
  } catch (_) {}
  return false;
}

// ── Stats Counters API ────────────────────────────────────────────────────────

function incrementStat(name, delta = 1) {
  const db = getDb();
  const now = Date.now();
  db.prepare(`
    INSERT INTO stats_counters (name, count, updated_at)
    VALUES (?, ?, ?)
    ON CONFLICT(name) DO UPDATE SET
      count = count + excluded.count,
      updated_at = excluded.updated_at
  `).run(name, delta, now);
}

function getStats() {
  const db = getDb();
  const rows = db.prepare('SELECT name, count FROM stats_counters').all();
  const res = {
    searches: 0,
    streams_direct: 0,
    streams_forwarded: 0,
  };
  for (const r of rows) {
    res[r.name] = r.count;
  }
  return res;
}

// ── Trace Logs API ────────────────────────────────────────────────────────────

function insertTrace(trace) {
  const db = getDb();
  try {
    let route = trace.route || '';
    if (Array.isArray(route)) route = route[0] || '';
    else if (typeof route !== 'string') route = String(route);

    let ip = trace.ip || '127.0.0.1';
    if (typeof ip !== 'string') ip = String(ip);

    let country = trace.country || 'XX';
    if (typeof country !== 'string') country = String(country);

    let method = trace.method || 'GET';
    if (typeof method !== 'string') method = String(method);

    let url = trace.url || '';
    if (typeof url !== 'string') url = String(url);

    let userAgent = trace.userAgent || '';
    if (typeof userAgent !== 'string') userAgent = String(userAgent);

    let rayId = trace.rayId || '';
    if (typeof rayId !== 'string') rayId = String(rayId);

    let eventType = trace.eventType || '';
    if (typeof eventType !== 'string') eventType = String(eventType);

    const timestamp = Number(trace.timestamp) || Date.now();
    const status = Number.isInteger(trace.status) ? trace.status : 200;
    const durationMs = Number(trace.durationMs) || 0;
    const bytesSent = Number(trace.bytesSent) || 0;
    const details = trace.details ? (typeof trace.details === 'string' ? trace.details : JSON.stringify(trace.details)) : '';

    return db.prepare(`
      INSERT INTO trace_logs (timestamp, ip, country, method, url, route, status, duration_ms, user_agent, ray_id, bytes_sent, event_type, details)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      timestamp,
      ip,
      country,
      method,
      url,
      route,
      status,
      durationMs,
      userAgent,
      rayId,
      bytesSent,
      eventType,
      details
    );
  } catch (err) {
    // Logging failure should never crash the server
    console.error('[TraceLog Error]:', err.message);
  }
}

function getTraces({ limit = 100, offset = 0, ip, status, search, minDuration, eventType } = {}) {
  const db = getDb();
  let sql = 'SELECT * FROM trace_logs WHERE 1=1';
  const params = [];

  if (eventType) {
    sql += ' AND event_type = ?';
    params.push(eventType);
  }
  if (ip) {
    sql += ' AND ip = ?';
    params.push(ip);
  }
  if (status) {
    if (status === 'error') {
      sql += ' AND status >= 400';
    } else if (status === '2xx') {
      sql += ' AND status >= 200 AND status < 300';
    } else {
      sql += ' AND status = ?';
      params.push(parseInt(status, 10));
    }
  }
  if (minDuration) {
    sql += ' AND duration_ms >= ?';
    params.push(parseFloat(minDuration));
  }
  if (search) {
    sql += ' AND (url LIKE ? OR ip LIKE ? OR route LIKE ?)';
    const s = `%${search}%`;
    params.push(s, s, s);
  }

  sql += ' ORDER BY id DESC LIMIT ? OFFSET ?';
  params.push(Math.min(limit, 500), offset);

  return db.prepare(sql).all(...params).map(r => ({
    ...r,
    durationMs: r.duration_ms != null ? r.duration_ms : 0,
    rayId: r.ray_id || '',
    userAgent: r.user_agent || '',
    bytesSent: r.bytes_sent || 0,
    eventType: r.event_type || '',
  }));
}

/**
 * @param {object} [options]
 * @param {'rolling24h'|'today'} [options.mode='rolling24h']
 *   'today'      — from UTC midnight of the current calendar day (resets at 00:00 UTC)
 *   'rolling24h' — traditional last-24-hours rolling window
 */
function getTraceMetrics({ mode = 'rolling24h' } = {}) {
  const db = getDb();
  const now = Date.now();

  let since;
  if (mode === 'today') {
    // Start of current UTC day (resets at midnight UTC)
    const todayStr = new Date(now).toISOString().slice(0, 10);
    since = new Date(todayStr + 'T00:00:00.000Z').getTime();
  } else {
    since = now - 24 * 3600 * 1000;
  }

  const windowLabel = mode === 'today' ? 'today' : 'last24h';

  const totalRow = db.prepare('SELECT COUNT(*) as count, AVG(duration_ms) as avg_lat FROM trace_logs WHERE timestamp >= ?').get(since);
  const total = totalRow?.count || 0;
  const avgLatency = Math.round(totalRow?.avg_lat || 0);

  const errorRow = db.prepare('SELECT COUNT(*) as count FROM trace_logs WHERE timestamp >= ? AND status >= 400').get(since);
  const errors = errorRow?.count || 0;
  const errorRate = total > 0 ? ((errors / total) * 100).toFixed(1) : '0.0';

  const eventCounts = db.prepare(`
    SELECT 
      SUM(CASE WHEN event_type = 'search' THEN 1 ELSE 0 END) as searches,
      SUM(CASE WHEN event_type = 'stream_direct' THEN 1 ELSE 0 END) as streams_direct,
      SUM(CASE WHEN event_type = 'stream_forwarded' THEN 1 ELSE 0 END) as streams_forwarded
    FROM trace_logs WHERE timestamp >= ?
  `).get(since) || {};

  const allTimeStats = getStats();

  const statusRows = db.prepare(`
    SELECT 
      CASE 
        WHEN status >= 200 AND status < 300 THEN '2xx'
        WHEN status >= 300 AND status < 400 THEN '3xx'
        WHEN status >= 400 AND status < 500 THEN '4xx'
        ELSE '5xx'
      END as grp, COUNT(*) as count
    FROM trace_logs WHERE timestamp >= ?
    GROUP BY grp
  `).all(since);

  const topRoutes = db.prepare(`
    SELECT route, COUNT(*) as count, AVG(duration_ms) as avg_lat
    FROM trace_logs WHERE timestamp >= ?
    GROUP BY route ORDER BY count DESC LIMIT 8
  `).all(since);

  const topIps = db.prepare(`
    SELECT ip, country, COUNT(*) as count, MAX(timestamp) as last_seen
    FROM trace_logs WHERE timestamp >= ?
    GROUP BY ip ORDER BY count DESC LIMIT 10
  `).all(since);

  return {
    total,
    errors,
    errorRate: parseFloat(errorRate),
    avgLatency,
    windowLabel,
    since,
    statusBreakdown: statusRows,
    topRoutes,
    topIps,
    searches: {
      today: eventCounts.searches || 0,
      allTime: allTimeStats.searches || 0,
    },
    streamsDirect: {
      today: eventCounts.streams_direct || 0,
      allTime: allTimeStats.streams_direct || 0,
    },
    streamsForwarded: {
      today: eventCounts.streams_forwarded || 0,
      allTime: allTimeStats.streams_forwarded || 0,
    },
  };
}

const ONE_DAY_MS = 24 * 60 * 60 * 1000;
const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_TRACE_LOGS = 10000; // 10k rows max (1 day only)

function rollupDailyMetrics(dateStr, forceFinalize = false) {
  const db = getDb();
  const now = Date.now();
  const todayStr = new Date(now).toISOString().slice(0, 10);
  const targetDate = dateStr || todayStr;
  const isPastDay = targetDate < todayStr;

  // If this past day is already marked finalized, do not overwrite with partial trace data
  if (isPastDay && !forceFinalize) {
    const existing = db.prepare('SELECT is_finalized FROM daily_metrics WHERE date = ?').get(targetDate);
    if (existing && existing.is_finalized === 1) {
      return;
    }
  }

  const startOfDay = new Date(targetDate + 'T00:00:00Z').getTime();
  const endOfDay = startOfDay + ONE_DAY_MS;

  const summary = db.prepare(`
    SELECT 
      COUNT(*) as total,
      SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) as errors,
      AVG(duration_ms) as avg_lat,
      SUM(CASE WHEN event_type = 'search' THEN 1 ELSE 0 END) as total_searches,
      SUM(CASE WHEN event_type = 'stream_direct' THEN 1 ELSE 0 END) as total_streams_direct,
      SUM(CASE WHEN event_type = 'stream_forwarded' THEN 1 ELSE 0 END) as total_streams_forwarded
    FROM trace_logs
    WHERE timestamp >= ? AND timestamp < ?
  `).get(startOfDay, endOfDay);

  if (!summary || summary.total === 0) return;

  const routes = db.prepare(`
    SELECT route, COUNT(*) as count
    FROM trace_logs
    WHERE timestamp >= ? AND timestamp < ?
    GROUP BY route ORDER BY count DESC LIMIT 30
  `).all(startOfDay, endOfDay);

  const routeHits = {};
  for (const r of routes) routeHits[r.route || '/'] = r.count;

  const statuses = db.prepare(`
    SELECT 
      CASE 
        WHEN status >= 200 AND status < 300 THEN '2xx'
        WHEN status >= 300 AND status < 400 THEN '3xx'
        WHEN status >= 400 AND status < 500 THEN '4xx'
        ELSE '5xx'
      END as grp, COUNT(*) as count
    FROM trace_logs
    WHERE timestamp >= ? AND timestamp < ?
    GROUP BY grp
  `).all(startOfDay, endOfDay);

  const statusMap = {};
  for (const s of statuses) statusMap[s.grp] = s.count;

  const topIps = db.prepare(`
    SELECT ip, country, COUNT(*) as hits
    FROM trace_logs
    WHERE timestamp >= ? AND timestamp < ?
    GROUP BY ip ORDER BY hits DESC LIMIT 25
  `).all(startOfDay, endOfDay);

  const finalizedValue = (isPastDay || forceFinalize) ? 1 : 0;

  db.prepare(`
    INSERT INTO daily_metrics (
      date, total_requests, total_searches, total_streams_direct, total_streams_forwarded,
      error_count, avg_latency_ms, endpoint_hits, status_breakdown, top_ips, is_finalized, updated_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(date) DO UPDATE SET
      total_requests          = excluded.total_requests,
      total_searches          = excluded.total_searches,
      total_streams_direct    = excluded.total_streams_direct,
      total_streams_forwarded = excluded.total_streams_forwarded,
      error_count             = excluded.error_count,
      avg_latency_ms          = excluded.avg_latency_ms,
      endpoint_hits           = excluded.endpoint_hits,
      status_breakdown        = excluded.status_breakdown,
      top_ips                 = excluded.top_ips,
      is_finalized            = excluded.is_finalized,
      updated_at              = excluded.updated_at
  `).run(
    targetDate,
    summary.total,
    summary.total_searches || 0,
    summary.total_streams_direct || 0,
    summary.total_streams_forwarded || 0,
    summary.errors || 0,
    Math.round(summary.avg_lat || 0),
    JSON.stringify(routeHits),
    JSON.stringify(statusMap),
    JSON.stringify(topIps),
    finalizedValue,
    now
  );
}

function getDailyMetrics(days = 30) {
  const db = getDb();
  // Ensure today's metrics are fresh
  try { rollupDailyMetrics(); } catch (e) { }

  const rows = db.prepare(`
    SELECT * FROM daily_metrics
    ORDER BY date DESC LIMIT ?
  `).all(days);

  return rows.map(r => ({
    date: r.date,
    totalRequests: r.total_requests,
    totalSearches: r.total_searches || 0,
    totalStreamsDirect: r.total_streams_direct || 0,
    totalStreamsForwarded: r.total_streams_forwarded || 0,
    errorCount: r.error_count,
    errorRate: r.total_requests > 0 ? ((r.error_count / r.total_requests) * 100).toFixed(1) : '0.0',
    avgLatencyMs: Math.round(r.avg_latency_ms),
    endpointHits: JSON.parse(r.endpoint_hits || '{}'),
    statusBreakdown: JSON.parse(r.status_breakdown || '{}'),
    topIps: JSON.parse(r.top_ips || '[]'),
    isFinalized: Boolean(r.is_finalized),
    updatedAt: r.updated_at,
    ingress_bytes: r.ingress_bytes || 0,
    egress_bytes: r.egress_bytes || 0,
    peak_ingress_bps: r.peak_ingress_bps || 0,
    peak_egress_bps: r.peak_egress_bps || 0,
  }));
}

function initDailyMetrics(db, dateStr) {
  const row = db.prepare('SELECT 1 FROM daily_metrics WHERE date = ?').get(dateStr);
  if (!row) {
    db.prepare('INSERT OR IGNORE INTO daily_metrics (date, updated_at) VALUES (?, ?)').run(dateStr, Date.now());
  }
}

function recordBandwidth(ingressBytes, egressBytes, currentIngressBps, currentEgressBps) {
  const db = getDb();
  const dateStr = new Date().toISOString().split('T')[0];
  initDailyMetrics(db, dateStr);

  try {
    const updateSql = `
      UPDATE daily_metrics 
      SET 
        ingress_bytes = ingress_bytes + ?,
        egress_bytes = egress_bytes + ?,
        peak_ingress_bps = MAX(peak_ingress_bps, ?),
        peak_egress_bps = MAX(peak_egress_bps, ?),
        updated_at = ?
      WHERE date = ?
    `;
    db.prepare(updateSql).run(ingressBytes, egressBytes, currentIngressBps, currentEgressBps, Date.now(), dateStr);
  } catch (err) {
    console.error('[DB] Failed to record bandwidth:', err.message);
  }
}

function pruneOldTraces(keepCount = MAX_TRACE_LOGS) {
  const db = getDb();
  const now = Date.now();
  const todayStr = new Date(now).toISOString().slice(0, 10);

  // 1. Roll up all dates present in trace_logs before deleting anything.
  // Any past dates are finalized into daily_metrics so 30-day historical data is never lost.
  try {
    const distinctDates = db.prepare(`
      SELECT DISTINCT strftime('%Y-%m-%d', timestamp / 1000, 'unixepoch') as d
      FROM trace_logs
    `).all();

    for (const row of distinctDates) {
      if (row && row.d) {
        rollupDailyMetrics(row.d, row.d < todayStr);
      }
    }
  } catch (e) {
    console.error('[DB Rollup Error]:', e.message);
  }

  // 2. 1-day trace log cutoff: delete traces older than 24 hours
  const oneDayAgo = now - ONE_DAY_MS;
  const timeDeleted = db.prepare('DELETE FROM trace_logs WHERE timestamp < ?').run(oneDayAgo);
  if (timeDeleted.changes > 0) {
    console.log(`[DB Prune] Purged ${timeDeleted.changes} trace logs older than 1 day.`);
  }

  // 3. 10,000 max row limit (FIFO)
  const countRow = db.prepare('SELECT COUNT(*) as c FROM trace_logs').get();
  if (countRow && countRow.c > keepCount) {
    const toDelete = countRow.c - keepCount;
    const countDeleted = db.prepare(`
      DELETE FROM trace_logs WHERE id IN (
        SELECT id FROM trace_logs ORDER BY id ASC LIMIT ?
      )
    `).run(toDelete);
    if (countDeleted.changes > 0) {
      console.log(`[DB Prune] Purged ${countDeleted.changes} trace logs to enforce 10k row limit.`);
    }
  }

  // 4. Prune daily metrics older than 30 days
  const thirtyDaysAgo = new Date(now - THIRTY_DAYS_MS).toISOString().slice(0, 10);
  const dailyDeleted = db.prepare('DELETE FROM daily_metrics WHERE date < ?').run(thirtyDaysAgo);
  if (dailyDeleted.changes > 0) {
    console.log(`[DB Prune] Purged ${dailyDeleted.changes} daily metric entries older than 30 days.`);
  }
}

// ── IP Rules API ──────────────────────────────────────────────────────────────

function getAllIpRules() {
  const db = getDb();
  return db.prepare('SELECT * FROM ip_rules ORDER BY updated_at DESC').all();
}

function getIpRule(ip) {
  const db = getDb();
  return db.prepare('SELECT * FROM ip_rules WHERE ip = ?').get(ip);
}

function setIpRule(ip, action, rateLimit = 60, reason = '') {
  const db = getDb();
  const now = Date.now();
  db.prepare(`
    INSERT INTO ip_rules (ip, action, rate_limit, reason, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(ip) DO UPDATE SET
      action     = excluded.action,
      rate_limit = excluded.rate_limit,
      reason     = excluded.reason,
      updated_at = excluded.updated_at
  `).run(ip, action, rateLimit, reason, now, now);
}

function removeIpRule(ip) {
  const db = getDb();
  db.prepare('DELETE FROM ip_rules WHERE ip = ?').run(ip);
}

// ── Database Diagnostics API ──────────────────────────────────────────────────

function getDatabaseDiagnostics() {
  const db = getDb();
  let dbFileSize = 0;
  try {
    if (fs.existsSync(DB_PATH)) dbFileSize += fs.statSync(DB_PATH).size;
    const walPath = DB_PATH + '-wal';
    if (fs.existsSync(walPath)) dbFileSize += fs.statSync(walPath).size;
    const shmPath = DB_PATH + '-shm';
    if (fs.existsSync(shmPath)) dbFileSize += fs.statSync(shmPath).size;
  } catch (e) { }

  const searchCacheCount = db.prepare('SELECT COUNT(*) as c FROM search_cache').get()?.c || 0;
  const searchCacheBytes = db.prepare('SELECT COALESCE(SUM(size_bytes), 0) as s FROM search_cache').get()?.s || 0;

  const torboxCacheCount = db.prepare('SELECT COUNT(*) as c FROM torbox_cache').get()?.c || 0;
  const torboxUniqueTracks = db.prepare('SELECT COUNT(DISTINCT track_id) as c FROM torbox_cache').get()?.c || 0;

  const trackMetaCount = db.prepare('SELECT COUNT(*) as c FROM track_meta').get()?.c || 0;
  const kvCount = db.prepare('SELECT COUNT(*) as c FROM kv_store').get()?.c || 0;
  const ipRulesCount = db.prepare('SELECT COUNT(*) as c FROM ip_rules').get()?.c || 0;
  const traceLogsCount = db.prepare('SELECT COUNT(*) as c FROM trace_logs').get()?.c || 0;
  const dailyMetricsCount = db.prepare('SELECT COUNT(*) as c FROM daily_metrics').get()?.c || 0;

  return {
    fileSizeBytes: dbFileSize,
    fileSizeMb: (dbFileSize / (1024 * 1024)).toFixed(2),
    searchCache: {
      count: searchCacheCount,
      sizeBytes: searchCacheBytes,
      sizeMb: (searchCacheBytes / (1024 * 1024)).toFixed(2),
      maxLimitMb: 1024,
    },
    trackMeta: {
      count: trackMetaCount,
      description: 'Instant track metadata index (ISRC, artwork, duration)',
    },
    torboxCache: {
      count: torboxCacheCount,
      uniqueTracks: torboxUniqueTracks,
    },
    kvStore: {
      count: kvCount,
    },
    ipRules: {
      count: ipRulesCount,
    },
    traceLogs: {
      count: traceLogsCount,
      retention: '1 Day (10,000 max rows)',
    },
    dailyMetrics: {
      count: dailyMetricsCount,
      retention: '30 Days Essential Aggregates',
    },
    statsCounters: {
      count: db.prepare('SELECT COUNT(*) as c FROM stats_counters').get()?.c || 0,
      allTime: getStats(),
    },
  };
}

function clearAllSearchCache() {
  const db = getDb();
  const info = db.prepare('DELETE FROM search_cache').run();
  return info.changes;
}

function clearAllTraces() {
  const db = getDb();
  const info = db.prepare('DELETE FROM trace_logs').run();
  return info.changes;
}

function vacuumDb() {
  const db = getDb();
  db.exec('VACUUM');
}

// ── Cleanup Scheduler ─────────────────────────────────────────────────────────

// Run daily rollup every 5 minutes to keep current day's totals fresh
setInterval(() => {
  try { rollupDailyMetrics(); } catch (e) { }
}, 5 * 60 * 1000).unref();

// Run expired search cache cleanup and trace pruning every hour
setInterval(() => {
  cleanExpiredSearchCache();
  pruneOldTraces();
}, 60 * 60 * 1000).unref();

// ── Plus Members ──────────────────────────────────────────────────────────────

function isPlusMember(apiKey) {
  if (!apiKey) return false;
  try {
    const db = getDb();
    const row = db.prepare('SELECT expires_at FROM plus_members WHERE api_key = ?').get(apiKey.trim());
    if (!row) return false;
    return row.expires_at > Date.now();
  } catch (err) {
    console.error('[Plus Error]', err.message);
    return false;
  }
}

function addPlusMember(apiKey, months) {
  if (!apiKey) return false;
  const cleanKey = apiKey.trim();
  const db = getDb();
  const now = Date.now();

  const current = db.prepare('SELECT expires_at FROM plus_members WHERE api_key = ?').get(cleanKey);
  let newExpiry = now;
  if (current && current.expires_at > now) {
    newExpiry = current.expires_at;
  }

  const msToAdd = months * 30 * 24 * 60 * 60 * 1000;
  newExpiry += msToAdd;

  const stmt = db.prepare(`
    INSERT INTO plus_members (api_key, expires_at, updated_at) 
    VALUES (?, ?, ?)
    ON CONFLICT(api_key) DO UPDATE SET 
      expires_at = excluded.expires_at,
      updated_at = excluded.updated_at
  `);
  stmt.run(cleanKey, newExpiry, now);
  return { apiKey: cleanKey, expires_at: newExpiry };
}

function removePlusMember(apiKey) {
  if (!apiKey) return false;
  const db = getDb();
  const info = db.prepare('DELETE FROM plus_members WHERE api_key = ?').run(apiKey.trim());
  return info.changes > 0;
}

function getAllPlusMembers() {
  const db = getDb();
  return db.prepare('SELECT * FROM plus_members ORDER BY expires_at DESC').all();
}


// ── API Key Bans ──────────────────────────────────────────────────────────────

function getBannedKey(apiKey) {
  if (!apiKey) return null;
  const db = getDb();
  return db.prepare('SELECT * FROM api_key_bans WHERE api_key = ?').get(apiKey.trim()) || null;
}

function addBannedKey(apiKey, tier = 'BAN', reason = '') {
  if (!apiKey) return false;
  const db = getDb();
  const cleanKey = apiKey.trim();
  db.prepare(`
    INSERT INTO api_key_bans (api_key, tier, reason, created_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(api_key) DO UPDATE SET tier = excluded.tier, reason = excluded.reason, created_at = excluded.created_at, troll_torrent_id = ''
  `).run(cleanKey, tier.toUpperCase(), reason, Date.now());
  return true;
}

function removeBannedKey(apiKey) {
  if (!apiKey) return false;
  const db = getDb();
  const info = db.prepare('DELETE FROM api_key_bans WHERE api_key = ?').run(apiKey.trim());
  return info.changes > 0;
}

function getAllBannedKeys() {
  const db = getDb();
  return db.prepare('SELECT * FROM api_key_bans ORDER BY created_at DESC').all();
}

function setTrollTorrentId(apiKey, torrentId) {
  if (!apiKey || !torrentId) return false;
  const db = getDb();
  db.prepare('UPDATE api_key_bans SET troll_torrent_id = ? WHERE api_key = ? AND tier = ?')
    .run(String(torrentId), apiKey.trim(), 'TROLL');
  return true;
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
  getDb,

  // Settings
  settings: {
    get: settingsGet,
    set: settingsSet,
    getAll: settingsGetAll,
  },
  // KV
  kv: {
    get: kvGet,
    put: kvPut,
    getAll: kvGetAll,
    remove: kvDelete,
  },

  // Stats Counters (All-Time)
  stats: {
    increment: incrementStat,
    get: getStats,
  },

  // Search Cache
  searchCache: {
    buildKey: buildSearchCacheKey,
    get: getSearchCache,
    getWithMeta: getSearchCacheWithMeta,
    set: setSearchCache,
    cleanExpired: cleanExpiredSearchCache,
    clearAll: clearAllSearchCache,
    findTrackInCache: findTrackInCache,
    findTrackByIsrc: findTrackByIsrc,
    findTracksInBatch: findTracksInBatch,
    saveTracksMeta: saveTracksMeta,
  },

  // Track Metadata
  trackMeta: {
    get: findTrackInCache,
    findByIsrc: findTrackByIsrc,
    findInBatch: findTracksInBatch,
    save: saveTracksMeta,
    markHiresUnavailable: markHiresUnavailable,
    isHiresUnavailable: isHiresUnavailable,
    markAtmosUnavailable: markAtmosUnavailable,
    isAtmosUnavailable: isAtmosUnavailable,
  },

  // TorBox Cache
  torboxCache: {
    write: writeTorboxCache,
    markHiresUnavailable: markHiresUnavailable,
    isHiresUnavailable: isHiresUnavailable,
    markAtmosUnavailable: markAtmosUnavailable,
    isAtmosUnavailable: isAtmosUnavailable,
    lookupBadges: lookupTorboxBadges,
    lookupStreamHit: lookupStreamHit,
  },

  // WebSeed Files Tracking


  // Trace Logs
  traceLogs: {
    insert: insertTrace,
    get: getTraces,
    getMetrics: getTraceMetrics,
    prune: pruneOldTraces,
    clearAll: clearAllTraces,
  },

  // 30-Day Daily Metrics Rollup
  dailyMetrics: {
    rollup: rollupDailyMetrics,
    getHistory: getDailyMetrics, recordBandwidth,
  },

  // IP Security Rules
  ipRules: {
    getAll: getAllIpRules,
    get: getIpRule,
    set: setIpRule,
    remove: removeIpRule,
  },

  // Database Diagnostics
  dbStats: {
    get: getDatabaseDiagnostics,
    vacuum: vacuumDb,
  },

  // Plus Members


  // API Key Bans (BAN tier = 403, TROLL tier = rickroll)
  bannedKeys: {
    get: getBannedKey,
    add: addBannedKey,
    remove: removeBannedKey,
    getAll: getAllBannedKeys,
    setTrollTorrentId: setTrollTorrentId,
  },
};
