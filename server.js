'use strict';

/**
 * NullBeat Lite — Self-Hostable Lossless Music Server
 *
 * Direct TorBox playback on cache hits; forwards uncached requests to the Head Server.
 * All metadata, caching, user management, and security firewalls run locally.
 */

// ── Load .env ─────────────────────────────────────────────────────────────────
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

const { createHash } = require('node:crypto');
const express = require('express');
const cors = require('cors');

const { kv, searchCache, torboxCache, stats, bannedKeys, trackMeta } = require('./db');
const { injectCacheInfo, lookupAndInjectBadges, checkSingleTrackCache } = require('./cache_injector');
const { fetchWithFailover, tidalSearch, parseIsoDuration, getTidalArtist, getTidalV1Artist, getTidalAlbum, getTidalOpenApiTracks } = require('./tidal');
const { securityMiddleware } = require('./security');
const { traceLoggerMiddleware } = require('./logger');
const { createAdminServer } = require('./admin');

const app = express();
const PORT = process.env.PORT || 3000;

function getHeadServerUrl() {
  let url = (process.env.HEAD_SERVER_URL || '').trim();
  if (!url) url = 'https://nullbeat.thevolecitor.qzz.io';
  if (!/^https?:\/\//i.test(url)) {
    url = 'https://' + url;
  }
  return url.replace(/\/+$/, '');
}

const SEARCH_CACHE_TTL = parseInt(process.env.SEARCH_CACHE_TTL || '86400', 10); // 24h default
const STALE_THRESHOLD_MS = parseInt(process.env.SEARCH_STALE_THRESHOLD || '43200', 10) * 1000; // 12h: serve from cache but background-refresh
const METADATA_CACHE_CONTROL = process.env.METADATA_CACHE_CONTROL || 'public, max-age=300';

// ── Troll Ban Constants ────────────────────────────────────────────────────────
const TROLL_TRACK_ID = '491206012'; // "Never Gonna Give You Up" Tidal track
const TROLL_ALBUM_ID = '492950065'; // Rickroll album
const TROLL_ARTIST_ID = '1798';      // Rick Astley

app.use(cors());
app.use(express.json());
app.set('trust proxy', 1);
app.use(traceLoggerMiddleware);
app.use(securityMiddleware);

// Public instance config & head server discovery
app.get(['/api/config', '/api/info', '/api/head-url'], (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=60');
  res.json({
    name: 'NullBeat Lite',
    version: '1.0.0-lite',
    headServerUrl: getHeadServerUrl()
  });
});

// Strictly block any Control Plane / Admin access on the public API port (port 3000)
app.use((req, res, next) => {
  const p = req.path.toLowerCase();
  if (
    p === '/admin' || p.startsWith('/admin/') ||
    p.startsWith('/api/traces') ||
    p.startsWith('/api/metrics') ||
    p.startsWith('/api/db') ||
    p.startsWith('/api/env') ||
    p.startsWith('/api/security') ||
    p.startsWith('/api/auth') ||
    p.startsWith('/api/setup') ||
    p === '/login' || p === '/logout'
  ) {
    return res.status(404).json({
      error: 'Not Found',
      message: 'NullBeat Control Plane is strictly restricted to ADMIN_PORT (default 3001)'
    });
  }
  next();
});
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('favicon.png') || filePath.endsWith('favicon.ico')) {
      res.setHeader('Cache-Control', 'public, max-age=604800, s-maxage=2592000, stale-while-revalidate=86400');
      res.setHeader('CDN-Cache-Control', 'max-age=2592000');
      res.setHeader('Cloudflare-CDN-Cache-Control', 'max-age=2592000');
    } else if (filePath.endsWith('logo_plus.gif')) {
      res.setHeader('Cache-Control', 'public, max-age=31536000, s-maxage=31536000, immutable');
      res.setHeader('CDN-Cache-Control', 'max-age=31536000');
      res.setHeader('Cloudflare-CDN-Cache-Control', 'max-age=31536000');
    } else if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'public, max-age=21600, must-revalidate');
    }
  }
}));

// ── Constants ─────────────────────────────────────────────────────────────────

const SEP = '|||';

const FALLBACK_CHAINS = {
  MAX: ['HI_RES_LOSSLESS', 'LOSSLESS', 'HIGH', 'LOW'],
  HIRES: ['HI_RES_LOSSLESS', 'LOSSLESS', 'HIGH', 'LOW'],
  LOSSLESS: ['LOSSLESS', 'HIGH', 'LOW'],
  HIGH: ['HIGH', 'LOW'],
  LOW: ['LOW'],
};

const QUALITY_LABELS = {
  MAX: 'Max (Auto)', HIRES: 'Hi-Res FLAC',
  LOSSLESS: 'HiFi Lossless', HIGH: 'AAC 320 kbps', LOW: 'AAC 96 kbps',
};

const VALID_QUALITIES = Object.keys(FALLBACK_CHAINS);
const DEFAULT_QUALITY = 'MAX';
const TIDAL_IMG = 'https://resources.tidal.com/images';

// ── Utilities ─────────────────────────────────────────────────────────────────

function formatQualityOutput(q) {
  if (!q) return '16bit/44.1khz';
  const lq = String(q).toLowerCase();
  if (lq === 'hifi cd' || lq.includes('hifi') || lq.includes('cd') || lq === 'lossless' || lq.includes('16bit') || lq.includes('44.1')) {
    return '16bit/44.1khz';
  }
  if (lq.includes('hires') || lq.includes('hi-res')) {
    return 'Hi-Res';
  }
  if (lq.includes('320')) {
    return '320kbps';
  }
  if (lq.includes('96')) {
    return '96kbps';
  }
  return q;
}

function enrichStreamMeta(baseObj, qualityStr, formatStr, isrc = null) {
  const q = formatQualityOutput(qualityStr);
  const isFlac = formatStr === 'flac' || q === '16bit/44.1khz' || q === 'Hi-Res';
  const fmt = isFlac ? 'flac' : (formatStr || 'm4a');

  const meta = {
    ...baseObj,
    format: fmt,
    quality: q,
    codec: isFlac ? 'flac' : 'aac',
    container: isFlac ? 'flac' : 'fmp4',
  };

  const finalIsrc = isrc || baseObj?.isrc;
  if (finalIsrc) {
    meta.isrc = String(finalIsrc);
  }

  if (q === '16bit/44.1khz') {
    meta.sampleRate = 44100;
    meta.bitDepth = 16;
  }

  return meta;
}

function tidalCover(id, size = 640) {
  if (!id) return '';
  if (typeof id === 'string' && (id.startsWith('http://') || id.startsWith('https://'))) return id;
  return `${TIDAL_IMG}/${String(id).replace(/-/g, '/')}/${size}x${size}.jpg`;
}

function b64Encode(str) {
  return Buffer.from(str).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64Decode(str) {
  const pad = str.length % 4;
  const s = pad ? str + '='.repeat(4 - pad) : str;
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf-8');
}

function normalizeQuality(val, fallback = DEFAULT_QUALITY) {
  if (!val || typeof val !== 'string') return fallback;
  const upper = val.trim().toUpperCase();
  if (upper === 'MAX' || upper === 'AUTO') return 'MAX';
  if (upper === 'HIRES' || upper === 'HI-RES' || upper === 'HI_RES' || upper === 'HI_RES_LOSSLESS') return 'HIRES';
  if (upper === 'LOSSLESS' || upper === 'HIFI' || upper === 'CD' || upper === 'FLAC') return 'LOSSLESS';
  if (upper === 'HIGH' || upper === '320' || upper === '320KBPS' || upper === 'NORMAL' || upper === '160') return 'HIGH';
  if (upper === 'LOW' || upper === '96' || upper === '96KBPS') return 'LOW';
  if (VALID_QUALITIES.includes(upper)) return upper;
  return fallback;
}

function decodeToken(enc) {
  try {
    const raw = b64Decode(enc);
    const parts = raw.split(SEP);
    const torboxApiKey = parts[0] || '';
    let q = parts[1] ? normalizeQuality(parts[1], DEFAULT_QUALITY) : DEFAULT_QUALITY;
    return { torboxApiKey, quality: q };
  } catch {
    return { torboxApiKey: '', quality: DEFAULT_QUALITY };
  }
}

function md5(text) {
  return createHash('md5').update(text).digest('hex');
}

function extractItems(res, ...paths) {
  if (!res) return [];
  for (const p of paths) {
    let cur = res;
    let ok = true;
    for (const key of p) {
      if (cur == null || typeof cur !== 'object') { ok = false; break; }
      cur = cur[key];
    }
    if (ok && Array.isArray(cur)) return cur.map(i => (i && i.item) ? i.item : i);
  }
  return [];
}

function mapTrack(t, base, enc) {
  if (!t || !t.id) return null;
  const tags = t.mediaMetadata?.tags || [];
  const artist =
    t.artist?.name ||
    (typeof t.artist === 'string' ? t.artist : null) ||
    t.artists?.find(a => a?.type === 'MAIN')?.name ||
    t.artists?.[0]?.name ||
    t.album?.artist?.name ||
    (typeof t.album?.artist === 'string' ? t.album.artist : null) ||
    t.album?.artists?.[0]?.name ||
    '';

  const albumTitle =
    t.album?.title ||
    t.album?.name ||
    (typeof t.album === 'string' ? t.album : '') ||
    '';

  const rawCover = t.artworkURL || t.album?.cover || t.cover || '';
  const coverUrl = tidalCover(rawCover, 640) || (base ? `${base}/favicon.png` : '');

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
  const isHiRes = Boolean(hasHires);
  if (!isHiRes && t.id) {
    torboxCache.markHiresUnavailable(String(t.id));
  }

  return {
    id: String(t.id),
    title: t.title || t.name || 'Unknown',
    artist: artist || 'Unknown',
    album: albumTitle || 'Unknown',
    duration: t.duration || 0,
    isrc: t.isrc || '',
    artworkURL: coverUrl,
    isHiRes: isHiRes,
  };
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ── Key Validation & User Registration (Floodgate with KV Store) ────────────

async function isKeyAllowed(apiKey, inviteCode = null) {
  if (!apiKey) return false;
  const cleanKey = String(apiKey).trim().toLowerCase();
  const ban = bannedKeys.get(cleanKey);
  if (ban && ban.tier === 'BAN') return false;

  const allowedKeysRaw = process.env.ALLOWED_KEYS;
  if (allowedKeysRaw && allowedKeysRaw.trim() !== '' && allowedKeysRaw.trim() !== '*') {
    const list = allowedKeysRaw.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
    if (list.includes(cleanKey)) return true;
  }

  const maxUsersRaw = process.env.MAX_USERS;
  const maxUsers = maxUsersRaw ? parseInt(maxUsersRaw, 10) : 0;
  const maxInvitedUsers = parseInt(process.env.MAX_INVITE_POOL || '50', 10);

  try {
    const registeredRaw = kv.get('registered_keys');
    const invitedRaw = kv.get('invited_keys');
    let registered = registeredRaw ? JSON.parse(registeredRaw) : [];
    let invited = invitedRaw ? JSON.parse(invitedRaw) : [];

    if (registered.includes(cleanKey) || invited.includes(cleanKey)) return true;

    if (inviteCode) {
      try {
        const decoded = Buffer.from(inviteCode, 'base64').toString('utf-8');
        const parts = decoded.split('.');
        if (parts.length === 2) {
          const salt = parseInt(parts[0], 10);
          const signature = parts[1];

          if (!isNaN(salt) && salt % 2 === 0) {
            const expectedSig = md5(String(salt) + (process.env.INVITE_SECRET || ''));
            if (signature === expectedSig) {
              const countsRaw = kv.get('invite_counts');
              const inviteCounts = countsRaw ? JSON.parse(countsRaw) : {};
              const validSalts = Array.isArray(inviteCounts.salts) ? inviteCounts.salts : [];
              const saltIdx = validSalts.indexOf(salt);
              if (saltIdx === -1) {
                console.log(`[Floodgate] Invite already used (salt: ${salt})`);
                return false;
              }
              validSalts.splice(saltIdx, 1);
              inviteCounts.salts = validSalts;

              if (maxInvitedUsers <= 0 || invited.length < maxInvitedUsers) {
                invited.push(cleanKey);
                kv.put('invited_keys', JSON.stringify(invited));
                kv.put('invite_counts', JSON.stringify(inviteCounts));
                console.log(`[Floodgate] Registered INVITED user: ...${cleanKey.slice(-4)}`);
                return true;
              } else {
                console.log(`[Floodgate] Invite pool closed (${invited.length}/${maxInvitedUsers})`);
                return false;
              }
            }
          }
        }
      } catch {
        return false;
      }
      return false;
    }

    if (maxUsers <= 0 || registered.length < maxUsers) {
      registered.push(cleanKey);
      kv.put('registered_keys', JSON.stringify(registered));
      console.log(`[Floodgate] Registered new user (${registered.length}${maxUsers > 0 ? '/' + maxUsers : ''}): ...${cleanKey.slice(-4)}`);
      return true;
    }

    console.log(`[Floodgate] Registration closed (${registered.length}/${maxUsers}).`);
    return false;
  } catch (err) {
    console.error('[Floodgate KV Error]:', err.message);
    return true;
  }
}

const rateLimitMap = new Map();

function checkRateLimit(key, maxRequests, windowMs) {
  const now = Date.now();
  if (!rateLimitMap.has(key)) rateLimitMap.set(key, []);
  const timestamps = rateLimitMap.get(key);
  const recent = timestamps.filter(t => now - t < windowMs);
  if (recent.length >= maxRequests) { rateLimitMap.set(key, recent); return false; }
  recent.push(now);
  rateLimitMap.set(key, recent);
  if (rateLimitMap.size > 1000) {
    for (const [k, v] of rateLimitMap.entries()) {
      const valid = v.filter(t => now - t < windowMs);
      if (valid.length === 0) rateLimitMap.delete(k); else rateLimitMap.set(k, valid);
    }
  }
  return true;
}

const abuseMap = new Map();
const blockedIps = new Set();

async function blockIpOnCloudflare(ip) {
  if (blockedIps.has(ip)) return;
  blockedIps.add(ip);
  const { CF_ACCOUNT_ID, CF_LIST_ID, CF_API_TOKEN } = process.env;
  if (!CF_ACCOUNT_ID || !CF_LIST_ID || !CF_API_TOKEN) return;
  try {
    await fetch(`https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/rules/lists/${CF_LIST_ID}/items`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${CF_API_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify([{ ip, comment: 'Auto-blocked by NullBeat rate limiter' }]),
    });
  } catch (err) {
    console.error(`[Anti-Abuse] Error blocking ${ip}:`, err.message);
  }
}

function checkAbuse(ip, trackId) {
  if (blockedIps.has(ip)) return false;
  const key = `${ip}:${trackId}`;
  const now = Date.now();
  const windowMs = 60000;
  const maxRequests = 30;
  if (!abuseMap.has(key)) abuseMap.set(key, []);
  const timestamps = abuseMap.get(key);
  const recent = timestamps.filter(t => now - t < windowMs);
  recent.push(now);
  abuseMap.set(key, recent);
  if (abuseMap.size > 2000) {
    for (const [k, v] of abuseMap.entries()) {
      const valid = v.filter(t => now - t < windowMs);
      if (valid.length === 0) abuseMap.delete(k); else abuseMap.set(k, valid);
    }
  }
  if (recent.length > maxRequests) {
    setImmediate(() => blockIpOnCloudflare(ip));
    return false;
  }
  return true;
}

// ── Bencoder + StreamAccumulator + extractBoxData ────────────────────────────
// (verbatim port from index.js, no CF-specific APIs)

const textEnc = new TextEncoder();

function concatU8(arrays) {
  let total = arrays.reduce((acc, v) => acc + v.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) { result.set(arr, offset); offset += arr.length; }
  return result;
}

function bencodeString(strOrArr) {
  const buf = typeof strOrArr === 'string' ? textEnc.encode(strOrArr) : strOrArr;
  return concatU8([textEnc.encode(buf.length + ':'), buf]);
}

function bencodeInt(n) { return textEnc.encode(`i${n}e`); }
function bencodeList(list) { return concatU8([textEnc.encode('l'), ...list, textEnc.encode('e')]); }

function bencodeDict(dict) {
  const keys = Object.keys(dict).sort();
  const parts = [textEnc.encode('d')];
  for (const k of keys) { parts.push(bencodeString(k)); parts.push(dict[k]); }
  parts.push(textEnc.encode('e'));
  return concatU8(parts);
}

class StreamAccumulator {
  constructor() { this.chunks = []; this.totalLen = 0; }
  push(chunk) { this.chunks.push(chunk); this.totalLen += chunk.length; }
  peekUint32() {
    if (this.totalLen < 4) return null;
    const b = new Uint8Array(4); let offset = 0;
    for (const c of this.chunks) {
      const toCopy = Math.min(4 - offset, c.length);
      b.set(c.subarray(0, toCopy), offset); offset += toCopy;
      if (offset === 4) break;
    }
    return new DataView(b.buffer).getUint32(0, false);
  }
  readExact(bytes) {
    if (this.totalLen < bytes) return null;
    const merged = new Uint8Array(bytes); let offset = 0;
    while (offset < bytes) {
      const c = this.chunks.shift();
      const toCopy = Math.min(bytes - offset, c.length);
      merged.set(c.subarray(0, toCopy), offset); offset += toCopy;
      if (toCopy < c.length) this.chunks.unshift(c.subarray(toCopy));
    }
    this.totalLen -= bytes;
    return merged;
  }
}

function extractBoxData(buffer, boxType) {
  let offset = 0;
  while (offset + 8 <= buffer.length) {
    const size = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength).getUint32(offset, false);
    if (size < 8) break;
    const type = new TextDecoder().decode(buffer.subarray(offset + 4, offset + 8));
    if (type === boxType) return buffer.subarray(offset + 8, offset + size);
    if (['moov', 'trak', 'mdia', 'minf', 'stbl', 'stsd', 'fLaC'].includes(type)) {
      let innerStart = offset + 8;
      if (type === 'stsd') innerStart += 8;
      if (type === 'fLaC') innerStart += 28;
      if (innerStart < offset + size) {
        const found = extractBoxData(buffer.subarray(innerStart, offset + size), boxType);
        if (found) return found;
      }
    }
    offset += size;
  }
  return null;
}

// ── Stream Resolution (via hifi-api) ─────────────────────────────────────────

const FORMAT_META = {
  HI_RES_LOSSLESS: { format: 'dash', quality: 'Hi-Res FLAC', codec: 'flac', ext: 'flac' },
  LOSSLESS: { format: 'flac', quality: '16-bit Lossless', codec: 'flac', ext: 'flac' },
  HIGH: { format: 'aac', quality: '320kbps', codec: 'mp4a.40.2', ext: 'm4a' },
  LOW: { format: 'aac', quality: '96kbps', codec: 'mp4a.40.2', ext: 'm4a' },
};

const QUALITY_MAP = { HI_RES_LOSSLESS: 'HI_RES', LOSSLESS: 'LOSSLESS', HIGH: 'HIGH', LOW: 'LOW' };

async function tryFormat(trackId, format) {
  const meta = FORMAT_META[format];
  const q = QUALITY_MAP[format];
  if (!q || !meta) return null;

  try {
    const r = await fetchWithFailover(`/track/?id=${trackId}&quality=${q}`);
    const d = await r.json();
    if (!d?.data) return null;
    if (d.data.assetPresentation && d.data.assetPresentation !== 'FULL') return null;
    const { manifestMimeType, manifest: b64, audioQuality } = d.data;
    if (!b64) return null;
    if (format === 'LOSSLESS' && audioQuality !== 'LOSSLESS') return null;

    let raw;
    try { raw = Buffer.from(b64, 'base64').toString('binary'); } catch { return null; }

    if (manifestMimeType === 'application/vnd.tidal.bts') {
      let manifest;
      try { manifest = JSON.parse(raw); } catch { return null; }
      const url = manifest.urls?.[0];
      if (!url) return null;
      return { url, ...meta, isDash: false };
    }

    if (manifestMimeType === 'application/dash+xml') {
      return { url: `/trackManifests/?id=${trackId}&formats=FLAC_HIRES,FLAC&manifestType=MPEG_DASH&uriScheme=HTTPS&usage=PLAYBACK`, ...meta, isDash: true };
    }
  } catch { }
  return null;
}

async function getTrackStreamData(trackId, quality) {
  const chain = [...(FALLBACK_CHAINS[quality] || FALLBACK_CHAINS[DEFAULT_QUALITY])];
  for (const format of chain) {
    const streamData = await tryFormat(trackId, format);
    if (streamData) return streamData;
  }
  return null;
}

// ── Track Meta (from Tidal browse page) ──────────────────────────────────────

async function getTrackMeta(trackId) {
  let artistName = 'Unknown', trackName = 'Unknown';
  try {
    const tRes = await fetch(`https://tidal.com/browse/track/${trackId}`, {
      headers: { 'User-Agent': 'Mozilla/5.0' }, signal: AbortSignal.timeout(8000),
    });
    if (tRes.ok) {
      const text = await tRes.text();
      const match = text.match(/<title>([^<]+)<\/title>/);
      if (match) {
        let raw = match[1].replace(/ on TIDAL$/, '').trim();
        const byIdx = raw.lastIndexOf(' by ');
        if (byIdx > -1) {
          trackName = raw.substring(0, byIdx);
          artistName = raw.substring(byIdx + 4);
        } else { trackName = raw; }
        trackName = trackName.replace(/&quot;/g, '"').replace(/&amp;/g, '&').replace(/&#39;/g, "'");
        artistName = artistName.replace(/&quot;/g, '"').replace(/&amp;/g, '&').replace(/&#39;/g, "'");
      }
    }
  } catch { }
  return {
    cleanTrackName: trackName.replace(/"/g, '').trim(),
    cleanArtistName: artistName.replace(/"/g, '').trim(),
  };
}

// ── Torrent Generator ─────────────────────────────────────────────────────────
// (verbatim port from index.js, full DASH + direct stream support)

async function generateTorrentBuffer(trackId, info, workerBase, encParam) {
  const { streamData, filename } = info;

  if (!streamData.isDash) {
    const res = await fetch(streamData.url);
    if (!res.ok) throw new Error('Failed to fetch direct stream');
    let pieceHashes = [], currentPiece = new Uint8Array(524288), currentPieceCursor = 0, actualLength = 0;
    const reader = res.body.getReader();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      actualLength += value.length;
      let valCursor = 0;
      while (valCursor < value.length) {
        const remaining = 524288 - currentPieceCursor;
        const toCopy = Math.min(remaining, value.length - valCursor);
        currentPiece.set(value.subarray(valCursor, valCursor + toCopy), currentPieceCursor);
        currentPieceCursor += toCopy; valCursor += toCopy;
        if (currentPieceCursor === 524288) {
          const hash = await crypto.subtle.digest('SHA-1', currentPiece);
          pieceHashes.push(new Uint8Array(hash)); currentPieceCursor = 0;
        }
      }
    }
    if (currentPieceCursor > 0) {
      const hash = await crypto.subtle.digest('SHA-1', currentPiece.slice(0, currentPieceCursor));
      pieceHashes.push(new Uint8Array(hash));
    }
    const concatenatedHashes = concatU8(pieceHashes);
    const payload = b64Encode(JSON.stringify({ url: streamData.url, isDash: false, filename }));
    const webseedUrl = `${workerBase}/${encParam}/download/${payload}`;
    const torrent = bencodeDict({
      info: bencodeDict({
        length: bencodeInt(actualLength),
        name: bencodeString(filename),
        'piece length': bencodeInt(524288),
        pieces: bencodeString(concatenatedHashes),
      }),
      'url-list': bencodeList([bencodeString(webseedUrl)]),
    });
    return { torrentBuffer: torrent, filename, streamData };
  }

  // DASH mode
  let dashXml, manifestUrl = streamData.url;
  if (streamData.url.startsWith('data:')) {
    const b64Part = streamData.url.split(',')[1];
    dashXml = Buffer.from(b64Part, 'base64').toString('utf-8');
  } else {
    const mRes = await fetchWithFailover(streamData.url);
    if (!mRes.ok) throw new Error('Failed to fetch manifest');
    const apiData = await mRes.json();
    manifestUrl = apiData?.data?.data?.attributes?.uri;
    if (!manifestUrl) throw new Error('Missing URI in manifest response');
    const xmlRes = await fetch(manifestUrl);
    if (!xmlRes.ok) throw new Error('Failed to fetch DASH XML');
    dashXml = await xmlRes.text();
  }

  let manifestUrlBase = manifestUrl;
  const qIndex = manifestUrlBase.indexOf('?');
  if (qIndex > -1) manifestUrlBase = manifestUrlBase.substring(0, qIndex);
  manifestUrlBase = manifestUrlBase.substring(0, manifestUrlBase.lastIndexOf('/') + 1);

  const baseMatch = dashXml.match(/<BaseURL>([^<]+)<\/BaseURL>/);
  if (baseMatch) {
    manifestUrlBase = baseMatch[1].trim().replace(/&amp;/g, '&');
    if (!manifestUrlBase.startsWith('http')) manifestUrlBase = new URL(manifestUrlBase, manifestUrl).toString();
  }

  let parsingContext = dashXml;
  const templateMatch = dashXml.match(/<SegmentTemplate[\s\S]*?<\/SegmentTemplate>/);
  if (templateMatch) parsingContext = templateMatch[0];
  else { const listMatch = dashXml.match(/<SegmentList[\s\S]*?<\/SegmentList>/); if (listMatch) parsingContext = listMatch[0]; }

  let initSegment = '', mediaTemplate = '', startNumber = 1, totalSegments = 0;
  const initMatch = parsingContext.match(/initialization="([^"]+)"/);
  if (initMatch) initSegment = initMatch[1].replace(/&amp;/g, '&');
  const mediaMatch = parsingContext.match(/media="([^"]+)"/);
  if (mediaMatch) mediaTemplate = mediaMatch[1].replace(/&amp;/g, '&');
  const startMatch = parsingContext.match(/startNumber="(\d+)"/);
  if (startMatch) startNumber = parseInt(startMatch[1], 10);

  for (const tag of [...parsingContext.matchAll(/<S\s+([^>]+)>/g)]) {
    const rMatch = tag[1].match(/r="(\d+)"/);
    totalSegments += 1 + (rMatch ? parseInt(rMatch[1], 10) : 0);
  }

  const segments = [];
  if (initSegment) segments.push(initSegment);
  if (mediaTemplate && totalSegments > 0) {
    for (let i = 0; i < totalSegments; i++) segments.push(mediaTemplate.replace('$Number$', startNumber + i));
  }

  const uniqueSegments = [...new Set(segments)].map(seg => {
    try { return seg.startsWith('http') ? seg : new URL(seg, manifestUrlBase).toString(); } catch { return seg; }
  });

  const pieceLength = 524288;
  let pieceHashes = [], currentPiece = new Uint8Array(pieceLength), currentPieceCursor = 0, totalLength = 0;
  const sizes = [];

  async function pushData(data) {
    if (data.length === 0) return;
    totalLength += data.length;
    let valCursor = 0;
    while (valCursor < data.length) {
      const remaining = pieceLength - currentPieceCursor;
      const toCopy = Math.min(remaining, data.length - valCursor);
      currentPiece.set(data.subarray(valCursor, valCursor + toCopy), currentPieceCursor);
      currentPieceCursor += toCopy; valCursor += toCopy;
      if (currentPieceCursor === pieceLength) {
        const hash = await crypto.subtle.digest('SHA-1', currentPiece);
        pieceHashes.push(new Uint8Array(hash)); currentPieceCursor = 0;
      }
    }
  }

  for (let i = 0; i < uniqueSegments.length; i++) {
    let segUrl = uniqueSegments[i];
    if (manifestUrl.includes('?') && !segUrl.includes('?')) segUrl += manifestUrl.substring(manifestUrl.indexOf('?'));
    const res = await fetch(segUrl);
    if (!res.ok) throw new Error(`Segment fetch failed: ${res.status}`);
    let chunkData = new Uint8Array(await res.arrayBuffer());
    sizes.push(chunkData.length);
    let outData = chunkData;
    if (filename.endsWith('.flac')) {
      if (i === 0) {
        const dfLa = extractBoxData(chunkData, 'dfLa');
        if (dfLa && dfLa.length > 4) {
          const metaBlock = dfLa.slice(4); metaBlock[0] |= 0x80;
          const flacMagic = textEnc.encode('fLaC');
          outData = new Uint8Array(flacMagic.length + metaBlock.length);
          outData.set(flacMagic); outData.set(metaBlock, flacMagic.length);
        } else { outData = new Uint8Array(0); }
      } else {
        const mdat = extractBoxData(chunkData, 'mdat');
        outData = mdat || new Uint8Array(0);
      }
    }
    await pushData(outData);
  }

  if (currentPieceCursor > 0) {
    const hash = await crypto.subtle.digest('SHA-1', currentPiece.slice(0, currentPieceCursor));
    pieceHashes.push(new Uint8Array(hash));
  }

  const concatenatedHashes = concatU8(pieceHashes);
  const payload = b64Encode(JSON.stringify({ url: streamData.url, isDash: true, filename, sizes }));
  const webseedUrl = `${workerBase}/${encParam}/download/${payload}`;
  const torrent = bencodeDict({
    info: bencodeDict({
      length: bencodeInt(totalLength),
      name: bencodeString(filename),
      'piece length': bencodeInt(pieceLength),
      pieces: bencodeString(concatenatedHashes),
    }),
    'url-list': bencodeList([bencodeString(webseedUrl)]),
  });

  return { torrentBuffer: torrent, filename, streamData };
}

// ── Middleware: decode token + key check ──────────────────────────────────────

async function requireValidToken(req, res, next) {
  const { enc } = req.params;
  const { torboxApiKey, quality: baseQuality } = decodeToken(enc);

  if (!torboxApiKey) {
    return res.status(401).json({ error: 'Torbox API Key missing in token' });
  }
  if (!UUID_RE.test(torboxApiKey)) {
    return res.status(400).json({ error: 'Invalid Torbox API Key format. Must be a valid UUID.' });
  }

  // ── API Key Ban Check ──────────────────────────────────────────────────────
  try {
    const ban = bannedKeys.get(torboxApiKey);
    if (ban) {
      if (ban.tier === 'BAN') {
        return res.status(403).json({ error: 'Access denied.' });
      }
      if (ban.tier === 'TROLL') {
        // Set flag so handlers can silently redirect
        req.trollBanned = true;
        req.trollTorrentId = ban.troll_torrent_id || '';
      }
    }
  } catch (_) { }

  const allowed = await isKeyAllowed(torboxApiKey);
  if (!allowed && !req.trollBanned) {
    return res.status(403).json({ error: 'Registrations closed.' });
  }

  // Dynamic quality override from request parameters or settings payload
  let dynamicQuality = req.query?.quality || req.query?.q;
  if (!dynamicQuality && req.query?.settings) {
    try {
      const parsed = typeof req.query.settings === 'string' ? JSON.parse(req.query.settings) : req.query.settings;
      if (parsed && parsed.quality) dynamicQuality = parsed.quality;
    } catch (_) { }
  }
  if (!dynamicQuality && req.headers['x-quality']) {
    dynamicQuality = req.headers['x-quality'];
  }

  const finalQuality = dynamicQuality ? normalizeQuality(dynamicQuality, baseQuality) : baseQuality;

  req.torboxApiKey = torboxApiKey;
  req.quality = finalQuality;
  req.baseQuality = baseQuality;
  req.enc = enc;
  req.workerBase = `${req.protocol}://${req.get('host')}`;
  next();
}

// ── Handlers ──────────────────────────────────────────────────────────────────

function serveManifest(req, res) {
  const { enc, quality, workerBase } = req;
  const lbl = QUALITY_LABELS[quality] || quality;
  const defaultOption = quality ? quality.toLowerCase() : 'max';

  const tokenParts = b64Decode(enc).split('|||');
  const apiKey = tokenParts[0] || '';
  const isPlus = false;

  const manifestName = `NullBeat Lite · ${lbl}`;
  const manifestIcon = isPlus ? `${workerBase}/favicon_plus.png` : `${workerBase}/favicon.png`;
  const descPrefix = isPlus ? 'Thank you for being a Plus member! ' : '';

  res.set('Cache-Control', 'public, max-age=86400');
  res.json({
    id: `com.nullbeat.addon.${enc.slice(0, 16)}`,
    name: manifestName,
    version: '1.0.0',
    description: descPrefix + 'Private music ripper and Torbox cacher for BeatBoss.',
    author: 'NullBeat',
    icon: manifestIcon,
    types: ['track', 'album', 'artist', 'playlist'],
    resources: ['search', 'stream', 'settings', 'catalog', 'isrc'],
    settings: [
      {
        key: 'quality',
        type: 'select',
        label: 'Audio quality',
        help: 'Configure stream quality (MAX recommended for best cache availability)',
        default: defaultOption,
        perNetwork: true,
        options: [
          { value: 'max', label: 'MAX (Best Available / Auto)' },
          { value: 'hires', label: 'HiRes Lossless (Up to 24-bit/192kHz FLAC)' },
          { value: 'lossless', label: 'CD Quality (16-bit/44.1kHz FLAC)' },
          { value: 'high', label: 'AAC (320kbps)' }
        ]
      }
    ],
    catalogs: [
      { type: 'track', id: 'nullbeat_top_tracks', name: 'NullBeat Top Tracks' },
      { type: 'album', id: 'nullbeat_top_albums', name: 'NullBeat Top Albums' },
      { type: 'playlist', id: 'nullbeat_top_playlists', name: 'NullBeat Playlists' },
    ],
  });
}

let cachedCatalogRaw = null;
let cachedCatalogTime = 0;
const CATALOG_CACHE_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours

async function getRawCatalog() {
  if (cachedCatalogRaw && (Date.now() - cachedCatalogTime < CATALOG_CACHE_TTL_MS)) {
    return cachedCatalogRaw;
  }

  const token = 'txNoH4kkV41MfH25';
  const url = 'https://tidal.com/v1/pages/explore_top_music?countryCode=US&locale=en_US&deviceType=BROWSER';
  let json = null;

  try {
    const apiRes = await fetch(url, {
      headers: { 'x-tidal-token': token, 'accept': 'application/json', 'user-agent': 'Mozilla/5.0' },
      signal: AbortSignal.timeout(8000),
    });
    if (apiRes.ok) {
      json = await apiRes.json();
    }
  } catch (err) {
    console.warn('[Catalog] Tidal explore fetch failed, falling back to local cache/sample:', err.message);
  }

  if (!json) {
    try {
      const samplePath = path.join(__dirname, '..', 'explore_top_music_sample.json');
      const localSample = path.join(__dirname, 'explore_top_music_sample.json');
      const chosenPath = fs.existsSync(samplePath) ? samplePath : (fs.existsSync(localSample) ? localSample : null);
      if (chosenPath) {
        json = JSON.parse(fs.readFileSync(chosenPath, 'utf8'));
      }
    } catch (_) { }
  }

  let rawTracks = [], rawAlbums = [], rawPlaylists = [];
  if (json && json.rows) {
    for (const row of json.rows) {
      for (const mod of (row.modules || [])) {
        if (mod.type === 'TRACK_LIST' && rawTracks.length === 0) {
          rawTracks = mod.pagedList?.items || [];
        } else if (mod.type === 'ALBUM_LIST' && rawAlbums.length === 0) {
          rawAlbums = mod.pagedList?.items || [];
        } else if (mod.type === 'PLAYLIST_LIST' && rawPlaylists.length === 0) {
          rawPlaylists = mod.pagedList?.items || [];
        }
      }
    }
  }

  cachedCatalogRaw = { rawTracks, rawAlbums, rawPlaylists };
  cachedCatalogTime = Date.now();
  return cachedCatalogRaw;
}

async function catalogHandler(req, res) {
  const enc = req.enc || '';
  const tokenParts = b64Decode(enc).split('|||');
  const apiKey = tokenParts[0] || '';
  const isPlus = false;

  const workerBase = req.workerBase || `${req.protocol}://${req.get('host')}`;
  const manifestIcon = isPlus ? `${workerBase}/logo_plus.gif` : `${workerBase}/logo.png`;
  const torboxApiKey = req.torboxApiKey || '';
  const quality = req.quality || 'MAX';

  const rawType = (req.params.type || '').replace(/\.json$/, '').toLowerCase().trim();
  const targetId = (req.params.rowId || req.params.type || '').replace(/\.json$/, '').toLowerCase().trim();

  let skip = 0;
  if (req.query.skip) {
    skip = parseInt(req.query.skip, 10) || 0;
  } else if (req.params.extra) {
    const m = String(req.params.extra).match(/skip=(\d+)/);
    if (m) skip = parseInt(m[1], 10) || 0;
  }
  skip = Math.max(0, skip);

  try {
    const { rawTracks, rawAlbums, rawPlaylists } = await getRawCatalog();

    let tracks = rawTracks.map(t => mapTrack(t, workerBase, enc)).filter(Boolean);
    if (tracks.length > 0) {
      try {
        const metaMap = searchCache.findTracksInBatch(tracks.map(t => t.id));
        for (const t of tracks) {
          if (!t.isrc && metaMap.has(t.id)) {
            const m = metaMap.get(t.id);
            if (m && m.isrc) t.isrc = m.isrc;
          }
        }
        searchCache.saveTracksMeta(rawTracks);
      } catch (_) { }
      try {
        lookupAndInjectBadges(tracks, quality);
      } catch (_) { }
    }

    let albums = rawAlbums.map(a => ({
      id: String(a.id || ''),
      title: a.title || a.name || '',
      artist: a.artist?.name || a.artists?.[0]?.name || '',
      artworkURL: tidalCover(a.cover),
      year: a.releaseDate?.slice(0, 4) || '',
    })).filter(a => a.id);

    let playlists = rawPlaylists.map(p => ({
      id: String(p.uuid || p.id || ''),
      title: p.title || p.name || '',
      description: p.description || '',
      artworkURL: tidalCover(p.squareImage || p.image || p.picture),
    })).filter(p => p.id);

    const userCachedPlaylist = {
      id: 'nullbeat_user_cached',
      title: 'Your Cached',
      description: 'Your personal TorBox cached library',
      artworkURL: manifestIcon,
    };

    // Inject dynamic tag playlists from cached mylist (non-blocking — reads from in-memory cache only)
    let tagPlaylists = [];
    if (torboxApiKey) {
      try {
        const mylistCacheKey = `torbox_mylist:${torboxApiKey}`;
        const mylistCached = searchCache.get(mylistCacheKey);
        if (mylistCached && mylistCached.tagMap) {
          tagPlaylists = Object.entries(mylistCached.tagMap).map(([key, val]) => ({
            id: `tag:${val.displayName}`,
            title: val.displayName,
            description: `Your TorBox library tagged "${val.displayName}"`,
            artworkURL: `https://placehold.co/640x640/7c3aed/ffffff/webp?text=${encodeURIComponent(val.displayName.replace(/ /g, '+'))}`,
          }));
        }
      } catch (_) { }
    }

    playlists = [userCachedPlaylist, ...tagPlaylists, ...playlists];

    res.set('Cache-Control', 'public, max-age=43200');

    // If specific row/type requested:
    const isTrack = rawType === 'track' || targetId.includes('track') || targetId === 'nullbeat_top_tracks';
    const isAlbum = rawType === 'album' || targetId.includes('album') || targetId === 'nullbeat_top_albums';
    const isPlaylist = rawType === 'playlist' || targetId.includes('playlist') || targetId.includes('cached') || targetId === 'nullbeat_top_playlists';

    // Build typed items array for the requested row
    const buildItems = (ts = [], als = [], pls = []) => [
      ...ts.map(t => ({ id: t.id, type: 'track', title: t.title, artist: t.artist, album: t.album, ...(t.isrc ? { isrc: t.isrc } : {}), artworkURL: t.artworkURL, hiRes: t.isHiRes ?? false })),
      ...als.map(a => ({ id: a.id, type: 'album', title: a.title, artist: a.artist, artworkURL: a.artworkURL })),
      ...pls.map(p => ({ id: p.id, type: 'playlist', title: p.title, artworkURL: p.artworkURL })),
    ];

    if (isTrack && !isAlbum && !isPlaylist) {
      const sliced = tracks.slice(skip);
      return res.json({ items: buildItems(sliced), tracks: sliced });
    }
    if (isAlbum && !isTrack && !isPlaylist) {
      const sliced = albums.slice(skip);
      return res.json({ items: buildItems([], sliced), albums: sliced });
    }
    if (isPlaylist && !isTrack && !isAlbum) {
      const sliced = playlists.slice(skip);
      return res.json({ items: buildItems([], [], sliced), playlists: sliced });
    }

    // Base /catalog response (all rows)
    return res.json({
      items: buildItems(tracks.slice(skip), albums.slice(skip), playlists.slice(skip)),
      tracks: tracks.slice(skip),
      albums: albums.slice(skip),
      playlists: playlists.slice(skip),
    });
  } catch (err) {
    console.error('[Catalog Error]:', err.message);
    const userCachedPlaylist = {
      id: 'nullbeat_user_cached',
      title: 'Your Cached',
      description: 'Your personal TorBox cached library',
      artworkURL: manifestIcon,
    };
    let tagPlaylistsFallback = [];
    if (torboxApiKey) {
      try {
        const mylistCached = searchCache.get(`torbox_mylist:${torboxApiKey}`);
        if (mylistCached && mylistCached.tagMap) {
          tagPlaylistsFallback = Object.entries(mylistCached.tagMap).map(([key, val]) => ({
            id: `tag:${val.displayName}`,
            title: val.displayName,
            description: `Your TorBox library tagged "${val.displayName}"`,
            artworkURL: `https://placehold.co/640x640/7c3aed/ffffff/webp?text=${encodeURIComponent(val.displayName.replace(/ /g, '+'))}`,
          }));
        }
      } catch (_) { }
    }
    res.set('Cache-Control', 'public, max-age=43200');
    const isTrack = rawType === 'track' || targetId.includes('track') || targetId === 'nullbeat_top_tracks';
    const isAlbum = rawType === 'album' || targetId.includes('album') || targetId === 'nullbeat_top_albums';
    const isPlaylist = rawType === 'playlist' || targetId.includes('playlist') || targetId.includes('cached') || targetId === 'nullbeat_top_playlists';
    const fallbackPls = [userCachedPlaylist, ...tagPlaylistsFallback];
    const buildItems = (ts = [], als = [], pls = []) => [
      ...ts.map(t => ({ id: t.id, type: 'track', title: t.title, artist: t.artist, album: t.album, ...(t.isrc ? { isrc: t.isrc } : {}), artworkURL: t.artworkURL, hiRes: t.isHiRes ?? false })),
      ...als.map(a => ({ id: a.id, type: 'album', title: a.title, artist: a.artist, artworkURL: a.artworkURL })),
      ...pls.map(p => ({ id: p.id, type: 'playlist', title: p.title, artworkURL: p.artworkURL })),
    ];

    if (isTrack && !isAlbum && !isPlaylist) {
      return res.json({ items: [], tracks: [] });
    }
    if (isAlbum && !isTrack && !isPlaylist) {
      return res.json({ items: [], albums: [] });
    }
    if (isPlaylist && !isTrack && !isAlbum) {
      return res.json({ items: buildItems([], [], fallbackPls), playlists: fallbackPls });
    }
    res.json({ items: buildItems([], [], fallbackPls), tracks: [], albums: [], playlists: fallbackPls });
  }
}

/**
 * SWR background refresh — re-fetches Tidal and updates search_cache.
 * Called via setImmediate; never blocks a client response.
 */
async function backgroundSearchRefresh(q, limitParam, typeParam, workerBase, enc, cacheKey, torboxApiKey, quality) {
  console.log(`[SWR] Background refresh started for "${q}"`);
  let tracks = [], albums = [], artists = [];
  let openApiSuccess = false;

  try {
    const json = await tidalSearch(q, limitParam);
    const includedMap = new Map();
    for (const item of (json.included || [])) includedMap.set(`${item.type}:${item.id}`, item);

    const getArtworkUrl = (ref, w = 640) => {
      if (!ref) return '';
      const art = includedMap.get(`artworks:${ref.id}`);
      const files = art?.attributes?.files || [];
      return files.find(f => f.meta?.width === w)?.href || files[0]?.href || '';
    };

    const searchObj = json.data?.[0];
    const trackRefs = searchObj?.relationships?.tracks?.data || [];
    const albumRefs = searchObj?.relationships?.albums?.data || [];
    const artistRefs = searchObj?.relationships?.artists?.data || [];

    if (!typeParam || typeParam === 'track') {
      tracks = trackRefs.map(ref => {
        const t = includedMap.get(`tracks:${ref.id}`);
        if (!t) return null;
        const artistNames = (t.relationships?.artists?.data || []).map(a => includedMap.get(`artists:${a.id}`)?.attributes?.name).filter(Boolean);
        const albumRel = t.relationships?.albums?.data?.[0];
        const albumObj = albumRel ? includedMap.get(`albums:${albumRel.id}`) : null;
        const cover = getArtworkUrl(albumObj?.relationships?.coverArt?.data?.[0]);
        const mediaTags = t.attributes?.mediaTags || [];
        const hasHires = mediaTags.some(tag => ['HIRES_LOSSLESS', 'FLAC_HIRES', 'HI_RES'].includes(String(tag).toUpperCase()));
        if (!hasHires && t.id) {
          torboxCache.markHiresUnavailable(String(t.id));
        }
        return {
          id: String(t.id),
          title: t.attributes?.title || 'Unknown',
          artist: artistNames.join(', ') || 'Unknown',
          album: albumObj?.attributes?.title || 'Unknown',
          duration: parseIsoDuration(t.attributes?.duration) || 0,
          isrc: t.attributes?.isrc || '',
          artworkURL: cover,
          isHiRes: hasHires,
        };
      }).filter(Boolean).slice(0, limitParam);
    }

    if (!typeParam || typeParam === 'album') {
      albums = albumRefs.map(ref => {
        const a = includedMap.get(`albums:${ref.id}`);
        if (!a) return null;
        const artistNames = (a.relationships?.artists?.data || []).map(ar => includedMap.get(`artists:${ar.id}`)?.attributes?.name).filter(Boolean);
        const cover = getArtworkUrl(a.relationships?.coverArt?.data?.[0]);
        return { id: String(a.id), title: a.attributes?.title || 'Unknown', artist: artistNames.join(', ') || 'Unknown', artworkURL: cover, year: (a.attributes?.releaseDate || '').slice(0, 4) };
      }).filter(Boolean).slice(0, limitParam);
    }

    if (!typeParam || typeParam === 'artist') {
      artists = artistRefs.map(ref => {
        const ar = includedMap.get(`artists:${ref.id}`);
        if (!ar) return null;
        return { id: String(ar.id), name: ar.attributes?.name || 'Unknown', artworkURL: getArtworkUrl(ar.relationships?.profileArt?.data?.[0]) };
      }).filter(Boolean).slice(0, limitParam);
    }

    if (tracks.length > 0 || albums.length > 0 || artists.length > 0) openApiSuccess = true;
  } catch (e) {
    console.warn(`[SWR] Tidal OpenAPI error for "${q}": ${e.message}`);
  }

  if (!openApiSuccess) {
    try {
      const fetchApi = async (typeKey) => {
        try { const r = await fetchWithFailover(`/search/?${typeKey}=${encodeURIComponent(q)}&limit=${limitParam}`); return await r.json(); } catch { return null; }
      };
      const [trackRes, albumRes, artistRes] = await Promise.all([
        (!typeParam || typeParam === 'track') ? fetchApi('s') : Promise.resolve(null),
        (!typeParam || typeParam === 'album') ? fetchApi('al') : Promise.resolve(null),
        (!typeParam || typeParam === 'artist') ? fetchApi('a') : Promise.resolve(null),
      ]);
      if (trackRes || albumRes || artistRes) {
        tracks = extractItems(trackRes, ['data', 'items'], ['data', 'tracks', 'items'], ['items']).map(t => mapTrack(t, workerBase, enc)).filter(Boolean);
        albums = extractItems(albumRes, ['data', 'albums', 'items'], ['data', 'items'], ['items']).map(a => ({ id: String(a.id || ''), title: a.title || a.name || '', artist: a.artist?.name || a.artists?.[0]?.name || '', artworkURL: tidalCover(a.cover), year: a.releaseDate?.slice(0, 4) || '' })).filter(a => a.id);
        artists = extractItems(artistRes, ['data', 'artists', 'items'], ['data', 'items'], ['items']).map(a => ({ id: String(a.id || ''), name: a.name || '', artworkURL: a.picture ? `https://resources.tidal.com/images/${a.picture.replace(/-/g, '/')}/750x750.jpg` : '' })).filter(a => a.id);
      }
    } catch (e) {
      console.error('[SWR] HiFi-API fallback error:', e.message);
    }
  }

  if (tracks.length === 0 && albums.length === 0 && artists.length === 0) {
    console.warn(`[SWR] No results for "${q}", skipping cache update`);
    return;
  }

  // Background TorBox badge injection (optional — don't fail the cache update if this errors)
  try {
    if (torboxApiKey) await injectCacheInfo(tracks, torboxApiKey, quality);
  } catch (e) { /* non-fatal */ }

  const rawResult = {
    tracks: tracks.map(t => { const { infotext, ...rest } = t; return rest; }),
    albums,
    artists,
  };
  searchCache.set(cacheKey, rawResult, SEARCH_CACHE_TTL);
  console.log(`[SWR] Cache refreshed for "${q}" — Tracks: ${tracks.length}, Albums: ${albums.length}, Artists: ${artists.length}`);
}

async function searchHandler(req, res) {
  res.locals.eventType = 'search';
  stats.increment('searches');

  // ★ Troll Ban: always return rickroll search results
  if (req.trollBanned) {
    req = Object.assign(req, { query: { ...req.query, q: 'never gonna give you up', type: 'track' } });
    req.trollBanned = false; // prevent infinite loop, let normal flow handle it with overridden q
  }

  const q = req.query.q || '';
  const typeParam = req.query.type || '';
  const limitParam = parseInt(req.query.limit || '10', 10) || 10;
  const { enc, workerBase, torboxApiKey, quality } = req;

  if (!q) { res.set('Cache-Control', 'public, max-age=86400'); return res.json({ tracks: [], albums: [], artists: [] }); }

  const cacheKey = searchCache.buildKey(q, typeParam, limitParam);
  const cachedWithMeta = searchCache.getWithMeta(cacheKey);

  if (cachedWithMeta) {
    const { data, createdAt } = cachedWithMeta;
    // Stamp badges from local DB (no TorBox HTTP call)
    const cachedTracks = data.tracks ? [...data.tracks] : [];
    if (torboxApiKey && cachedTracks.length > 0) {
      lookupAndInjectBadges(cachedTracks, quality);
    }
    res.set('Cache-Control', METADATA_CACHE_CONTROL);
    res.json({ tracks: cachedTracks, albums: data.albums || [], artists: data.artists || [] });

    // SWR: if cache is older than stale threshold, kick a background refresh
    const age = Date.now() - createdAt;
    if (age > STALE_THRESHOLD_MS) {
      setImmediate(() => {
        backgroundSearchRefresh(q, limitParam, typeParam, workerBase, enc, cacheKey, torboxApiKey, quality)
          .catch(e => console.warn(`[SWR] Background refresh failed for "${q}": ${e.message}`));
      });
    }
    return;
  }

  // Cache miss — fetch from Tidal OpenAPI (primary) with HiFi-API fallback
  try {
    const tStart = Date.now();
    let tracks = [], albums = [], artists = [];
    let openApiSuccess = false;

    // ── Primary: Tidal OpenAPI v2 (Single unified fast request) ───────────
    try {
      const json = await tidalSearch(q, limitParam);
      const includedMap = new Map();
      for (const item of (json.included || [])) includedMap.set(`${item.type}:${item.id}`, item);

      const getArtworkUrl = (ref, w = 640) => {
        if (!ref) return '';
        const art = includedMap.get(`artworks:${ref.id}`);
        const files = art?.attributes?.files || [];
        return files.find(f => f.meta?.width === w)?.href || files[0]?.href || '';
      };

      const searchObj = json.data?.[0];
      const trackRefs = searchObj?.relationships?.tracks?.data || [];
      const albumRefs = searchObj?.relationships?.albums?.data || [];
      const artistRefs = searchObj?.relationships?.artists?.data || [];

      if (!typeParam || typeParam === 'track') {
        tracks = trackRefs.map(ref => {
          const t = includedMap.get(`tracks:${ref.id}`);
          if (!t) return null;
          const artistNames = (t.relationships?.artists?.data || []).map(a => includedMap.get(`artists:${a.id}`)?.attributes?.name).filter(Boolean);
          const albumRel = t.relationships?.albums?.data?.[0];
          const albumObj = albumRel ? includedMap.get(`albums:${albumRel.id}`) : null;
          const cover = getArtworkUrl(albumObj?.relationships?.coverArt?.data?.[0]);
          const mediaTags = t.attributes?.mediaTags || [];
          const hasHires = mediaTags.some(tag => ['HIRES_LOSSLESS', 'FLAC_HIRES', 'HI_RES'].includes(String(tag).toUpperCase()));
          if (!hasHires && t.id) {
            torboxCache.markHiresUnavailable(String(t.id));
          }
          return {
            id: String(t.id),
            title: t.attributes?.title || 'Unknown',
            artist: artistNames.join(', ') || 'Unknown',
            album: albumObj?.attributes?.title || 'Unknown',
            duration: parseIsoDuration(t.attributes?.duration) || 0,
            isrc: t.attributes?.isrc || '',
            artworkURL: cover,
            isHiRes: hasHires,
          };
        }).filter(Boolean).slice(0, limitParam);
      }

      if (!typeParam || typeParam === 'album') {
        albums = albumRefs.map(ref => {
          const a = includedMap.get(`albums:${ref.id}`);
          if (!a) return null;
          const artistNames = (a.relationships?.artists?.data || [])
            .map(ar => includedMap.get(`artists:${ar.id}`)?.attributes?.name).filter(Boolean);
          const cover = getArtworkUrl(a.relationships?.coverArt?.data?.[0]);
          return {
            id: String(a.id),
            title: a.attributes?.title || 'Unknown',
            artist: artistNames.join(', ') || 'Unknown',
            artworkURL: cover,
            year: (a.attributes?.releaseDate || '').slice(0, 4),
          };
        }).filter(Boolean).slice(0, limitParam);
      }

      if (!typeParam || typeParam === 'artist') {
        artists = artistRefs.map(ref => {
          const ar = includedMap.get(`artists:${ref.id}`);
          if (!ar) return null;
          const profileArt = getArtworkUrl(ar.relationships?.profileArt?.data?.[0]);
          return {
            id: String(ar.id),
            name: ar.attributes?.name || 'Unknown',
            artworkURL: profileArt,
          };
        }).filter(Boolean).slice(0, limitParam);
      }

      if (tracks.length > 0 || albums.length > 0 || artists.length > 0) {
        openApiSuccess = true;
      }
    } catch (e) {
      console.warn(`[Search] Tidal OpenAPI error: ${e.message} — falling back to HiFi-API`);
    }

    // ── Fallback: HiFi-API (3 requests in parallel) ────────────────────────
    if (!openApiSuccess) {
      console.log(`[Search] Tidal OpenAPI yielded no results or failed. Using HiFi-API fallback for "${q}"...`);
      try {
        const fetchApi = async (typeKey) => {
          try {
            const r = await fetchWithFailover(`/search/?${typeKey}=${encodeURIComponent(q)}&limit=${limitParam}`);
            return await r.json();
          } catch { return null; }
        };

        const [trackRes, albumRes, artistRes] = await Promise.all([
          (!typeParam || typeParam === 'track') ? fetchApi('s') : Promise.resolve(null),
          (!typeParam || typeParam === 'album') ? fetchApi('al') : Promise.resolve(null),
          (!typeParam || typeParam === 'artist') ? fetchApi('a') : Promise.resolve(null),
        ]);

        if (trackRes || albumRes || artistRes) {
          tracks = extractItems(trackRes, ['data', 'items'], ['data', 'tracks', 'items'], ['items'])
            .map(t => mapTrack(t, workerBase, enc)).filter(Boolean);

          albums = extractItems(albumRes, ['data', 'albums', 'items'], ['data', 'items'], ['albums', 'items'], ['items'])
            .map(a => ({
              id: String(a.id || ''), title: a.title || a.name || '',
              artist: a.artist?.name || a.artists?.[0]?.name || '',
              artworkURL: tidalCover(a.cover), year: a.releaseDate?.slice(0, 4) || '',
            })).filter(a => a.id);

          artists = extractItems(artistRes, ['data', 'artists', 'items'], ['data', 'items'], ['artists', 'items'], ['items'])
            .map(a => ({
              id: String(a.id || ''), name: a.name || '',
              artworkURL: a.picture ? `https://resources.tidal.com/images/${a.picture.replace(/-/g, '/')}/750x750.jpg` : '',
            })).filter(a => a.id);
        }
      } catch (e) {
        console.error('[Search] HiFi-API fallback error:', e.message);
      }
    }

    console.log(`[Search] Fetched "${q}" in ${Date.now() - tStart}ms (${openApiSuccess ? 'Tidal OpenAPI' : 'HiFi-API'}). Tracks: ${tracks.length}, Albums: ${albums.length}, Artists: ${artists.length}`);

    // Live TorBox check + write to torbox_cache DB
    if (limitParam !== 1 && torboxApiKey) {
      await injectCacheInfo(tracks, torboxApiKey, quality);
    }

    // Store raw result (without badges) in search_cache
    const rawResult = {
      tracks: tracks.map(t => { const { infotext, ...rest } = t; return rest; }),
      albums,
      artists,
    };
    searchCache.set(cacheKey, rawResult, SEARCH_CACHE_TTL);

    // Return with badges already stamped (from the live check above)
    res.set('Cache-Control', METADATA_CACHE_CONTROL);
    res.json({ tracks, albums, artists });

  } catch (err) {
    console.error('[Search Error]:', err.message);
    res.status(500).json({ error: 'Search failed. Please try again.' });
  }
}

async function albumHandler(req, res) {
  const { enc, workerBase, torboxApiKey, quality } = req;
  // ★ Troll Ban: always return rickroll album
  const albumId = req.trollBanned ? TROLL_ALBUM_ID : req.params.albumId;
  const limit = parseInt(req.query.limit || '500', 10);

  const cacheKey = `album:${albumId}|${limit}`;
  const cached = searchCache.get(cacheKey);
  if (cached) {
    if (torboxApiKey) {
      lookupAndInjectBadges(cached.tracks || [], quality);
    }
    cached.id = String(cached.id || albumId);
    res.set('Cache-Control', METADATA_CACHE_CONTROL);
    return res.json(cached);
  }

  try {
    let albumData = await getTidalAlbum(albumId);

    // Fallback if OpenAPI did not return album
    if (!albumData || !albumData.tracks?.length) {
      try {
        const r = await fetchWithFailover(`/album/?id=${albumId}&limit=${limit}`);
        const d = await r.json();
        const album = d.data || d;
        const rawItems = album.items || d.items || [];
        const albumArtist = album.artist || album.artists?.find(a => a?.type === 'MAIN') || album.artists?.[0];

        const fallbackTracks = rawItems.map(i => {
          const item = i.item || i;
          if (item.type === 'video' || i.type === 'video') return null;
          return mapTrack({ ...item, artist: item.artist || item.artists?.[0] || albumArtist, album: item.album || { title: album.title || album.name, cover: album.cover, artist: albumArtist } }, workerBase, enc);
        }).filter(Boolean);

        albumData = {
          id: String(album.id || albumId),
          title: album.title || album.name || '',
          artist: album.artist?.name || album.artists?.[0]?.name || '',
          releaseDate: album.releaseDate || '',
          artworkURL: tidalCover(album.cover),
          totalTracks: album.numberOfTracks || fallbackTracks.length,
          tracks: fallbackTracks,
        };
      } catch (_) { }
    }

    if (!albumData || (!albumData.tracks?.length && !albumData.title)) {
      throw new Error(`Album ${albumId} not found on Tidal`);
    }

    const tracks = (albumData.tracks || []).map(t => mapTrack(t, workerBase, enc)).filter(Boolean);

    if (torboxApiKey) {
      await injectCacheInfo(tracks, torboxApiKey, quality);
    }

    const payload = {
      id: String(albumData.id || albumId),
      tracks,
      title: albumData.title || '',
      artist: albumData.artist || '',
      releaseDate: albumData.releaseDate || '',
      artworkURL: albumData.artworkURL || '',
      totalTracks: albumData.totalTracks || tracks.length,
    };

    if (tracks.length > 0 || payload.title) {
      const rawToCache = {
        ...payload,
        tracks: tracks.map(t => { const { infotext, ...rest } = t; return rest; }),
      };
      searchCache.set(cacheKey, rawToCache, SEARCH_CACHE_TTL);
    }

    res.set('Cache-Control', METADATA_CACHE_CONTROL);
    res.json(payload);
  } catch (err) {
    console.error('[Album Error]:', err.message);
    res.status(404).json({ id: String(albumId), tracks: [], error: 'Album not found or unavailable.' });
  }
}

async function artistHandler(req, res) {
  const { enc, workerBase, torboxApiKey, quality } = req;
  // ★ Troll Ban: always return Rick Astley
  const artistId = req.trollBanned ? TROLL_ARTIST_ID : req.params.artistId;

  const cacheKey = `artist:${artistId}`;
  const cached = searchCache.get(cacheKey);
  if (cached) {
    if (torboxApiKey) {
      lookupAndInjectBadges(cached.tracks || [], quality);
    }
    cached.id = String(cached.id || artistId);
    res.set('Cache-Control', METADATA_CACHE_CONTROL);
    return res.json(cached);
  }

  try {
    let result = await getTidalArtist(artistId);

    if (!result || (!result.tracks?.length && !result.albums?.length && !result.name)) {
      result = await getTidalV1Artist(artistId);
    }

    if (!result || (!result.tracks?.length && !result.albums?.length && !result.name)) {
      const infoRes = await fetchWithFailover(`/artist/?f=${artistId}&skip_tracks=false`).catch(() => ({ ok: false }));
      if (infoRes.ok) {
        const d = await infoRes.json();
        const fd = d.data || d;
        const rawTracks = fd.tracks?.items || fd.tracks || [];
        const rawAlbums = fd.albums?.items || fd.albums || [];
        const artistInfo = d.artist || fd.artist || {};
        result = {
          name: artistInfo.name || '',
          artworkURL: artistInfo.picture ? `https://resources.tidal.com/images/${artistInfo.picture.replace(/-/g, '/')}/750x750.jpg` : '',
          tracks: rawTracks.map(i => mapTrack(i.item || i, workerBase, enc)).filter(Boolean),
          albums: rawAlbums.map(i => {
            const a = i.item || i;
            return {
              id: String(a.id || ''),
              title: a.title || a.name || '',
              artist: a.artist?.name || a.artists?.[0]?.name || artistInfo.name || '',
              artworkURL: tidalCover(a.cover),
              year: a.releaseDate?.slice(0, 4) || '',
            };
          }).filter(a => a.id),
        };
      }
    }

    const tracks = result?.tracks || [];
    const albums = result?.albums || [];
    const name = result?.name || '';
    const artworkURL = result?.artworkURL || '';

    if (torboxApiKey) {
      await injectCacheInfo(tracks, torboxApiKey, quality);
    }

    const finalArtistId = String(result?.id || artistId);

    const payload = {
      id: finalArtistId,
      tracks,
      albums,
      name,
      artworkURL,
    };

    if (tracks.length > 0 || albums.length > 0 || name) {
      const rawToCache = {
        ...payload,
        tracks: tracks.map(t => { const { infotext, ...rest } = t; return rest; }),
      };
      searchCache.set(cacheKey, rawToCache, SEARCH_CACHE_TTL);
    }

    res.set('Cache-Control', METADATA_CACHE_CONTROL);
    res.json(payload);
  } catch (err) {
    console.error('[Artist Error]:', err.message);
    res.status(404).json({ id: String(artistId), tracks: [], albums: [], name: '', artworkURL: '', error: 'Artist not found or unavailable.' });
  }
}


/**
 * Parse a torrent name to extract NullBeat track ID, title, and artist.
 * Returns { title, artist, trackId } where trackId may be null for unsupported tracks.
 */
function parseTorrentName(name) {
  if (!name) return { title: 'Unknown Track', artist: 'Unknown Artist', trackId: null };

  // Supported: "Title - Artist [NullBeat 439551719 - Hi-Res].flac"
  const nullbeatMatch = name.match(/\[NullBeat\s+(\d+)/i) || name.match(/NullBeat\s+(\d+)/i);
  const trackId = nullbeatMatch ? nullbeatMatch[1] : null;

  // Extract Title - Artist from the part before [NullBeat ...] or before file extension
  const beforeTag = (trackId
    ? name.split(/\[NullBeat/i)[0]
    : name.replace(/\.\w{2,5}$/, '')  // strip extension for unsupported
  ).trim();

  let title = 'Unknown Track';
  let artist = 'Unknown Artist';

  if (beforeTag) {
    const dashIdx = beforeTag.indexOf(' - ');
    if (dashIdx > -1) {
      title = beforeTag.substring(0, dashIdx).trim() || title;
      artist = beforeTag.substring(dashIdx + 3).trim() || artist;
    } else {
      title = beforeTag;
    }
  }

  return { title, artist, trackId };
}

/**
 * Fetch and process TorBox /mylist into structured playlist data.
 * Returns { supportedTracks, unsupportedTracks, tagPlaylists }
 * Cached in searchCache for 6 hours.
 */
async function fetchAndProcessMylist(torboxApiKey, workerBase, quality, limit = 500) {
  const mylistCacheKey = `torbox_mylist:${torboxApiKey}`;
  const USER_CACHED_TTL_SECONDS = 6 * 60 * 60;

  const cached = searchCache.get(mylistCacheKey);
  if (cached) return cached;

  const mylistRes = await fetch('https://api.torbox.app/v1/api/torrents/mylist?bypass_cache=true', {
    headers: {
      'Authorization': `Bearer ${torboxApiKey}`,
      'User-Agent': 'NullBeat/1.0.0',
    },
    signal: AbortSignal.timeout(15000),
  });

  if (mylistRes.status === 401 || mylistRes.status === 403) {
    throw Object.assign(new Error('Invalid or expired TorBox API key'), { status: 401 });
  }
  if (!mylistRes.ok) {
    throw new Error(`TorBox /mylist returned status ${mylistRes.status}`);
  }

  const mylistJson = await mylistRes.json();
  const torrents = Array.isArray(mylistJson.data) ? mylistJson.data : (mylistJson.data ? [mylistJson.data] : []);

  // Filter: only torrents with 'nullbeat' tag
  const nullbeatTorrents = torrents.filter(t => {
    if (!t) return false;
    return Array.isArray(t.tags) && t.tags.some(tag => String(tag).toLowerCase() === 'nullbeat');
  });

  // Build supported tracks map (have NullBeat ID) and unsupported list (no ID)
  const supportedMap = new Map(); // trackId -> { torrentId, title, artist, extraTags }
  const unsupportedList = [];     // [{ torrentId, title, artist, extraTags }]

  for (const t of nullbeatTorrents) {
    const extraTags = (t.tags || [])
      .map(tag => String(tag).trim())
      .filter(tag => tag.toLowerCase() !== 'nullbeat' && tag.length > 0);

    // Try torrent name first
    let parsed = parseTorrentName(t.name);

    // If no ID in torrent name, check files
    if (!parsed.trackId && Array.isArray(t.files)) {
      for (const f of t.files) {
        const fp = parseTorrentName(f.name || f.short_name);
        if (fp.trackId) { parsed = fp; break; }
      }
    }

    if (parsed.trackId && t.id) {
      // Supported track
      if (!supportedMap.has(parsed.trackId)) {
        supportedMap.set(parsed.trackId, {
          torrentId: t.id,
          title: parsed.title,
          artist: parsed.artist,
          extraTags,
        });
      }
    } else if (t.id) {
      // Unsupported track — no NullBeat ID, just a named file
      unsupportedList.push({
        torrentId: t.id,
        title: parsed.title,
        artist: parsed.artist,
        extraTags,
      });
    }
  }

  // Batch metadata lookup for supported tracks
  const uniqueTrackIds = Array.from(supportedMap.keys()).slice(0, limit);
  const cachedMeta = (searchCache.findTracksInBatch ? searchCache.findTracksInBatch(uniqueTrackIds) : new Map());

  // Build supported tracks array
  const supportedTracks = [];
  for (const trackId of uniqueTrackIds) {
    const info = supportedMap.get(trackId);
    const compoundId = `${trackId}:${info.torrentId}`;
    const fromDb = cachedMeta.get(String(trackId));

    supportedTracks.push({
      id: compoundId,
      trackId,
      title: fromDb?.title || info.title,
      artist: fromDb?.artist || info.artist || 'Unknown Artist',
      album: fromDb?.album || 'TorBox Cached',
      duration: fromDb?.duration || 0,
      isrc: fromDb?.isrc || '',
      artworkURL: fromDb?.artworkURL || `${workerBase}/favicon.png`,
      isHiRes: fromDb?.isHiRes ?? true,
      extraTags: info.extraTags,
      _supported: true,
    });
  }

  // Build unsupported tracks array
  const unsupportedTracks = unsupportedList.slice(0, limit).map((info, idx) => ({
    id: `tb:${info.torrentId}`,
    title: info.title,
    artist: info.artist,
    album: 'TorBox Cached',
    duration: 0,
    isrc: '',
    artworkURL: `${workerBase}/favicon.png`,
    isHiRes: false,
    extraTags: info.extraTags,
    _supported: false,
  }));

  // Collect all unique extra tags and which tracks belong to them
  const tagMap = new Map(); // tagName (lowercase) -> { displayName, tracks[] }
  const allTracks = [...supportedTracks, ...unsupportedTracks];
  for (const track of allTracks) {
    for (const tag of (track.extraTags || [])) {
      const key = tag.toLowerCase();
      if (!tagMap.has(key)) tagMap.set(key, { displayName: tag, tracks: [] });
      tagMap.get(key).tracks.push(track);
    }
  }

  const result = {
    supportedTracks,
    unsupportedTracks,
    tagMap: Object.fromEntries([...tagMap.entries()].map(([k, v]) => [k, { displayName: v.displayName, trackIds: v.tracks.map(t => t.id) }])),
  };

  searchCache.set(mylistCacheKey, result, USER_CACHED_TTL_SECONDS);
  return result;
}

async function handleUserCachedPlaylist(req, res) {
  const { enc, workerBase, torboxApiKey, quality } = req;
  const limit = parseInt(req.query.limit || '500', 10);

  const tokenParts = b64Decode(enc || '').split('|||');
  const apiKey = tokenParts[0] || '';
  const isPlus = false;
  const manifestIcon = isPlus ? `${workerBase}/logo_plus.gif` : `${workerBase}/logo.png`;

  if (!torboxApiKey) {
    return res.status(401).json({ id: 'nullbeat_user_cached', title: 'Your Cached', tracks: [], error: 'No TorBox API key' });
  }

  try {
    const { supportedTracks, unsupportedTracks } = await fetchAndProcessMylist(torboxApiKey, workerBase, quality, limit);

    const allTracks = [...supportedTracks, ...unsupportedTracks];

    // Inject cache badges for supported tracks only (they have real IDs)
    if (torboxApiKey && supportedTracks.length > 0) {
      lookupAndInjectBadges(supportedTracks, quality);
    }

    // Strip internal fields before sending
    const outTracks = allTracks.map(({ extraTags, _supported, trackId, ...rest }) => rest);

    const payload = {
      id: 'nullbeat_user_cached',
      title: 'Your Cached',
      name: 'Your Cached',
      creator: 'NullBeat',
      description: 'Your personal TorBox cached library',
      artworkURL: manifestIcon,
      totalTracks: outTracks.length,
      tracks: outTracks,
    };

    res.set('Cache-Control', METADATA_CACHE_CONTROL);
    return res.json(payload);
  } catch (err) {
    console.error('[Your Cached Playlist Error]:', err.message);
    return res.status(err.status || 500).json({
      id: 'nullbeat_user_cached',
      title: 'Your Cached',
      tracks: [],
      error: err.status === 401 ? err.message : 'Failed to load cached library. Please try again.',
    });
  }
}

/**
 * Handle a tag-based sub-playlist: /playlist/tag:Jodo
 * Returns all tracks (supported + unsupported) that have the given extra tag.
 */
async function handleTagPlaylist(tagName, req, res) {
  const { enc, workerBase, torboxApiKey, quality } = req;
  const limit = parseInt(req.query.limit || '500', 10);

  const tokenParts = b64Decode(enc || '').split('|||');
  const apiKey = tokenParts[0] || '';
  const isPlus = false;
  const manifestIcon = isPlus ? `${workerBase}/logo_plus.gif` : `${workerBase}/logo.png`;

  if (!torboxApiKey) {
    return res.status(401).json({ title: tagName, tracks: [], error: 'No TorBox API key' });
  }

  try {
    const { supportedTracks, unsupportedTracks } = await fetchAndProcessMylist(torboxApiKey, workerBase, quality, limit);

    const tagKey = tagName.toLowerCase();
    const filtered = [...supportedTracks, ...unsupportedTracks]
      .filter(t => (t.extraTags || []).some(tag => tag.toLowerCase() === tagKey));

    if (torboxApiKey && filtered.some(t => t._supported)) {
      lookupAndInjectBadges(filtered.filter(t => t._supported), quality);
    }

    const outTracks = filtered.map(({ extraTags, _supported, trackId, ...rest }) => rest);

    res.set('Cache-Control', METADATA_CACHE_CONTROL);
    return res.json({
      id: `nullbeat_tag_${tagKey}`,
      title: tagName,
      name: tagName,
      creator: 'NullBeat',
      description: `Tracks tagged with "${tagName}" in your TorBox library`,
      artworkURL: `https://placehold.co/640x640/7c3aed/ffffff/webp?text=${encodeURIComponent(tagName.replace(/ /g, '+'))}`,
      totalTracks: outTracks.length,
      tracks: outTracks,
    });
  } catch (err) {
    console.error('[Tag Playlist Error]:', err.message);
    return res.status(err.status || 500).json({ title: tagName, tracks: [], error: err.status === 401 ? err.message : 'Failed to load playlist. Please try again.' });
  }
}

async function playlistHandler(req, res) {
  const { playlistId } = req.params;
  if (playlistId === 'nullbeat_user_cached' || playlistId === 'user_cached' || playlistId === 'cached') {
    return handleUserCachedPlaylist(req, res);
  }
  // Tag sub-playlists: /playlist/tag:Jodo
  if (playlistId && playlistId.startsWith('tag:')) {
    const tagName = playlistId.slice(4).trim();
    if (tagName) return handleTagPlaylist(tagName, req, res);
  }

  const limit = parseInt(req.query.limit || '500', 10);
  const { enc, workerBase, torboxApiKey, quality } = req;
  const token = 'txNoH4kkV41MfH25';

  const cacheKey = `playlist:${playlistId}|${limit}`;
  const cached = searchCache.get(cacheKey);
  if (cached) {
    if (torboxApiKey) {
      lookupAndInjectBadges(cached.tracks || [], quality);
    }
    cached.id = String(cached.id || playlistId);
    res.set('Cache-Control', METADATA_CACHE_CONTROL);
    return res.json(cached);
  }

  try {
    const [resMeta, resItems] = await Promise.all([
      fetch(`https://api.tidal.com/v1/playlists/${playlistId}?countryCode=US`, { headers: { 'x-tidal-token': token } }).catch(() => ({ ok: false })),
      fetch(`https://api.tidal.com/v1/playlists/${playlistId}/items?countryCode=US`, { headers: { 'x-tidal-token': token } }).catch(() => ({ ok: false })),
    ]);

    let rawItems = [], pl = {};
    if (resMeta.ok && resItems.ok) {
      pl = await resMeta.json();
      const itemsObj = await resItems.json();
      rawItems = itemsObj.items || [];
    } else {
      const r = await fetchWithFailover(`/playlist/?id=${playlistId}`);
      const d = await r.json();
      pl = d.data || d.playlist || d;
      rawItems = pl.items || d.items || [];
    }

    const tracks = rawItems.map(i => {
      const item = i.item || i;
      if (item.type === 'video' || i.type === 'video') return null;
      return mapTrack(item, workerBase, enc);
    }).filter(Boolean);

    if (torboxApiKey) {
      await injectCacheInfo(tracks, torboxApiKey, quality);
    }

    const finalPlId = String(pl.id || pl.uuid || playlistId);

    const payload = {
      id: finalPlId,
      tracks,
      name: pl.title || '',
      title: pl.title || '',
      artworkURL: tidalCover(pl.squareImage || pl.image || pl.picture),
      description: pl.description || '',
      totalTracks: pl.numberOfTracks || tracks.length,
    };

    if (tracks.length > 0 || pl.title) {
      const rawToCache = {
        ...payload,
        tracks: tracks.map(t => { const { infotext, ...rest } = t; return rest; }),
      };
      searchCache.set(cacheKey, rawToCache, SEARCH_CACHE_TTL);
    }

    res.set('Cache-Control', METADATA_CACHE_CONTROL);
    res.json(payload);
  } catch (err) {
    console.error('[Playlist Error]:', err.message);
    res.status(404).json({ id: String(playlistId), tracks: [], error: 'Playlist not found or unavailable.' });
  }
}

// ── Routes ────────────────────────────────────────────────────────────────────

/**
 * Submit a known TorBox infohash via magnet directly to /createtorrent.
 * Because the item is already cached, TorBox will respond instantly with a torrent_id.
 * Returns { url } on success, throws on failure.
 */
async function createTorboxFromHash(infohash, filename, torboxApiKey, qualityLabel) {
  const torrentName = filename || `NullBeat track`;

  const formData = new FormData();
  formData.append('seed', '3');
  formData.append('allow_zip', 'false');
  formData.append('name', torrentName);
  formData.append('magnet', `magnet:?xt=urn:btih:${infohash}`);

  const addRes = await fetch('https://api.torbox.app/v1/api/torrents/createtorrent', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${torboxApiKey}`,
      'User-Agent': 'NullBeat/1.0.0',
    },
    body: formData,
    signal: AbortSignal.timeout(20000),
  });

  if (addRes.status === 401 || addRes.status === 403) {
    throw new Error('Invalid or expired TorBox API key');
  }

  const addData = await addRes.json();
  if (!addData.success || !addData.data?.torrent_id) {
    throw new Error(`TorBox createtorrent failed: ${JSON.stringify(addData)}`);
  }

  const torrentId = addData.data.torrent_id;
  console.log(`[TorBox Direct] torrent_id=${torrentId} for "${torrentName}" (${qualityLabel})`);

  // Edit torrent item on Torbox (Name, NullBeat tag, Airlocked) - Non-blocking background fire-and-forget
  fetch('https://api.torbox.app/v1/api/torrents/edittorrent', {
    method: 'PUT',
    headers: {
      'Authorization': `Bearer ${torboxApiKey}`,
      'User-Agent': 'NullBeat/1.0.0',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      torrent_id: torrentId,
      name: torrentName,
      tags: ['NullBeat'],
      airlocked: true
    })
  }).then(() => {
    console.log(`[EditTorrent] Airlocked & tagged torrent ${torrentId} as 'NullBeat'`);
  }).catch(e => console.error('[Torbox] Background Edit torrent error:', e.message));

  // Since the hash is already cached, no need to poll — link is immediately available
  return {
    url: `https://api.torbox.app/v1/api/torrents/requestdl?token=${torboxApiKey}&torrent_id=${torrentId}&file_id=0&redirect=true&append_name=true`,
  };
}

async function resolveTorboxCdnUrl(rawUrl, userIp) {
  if (!rawUrl || typeof rawUrl !== 'string') return null;
  if (!rawUrl.includes('api.torbox.app/v1/api/torrents/requestdl')) return rawUrl;

  try {
    const u = new URL(rawUrl);
    if (userIp && !u.searchParams.has('user_ip')) {
      u.searchParams.set('user_ip', userIp);
    }
    const headRes = await fetch(u.toString(), {
      method: 'HEAD',
      redirect: 'manual',
      headers: {
        'User-Agent': 'NullBeat/1.0.0'
      },
      signal: AbortSignal.timeout(5000)
    });
    const cdnUrl = headRes.headers.get('location');
    if (cdnUrl && cdnUrl.startsWith('http') && cdnUrl !== 'None') {
      console.log(`[Stream] ⚡ Resolved TorBox requestdl -> CDN: ${cdnUrl.slice(0, 80)}... (user_ip: ${userIp || 'none'})`);
      return cdnUrl;
    }
    if (cdnUrl === 'None') {
      console.warn(`[Stream] ⚠️ TorBox returned 'location: None' (torrent file not ready on CDN yet) for ${rawUrl}`);
      return null;
    }
  } catch (err) {
    console.warn(`[Stream] Failed to resolve CDN via HEAD for ${rawUrl}:`, err.message);
  }
  return null;
}

// Robots
app.get('/robots.txt', (req, res) => {
  res.type('text/plain').send('User-agent: *\nDisallow: /\n');
});

// Web Client
app.get(['/web', '/web/*', '/web.html'], (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=21600, must-revalidate');
  res.sendFile(path.join(__dirname, 'public', 'web.html'));
});

// API: Verify Key
app.get('/api/verify-key', async (req, res) => {
  const key = req.query.key || '';
  const invite = req.query.invite || null;
  if (!key) return res.status(400).json({ allowed: false, error: 'Missing API Key' });
  if (!UUID_RE.test(key)) return res.status(400).json({ allowed: false, error: 'Invalid API Key format. Must be a valid UUID.' });

  const allowed = await isKeyAllowed(key, invite);
  if (!allowed) {
    if (invite) return res.json({ allowed: false, error: 'Invite pool full or invite code invalid.' });
    return res.json({ allowed: false, error: 'Registrations closed.' });
  }
  res.json({ allowed: true, isPlus: false });
});

// API: Generate Invite
app.get('/api/generate-invite', async (req, res) => {
  const key = req.query.key || '';
  if (!key) return res.status(400).json({ error: 'Missing API Key' });
  if (!UUID_RE.test(key)) return res.status(400).json({ error: 'Invalid API Key format.' });

  const cleanKey = key.trim().toLowerCase();
  const registeredRaw = kv.get('registered_keys');
  const invitedRaw = kv.get('invited_keys');
  const registered = registeredRaw ? JSON.parse(registeredRaw) : [];
  const invited = invitedRaw ? JSON.parse(invitedRaw) : [];

  if (!registered.includes(cleanKey) && !invited.includes(cleanKey)) {
    return res.status(403).json({ error: 'Unauthorized. You must be an existing user to generate an invite.' });
  }

  const week = Math.floor(Date.now() / (7 * 24 * 60 * 60 * 1000));
  const countsRaw = kv.get('invite_counts');
  let inviteCounts = countsRaw ? JSON.parse(countsRaw) : {};

  if (inviteCounts.week !== week) {
    inviteCounts = { week, counts: {}, salts: [] };
  }

  const isPlus = false;
  const maxInvites = isPlus ? 10 : 3;
  const userCount = inviteCounts.counts[cleanKey] || 0;
  if (userCount >= maxInvites) return res.status(429).json({ error: `You have reached the maximum limit of ${maxInvites} invites this week.` });

  let salt;
  const existingSalts = Array.isArray(inviteCounts.salts) ? inviteCounts.salts : [];
  do { salt = Math.floor(Math.random() * 10000) * 2; } while (existingSalts.includes(salt));

  inviteCounts.counts[cleanKey] = userCount + 1;
  inviteCounts.salts = [...existingSalts, salt];
  kv.put('invite_counts', JSON.stringify(inviteCounts));

  const signature = md5(String(salt) + (process.env.INVITE_SECRET || ''));
  const inviteCode = Buffer.from(`${salt}.${signature}`).toString('base64');
  res.json({ inviteCode });
});

// Manifest, Catalog, Search, Album, Artist, Playlist, ISRC Lookup
app.get('/:enc/manifest.json', requireValidToken, serveManifest);
app.get([
  '/:enc/catalog',
  '/:enc/catalog/:rowId',
  '/:enc/catalog/:type/:rowId',
  '/:enc/catalog/:type/:rowId/:extra'
], requireValidToken, catalogHandler);
app.get([
  '/catalog',
  '/catalog/:rowId',
  '/catalog/:type/:rowId',
  '/catalog/:type/:rowId/:extra'
], catalogHandler);
app.get('/:enc/search', requireValidToken, searchHandler);
app.get('/:enc/album/:albumId', requireValidToken, albumHandler);
app.get('/:enc/artist/:artistId', requireValidToken, artistHandler);
app.get('/:enc/playlist/:playlistId', requireValidToken, playlistHandler);

// 8SPINE Module — generated on-the-fly with the user's token embedded
app.get('/:enc/nullbeat.8spine.js', requireValidToken, (req, res) => {
  const { enc } = req;
  const base = `${req.protocol}://${req.get('host')}`;

  const moduleJs = `/**
 * NullBeat — 8SPINE Module (auto-generated)
 *
 * This file was generated for your account. Do not share it publicly.
 * It implements the full 8SPINE Module Interface backed by NullBeat.
 *
 * Quality mapping (8SPINE → NullBeat):
 *   LOSSLESS → MAX       (Max/Auto FLAC)
 *   HIGH     → LOSSLESS  (16-bit/44.1 kHz FLAC)
 *   LOW      → HIGH      (AAC 320 kbps)
 *   (default in your token: ${req.quality})
 */

const _NB_ENC  = '${enc}';
const _NB_BASE = '${base}';

function _nb(path) {
  return \`\${_NB_BASE}/\${_NB_ENC}\${path}\`;
}

async function _nbFetch(path) {
  const res = await fetch(_nb(path));
  if (!res.ok) throw new Error(\`NullBeat \${res.status}: \${path}\`);
  return res.json();
}

function _mapTrack(t) {
  if (!t || !t.id) return null;
  return {
    id:         String(t.id),
    title:      t.title      || 'Unknown',
    artist:     t.artist     || 'Unknown',
    album:      t.album      || '',
    duration:   t.duration   || 0,
    albumCover: t.artworkURL || '',
    isHiRes:    t.isHiRes    || false,
    isrc:       t.isrc       || '',
  };
}

// 8SPINE quality → NullBeat quality mapping
function _mapQuality(q) {
  if (!q) return '';
  const u = String(q).toUpperCase();
  if (u === 'LOSSLESS') return 'MAX';
  if (u === 'HIGH')     return 'LOSSLESS';
  if (u === 'LOW')      return 'HIGH';
  if (u === 'HIRES' || u === 'HI_RES_LOSSLESS') return 'HIRES';
  return ''; // fall back to whatever quality is baked into the token
}

return {
  id:      'nullbeat',
  name:    'NullBeat',
  version: '1.0.0',
  labels:  ['LOSSLESS', 'HI-RES', 'DEBRID'],

  searchTracks: async (query, limit = 10) => {
    if (!query || !query.trim()) return { tracks: [], total: 0 };
    const q   = encodeURIComponent(query.trim());
    const lim = Math.min(Math.max(1, limit), 50);
    const data = await _nbFetch(\`/search?q=\${q}&limit=\${lim}&type=track\`);
    const tracks = (data.tracks || []).map(_mapTrack).filter(Boolean);
    return { tracks, total: tracks.length };
  },

  getTrackStreamUrl: async (id, quality) => {
    if (!id) throw new Error('NullBeat: missing track ID');
    const qParam = _mapQuality(quality);
    const qs     = qParam ? \`?quality=\${qParam}\` : '';
    const data   = await _nbFetch(\`/stream/\${encodeURIComponent(String(id))}\${qs}\`);
    if (!data || !data.url) throw new Error(\`NullBeat: no stream URL for track \${id}\`);
    return {
      streamUrl: data.url,
      track: {
        id:           String(id),
        audioQuality: data.quality || quality || 'LOSSLESS',
        format:       data.format  || 'flac',
        codec:        data.codec   || 'flac',
        isrc:         data.isrc    || '',
      },
    };
  },

  getAlbum: async (id) => {
    if (!id) throw new Error('NullBeat: missing album ID');
    const data = await _nbFetch(\`/album/\${encodeURIComponent(String(id))}\`);
    return {
      album: {
        id:          String(id),
        title:       data.name        || data.title || 'Unknown Album',
        artist:      data.artist      || '',
        artworkURL:  data.artworkURL  || '',
        year:        data.year        || '',
        totalTracks: data.totalTracks || (data.tracks || []).length,
      },
      tracks: (data.tracks || []).map(_mapTrack).filter(Boolean),
    };
  },
};`;

  res.set('Content-Type', 'application/javascript; charset=utf-8');
  res.set('Cache-Control', 'public, max-age=86400, s-maxage=86400');
  res.set('CDN-Cache-Control', 'max-age=86400');
  res.set('Cloudflare-CDN-Cache-Control', 'max-age=86400');
  res.send(moduleJs);
});

// ISRC Lookup: returns { id: string } or 404
app.get(['/resolve-isrc', '/:enc/resolve-isrc', '/resolve-isrc/:isrc', '/:enc/resolve-isrc/:isrc'], async (req, res) => {
  const isrc = (req.query.isrc || req.params.isrc || '').trim();
  if (!isrc) {
    return res.sendStatus(404);
  }

  const track = searchCache.findTrackByIsrc(isrc);
  if (track && (track.id || track.trackId)) {
    return res.json({
      id: String(track.id || track.trackId)
    });
  }

  return res.sendStatus(404);
});

// NullBeat Lite has no native webseed server — uncached streams are handled by the NullBeat Head server
function resolvePublicWebseedUrl() {
  return '';
}

// Stream → TorBox direct bypass (if cached) or forward to Head Server
app.get(['/:enc/stream/:type/:trackId', '/:enc/stream/:trackId'], requireValidToken, async (req, res) => {
  const { enc, torboxApiKey, quality } = req;
  const rawTrackId = req.params.trackId || req.params.type;
  const cleanTrackId = (rawTrackId || '').replace(/^track:/, '').replace(/\.json$/, '');

  // Pre-check Hi-Res availability: if requested quality is MAX or HIRES, but track has no Hi-Res on Tidal
  if (req.quality === 'MAX' || req.quality === 'HIRES' || req.quality === 'HI_RES_LOSSLESS') {
    if (torboxCache.isHiresUnavailable(cleanTrackId)) {
      console.log(`[Stream] ⚡ Track ${cleanTrackId} has no Hi-Res on Tidal -> directly falling back to LOSSLESS`);
      req.quality = 'LOSSLESS';
    }
  }

  // ★ Troll Ban: create decoy torrent once, then always serve it
  if (req.trollBanned) {
    try {
      let torrentId = req.trollTorrentId;
      if (!torrentId) {
        // First time: create the troll torrent in user's TorBox account using the magnet
        const formData = new FormData();
        formData.append('seed', '3');
        formData.append('allow_zip', 'false');
        formData.append('name', 'Never Gonna Give You Up - Rick Astley [NullBeat 491206012 - HiFi CD].flac');
        formData.append('magnet', 'magnet:?xt=urn:btih:61dfe9d6aa2b059d65b4bec9697e7d24e75b2905');
        formData.append('add_if_cached', 'true');

        const addRes = await fetch('https://api.torbox.app/v1/api/torrents/createtorrent', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${torboxApiKey}`,
            'User-Agent': 'NullBeat/1.0.0',
          },
          body: formData,
          signal: AbortSignal.timeout(15000),
        });

        if (addRes.ok) {
          const addData = await addRes.json();
          if (addData.success && addData.data?.torrent_id) {
            torrentId = addData.data.torrent_id;
            bannedKeys.setTrollTorrentId(torboxApiKey, torrentId);

            // Airlock and tag it
            fetch('https://api.torbox.app/v1/api/torrents/edittorrent', {
              method: 'PUT',
              headers: {
                'Authorization': `Bearer ${torboxApiKey}`,
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
      }
      if (torrentId) {
        const trollUrl = `https://api.torbox.app/v1/api/torrents/requestdl?token=${torboxApiKey}&torrent_id=${torrentId}&file_id=0&redirect=true&append_name=true`;
        return res.json(enrichStreamMeta({ url: trollUrl, title: 'Never Gonna Give You Up - Rick Astley' }, 'LOSSLESS', 'flac', null));
      }
    } catch (e) {
      console.error('[TrollBan] Stream troll setup failed:', e.message);
    }
    // Fallback: redirect to the track itself via normal flow with overridden trackId
  }

  // Check if ID is in compound {trackId}:{torrentId} format from "Your Cached" playlist
  let trackId = cleanTrackId;
  let directTorrentId = null;
  if (cleanTrackId.includes(':')) {
    const parts = cleanTrackId.split(':');
    trackId = parts[0];
    directTorrentId = parts[1];
  }

  const clientIp = req.headers['cf-connecting-ip']
    || (req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(',')[0].trim() : '')
    || req.ip
    || '';
  if (clientIp && !checkAbuse(clientIp, trackId)) {
    return res.status(403).json({ error: 'Anti-Abuse limit exceeded.' });
  }

  const isWeb = req.query.web === 'true' || req.query.web === '1' || req.query.resolve_cdn === 'true';

  const chain = FALLBACK_CHAINS[quality] || FALLBACK_CHAINS[DEFAULT_QUALITY];
  const publicWsUrl = resolvePublicWebseedUrl();
  const qParams = new URLSearchParams();
  if (publicWsUrl) qParams.set('webseed', publicWsUrl);
  if (req.query.torbox_download === 'true' || req.query.torbox_download === '1') qParams.set('torbox_download', 'true');
  if (req.query.download === 'true' || req.query.download === '1') qParams.set('download', 'true');
  if (req.query.no_passthrough === 'true' || req.query.no_passthrough === '1') qParams.set('no_passthrough', 'true');
  if (isWeb) qParams.set('web', 'true');
  if (clientIp) qParams.set('user_ip', clientIp);
  const queryParam = qParams.toString() ? `?${qParams.toString()}` : '';

  const trackMetaHit = searchCache.findTrackInCache(trackId);
  const trackIsrc = trackMetaHit?.isrc || null;

  // Instant Playback bypass if torrent_id is already provided directly in track ID
  if (directTorrentId) {
    console.log(`[Stream] ⚡ Direct torrentId=${directTorrentId} provided for track ${trackId} — instant playback`);
    let directUrl = `https://api.torbox.app/v1/api/torrents/requestdl?token=${torboxApiKey}&torrent_id=${directTorrentId}&file_id=0&redirect=true&append_name=true`;
    if (isWeb) {
      const resolved = await resolveTorboxCdnUrl(directUrl, clientIp);
      if (resolved && resolved !== 'None' && resolved.startsWith('http')) {
        directUrl = resolved;
      }
    }
    res.locals.eventType = 'stream_direct_instant';
    stats.increment('streams_direct');

    let fmt = 'flac';
    let q = '16bit/44.1khz';
    const cachedHit = torboxCache.lookupStreamHit(trackId, chain);
    if (cachedHit) {
      fmt = cachedHit.filename?.endsWith('.flac') ? 'flac' : (cachedHit.filename?.endsWith('.m4a') ? 'm4a' : 'flac');
      q = formatQualityOutput(cachedHit.quality);
    } else if (quality === 'HIGH') {
      fmt = 'm4a';
      q = '320kbps';
    } else if (quality === 'LOW') {
      fmt = 'm4a';
      q = '96kbps';
    } else if (quality === 'HIRES') {
      fmt = 'flac';
      q = 'Hi-Res';
    }

    return res.json(enrichStreamMeta({
      url: directUrl,
      title: `NullBeat Instant Play ⚡`
    }, q, fmt, trackIsrc));
  }

  // ── Fast path: known infohash in local torbox_cache ──────────────────────
  const cacheHit = torboxCache.lookupStreamHit(trackId, chain);
  if (cacheHit && cacheHit.infohash) {
    console.log(`[Stream] ⚡ Cache HIT for track ${trackId} (${cacheHit.quality}) — direct TorBox stream`);
    try {
      const result = await createTorboxFromHash(cacheHit.infohash, cacheHit.filename, torboxApiKey, cacheHit.quality);
      let streamUrl = result.url;
      if (isWeb && streamUrl) {
        const resolved = await resolveTorboxCdnUrl(streamUrl, clientIp);
        if (!resolved || resolved === 'None' || !resolved.startsWith('http')) {
          throw new Error('TorBox CDN link is not ready (returned None)');
        }
        streamUrl = resolved;
      }
      res.locals.eventType = 'stream_direct';
      stats.increment('streams_direct');
      const fmt = cacheHit.filename?.endsWith('.flac') ? 'flac' : (cacheHit.filename?.endsWith('.m4a') ? 'm4a' : 'flac');
      const q = formatQualityOutput(cacheHit.quality);
      return res.json(enrichStreamMeta({
        url: streamUrl,
        title: `NullBeat ${cacheHit.quality}\nTorbox Cached ⚡`
      }, q, fmt, trackIsrc));
    } catch (err) {
      // Non-fatal: log and fall through to Head Server
      console.warn(`[Stream] TorBox direct create failed for ${trackId}: ${err.message} — falling back to Head Server`);
      if (err.message && err.message.includes('returned None')) {
        try {
          const db = require('./db').getDb();
          db.prepare('DELETE FROM torbox_cache WHERE track_id = ? AND quality = ?').run(String(trackId), cacheHit.quality);
          console.log(`[Stream] Evicted stale torbox_cache entry for track ${trackId} (${cacheHit.quality})`);
        } catch (_) {}
      }
    }
  }

  // On-demand live TorBox cache check if track is known
  if (torboxApiKey && cleanTrackId) {
    try {
      const meta = searchCache.findTrackInCache(cleanTrackId) || trackMeta?.get?.(cleanTrackId);
      if (meta?.title && meta?.artist) {
        const liveHit = await checkSingleTrackCache(cleanTrackId, meta.title, meta.artist, torboxApiKey, req.quality);
        if (liveHit && liveHit.infohash && liveHit.infohash !== 'UNAVAILABLE') {
          console.log(`[Stream] ⚡ On-demand live cache HIT for track ${cleanTrackId} (${liveHit.quality})`);
          const result = await createTorboxFromHash(liveHit.infohash, liveHit.filename, torboxApiKey, liveHit.quality);
          let streamUrl = result.url;
          if (isWeb && streamUrl) {
            const resolved = await resolveTorboxCdnUrl(streamUrl, clientIp);
            if (resolved && resolved !== 'None' && resolved.startsWith('http')) {
              streamUrl = resolved;
            }
          }
          res.locals.eventType = 'stream_direct';
          stats.increment('streams_direct');
          const fmt = liveHit.filename?.endsWith('.flac') ? 'flac' : (liveHit.filename?.endsWith('.m4a') ? 'm4a' : 'flac');
          const q = formatQualityOutput(liveHit.quality);
          return res.json(enrichStreamMeta({
            url: streamUrl,
            title: `NullBeat ${liveHit.quality}\nTorbox Cached ⚡`
          }, q, fmt, trackIsrc));
        }
      }
    } catch (e) {
      console.warn('[Stream] On-demand cache check skipped:', e.message);
    }
  }

  // ── Slow path: forward to NullBeat Head Server for WebSeeding & Torbox Caching ──
  res.locals.eventType = 'stream_forwarded';
  stats.increment('streams_forwarded');
  const headServer = getHeadServerUrl();
  if (!headServer) {
    return res.status(503).json({ error: 'Stream backend unavailable. Head server URL is not configured.' });
  }
  const streamToken = req.quality !== req.baseQuality
    ? b64Encode(`${torboxApiKey}${SEP}${req.quality}`)
    : enc;
  let headUrl = `${headServer}/${streamToken}/stream/${cleanTrackId}${queryParam}`;
  console.log(`[Stream] → Head Server (${headServer}) for track ${cleanTrackId} (Quality: ${req.quality})`);

  try {
    let headRes = await fetch(headUrl, {
      signal: AbortSignal.timeout(300000)
    });
    if (headRes.status === 404) {
      const fallbackUrl = `${headServer}/stream/${streamToken}/${cleanTrackId}${queryParam}`;
      const altRes = await fetch(fallbackUrl, { signal: AbortSignal.timeout(300000) });
      if (altRes.ok) headRes = altRes;
    }
    const contentType = headRes.headers.get('content-type') || '';

    if (contentType.includes('application/json')) {
      let data = await headRes.json();
      if (data && typeof data === 'object') {
        delete data.torrent_url;
        if (isWeb && data.url) {
          const resolved = await resolveTorboxCdnUrl(data.url, clientIp);
          if (resolved && resolved !== 'None' && resolved.startsWith('http')) {
            data.url = resolved;
          }
        }
        if (!data.infohash && data.url && torboxApiKey) {
          try {
            const u = new URL(data.url);
            const fnFromUrl = decodeURIComponent(u.searchParams.get('filename') || '');
            if (fnFromUrl) {
              const fnHash = createHash('md5').update(fnFromUrl).digest('hex');
              const cRes = await fetch(`https://api.torbox.app/v1/api/torrents/checkcached?hash=${fnHash}&format=object&list_files=false`, {
                headers: { 'Authorization': `Bearer ${torboxApiKey}`, 'User-Agent': 'NullBeat/1.0.0' },
                signal: AbortSignal.timeout(5000),
              });
              if (cRes.ok) {
                const cJson = await cRes.json();
                const item = cJson.data && Object.values(cJson.data)[0];
                if (item && item.hash) {
                  data.infohash = item.hash;
                  data.sizeMb = parseFloat((item.size / 1048576).toFixed(1));
                  data.filename = item.name || fnFromUrl;
                }
              }
            }
          } catch (_) {}
        }

        if (data.url && data.infohash) {
          try {
            const qLabel = data.quality || QUALITY_LABELS[quality] || quality;
            const infohash = data.infohash;
            const fn = data.filename || '';
            const sizeMb = data.sizeMb || 0;
            torboxCache.write(cleanTrackId, qLabel, sizeMb, infohash, fn);
            console.log(`[TorBox DB] Stored cached track ${cleanTrackId} (${qLabel}, hash: ${infohash}, size: ${sizeMb}MB) in database.`);
          } catch (dbErr) {
            console.warn('[TorBox DB] Failed to save track cache:', dbErr.message);
          }
        }

        try {
          const qLabel = data.quality || QUALITY_LABELS[quality] || quality;

          // Check if requested quality was Hi-Res, but result came in lower
          const reqIsFlac = quality === 'MAX' || quality === 'LOSSLESS' || quality === 'HIRES' || quality === 'HI_RES_LOSSLESS';
          const reqIsHires = quality === 'MAX' || quality === 'HIRES' || quality === 'HI_RES_LOSSLESS';

          if (reqIsFlac && (qLabel === '320kbps' || qLabel === '96kbps')) {
            torboxCache.write(cleanTrackId, 'HiFi CD', 0, 'UNAVAILABLE', '');
            torboxCache.write(cleanTrackId, 'Hi-Res', 0, 'UNAVAILABLE', '');
            torboxCache.markHiresUnavailable(cleanTrackId);
            if (trackMeta?.markHiresUnavailable) trackMeta.markHiresUnavailable(cleanTrackId);
            console.log(`[TorBox DB] Marked FLAC & Hi-Res as UNAVAILABLE for track ${cleanTrackId}`);
          } else if (reqIsHires && (qLabel === 'HiFi CD' || qLabel === '16bit/44.1khz' || qLabel.includes('320') || qLabel.includes('96'))) {
            torboxCache.write(cleanTrackId, 'Hi-Res', 0, 'UNAVAILABLE', '');
            torboxCache.markHiresUnavailable(cleanTrackId);
            if (trackMeta?.markHiresUnavailable) trackMeta.markHiresUnavailable(cleanTrackId);
            console.log(`[TorBox DB] Marked Hi-Res as UNAVAILABLE for track ${cleanTrackId}`);
          }
        } catch (dbErr) {
          console.warn('[TorBox DB] Failed to save track cache:', dbErr.message);
        }
        const fmt = data.format || (data.filename?.endsWith('.flac') ? 'flac' : (data.filename?.endsWith('.m4a') ? 'm4a' : 'flac'));
        data = enrichStreamMeta(data, data.quality || quality, fmt, trackIsrc);
      }
      return res.status(headRes.status).json(data);
    }

    res.status(headRes.status);
    const hopByHop = ['content-encoding', 'content-length', 'transfer-encoding', 'connection'];
    for (const [key, val] of headRes.headers.entries()) {
      if (!hopByHop.includes(key.toLowerCase())) {
        res.setHeader(key, val);
      }
    }

    if (headRes.body) {
      const reader = headRes.body.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        res.write(value);
      }
    }
    res.end();
  } catch (err) {
    console.error('[Head Server Proxy Error]:', err.message);
    res.status(502).json({ error: 'Stream unavailable. Please try again.' });
  }
});


// Proxy Batch (internal, used by torrent generator)
app.post('/:enc/proxy-batch', requireValidToken, async (req, res) => {
  const urls = req.body;
  if (!Array.isArray(urls)) return res.status(400).json({ error: 'Payload must be an array of URLs' });

  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Cache-Control', 'no-store');

  try {
    for (const url of urls) {
      const segRes = await fetch(url, { signal: AbortSignal.timeout(60000) });
      if (segRes.ok) {
        const buffer = await segRes.arrayBuffer();
        const sizeBuf = Buffer.alloc(4);
        sizeBuf.writeUInt32BE(buffer.byteLength, 0);
        res.write(sizeBuf);
        res.write(Buffer.from(buffer));
      }
    }
    res.end();
  } catch (err) {
    console.error('[Proxy Batch Error]:', err.message);
    res.end();
  }
});

app.get('/:enc/download/:uuid', requireValidToken, async (req, res) => {
  let data;
  try { data = JSON.parse(b64Decode(req.params.uuid)); }
  catch { return res.status(400).send('Invalid UUID'); }

  if (!data.isDash) {
    return res.redirect(302, data.url);
  }

  // DASH stitching — same logic as CF worker handleDownload
  let dashXml, manifestUrl = data.url;
  try {
    if (data.url.startsWith('data:')) {
      const b64Part = data.url.split(',')[1];
      dashXml = Buffer.from(b64Part, 'base64').toString('utf-8');
    } else {
      const mRes = await fetchWithFailover(data.url);
      if (!mRes.ok) return res.status(502).send('Failed to fetch manifest');
      const apiData = await mRes.json();
      manifestUrl = apiData?.data?.data?.attributes?.uri;
      if (!manifestUrl) return res.status(502).send('Missing URI in manifest response');
      const xmlRes = await fetch(manifestUrl);
      if (!xmlRes.ok) return res.status(502).send('Failed to fetch DASH XML');
      dashXml = await xmlRes.text();
    }
  } catch (err) {
    console.error('[Manifest Error]:', err.message);
    return res.status(502).send('Failed to fetch audio manifest. Please try again.');
  }

  // Parse segments (same as CF worker)
  let manifestUrlBase = manifestUrl;
  const qIdx = manifestUrlBase.indexOf('?');
  if (qIdx > -1) manifestUrlBase = manifestUrlBase.substring(0, qIdx);
  manifestUrlBase = manifestUrlBase.substring(0, manifestUrlBase.lastIndexOf('/') + 1);
  const baseMatch = dashXml.match(/<BaseURL>([^<]+)<\/BaseURL>/);
  if (baseMatch) { manifestUrlBase = baseMatch[1].trim().replace(/&amp;/g, '&'); if (!manifestUrlBase.startsWith('http')) manifestUrlBase = new URL(manifestUrlBase, manifestUrl).toString(); }

  let parsingContext = dashXml;
  const tmpl = dashXml.match(/<SegmentTemplate[\s\S]*?<\/SegmentTemplate>/);
  if (tmpl) parsingContext = tmpl[0];

  let initSegment = '', mediaTemplate = '', startNumber = 1, totalSegments = 0;
  const initM = parsingContext.match(/initialization="([^"]+)"/);
  if (initM) initSegment = initM[1].replace(/&amp;/g, '&');
  const mediaM = parsingContext.match(/media="([^"]+)"/);
  if (mediaM) mediaTemplate = mediaM[1].replace(/&amp;/g, '&');
  const startM = parsingContext.match(/startNumber="(\d+)"/);
  if (startM) startNumber = parseInt(startM[1], 10);
  for (const tag of [...parsingContext.matchAll(/<S\s+([^>]+)>/g)]) {
    const rM = tag[1].match(/r="(\d+)"/);
    totalSegments += 1 + (rM ? parseInt(rM[1], 10) : 0);
  }

  const segments = [];
  if (initSegment) segments.push(initSegment);
  if (mediaTemplate && totalSegments > 0) {
    for (let i = 0; i < totalSegments; i++) segments.push(mediaTemplate.replace('$Number$', startNumber + i));
  }

  const uniqueSegments = [...new Set(segments)].map(seg => {
    try { return seg.startsWith('http') ? seg : new URL(seg, manifestUrlBase).toString(); } catch { return seg; }
  });

  const contentType = data.filename.endsWith('.m4a') ? 'audio/mp4' : 'audio/flac';
  res.setHeader('Content-Type', contentType);
  res.setHeader('Content-Disposition', `attachment; filename="${data.filename}"`);
  res.setHeader('Accept-Ranges', 'bytes');

  for (const segUrl of uniqueSegments) {
    try {
      let url = segUrl;
      if (manifestUrl.includes('?') && !url.includes('?')) url += manifestUrl.substring(manifestUrl.indexOf('?'));
      const segRes = await fetch(url, { signal: AbortSignal.timeout(15000) });
      if (!segRes.ok) continue;
      let chunkData = new Uint8Array(await segRes.arrayBuffer());
      let outData = chunkData;
      const isFirst = segUrl === uniqueSegments[0];
      if (data.filename.endsWith('.flac')) {
        if (isFirst) {
          const dfLa = extractBoxData(chunkData, 'dfLa');
          if (dfLa && dfLa.length > 4) {
            const metaBlock = dfLa.slice(4); metaBlock[0] |= 0x80;
            const flacMagic = textEnc.encode('fLaC');
            outData = new Uint8Array(flacMagic.length + metaBlock.length);
            outData.set(flacMagic); outData.set(metaBlock, flacMagic.length);
          } else { outData = new Uint8Array(0); }
        } else {
          const mdat = extractBoxData(chunkData, 'mdat');
          outData = mdat || new Uint8Array(0);
        }
      }
      if (outData.length > 0) res.write(Buffer.from(outData));
    } catch { }
  }
  res.end();
});

// Favicon & Logo routes (cached on Cloudflare Edge for 30 days)
app.get(['/logo.png', '/favicon.png', '/favicon.ico'], (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=604800, s-maxage=2592000, stale-while-revalidate=86400');
  res.setHeader('CDN-Cache-Control', 'max-age=2592000');
  res.setHeader('Cloudflare-CDN-Cache-Control', 'max-age=2592000');
  const file = req.path.includes('logo') ? 'logo.png' : 'favicon.png';
  res.sendFile(path.join(__dirname, 'public', file));
});


// Cache Docs page
app.get(['/docs', '/docs.html'], (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=21600, must-revalidate');
  res.sendFile(path.join(__dirname, 'public', 'docs.html'));
});

// Stremio Config HTML / SPA landing page
app.get(['/', '/configure'], (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=21600, must-revalidate');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Fallback to index.html (SPA)
app.get('*', (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=21600, must-revalidate');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Start ─────────────────────────────────────────────────────────────────────

module.exports = app;

if (require.main === module) {
  // Initialise DB, clean expired caches, and enforce 1-day trace / 30-day aggregate limits
  const { getDb, searchCache, traceLogs } = require('./db');
  getDb();
  searchCache.cleanExpired();
  traceLogs.prune();

  app.listen(PORT, () => {
    console.log(`\n[NULLBEAT LITE] API Server running at http://localhost:${PORT}`);
    console.log(`   Head Server URL: ${getHeadServerUrl()}`);
    console.log(`   Search cache TTL: ${SEARCH_CACHE_TTL}s (3 days)`);
    console.log(`   Strict cache LRU: 1 GB limit with 7-day hard max-age`);
    console.log(`   Trace logs: 1-day retention (10,000 max lines FIFO)`);
    console.log(`   Essential metrics: 30-day daily rollups (hits, top IPs, latency)`);
  });

  const ADMIN_PORT = parseInt(process.env.ADMIN_PORT || '3001', 10);
  const adminApp = createAdminServer();
  adminApp.listen(ADMIN_PORT, () => {
    console.log(`\n[NULLBEAT LITE] Control Plane active at http://localhost:${ADMIN_PORT}`);
    console.log(`   Admin Secret: ${process.env.ADMIN_SECRET ? '[CONFIGURED]' : '[NONE]'}\n`);
  });


}


