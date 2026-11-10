'use strict';

/**
 * cache_injector.js
 *
 * Provides injectCacheInfo() — checks TorBox for cached qualities
 * and stamps infotext onto tracks. Also writes hits to torbox_cache DB.
 *
 * Provides lookupAndInjectBadges() — for cached search results, reads
 * torbox_cache (SQLite, <1ms) to stamp badges without any TorBox HTTP call.
 *
 * Provides checkSingleTrackCache() — on-demand TorBox checkcached for /stream.
 */

const { createHash } = require('node:crypto');
const { torboxCache } = require('./db');

const FALLBACK_CHAINS = {
  MAX:      ['HI_RES_LOSSLESS', 'LOSSLESS', 'HIGH', 'LOW'],
  HIRES:    ['HI_RES_LOSSLESS', 'LOSSLESS', 'HIGH', 'LOW'],
  LOSSLESS: ['LOSSLESS', 'HIGH', 'LOW'],
  HIGH:     ['HIGH', 'LOW'],
  LOW:      ['LOW'],
};

const META_MAP = {
  HI_RES_LOSSLESS: { label: 'Hi-Res',      ext: 'flac' },
  LOSSLESS:        { label: 'HiFi CD',     ext: 'flac' },
  HIGH:            { label: '320kbps AAC', ext: 'm4a'  },
  LOW:             { label: '96kbps',      ext: 'm4a'  },
};

function md5(text) {
  return createHash('md5').update(text).digest('hex');
}

const CLEAN_RE = /[\/\\?%*:|"<>]/g;
function clean(str) {
  return (str || '').replace(CLEAN_RE, '').trim();
}

/**
 * Live TorBox cache check.
 * - Calls TorBox /checkcached with MD5 hashes of candidate filenames.
 * - Writes every hit into torbox_cache DB.
 * - Stamps track.infotext for the best cached quality in the user's chain.
 */
async function injectCacheInfo(tracks, torboxApiKey, quality = 'MAX', isAtmos = false) {
  if (!tracks || tracks.length === 0) return tracks;
  if (!torboxApiKey) return tracks;

  const chain = FALLBACK_CHAINS[quality] || FALLBACK_CHAINS['MAX'];

  const hashToInfo = {};
  const hashes = [];

  for (const track of tracks) {
    if (!track.id || !track.title) continue;
    const cleanTrackName = clean(track.title) || 'Track';
    const cleanArtistName = clean(track.artist || 'Unknown Artist');
    const trackIdRaw = String(track.id).replace('track:', '');

    if (track.isAtmos) {
      // Dolby Atmos tag present: check for DOLBY ATMOS quality hash
      const fn = `${cleanTrackName} - ${cleanArtistName} [NullBeat ${trackIdRaw} - DOLBY ATMOS].m4a`;
      const fnNoExt = `${cleanTrackName} - ${cleanArtistName} [NullBeat ${trackIdRaw} - DOLBY ATMOS]`;
      const hash = md5(fn);
      const hashNoExt = md5(fnNoExt);
      hashToInfo[hash] = { track, formatKey: 'ATMOS', label: 'DOLBY ATMOS', trackId: trackIdRaw, filename: fn };
      hashToInfo[hashNoExt] = hashToInfo[hash];
      hashToInfo[fn] = hashToInfo[hash];
      hashToInfo[fnNoExt] = hashToInfo[hash];
      hashes.push(hash);
      hashes.push(hashNoExt);
    }

    // Check Hi-Res availability: if track has no Hi-Res on Tidal, mark it unavailable and skip Hi-Res
    const isHires = track.isHiRes !== false && !torboxCache.isHiresUnavailable(trackIdRaw);
    if (!isHires) {
      torboxCache.markHiresUnavailable(trackIdRaw);
    }

    // Artist candidate variations:
    // 1. Full artist string: "sufr, Arpit Bala, toorjo dey"
    // 2. Each individual artist: "sufr", "Arpit Bala", "toorjo dey"
    const artistVariants = [cleanArtistName];
    if (track.artist && /[,&/]/.test(track.artist)) {
      const parts = track.artist.split(/[,&/]/).map(clean).filter(Boolean);
      for (const p of parts) {
        if (!artistVariants.includes(p)) {
          artistVariants.push(p);
        }
      }
    }

    for (const formatKey of chain) {
      if (formatKey === 'HI_RES_LOSSLESS' && !isHires) {
        continue; // Skip querying Hi-Res if track is not Hi-Res on Tidal
      }
      const info = META_MAP[formatKey];
      if (!info) continue;

      for (const aName of artistVariants) {
        const fn = `${cleanTrackName} - ${aName} [NullBeat ${trackIdRaw} - ${info.label}].${info.ext}`;
        const hash = md5(fn);
        hashToInfo[hash] = { track, formatKey, label: info.label, trackId: trackIdRaw, filename: fn };
        hashToInfo[fn] = hashToInfo[hash];
        hashes.push(hash);
      }
    }
  }

  if (hashes.length === 0) return tracks;

  const CHUNK_SIZE = 200;
  for (let i = 0; i < hashes.length; i += CHUNK_SIZE) {
    const chunk = hashes.slice(i, i + CHUNK_SIZE);
    const url = `https://api.torbox.app/v1/api/torrents/checkcached?hash=${chunk.join(',')}&format=object&list_files=false`;

    try {
      const res = await fetch(url, {
        headers: {
          'Authorization': `Bearer ${torboxApiKey}`,
          'User-Agent': 'NullBeat/1.0.0',
        },
        signal: AbortSignal.timeout(10000),
      });

      if (!res.ok) continue;
      const data = await res.json();

      if (data.success && data.data) {
        for (const [hashKey, item] of Object.entries(data.data)) {
          if (!item) continue;

          let info = hashToInfo[hashKey] || (item.hash && hashToInfo[item.hash]) || (item.name && hashToInfo[item.name]);
          if (!info && item.name) {
            const matchedKey = Object.keys(hashToInfo).find(k =>
              item.name.startsWith(k.substring(0, k.lastIndexOf('.')))
            );
            if (matchedKey) info = hashToInfo[matchedKey];
          }

          if (info) {
            const { track, formatKey, label, trackId, filename } = info;
            const sizeMb = (item.size / 1048576).toFixed(1);
            const actualHash = item.hash || hashKey;

            // Write to torbox_cache DB — include infohash for direct TorBox bypass on /stream
            try {
              torboxCache.write(trackId, label, parseFloat(sizeMb), actualHash, filename);
            } catch (e) {
              // non-fatal
            }

            // Stamp badge on track (best quality wins, DOLBY ATMOS only if user requested Atmos)
            if (formatKey === 'ATMOS') {
              if (isAtmos) {
                track._cacheIdx = -1;
                track.infotext = `⚡ Cached - DOLBY ATMOS - ${sizeMb}MB`;
              }
            } else {
              const currentBestIdx = track._cacheIdx !== undefined ? track._cacheIdx : 999;
              const newIdx = chain.indexOf(formatKey);
              if (newIdx !== -1 && newIdx < currentBestIdx) {
                track._cacheIdx = newIdx;
                track.infotext = `⚡ Cached - ${label} - ${sizeMb}MB`;
              }
            }
          }
        }
      }
    } catch (e) {
      console.error('[CacheInjector] Checkcached error:', e.message);
    }
  }

  for (const t of tracks) {
    if (t._cacheIdx !== undefined) delete t._cacheIdx;
  }

  return tracks;
}

/**
 * Check a single track against TorBox checkcached.
 * Used during /stream to resolve immediate cache status if not yet in SQLite.
 * Returns cached hit object { quality, infohash, filename, sizeMb } or null.
 */
async function checkSingleTrackCache(trackId, title, artist, torboxApiKey, quality = 'MAX', isAtmos = false) {
  if (!trackId || !torboxApiKey) return null;
  const cleanTrackId = String(trackId).replace(/^track:/, '').trim();
  const cleanTrackName = clean(title) || 'Track';
  const cleanArtistName = clean(artist) || 'Unknown Artist';

  const chain = isAtmos ? ['ATMOS'] : (FALLBACK_CHAINS[quality] || FALLBACK_CHAINS['MAX']);
  const isHires = !torboxCache.isHiresUnavailable(cleanTrackId);

  const artistVariants = [cleanArtistName];
  if (artist && /[,&/]/.test(artist)) {
    const parts = artist.split(/[,&/]/).map(clean).filter(Boolean);
    for (const p of parts) {
      if (!artistVariants.includes(p)) {
        artistVariants.push(p);
      }
    }
  }

  const hashToInfo = {};
  const hashes = [];

  if (isAtmos) {
    for (const aName of artistVariants) {
      const fn = `${cleanTrackName} - ${aName} [NullBeat ${cleanTrackId} - DOLBY ATMOS].m4a`;
      const fnNoExt = `${cleanTrackName} - ${aName} [NullBeat ${cleanTrackId} - DOLBY ATMOS]`;
      const hash = md5(fn);
      const hashNoExt = md5(fnNoExt);
      hashToInfo[hash] = { formatKey: 'ATMOS', label: 'DOLBY ATMOS', trackId: cleanTrackId, filename: fn };
      hashToInfo[hashNoExt] = hashToInfo[hash];
      hashToInfo[fn] = hashToInfo[hash];
      hashToInfo[fnNoExt] = hashToInfo[hash];
      hashes.push(hash);
      hashes.push(hashNoExt);
    }
  }

  for (const formatKey of chain) {
    if (formatKey === 'ATMOS') continue;
    if (formatKey === 'HI_RES_LOSSLESS' && !isHires) continue;
    const info = META_MAP[formatKey];
    if (!info) continue;

    for (const aName of artistVariants) {
      const fn = `${cleanTrackName} - ${aName} [NullBeat ${cleanTrackId} - ${info.label}].${info.ext}`;
      const hash = md5(fn);
      hashToInfo[hash] = { formatKey, label: info.label, trackId: cleanTrackId, filename: fn };
      hashToInfo[fn] = hashToInfo[hash];
      hashes.push(hash);
    }
  }

  if (hashes.length === 0) return null;

  try {
    const url = `https://api.torbox.app/v1/api/torrents/checkcached?hash=${hashes.join(',')}&format=object&list_files=false`;
    const res = await fetch(url, {
      headers: {
        'Authorization': `Bearer ${torboxApiKey}`,
        'User-Agent': 'NullBeat/1.0.0',
      },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return null;
    const data = await res.json();
    if (data.success && data.data) {
      let bestHit = null;
      let bestIdx = 999;

      for (const [hashKey, item] of Object.entries(data.data)) {
        if (!item) continue;
        let info = hashToInfo[hashKey] || (item.hash && hashToInfo[item.hash]) || (item.name && hashToInfo[item.name]);
        if (!info && item.name) {
          const matchedKey = Object.keys(hashToInfo).find(k =>
            item.name.startsWith(k.substring(0, k.lastIndexOf('.')))
          );
          if (matchedKey) info = hashToInfo[matchedKey];
        }
        if (info) {
          const { formatKey, label, filename } = info;
          const sizeMb = parseFloat((item.size / 1048576).toFixed(1));
          const actualInfohash = item.hash || hashKey;
          try {
            torboxCache.write(cleanTrackId, label, sizeMb, actualInfohash, filename);
          } catch (_) {}

          if (formatKey === 'ATMOS' && isAtmos) {
            return {
              quality: label,
              infohash: actualInfohash,
              filename,
              sizeMb,
            };
          }

          const idx = chain.indexOf(formatKey);
          if (idx !== -1 && idx < bestIdx) {
            bestIdx = idx;
            bestHit = {
              quality: label,
              infohash: actualInfohash,
              filename,
              sizeMb,
            };
          }
        }
      }
      return bestHit;
    }
  } catch (e) {
    console.error('[CacheInjector] Single track checkcached error:', e.message);
  }
  return null;
}

/**
 * Badge injection from local torbox_cache DB — no HTTP call.
 * Used when serving a cached search result to stamp the right badges
 * for the requesting user's quality setting.
 */
function lookupAndInjectBadges(tracks, quality = 'MAX', isAtmos = false) {
  if (!tracks || tracks.length === 0) return tracks;

  const chain = FALLBACK_CHAINS[quality] || FALLBACK_CHAINS['MAX'];
  
  const normalTrackIds = [];
  const atmosTrackIds = [];

  for (const track of tracks) {
    const rawId = String(track.id).replace('track:', '');
    if (isAtmos && track.isAtmos) {
      atmosTrackIds.push(rawId);
    }
    normalTrackIds.push(rawId);
  }

  const badgeMap = normalTrackIds.length > 0 ? torboxCache.lookupBadges(normalTrackIds, chain) : new Map();
  const atmosBadgeMap = atmosTrackIds.length > 0 ? torboxCache.lookupBadges(atmosTrackIds, ['ATMOS']) : new Map();

  for (const track of tracks) {
    const rawId = String(track.id).replace('track:', '');
    const atmosHit = (isAtmos && track.isAtmos) ? atmosBadgeMap.get(rawId) : null;
    if (atmosHit) {
      track.infotext = `⚡ Cached - DOLBY ATMOS - ${atmosHit.sizeMb}MB`;
    } else {
      const hit = badgeMap.get(rawId);
      if (hit) {
        track.infotext = `⚡ Cached - ${hit.label} - ${hit.sizeMb}MB`;
      }
    }
  }

  return tracks;
}

module.exports = {
  injectCacheInfo,
  lookupAndInjectBadges,
  checkSingleTrackCache,
};
