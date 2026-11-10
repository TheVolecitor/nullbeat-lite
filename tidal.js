'use strict';

/**
 * tidal.js — NullBeat Lite Tidal Client
 *
 * Uses Tidal OpenAPI v2 with OAuth2 client_credentials.
 * Retrieves client_id and client_secret dynamically from environment variables.
 */

// ── Dynamic Tidal Credentials Resolution ────────────────────────────────────

function getTidalCredentials() {
  const clientId = (process.env.TIDAL_CLIENT_ID || '').trim();
  const clientSecret = (process.env.TIDAL_CLIENT_SECRET || '').trim();

  return {
    clientId: clientId || '',
    clientSecret: clientSecret || ''
  };
}

// ── Tidal OAuth Token (in-memory cache) ──────────────────────────────────────

let _tidalAuthCache = null;

async function getTidalAuthToken() {
  if (_tidalAuthCache && _tidalAuthCache.expires > Date.now()) {
    return _tidalAuthCache.token;
  }

  const { clientId, clientSecret } = getTidalCredentials();
  if (!clientId || !clientSecret) return null;
  const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

  try {
    const res = await fetch('https://auth.tidal.com/v1/oauth2/token', {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${credentials}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: 'grant_type=client_credentials',
      signal: AbortSignal.timeout(10000),
    });

    if (res.ok) {
      const data = await res.json();
      _tidalAuthCache = {
        token:   data.access_token,
        expires: Date.now() + (data.expires_in - 60) * 1000,
      };
      return data.access_token;
    }
  } catch (e) {
    console.error('[Tidal] Auth token fetch failed:', e.message);
  }

  return null;
}

// ── Failover Fetch (Custom Backends) ──────────────────────────────────────────

async function fetchWithFailover(urlPath, options = {}) {
  const env = process.env.HIFI_SEARCH || process.env.HIFI_BACKENDS;
  const backends = env ? env.split(',').map(s => s.trim().replace(/^['"]|['"]$/g, '')).filter(Boolean) : [];
  let lastError = null;

  for (const base of backends) {
    const url = `${base.replace(/\/+$/, '')}${urlPath}`;
    try {
      const res = await fetch(url, {
        ...options,
        signal: AbortSignal.timeout(8000),
      });
      if (res.ok) return res;
      lastError = new Error(`HTTP ${res.status} from ${url}`);
    } catch (e) {
      lastError = e;
    }
  }

  throw lastError || new Error(`Endpoint not reachable: ${urlPath}`);
}

// ── Tidal OpenAPI v2 — Album Details (Tracks, Cover, Artists) ─────────────────

async function getTidalAlbum(albumId) {
  const token = await getTidalAuthToken();
  if (!token) return null;

  const url = `https://openapi.tidal.com/v2/albums/${albumId}?countryCode=US&include=items,items.artists,items.albums,items.albums.coverArt,artists,coverArt`;
  try {
    const res = await fetch(url, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/vnd.api+json',
      },
      signal: AbortSignal.timeout(10000),
    });

    if (!res.ok) {
      console.warn(`[Tidal OpenAPI] /albums/${albumId} returned status ${res.status}`);
      return null;
    }

    const data = await res.json();
    const albumTitle = data.data?.attributes?.title || '';
    const releaseDate = data.data?.attributes?.releaseDate || '';
    const numberOfTracks = data.data?.attributes?.numberOfItems || 0;

    const artworks = new Map();
    const artistsMap = new Map();
    for (const item of (data.included || [])) {
      if (item.type === 'artworks') {
        const files = item.attributes?.files || [];
        const best = files.find(f => f.meta?.width === 750) || files.find(f => f.meta?.width === 640) || files[0];
        artworks.set(item.id, best?.href || '');
      }
      if (item.type === 'artists') {
        artistsMap.set(item.id, item.attributes?.name || '');
      }
    }

    const coverArtId = data.data?.relationships?.coverArt?.data?.[0]?.id;
    const albumArtwork = artworks.get(coverArtId) || '';

    const mainArtistId = data.data?.relationships?.artists?.data?.[0]?.id;
    const mainArtistName = artistsMap.get(mainArtistId) || '';

    const tracks = [];
    for (const item of (data.included || [])) {
      if (item.type === 'tracks') {
        const trackArtistId = item.relationships?.artists?.data?.[0]?.id;
        const trackArtistName = artistsMap.get(trackArtistId) || mainArtistName;
        const tags = item.attributes?.mediaTags || [];
        const audioModes = item.attributes?.audioModes || [];
        const isAtmos = tags.some(tag => String(tag).toUpperCase() === 'DOLBY_ATMOS') || audioModes.includes('DOLBY_ATMOS');
        tracks.push({
          id: String(item.id),
          title: item.attributes?.title || 'Unknown',
          artist: trackArtistName || 'Unknown',
          album: albumTitle || 'Unknown',
          duration: parseIsoDuration(item.attributes?.duration),
          isrc: item.attributes?.isrc || '',
          artworkURL: albumArtwork,
          isHiRes: tags.some(tag => ['HIRES_LOSSLESS', 'FLAC_HIRES', 'HI_RES'].includes(String(tag).toUpperCase())),
          isAtmos: Boolean(isAtmos),
        });
      }
    }

    return {
      id: String(data.data?.id || albumId),
      title: albumTitle,
      artist: mainArtistName,
      releaseDate,
      artworkURL: albumArtwork,
      totalTracks: numberOfTracks || tracks.length,
      tracks
    };
  } catch (err) {
    console.error(`[Tidal OpenAPI] Error fetching album ${albumId}:`, err.message);
    return null;
  }
}

// ── Tidal OpenAPI v2 — Single Unified Search ─────────────────────────────────

async function tidalSearch(query, limit = 10, countryCode = 'US') {
  const token = await getTidalAuthToken();
  if (!token) throw new Error('Could not obtain Tidal auth token');

  const includes = [
    'tracks.artists',
    'tracks.albums.coverArt',
    'albums.artists',
    'albums.coverArt',
    'artists.profileArt',
  ].join(',');

  const url = `https://openapi.tidal.com/v2/searchResults?filter[query]=${encodeURIComponent(query)}&countryCode=${countryCode}&include=${includes}`;
  const res = await fetch(url, {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Accept': 'application/vnd.api+json',
    },
    signal: AbortSignal.timeout(10000),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Tidal search failed (${res.status}): ${err}`);
  }

  const json = await res.json();
  return json;
}

function parseIsoDuration(str) {
  if (!str) return 0;
  if (typeof str === 'number') return str;
  const match = str.match(/PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?/);
  if (!match) return 0;
  return (parseInt(match[1] || '0', 10) * 3600) +
         (parseInt(match[2] || '0', 10) * 60) +
         parseInt(match[3] || '0', 10);
}

// ── Tidal OpenAPI v2 — Artist Details (Tracks, Albums, Art) ─────────────────

async function getTidalArtist(artistId) {
  const token = await getTidalAuthToken();
  if (!token) return null;

  const url = `https://openapi.tidal.com/v2/artists/${artistId}?countryCode=US&collapseBy=FINGERPRINT&include=profileArt,tracks,tracks.albums,tracks.albums.coverArt,albums,albums.coverArt`;
  try {
    const res = await fetch(url, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/vnd.api+json',
      },
      signal: AbortSignal.timeout(10000),
    });

    if (!res.ok) {
      console.warn(`[Tidal OpenAPI] /artists/${artistId} returned status ${res.status}`);
      return null;
    }

    const data = await res.json();
    const name = data.data?.attributes?.name || '';

    // Map artworks
    const artworks = new Map();
    for (const item of (data.included || [])) {
      if (item.type === 'artworks') {
        const files = item.attributes?.files || [];
        const bestFile = files.find(f => f.meta?.width === 750)
                      || files.find(f => f.meta?.width === 640)
                      || files.find(f => f.meta?.width === 1280)
                      || files[0];
        artworks.set(item.id, bestFile?.href || '');
      }
    }

    // Artist Profile Art
    const profileArtId = data.data?.relationships?.profileArt?.data?.[0]?.id;
    let artistArtworkURL = artworks.get(profileArtId) || '';

    // Map albums
    const albumsMap = new Map();
    for (const item of (data.included || [])) {
      if (item.type === 'albums' && item.attributes) {
        const coverArtId = item.relationships?.coverArt?.data?.[0]?.id;
        albumsMap.set(item.id, {
          id: String(item.id),
          title: item.attributes.title || 'Unknown',
          releaseDate: item.attributes.releaseDate || '',
          artworkURL: artworks.get(coverArtId) || '',
        });
      }
    }

    // Map tracks
    const tracks = [];
    for (const item of (data.included || [])) {
      if (item.type === 'tracks' && item.attributes) {
        const albumId = item.relationships?.albums?.data?.[0]?.id;
        const albumObj = albumsMap.get(albumId);
        const tags = item.attributes.mediaTags || [];

        tracks.push({
          id: String(item.id),
          title: item.attributes.title || 'Unknown',
          artist: name || 'Unknown',
          album: albumObj?.title || 'Unknown',
          duration: parseIsoDuration(item.attributes.duration),
          isrc: item.attributes.isrc || '',
          artworkURL: albumObj?.artworkURL || artistArtworkURL || '',
          isHiRes: tags.some(tag => ['HIRES_LOSSLESS', 'FLAC_HIRES', 'HI_RES'].includes(String(tag).toUpperCase())),
        });
      }
    }

    // Convert albums to list
    const albums = [];
    for (const [, a] of albumsMap.entries()) {
      albums.push({
        id: a.id,
        title: a.title,
        artist: name || 'Unknown',
        artworkURL: a.artworkURL,
        year: a.releaseDate ? a.releaseDate.slice(0, 4) : '',
      });
    }

    if (!artistArtworkURL) {
      artistArtworkURL = albums[0]?.artworkURL || tracks[0]?.artworkURL || '';
    }

    return {
      name,
      artworkURL: artistArtworkURL,
      tracks,
      albums,
    };
  } catch (err) {
    console.error(`[Tidal OpenAPI] Error fetching artist ${artistId}:`, err.message);
    return null;
  }
}

// ── Tidal v1 Web API Fallback for Artists ────────────────────────────────────

async function getTidalV1Artist(artistId) {
  const token = 'txNoH4kkV41MfH25';
  const headers = { 'x-tidal-token': token, 'Accept': 'application/json' };
  try {
    const [rMeta, rTracks, rAlbums] = await Promise.all([
      fetch(`https://api.tidal.com/v1/artists/${artistId}?countryCode=US`, { headers, signal: AbortSignal.timeout(8000) }).catch(() => ({ ok: false })),
      fetch(`https://api.tidal.com/v1/artists/${artistId}/toptracks?countryCode=US&limit=25`, { headers, signal: AbortSignal.timeout(8000) }).catch(() => ({ ok: false })),
      fetch(`https://api.tidal.com/v1/artists/${artistId}/albums?countryCode=US&limit=50`, { headers, signal: AbortSignal.timeout(8000) }).catch(() => ({ ok: false }))
    ]);

    let name = '', artworkURL = '', tracks = [], albums = [];
    if (rMeta.ok) {
      const meta = await rMeta.json();
      name = meta.name || '';
      if (meta.picture) {
        artworkURL = `https://resources.tidal.com/images/${meta.picture.replace(/-/g, '/')}/750x750.jpg`;
      }
    }

    if (rTracks.ok) {
      const tData = await rTracks.json();
      const rawTracks = tData.items || [];
      tracks = rawTracks.map(t => {
        const tags = t.mediaMetadata?.tags || [];
        const audioModes = t.audioModes || [];
        const isAtmos = tags.some(tag => String(tag).toUpperCase() === 'DOLBY_ATMOS') || audioModes.includes('DOLBY_ATMOS');
        const cover = t.album?.cover || t.cover;
        return {
          id: String(t.id),
          title: t.title || 'Unknown',
          artist: t.artist?.name || name || 'Unknown',
          album: t.album?.title || 'Unknown',
          duration: t.duration || 0,
          isrc: t.isrc || '',
          artworkURL: cover ? `https://resources.tidal.com/images/${cover.replace(/-/g, '/')}/640x640.jpg` : '',
          isHiRes: tags.some(tag => ['HIRES_LOSSLESS', 'FLAC_HIRES', 'HI_RES'].includes(String(tag).toUpperCase())),
          isAtmos: Boolean(isAtmos),
        };
      });
    }

    if (rAlbums.ok) {
      const aData = await rAlbums.json();
      const rawAlbums = aData.items || [];
      albums = rawAlbums.map(a => ({
        id: String(a.id || ''),
        title: a.title || a.name || '',
        artist: a.artist?.name || name || 'Unknown',
        artworkURL: a.cover ? `https://resources.tidal.com/images/${a.cover.replace(/-/g, '/')}/640x640.jpg` : '',
        year: a.releaseDate?.slice(0, 4) || '',
      })).filter(a => a.id);
    }

    if (!artworkURL) {
      artworkURL = albums[0]?.artworkURL || tracks[0]?.artworkURL || '';
    }

    return { name, artworkURL, tracks, albums };
  } catch (err) {
    console.error(`[Tidal v1] Error fetching artist ${artistId}:`, err.message);
    return null;
  }
}

async function getTidalOpenApiTracks(artistId, albumArtistInfo) {
  const details = await getTidalArtist(artistId);
  if (details && details.tracks && details.tracks.length > 0) {
    return details.tracks;
  }
  const v1Details = await getTidalV1Artist(artistId);
  return v1Details?.tracks || [];
}

function resetTidalAuthCache() {
  _tidalAuthCache = null;
}

module.exports = {
  getTidalCredentials,
  getTidalAuthToken,
  resetTidalAuthCache,
  fetchWithFailover,
  tidalSearch,
  parseIsoDuration,
  getTidalArtist,
  getTidalV1Artist,
  getTidalAlbum,
  getTidalOpenApiTracks,
};

