<p align="center">
  <img src="nullbeat-logo.svg" alt="NullBeat" width="520">
</p>

# NullBeat Lite

NullBeat Lite is a self-hostable music indexing service. Its a stripped down, lightweight version of NullBeat. It can either be used as an addon with popular manifest based music apps like BeatBoss, Eclipse, BitChord, etc. or with the NullBeat Web as a standalone webapp.

## Default Ports and URLs

| Service | Default URL | Environment Variable | Port |
| :--- | :--- | :--- | :--- |
| Public API and Web UI | `http://localhost:3000` | `PORT` | `3000` |
| Control Plane and Admin Panel | `http://localhost:3001` | `ADMIN_PORT` | `3001` |
| Upstream Head Server | `https://nullbeat.thevolecitor.qzz.io` | `HEAD_SERVER_URL` | N/A |
| Source Repository | `https://github.com/TheVolecitor/nullbeat-lite` | N/A | N/A |

## Architecture

NullBeat Lite isolates public traffic from the administrative control plane across two separate HTTP ports:

- **Public API (Port 3000):** Serves the BeatBoss addon configurator, manifest generator, Tidal search queries, and stream resolution routes. Uncached tracks fall back to the upstream Head Server.
- **Control Plane (Port 3001):** Restricted administrative dashboard providing live SSE request tracing, 30-day persistent metrics, IP firewall rules (bans and rate limits), and configuration controls. Access to control plane endpoints is blocked on port 3000.

## Prerequisites

- Node.js 18.0.0 or higher
- npm 9.0.0 or higher
- Tidal Developer credentials (free registration at https://developer.tidal.com/)

## Installation

Clone the repository:

```bash
git clone https://github.com/TheVolecitor/nullbeat-lite.git
cd nullbeat-lite
```

Install production dependencies:

```bash
npm install
```

Start the application:

```bash
npm start
```

For development with automatic process reloading:

```bash
npm run dev
```

## First-Time Setup

1. On first boot without an `ADMIN_SECRET` configured in `.env`, open `http://localhost:3001` in your browser.
2. The initial setup wizard will prompt for:
   - Admin Password (creates `ADMIN_SECRET`)
   - Tidal Client ID (`TIDAL_CLIENT_ID`)
   - Tidal Client Secret (`TIDAL_CLIENT_SECRET`)
   - Upstream Head Server URL (`HEAD_SERVER_URL`, defaults to `https://nullbeat.thevolecitor.qzz.io`)
3. Upon submission, credentials are saved directly to `.env` on disk and the dashboard unlocks immediately.

Alternatively, copy the example environment file and set credentials manually before starting:

```bash
cp .env.example .env
```

## Environment Configuration

Configuration is loaded from `.env` in the project root.

| Variable | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `PORT` | No | `3000` | HTTP port for public API and web UI |
| `ADMIN_PORT` | No | `3001` | HTTP port for the admin control plane |
| `ADMIN_SECRET` | Yes | (empty) | Password for control plane authentication |
| `HEAD_SERVER_URL` | No | `https://nullbeat.thevolecitor.qzz.io` | Upstream head server for webseeding uncached tracks |
| `TIDAL_CLIENT_ID` | Yes | (empty) | Tidal OpenAPI client identifier |
| `TIDAL_CLIENT_SECRET` | Yes | (empty) | Tidal OpenAPI client secret |
| `SEARCH_CACHE_TTL` | No | `259200` | Search cache duration in seconds (default: 3 days) |
| `MAX_USERS` | No | `0` | Maximum registered API keys (0 = unlimited) |
| `MAX_INVITE_POOL` | No | `50` | Maximum users allowed via invite registration |
| `INVITE_SECRET` | No | (empty) | Secret string used for HMAC invite signatures |
| `ALLOWED_KEYS` | No | (empty) | Comma-separated API keys bypassing user limits |

## API Endpoints

### Public API (Port 3000)

- `GET /`: Addon installer and token generator web UI
- `GET /docs`: API documentation and caching guide
- `GET /web`: Lightweight web player client
- `GET /api/config`: Instance configuration and upstream head URL discovery
- `GET /:enc/manifest.json`: Addon manifest for BeatBoss
- `GET /:enc/catalog`: Catalog taxonomy definitions
- `GET /:enc/search?q={query}`: Tidal OpenAPI search with TorBox cache badges
- `GET /:enc/stream/:trackId`: Direct TorBox stream resolver or Head Server forwarder
- `GET /:enc/album/:id`: Album tracklist and metadata
- `GET /:enc/artist/:id`: Artist profile, top tracks, and discography

### Control Plane (Port 3001)

- `GET /`: Control plane web interface (redirects to setup or login)
- `GET /api/traces/live`: Server-Sent Events (SSE) stream for live request logs
- `GET /api/metrics/summary`: Aggregate counters and real-time telemetry
- `GET /api/metrics/daily`: 30-day historical bandwidth and latency analytics
- `GET /api/security/rules`: Configured IP bans and granular rate limit rules
- `POST /api/security/ban`: Ban an IP address (returns HTTP 403)
- `POST /api/security/ratelimit`: Set custom requests-per-minute limits for an IP
- `GET /api/db/torbox-cache`: Inspect and search cached TorBox records
- `POST /api/settings/core`: Update head server URL and Tidal credentials

## License

MIT License. Copyright (c) 2026 TheVolecitor. See [LICENSE](LICENSE) for details.
