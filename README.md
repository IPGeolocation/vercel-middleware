# ipgeolocation-vercel-middleware

**Official [IPGeolocation.io](https://ipgeolocation.io) middleware for Next.js.**  
Block bots, VPNs, proxies, and bad actors at the Vercel edge — before your app sees a single request.

[![npm version](https://img.shields.io/npm/v/ipgeolocation-vercel-middleware)](https://www.npmjs.com/package/ipgeolocation-vercel-middleware)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Next.js](https://img.shields.io/badge/Next.js-%E2%89%A513.0-black)](https://nextjs.org)

---

## How it works

```
Incoming request
      │
      ▼
 Vercel Edge Network
      │
      ▼
 middleware.ts  ──► IPGeolocation.io API (with 60s in-memory cache)
      │
      ├── Blocked country / VPN / bot / threat score?  ──► redirect to /blocked
      │
      ├── Country redirect configured?  ──► redirect to /us, /uk, etc.
      │
      └── Pass through + attach x-ipgeo-* headers to request
```

Zero latency added for repeat visitors (cached). No changes required to your app — geo data is forwarded as HTTP headers.

---

## Features

| Feature | Description |
|---|---|
| Country allow-list | Only permit traffic from specific countries |
| Country block-list | Block specific countries |
| Country redirects | Send users to locale-specific paths (`/us`, `/uk`) |
| VPN detection | Block VPN connections |
| Proxy detection | Block datacenter / anonymous proxies |
| Tor detection | Block Tor exit nodes |
| Bot detection | Block known bots and scrapers |
| Spam detection | Block IPs flagged as spam sources |
| Attacker detection | Block IPs with a known attack history |
| Cloud provider detection | Block cloud / datacenter IP ranges |
| Threat score | Block IPs above a configurable threat score (0–100) |
| Geo headers | Forward rich geo data to your app as `x-ipgeo-*` headers |
| Edge caching | In-memory TTL cache — one API call per IP per minute |
| Fail-closed mode | Block traffic when the API is unavailable |

---

## Requirements

- Next.js ≥ 13 (Edge Middleware)
- An [IPGeolocation.io API key](https://app.ipgeolocation.io/signup) (free tier available)

---

## Installation

```bash
npm install ipgeolocation-vercel-middleware
# or
yarn add ipgeolocation-vercel-middleware
# or
pnpm add ipgeolocation-vercel-middleware
```

---

## Quick start

### Option A — Use the pre-built middleware (simplest)

Create `middleware.ts` at your project root:

```typescript
export { middleware, config } from 'ipgeolocation-vercel-middleware/middleware';
```

Then add your API key to `.env.local`:

```bash
IPGEOLOCATION_API_KEY=your_api_key_here
```

Done.

---

### Option B — Compose with your own middleware

```typescript
// middleware.ts
import { NextRequest, NextResponse } from 'next/server';
import { middleware as ipGeoMiddleware } from 'ipgeolocation-vercel-middleware/middleware';

export async function middleware(request: NextRequest) {
  // Run IPGeolocation checks first
  const geoResponse = await ipGeoMiddleware(request);

  // If the middleware wants to block/redirect, respect it
  if (geoResponse.status !== 200) return geoResponse;

  // Your own logic here...
  return NextResponse.next();
}

export { config } from 'ipgeolocation-vercel-middleware/middleware';
```

---

### Option C — Use the utility functions directly

```typescript
import {
  lookupIpGeolocation,
  getClientIp,
  shouldBlockBySecurity
} from 'ipgeolocation-vercel-middleware';
```

---

## Configuration

All configuration is done via environment variables. No code changes needed.

### Required

| Variable | Description |
|---|---|
| `IPGEOLOCATION_API_KEY` | Your IPGeolocation.io API key |

### Country controls

| Variable | Type | Default | Description |
|---|---|---|---|
| `IPGEO_ALLOWED_COUNTRIES` | `string` | _(all)_ | CSV of ISO 3166-1 alpha-2 codes. Only these countries are allowed. Example: `US,CA,GB` |
| `IPGEO_BLOCKED_COUNTRIES` | `string` | _(none)_ | CSV of ISO 3166-1 alpha-2 codes. These countries are always blocked. Example: `CN,RU` |
| `IPGEO_COUNTRY_REDIRECTS` | `JSON` | `{}` | JSON map of country → path redirects. Example: `{"US":"/us","GB":"/uk","PK":"/pk"}` |

### Security controls

| Variable | Type | Default | Description |
|---|---|---|---|
| `IPGEO_BLOCK_VPN` | `boolean` | `false` | Block VPN connections |
| `IPGEO_BLOCK_PROXY` | `boolean` | `false` | Block proxy connections |
| `IPGEO_BLOCK_TOR` | `boolean` | `true` | Block Tor exit nodes |
| `IPGEO_BLOCK_CLOUD_PROVIDER` | `boolean` | `false` | Block cloud provider IPs (AWS, GCP, Azure, etc.) |
| `IPGEO_BLOCK_BOT` | `boolean` | `false` | Block known bots and scrapers |
| `IPGEO_BLOCK_SPAM` | `boolean` | `false` | Block IPs flagged as spam sources |
| `IPGEO_BLOCK_KNOWN_ATTACKER` | `boolean` | `false` | Block IPs with known attack history |
| `IPGEO_THREAT_SCORE_BLOCK_THRESHOLD` | `number` | _(disabled)_ | Block IPs with threat score ≥ this value (0–100). Example: `75` |

### Behaviour

| Variable | Type | Default | Description |
|---|---|---|---|
| `IPGEO_BLOCK_PATH` | `string` | `/blocked` | Path to redirect blocked requests to |
| `IPGEO_HEADER_PREFIX` | `string` | `x-ipgeo` | Prefix for forwarded geo headers |
| `IPGEO_TIMEOUT_MS` | `number` | `3000` | API request timeout in milliseconds |
| `IPGEO_CACHE_TTL_MS` | `number` | `60000` | In-memory cache TTL in milliseconds. Set to `0` to disable |
| `IPGEO_FAIL_CLOSED` | `boolean` | `false` | Block requests when API lookup fails. `false` = fail-open (safer for uptime) |
| `IPGEO_TRUST_FIRST_XFF` | `boolean` | `false` | Trust the first IP in `x-forwarded-for`. Leave `false` on Vercel (Vercel injects the last, trusted IP) |

---

## Forwarded headers

The middleware attaches the following headers to every passing request so your app can read geo data without another API call:

| Header | Example value |
|---|---|
| `x-ipgeo-ip` | `1.2.3.4` |
| `x-ipgeo-country` | `US` |
| `x-ipgeo-country-name` | `United States` |
| `x-ipgeo-state` | `New York` |
| `x-ipgeo-city` | `New York City` |
| `x-ipgeo-latitude` | `40.7128` |
| `x-ipgeo-longitude` | `-74.0060` |
| `x-ipgeo-timezone` | `America/New_York` |
| `x-ipgeo-asn` | `15169` |
| `x-ipgeo-asn-organization` | `Google LLC` |
| `x-ipgeo-threat-score` | `0` |
| `x-ipgeo-is-vpn` | `false` |
| `x-ipgeo-is-proxy` | `false` |
| `x-ipgeo-is-tor` | `false` |
| `x-ipgeo-is-bot` | `false` |
| `x-ipgeo-is-spam` | `false` |
| `x-ipgeo-is-known-attacker` | `false` |
| `x-ipgeo-is-cloud-provider` | `false` |
| `x-ipgeo-cloud-provider-name` | `Amazon AWS` |

Read them in a Server Component, Route Handler, or API route:

```typescript
// app/page.tsx
import { headers } from 'next/headers';

export default function Page() {
  const h = headers();
  const country = h.get('x-ipgeo-country');   // "US"
  const city    = h.get('x-ipgeo-city');       // "New York City"
  const isVpn   = h.get('x-ipgeo-is-vpn');    // "false"

  return <div>Hello from {city}, {country}!</div>;
}
```

---

## Block page

Create `app/blocked/page.tsx` (or `pages/blocked.tsx`) to show a custom message:

```typescript
export default function BlockedPage({
  searchParams
}: {
  searchParams: { reason?: string };
}) {
  const reason = searchParams.reason ?? 'policy';

  return (
    <main>
      <h1>Access restricted</h1>
      <p>Your connection was blocked ({reason}).</p>
      <p>
        If you believe this is a mistake, please{' '}
        <a href="mailto:support@example.com">contact support</a>.
      </p>
    </main>
  );
}
```

The `reason` query parameter will be one of: `vpn`, `proxy`, `tor`, `bot`, `spam`, `known_attacker`, `cloud_provider`, `threat_score`, `lookup_failed`.

---

## Full `.env.example`

```bash
# Required
IPGEOLOCATION_API_KEY=

# Country controls
IPGEO_ALLOWED_COUNTRIES=
IPGEO_BLOCKED_COUNTRIES=
IPGEO_COUNTRY_REDIRECTS={}

# Security controls
IPGEO_BLOCK_VPN=false
IPGEO_BLOCK_PROXY=false
IPGEO_BLOCK_TOR=true
IPGEO_BLOCK_CLOUD_PROVIDER=false
IPGEO_BLOCK_BOT=false
IPGEO_BLOCK_SPAM=false
IPGEO_BLOCK_KNOWN_ATTACKER=false
IPGEO_THREAT_SCORE_BLOCK_THRESHOLD=

# Behaviour
IPGEO_BLOCK_PATH=/blocked
IPGEO_HEADER_PREFIX=x-ipgeo
IPGEO_TIMEOUT_MS=3000
IPGEO_CACHE_TTL_MS=60000
IPGEO_FAIL_CLOSED=false
IPGEO_TRUST_FIRST_XFF=false
```

---

## Security notes

**`x-forwarded-for` and IP spoofing**  
On Vercel, this middleware reads the *last* IP in `x-forwarded-for` by default. Vercel's edge network appends the real client IP as the final entry, making it the most trustworthy value. Only set `IPGEO_TRUST_FIRST_XFF=true` if you're behind a custom reverse proxy you control.

**Fail-open vs fail-closed**  
By default, if the IPGeolocation.io API is unavailable the middleware passes the request through (`fail-open`). This keeps your app available during API outages. Set `IPGEO_FAIL_CLOSED=true` if availability of geo-blocking is more important than uptime.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Links

- [IPGeolocation.io](https://ipgeolocation.io)
- [API documentation](https://ipgeolocation.io/documentation.html)
- [Get a free API key](https://app.ipgeolocation.io/signup)
- [Report an issue](https://github.com/ipgeolocation/vercel-middleware/issues)
