# IPGeolocation.io Next.js Middleware for Vercel

## Overview

Official Next.js middleware from [IPGeolocation.io](https://ipgeolocation.io). It resolves the visitor's IP address at the Vercel edge, applies your country and security rules before the request reaches your application, and passes the geolocation data on as request headers.

[![npm version](https://img.shields.io/npm/v/ipgeolocation-vercel-middleware)](https://www.npmjs.com/package/ipgeolocation-vercel-middleware)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/ipgeolocation/vercel-middleware/blob/main/LICENSE)
[![Next.js](https://img.shields.io/badge/Next.js-13%20to%2016-black)](https://nextjs.org)

Next.js middleware runs on the Vercel edge network before a request is routed to a page, a Route Handler or an API route. That is the right place to decide whether a visitor should be served at all, and the right place to work out where they are so the rest of your application does not have to.

This package handles both jobs. Set an API key, and every request that matches your matcher carries headers such as `x-ipgeo-country`, `x-ipgeo-city` and `x-ipgeo-timezone`. Switch on a rule, and traffic from a blocked country, a VPN, a Tor exit node or an IP with a high threat score is stopped at the edge.

### What you can do with it

| Capability | Description |
|---|---|
| Country allow list | Serve only the countries you list |
| Country block list | Block the countries you list |
| Country redirects | Send visitors to locale paths such as `/us` or `/uk`, keeping the path and query string |
| VPN detection | Block connections coming through a VPN |
| Proxy detection | Block datacenter, anonymous and residential proxies |
| Tor detection | Block Tor exit nodes |
| Relay detection | Block relay networks such as iCloud Private Relay |
| Bot detection | Block automated traffic while keeping known good crawlers |
| Spam and attacker detection | Block addresses with spam or attack history |
| Cloud provider detection | Block AWS, GCP, Azure and other hosting ranges |
| Threat score | Block at or above a score you choose, from 0 to 100 |
| Geolocation headers | Country, city, region, coordinates, time zone, currency, ASN and company as request headers |
| Edge caching | One API call per IP per cache window, per edge isolate |
| Circuit breaker | Lookups pause during an API incident instead of adding latency to every request |
| Fail open or fail closed | Choose availability or enforcement when a lookup cannot complete |

### How a request flows

1. A request reaches the Vercel edge network and matches the middleware matcher.
2. Inbound headers that use your geo prefix are removed, so a visitor cannot forge them.
3. The client IP is read from `x-forwarded-for` or another platform header, then validated.
4. The IP is looked up through the IPGeolocation.io v3 API, or read from the in memory cache.
5. Country rules run, then security rules, then country redirects.
6. If nothing matched, the request continues with the `x-ipgeo-*` headers attached.

Repeat visitors within the cache window add no network latency and cost no credits.

## Requirements

- Next.js 13 or later, including Next.js 16 with `proxy.ts`
- Node.js 18 or later for local development
- An [IPGeolocation.io API key](https://app.ipgeolocation.io/signup)

### Which plan you need

The base lookup, which returns country, region, city, coordinates, time zone, currency and ASN, works on the free plan. The free plan includes 1,000 requests per day.

The security module, which is what VPN, proxy, Tor, relay, bot, spam, attacker and threat score rules read, is available on paid plans only. A free plan key that asks for it receives HTTP 401. This middleware requests the module only when at least one security rule is switched on, so a free key that uses country rules and geolocation headers works without any extra configuration.

| What you use | Credits per uncached lookup | Plan |
|---|---|---|
| Geolocation headers, country allow and block lists, country redirects | 1 | Free or paid |
| Any of the security rules, or a threat score threshold | 3 | Paid |

Credits are charged only on a successful response, and the exact figure for a request is returned in the `X-Credits-Charged` header. See the [credits usage guide](https://ipgeolocation.io/documentation/credits-usage.html) for the full rules.

## Installation

```bash
npm install ipgeolocation-vercel-middleware
```

```bash
yarn add ipgeolocation-vercel-middleware
```

```bash
pnpm add ipgeolocation-vercel-middleware
```

## Quick Start

### Step 1. Add your API key

Create `.env.local` in your project root:

```bash
IPGEOLOCATION_API_KEY=your_api_key_here
```

Add the same variable in your Vercel project under **Settings > Environment Variables** for Production, Preview and Development.

### Step 2. Create the middleware file

On Next.js 13, 14 and 15, create `middleware.ts` in your project root, next to `app/` or `pages/`:

```typescript
import { middleware } from 'ipgeolocation-vercel-middleware/middleware';

export { middleware };

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|_next/data|favicon.ico|robots.txt|sitemap.xml|.*\\.(?:css|js|mjs|map|json|txt|xml|ico|png|jpg|jpeg|gif|webp|avif|svg|woff|woff2|ttf|otf|eot|mp4|webm|mp3|pdf|zip)$).*)'
  ]
};
```

On Next.js 16, the file is named `proxy.ts` and the exported function is named `proxy`:

```typescript
import { proxy } from 'ipgeolocation-vercel-middleware/middleware';

export { proxy };

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)']
};
```

Declare `config` in your own file rather than re-exporting it from the package. Next.js reads the matcher statically at build time and cannot follow a value that comes from a dependency. Next.js 16 rejects a re-exported `config` outright.

The matcher above skips Next.js internals and files with a static extension. Every path you exclude is a lookup you do not pay for.

### Step 3. Add a block page

Only needed if you use country or security rules with the default block mode. Create `app/blocked/page.tsx`:

```tsx
export const metadata = {
  title: 'Access restricted',
  robots: { index: false, follow: false }
};

export default async function BlockedPage({
  searchParams
}: {
  searchParams: Promise<{ reason?: string }>;
}) {
  const { reason } = await searchParams;

  return (
    <main>
      <h1>Access restricted</h1>
      <p>We could not accept this connection ({reason ?? 'policy'}).</p>
      <p>
        If you think this is a mistake, contact{' '}
        <a href="mailto:support@example.com">support@example.com</a>.
      </p>
    </main>
  );
}
```

On Next.js 13 and 14, `searchParams` is a plain object rather than a promise, so drop the `await` and the `Promise` type. A fuller example with a message for every reason is in [`examples/app/blocked/page.tsx`](https://github.com/ipgeolocation/vercel-middleware/blob/main/examples/app/blocked/page.tsx).

If you would rather not create a page at all, set `IPGEO_BLOCK_MODE=deny` and the middleware answers with a plain HTTP 403.

### Step 4. Switch on the rules you want

Everything is configured through environment variables. A few common starting points:

```bash
# Geolocation headers only, no blocking. Costs 1 credit per uncached lookup.
IPGEOLOCATION_API_KEY=your_api_key_here
```

```bash
# Serve three countries and nobody else.
IPGEOLOCATION_API_KEY=your_api_key_here
IPGEO_ALLOWED_COUNTRIES=US,CA,GB
```

```bash
# Send visitors to locale paths.
IPGEOLOCATION_API_KEY=your_api_key_here
IPGEO_COUNTRY_REDIRECTS={"US":"/us","GB":"/uk","DE":"/de"}
```

```bash
# Block anonymised and high risk traffic. Needs a paid plan.
IPGEOLOCATION_API_KEY=your_api_key_here
IPGEO_BLOCK_VPN=true
IPGEO_BLOCK_TOR=true
IPGEO_THREAT_SCORE_BLOCK_THRESHOLD=75
```

### Step 5. Read the data in your application

```tsx
// app/page.tsx
import { headers } from 'next/headers';

export default async function Page() {
  const h = await headers();
  const country = h.get('x-ipgeo-country');
  const city = h.get('x-ipgeo-city');

  return <p>Hello from {city ?? 'somewhere'}, {country ?? 'unknown'}</p>;
}
```

On Next.js 13 and 14, `headers()` is synchronous, so drop the `await`.

### Step 6. Check that it works

Run `next dev` and open the site. Locally there is no edge network in front of you, so the request arrives from `127.0.0.1`, which the API cannot resolve. The middleware recognises a private address and passes the request through without spending a credit, which means no headers are set. To see real data locally, send a public address yourself:

```bash
curl -H 'x-forwarded-for: 91.128.103.196' http://localhost:3000/
```

Set `IPGEO_LOG_LEVEL=debug` while you are setting things up and the middleware reports each lookup, each cache hit and the credits charged. Move back to the default `warn` afterwards.

## Reading geolocation data in your application

The middleware attaches the data to the request, so any part of your application can read it without a second API call.

### Server Component

```tsx
import { headers } from 'next/headers';

export default async function PricingPage() {
  const h = await headers();
  const currency = h.get('x-ipgeo-currency') ?? 'USD';
  const isEu = h.get('x-ipgeo-is-eu') === 'true';

  return <Prices currency={currency} showVatNotice={isEu} />;
}
```

### Route Handler

```typescript
// app/api/where/route.ts
export function GET(request: Request) {
  return Response.json({
    ip: request.headers.get('x-ipgeo-ip'),
    country: request.headers.get('x-ipgeo-country'),
    city: request.headers.get('x-ipgeo-city'),
    timezone: request.headers.get('x-ipgeo-timezone')
  });
}
```

### Pages Router

```typescript
// pages/index.tsx
export async function getServerSideProps({ req }) {
  return {
    props: {
      country: req.headers['x-ipgeo-country'] ?? null,
      city: req.headers['x-ipgeo-city'] ?? null
    }
  };
}
```

### Forwarded headers

A header is set only when the API returned a value for it, so a missing header means the data was not available rather than an empty string. The security headers appear only when a security rule is active, because that is the only time the module is requested.

| Header | Example | Needs security module |
|---|---|---|
| `x-ipgeo-ip` | `91.128.103.196` | No |
| `x-ipgeo-country` | `SE` | No |
| `x-ipgeo-country-name` | `Sweden` | No |
| `x-ipgeo-continent` | `EU` | No |
| `x-ipgeo-state` | `Stockholms län` | No |
| `x-ipgeo-state-code` | `SE-AB` | No |
| `x-ipgeo-city` | `Stockholm` | No |
| `x-ipgeo-zipcode` | `164 40` | No |
| `x-ipgeo-latitude` | `59.40510` | No |
| `x-ipgeo-longitude` | `17.95510` | No |
| `x-ipgeo-is-eu` | `true` | No |
| `x-ipgeo-timezone` | `Europe/Stockholm` | No |
| `x-ipgeo-currency` | `SEK` | No |
| `x-ipgeo-asn` | `AS1257` | No |
| `x-ipgeo-asn-organization` | `Tele2 Sverige AB` | No |
| `x-ipgeo-company` | `Tele2 Sverige AB` | No |
| `x-ipgeo-threat-score` | `80` | Yes |
| `x-ipgeo-is-vpn` | `true` | Yes |
| `x-ipgeo-is-proxy` | `false` | Yes |
| `x-ipgeo-is-residential-proxy` | `false` | Yes |
| `x-ipgeo-is-tor` | `false` | Yes |
| `x-ipgeo-is-relay` | `false` | Yes |
| `x-ipgeo-is-anonymous` | `true` | Yes |
| `x-ipgeo-is-bot` | `false` | Yes |
| `x-ipgeo-is-known-good-bot` | `false` | Yes |
| `x-ipgeo-is-spam` | `false` | Yes |
| `x-ipgeo-is-known-attacker` | `false` | Yes |
| `x-ipgeo-is-cloud-provider` | `true` | Yes |
| `x-ipgeo-cloud-provider-name` | `Packethub S.A.` | Yes |

Rename the prefix with `IPGEO_HEADER_PREFIX` if `x-ipgeo` clashes with something in your stack.

Headers that use the prefix are removed from the inbound request on every path, including paths where no lookup runs. Without that step, a visitor could send `x-ipgeo-country: US` and your application would have no way to tell the difference. If you read these headers anywhere, keep the prefix consistent between the middleware and the reader.

## Configuration

Every setting is an environment variable, so you can change behaviour per environment in Vercel without a code change. A complete annotated file is in [`.env.example`](https://github.com/IPGeolocation/vercel-middleware/blob/main/.env.example).

### Required

| Variable | Description |
|---|---|
| `IPGEOLOCATION_API_KEY` | Your API key. When it is missing, the middleware passes every request through untouched. |

### Country controls

| Variable | Type | Default | Description |
|---|---|---|---|
| `IPGEO_ALLOWED_COUNTRIES` | CSV | empty | Only these ISO 3166-1 alpha-2 codes are served. Example: `US,CA,GB` |
| `IPGEO_BLOCKED_COUNTRIES` | CSV | empty | These codes are always blocked. Example: `CN,RU,KP` |
| `IPGEO_ALLOW_UNKNOWN_COUNTRY` | boolean | `false` | When an allow list is set and the country cannot be determined, the request is blocked. Set to `true` to let it through. |
| `IPGEO_COUNTRY_REDIRECTS` | JSON | `{}` | Country to path map. Example: `{"US":"/us","GB":"/uk"}` |
| `IPGEO_REDIRECT_PRESERVE_PATH` | boolean | `true` | Keep the path and query string, so `/pricing?ref=ad` becomes `/uk/pricing?ref=ad` |
| `IPGEO_REDIRECT_RESPECT_EXISTING` | boolean | `true` | Do not move a visitor who is already on one of the mapped paths |
| `IPGEO_REDIRECT_STATUS` | number | `307` | One of `301`, `302`, `307`, `308` |
| `IPGEO_REDIRECT_SKIP_COOKIE` | string | empty | Name of a cookie that switches redirects off for that visitor |

### Security controls

Each of these needs the security module, which requires a paid plan and raises an uncached lookup from 1 credit to 3.

| Variable | Type | Default | Description |
|---|---|---|---|
| `IPGEO_BLOCK_VPN` | boolean | `false` | Block VPN exit nodes |
| `IPGEO_BLOCK_PROXY` | boolean | `false` | Block datacenter and anonymous proxies |
| `IPGEO_BLOCK_RESIDENTIAL_PROXY` | boolean | `false` | Block residential proxy networks |
| `IPGEO_BLOCK_TOR` | boolean | `false` | Block Tor exit nodes |
| `IPGEO_BLOCK_RELAY` | boolean | `false` | Block relay networks such as iCloud Private Relay |
| `IPGEO_BLOCK_CLOUD_PROVIDER` | boolean | `false` | Block cloud and hosting ranges |
| `IPGEO_BLOCK_BOT` | boolean | `false` | Block addresses with bot activity |
| `IPGEO_ALLOW_KNOWN_GOOD_BOTS` | boolean | `true` | Keep crawlers the API marks as known good when bots are blocked |
| `IPGEO_BLOCK_SPAM` | boolean | `false` | Block addresses flagged as spam sources |
| `IPGEO_BLOCK_KNOWN_ATTACKER` | boolean | `false` | Block addresses with attack history |
| `IPGEO_BLOCK_ANONYMOUS` | boolean | `false` | Block anything the API marks as anonymous, covering VPN, proxy, Tor and relay together |
| `IPGEO_THREAT_SCORE_BLOCK_THRESHOLD` | number | disabled | Block at or above this score, 0 to 100 |
| `IPGEO_REQUIRE_SECURITY` | boolean | `false` | Block when a security rule is active but the API returned no security data |

### Blocking behaviour

| Variable | Type | Default | Description |
|---|---|---|---|
| `IPGEO_BLOCK_MODE` | enum | `redirect` | `redirect`, `rewrite` or `deny` |
| `IPGEO_BLOCK_PATH` | path | `/blocked` | Page used by `redirect` and `rewrite` |
| `IPGEO_BLOCK_STATUS` | number | `403` | Status used by `deny` |
| `IPGEO_BLOCK_MESSAGE` | string | `Access to this site is restricted.` | Body used by `deny` |
| `IPGEO_BLOCK_INCLUDE_REASON` | boolean | `true` | Add `?reason=...` to the block URL |
| `IPGEO_FAIL_CLOSED` | boolean | `false` | Block when a lookup fails, rather than letting the request through |

### Bypasses

| Variable | Type | Default | Description |
|---|---|---|---|
| `IPGEO_ENABLED` | boolean | `true` | Set to `false` to switch the middleware off without removing it |
| `IPGEO_BYPASS_PATHS` | CSV | empty | Paths that skip every check. Example: `/health,/api/webhooks` |
| `IPGEO_BYPASS_IPS` | CSV | empty | Addresses that skip every check |
| `IPGEO_BYPASS_TOKEN` | string | empty | A request carrying `x-ipgeo-bypass-token` with this value skips every check |

### Headers, network and logging

| Variable | Type | Default | Description |
|---|---|---|---|
| `IPGEO_HEADER_PREFIX` | string | `x-ipgeo` | Prefix for the forwarded headers |
| `IPGEO_SET_RESPONSE_HEADERS` | boolean | `false` | Also copy the geo headers onto the response |
| `IPGEO_TIMEOUT_MS` | number | `3000` | API timeout per attempt |
| `IPGEO_RETRIES` | number | `1` | Retries for a timeout, a network error or a 5xx response, 0 to 3 |
| `IPGEO_CACHE_TTL_MS` | number | `60000` | Cache lifetime. `0` disables caching |
| `IPGEO_CACHE_MAX_ENTRIES` | number | `1000` | Largest number of cached addresses per edge isolate |
| `IPGEO_CIRCUIT_FAILURE_THRESHOLD` | number | `5` | Consecutive failures before lookups pause. `0` disables the breaker |
| `IPGEO_CIRCUIT_COOLDOWN_MS` | number | `30000` | How long the pause lasts |
| `IPGEO_FIELDS` | CSV | empty | Restrict the API response to these fields to shrink the payload |
| `IPGEO_TRUST_FIRST_XFF` | boolean | `false` | Read the leftmost `x-forwarded-for` entry. Leave off on Vercel |
| `IPGEO_TRUSTED_PROXY_COUNT` | number | `0` | Number of proxies you operate in front of the application |
| `IPGEO_LOG_LEVEL` | enum | `warn` | `silent`, `error`, `warn`, `info` or `debug` |

## Blocking behaviour in detail

### Block modes

`redirect` sends a 307 to `IPGEO_BLOCK_PATH` with the reason as a query parameter. The visitor sees the block URL in the address bar, and your block page can explain what happened. This is the default.

`rewrite` renders the block page at the URL the visitor asked for. The status stays 200 and the URL does not change, which suits cases where you would rather not advertise that a rule fired.

`deny` answers immediately with `IPGEO_BLOCK_STATUS` and `IPGEO_BLOCK_MESSAGE` as plain text. No page is needed, nothing else runs, and there is no way to create a loop. This is the right mode for an API only deployment.

Every block response carries `x-ipgeo-block-reason` and `cache-control: no-store`, so a shared cache cannot serve one visitor's decision to another.

### Block reasons

The reason appears in the `reason` query parameter and in the `x-ipgeo-block-reason` header.

| Reason | Meaning |
|---|---|
| `country` | The country failed the allow list or matched the block list |
| `vpn`, `proxy`, `residential_proxy`, `tor`, `relay`, `cloud_provider` | The matching connection type rule fired |
| `bot`, `spam`, `known_attacker`, `anonymous` | The matching reputation rule fired |
| `threat_score` | The score reached `IPGEO_THREAT_SCORE_BLOCK_THRESHOLD` |
| `lookup_failed` | The lookup did not complete and `IPGEO_FAIL_CLOSED` is on |
| `security_unavailable` | A security rule is active, the API returned no security data, and `IPGEO_REQUIRE_SECURITY` is on |
| `middleware_error` | An unexpected error occurred and `IPGEO_FAIL_CLOSED` is on |

### Fail open and fail closed

By default a failed lookup lets the request through. An API incident, a timeout or an exhausted quota then costs you enforcement rather than availability. Set `IPGEO_FAIL_CLOSED=true` when the rules matter more than uptime, for example on a licensing or compliance boundary.

A private or malformed address is not treated as a failure. Those requests pass through even in fail closed mode, because blocking them would break local development and internal health checks.

## Country redirects

```bash
IPGEO_COUNTRY_REDIRECTS={"US":"/us","GB":"/uk","DE":"/de"}
```

A visitor from Great Britain who opens `/pricing?ref=ad` is sent to `/uk/pricing?ref=ad`. Set `IPGEO_REDIRECT_PRESERVE_PATH=false` if you want every visitor to land on the locale home page instead.

Rules that keep the feature predictable:

- Only same origin paths are accepted. A value such as `https://example.com/uk` is ignored and logged, so a mistyped variable cannot turn the middleware into an open redirect.
- A trailing slash is removed, so `{"GB":"/uk/"}` behaves the same as `{"GB":"/uk"}` rather than redirecting forever.
- A visitor already at or below the target path is left alone.
- With `IPGEO_REDIRECT_RESPECT_EXISTING` on, a visitor sitting on any other mapped path is also left alone, so a German visitor who deliberately opened `/uk` stays there.
- Only `GET` and `HEAD` requests are redirected. A `POST` is never turned into a `GET`.

For a visible way out, set `IPGEO_REDIRECT_SKIP_COOKIE=ipgeo_no_redirect`, then have a "stay on this site" link set that cookie.

## Composing with your own middleware

Next.js allows one middleware file per project, so this package exposes the decision rather than only the finished response.

```typescript
// middleware.ts
import { NextResponse, type NextRequest } from 'next/server';
import { evaluateIpGeolocation } from 'ipgeolocation-vercel-middleware/middleware';

export async function middleware(request: NextRequest) {
  const geo = await evaluateIpGeolocation(request);

  // A block or a country redirect. Return it unchanged.
  if (geo.response) return geo.response;

  // Your own rules, with the geo data already resolved.
  if (geo.country === 'DE' && request.nextUrl.pathname === '/') {
    return NextResponse.redirect(new URL('/de', request.url));
  }

  // Forward the geo headers. Returning a bare NextResponse.next() here is what
  // drops them.
  return NextResponse.next({ request: { headers: geo.requestHeaders } });
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)']
};
```

`evaluateIpGeolocation` returns:

| Field | Type | Description |
|---|---|---|
| `action` | `'pass'`, `'block'`, `'redirect'`, `'bypass'`, `'disabled'` | What the middleware decided |
| `response` | `NextResponse` or `null` | The response to return, or `null` to continue |
| `requestHeaders` | `Headers` | Request headers with geo values added and forged values removed |
| `geo` | `IpGeoResponse` or `null` | The full API response |
| `ip` | `string` or `null` | The resolved client IP |
| `country` | `string` or `null` | ISO 3166-1 alpha-2 code |
| `reason` | `string` or `null` | Why the request was blocked or redirected |

`withIpGeolocation` wraps the same pattern when you only need the happy path:

```typescript
import { NextResponse } from 'next/server';
import { withIpGeolocation } from 'ipgeolocation-vercel-middleware/middleware';

export const middleware = withIpGeolocation(async (request, geo) => {
  if (geo.country === 'US' && !request.cookies.get('age_verified')) {
    return NextResponse.redirect(new URL('/verify', request.url));
  }

  return NextResponse.next({ request: { headers: geo.requestHeaders } });
});
```

Configuration can also be passed in code, which is useful when a value comes from somewhere other than an environment variable:

```typescript
import { createIpGeoMiddleware } from 'ipgeolocation-vercel-middleware/middleware';

export const middleware = createIpGeoMiddleware({
  blockedCountries: new Set(['RU', 'KP']),
  blockMode: 'deny'
});
```

## Client IP resolution

The middleware reads the first of these headers that carries a usable address: `x-vercel-forwarded-for`, `x-forwarded-for`, `x-real-ip`, `cf-connecting-ip`, `true-client-ip`. Values are validated before use, and ports, bracketed IPv6, IPv4 mapped IPv6 such as `::ffff:203.0.113.10` and zone indexes are all normalised.

Private, loopback, link local, carrier grade NAT and documentation ranges are rejected, because the API answers HTTP 423 for them. Rejecting them locally saves a round trip and a log line.

On Vercel, the platform sets `x-forwarded-for` from the real connection and does not forward an externally supplied value, which is why the default of reading the rightmost entry is safe there. Vercel's own [request headers documentation](https://vercel.com/docs/headers/request-headers) states that the header is overwritten to prevent spoofing, and that forwarding a custom value requires an Enterprise trusted proxy.

If you run your own reverse proxy in front of the application, set `IPGEO_TRUSTED_PROXY_COUNT` to the number of hops you control and the client IP is read that many positions to the left of the rightmost entry. `IPGEO_TRUST_FIRST_XFF=true` reads the leftmost entry instead, which is only correct when something you trust rewrites the header for you.

## Performance and cost

**Caching.** Responses are cached in memory per IP and per module set for `IPGEO_CACHE_TTL_MS`, with a default of 60 seconds. The cache lives inside one edge isolate, so it is shared by the requests that isolate serves and is not shared across regions. A larger window cuts credit use, at the cost of reacting more slowly when an address changes reputation.

**Coalescing.** Concurrent lookups for the same address share a single request, so a burst of traffic from one IP does not turn into a burst of API calls.

**Cache size.** The cache is bounded by `IPGEO_CACHE_MAX_ENTRIES`. Expired entries are dropped first, then the coldest keys, so a long lived isolate cannot grow without limit.

**Retries.** A timeout, a network error or a 5xx response is retried once by default with a short delay. Client errors such as 401, 403, 423 and 429 are never retried, because retrying them cannot help.

**Circuit breaker.** After five consecutive failures, lookups pause for 30 seconds. During the pause the middleware applies your fail open or fail closed setting immediately instead of waiting for a timeout on every request. A single success closes the breaker again.

**Credits.** Keep the matcher tight. Every static file that reaches the middleware is a lookup you pay for. Switch security rules off where you do not need them and each lookup costs 1 credit instead of 3. `IPGEO_FIELDS` reduces the response payload, though it does not change the credit cost.

## Using the library directly

The package root exports the building blocks without pulling `next/server` into your bundle, so you can use them in a Route Handler, a cron job or a server action.

```typescript
import {
  lookupIpGeolocationResult,
  getClientIp,
  shouldBlockBySecurity
} from 'ipgeolocation-vercel-middleware';

export async function POST(request: Request) {
  const ip = getClientIp(request.headers);
  if (!ip) return Response.json({ error: 'No client IP' }, { status: 400 });

  const result = await lookupIpGeolocationResult({
    apiKey: process.env.IPGEOLOCATION_API_KEY!,
    ip,
    include: ['security']
  });

  if (!result.ok) {
    console.error(result.reason, result.message);
    return Response.json({ error: 'Lookup failed' }, { status: 502 });
  }

  const reason = shouldBlockBySecurity(result.data.security);
  if (reason) return Response.json({ error: reason }, { status: 403 });

  return Response.json({ country: result.data.location?.country_code2 });
}
```

| Export | Description |
|---|---|
| `lookupIpGeolocation(options)` | Returns the response or `null` |
| `lookupIpGeolocationResult(options)` | Returns the response plus the failure reason, HTTP status, cache status and credits charged |
| `getClientIp(headers, options?)` | Resolves and validates the client IP |
| `normalizeIp(value)` | Cleans a single address taken from a header |
| `isPublicIp(value)` | True for a globally routable address |
| `shouldBlockBySecurity(security, rules?)` | Evaluates the security object and returns the first matching reason |
| `getSecurityRulesFromEnv()` | Reads the security rules from the environment |
| `securityRulesEnabled(rules)` | True when at least one rule needs the security module |
| `buildGeoHeaders(geo, ip, prefix?)` | Builds the `x-ipgeo-*` map |
| `stripSpoofedGeoHeaders(headers, prefix?)` | Removes inbound headers using the prefix |
| `parseCsvEnv`, `parseList`, `parseRedirectMap`, `normalizeInternalPath`, `envFlag`, `envNumber` | Configuration parsing helpers |
| `getIpGeoRuntimeState()` | Cache size, in flight count, failure count and breaker state |
| `resetIpGeoRuntimeState()` | Clears cache and breaker state, useful in tests |

`lookupIpGeolocationResult` accepts `apiKey`, `ip`, `include`, `includeSecurity`, `fields`, `excludes`, `timeoutMs`, `retries`, `cacheTtlMs`, `allowPrivateIp` and `baseUrl`.

## Upgrading from 1.x

Version 2.0.0 fixes behaviour that was wrong rather than merely different, so a few defaults changed. The full list is in [CHANGELOG.md](https://github.com/ipgeolocation/vercel-middleware/blob/main/CHANGELOG.md). The points most likely to affect you:

- The security module is requested only when a security rule is on. If you relied on `x-ipgeo-is-vpn` being present while every rule was off, switch on the rule you care about or pass `include: ['security']` when calling the library directly.
- `lookupIpGeolocation` no longer sets `includeSecurity: true` by default.
- Country redirects keep the path and query string. Set `IPGEO_REDIRECT_PRESERVE_PATH=false` for the old behaviour.
- An allow list now blocks an unknown country. Set `IPGEO_ALLOW_UNKNOWN_COUNTRY=true` for the old behaviour.
- Country blocks now add `?reason=country`, so a block page that switches on the reason needs a case for it.
- `getClientIp` returns `null` for private addresses, including `127.0.0.1` in local development.
- `IPGEO_BLOCK_TOR` defaults to `false`. The 1.0.0 documentation said the default was `true`, but the code never did that. If you want Tor blocked, set the variable explicitly.
- Update your matcher. The 1.0.0 matcher excluded every path beginning with `blocked`, including `/blockedlist`, and still ran on static files.

## Troubleshooting

### No `x-ipgeo-*` headers reach my application

**Cause:** the middleware never ran, the lookup never happened, or the headers were dropped downstream.

**Fix:** work through these in order.

1. Confirm the file is at the project root next to `app/` or `pages/`, not inside `app/`. Next.js 16 expects `proxy.ts` rather than `middleware.ts`.
2. Confirm the request path matches the matcher. A path excluded by the matcher never reaches the middleware.
3. Confirm `IPGEOLOCATION_API_KEY` is set in the environment you are testing. Without a key the middleware passes every request through in silence.
4. Set `IPGEO_LOG_LEVEL=debug` and look at the runtime logs for the lookup line.
5. If you wrote your own middleware around this one, make sure you return `NextResponse.next({ request: { headers: geo.requestHeaders } })`. A bare `NextResponse.next()` discards them.

### Build fails with `It mustn't be reexported`

**Cause:** `config` was re-exported from the package, as in `export { middleware, config } from 'ipgeolocation-vercel-middleware/middleware'`. Next.js reads the matcher statically at build time and cannot resolve a value that lives in a dependency.

**Fix:** re-export only the function and declare `config` in your own file:

```typescript
import { middleware } from 'ipgeolocation-vercel-middleware/middleware';

export { middleware };

export const config = { matcher: ['/((?!_next/static|_next/image).*)'] };
```

### TypeScript cannot find `ipgeolocation-vercel-middleware/middleware`

**Cause:** `moduleResolution` is set to `node`, which predates package export maps and cannot see subpath exports.

**Fix:** set `"moduleResolution": "bundler"` in `tsconfig.json`, which is what `create-next-app` generates. `node16` and `nodenext` also work.

### Security rules do nothing, and the logs mention HTTP 401

**Cause:** the security module needs a paid plan. A free key that asks for it receives HTTP 401.

**Fix:** upgrade at [ipgeolocation.io/pricing](https://ipgeolocation.io/pricing.html), or switch the security rules off and use country rules instead. The middleware retries the lookup without the module so your site keeps working, and it stops asking for five minutes rather than repeating the error on every request. While the module is unavailable, no VPN, proxy, Tor, bot, spam, attacker or threat score rule can fire. Set `IPGEO_REQUIRE_SECURITY=true` if you would rather block traffic than let it through unverified.

### Everything is blocked after I switched on fail closed

**Cause:** in fail closed mode any failed lookup becomes a block. An invalid key, an exhausted quota or a network problem takes the whole site down.

**Fix:** check the logs for the failure reason. `unauthorized` points at the key or the subscription, `rate_limited` at the daily quota, `timeout` at network conditions. Verify the key directly:

```bash
curl "https://api.ipgeolocation.io/v3/ipgeo?apiKey=YOUR_KEY&ip=8.8.8.8"
```

While you investigate, set `IPGEO_FAIL_CLOSED=false` or `IPGEO_ENABLED=false`.

### Redirect loop after setting up country redirects

**Cause:** in 1.x a target with a trailing slash, such as `{"GB":"/uk/"}`, redirected forever. It can also happen when the target path does not exist and your application rewrites it back.

**Fix:** upgrade to 2.0.0, which normalises the target and leaves a visitor alone once they are at or below it. Then confirm the target path really exists, and that no `next.config.js` rewrite sends it back to the root.

### Locally I get no data, or the logs mention a private address

**Cause:** in `next dev` there is no edge network in front of you, so the request comes from `127.0.0.1`. The API answers HTTP 423 for private and bogon ranges, so the middleware skips the lookup.

**Fix:** send a public address yourself while testing:

```bash
curl -H 'x-forwarded-for: 91.128.103.196' http://localhost:3000/
```

### Credit usage is higher than expected

**Cause:** the matcher is too broad, the cache window is too short, or the security module is being requested when you do not need it.

**Fix:** exclude static files and Next.js internals from the matcher, as in the Quick Start. Raise `IPGEO_CACHE_TTL_MS`. Switch off any security rule you are not using, which takes an uncached lookup from 3 credits back to 1. Set `IPGEO_LOG_LEVEL=debug` to see the credits charged per lookup, and check your usage in the [dashboard](https://app.ipgeolocation.io).

### The wrong country is detected, or every visitor looks the same

**Cause:** the address being looked up is a proxy rather than the visitor.

**Fix:** log `x-ipgeo-ip` and compare it with the visitor's real address. If it belongs to your own infrastructure, set `IPGEO_TRUSTED_PROXY_COUNT` to the number of proxies you run in front of the application. On Vercel without a custom proxy, leave both `IPGEO_TRUST_FIRST_XFF` and `IPGEO_TRUSTED_PROXY_COUNT` at their defaults.

### Search engines stopped indexing the site

**Cause:** a crawler was blocked. Country rules and `IPGEO_BLOCK_CLOUD_PROVIDER` both catch crawlers, since they run from datacenter ranges.

**Fix:** keep `IPGEO_ALLOW_KNOWN_GOOD_BOTS=true`, which is the default, so crawlers the API marks as known good survive `IPGEO_BLOCK_BOT`. Be careful with `IPGEO_BLOCK_CLOUD_PROVIDER`, which does not make that distinction. Make sure your block page sends `noindex`, and exclude `robots.txt` and `sitemap.xml` from the matcher.

### Health checks and webhooks are being blocked

**Cause:** monitoring services and webhook senders run from cloud ranges and from countries your visitors do not use.

**Fix:** list their paths in `IPGEO_BYPASS_PATHS`, list their addresses in `IPGEO_BYPASS_IPS`, or give the monitor a header with `IPGEO_BYPASS_TOKEN`.

## Development

```bash
git clone https://github.com/ipgeolocation/vercel-middleware
cd vercel-middleware
npm install
npm test          # 177 unit tests across the library and the middleware
npm run typecheck # strict TypeScript, no emit
npm run build     # ESM, CommonJS and declarations into dist/
```

Issues and pull requests are welcome at [github.com/ipgeolocation/vercel-middleware](https://github.com/ipgeolocation/vercel-middleware/issues).

## Support and resources

| Resource | Link |
|---|---|
| IPGeolocation.io homepage | [https://ipgeolocation.io](https://ipgeolocation.io) |
| IP Geolocation API documentation | [https://ipgeolocation.io/documentation/ip-location-api.html](https://ipgeolocation.io/documentation/ip-location-api.html) |
| IP Security API documentation | [https://ipgeolocation.io/documentation/ip-security-api.html](https://ipgeolocation.io/documentation/ip-security-api.html) |
| Credits usage guide | [https://ipgeolocation.io/documentation/credits-usage.html](https://ipgeolocation.io/documentation/credits-usage.html) |
| API pricing | [https://ipgeolocation.io/pricing.html](https://ipgeolocation.io/pricing.html) |
| Account dashboard | [https://app.ipgeolocation.io/dashboard](https://app.ipgeolocation.io/dashboard) |
| All integrations | [https://ipgeolocation.io/integrations.html](https://ipgeolocation.io/integrations.html) |
| Contact support | [https://ipgeolocation.io/contact.html](https://ipgeolocation.io/contact.html) |

## Frequently Asked Questions

<details>
<summary><strong>Do I need a paid plan to use this middleware?</strong></summary>
No. Geolocation headers, country allow and block lists, and country redirects all work on the free plan, which includes 1,000 requests per day. The security rules, which cover VPN, proxy, Tor, relay, bot, spam, attacker and threat score, need a paid plan. The middleware requests the security module only when one of those rules is switched on, so a free key is never asked for something it cannot have.
</details>

<details>
<summary><strong>How many credits does each request cost?</strong></summary>
An uncached lookup costs 1 credit with no security rules active, and 3 credits with any of them active, because the security module adds 2 credits to the base lookup. A cached lookup costs nothing. With the default 60 second cache, a visitor who loads ten pages in a minute costs one lookup on that edge isolate. The exact charge for a request is returned in the `X-Credits-Charged` header, which the middleware reports at debug log level.
</details>

<details>
<summary><strong>How much latency does this add?</strong></summary>
A cached lookup adds no network call. An uncached lookup adds one API round trip from the edge region, bounded by `IPGEO_TIMEOUT_MS`, which defaults to 3 seconds. During an API incident the circuit breaker stops the middleware from spending that timeout on every request.
</details>

<details>
<summary><strong>Does it work outside Vercel?</strong></summary>
Yes. The middleware uses standard Next.js APIs and the Web Fetch API, so it runs anywhere Next.js middleware runs, including self hosted Node.js. The only platform specific part is client IP resolution. Outside Vercel, check which header your proxy sets and configure `IPGEO_TRUSTED_PROXY_COUNT` or `IPGEO_TRUST_FIRST_XFF` accordingly.
</details>

<details>
<summary><strong>Does it work with Next.js 16?</strong></summary>
Yes. Next.js 16 renamed `middleware.ts` to `proxy.ts` and expects an exported function named `proxy`, which the package exports alongside `middleware`. Create `proxy.ts` at your project root and re-export `proxy` from it.
</details>

<details>
<summary><strong>Can a visitor fake the geolocation headers?</strong></summary>
Not through these headers. Every inbound header that uses your prefix is removed before the request continues, on every path, including those where no lookup runs. What a visitor can still do is use a VPN or a proxy to change which country the API sees, which is what the security rules are for.
</details>

<details>
<summary><strong>Why is there no country for some visitors?</strong></summary>
Either no usable client IP was present, or the lookup did not complete. In both cases the request passes through with no geo headers, so write your application to treat a missing header as unknown rather than assuming a default country. Set `IPGEO_FAIL_CLOSED=true` if an unknown visitor should be blocked instead.
</details>

<details>
<summary><strong>Is the cache shared between requests and regions?</strong></summary>
The cache lives in memory inside one edge isolate, so it is shared by the requests that isolate serves and is not shared across regions or across a new deployment. That is the correct trade off for middleware, where an external cache would add the latency the cache is meant to remove. Raise `IPGEO_CACHE_TTL_MS` if you want fewer lookups per isolate.
</details>

<details>
<summary><strong>Can I use both a country allow list and a block list?</strong></summary>
Yes. The allow list is evaluated first, then the block list, so a country missing from the allow list is blocked even if it is not on the block list. Most setups need only one of the two.
</details>

<details>
<summary><strong>Will blocking bots hurt my search ranking?</strong></summary>
It should not, as long as `IPGEO_ALLOW_KNOWN_GOOD_BOTS` stays at its default of `true`, which keeps crawlers the API identifies as known good. Take more care with `IPGEO_BLOCK_CLOUD_PROVIDER`, because crawlers run from datacenter ranges and that rule does not separate good from bad. Keep `robots.txt` and `sitemap.xml` out of the matcher, and send `noindex` from the block page.
</details>

<details>
<summary><strong>Can I test the rules without affecting real traffic?</strong></summary>
Yes. Vercel keeps environment variables separate for Production, Preview and Development, so switch the rules on for Preview first. `IPGEO_ENABLED=false` turns everything off without a redeploy of your code, and `IPGEO_BYPASS_TOKEN` lets you reach the site while a rule is active.
</details>

<details>
<summary><strong>Does it support IPv6?</strong></summary>
Yes. IPv6 addresses are validated and normalised, including bracketed forms with a port, zone indexes and IPv4 mapped addresses, and the API resolves IPv6 the same way it resolves IPv4.
</details>

<details>
<summary><strong>Can I add my own rules on top of it?</strong></summary>
Yes. Use `evaluateIpGeolocation` or `withIpGeolocation`, both shown in the composing section above. They return the decision and the prepared request headers so your own logic runs in the same middleware without losing the geo data.
</details>

<details>
<summary><strong>How do I get an API key?</strong></summary>
Sign up at <a href="https://app.ipgeolocation.io/signup">app.ipgeolocation.io/signup</a> and copy the key from your dashboard. The free plan needs no card. Keep the key in an environment variable and never in client side code, because the API authenticates with the key as a query parameter.
</details>

## License

MIT. See [LICENSE](https://github.com/ipgeolocation/vercel-middleware/blob/main/LICENSE).