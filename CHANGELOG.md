# Changelog

All notable changes to `ipgeolocation-vercel-middleware` are recorded here.
This project follows [Semantic Versioning](https://semver.org/).

## 2.0.0

A correctness and hardening release. Read the upgrade notes before deploying,
because several defaults changed.

### Breaking changes

- The security module is now requested only when a security rule is switched on.
  Version 1.0.0 always sent `include=security`, which made every lookup cost 3
  credits and returned HTTP 401 on free plans. With no security rules active, a
  lookup now costs 1 credit and works on a free key.
- `lookupIpGeolocation` no longer defaults `includeSecurity` to `true`. Pass
  `includeSecurity: true` or `include: ['security']` when you want it.
- `lookupIpGeolocation` rejects private, loopback and bogon addresses before
  calling the API, because the API answers HTTP 423 for them. Pass
  `allowPrivateIp: true` to restore the old behaviour.
- `getClientIp` validates the address and ignores private ranges by default.
  It returns `null` where 1.0.0 returned `127.0.0.1` during local development.
- Country redirects keep the requested path and query string by default. Set
  `IPGEO_REDIRECT_PRESERVE_PATH=false` for the 1.0.0 behaviour.
- When `IPGEO_ALLOWED_COUNTRIES` is set and the country cannot be determined,
  the request is blocked. Set `IPGEO_ALLOW_UNKNOWN_COUNTRY=true` to allow it.
- Country blocks now include `?reason=country` in the block URL.

### Added

- `evaluateIpGeolocation`, which returns the decision without sending a
  response, so the geo headers survive when you compose your own middleware.
- `withIpGeolocation`, a wrapper for the same pattern.
- `createIpGeoMiddleware` and `getMiddlewareConfig` for configuration in code.
- `proxy`, an alias of `middleware` for the Next.js 16 `proxy.ts` convention.
- `lookupIpGeolocationResult`, which reports the failure reason, the HTTP
  status, whether the answer came from cache and how many credits were charged.
- Block modes: `redirect`, `rewrite` and `deny` through `IPGEO_BLOCK_MODE`.
- Bypasses: `IPGEO_ENABLED`, `IPGEO_BYPASS_PATHS`, `IPGEO_BYPASS_IPS` and
  `IPGEO_BYPASS_TOKEN`.
- Retries for timeouts, network errors and 5xx responses, with `IPGEO_RETRIES`.
- A circuit breaker, `IPGEO_CIRCUIT_FAILURE_THRESHOLD` and
  `IPGEO_CIRCUIT_COOLDOWN_MS`, so an API incident does not add the full timeout
  to every request.
- Request coalescing, so concurrent lookups for one IP share a single call.
- A bounded cache, `IPGEO_CACHE_MAX_ENTRIES`, with eviction of the coldest keys.
- Automatic retry without the security module when a free plan key rejects it,
  plus a five minute latch so the mistake is not repeated on every request.
- New rules: `IPGEO_BLOCK_RESIDENTIAL_PROXY`, `IPGEO_BLOCK_RELAY`,
  `IPGEO_BLOCK_ANONYMOUS`, `IPGEO_ALLOW_KNOWN_GOOD_BOTS` and
  `IPGEO_REQUIRE_SECURITY`.
- Redirect controls: `IPGEO_REDIRECT_STATUS`, `IPGEO_REDIRECT_PRESERVE_PATH`,
  `IPGEO_REDIRECT_RESPECT_EXISTING` and `IPGEO_REDIRECT_SKIP_COOKIE`.
- `IPGEO_TRUSTED_PROXY_COUNT` for deployments behind your own reverse proxy.
- `IPGEO_LOG_LEVEL` with a `warn` default, replacing a log line per lookup.
- `IPGEO_SET_RESPONSE_HEADERS` for copying the geo headers onto the response.
- New headers: `x-ipgeo-continent`, `x-ipgeo-state-code`, `x-ipgeo-zipcode`,
  `x-ipgeo-is-eu`, `x-ipgeo-currency`, `x-ipgeo-company`,
  `x-ipgeo-is-residential-proxy`, `x-ipgeo-is-relay`, `x-ipgeo-is-anonymous`
  and `x-ipgeo-is-known-good-bot`.
- `resetIpGeoRuntimeState` and `getIpGeoRuntimeState` for tests and health
  checks.
- 177 unit tests covering the library and the middleware.

### Fixed

- Inbound `x-ipgeo-*` headers are removed on every path. In 1.0.0 a visitor
  could send `x-ipgeo-country` and the application had no way to tell.
- A redirect target with a trailing slash, such as `{"GB":"/uk/"}`, caused an
  endless redirect loop. Targets are normalised and loops are detected.
- Redirect targets pointing at another origin are rejected, so a mistyped
  variable cannot turn the middleware into an open redirect.
- The default matcher skipped every path starting with `blocked`, including
  `/blockedlist`, and ran on static files. Both are fixed.
- Country blocks sent no reason, so the block page could not explain itself.
- Country redirects fired on POST requests, which turned a form submission into
  a GET.
- An unexpected error inside the middleware could return HTTP 500 for the whole
  site. Errors are caught and follow the fail open or fail closed setting.
- Blocks and redirects now send `cache-control: no-store`, so a shared cache
  cannot serve one visitor's geo decision to another.
- `x-forwarded-for` values with a port, IPv6 in brackets, IPv4 mapped IPv6 and
  zone indexes are parsed correctly instead of being sent to the API as is.
- `IPGEO_COUNTRY_REDIRECTS` is parsed once per value rather than on every
  request.

## 1.0.0

### Added
- `lookupIpGeolocation` — fetch geo + security data from IPGeolocation.io v3 API
- `getClientIp` — safe IP extraction from `x-forwarded-for`, `x-real-ip`, `cf-connecting-ip`
- `shouldBlockBySecurity` — evaluate VPN, proxy, Tor, bot, spam, known attacker, cloud provider, threat score
- `parseCsvEnv` — parse comma-separated country code env vars into a `Set`
- `parseRedirectMap` — parse JSON country→path redirect map
- `envFlag` — parse boolean env vars
- Full Next.js middleware with country allow/block lists, country redirects, security blocking, geo header forwarding
- In-memory TTL cache (configurable via `IPGEO_CACHE_TTL_MS`)
- Fail-open / fail-closed mode (`IPGEO_FAIL_CLOSED`)
- Configurable XFF trust strategy (`IPGEO_TRUST_FIRST_XFF`)
- 40+ unit tests with Vitest
