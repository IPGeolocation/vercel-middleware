# Changelog

All notable changes to `@ipgeolocation/vercel-middleware` will be documented here.

This project adheres to [Semantic Versioning](https://semver.org/).

---

## [1.0.0] — Initial release

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
