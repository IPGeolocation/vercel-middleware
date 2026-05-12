// ─────────────────────────────────────────────────────────────────────────────
// IPGeolocation.io – Next.js Middleware
//
// Usage (Next.js ≥ 13):
//   Copy this file to `middleware.ts` at your project root, or import the
//   middleware function and call it from your own middleware.ts:
//
//   import { middleware, config } from 'ipgeolocation-vercel-middleware/middleware';
//   export { middleware, config };
//
// ─────────────────────────────────────────────────────────────────────────────

import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import {
  getClientIp,
  lookupIpGeolocation,
  parseCsvEnv,
  parseRedirectMap,
  shouldBlockBySecurity,
  envFlag
} from './ipgeolocation-edge.js';

export async function middleware(request: NextRequest): Promise<NextResponse> {
  const apiKey = process.env.IPGEOLOCATION_API_KEY;

  if (!apiKey) return NextResponse.next();

  // ── Config ────────────────────────────────────────────────────────────────

  const blockPath = process.env.IPGEO_BLOCK_PATH || '/blocked';
  const headerPrefix = process.env.IPGEO_HEADER_PREFIX || 'x-ipgeo';
  const failClosed = envFlag(process.env.IPGEO_FAIL_CLOSED);
  const trustFirstXff = envFlag(process.env.IPGEO_TRUST_FIRST_XFF);

  // ── Guard: never re-run on the block page itself ──────────────────────────

  const { pathname } = request.nextUrl;
  if (pathname === blockPath || pathname.startsWith(blockPath + '/')) {
    return NextResponse.next();
  }

  // ── Extract client IP ─────────────────────────────────────────────────────

  const ip = getClientIp(request.headers, trustFirstXff);
  if (!ip) return NextResponse.next();

  // ── Geo lookup ────────────────────────────────────────────────────────────

  const geo = await lookupIpGeolocation({
    apiKey,
    ip,
    includeSecurity: true,
    timeoutMs: Number(process.env.IPGEO_TIMEOUT_MS || '3000')
  });

  if (!geo) {
    if (failClosed) {
      const url = new URL(blockPath, request.url);
      url.searchParams.set('reason', 'lookup_failed');
      return NextResponse.redirect(url);
    }
    return NextResponse.next();
  }

  // ── Country controls ──────────────────────────────────────────────────────

  const countryCode = geo.location?.country_code2?.toUpperCase() ?? '';
  const allowedCountries = parseCsvEnv(process.env.IPGEO_ALLOWED_COUNTRIES);
  const blockedCountries = parseCsvEnv(process.env.IPGEO_BLOCKED_COUNTRIES);

  if (countryCode && allowedCountries.size > 0 && !allowedCountries.has(countryCode)) {
    return NextResponse.redirect(new URL(blockPath, request.url));
  }

  if (countryCode && blockedCountries.has(countryCode)) {
    return NextResponse.redirect(new URL(blockPath, request.url));
  }

  // ── Security controls ─────────────────────────────────────────────────────

  const securityBlockReason = shouldBlockBySecurity(geo.security);

  if (securityBlockReason) {
    const url = new URL(blockPath, request.url);
    url.searchParams.set('reason', securityBlockReason);
    return NextResponse.redirect(url);
  }

  // ── Country-based redirects ───────────────────────────────────────────────

  const redirectMap = parseRedirectMap(process.env.IPGEO_COUNTRY_REDIRECTS);
  const redirectPath = countryCode ? redirectMap[countryCode] : undefined;

  if (redirectPath && !pathname.startsWith(redirectPath)) {
    return NextResponse.redirect(new URL(redirectPath, request.url));
  }

  // ── Forward geo headers to the origin ────────────────────────────────────

  const requestHeaders = new Headers(request.headers);

  requestHeaders.set(`${headerPrefix}-ip`,                geo.ip ?? ip);
  requestHeaders.set(`${headerPrefix}-country`,           countryCode);
  requestHeaders.set(`${headerPrefix}-country-name`,      geo.location?.country_name ?? '');
  requestHeaders.set(`${headerPrefix}-state`,             geo.location?.state_prov ?? '');
  requestHeaders.set(`${headerPrefix}-city`,              geo.location?.city ?? '');
  requestHeaders.set(`${headerPrefix}-latitude`,          geo.location?.latitude ?? '');
  requestHeaders.set(`${headerPrefix}-longitude`,         geo.location?.longitude ?? '');
  requestHeaders.set(`${headerPrefix}-timezone`,          geo.time_zone?.name ?? '');
  requestHeaders.set(`${headerPrefix}-asn`,               geo.asn?.as_number ?? '');
  requestHeaders.set(`${headerPrefix}-asn-organization`,  geo.asn?.organization ?? '');
  requestHeaders.set(`${headerPrefix}-threat-score`,      String(geo.security?.threat_score ?? ''));
  requestHeaders.set(`${headerPrefix}-is-vpn`,            String(Boolean(geo.security?.is_vpn)));
  requestHeaders.set(`${headerPrefix}-is-proxy`,          String(Boolean(geo.security?.is_proxy)));
  requestHeaders.set(`${headerPrefix}-is-tor`,            String(Boolean(geo.security?.is_tor)));
  requestHeaders.set(`${headerPrefix}-is-bot`,            String(Boolean(geo.security?.is_bot)));
  requestHeaders.set(`${headerPrefix}-is-spam`,           String(Boolean(geo.security?.is_spam)));
  requestHeaders.set(`${headerPrefix}-is-known-attacker`, String(Boolean(geo.security?.is_known_attacker)));
  requestHeaders.set(`${headerPrefix}-is-cloud-provider`, String(Boolean(geo.security?.is_cloud_provider)));
  requestHeaders.set(`${headerPrefix}-cloud-provider-name`, geo.security?.cloud_provider_name ?? '');

  return NextResponse.next({ request: { headers: requestHeaders } });
}

// ─────────────────────────────────────────────────────────────────────────────
// Matcher — skips static assets, favicons, sitemaps, and the block page
// ─────────────────────────────────────────────────────────────────────────────

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico|robots.txt|sitemap.xml|blocked).*)'
  ]
};
