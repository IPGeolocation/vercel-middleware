// =============================================================================
// IPGeolocation.io middleware for Next.js
//
// Next.js 13, 14 and 15 read this from middleware.ts at the project root.
// Next.js 16 reads proxy.ts and expects an exported function named proxy, which
// this module also exports.
//
// Create middleware.ts (or proxy.ts) at your project root with:
//
//   import { middleware } from 'ipgeolocation-vercel-middleware/middleware';
//   export { middleware };
//   export const config = { matcher: ['/((?!_next/static|_next/image).*)'] };
//
// Define config locally. Next.js reads the matcher at build time and cannot
// follow a re-exported value.
// =============================================================================

import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';

import {
  buildGeoHeaders,
  envFlag,
  envNumber,
  getClientIp,
  getSecurityRulesFromEnv,
  isUnderPath,
  lookupIpGeolocationResult,
  normalizeInternalPath,
  parseCsvEnv,
  parseList,
  parseRedirectMap,
  securityRulesEnabled,
  shouldBlockBySecurity,
  stripSpoofedGeoHeaders,
  type IpGeoResponse,
  type SecurityRules
} from './ipgeolocation-edge.js';

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

export type BlockMode = 'redirect' | 'rewrite' | 'deny';

export type IpGeoMiddlewareConfig = {
  enabled: boolean;
  apiKey: string;
  headerPrefix: string;
  blockPath: string;
  blockMode: BlockMode;
  blockStatus: number;
  blockMessage: string;
  includeBlockReason: boolean;
  failClosed: boolean;
  timeoutMs: number;
  trustFirstXff: boolean;
  trustedProxyCount: number;
  allowedCountries: Set<string>;
  blockedCountries: Set<string>;
  allowUnknownCountry: boolean;
  countryRedirects: Record<string, string>;
  redirectStatus: 307 | 308 | 302 | 301;
  redirectPreservePath: boolean;
  redirectRespectExisting: boolean;
  redirectSkipCookie: string;
  securityRules: SecurityRules;
  requireSecurity: boolean;
  bypassPaths: string[];
  bypassIps: Set<string>;
  bypassToken: string;
  responseHeaders: boolean;
  fields: string[];
};

const REDIRECT_STATUSES = new Set([301, 302, 307, 308]);

let redirectMapCacheKey: string | undefined;
let redirectMapCacheValue: Record<string, string> = {};

function readRedirectMap(): Record<string, string> {
  const raw = process.env.IPGEO_COUNTRY_REDIRECTS ?? '';

  if (raw !== redirectMapCacheKey) {
    redirectMapCacheKey = raw;
    redirectMapCacheValue = parseRedirectMap(raw);
  }

  return redirectMapCacheValue;
}

/** Builds the active configuration from environment variables. */
export function getMiddlewareConfig(
  overrides: Partial<IpGeoMiddlewareConfig> = {}
): IpGeoMiddlewareConfig {
  const blockMode = String(process.env.IPGEO_BLOCK_MODE ?? 'redirect').trim().toLowerCase();
  const redirectStatus = envNumber(process.env.IPGEO_REDIRECT_STATUS, 307);

  const base: IpGeoMiddlewareConfig = {
    enabled: envFlag(process.env.IPGEO_ENABLED, true),
    apiKey: String(process.env.IPGEOLOCATION_API_KEY ?? '').trim(),
    headerPrefix: (process.env.IPGEO_HEADER_PREFIX || 'x-ipgeo').trim().toLowerCase(),
    blockPath: normalizeInternalPath(process.env.IPGEO_BLOCK_PATH || '/blocked') ?? '/blocked',
    blockMode: (blockMode === 'rewrite' || blockMode === 'deny' ? blockMode : 'redirect') as BlockMode,
    blockStatus: envNumber(process.env.IPGEO_BLOCK_STATUS, 403, { min: 400, max: 599 }),
    blockMessage: process.env.IPGEO_BLOCK_MESSAGE || 'Access to this site is restricted.',
    includeBlockReason: envFlag(process.env.IPGEO_BLOCK_INCLUDE_REASON, true),
    failClosed: envFlag(process.env.IPGEO_FAIL_CLOSED),
    timeoutMs: envNumber(process.env.IPGEO_TIMEOUT_MS, 3000, { min: 250, max: 20_000 }),
    trustFirstXff: envFlag(process.env.IPGEO_TRUST_FIRST_XFF),
    trustedProxyCount: envNumber(process.env.IPGEO_TRUSTED_PROXY_COUNT, 0, { min: 0, max: 10 }),
    allowedCountries: parseCsvEnv(process.env.IPGEO_ALLOWED_COUNTRIES),
    blockedCountries: parseCsvEnv(process.env.IPGEO_BLOCKED_COUNTRIES),
    allowUnknownCountry: envFlag(process.env.IPGEO_ALLOW_UNKNOWN_COUNTRY),
    countryRedirects: readRedirectMap(),
    redirectStatus: (REDIRECT_STATUSES.has(redirectStatus) ? redirectStatus : 307) as 307,
    redirectPreservePath: envFlag(process.env.IPGEO_REDIRECT_PRESERVE_PATH, true),
    redirectRespectExisting: envFlag(process.env.IPGEO_REDIRECT_RESPECT_EXISTING, true),
    redirectSkipCookie: (process.env.IPGEO_REDIRECT_SKIP_COOKIE || '').trim(),
    securityRules: getSecurityRulesFromEnv(),
    requireSecurity: envFlag(process.env.IPGEO_REQUIRE_SECURITY),
    bypassPaths: parseList(process.env.IPGEO_BYPASS_PATHS)
      .map((path) => normalizeInternalPath(path))
      .filter((path): path is string => path !== null),
    bypassIps: new Set(parseList(process.env.IPGEO_BYPASS_IPS)),
    bypassToken: (process.env.IPGEO_BYPASS_TOKEN || '').trim(),
    responseHeaders: envFlag(process.env.IPGEO_SET_RESPONSE_HEADERS),
    fields: parseList(process.env.IPGEO_FIELDS)
  };

  return { ...base, ...overrides };
}

// -----------------------------------------------------------------------------
// Evaluation result
// -----------------------------------------------------------------------------

export type IpGeoAction = 'disabled' | 'bypass' | 'pass' | 'block' | 'redirect';

export type IpGeoEvaluation = {
  /** What the middleware decided to do. */
  action: IpGeoAction;
  /** The response to return, or null when the request should continue. */
  response: NextResponse | null;
  /** Request headers with the geo values added and spoofed values removed. */
  requestHeaders: Headers;
  /** The API response, or null when no lookup ran or the lookup failed. */
  geo: IpGeoResponse | null;
  /** The resolved client IP, or null when none could be read. */
  ip: string | null;
  /** ISO 3166-1 alpha-2 country code, or null when it is unknown. */
  country: string | null;
  /** Why the request was blocked or redirected. */
  reason: string | null;
};

function passThrough(
  action: IpGeoAction,
  requestHeaders: Headers,
  extra: Partial<IpGeoEvaluation> = {}
): IpGeoEvaluation {
  return {
    action,
    response: null,
    requestHeaders,
    geo: null,
    ip: null,
    country: null,
    reason: null,
    ...extra
  };
}

function buildBlockResponse(
  request: NextRequest,
  config: IpGeoMiddlewareConfig,
  reason: string
): NextResponse {
  let response: NextResponse;

  if (config.blockMode === 'deny') {
    response = new NextResponse(config.blockMessage, {
      status: config.blockStatus,
      headers: { 'content-type': 'text/plain; charset=utf-8' }
    });
  } else if (config.blockMode === 'rewrite') {
    const url = new URL(config.blockPath, request.url);
    if (config.includeBlockReason) url.searchParams.set('reason', reason);
    response = NextResponse.rewrite(url);
  } else {
    const url = new URL(config.blockPath, request.url);
    if (config.includeBlockReason) url.searchParams.set('reason', reason);
    response = NextResponse.redirect(url, 307);
  }

  response.headers.set(`${config.headerPrefix}-block-reason`, reason);
  response.headers.set('cache-control', 'no-store');

  return response;
}

function buildRedirectResponse(
  request: NextRequest,
  config: IpGeoMiddlewareConfig,
  target: string
): NextResponse {
  const url = new URL(target, request.url);

  if (config.redirectPreservePath) {
    const { pathname, search } = request.nextUrl;
    const suffix = pathname === '/' ? '' : pathname;
    url.pathname = `${target}${suffix}`;
    url.search = search;
  }

  const response = NextResponse.redirect(url, config.redirectStatus);
  response.headers.set('cache-control', 'no-store');

  return response;
}

// -----------------------------------------------------------------------------
// Core evaluation
// -----------------------------------------------------------------------------

/**
 * Runs the full IPGeolocation.io decision for a request without sending a
 * response. Use it when you want to combine geo rules with your own middleware
 * and still forward the geo headers.
 *
 *   const result = await evaluateIpGeolocation(request);
 *   if (result.response) return result.response;
 *   return NextResponse.next({ request: { headers: result.requestHeaders } });
 */
export async function evaluateIpGeolocation(
  request: NextRequest,
  overrides: Partial<IpGeoMiddlewareConfig> = {}
): Promise<IpGeoEvaluation> {
  const config = getMiddlewareConfig(overrides);

  const requestHeaders = new Headers(request.headers);

  // A visitor can send x-ipgeo-* headers. Remove them on every path so the
  // application can trust what it receives.
  stripSpoofedGeoHeaders(requestHeaders, config.headerPrefix);

  if (!config.enabled) return passThrough('disabled', requestHeaders);
  if (!config.apiKey) return passThrough('disabled', requestHeaders);

  const { pathname } = request.nextUrl;

  if (isUnderPath(pathname, config.blockPath)) return passThrough('bypass', requestHeaders);

  for (const bypassPath of config.bypassPaths) {
    if (isUnderPath(pathname, bypassPath)) return passThrough('bypass', requestHeaders);
  }

  if (config.bypassToken) {
    const token = request.headers.get(`${config.headerPrefix}-bypass-token`);
    if (token && token === config.bypassToken) return passThrough('bypass', requestHeaders);
  }

  const ip = getClientIp(request.headers, {
    trustFirstXff: config.trustFirstXff,
    trustedProxyCount: config.trustedProxyCount
  });

  if (!ip) return passThrough('pass', requestHeaders);
  if (config.bypassIps.has(ip)) return passThrough('bypass', requestHeaders, { ip });

  const needsSecurity = securityRulesEnabled(config.securityRules);

  const lookup = await lookupIpGeolocationResult({
    apiKey: config.apiKey,
    ip,
    include: needsSecurity ? ['security'] : [],
    timeoutMs: config.timeoutMs,
    ...(config.fields.length > 0 ? { fields: config.fields } : {})
  });

  if (!lookup.ok) {
    // A private address is not a failure. It means the request did not come
    // through the edge, which is normal in local development.
    const lookupFailed = lookup.reason !== 'private_ip' && lookup.reason !== 'invalid_input';

    if (lookupFailed && config.failClosed) {
      return {
        action: 'block',
        response: buildBlockResponse(request, config, 'lookup_failed'),
        requestHeaders,
        geo: null,
        ip,
        country: null,
        reason: 'lookup_failed'
      };
    }

    return passThrough('pass', requestHeaders, { ip });
  }

  const geo = lookup.data;
  const country = geo.location?.country_code2?.toUpperCase() || null;

  // Country allow list. An unknown country fails the allow list unless
  // IPGEO_ALLOW_UNKNOWN_COUNTRY is on, because an allow list that lets unknown
  // traffic through is not an allow list.
  if (config.allowedCountries.size > 0) {
    const allowed = country ? config.allowedCountries.has(country) : config.allowUnknownCountry;

    if (!allowed) {
      return {
        action: 'block',
        response: buildBlockResponse(request, config, 'country'),
        requestHeaders,
        geo,
        ip,
        country,
        reason: 'country'
      };
    }
  }

  if (country && config.blockedCountries.has(country)) {
    return {
      action: 'block',
      response: buildBlockResponse(request, config, 'country'),
      requestHeaders,
      geo,
      ip,
      country,
      reason: 'country'
    };
  }

  // Security rules.
  if (needsSecurity) {
    if (!geo.security) {
      if (config.requireSecurity) {
        return {
          action: 'block',
          response: buildBlockResponse(request, config, 'security_unavailable'),
          requestHeaders,
          geo,
          ip,
          country,
          reason: 'security_unavailable'
        };
      }
    } else {
      const securityReason = shouldBlockBySecurity(geo.security, config.securityRules);

      if (securityReason) {
        return {
          action: 'block',
          response: buildBlockResponse(request, config, securityReason),
          requestHeaders,
          geo,
          ip,
          country,
          reason: securityReason
        };
      }
    }
  }

  // Country redirects.
  const target = country ? config.countryRedirects[country] : undefined;

  if (target && shouldRedirect(request, config, target)) {
    const response = buildRedirectResponse(request, config, target);

    return {
      action: 'redirect',
      response,
      requestHeaders,
      geo,
      ip,
      country,
      reason: `redirect:${target}`
    };
  }

  // Pass through with geo headers attached.
  const geoHeaders = buildGeoHeaders(geo, ip, config.headerPrefix);

  for (const [name, value] of Object.entries(geoHeaders)) {
    requestHeaders.set(name, value);
  }

  return {
    action: 'pass',
    response: null,
    requestHeaders,
    geo,
    ip,
    country,
    reason: null
  };
}

function shouldRedirect(
  request: NextRequest,
  config: IpGeoMiddlewareConfig,
  target: string
): boolean {
  const method = request.method.toUpperCase();
  if (method !== 'GET' && method !== 'HEAD') return false;

  const { pathname } = request.nextUrl;

  // Already at or below the target.
  if (isUnderPath(pathname, target)) return false;

  // The visitor chose another locale that is also in the map.
  if (config.redirectRespectExisting) {
    for (const candidate of Object.values(config.countryRedirects)) {
      if (isUnderPath(pathname, candidate)) return false;
    }
  }

  if (config.redirectSkipCookie) {
    const cookie = request.cookies.get(config.redirectSkipCookie);
    if (cookie) return false;
  }

  return true;
}

// -----------------------------------------------------------------------------
// Middleware entry points
// -----------------------------------------------------------------------------

function applyResponseHeaders(
  response: NextResponse,
  evaluation: IpGeoEvaluation,
  prefix: string
): NextResponse {
  const geoHeaders = buildGeoHeaders(evaluation.geo, evaluation.ip ?? '', prefix);

  for (const [name, value] of Object.entries(geoHeaders)) {
    response.headers.set(name, value);
  }

  return response;
}

/**
 * Builds a middleware function with configuration overrides applied on top of
 * the environment variables.
 */
export function createIpGeoMiddleware(
  overrides: Partial<IpGeoMiddlewareConfig> = {}
): (request: NextRequest) => Promise<NextResponse> {
  return async function ipGeoMiddleware(request: NextRequest): Promise<NextResponse> {
    try {
      const evaluation = await evaluateIpGeolocation(request, overrides);

      if (evaluation.response) return evaluation.response;

      const response = NextResponse.next({ request: { headers: evaluation.requestHeaders } });

      const config = getMiddlewareConfig(overrides);
      if (config.responseHeaders && evaluation.geo) {
        applyResponseHeaders(response, evaluation, config.headerPrefix);
      }

      return response;
    } catch (error) {
      // Middleware runs in front of every request, so an unexpected error must
      // never take the site down. Fail open unless fail closed is requested.
      console.error('[IPGeolocation.io] The middleware threw an unexpected error:', error);

      if (envFlag(process.env.IPGEO_FAIL_CLOSED)) {
        const blockPath = normalizeInternalPath(process.env.IPGEO_BLOCK_PATH || '/blocked') ?? '/blocked';
        const url = new URL(blockPath, request.url);
        url.searchParams.set('reason', 'middleware_error');
        return NextResponse.redirect(url, 307);
      }

      return NextResponse.next();
    }
  };
}

const defaultMiddleware = createIpGeoMiddleware();

/** The ready to use middleware. Next.js 13, 14 and 15 expect this name. */
export async function middleware(request: NextRequest): Promise<NextResponse> {
  return defaultMiddleware(request);
}

/** The same function under the name Next.js 16 expects in proxy.ts. */
export const proxy = middleware;

/**
 * Wraps your own handler. The geo decision runs first, and your handler
 * receives the evaluation so it can forward the geo headers.
 *
 *   export const middleware = withIpGeolocation(async (request, geo) => {
 *     if (!isSignedIn(request)) return NextResponse.redirect(new URL('/login', request.url));
 *     return NextResponse.next({ request: { headers: geo.requestHeaders } });
 *   });
 */
export function withIpGeolocation(
  handler: (request: NextRequest, evaluation: IpGeoEvaluation) => Promise<Response> | Response,
  overrides: Partial<IpGeoMiddlewareConfig> = {}
): (request: NextRequest) => Promise<Response> {
  return async function composedMiddleware(request: NextRequest): Promise<Response> {
    const evaluation = await evaluateIpGeolocation(request, overrides);
    if (evaluation.response) return evaluation.response;
    return handler(request, evaluation);
  };
}

// -----------------------------------------------------------------------------
// Matcher
//
// Skips Next.js internals and common static file extensions so that images,
// fonts and stylesheets never trigger a lookup. Every lookup you avoid is a
// credit you keep.
// -----------------------------------------------------------------------------

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|_next/data|favicon.ico|robots.txt|sitemap.xml|.*\\.(?:css|js|mjs|map|json|txt|xml|ico|png|jpg|jpeg|gif|webp|avif|svg|woff|woff2|ttf|otf|eot|mp4|webm|mp3|pdf|zip)$).*)'
  ]
};
