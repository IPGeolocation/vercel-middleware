// =============================================================================
// Tests for middleware.ts
// Run with: npm test
// =============================================================================

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NextRequest, NextResponse } from 'next/server';

import { resetIpGeoRuntimeState, type IpGeoResponse } from './ipgeolocation-edge.js';
import { evaluateIpGeolocation, middleware, proxy, withIpGeolocation } from './middleware.js';

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

const ENV_KEYS = [
  'IPGEOLOCATION_API_KEY',
  'IPGEO_ALLOWED_COUNTRIES',
  'IPGEO_ALLOW_UNKNOWN_COUNTRY',
  'IPGEO_BLOCKED_COUNTRIES',
  'IPGEO_BLOCK_BOT',
  'IPGEO_BLOCK_INCLUDE_REASON',
  'IPGEO_BLOCK_MESSAGE',
  'IPGEO_BLOCK_MODE',
  'IPGEO_BLOCK_PATH',
  'IPGEO_BLOCK_STATUS',
  'IPGEO_BLOCK_TOR',
  'IPGEO_BLOCK_VPN',
  'IPGEO_BYPASS_IPS',
  'IPGEO_BYPASS_PATHS',
  'IPGEO_BYPASS_TOKEN',
  'IPGEO_CACHE_TTL_MS',
  'IPGEO_COUNTRY_REDIRECTS',
  'IPGEO_ENABLED',
  'IPGEO_FAIL_CLOSED',
  'IPGEO_HEADER_PREFIX',
  'IPGEO_LOG_LEVEL',
  'IPGEO_REDIRECT_PRESERVE_PATH',
  'IPGEO_REDIRECT_RESPECT_EXISTING',
  'IPGEO_REDIRECT_SKIP_COOKIE',
  'IPGEO_REDIRECT_STATUS',
  'IPGEO_REQUIRE_SECURITY',
  'IPGEO_RETRIES',
  'IPGEO_SET_RESPONSE_HEADERS',
  'IPGEO_THREAT_SCORE_BLOCK_THRESHOLD'
];

function clearEnv(): void {
  for (const key of ENV_KEYS) delete process.env[key];
}

function makeRequest(
  url: string,
  init: { ip?: string; headers?: Record<string, string>; method?: string } = {}
): NextRequest {
  const headers = new Headers(init.headers ?? {});
  if (init.ip !== undefined) headers.set('x-forwarded-for', init.ip);

  const requestInit: { headers: Headers; method?: string } = { headers };
  if (init.method) requestInit.method = init.method;

  return new NextRequest(url, requestInit);
}

function geoFor(countryCode: string, security?: IpGeoResponse['security']): IpGeoResponse {
  const response: IpGeoResponse = {
    ip: '8.8.8.8',
    location: {
      country_code2: countryCode,
      country_name: countryCode === 'SE' ? 'Sweden' : 'United States',
      city: 'Stockholm',
      latitude: '59.40510',
      longitude: '17.95510'
    },
    asn: { as_number: 'AS1257', organization: 'Tele2 Sverige AB' },
    time_zone: { name: 'Europe/Stockholm' }
  };

  if (security) response.security = security;

  return response;
}

function mockApi(body: IpGeoResponse | null, status = 200): ReturnType<typeof vi.fn> {
  const fetchMock = vi.fn().mockImplementation(
    async () =>
      new Response(body === null ? 'error' : JSON.stringify(body), {
        status,
        headers: { 'content-type': 'application/json' }
      })
  );

  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

/** Reads a request header that the middleware forwarded to the application. */
function forwardedHeader(response: NextResponse, name: string): string | null {
  return response.headers.get(`x-middleware-request-${name}`);
}

beforeEach(() => {
  clearEnv();
  process.env.IPGEO_LOG_LEVEL = 'silent';
  process.env.IPGEOLOCATION_API_KEY = 'test-key';
  process.env.IPGEO_RETRIES = '0';
  resetIpGeoRuntimeState();
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  clearEnv();
});

// -----------------------------------------------------------------------------
// Pass through and configuration guards
// -----------------------------------------------------------------------------

describe('middleware guards', () => {
  it('does nothing when no API key is set', async () => {
    delete process.env.IPGEOLOCATION_API_KEY;
    const fetchMock = mockApi(geoFor('SE'));

    const response = await middleware(makeRequest('https://example.com/', { ip: '8.8.8.8' }));

    expect(response.status).toBe(200);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('does nothing when IPGEO_ENABLED is false', async () => {
    process.env.IPGEO_ENABLED = 'false';
    const fetchMock = mockApi(geoFor('SE'));

    await middleware(makeRequest('https://example.com/', { ip: '8.8.8.8' }));

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('skips the block page so it cannot loop', async () => {
    process.env.IPGEO_BLOCKED_COUNTRIES = 'SE';
    const fetchMock = mockApi(geoFor('SE'));

    const response = await middleware(
      makeRequest('https://example.com/blocked?reason=tor', { ip: '8.8.8.8' })
    );

    expect(response.status).toBe(200);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('does not treat a path that merely starts with the block path as the block page', async () => {
    process.env.IPGEO_BLOCKED_COUNTRIES = 'SE';
    mockApi(geoFor('SE'));

    const response = await middleware(
      makeRequest('https://example.com/blockedlist', { ip: '8.8.8.8' })
    );

    expect(response.status).toBe(307);
  });

  it('skips paths listed in IPGEO_BYPASS_PATHS', async () => {
    process.env.IPGEO_BYPASS_PATHS = '/health,/api/webhooks';
    process.env.IPGEO_BLOCKED_COUNTRIES = 'SE';
    const fetchMock = mockApi(geoFor('SE'));

    const response = await middleware(
      makeRequest('https://example.com/api/webhooks/stripe', { ip: '8.8.8.8' })
    );

    expect(response.status).toBe(200);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('skips a request that carries the bypass token', async () => {
    process.env.IPGEO_BYPASS_TOKEN = 'uptime-robot';
    process.env.IPGEO_BLOCKED_COUNTRIES = 'SE';
    const fetchMock = mockApi(geoFor('SE'));

    const response = await middleware(
      makeRequest('https://example.com/', {
        ip: '8.8.8.8',
        headers: { 'x-ipgeo-bypass-token': 'uptime-robot' }
      })
    );

    expect(response.status).toBe(200);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('skips IPs listed in IPGEO_BYPASS_IPS', async () => {
    process.env.IPGEO_BYPASS_IPS = '8.8.8.8';
    process.env.IPGEO_BLOCKED_COUNTRIES = 'SE';
    const fetchMock = mockApi(geoFor('SE'));

    const response = await middleware(makeRequest('https://example.com/', { ip: '8.8.8.8' }));

    expect(response.status).toBe(200);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('passes a local request through without calling the API', async () => {
    const fetchMock = mockApi(geoFor('SE'));

    const response = await middleware(makeRequest('https://example.com/', { ip: '127.0.0.1' }));

    expect(response.status).toBe(200);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('passes through when no IP header is present', async () => {
    const fetchMock = mockApi(geoFor('SE'));

    const response = await middleware(makeRequest('https://example.com/'));

    expect(response.status).toBe(200);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

// -----------------------------------------------------------------------------
// Header hardening
// -----------------------------------------------------------------------------

describe('header hardening', () => {
  it('removes client supplied geo headers before the request reaches the app', async () => {
    mockApi(geoFor('SE'));

    const response = await middleware(
      makeRequest('https://example.com/', {
        ip: '8.8.8.8',
        headers: { 'x-ipgeo-country': 'US', 'x-ipgeo-is-vpn': 'false' }
      })
    );

    expect(forwardedHeader(response, 'x-ipgeo-country')).toBe('SE');
    expect(forwardedHeader(response, 'x-ipgeo-is-vpn')).toBeNull();
  });

  it('removes client supplied geo headers even when no lookup runs', async () => {
    delete process.env.IPGEOLOCATION_API_KEY;

    const evaluation = await evaluateIpGeolocation(
      makeRequest('https://example.com/', {
        ip: '8.8.8.8',
        headers: { 'x-ipgeo-country': 'US' }
      })
    );

    expect(evaluation.requestHeaders.get('x-ipgeo-country')).toBeNull();
  });

  it('forwards the geo headers on a normal request', async () => {
    mockApi(geoFor('SE'));

    const response = await middleware(makeRequest('https://example.com/', { ip: '8.8.8.8' }));

    expect(forwardedHeader(response, 'x-ipgeo-country')).toBe('SE');
    expect(forwardedHeader(response, 'x-ipgeo-city')).toBe('Stockholm');
    expect(forwardedHeader(response, 'x-ipgeo-timezone')).toBe('Europe/Stockholm');
    expect(forwardedHeader(response, 'x-ipgeo-asn-organization')).toBe('Tele2 Sverige AB');
  });

  it('honours a custom header prefix', async () => {
    process.env.IPGEO_HEADER_PREFIX = 'x-acme-geo';
    mockApi(geoFor('SE'));

    const response = await middleware(makeRequest('https://example.com/', { ip: '8.8.8.8' }));

    expect(forwardedHeader(response, 'x-acme-geo-country')).toBe('SE');
  });

  it('adds the geo headers to the response when IPGEO_SET_RESPONSE_HEADERS is on', async () => {
    process.env.IPGEO_SET_RESPONSE_HEADERS = 'true';
    mockApi(geoFor('SE'));

    const response = await middleware(makeRequest('https://example.com/', { ip: '8.8.8.8' }));

    expect(response.headers.get('x-ipgeo-country')).toBe('SE');
  });
});

// -----------------------------------------------------------------------------
// Country rules
// -----------------------------------------------------------------------------

describe('country rules', () => {
  it('blocks a country on the block list', async () => {
    process.env.IPGEO_BLOCKED_COUNTRIES = 'se,ru';
    mockApi(geoFor('SE'));

    const response = await middleware(makeRequest('https://example.com/', { ip: '8.8.8.8' }));

    expect(response.status).toBe(307);
    expect(response.headers.get('location')).toBe('https://example.com/blocked?reason=country');
    expect(response.headers.get('x-ipgeo-block-reason')).toBe('country');
    expect(response.headers.get('cache-control')).toBe('no-store');
  });

  it('allows a country that is not on the block list', async () => {
    process.env.IPGEO_BLOCKED_COUNTRIES = 'RU';
    mockApi(geoFor('SE'));

    const response = await middleware(makeRequest('https://example.com/', { ip: '8.8.8.8' }));

    expect(response.status).toBe(200);
  });

  it('blocks a country that is not on the allow list', async () => {
    process.env.IPGEO_ALLOWED_COUNTRIES = 'US,CA';
    mockApi(geoFor('SE'));

    const response = await middleware(makeRequest('https://example.com/', { ip: '8.8.8.8' }));

    expect(response.status).toBe(307);
  });

  it('allows a country on the allow list', async () => {
    process.env.IPGEO_ALLOWED_COUNTRIES = 'SE';
    mockApi(geoFor('SE'));

    const response = await middleware(makeRequest('https://example.com/', { ip: '8.8.8.8' }));

    expect(response.status).toBe(200);
  });

  it('blocks an unknown country when an allow list is configured', async () => {
    process.env.IPGEO_ALLOWED_COUNTRIES = 'US';
    mockApi({ ip: '8.8.8.8', location: {} });

    const response = await middleware(makeRequest('https://example.com/', { ip: '8.8.8.8' }));

    expect(response.status).toBe(307);
  });

  it('allows an unknown country when IPGEO_ALLOW_UNKNOWN_COUNTRY is on', async () => {
    process.env.IPGEO_ALLOWED_COUNTRIES = 'US';
    process.env.IPGEO_ALLOW_UNKNOWN_COUNTRY = 'true';
    mockApi({ ip: '8.8.8.8', location: {} });

    const response = await middleware(makeRequest('https://example.com/', { ip: '8.8.8.8' }));

    expect(response.status).toBe(200);
  });

  it('leaves the reason out when IPGEO_BLOCK_INCLUDE_REASON is off', async () => {
    process.env.IPGEO_BLOCKED_COUNTRIES = 'SE';
    process.env.IPGEO_BLOCK_INCLUDE_REASON = 'false';
    mockApi(geoFor('SE'));

    const response = await middleware(makeRequest('https://example.com/', { ip: '8.8.8.8' }));

    expect(response.headers.get('location')).toBe('https://example.com/blocked');
  });
});

// -----------------------------------------------------------------------------
// Block modes
// -----------------------------------------------------------------------------

describe('block modes', () => {
  it('answers 403 in deny mode without needing a block page', async () => {
    process.env.IPGEO_BLOCK_MODE = 'deny';
    process.env.IPGEO_BLOCKED_COUNTRIES = 'SE';
    mockApi(geoFor('SE'));

    const response = await middleware(makeRequest('https://example.com/', { ip: '8.8.8.8' }));

    expect(response.status).toBe(403);
    expect(await response.text()).toBe('Access to this site is restricted.');
  });

  it('uses a custom status and message in deny mode', async () => {
    process.env.IPGEO_BLOCK_MODE = 'deny';
    process.env.IPGEO_BLOCK_STATUS = '451';
    process.env.IPGEO_BLOCK_MESSAGE = 'Not available in your region.';
    process.env.IPGEO_BLOCKED_COUNTRIES = 'SE';
    mockApi(geoFor('SE'));

    const response = await middleware(makeRequest('https://example.com/', { ip: '8.8.8.8' }));

    expect(response.status).toBe(451);
    expect(await response.text()).toBe('Not available in your region.');
  });

  it('keeps the visitor URL in rewrite mode', async () => {
    process.env.IPGEO_BLOCK_MODE = 'rewrite';
    process.env.IPGEO_BLOCKED_COUNTRIES = 'SE';
    mockApi(geoFor('SE'));

    const response = await middleware(makeRequest('https://example.com/pricing', { ip: '8.8.8.8' }));

    expect(response.status).toBe(200);
    expect(response.headers.get('x-middleware-rewrite')).toBe(
      'https://example.com/blocked?reason=country'
    );
  });

  it('honours a custom block path', async () => {
    process.env.IPGEO_BLOCK_PATH = '/access-denied';
    process.env.IPGEO_BLOCKED_COUNTRIES = 'SE';
    mockApi(geoFor('SE'));

    const response = await middleware(makeRequest('https://example.com/', { ip: '8.8.8.8' }));

    expect(response.headers.get('location')).toBe(
      'https://example.com/access-denied?reason=country'
    );
  });
});

// -----------------------------------------------------------------------------
// Security rules
// -----------------------------------------------------------------------------

describe('security rules', () => {
  it('does not request the security module when no security rule is on', async () => {
    const fetchMock = mockApi(geoFor('SE'));

    await middleware(makeRequest('https://example.com/', { ip: '8.8.8.8' }));

    expect(String(fetchMock.mock.calls[0]?.[0])).not.toContain('include=');
  });

  it('requests the security module when a security rule is on', async () => {
    process.env.IPGEO_BLOCK_VPN = 'true';
    const fetchMock = mockApi(geoFor('SE', { is_vpn: false }));

    await middleware(makeRequest('https://example.com/', { ip: '8.8.8.8' }));

    expect(String(fetchMock.mock.calls[0]?.[0])).toContain('include=security');
  });

  it('blocks a VPN with the matching reason', async () => {
    process.env.IPGEO_BLOCK_VPN = 'true';
    mockApi(geoFor('SE', { is_vpn: true }));

    const response = await middleware(makeRequest('https://example.com/', { ip: '8.8.8.8' }));

    expect(response.status).toBe(307);
    expect(response.headers.get('location')).toBe('https://example.com/blocked?reason=vpn');
  });

  it('blocks on the threat score threshold', async () => {
    process.env.IPGEO_THREAT_SCORE_BLOCK_THRESHOLD = '75';
    mockApi(geoFor('SE', { threat_score: 80 }));

    const response = await middleware(makeRequest('https://example.com/', { ip: '8.8.8.8' }));

    expect(response.headers.get('location')).toBe('https://example.com/blocked?reason=threat_score');
  });

  it('passes the request through when security data is missing', async () => {
    process.env.IPGEO_BLOCK_VPN = 'true';
    mockApi(geoFor('SE'));

    const response = await middleware(makeRequest('https://example.com/', { ip: '8.8.8.8' }));

    expect(response.status).toBe(200);
  });

  it('blocks when security data is missing and IPGEO_REQUIRE_SECURITY is on', async () => {
    process.env.IPGEO_BLOCK_VPN = 'true';
    process.env.IPGEO_REQUIRE_SECURITY = 'true';
    mockApi(geoFor('SE'));

    const response = await middleware(makeRequest('https://example.com/', { ip: '8.8.8.8' }));

    expect(response.headers.get('location')).toBe(
      'https://example.com/blocked?reason=security_unavailable'
    );
  });
});

// -----------------------------------------------------------------------------
// Country redirects
// -----------------------------------------------------------------------------

describe('country redirects', () => {
  it('redirects to the mapped path', async () => {
    process.env.IPGEO_COUNTRY_REDIRECTS = '{"SE":"/se"}';
    mockApi(geoFor('SE'));

    const response = await middleware(makeRequest('https://example.com/', { ip: '8.8.8.8' }));

    expect(response.status).toBe(307);
    expect(response.headers.get('location')).toBe('https://example.com/se');
  });

  it('keeps the path and the query string', async () => {
    process.env.IPGEO_COUNTRY_REDIRECTS = '{"SE":"/se"}';
    mockApi(geoFor('SE'));

    const response = await middleware(
      makeRequest('https://example.com/pricing?ref=ad', { ip: '8.8.8.8' })
    );

    expect(response.headers.get('location')).toBe('https://example.com/se/pricing?ref=ad');
  });

  it('drops the path when IPGEO_REDIRECT_PRESERVE_PATH is off', async () => {
    process.env.IPGEO_COUNTRY_REDIRECTS = '{"SE":"/se"}';
    process.env.IPGEO_REDIRECT_PRESERVE_PATH = 'false';
    mockApi(geoFor('SE'));

    const response = await middleware(
      makeRequest('https://example.com/pricing?ref=ad', { ip: '8.8.8.8' })
    );

    expect(response.headers.get('location')).toBe('https://example.com/se');
  });

  it('does not redirect a visitor who is already on the target path', async () => {
    process.env.IPGEO_COUNTRY_REDIRECTS = '{"SE":"/se"}';
    mockApi(geoFor('SE'));

    const response = await middleware(makeRequest('https://example.com/se', { ip: '8.8.8.8' }));

    expect(response.status).toBe(200);
  });

  it('does not loop when the configured target has a trailing slash', async () => {
    process.env.IPGEO_COUNTRY_REDIRECTS = '{"SE":"/se/"}';
    mockApi(geoFor('SE'));

    const first = await middleware(makeRequest('https://example.com/', { ip: '8.8.8.8' }));
    expect(first.headers.get('location')).toBe('https://example.com/se');

    const second = await middleware(makeRequest('https://example.com/se', { ip: '8.8.8.8' }));
    expect(second.status).toBe(200);
  });

  it('leaves a visitor alone on another mapped locale', async () => {
    process.env.IPGEO_COUNTRY_REDIRECTS = '{"SE":"/se","US":"/us"}';
    mockApi(geoFor('SE'));

    const response = await middleware(makeRequest('https://example.com/us', { ip: '8.8.8.8' }));

    expect(response.status).toBe(200);
  });

  it('redirects across locales when IPGEO_REDIRECT_RESPECT_EXISTING is off', async () => {
    process.env.IPGEO_COUNTRY_REDIRECTS = '{"SE":"/se","US":"/us"}';
    process.env.IPGEO_REDIRECT_RESPECT_EXISTING = 'false';
    mockApi(geoFor('SE'));

    const response = await middleware(makeRequest('https://example.com/us', { ip: '8.8.8.8' }));

    expect(response.status).toBe(307);
  });

  it('does not redirect a POST request', async () => {
    process.env.IPGEO_COUNTRY_REDIRECTS = '{"SE":"/se"}';
    mockApi(geoFor('SE'));

    const response = await middleware(
      makeRequest('https://example.com/checkout', { ip: '8.8.8.8', method: 'POST' })
    );

    expect(response.status).toBe(200);
  });

  it('skips the redirect when the opt out cookie is present', async () => {
    process.env.IPGEO_COUNTRY_REDIRECTS = '{"SE":"/se"}';
    process.env.IPGEO_REDIRECT_SKIP_COOKIE = 'ipgeo_no_redirect';
    mockApi(geoFor('SE'));

    const response = await middleware(
      makeRequest('https://example.com/', {
        ip: '8.8.8.8',
        headers: { cookie: 'ipgeo_no_redirect=1' }
      })
    );

    expect(response.status).toBe(200);
  });

  it('uses the configured redirect status', async () => {
    process.env.IPGEO_COUNTRY_REDIRECTS = '{"SE":"/se"}';
    process.env.IPGEO_REDIRECT_STATUS = '302';
    mockApi(geoFor('SE'));

    const response = await middleware(makeRequest('https://example.com/', { ip: '8.8.8.8' }));

    expect(response.status).toBe(302);
  });

  it('ignores an off site redirect target', async () => {
    process.env.IPGEO_COUNTRY_REDIRECTS = '{"SE":"https://evil.example"}';
    mockApi(geoFor('SE'));

    const response = await middleware(makeRequest('https://example.com/', { ip: '8.8.8.8' }));

    expect(response.status).toBe(200);
  });
});

// -----------------------------------------------------------------------------
// Failure handling
// -----------------------------------------------------------------------------

describe('failure handling', () => {
  it('passes the request through when the lookup fails', async () => {
    mockApi(null, 500);

    const response = await middleware(makeRequest('https://example.com/', { ip: '8.8.8.8' }));

    expect(response.status).toBe(200);
  });

  it('blocks when the lookup fails and IPGEO_FAIL_CLOSED is on', async () => {
    process.env.IPGEO_FAIL_CLOSED = 'true';
    mockApi(null, 500);

    const response = await middleware(makeRequest('https://example.com/', { ip: '8.8.8.8' }));

    expect(response.status).toBe(307);
    expect(response.headers.get('location')).toBe(
      'https://example.com/blocked?reason=lookup_failed'
    );
  });

  it('does not block a local request in fail closed mode', async () => {
    process.env.IPGEO_FAIL_CLOSED = 'true';
    mockApi(geoFor('SE'));

    const response = await middleware(makeRequest('https://example.com/', { ip: '10.0.0.4' }));

    expect(response.status).toBe(200);
  });

  it('passes the request through when fetch throws', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('network down')));

    const response = await middleware(makeRequest('https://example.com/', { ip: '8.8.8.8' }));

    expect(response.status).toBe(200);
  });
});

// -----------------------------------------------------------------------------
// Composition
// -----------------------------------------------------------------------------

describe('composition', () => {
  it('exposes the evaluation so your own middleware can forward the headers', async () => {
    mockApi(geoFor('SE'));

    const evaluation = await evaluateIpGeolocation(
      makeRequest('https://example.com/', { ip: '8.8.8.8' })
    );

    expect(evaluation.action).toBe('pass');
    expect(evaluation.response).toBeNull();
    expect(evaluation.country).toBe('SE');
    expect(evaluation.requestHeaders.get('x-ipgeo-country')).toBe('SE');
  });

  it('keeps the geo headers when the wrapped handler passes the request on', async () => {
    mockApi(geoFor('SE'));

    const composed = withIpGeolocation(async (_request, geo) =>
      NextResponse.next({ request: { headers: geo.requestHeaders } })
    );

    const response = await composed(makeRequest('https://example.com/', { ip: '8.8.8.8' }));

    expect(forwardedHeader(response as NextResponse, 'x-ipgeo-country')).toBe('SE');
  });

  it('does not call the wrapped handler when the request is blocked', async () => {
    process.env.IPGEO_BLOCKED_COUNTRIES = 'SE';
    mockApi(geoFor('SE'));

    const handler = vi.fn().mockResolvedValue(NextResponse.next());
    const composed = withIpGeolocation(handler);

    const response = await composed(makeRequest('https://example.com/', { ip: '8.8.8.8' }));

    expect(handler).not.toHaveBeenCalled();
    expect(response.status).toBe(307);
  });

  it('accepts configuration overrides in code', async () => {
    mockApi(geoFor('SE'));

    const evaluation = await evaluateIpGeolocation(
      makeRequest('https://example.com/', { ip: '8.8.8.8' }),
      { blockedCountries: new Set(['SE']) }
    );

    expect(evaluation.action).toBe('block');
    expect(evaluation.reason).toBe('country');
  });

  it('exports proxy as an alias for Next.js 16', async () => {
    mockApi(geoFor('SE'));

    const response = await proxy(makeRequest('https://example.com/', { ip: '8.8.8.8' }));

    expect(response.status).toBe(200);
    expect(forwardedHeader(response, 'x-ipgeo-country')).toBe('SE');
  });
});
