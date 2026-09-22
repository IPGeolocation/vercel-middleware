// =============================================================================
// Tests for ipgeolocation-edge.ts
// Run with: npm test
// =============================================================================

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  buildGeoHeaders,
  envFlag,
  envNumber,
  getClientIp,
  getIpGeoRuntimeState,
  getSecurityRulesFromEnv,
  isPublicIp,
  isUnderPath,
  lookupIpGeolocation,
  lookupIpGeolocationResult,
  normalizeInternalPath,
  normalizeIp,
  parseCsvEnv,
  parseList,
  parseRedirectMap,
  resetIpGeoRuntimeState,
  securityRulesEnabled,
  shouldBlockBySecurity,
  stripSpoofedGeoHeaders,
  type IpGeoResponse,
  type IpGeoSecurity,
  type SecurityRules
} from './ipgeolocation-edge.js';

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

const IPGEO_KEYS = [
  'IPGEOLOCATION_API_KEY',
  'IPGEO_ALLOWED_COUNTRIES',
  'IPGEO_ALLOW_KNOWN_GOOD_BOTS',
  'IPGEO_BLOCKED_COUNTRIES',
  'IPGEO_BLOCK_ANONYMOUS',
  'IPGEO_BLOCK_BOT',
  'IPGEO_BLOCK_CLOUD_PROVIDER',
  'IPGEO_BLOCK_KNOWN_ATTACKER',
  'IPGEO_BLOCK_PROXY',
  'IPGEO_BLOCK_RELAY',
  'IPGEO_BLOCK_RESIDENTIAL_PROXY',
  'IPGEO_BLOCK_SPAM',
  'IPGEO_BLOCK_TOR',
  'IPGEO_BLOCK_VPN',
  'IPGEO_CACHE_MAX_ENTRIES',
  'IPGEO_CACHE_TTL_MS',
  'IPGEO_CIRCUIT_COOLDOWN_MS',
  'IPGEO_CIRCUIT_FAILURE_THRESHOLD',
  'IPGEO_COUNTRY_REDIRECTS',
  'IPGEO_LOG_LEVEL',
  'IPGEO_RETRIES',
  'IPGEO_THREAT_SCORE_BLOCK_THRESHOLD',
  'IPGEO_TIMEOUT_MS'
];

function clearIpGeoEnv(): void {
  for (const key of IPGEO_KEYS) delete process.env[key];
}

function makeHeaders(entries: Record<string, string>): Headers {
  const headers = new Headers();
  for (const [key, value] of Object.entries(entries)) headers.set(key, value);
  return headers;
}

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
    ...init
  });
}

const SAMPLE: IpGeoResponse = {
  ip: '91.128.103.196',
  location: {
    continent_code: 'EU',
    country_code2: 'SE',
    country_name: 'Sweden',
    state_prov: 'Stockholms',
    state_code: 'SE-AB',
    city: 'Stockholm',
    zipcode: '164 40',
    latitude: '59.40510',
    longitude: '17.95510',
    is_eu: true
  },
  currency: { code: 'SEK' },
  asn: { as_number: 'AS1257', organization: 'Tele2 Sverige AB' },
  company: { name: 'Tele2 Sverige AB' },
  time_zone: { name: 'Europe/Stockholm' }
};

beforeEach(() => {
  clearIpGeoEnv();
  process.env.IPGEO_LOG_LEVEL = 'silent';
  resetIpGeoRuntimeState();
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  clearIpGeoEnv();
});

// -----------------------------------------------------------------------------
// envFlag
// -----------------------------------------------------------------------------

describe('envFlag', () => {
  it.each(['true', 'TRUE', 'True', '1', 'yes', 'on'])('reads %s as true', (value) => {
    expect(envFlag(value)).toBe(true);
  });

  it.each(['false', '0', 'no', 'off', ''])('reads %s as false', (value) => {
    expect(envFlag(value)).toBe(false);
  });

  it('returns the fallback for undefined', () => {
    expect(envFlag(undefined)).toBe(false);
    expect(envFlag(undefined, true)).toBe(true);
  });

  it('returns the fallback for an unrecognised value', () => {
    expect(envFlag('maybe', true)).toBe(true);
  });
});

// -----------------------------------------------------------------------------
// envNumber
// -----------------------------------------------------------------------------

describe('envNumber', () => {
  it('parses a numeric string', () => {
    expect(envNumber('250', 100)).toBe(250);
  });

  it('falls back for an empty or missing value', () => {
    expect(envNumber(undefined, 42)).toBe(42);
    expect(envNumber('   ', 42)).toBe(42);
  });

  it('falls back for a value that is not a number', () => {
    expect(envNumber('soon', 42)).toBe(42);
  });

  it('clamps to the range', () => {
    expect(envNumber('500', 10, { max: 100 })).toBe(100);
    expect(envNumber('-5', 10, { min: 0 })).toBe(0);
  });
});

// -----------------------------------------------------------------------------
// parseCsvEnv and parseList
// -----------------------------------------------------------------------------

describe('parseCsvEnv', () => {
  it('parses, trims and uppercases country codes', () => {
    expect(parseCsvEnv(' us , ca ,gb ')).toEqual(new Set(['US', 'CA', 'GB']));
  });

  it('drops empty segments', () => {
    expect(parseCsvEnv('US,,CA,')).toEqual(new Set(['US', 'CA']));
  });

  it('drops values that are not two letter codes', () => {
    expect(parseCsvEnv('US,USA,1,GB')).toEqual(new Set(['US', 'GB']));
  });

  it('returns an empty set for undefined', () => {
    expect(parseCsvEnv(undefined)).toEqual(new Set());
  });
});

describe('parseList', () => {
  it('splits and trims', () => {
    expect(parseList(' /health , /status ')).toEqual(['/health', '/status']);
  });

  it('returns an empty array for undefined', () => {
    expect(parseList(undefined)).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// normalizeInternalPath and isUnderPath
// -----------------------------------------------------------------------------

describe('normalizeInternalPath', () => {
  it('keeps a simple path', () => {
    expect(normalizeInternalPath('/uk')).toBe('/uk');
  });

  it('removes a trailing slash, which is what caused redirect loops in 1.x', () => {
    expect(normalizeInternalPath('/uk/')).toBe('/uk');
  });

  it('keeps the root path', () => {
    expect(normalizeInternalPath('/')).toBe('/');
  });

  it('rejects absolute URLs', () => {
    expect(normalizeInternalPath('https://example.com/uk')).toBeNull();
  });

  it('rejects protocol relative values', () => {
    expect(normalizeInternalPath('//evil.example')).toBeNull();
  });

  it('rejects backslash variants', () => {
    expect(normalizeInternalPath('/\\evil.example')).toBeNull();
  });

  it('rejects values without a leading slash', () => {
    expect(normalizeInternalPath('uk')).toBeNull();
  });
});

describe('isUnderPath', () => {
  it('matches the path itself', () => {
    expect(isUnderPath('/blocked', '/blocked')).toBe(true);
  });

  it('matches a child path', () => {
    expect(isUnderPath('/blocked/details', '/blocked')).toBe(true);
  });

  it('does not match a path that only shares a prefix', () => {
    expect(isUnderPath('/blockedlist', '/blocked')).toBe(false);
  });
});

// -----------------------------------------------------------------------------
// parseRedirectMap
// -----------------------------------------------------------------------------

describe('parseRedirectMap', () => {
  it('parses and uppercases the keys', () => {
    expect(parseRedirectMap('{"us":"/us","gb":"/uk"}')).toEqual({ US: '/us', GB: '/uk' });
  });

  it('normalizes trailing slashes in targets', () => {
    expect(parseRedirectMap('{"GB":"/uk/"}')).toEqual({ GB: '/uk' });
  });

  it('returns an empty object for invalid JSON', () => {
    expect(parseRedirectMap('{oops')).toEqual({});
  });

  it('returns an empty object for an empty value', () => {
    expect(parseRedirectMap('')).toEqual({});
    expect(parseRedirectMap('{}')).toEqual({});
    expect(parseRedirectMap(undefined)).toEqual({});
  });

  it('returns an empty object for a JSON array', () => {
    expect(parseRedirectMap('["/uk"]')).toEqual({});
  });

  it('drops off site targets so the map cannot become an open redirect', () => {
    expect(parseRedirectMap('{"GB":"https://evil.example"}')).toEqual({});
    expect(parseRedirectMap('{"GB":"//evil.example"}')).toEqual({});
  });

  it('drops keys that are not country codes', () => {
    expect(parseRedirectMap('{"EUROPE":"/eu","GB":"/uk"}')).toEqual({ GB: '/uk' });
  });
});

// -----------------------------------------------------------------------------
// normalizeIp and isPublicIp
// -----------------------------------------------------------------------------

describe('normalizeIp', () => {
  it('accepts a plain IPv4 address', () => {
    expect(normalizeIp('203.0.113.10')).toBe('203.0.113.10');
  });

  it('strips a port from an IPv4 address', () => {
    expect(normalizeIp('203.0.113.10:51234')).toBe('203.0.113.10');
  });

  it('unwraps a bracketed IPv6 address with a port', () => {
    expect(normalizeIp('[2001:4860:4860::8888]:443')).toBe('2001:4860:4860::8888');
  });

  it('unwraps an IPv4 mapped IPv6 address', () => {
    expect(normalizeIp('::ffff:8.8.8.8')).toBe('8.8.8.8');
  });

  it('removes an IPv6 zone index', () => {
    expect(normalizeIp('fe80::1%eth0')).toBe('fe80::1');
  });

  it('strips surrounding quotes', () => {
    expect(normalizeIp('"8.8.8.8"')).toBe('8.8.8.8');
  });

  it('rejects malformed values', () => {
    expect(normalizeIp('999.1.1.1')).toBeNull();
    expect(normalizeIp('not-an-ip')).toBeNull();
    expect(normalizeIp('')).toBeNull();
    expect(normalizeIp(undefined)).toBeNull();
  });
});

describe('isPublicIp', () => {
  it.each(['8.8.8.8', '91.128.103.196', '2001:4860:4860::8888'])('accepts %s', (ip) => {
    expect(isPublicIp(ip)).toBe(true);
  });

  it.each([
    '127.0.0.1',
    '10.0.0.5',
    '172.16.0.1',
    '192.168.1.1',
    '169.254.1.1',
    '100.64.0.1',
    '0.0.0.0',
    '224.0.0.1',
    '::1',
    'fe80::1',
    'fd00::1'
  ])('rejects %s', (ip) => {
    expect(isPublicIp(ip)).toBe(false);
  });
});

// -----------------------------------------------------------------------------
// getClientIp
// -----------------------------------------------------------------------------

describe('getClientIp', () => {
  it('reads a single x-forwarded-for entry', () => {
    expect(getClientIp(makeHeaders({ 'x-forwarded-for': '8.8.8.8' }))).toBe('8.8.8.8');
  });

  it('reads the rightmost entry by default', () => {
    const headers = makeHeaders({ 'x-forwarded-for': '1.1.1.1, 9.9.9.9' });
    expect(getClientIp(headers)).toBe('9.9.9.9');
  });

  it('reads the leftmost entry when trustFirstXff is set', () => {
    const headers = makeHeaders({ 'x-forwarded-for': '1.1.1.1, 9.9.9.9' });
    expect(getClientIp(headers, { trustFirstXff: true })).toBe('1.1.1.1');
  });

  it('accepts a boolean for compatibility with 1.x', () => {
    const headers = makeHeaders({ 'x-forwarded-for': '1.1.1.1, 9.9.9.9' });
    expect(getClientIp(headers, true)).toBe('1.1.1.1');
  });

  it('skips the proxies you control when trustedProxyCount is set', () => {
    const headers = makeHeaders({ 'x-forwarded-for': '8.8.8.8, 9.9.9.9, 1.1.1.1' });
    expect(getClientIp(headers, { trustedProxyCount: 1 })).toBe('9.9.9.9');
  });

  it('prefers x-vercel-forwarded-for when a proxy sits in front of Vercel', () => {
    const headers = makeHeaders({
      'x-vercel-forwarded-for': '8.8.8.8',
      'x-forwarded-for': '203.0.113.9'
    });
    expect(getClientIp(headers)).toBe('8.8.8.8');
  });

  it('falls back to x-real-ip', () => {
    expect(getClientIp(makeHeaders({ 'x-real-ip': '8.8.4.4' }))).toBe('8.8.4.4');
  });

  it('falls back to cf-connecting-ip', () => {
    expect(getClientIp(makeHeaders({ 'cf-connecting-ip': '8.8.4.4' }))).toBe('8.8.4.4');
  });

  it('returns null when no header carries an IP', () => {
    expect(getClientIp(makeHeaders({}))).toBeNull();
  });

  it('returns null for a private address, which is what happens locally', () => {
    expect(getClientIp(makeHeaders({ 'x-forwarded-for': '127.0.0.1' }))).toBeNull();
  });

  it('returns a private address when allowPrivate is set', () => {
    const headers = makeHeaders({ 'x-forwarded-for': '127.0.0.1' });
    expect(getClientIp(headers, { allowPrivate: true })).toBe('127.0.0.1');
  });

  it('ignores a garbage value and moves to the next header', () => {
    const headers = makeHeaders({ 'x-forwarded-for': 'unknown', 'x-real-ip': '8.8.8.8' });
    expect(getClientIp(headers)).toBe('8.8.8.8');
  });

  it('normalizes a port suffix', () => {
    expect(getClientIp(makeHeaders({ 'x-forwarded-for': '8.8.8.8:1234' }))).toBe('8.8.8.8');
  });
});

// -----------------------------------------------------------------------------
// Security rules
// -----------------------------------------------------------------------------

function rules(overrides: Partial<SecurityRules> = {}): SecurityRules {
  return {
    blockVpn: false,
    blockProxy: false,
    blockResidentialProxy: false,
    blockTor: false,
    blockRelay: false,
    blockCloudProvider: false,
    blockBot: false,
    blockSpam: false,
    blockKnownAttacker: false,
    blockAnonymous: false,
    allowKnownGoodBots: true,
    threatScoreThreshold: 0,
    ...overrides
  };
}

describe('getSecurityRulesFromEnv', () => {
  it('defaults every block rule to off', () => {
    const parsed = getSecurityRulesFromEnv();
    expect(securityRulesEnabled(parsed)).toBe(false);
    expect(parsed.blockTor).toBe(false);
  });

  it('reads the flags from the environment', () => {
    process.env.IPGEO_BLOCK_TOR = 'true';
    process.env.IPGEO_THREAT_SCORE_BLOCK_THRESHOLD = '75';

    const parsed = getSecurityRulesFromEnv();
    expect(parsed.blockTor).toBe(true);
    expect(parsed.threatScoreThreshold).toBe(75);
    expect(securityRulesEnabled(parsed)).toBe(true);
  });

  it('clamps the threat score threshold to 0 through 100', () => {
    process.env.IPGEO_THREAT_SCORE_BLOCK_THRESHOLD = '500';
    expect(getSecurityRulesFromEnv().threatScoreThreshold).toBe(100);
  });

  it('keeps known good bots by default', () => {
    expect(getSecurityRulesFromEnv().allowKnownGoodBots).toBe(true);
  });
});

describe('shouldBlockBySecurity', () => {
  const security: IpGeoSecurity = {
    threat_score: 80,
    is_vpn: true,
    is_proxy: true,
    is_tor: true,
    is_bot: true,
    is_spam: true,
    is_known_attacker: true,
    is_cloud_provider: true,
    is_relay: true,
    is_anonymous: true,
    is_residential_proxy: true
  };

  it('returns null when no rule is active', () => {
    expect(shouldBlockBySecurity(security, rules())).toBeNull();
  });

  it('returns null when there is no security object', () => {
    expect(shouldBlockBySecurity(undefined, rules({ blockVpn: true }))).toBeNull();
  });

  it.each([
    ['blockVpn', 'vpn'],
    ['blockProxy', 'proxy'],
    ['blockResidentialProxy', 'residential_proxy'],
    ['blockTor', 'tor'],
    ['blockRelay', 'relay'],
    ['blockCloudProvider', 'cloud_provider'],
    ['blockBot', 'bot'],
    ['blockSpam', 'spam'],
    ['blockKnownAttacker', 'known_attacker'],
    ['blockAnonymous', 'anonymous']
  ] as const)('%s produces the reason %s', (rule, reason) => {
    expect(shouldBlockBySecurity(security, rules({ [rule]: true }))).toBe(reason);
  });

  it('blocks at or above the threat score threshold', () => {
    expect(shouldBlockBySecurity({ threat_score: 75 }, rules({ threatScoreThreshold: 75 }))).toBe(
      'threat_score'
    );
    expect(shouldBlockBySecurity({ threat_score: 74 }, rules({ threatScoreThreshold: 75 }))).toBeNull();
  });

  it('keeps a known good bot when bots are blocked', () => {
    const goodBot: IpGeoSecurity = { is_bot: true, is_known_good_bot: true };
    expect(shouldBlockBySecurity(goodBot, rules({ blockBot: true }))).toBeNull();
  });

  it('blocks a known good bot when allowKnownGoodBots is off', () => {
    const goodBot: IpGeoSecurity = { is_bot: true, is_known_good_bot: true };
    expect(shouldBlockBySecurity(goodBot, rules({ blockBot: true, allowKnownGoodBots: false }))).toBe(
      'bot'
    );
  });

  it('reads the rules from the environment when none are passed', () => {
    process.env.IPGEO_BLOCK_TOR = 'true';
    expect(shouldBlockBySecurity({ is_tor: true })).toBe('tor');
  });
});

// -----------------------------------------------------------------------------
// Header helpers
// -----------------------------------------------------------------------------

describe('buildGeoHeaders', () => {
  it('maps the response onto prefixed headers', () => {
    const headers = buildGeoHeaders(SAMPLE, '91.128.103.196');

    expect(headers['x-ipgeo-country']).toBe('SE');
    expect(headers['x-ipgeo-country-name']).toBe('Sweden');
    expect(headers['x-ipgeo-city']).toBe('Stockholm');
    expect(headers['x-ipgeo-timezone']).toBe('Europe/Stockholm');
    expect(headers['x-ipgeo-asn']).toBe('AS1257');
    expect(headers['x-ipgeo-is-eu']).toBe('true');
    expect(headers['x-ipgeo-currency']).toBe('SEK');
  });

  it('omits values the API did not return', () => {
    const headers = buildGeoHeaders({ ip: '8.8.8.8' }, '8.8.8.8');
    expect(headers['x-ipgeo-city']).toBeUndefined();
    expect(headers['x-ipgeo-threat-score']).toBeUndefined();
  });

  it('includes the security flags when the module was requested', () => {
    const withSecurity: IpGeoResponse = {
      ...SAMPLE,
      security: { threat_score: 80, is_vpn: true, is_tor: false }
    };

    const headers = buildGeoHeaders(withSecurity, '91.128.103.196');
    expect(headers['x-ipgeo-threat-score']).toBe('80');
    expect(headers['x-ipgeo-is-vpn']).toBe('true');
    expect(headers['x-ipgeo-is-tor']).toBe('false');
  });

  it('honours a custom prefix', () => {
    const headers = buildGeoHeaders(SAMPLE, '91.128.103.196', 'x-acme-geo');
    expect(headers['x-acme-geo-country']).toBe('SE');
  });

  it('falls back to the supplied IP when the response has none', () => {
    const headers = buildGeoHeaders(null, '8.8.8.8');
    expect(headers['x-ipgeo-ip']).toBe('8.8.8.8');
  });
});

describe('stripSpoofedGeoHeaders', () => {
  it('removes client supplied geo headers', () => {
    const headers = makeHeaders({
      'x-ipgeo-country': 'US',
      'x-ipgeo-is-vpn': 'false',
      'user-agent': 'test'
    });

    stripSpoofedGeoHeaders(headers);

    expect(headers.get('x-ipgeo-country')).toBeNull();
    expect(headers.get('x-ipgeo-is-vpn')).toBeNull();
    expect(headers.get('user-agent')).toBe('test');
  });

  it('respects a custom prefix', () => {
    const headers = makeHeaders({ 'x-acme-geo-country': 'US', 'x-ipgeo-country': 'US' });
    stripSpoofedGeoHeaders(headers, 'x-acme-geo');

    expect(headers.get('x-acme-geo-country')).toBeNull();
    expect(headers.get('x-ipgeo-country')).toBe('US');
  });
});

// -----------------------------------------------------------------------------
// lookupIpGeolocation
// -----------------------------------------------------------------------------

describe('lookupIpGeolocation', () => {
  it('returns the parsed response', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(SAMPLE));
    vi.stubGlobal('fetch', fetchMock);

    const result = await lookupIpGeolocation({ apiKey: 'key', ip: '91.128.103.196' });

    expect(result?.location?.country_code2).toBe('SE');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('does not request the security module unless it is asked for', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(SAMPLE));
    vi.stubGlobal('fetch', fetchMock);

    await lookupIpGeolocation({ apiKey: 'key', ip: '91.128.103.196' });

    const url = String(fetchMock.mock.calls[0]?.[0]);
    expect(url).not.toContain('include=');
  });

  it('requests the security module when includeSecurity is set', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(SAMPLE));
    vi.stubGlobal('fetch', fetchMock);

    await lookupIpGeolocation({ apiKey: 'key', ip: '91.128.103.196', includeSecurity: true });

    const url = String(fetchMock.mock.calls[0]?.[0]);
    expect(url).toContain('include=security');
  });

  it('sends the API key and the IP as query parameters', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(SAMPLE));
    vi.stubGlobal('fetch', fetchMock);

    await lookupIpGeolocation({ apiKey: 'abc123', ip: '8.8.8.8' });

    const url = new URL(String(fetchMock.mock.calls[0]?.[0]));
    expect(url.origin + url.pathname).toBe('https://api.ipgeolocation.io/v3/ipgeo');
    expect(url.searchParams.get('apiKey')).toBe('abc123');
    expect(url.searchParams.get('ip')).toBe('8.8.8.8');
  });

  it('returns null without calling the API when the key is missing', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    expect(await lookupIpGeolocation({ apiKey: '', ip: '8.8.8.8' })).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('returns null without calling the API for a private address', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    expect(await lookupIpGeolocation({ apiKey: 'key', ip: '127.0.0.1' })).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('returns null without calling the API for a malformed address', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    expect(await lookupIpGeolocation({ apiKey: 'key', ip: 'nope' })).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('caches by IP for the configured lifetime', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(SAMPLE));
    vi.stubGlobal('fetch', fetchMock);

    await lookupIpGeolocation({ apiKey: 'key', ip: '8.8.8.8' });
    await lookupIpGeolocation({ apiKey: 'key', ip: '8.8.8.8' });

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('keeps separate cache entries per module set', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(SAMPLE));
    vi.stubGlobal('fetch', fetchMock);

    await lookupIpGeolocation({ apiKey: 'key', ip: '8.8.8.8' });
    await lookupIpGeolocation({ apiKey: 'key', ip: '8.8.8.8', includeSecurity: true });

    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('bypasses the cache when IPGEO_CACHE_TTL_MS is 0', async () => {
    process.env.IPGEO_CACHE_TTL_MS = '0';

    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(SAMPLE));
    vi.stubGlobal('fetch', fetchMock);

    await lookupIpGeolocation({ apiKey: 'key', ip: '8.8.8.8' });
    await lookupIpGeolocation({ apiKey: 'key', ip: '8.8.8.8' });

    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('shares one request between concurrent lookups for the same IP', async () => {
    const fetchMock = vi.fn().mockImplementation(
      () => new Promise((resolve) => setTimeout(() => resolve(jsonResponse(SAMPLE)), 20))
    );
    vi.stubGlobal('fetch', fetchMock);

    const [first, second] = await Promise.all([
      lookupIpGeolocation({ apiKey: 'key', ip: '8.8.8.8' }),
      lookupIpGeolocation({ apiKey: 'key', ip: '8.8.8.8' })
    ]);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(first?.location?.country_code2).toBe('SE');
    expect(second?.location?.country_code2).toBe('SE');
  });

  it('evicts the oldest entry when the cache is full', async () => {
    process.env.IPGEO_CACHE_MAX_ENTRIES = '2';

    const fetchMock = vi.fn().mockImplementation(async () => jsonResponse(SAMPLE));
    vi.stubGlobal('fetch', fetchMock);

    await lookupIpGeolocation({ apiKey: 'key', ip: '8.8.8.8' });
    await lookupIpGeolocation({ apiKey: 'key', ip: '8.8.4.4' });
    await lookupIpGeolocation({ apiKey: 'key', ip: '1.1.1.1' });

    expect(getIpGeoRuntimeState().cacheSize).toBe(2);
  });

  it('returns null on a 4xx response', async () => {
    process.env.IPGEO_RETRIES = '0';

    const fetchMock = vi.fn().mockResolvedValue(new Response('bad request', { status: 400 }));
    vi.stubGlobal('fetch', fetchMock);

    expect(await lookupIpGeolocation({ apiKey: 'key', ip: '8.8.8.8' })).toBeNull();
  });

  it('returns null and does not cache when the response is not JSON', async () => {
    process.env.IPGEO_RETRIES = '0';

    const fetchMock = vi
      .fn()
      .mockResolvedValue(new Response('<html>maintenance</html>', { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    expect(await lookupIpGeolocation({ apiKey: 'key', ip: '8.8.8.8' })).toBeNull();
    expect(getIpGeoRuntimeState().cacheSize).toBe(0);
  });

  it('returns null when the request times out', async () => {
    process.env.IPGEO_RETRIES = '0';

    const abortError = new Error('The operation was aborted.');
    abortError.name = 'AbortError';

    const fetchMock = vi.fn().mockRejectedValue(abortError);
    vi.stubGlobal('fetch', fetchMock);

    const result = await lookupIpGeolocation({ apiKey: 'key', ip: '8.8.8.8', timeoutMs: 250 });
    expect(result).toBeNull();
  });
});

describe('lookupIpGeolocationResult', () => {
  it('reports the failure reason and status', async () => {
    process.env.IPGEO_RETRIES = '0';

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('nope', { status: 429 })));

    const result = await lookupIpGeolocationResult({ apiKey: 'key', ip: '8.8.8.8' });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('rate_limited');
      expect(result.status).toBe(429);
    }
  });

  it('reports a private address without calling the API', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    const result = await lookupIpGeolocationResult({ apiKey: 'key', ip: '10.0.0.1' });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('private_ip');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('reports the credits charged for the request', async () => {
    const response = jsonResponse(SAMPLE, {
      headers: { 'content-type': 'application/json', 'x-credits-charged': '3' }
    });

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response));

    const result = await lookupIpGeolocationResult({
      apiKey: 'key',
      ip: '8.8.8.8',
      includeSecurity: true
    });

    expect(result.ok).toBe(true);
    if (result.ok) expect(result.creditsCharged).toBe(3);
  });

  it('marks a cached response as cached', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse(SAMPLE)));

    await lookupIpGeolocationResult({ apiKey: 'key', ip: '8.8.8.8' });
    const second = await lookupIpGeolocationResult({ apiKey: 'key', ip: '8.8.8.8' });

    expect(second.ok).toBe(true);
    if (second.ok) expect(second.cached).toBe(true);
  });

  it('retries a 5xx response once by default', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response('server error', { status: 503 }))
      .mockResolvedValueOnce(jsonResponse(SAMPLE));

    vi.stubGlobal('fetch', fetchMock);

    const result = await lookupIpGeolocationResult({ apiKey: 'key', ip: '8.8.8.8' });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(result.ok).toBe(true);
  });

  it('does not retry a 4xx response', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('bad key', { status: 403 }));
    vi.stubGlobal('fetch', fetchMock);

    await lookupIpGeolocationResult({ apiKey: 'key', ip: '8.8.8.8' });

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('retries without the security module when a free plan key rejects it', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response('security requires a paid plan', { status: 401 }))
      .mockResolvedValueOnce(jsonResponse(SAMPLE));

    vi.stubGlobal('fetch', fetchMock);

    const result = await lookupIpGeolocationResult({
      apiKey: 'free-key',
      ip: '8.8.8.8',
      includeSecurity: true
    });

    expect(result.ok).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);

    expect(String(fetchMock.mock.calls[0]?.[0])).toContain('include=security');
    expect(String(fetchMock.mock.calls[1]?.[0])).not.toContain('include=security');
  });

  it('stops asking for the security module after it was rejected', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response('security requires a paid plan', { status: 401 }))
      .mockResolvedValue(jsonResponse(SAMPLE));

    vi.stubGlobal('fetch', fetchMock);

    await lookupIpGeolocationResult({ apiKey: 'free-key', ip: '8.8.8.8', includeSecurity: true });
    await lookupIpGeolocationResult({ apiKey: 'free-key', ip: '1.1.1.1', includeSecurity: true });

    expect(getIpGeoRuntimeState().securityModuleAvailable).toBe(false);
    expect(String(fetchMock.mock.calls[2]?.[0])).not.toContain('include=security');
  });

  it('opens the circuit after repeated failures and stops calling the API', async () => {
    process.env.IPGEO_RETRIES = '0';
    process.env.IPGEO_CIRCUIT_FAILURE_THRESHOLD = '3';
    process.env.IPGEO_CIRCUIT_COOLDOWN_MS = '10000';

    const fetchMock = vi.fn().mockResolvedValue(new Response('boom', { status: 500 }));
    vi.stubGlobal('fetch', fetchMock);

    await lookupIpGeolocationResult({ apiKey: 'key', ip: '8.8.8.1' });
    await lookupIpGeolocationResult({ apiKey: 'key', ip: '8.8.8.2' });
    await lookupIpGeolocationResult({ apiKey: 'key', ip: '8.8.8.3' });

    expect(getIpGeoRuntimeState().circuitOpen).toBe(true);

    const blocked = await lookupIpGeolocationResult({ apiKey: 'key', ip: '8.8.8.4' });

    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(blocked.ok).toBe(false);
    if (!blocked.ok) expect(blocked.reason).toBe('circuit_open');
  });

  it('closes the circuit again after a success', async () => {
    process.env.IPGEO_RETRIES = '0';
    process.env.IPGEO_CIRCUIT_FAILURE_THRESHOLD = '2';

    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response('boom', { status: 500 }))
      .mockResolvedValueOnce(jsonResponse(SAMPLE));

    vi.stubGlobal('fetch', fetchMock);

    await lookupIpGeolocationResult({ apiKey: 'key', ip: '8.8.8.1' });
    await lookupIpGeolocationResult({ apiKey: 'key', ip: '8.8.8.2' });

    expect(getIpGeoRuntimeState().consecutiveFailures).toBe(0);
    expect(getIpGeoRuntimeState().circuitOpen).toBe(false);
  });
});
