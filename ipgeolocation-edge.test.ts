// ─────────────────────────────────────────────────────────────────────────────
// Tests for src/lib/ipgeolocation-edge.ts
// Run: npm test
// ─────────────────────────────────────────────────────────────────────────────

import { beforeEach, afterEach, describe, it, expect, vi } from 'vitest';
import {
  envFlag,
  parseCsvEnv,
  parseRedirectMap,
  getClientIp,
  shouldBlockBySecurity,
  lookupIpGeolocation,
  type IpGeoSecurity,
  type IpGeoResponse
} from './ipgeolocation-edge.js';

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function makeHeaders(entries: Record<string, string>): Headers {
  const h = new Headers();
  for (const [k, v] of Object.entries(entries)) h.set(k, v);
  return h;
}

function setEnv(vars: Record<string, string | undefined>) {
  for (const [k, v] of Object.entries(vars)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// envFlag
// ─────────────────────────────────────────────────────────────────────────────

describe('envFlag', () => {
  it('returns true for "true"', () => expect(envFlag('true')).toBe(true));
  it('returns true for "TRUE"', () => expect(envFlag('TRUE')).toBe(true));
  it('returns true for "True"', () => expect(envFlag('True')).toBe(true));
  it('returns false for "false"', () => expect(envFlag('false')).toBe(false));
  it('returns false for "1"', () => expect(envFlag('1')).toBe(false));
  it('returns false for empty string', () => expect(envFlag('')).toBe(false));
  it('returns false for undefined', () => expect(envFlag(undefined)).toBe(false));
});

// ─────────────────────────────────────────────────────────────────────────────
// parseCsvEnv
// ─────────────────────────────────────────────────────────────────────────────

describe('parseCsvEnv', () => {
  it('parses a single value', () => {
    expect(parseCsvEnv('US')).toEqual(new Set(['US']));
  });

  it('parses multiple values', () => {
    expect(parseCsvEnv('US,CA,GB')).toEqual(new Set(['US', 'CA', 'GB']));
  });

  it('uppercases values', () => {
    expect(parseCsvEnv('us,ca')).toEqual(new Set(['US', 'CA']));
  });

  it('trims whitespace', () => {
    expect(parseCsvEnv(' US , CA , GB ')).toEqual(new Set(['US', 'CA', 'GB']));
  });

  it('filters empty segments', () => {
    expect(parseCsvEnv('US,,CA,')).toEqual(new Set(['US', 'CA']));
  });

  it('returns empty Set for undefined', () => {
    expect(parseCsvEnv(undefined)).toEqual(new Set());
  });

  it('returns empty Set for empty string', () => {
    expect(parseCsvEnv('')).toEqual(new Set());
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// parseRedirectMap
// ─────────────────────────────────────────────────────────────────────────────

describe('parseRedirectMap', () => {
  it('parses valid JSON', () => {
    expect(parseRedirectMap('{"US":"/us","GB":"/uk"}')).toEqual({
      US: '/us',
      GB: '/uk'
    });
  });

  it('uppercases country keys', () => {
    expect(parseRedirectMap('{"us":"/us","pk":"/pk"}')).toEqual({
      US: '/us',
      PK: '/pk'
    });
  });

  it('returns empty object for undefined', () => {
    expect(parseRedirectMap(undefined)).toEqual({});
  });

  it('returns empty object for empty string', () => {
    expect(parseRedirectMap('')).toEqual({});
  });

  it('returns empty object and warns on invalid JSON', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    expect(parseRedirectMap('not-json')).toEqual({});
    expect(warn).toHaveBeenCalledOnce();
    warn.mockRestore();
  });

  it('includes the bad value in the warning', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    parseRedirectMap('bad-value');
    expect(warn.mock.calls[0]?.[1]).toContain('bad-value');
    warn.mockRestore();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// getClientIp
// ─────────────────────────────────────────────────────────────────────────────

describe('getClientIp', () => {
  it('returns last IP from x-forwarded-for by default (Vercel-safe)', () => {
    const headers = makeHeaders({ 'x-forwarded-for': '1.2.3.4, 5.6.7.8, 9.10.11.12' });
    expect(getClientIp(headers)).toBe('9.10.11.12');
  });

  it('returns first IP from x-forwarded-for when trustFirstXff=true', () => {
    const headers = makeHeaders({ 'x-forwarded-for': '1.2.3.4, 5.6.7.8' });
    expect(getClientIp(headers, true)).toBe('1.2.3.4');
  });

  it('handles single IP in x-forwarded-for', () => {
    const headers = makeHeaders({ 'x-forwarded-for': '1.2.3.4' });
    expect(getClientIp(headers)).toBe('1.2.3.4');
  });

  it('trims whitespace around IPs', () => {
    const headers = makeHeaders({ 'x-forwarded-for': '  1.2.3.4  ,  5.6.7.8  ' });
    expect(getClientIp(headers)).toBe('5.6.7.8');
  });

  it('falls back to x-real-ip', () => {
    const headers = makeHeaders({ 'x-real-ip': '1.2.3.4' });
    expect(getClientIp(headers)).toBe('1.2.3.4');
  });

  it('falls back to cf-connecting-ip', () => {
    const headers = makeHeaders({ 'cf-connecting-ip': '1.2.3.4' });
    expect(getClientIp(headers)).toBe('1.2.3.4');
  });

  it('prefers x-forwarded-for over x-real-ip', () => {
    const headers = makeHeaders({
      'x-forwarded-for': '1.1.1.1, 2.2.2.2',
      'x-real-ip': '9.9.9.9'
    });
    expect(getClientIp(headers)).toBe('2.2.2.2');
  });

  it('returns null when no IP headers present', () => {
    expect(getClientIp(new Headers())).toBeNull();
  });

  it('returns null for empty x-forwarded-for', () => {
    const headers = makeHeaders({ 'x-forwarded-for': '   ' });
    expect(getClientIp(headers)).toBeNull();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// shouldBlockBySecurity
// ─────────────────────────────────────────────────────────────────────────────

describe('shouldBlockBySecurity', () => {
  beforeEach(() => {
    setEnv({
      IPGEO_BLOCK_VPN: 'false',
      IPGEO_BLOCK_PROXY: 'false',
      IPGEO_BLOCK_TOR: 'false',
      IPGEO_BLOCK_CLOUD_PROVIDER: 'false',
      IPGEO_BLOCK_BOT: 'false',
      IPGEO_BLOCK_SPAM: 'false',
      IPGEO_BLOCK_KNOWN_ATTACKER: 'false',
      IPGEO_THREAT_SCORE_BLOCK_THRESHOLD: ''
    });
  });

  it('returns null for undefined security', () => {
    expect(shouldBlockBySecurity(undefined)).toBeNull();
  });

  it('returns null when all flags disabled and score below threshold', () => {
    const security: IpGeoSecurity = {
      is_vpn: true,
      is_proxy: true,
      is_tor: true,
      threat_score: 99
    };
    expect(shouldBlockBySecurity(security)).toBeNull();
  });

  it('blocks VPN when IPGEO_BLOCK_VPN=true', () => {
    setEnv({ IPGEO_BLOCK_VPN: 'true' });
    expect(shouldBlockBySecurity({ is_vpn: true })).toBe('vpn');
  });

  it('does not block VPN when flag is true but is_vpn is false', () => {
    setEnv({ IPGEO_BLOCK_VPN: 'true' });
    expect(shouldBlockBySecurity({ is_vpn: false })).toBeNull();
  });

  it('blocks proxy when IPGEO_BLOCK_PROXY=true', () => {
    setEnv({ IPGEO_BLOCK_PROXY: 'true' });
    expect(shouldBlockBySecurity({ is_proxy: true })).toBe('proxy');
  });

  it('blocks Tor when IPGEO_BLOCK_TOR=true', () => {
    setEnv({ IPGEO_BLOCK_TOR: 'true' });
    expect(shouldBlockBySecurity({ is_tor: true })).toBe('tor');
  });

  it('blocks cloud provider when IPGEO_BLOCK_CLOUD_PROVIDER=true', () => {
    setEnv({ IPGEO_BLOCK_CLOUD_PROVIDER: 'true' });
    expect(shouldBlockBySecurity({ is_cloud_provider: true })).toBe('cloud_provider');
  });

  it('blocks bot when IPGEO_BLOCK_BOT=true', () => {
    setEnv({ IPGEO_BLOCK_BOT: 'true' });
    expect(shouldBlockBySecurity({ is_bot: true })).toBe('bot');
  });

  it('blocks spam when IPGEO_BLOCK_SPAM=true', () => {
    setEnv({ IPGEO_BLOCK_SPAM: 'true' });
    expect(shouldBlockBySecurity({ is_spam: true })).toBe('spam');
  });

  it('blocks known attacker when IPGEO_BLOCK_KNOWN_ATTACKER=true', () => {
    setEnv({ IPGEO_BLOCK_KNOWN_ATTACKER: 'true' });
    expect(shouldBlockBySecurity({ is_known_attacker: true })).toBe('known_attacker');
  });

  it('blocks on threat score at threshold', () => {
    setEnv({ IPGEO_THREAT_SCORE_BLOCK_THRESHOLD: '75' });
    expect(shouldBlockBySecurity({ threat_score: 75 })).toBe('threat_score');
  });

  it('blocks on threat score above threshold', () => {
    setEnv({ IPGEO_THREAT_SCORE_BLOCK_THRESHOLD: '75' });
    expect(shouldBlockBySecurity({ threat_score: 90 })).toBe('threat_score');
  });

  it('does not block on threat score below threshold', () => {
    setEnv({ IPGEO_THREAT_SCORE_BLOCK_THRESHOLD: '75' });
    expect(shouldBlockBySecurity({ threat_score: 74 })).toBeNull();
  });

  it('does not block when threshold is 0', () => {
    setEnv({ IPGEO_THREAT_SCORE_BLOCK_THRESHOLD: '0' });
    expect(shouldBlockBySecurity({ threat_score: 100 })).toBeNull();
  });

  it('does not block when threshold is not a number', () => {
    setEnv({ IPGEO_THREAT_SCORE_BLOCK_THRESHOLD: 'abc' });
    expect(shouldBlockBySecurity({ threat_score: 100 })).toBeNull();
  });

  it('respects priority order — vpn checked before threat_score', () => {
    setEnv({ IPGEO_BLOCK_VPN: 'true', IPGEO_THREAT_SCORE_BLOCK_THRESHOLD: '10' });
    expect(shouldBlockBySecurity({ is_vpn: true, threat_score: 90 })).toBe('vpn');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// lookupIpGeolocation — fetch mocking
// ─────────────────────────────────────────────────────────────────────────────

describe('lookupIpGeolocation', () => {
  const mockGeo: IpGeoResponse = {
    ip: '1.2.3.4',
    location: {
      country_code2: 'US',
      country_name: 'United States',
      city: 'New York',
      state_prov: 'New York',
      latitude: '40.7128',
      longitude: '-74.0060'
    },
    asn: { as_number: '15169', organization: 'Google LLC' },
    time_zone: { name: 'America/New_York' },
    security: { is_vpn: false, is_tor: false, threat_score: 0 }
  };

  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
    // Clear internal cache between tests by resetting the module would be
    // complex; instead we use unique IPs per test to avoid stale cache hits.
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function mockFetchOk(body: unknown) {
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(JSON.stringify(body), { status: 200 })
    );
  }

  function mockFetchError(status: number, text = 'error') {
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(text, { status })
    );
  }

  it('returns null when apiKey is empty', async () => {
    expect(await lookupIpGeolocation({ apiKey: '', ip: '1.2.3.4' })).toBeNull();
  });

  it('returns null when ip is empty', async () => {
    expect(await lookupIpGeolocation({ apiKey: 'key', ip: '' })).toBeNull();
  });

  it('fetches and returns geo data', async () => {
    mockFetchOk(mockGeo);
    const result = await lookupIpGeolocation({ apiKey: 'key', ip: '10.0.0.1' });
    expect(result).toEqual(mockGeo);
  });

  it('includes security param by default', async () => {
    mockFetchOk(mockGeo);
    await lookupIpGeolocation({ apiKey: 'key', ip: '10.0.0.2' });
    const url = vi.mocked(fetch).mock.calls[0]?.[0] as string;
    expect(url).toContain('include=security');
  });

  it('omits security param when includeSecurity=false', async () => {
    mockFetchOk(mockGeo);
    await lookupIpGeolocation({ apiKey: 'key', ip: '10.0.0.3', includeSecurity: false });
    const url = vi.mocked(fetch).mock.calls[0]?.[0] as string;
    expect(url).not.toContain('include=security');
  });

  it('returns null on non-OK response', async () => {
    mockFetchError(403, 'Forbidden');
    const result = await lookupIpGeolocation({ apiKey: 'key', ip: '10.0.0.4' });
    expect(result).toBeNull();
  });

  it('returns null on network error', async () => {
    vi.mocked(fetch).mockRejectedValueOnce(new Error('network error'));
    const result = await lookupIpGeolocation({ apiKey: 'key', ip: '10.0.0.5' });
    expect(result).toBeNull();
  });

  it('returns cached result on second call for same IP', async () => {
    mockFetchOk(mockGeo);
    const ip = '10.0.1.1'; // unique IP for this test
    await lookupIpGeolocation({ apiKey: 'key', ip });
    await lookupIpGeolocation({ apiKey: 'key', ip });
    // fetch should have only been called once — second call hits cache
    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(1);
  });

  it('bypasses cache when IPGEO_CACHE_TTL_MS=0', async () => {
    setEnv({ IPGEO_CACHE_TTL_MS: '0' });
    mockFetchOk(mockGeo);
    mockFetchOk(mockGeo);
    const ip = '10.0.1.2';
    await lookupIpGeolocation({ apiKey: 'key', ip });
    await lookupIpGeolocation({ apiKey: 'key', ip });
    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(2);
    setEnv({ IPGEO_CACHE_TTL_MS: undefined });
  });

  it('logs an AbortError with timeout message', async () => {
    const abortError = new DOMException('The operation was aborted.', 'AbortError');
    vi.mocked(fetch).mockRejectedValueOnce(abortError);
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    await lookupIpGeolocation({ apiKey: 'key', ip: '10.0.0.6', timeoutMs: 1 });
    expect(error.mock.calls.some((c) => String(c[0]).includes('timed out'))).toBe(true);
    error.mockRestore();
  });
});
