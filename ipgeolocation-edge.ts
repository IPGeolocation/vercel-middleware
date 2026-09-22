// =============================================================================
// IPGeolocation.io edge utility library
//
// Runs in the Vercel Edge Runtime, in Node.js 18 and later, and in any runtime
// that provides fetch, URL, Headers and AbortController.
//
// No runtime dependencies.
// =============================================================================

// -----------------------------------------------------------------------------
// Response types
// -----------------------------------------------------------------------------

export type IpGeoSecurity = {
  threat_score?: number;
  is_tor?: boolean;
  is_proxy?: boolean;
  proxy_provider_names?: string[];
  proxy_confidence_score?: number;
  proxy_last_seen?: string;
  is_residential_proxy?: boolean;
  is_vpn?: boolean;
  vpn_provider_names?: string[];
  vpn_confidence_score?: number;
  vpn_last_seen?: string;
  is_relay?: boolean;
  relay_provider_name?: string;
  is_anonymous?: boolean;
  is_known_attacker?: boolean;
  is_bot?: boolean;
  bot_confidence_score?: number;
  bot_operator_name?: string;
  bot_type?: string;
  is_known_good_bot?: boolean;
  bot_last_seen?: string;
  is_spam?: boolean;
  is_cloud_provider?: boolean;
  cloud_provider_name?: string;
  is_corporate_gateway?: boolean;
  corporate_gateway_type?: string;
  corporate_gateway_provider_name?: string;
};

export type IpGeoLocation = {
  continent_code?: string;
  continent_name?: string;
  country_code2?: string;
  country_code3?: string;
  country_name?: string;
  country_capital?: string;
  state_prov?: string;
  state_code?: string;
  district?: string;
  city?: string;
  zipcode?: string;
  latitude?: string;
  longitude?: string;
  is_eu?: boolean;
  geoname_id?: string;
};

export type IpGeoResponse = {
  ip?: string;
  domain?: string;
  hostname?: string;
  location?: IpGeoLocation;
  country_metadata?: {
    calling_code?: string;
    tld?: string;
    languages?: string[];
  };
  currency?: {
    code?: string;
    name?: string;
    symbol?: string;
  };
  network?: {
    connection_type?: string;
    route?: string;
    is_anycast?: boolean;
    is_cdn?: boolean;
    cdn_provider_name?: string;
  };
  asn?: {
    as_number?: string;
    organization?: string;
    country?: string;
    type?: string;
    domain?: string;
  };
  company?: {
    name?: string;
    type?: string;
    domain?: string;
  };
  time_zone?: {
    name?: string;
    offset?: number;
    offset_with_dst?: number;
    current_time?: string;
    is_dst?: boolean;
  };
  security?: IpGeoSecurity;
};

// -----------------------------------------------------------------------------
// Logging
//
// Every line is prefixed so it can be filtered in Vercel runtime logs. The
// default level is "warn", which keeps per request noise out of your logs while
// still surfacing configuration and API problems.
// -----------------------------------------------------------------------------

export type LogLevel = 'silent' | 'error' | 'warn' | 'info' | 'debug';

const LOG_WEIGHTS: Record<LogLevel, number> = {
  silent: 0,
  error: 1,
  warn: 2,
  info: 3,
  debug: 4
};

const LOG_PREFIX = '[IPGeolocation.io]';

function activeLogWeight(): number {
  const raw = String(process.env.IPGEO_LOG_LEVEL ?? 'warn').toLowerCase();
  const weight = LOG_WEIGHTS[raw as LogLevel];
  return typeof weight === 'number' ? weight : LOG_WEIGHTS.warn;
}

function logError(message: string, ...rest: unknown[]): void {
  if (activeLogWeight() >= LOG_WEIGHTS.error) console.error(LOG_PREFIX, message, ...rest);
}

function logWarn(message: string, ...rest: unknown[]): void {
  if (activeLogWeight() >= LOG_WEIGHTS.warn) console.warn(LOG_PREFIX, message, ...rest);
}

function logDebug(message: string, ...rest: unknown[]): void {
  if (activeLogWeight() >= LOG_WEIGHTS.debug) console.log(LOG_PREFIX, message, ...rest);
}

// -----------------------------------------------------------------------------
// Environment helpers
// -----------------------------------------------------------------------------

const TRUTHY = new Set(['true', '1', 'yes', 'y', 'on']);
const FALSY = new Set(['false', '0', 'no', 'n', 'off', '']);

/**
 * Parses a boolean environment variable.
 * Accepts true, 1, yes, y and on (case insensitive) as true.
 */
export function envFlag(value?: string, fallback = false): boolean {
  if (value === undefined || value === null) return fallback;

  const normalized = String(value).trim().toLowerCase();
  if (TRUTHY.has(normalized)) return true;
  if (FALSY.has(normalized)) return false;

  logWarn(`Unrecognised boolean value "${value}". Falling back to ${fallback}.`);
  return fallback;
}

/**
 * Parses a numeric environment variable with an optional inclusive range.
 * Values outside the range are clamped. Anything unparseable falls back.
 */
export function envNumber(
  value: string | undefined,
  fallback: number,
  range?: { min?: number; max?: number }
): number {
  if (value === undefined || value === null || String(value).trim() === '') return fallback;

  const parsed = Number(String(value).trim());
  if (!Number.isFinite(parsed)) {
    logWarn(`Expected a number but received "${value}". Falling back to ${fallback}.`);
    return fallback;
  }

  const min = range?.min;
  const max = range?.max;

  if (typeof min === 'number' && parsed < min) return min;
  if (typeof max === 'number' && parsed > max) return max;

  return parsed;
}

/**
 * Parses a comma separated list of ISO 3166-1 alpha-2 country codes into a Set
 * of uppercase codes. Values that are not two letters are dropped with a warning.
 */
export function parseCsvEnv(value?: string): Set<string> {
  const result = new Set<string>();
  if (!value) return result;

  for (const raw of String(value).split(',')) {
    const code = raw.trim().toUpperCase();
    if (!code) continue;

    if (!/^[A-Z]{2}$/.test(code)) {
      logWarn(`Ignoring "${raw.trim()}" because it is not a two letter country code.`);
      continue;
    }

    result.add(code);
  }

  return result;
}

/** Parses a comma separated list into a trimmed array with empties removed. */
export function parseList(value?: string): string[] {
  if (!value) return [];
  return String(value)
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

/**
 * Normalizes a same origin path.
 *
 * Returns null for absolute URLs, protocol relative values and backslash
 * variants. A trailing slash is removed so a value such as "/uk/" cannot cause
 * a redirect loop.
 */
export function normalizeInternalPath(value: string | undefined | null): string | null {
  if (typeof value !== 'string') return null;

  const trimmed = value.trim();
  if (!trimmed.startsWith('/')) return null;
  if (trimmed.startsWith('//')) return null;
  if (trimmed.includes('\\')) return null;

  const withoutTrailingSlash = trimmed.length > 1 ? trimmed.replace(/\/+$/, '') : trimmed;
  return withoutTrailingSlash === '' ? '/' : withoutTrailingSlash;
}

/**
 * Parses the country to path redirect map.
 *
 * Only same origin paths are accepted, so a misconfigured variable cannot turn
 * the middleware into an open redirect.
 */
export function parseRedirectMap(value?: string): Record<string, string> {
  if (!value || value.trim() === '' || value.trim() === '{}') return {};

  let parsed: unknown;

  try {
    parsed = JSON.parse(value);
  } catch {
    logWarn(
      'IPGEO_COUNTRY_REDIRECTS is not valid JSON, so no country redirects are active. First 120 characters:',
      value.slice(0, 120)
    );
    return {};
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    logWarn('IPGEO_COUNTRY_REDIRECTS must be a JSON object such as {"GB":"/uk"}.');
    return {};
  }

  const result: Record<string, string> = {};

  for (const [rawCountry, rawPath] of Object.entries(parsed as Record<string, unknown>)) {
    const country = rawCountry.trim().toUpperCase();

    if (!/^[A-Z]{2}$/.test(country)) {
      logWarn(`Ignoring redirect key "${rawCountry}" because it is not a two letter country code.`);
      continue;
    }

    if (typeof rawPath !== 'string') {
      logWarn(`Ignoring the redirect for ${country} because the target is not a string.`);
      continue;
    }

    const path = normalizeInternalPath(rawPath);

    if (!path) {
      logWarn(
        `Ignoring the redirect for ${country} because "${rawPath}" is not a same origin path starting with "/".`
      );
      continue;
    }

    result[country] = path;
  }

  return result;
}

/** True when pathname is the prefix itself or sits underneath it. */
export function isUnderPath(pathname: string, prefix: string): boolean {
  if (prefix === '/') return true;
  return pathname === prefix || pathname.startsWith(prefix + '/');
}

// -----------------------------------------------------------------------------
// IP address handling
// -----------------------------------------------------------------------------

const IPV4_PATTERN = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function isIpv4(value: string): boolean {
  const match = IPV4_PATTERN.exec(value);
  if (!match) return false;

  for (let i = 1; i <= 4; i += 1) {
    const part = match[i];
    if (part === undefined) return false;
    if (part.length > 1 && part.startsWith('0')) return false;
    if (Number(part) > 255) return false;
  }

  return true;
}

function isIpv6(value: string): boolean {
  if (!value.includes(':')) return false;
  if (!/^[0-9a-fA-F:.]+$/.test(value)) return false;
  if ((value.match(/::/g) ?? []).length > 1) return false;

  const groups = value.split(':');
  if (groups.length > 8) return false;

  const last = groups[groups.length - 1];
  if (last !== undefined && last.includes('.') && !isIpv4(last)) return false;

  return true;
}

/**
 * Cleans a single IP candidate taken from a header.
 *
 * Handles the shapes proxies produce in the wild: an IPv4 address with a port,
 * a bracketed IPv6 address with a port, quoted values, zone indexes, and IPv4
 * mapped IPv6 such as ::ffff:203.0.113.10.
 *
 * Returns null when the value is not a valid IPv4 or IPv6 address.
 */
export function normalizeIp(value: string | undefined | null): string | null {
  if (typeof value !== 'string') return null;

  let candidate = value.trim().replace(/^"|"$/g, '');
  if (!candidate) return null;

  const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(candidate);

  if (bracketed && bracketed[1]) {
    candidate = bracketed[1];
  } else if (candidate.includes('.') && candidate.includes(':') && !candidate.includes('::')) {
    const host = candidate.split(':')[0];
    if (host) candidate = host;
  }

  const percent = candidate.indexOf('%');
  if (percent > -1) candidate = candidate.slice(0, percent);

  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(candidate);
  if (mapped && mapped[1]) candidate = mapped[1];

  if (isIpv4(candidate)) return candidate;
  if (isIpv6(candidate)) return candidate.toLowerCase();

  return null;
}

/**
 * True when the address is a globally routable public IP.
 *
 * The API answers HTTP 423 for private and bogon ranges, so filtering them here
 * avoids a failed lookup and a wasted round trip. This is also what stops local
 * development from looking like an API outage.
 */
export function isPublicIp(value: string | undefined | null): boolean {
  const ip = normalizeIp(value);
  if (!ip) return false;

  if (isIpv4(ip)) {
    const parts = ip.split('.').map(Number);
    const a = parts[0] ?? 0;
    const b = parts[1] ?? 0;

    if (a === 0) return false; // this network
    if (a === 10) return false; // private
    if (a === 127) return false; // loopback
    if (a === 100 && b >= 64 && b <= 127) return false; // carrier grade NAT
    if (a === 169 && b === 254) return false; // link local
    if (a === 172 && b >= 16 && b <= 31) return false; // private
    if (a === 192 && b === 0) return false; // protocol assignments and documentation
    if (a === 192 && b === 168) return false; // private
    if (a === 198 && (b === 18 || b === 19)) return false; // benchmarking
    if (a === 198 && b === 51) return false; // documentation
    if (a === 203 && b === 0) return false; // documentation
    if (a >= 224) return false; // multicast, reserved and broadcast

    return true;
  }

  const lower = ip.toLowerCase();

  if (lower === '::' || lower === '::1') return false;
  if (lower.startsWith('fe80')) return false; // link local
  if (/^f[cd]/.test(lower)) return false; // unique local
  if (lower.startsWith('ff')) return false; // multicast
  if (lower.startsWith('2001:db8')) return false; // documentation
  if (lower.startsWith('100:')) return false; // discard only

  return true;
}

export type ClientIpOptions = {
  /** Read the leftmost entry of x-forwarded-for instead of the rightmost. */
  trustFirstXff?: boolean;
  /**
   * Number of proxies you operate in front of the application. The client IP is
   * read that many positions to the left of the rightmost entry. Ignored when
   * trustFirstXff is true.
   */
  trustedProxyCount?: number;
  /** Accept private, loopback and bogon addresses. Off by default. */
  allowPrivate?: boolean;
};

const IP_HEADERS = [
  'x-vercel-forwarded-for',
  'x-forwarded-for',
  'x-real-ip',
  'cf-connecting-ip',
  'true-client-ip'
] as const;

/**
 * Extracts the client IP from the request headers.
 *
 * On Vercel the platform sets x-forwarded-for from the real connection and does
 * not forward an externally supplied value, so reading the rightmost entry is
 * correct. Behind a reverse proxy you operate yourself, set trustedProxyCount
 * to the number of hops you control.
 *
 * The second argument also accepts a boolean for compatibility with 1.x, where
 * it meant trustFirstXff.
 */
export function getClientIp(
  headers: Headers,
  options: ClientIpOptions | boolean = {}
): string | null {
  const opts: ClientIpOptions = typeof options === 'boolean' ? { trustFirstXff: options } : options;
  const allowPrivate = opts.allowPrivate === true;

  const accept = (candidate: string | null | undefined): string | null => {
    if (!candidate) return null;
    const ip = normalizeIp(candidate);
    if (!ip) return null;
    if (!allowPrivate && !isPublicIp(ip)) return null;
    return ip;
  };

  for (const headerName of IP_HEADERS) {
    const raw = headers.get(headerName);
    if (!raw) continue;

    const entries = raw
      .split(',')
      .map((item) => item.trim())
      .filter(Boolean);

    if (entries.length === 0) continue;

    if (entries.length === 1 || opts.trustFirstXff) {
      const first = accept(entries[0]);
      if (first) return first;
      continue;
    }

    const hops = Math.max(0, Math.trunc(opts.trustedProxyCount ?? 0));
    const index = Math.max(0, entries.length - 1 - hops);
    const selected = accept(entries[index]);
    if (selected) return selected;
  }

  return null;
}

// -----------------------------------------------------------------------------
// Security rules
// -----------------------------------------------------------------------------

export type SecurityRules = {
  blockVpn: boolean;
  blockProxy: boolean;
  blockResidentialProxy: boolean;
  blockTor: boolean;
  blockRelay: boolean;
  blockCloudProvider: boolean;
  blockBot: boolean;
  blockSpam: boolean;
  blockKnownAttacker: boolean;
  blockAnonymous: boolean;
  /** Keep bots the API marks as known good, such as search engine crawlers. */
  allowKnownGoodBots: boolean;
  /** Block at or above this threat score. 0 disables the check. */
  threatScoreThreshold: number;
};

export type SecurityBlockReason =
  | 'vpn'
  | 'proxy'
  | 'residential_proxy'
  | 'tor'
  | 'relay'
  | 'cloud_provider'
  | 'bot'
  | 'spam'
  | 'known_attacker'
  | 'anonymous'
  | 'threat_score';

/** Reads the security rules from the environment. */
export function getSecurityRulesFromEnv(): SecurityRules {
  return {
    blockVpn: envFlag(process.env.IPGEO_BLOCK_VPN),
    blockProxy: envFlag(process.env.IPGEO_BLOCK_PROXY),
    blockResidentialProxy: envFlag(process.env.IPGEO_BLOCK_RESIDENTIAL_PROXY),
    blockTor: envFlag(process.env.IPGEO_BLOCK_TOR),
    blockRelay: envFlag(process.env.IPGEO_BLOCK_RELAY),
    blockCloudProvider: envFlag(process.env.IPGEO_BLOCK_CLOUD_PROVIDER),
    blockBot: envFlag(process.env.IPGEO_BLOCK_BOT),
    blockSpam: envFlag(process.env.IPGEO_BLOCK_SPAM),
    blockKnownAttacker: envFlag(process.env.IPGEO_BLOCK_KNOWN_ATTACKER),
    blockAnonymous: envFlag(process.env.IPGEO_BLOCK_ANONYMOUS),
    allowKnownGoodBots: envFlag(process.env.IPGEO_ALLOW_KNOWN_GOOD_BOTS, true),
    threatScoreThreshold: envNumber(process.env.IPGEO_THREAT_SCORE_BLOCK_THRESHOLD, 0, {
      min: 0,
      max: 100
    })
  };
}

/** True when at least one rule needs the security module. */
export function securityRulesEnabled(rules: SecurityRules): boolean {
  return (
    rules.blockVpn ||
    rules.blockProxy ||
    rules.blockResidentialProxy ||
    rules.blockTor ||
    rules.blockRelay ||
    rules.blockCloudProvider ||
    rules.blockBot ||
    rules.blockSpam ||
    rules.blockKnownAttacker ||
    rules.blockAnonymous ||
    rules.threatScoreThreshold > 0
  );
}

/**
 * Evaluates the security object against the active rules and returns the reason
 * for the first rule that matches, or null to allow the request.
 */
export function shouldBlockBySecurity(
  security: IpGeoSecurity | undefined,
  rules?: SecurityRules
): SecurityBlockReason | null {
  if (!security) return null;

  const active = rules ?? getSecurityRulesFromEnv();

  if (active.blockVpn && security.is_vpn) return 'vpn';
  if (active.blockProxy && security.is_proxy) return 'proxy';
  if (active.blockResidentialProxy && security.is_residential_proxy) return 'residential_proxy';
  if (active.blockTor && security.is_tor) return 'tor';
  if (active.blockRelay && security.is_relay) return 'relay';
  if (active.blockCloudProvider && security.is_cloud_provider) return 'cloud_provider';

  if (active.blockBot && security.is_bot) {
    const goodBot = active.allowKnownGoodBots && security.is_known_good_bot === true;
    if (!goodBot) return 'bot';
  }

  if (active.blockSpam && security.is_spam) return 'spam';
  if (active.blockKnownAttacker && security.is_known_attacker) return 'known_attacker';
  if (active.blockAnonymous && security.is_anonymous) return 'anonymous';

  if (active.threatScoreThreshold > 0) {
    const score = Number(security.threat_score ?? 0);
    if (Number.isFinite(score) && score >= active.threatScoreThreshold) return 'threat_score';
  }

  return null;
}

// -----------------------------------------------------------------------------
// Cache, request coalescing and circuit breaker
//
// All state is module level. In the Edge Runtime that means it is scoped to one
// isolate and shared by the requests that isolate serves.
// -----------------------------------------------------------------------------

type CacheEntry = { data: IpGeoResponse; expiresAt: number };

const geoCache = new Map<string, CacheEntry>();
const inFlight = new Map<string, Promise<LookupResult>>();

const DEFAULT_CACHE_TTL_MS = 60_000;
const DEFAULT_CACHE_MAX_ENTRIES = 1_000;
const DEFAULT_TIMEOUT_MS = 3_000;
const DEFAULT_RETRIES = 1;
const DEFAULT_CIRCUIT_THRESHOLD = 5;
const DEFAULT_CIRCUIT_COOLDOWN_MS = 30_000;
const SECURITY_LATCH_MS = 300_000;

let consecutiveFailures = 0;
let circuitOpenUntil = 0;
let securityUnavailableUntil = 0;

function cacheTtlMs(override?: number): number {
  if (typeof override === 'number' && Number.isFinite(override) && override >= 0) return override;
  return envNumber(process.env.IPGEO_CACHE_TTL_MS, DEFAULT_CACHE_TTL_MS, { min: 0 });
}

function cacheMaxEntries(): number {
  return envNumber(process.env.IPGEO_CACHE_MAX_ENTRIES, DEFAULT_CACHE_MAX_ENTRIES, { min: 0 });
}

function readCache(key: string): IpGeoResponse | null {
  const entry = geoCache.get(key);
  if (!entry) return null;

  if (entry.expiresAt <= Date.now()) {
    geoCache.delete(key);
    return null;
  }

  // Refresh insertion order so eviction drops the coldest keys first.
  geoCache.delete(key);
  geoCache.set(key, entry);

  return entry.data;
}

function writeCache(key: string, data: IpGeoResponse, ttlOverride?: number): void {
  const ttl = cacheTtlMs(ttlOverride);
  if (ttl === 0) return;

  const max = cacheMaxEntries();
  if (max === 0) return;

  geoCache.set(key, { data, expiresAt: Date.now() + ttl });

  if (geoCache.size <= max) return;

  const now = Date.now();
  for (const [existingKey, entry] of geoCache) {
    if (entry.expiresAt <= now) geoCache.delete(existingKey);
  }

  while (geoCache.size > max) {
    const oldest = geoCache.keys().next();
    if (oldest.done) break;
    geoCache.delete(oldest.value);
  }
}

function circuitIsOpen(): boolean {
  if (circuitOpenUntil === 0) return false;

  if (Date.now() >= circuitOpenUntil) {
    circuitOpenUntil = 0;
    consecutiveFailures = 0;
    return false;
  }

  return true;
}

function recordSuccess(): void {
  consecutiveFailures = 0;
  circuitOpenUntil = 0;
}

function recordFailure(): void {
  const threshold = envNumber(
    process.env.IPGEO_CIRCUIT_FAILURE_THRESHOLD,
    DEFAULT_CIRCUIT_THRESHOLD,
    { min: 0 }
  );

  if (threshold === 0) return;

  consecutiveFailures += 1;
  if (consecutiveFailures < threshold) return;

  const cooldown = envNumber(process.env.IPGEO_CIRCUIT_COOLDOWN_MS, DEFAULT_CIRCUIT_COOLDOWN_MS, {
    min: 0
  });

  if (cooldown === 0) return;

  circuitOpenUntil = Date.now() + cooldown;
  logWarn(
    `${consecutiveFailures} lookups failed in a row, so lookups pause for ${cooldown}ms. While the pause lasts, traffic follows your fail open or fail closed setting.`
  );
}

/**
 * Clears the cache, the in flight map and the circuit breaker state.
 * Intended for tests and for long running processes that need a clean slate.
 */
export function resetIpGeoRuntimeState(): void {
  geoCache.clear();
  inFlight.clear();
  consecutiveFailures = 0;
  circuitOpenUntil = 0;
  securityUnavailableUntil = 0;
}

/** A snapshot of cache and circuit breaker state, useful for a health route. */
export function getIpGeoRuntimeState(): {
  cacheSize: number;
  inFlight: number;
  consecutiveFailures: number;
  circuitOpen: boolean;
  securityModuleAvailable: boolean;
} {
  return {
    cacheSize: geoCache.size,
    inFlight: inFlight.size,
    consecutiveFailures,
    circuitOpen: circuitIsOpen(),
    securityModuleAvailable: securityUnavailableUntil === 0 || Date.now() >= securityUnavailableUntil
  };
}

// -----------------------------------------------------------------------------
// Lookup
// -----------------------------------------------------------------------------

export const IPGEO_API_BASE_URL = 'https://api.ipgeolocation.io/v3/ipgeo';

export type LookupFailureReason =
  | 'invalid_input'
  | 'private_ip'
  | 'circuit_open'
  | 'unauthorized'
  | 'rate_limited'
  | 'http_error'
  | 'timeout'
  | 'network_error'
  | 'invalid_response';

export type LookupResult =
  | { ok: true; data: IpGeoResponse; cached: boolean; creditsCharged: number | null }
  | { ok: false; reason: LookupFailureReason; status: number | null; message: string };

export type LookupOptions = {
  apiKey: string;
  ip: string;
  /**
   * Optional modules to request, for example ["security"]. Modules beyond the
   * base lookup cost extra credits and need a paid plan.
   */
  include?: string[];
  /** Compatibility with 1.x. Adds "security" to include. Defaults to false. */
  includeSecurity?: boolean;
  /** Restrict the response to these fields, which shrinks the payload. */
  fields?: string[];
  /** Remove these fields from the response. */
  excludes?: string[];
  timeoutMs?: number;
  /** Retries for timeouts, network errors and 5xx responses. Defaults to 1. */
  retries?: number;
  /** Cache lifetime for this call in milliseconds. Overrides IPGEO_CACHE_TTL_MS. */
  cacheTtlMs?: number;
  /** Allow private and bogon addresses to reach the API. Off by default. */
  allowPrivateIp?: boolean;
  /** Override the endpoint. Mainly for testing against a mock server. */
  baseUrl?: string;
};

function buildInclude(options: LookupOptions): string[] {
  const requested = new Set<string>();

  for (const value of options.include ?? []) {
    const trimmed = value.trim();
    if (trimmed) requested.add(trimmed);
  }

  if (options.includeSecurity) requested.add('security');

  const latched = securityUnavailableUntil > 0 && Date.now() < securityUnavailableUntil;
  if (latched && requested.delete('security')) {
    logDebug('Skipping the security module because the API key rejected it earlier.');
  }

  return [...requested];
}

function buildRequestUrl(options: LookupOptions, include: string[]): string {
  const url = new URL(options.baseUrl ?? IPGEO_API_BASE_URL);

  url.searchParams.set('apiKey', options.apiKey);
  url.searchParams.set('ip', options.ip);
  url.searchParams.set('output', 'json');

  if (include.length > 0) url.searchParams.set('include', include.join(','));

  if (options.fields && options.fields.length > 0) {
    url.searchParams.set('fields', options.fields.join(','));
  }

  if (options.excludes && options.excludes.length > 0) {
    url.searchParams.set('excludes', options.excludes.join(','));
  }

  return url.toString();
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function readErrorMessage(response: Response): Promise<string> {
  try {
    const text = await response.text();
    return text.slice(0, 300);
  } catch {
    return '';
  }
}

type RequestOutcome =
  | { kind: 'ok'; data: IpGeoResponse; creditsCharged: number | null }
  | { kind: 'http'; status: number; message: string }
  | { kind: 'timeout' }
  | { kind: 'network'; message: string }
  | { kind: 'invalid'; message: string };

async function performRequest(url: string, timeoutMs: number): Promise<RequestOutcome> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      method: 'GET',
      signal: controller.signal,
      headers: { accept: 'application/json' }
    });

    if (!response.ok) {
      return { kind: 'http', status: response.status, message: await readErrorMessage(response) };
    }

    const creditsHeader = response.headers.get('x-credits-charged');
    const credits = creditsHeader === null ? null : Number(creditsHeader);

    let data: unknown;

    try {
      data = await response.json();
    } catch {
      return { kind: 'invalid', message: 'The API response was not valid JSON.' };
    }

    if (typeof data !== 'object' || data === null || Array.isArray(data)) {
      return { kind: 'invalid', message: 'The API response was not a JSON object.' };
    }

    return {
      kind: 'ok',
      data: data as IpGeoResponse,
      creditsCharged: credits !== null && Number.isFinite(credits) ? credits : null
    };
  } catch (error) {
    if (error instanceof Error && (error.name === 'AbortError' || error.name === 'TimeoutError')) {
      return { kind: 'timeout' };
    }

    return { kind: 'network', message: error instanceof Error ? error.message : String(error) };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Looks up an IP address and returns a detailed result.
 *
 * Behaviour worth knowing about:
 *   - Responses are cached per IP and per module set for IPGEO_CACHE_TTL_MS.
 *   - Concurrent lookups for the same key share one request.
 *   - Timeouts, network errors and 5xx responses are retried once by default.
 *   - Repeated failures open a circuit breaker, so an API outage does not add
 *     the full timeout to every request.
 *   - If the security module is rejected with HTTP 401, the call is retried
 *     without it and the module is skipped for the next five minutes.
 */
export async function lookupIpGeolocationResult(options: LookupOptions): Promise<LookupResult> {
  const apiKey = String(options.apiKey ?? '').trim();
  const rawIp = String(options.ip ?? '').trim();

  if (!apiKey) {
    return { ok: false, reason: 'invalid_input', status: null, message: 'No API key was provided.' };
  }

  const ip = normalizeIp(rawIp);

  if (!ip) {
    return {
      ok: false,
      reason: 'invalid_input',
      status: null,
      message: `"${rawIp}" is not a valid IP address.`
    };
  }

  if (!options.allowPrivateIp && !isPublicIp(ip)) {
    return {
      ok: false,
      reason: 'private_ip',
      status: null,
      message: `${ip} is a private or reserved address, which the API cannot resolve.`
    };
  }

  const include = buildInclude(options);
  const cacheKey = `${ip}|${include.slice().sort().join(',')}|${(options.fields ?? []).join(',')}`;

  const cached = readCache(cacheKey);
  if (cached) {
    logDebug(`Cache hit for ${ip}.`);
    return { ok: true, data: cached, cached: true, creditsCharged: 0 };
  }

  if (circuitIsOpen()) {
    return {
      ok: false,
      reason: 'circuit_open',
      status: null,
      message: 'Lookups are paused because recent requests to the API failed.'
    };
  }

  const existing = inFlight.get(cacheKey);
  if (existing) return existing;

  const promise = executeLookup(options, apiKey, ip, include, cacheKey).finally(() => {
    inFlight.delete(cacheKey);
  });

  inFlight.set(cacheKey, promise);

  return promise;
}

async function executeLookup(
  options: LookupOptions,
  apiKey: string,
  ip: string,
  include: string[],
  cacheKey: string
): Promise<LookupResult> {
  const timeoutMs = Math.max(
    250,
    options.timeoutMs ?? envNumber(process.env.IPGEO_TIMEOUT_MS, DEFAULT_TIMEOUT_MS, { min: 250 })
  );

  const retries = Math.max(
    0,
    options.retries ?? envNumber(process.env.IPGEO_RETRIES, DEFAULT_RETRIES, { min: 0, max: 3 })
  );

  let activeInclude = include;
  let attempt = 0;

  let lastFailure: LookupResult = {
    ok: false,
    reason: 'network_error',
    status: null,
    message: 'The lookup did not run.'
  };

  while (attempt <= retries) {
    const url = buildRequestUrl({ ...options, apiKey, ip }, activeInclude);
    const suffix = activeInclude.length > 0 ? ` (include: ${activeInclude.join(',')})` : '';
    logDebug(`Looking up ${ip}${suffix}.`);

    const outcome = await performRequest(url, timeoutMs);

    if (outcome.kind === 'ok') {
      recordSuccess();
      writeCache(cacheKey, outcome.data, options.cacheTtlMs);

      if (outcome.creditsCharged !== null) {
        logDebug(`The lookup for ${ip} was charged ${outcome.creditsCharged} credit(s).`);
      }

      return {
        ok: true,
        data: outcome.data,
        cached: false,
        creditsCharged: outcome.creditsCharged
      };
    }

    if (outcome.kind === 'http') {
      const status = outcome.status;

      // A free plan key cannot request the security module. Drop it, retry once
      // and remember the answer so later requests do not repeat the mistake.
      if (status === 401 && activeInclude.includes('security')) {
        securityUnavailableUntil = Date.now() + SECURITY_LATCH_MS;
        activeInclude = activeInclude.filter((item) => item !== 'security');
        logError(
          'The API rejected the security module with HTTP 401, which means this key is not on a paid plan. Retrying without it. VPN, proxy, Tor, bot, spam, attacker and threat score rules cannot be applied until the plan is upgraded. See https://ipgeolocation.io/pricing.html'
        );
        continue;
      }

      if (status === 401 || status === 403) {
        recordFailure();
        return {
          ok: false,
          reason: 'unauthorized',
          status,
          message: `The API rejected the request with HTTP ${status}. Check IPGEOLOCATION_API_KEY and your subscription status. ${outcome.message}`
        };
      }

      if (status === 423) {
        return {
          ok: false,
          reason: 'private_ip',
          status,
          message: `${ip} is a private or bogon address. ${outcome.message}`
        };
      }

      if (status === 429) {
        recordFailure();
        return {
          ok: false,
          reason: 'rate_limited',
          status,
          message: `The plan quota is exhausted (HTTP 429). ${outcome.message}`
        };
      }

      if (status >= 500 && attempt < retries) {
        attempt += 1;
        await sleep(100 * attempt);
        continue;
      }

      recordFailure();
      return {
        ok: false,
        reason: 'http_error',
        status,
        message: `The API answered HTTP ${status}. ${outcome.message}`
      };
    }

    if (outcome.kind === 'invalid') {
      recordFailure();
      return { ok: false, reason: 'invalid_response', status: null, message: outcome.message };
    }

    lastFailure =
      outcome.kind === 'timeout'
        ? {
            ok: false,
            reason: 'timeout',
            status: null,
            message: `The lookup for ${ip} timed out after ${timeoutMs}ms.`
          }
        : {
            ok: false,
            reason: 'network_error',
            status: null,
            message: `The lookup for ${ip} failed: ${outcome.message}`
          };

    if (attempt < retries) {
      attempt += 1;
      await sleep(100 * attempt);
      continue;
    }

    break;
  }

  recordFailure();
  return lastFailure;
}

/**
 * Looks up an IP address and returns the response, or null when the lookup
 * cannot be completed. Use lookupIpGeolocationResult when you need the reason.
 */
export async function lookupIpGeolocation(options: LookupOptions): Promise<IpGeoResponse | null> {
  const result = await lookupIpGeolocationResult(options);

  if (result.ok) return result.data;

  if (result.reason === 'private_ip' || result.reason === 'invalid_input') {
    logDebug(result.message);
  } else if (result.reason === 'circuit_open') {
    logWarn(result.message);
  } else {
    logError(result.message);
  }

  return null;
}

// -----------------------------------------------------------------------------
// Header helpers
// -----------------------------------------------------------------------------

export type GeoHeaderMap = Record<string, string>;

/**
 * Builds the geo headers for a request.
 *
 * Empty values are left out, so a missing header means the data was not
 * available rather than an empty string.
 */
export function buildGeoHeaders(
  geo: IpGeoResponse | null,
  fallbackIp: string,
  prefix = 'x-ipgeo'
): GeoHeaderMap {
  const headers: GeoHeaderMap = {};

  const set = (name: string, value: string | undefined | null): void => {
    if (value === undefined || value === null) return;
    const text = String(value);
    if (text === '') return;
    headers[`${prefix}-${name}`] = text;
  };

  set('ip', geo?.ip ?? fallbackIp);

  if (!geo) return headers;

  const location = geo.location;

  set('country', location?.country_code2?.toUpperCase());
  set('country-name', location?.country_name);
  set('continent', location?.continent_code);
  set('state', location?.state_prov);
  set('state-code', location?.state_code);
  set('city', location?.city);
  set('zipcode', location?.zipcode);
  set('latitude', location?.latitude);
  set('longitude', location?.longitude);
  if (typeof location?.is_eu === 'boolean') set('is-eu', String(location.is_eu));

  set('timezone', geo.time_zone?.name);
  set('currency', geo.currency?.code);
  set('asn', geo.asn?.as_number);
  set('asn-organization', geo.asn?.organization);
  set('company', geo.company?.name);

  const security = geo.security;
  if (!security) return headers;

  if (typeof security.threat_score === 'number') set('threat-score', String(security.threat_score));

  const flags: Array<[string, boolean | undefined]> = [
    ['is-vpn', security.is_vpn],
    ['is-proxy', security.is_proxy],
    ['is-residential-proxy', security.is_residential_proxy],
    ['is-tor', security.is_tor],
    ['is-relay', security.is_relay],
    ['is-anonymous', security.is_anonymous],
    ['is-bot', security.is_bot],
    ['is-known-good-bot', security.is_known_good_bot],
    ['is-spam', security.is_spam],
    ['is-known-attacker', security.is_known_attacker],
    ['is-cloud-provider', security.is_cloud_provider]
  ];

  for (const [name, value] of flags) {
    if (typeof value === 'boolean') set(name, String(value));
  }

  set('cloud-provider-name', security.cloud_provider_name);

  return headers;
}

/**
 * Removes every inbound header that uses the geo prefix.
 *
 * Without this, a visitor can send x-ipgeo-country themselves and your
 * application cannot tell that value apart from one the middleware produced.
 */
export function stripSpoofedGeoHeaders(headers: Headers, prefix = 'x-ipgeo'): void {
  const marker = `${prefix.toLowerCase()}-`;
  const toDelete: string[] = [];

  headers.forEach((_value, key) => {
    if (key.toLowerCase().startsWith(marker)) toDelete.push(key);
  });

  for (const key of toDelete) headers.delete(key);
}
