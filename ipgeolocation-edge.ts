// ─────────────────────────────────────────────────────────────────────────────
// IPGeolocation.io – Edge utility library
// Compatible with Next.js Middleware (Edge Runtime)
// ─────────────────────────────────────────────────────────────────────────────

export type IpGeoSecurity = {
  threat_score?: number;
  is_tor?: boolean;
  is_proxy?: boolean;
  is_residential_proxy?: boolean;
  is_vpn?: boolean;
  is_relay?: boolean;
  is_anonymous?: boolean;
  is_known_attacker?: boolean;
  is_bot?: boolean;
  is_spam?: boolean;
  is_cloud_provider?: boolean;
  cloud_provider_name?: string;
};

export type IpGeoResponse = {
  ip?: string;
  location?: {
    country_code2?: string;
    country_name?: string;
    state_prov?: string;
    city?: string;
    latitude?: string;
    longitude?: string;
  };
  asn?: {
    as_number?: string;
    organization?: string;
  };
  time_zone?: {
    name?: string;
  };
  security?: IpGeoSecurity;
};

type LookupOptions = {
  apiKey: string;
  ip: string;
  includeSecurity?: boolean;
  timeoutMs?: number;
};

// ─────────────────────────────────────────────────────────────────────────────
// In-memory cache (edge-runtime safe — module-level Map)
// TTL defaults to 60 seconds. Override via IPGEO_CACHE_TTL_MS.
// ─────────────────────────────────────────────────────────────────────────────

type CacheEntry = { data: IpGeoResponse; expiresAt: number };
const geoCache = new Map<string, CacheEntry>();

function getCacheTtlMs(): number {
  const val = Number(process.env.IPGEO_CACHE_TTL_MS || '60000');
  return Number.isNaN(val) || val < 0 ? 60_000 : val;
}

function getCached(ip: string): IpGeoResponse | null {
  const entry = geoCache.get(ip);
  if (!entry) return null;
  if (entry.expiresAt < Date.now()) {
    geoCache.delete(ip);
    return null;
  }
  return entry.data;
}

function setCache(ip: string, data: IpGeoResponse): void {
  const ttl = getCacheTtlMs();
  if (ttl === 0) return; // caching disabled
  geoCache.set(ip, { data, expiresAt: Date.now() + ttl });
}

// ─────────────────────────────────────────────────────────────────────────────
// IP Geolocation lookup
// ─────────────────────────────────────────────────────────────────────────────

export async function lookupIpGeolocation(
  options: LookupOptions
): Promise<IpGeoResponse | null> {
  const { apiKey, ip, includeSecurity = true, timeoutMs = 3000 } = options;

  if (!apiKey || !ip) return null;

  const cached = getCached(ip);
  if (cached) return cached;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  const url = new URL('https://api.ipgeolocation.io/v3/ipgeo');
  url.searchParams.set('apiKey', apiKey);
  url.searchParams.set('ip', ip);
  url.searchParams.set('output', 'json');
  if (includeSecurity) url.searchParams.set('include', 'security');

  try {
    console.log(`[IPGeolocation.io] Looking up ${ip}`);

    const response = await fetch(url.toString(), {
      method: 'GET',
      signal: controller.signal,
      headers: { accept: 'application/json' }
    });

    if (!response.ok) {
      console.error(
        `[IPGeolocation.io] Lookup failed — status ${response.status}:`,
        await response.text()
      );
      return null;
    }

    const data = (await response.json()) as IpGeoResponse;
    setCache(ip, data);
    return data;
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') {
      console.error(
        `[IPGeolocation.io] Lookup timed out after ${timeoutMs}ms for ${ip}`
      );
    } else {
      console.error('[IPGeolocation.io] Lookup error:', error);
    }
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Client IP extraction
// ─────────────────────────────────────────────────────────────────────────────

export function getClientIp(
  headers: Headers,
  trustFirstXff: boolean = false
): string | null {
  const forwardedFor = headers.get('x-forwarded-for');

  if (forwardedFor) {
    const ips = forwardedFor
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);

    if (ips.length === 0) return null;
    return (trustFirstXff ? ips[0] : ips[ips.length - 1]) ?? null;
  }

  return (
    headers.get('x-real-ip') ||
    headers.get('cf-connecting-ip') ||
    null
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Env helpers
// ─────────────────────────────────────────────────────────────────────────────

export function envFlag(value?: string): boolean {
  return String(value ?? '').toLowerCase() === 'true';
}

export function parseCsvEnv(value?: string): Set<string> {
  return new Set(
    String(value ?? '')
      .split(',')
      .map((item) => item.trim().toUpperCase())
      .filter(Boolean)
  );
}

export function parseRedirectMap(value?: string): Record<string, string> {
  if (!value) return {};

  try {
    const parsed = JSON.parse(value) as Record<string, string>;
    return Object.fromEntries(
      Object.entries(parsed).map(([country, path]) => [
        country.toUpperCase(),
        path
      ])
    );
  } catch {
    console.warn(
      '[IPGeolocation.io] Invalid IPGEO_COUNTRY_REDIRECTS JSON (first 120 chars):',
      value.slice(0, 120)
    );
    return {};
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Security block evaluation
// ─────────────────────────────────────────────────────────────────────────────

export function shouldBlockBySecurity(
  security: IpGeoSecurity | undefined
): string | null {
  if (!security) return null;

  if (envFlag(process.env.IPGEO_BLOCK_VPN) && security.is_vpn)
    return 'vpn';
  if (envFlag(process.env.IPGEO_BLOCK_PROXY) && security.is_proxy)
    return 'proxy';
  if (envFlag(process.env.IPGEO_BLOCK_TOR) && security.is_tor)
    return 'tor';
  if (envFlag(process.env.IPGEO_BLOCK_CLOUD_PROVIDER) && security.is_cloud_provider)
    return 'cloud_provider';
  if (envFlag(process.env.IPGEO_BLOCK_BOT) && security.is_bot)
    return 'bot';
  if (envFlag(process.env.IPGEO_BLOCK_SPAM) && security.is_spam)
    return 'spam';
  if (envFlag(process.env.IPGEO_BLOCK_KNOWN_ATTACKER) && security.is_known_attacker)
    return 'known_attacker';

  const threshold = Number(process.env.IPGEO_THREAT_SCORE_BLOCK_THRESHOLD || '');
  if (
    !Number.isNaN(threshold) &&
    threshold > 0 &&
    Number(security.threat_score ?? 0) >= threshold
  ) {
    return 'threat_score';
  }

  return null;
}
