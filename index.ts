// =============================================================================
// ipgeolocation-vercel-middleware
//
// Public API. The middleware itself lives at the ./middleware subpath so that
// importing these helpers into a Server Component or a Route Handler does not
// pull next/server into the bundle.
// =============================================================================

export type {
  ClientIpOptions,
  GeoHeaderMap,
  IpGeoLocation,
  IpGeoResponse,
  IpGeoSecurity,
  LogLevel,
  LookupFailureReason,
  LookupOptions,
  LookupResult,
  SecurityBlockReason,
  SecurityRules
} from './ipgeolocation-edge.js';

export {
  IPGEO_API_BASE_URL,
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
  stripSpoofedGeoHeaders
} from './ipgeolocation-edge.js';
