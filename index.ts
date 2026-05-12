// @ipgeolocation/vercel-middleware
// Public API — re-exports everything consumers need

export type { IpGeoResponse, IpGeoSecurity } from './ipgeolocation-edge.js';

export {
  lookupIpGeolocation,
  getClientIp,
  shouldBlockBySecurity,
  parseCsvEnv,
  parseRedirectMap,
  envFlag
} from './ipgeolocation-edge.js';
