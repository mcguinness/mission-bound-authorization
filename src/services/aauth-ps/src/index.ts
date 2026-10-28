/**
 * The AAuth Person Server for the three-party route (issue #836 slice 2):
 * `mission_endpoint` propose and deterministic approval, the owner's read
 * of a mission's exact blob bytes, person tokens with their issued-token
 * records, resource-token `presented_token` verification (AAuth -11
 * Section 6.7.2 step 3), the mission gate, and direct auth token issuance.
 *
 * Pinned to draft-hardt-oauth-aauth-protocol-11 and
 * draft-hardt-httpbis-signature-key-09 through `@mission/aauth-wire`,
 * which does all RFC 9421, Signature-Key, JWKS and token verification.
 *
 * Durability: missions, issued-token records and the mission log are
 * durable SQLite through `@mission/store`'s `openDurableStore`; the replay
 * cache and the security-event list are in memory.
 *
 * Time: whole seconds, the PS's own clock, no tolerance on `exp` or on
 * `expires_at` (a mission is past `expires_at` once the clock reaches it).
 */
export {
  encodeBlob,
  isMissionS256,
  type MissionBlob,
  missionS256,
  parseRfc3339,
  rfc3339,
} from "./blob.js";
export {
  type AgentEntry,
  type DescriptionRule,
  loadPsConfig,
  type PersonEntry,
  type PsConfig,
  PsConfigError,
  type PsLifetimes,
  parsePsConfig,
} from "./config.js";
export { matchResourceToken, PsError, verifyPresentedToken } from "./presented.js";
export {
  createPersonServer,
  type ListenOptions,
  listen,
  type PersonServer,
  type PersonServerOptions,
  PS_PATHS,
  type RunningServer,
  type SecurityEvent,
} from "./server.js";
export {
  type IssuedTokenRecord,
  type MissionLogEntry,
  type MissionRecord,
  type MissionState,
  type PsStore,
  SqlitePsStore,
} from "./store.js";
