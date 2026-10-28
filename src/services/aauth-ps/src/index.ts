/**
 * The AAuth Person Server for the three-party route (issue #836 slices 2
 * and 3): `mission_endpoint` propose and deterministic approval, the
 * owner's read of a mission's exact blob bytes, person tokens with their
 * issued-token records, resource-token `presented_token` verification
 * (AAuth -11 Section 6.7.2 step 3), the mission gate, direct auth token
 * issuance, and the mission control plane of AAuth Mission Management:
 * `status` and `terminate` for the owning agent and configured
 * administrators, local gating, and revocation attempts for every Tracked
 * Credential after termination, with honest residual reporting.
 *
 * Pinned to draft-hardt-oauth-aauth-protocol-11 and
 * draft-hardt-httpbis-signature-key-09 through `@mission/aauth-wire`,
 * which does all RFC 9421, Signature-Key, JWKS and token verification.
 *
 * Durability: missions, issued-token records, the mission log, terminate
 * receipts and revocation attempts are durable SQLite through
 * `@mission/store`'s `openDurableStore`; the replay cache and the
 * security-event list are in memory.
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
  type AdministratorEntry,
  type AgentEntry,
  CONTROL_ACTIONS,
  type ControlAction,
  type DescriptionRule,
  loadPsConfig,
  type ManagementConfig,
  type PersonEntry,
  type PsConfig,
  PsConfigError,
  type PsLifetimes,
  parsePsConfig,
  type RevocationPolicy,
} from "./config.js";
export { SCHEDULER } from "./control.js";
export { canonicalJson, parseStrictJson, type StrictJsonResult } from "./json.js";
export { matchResourceToken, PsError, verifyPresentedToken } from "./presented.js";
export {
  createRevocationWorker,
  type OutboundRequest,
  type OutboundResponse,
  type OutboundTransport,
  type RevocationWorker,
  type RevocationWorkerOptions,
} from "./revocation.js";
export {
  createPersonServer,
  type ListenOptions,
  listen,
  type ManagementOptions,
  type PersonServer,
  type PersonServerOptions,
  PS_PATHS,
  type RunningServer,
  type SecurityEvent,
} from "./server.js";
export {
  type IssuedTokenRecord,
  type MissionControlStore,
  type MissionLogEntry,
  type MissionRecord,
  type MissionState,
  type PsStore,
  type RevocationRecord,
  type RevocationState,
  SqlitePsStore,
  type TerminateRequestRecord,
} from "./store.js";
