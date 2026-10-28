import { createHmac } from "node:crypto";
import type { IncomingMessage } from "node:http";
import {
  BODY_COMPONENTS,
  JwksResolver,
  type ReplayCache,
  SignatureError,
  type VerifiedRequest,
  type VerifiedToken,
  verifyRequest,
} from "@mission/aauth-wire";
import { isMissionS256, missionS256, rfc3339 } from "./blob.js";
import {
  type AdministratorEntry,
  CONTROL_ACTIONS,
  type ControlAction,
  type ManagementConfig,
  type PsConfig,
} from "./config.js";
import { canonicalJson, parseStrictJson } from "./json.js";
import { PsError } from "./presented.js";
import type { RevocationWorker } from "./revocation.js";
import type { MissionControlStore, MissionLogEntry, MissionRecord } from "./store.js";

/** The actor a scheduled expiry is attributed to in the mission log. */
export const SCHEDULER = { id: "ps-scheduler", role: "scheduler" } as const;

/** Termination reasons each admitted caller class may give. */
const REASONS = {
  owning_agent: ["revoked"],
  administrator: ["revoked", "superseded", "administrative"],
} as const;

/** `request_id` length bounds: 22 characters is 128 bits in base64url. */
const REQUEST_ID = /^[\x21-\x7E]{22,255}$/;
const MAX_PURPOSE = 1024;

const invalidRequest = (detail: string) => new PsError(400, "invalid_request", detail);
const serverError = (detail: string) => new PsError(500, "server_error", detail);
/** One response for an absent mission and one the caller may not know of. */
const notFound = () => new PsError(404, "mission_not_found", "no such mission");

/** An authenticated control-plane caller. */
type Caller =
  | {
      role: "owning_agent";
      id: string;
      /** Admitted: the PS admits owning agents, and this is a top-level, allowlisted agent. */
      admitted: boolean;
    }
  | { role: "administrator"; id: string; admin: AdministratorEntry };

/** A control-plane event surfaced to operators, never naming a reference in the clear. */
export interface ControlSecurityEvent {
  type: "control_plane_miss" | "mission_integrity_failure";
  agent: string;
  detail: string;
}

export interface ControlPlaneOptions {
  config: PsConfig;
  management: ManagementConfig;
  store: MissionControlStore;
  /** Discovers agent-provider keys for the owning agent's token. */
  resolver: JwksResolver;
  replayCache: ReplayCache;
  windowSeconds: number;
  endpointOrigin: string;
  now: () => number;
  worker: RevocationWorker;
  surface: (event: ControlSecurityEvent) => void;
  /** Keys the digest a miss is logged under, so the log builds no existence index. */
  probeKey: Buffer;
}

export interface ControlPlane {
  /** Answer `POST {mission_control_endpoint}/{segment}`; throws PsError or SignatureError. */
  handle(
    req: IncomingMessage,
    segment: string,
    body: Buffer,
  ): Promise<{ status: number; body: unknown }>;
}

/**
 * Keys for the control plane: an administrator's enrolled key from its
 * registration, never fetched, and every other key (the owning agent's
 * agent provider) through the PS's own resolver. A `dwk` naming an
 * administrator document is answered only from the registration.
 */
class ControlPlaneResolver extends JwksResolver {
  constructor(
    private readonly network: JwksResolver,
    private readonly administrators: ReadonlyMap<string, AdministratorEntry>,
    private readonly documents: ReadonlySet<string>,
  ) {
    super({
      fetchJson: () => Promise.reject(new Error("the control plane fetches through the PS")),
      admitEgress: () => false,
    });
  }

  override async resolveKey(
    issuer: string,
    dwk: string,
    kid: string,
    options: { refresh?: boolean } = {},
  ): Promise<Record<string, unknown>> {
    if (this.documents.has(dwk)) {
      const admin = this.administrators.get(issuer);
      if (admin && admin.dwk === dwk && admin.kid === kid) return { ...admin.key };
      throw new SignatureError("unknown_key", "no administrator is registered under this key");
    }
    return this.network.resolveKey(issuer, dwk, kid, options);
  }
}

function contentType(req: IncomingMessage): string | undefined {
  return (req.headers["content-type"] ?? "").split(";")[0]?.trim().toLowerCase();
}

/**
 * The mission control plane of AAuth Mission Management: `status` and
 * `terminate` at `{mission_control_endpoint}/{mission_s256}`, for the
 * owning agent (its agent token under `jwt`) and statically configured
 * administrators (an enrolled key under `jwks_uri`).
 *
 * Checks run in this order, so a caller learns nothing about a mission
 * it may not know of: the signature (401); the path segment, the body's
 * Content-Type and JSON, `mission_s256` in the body and `action`
 * (`invalid_request`); the terminate members (`invalid_request`,
 * `invalid_termination_reason`), which depend only on the caller's class;
 * then one lookup keyed by the caller's authorization and `s256` together
 * (`mission_not_found`, identical for an absent mission and one outside
 * the caller's authorization); then the action, under one transaction.
 *
 * @spec mission-aauth-management#endpoint
 * @spec mission-aauth-management#authorization
 * @spec mission-aauth-management#errors
 */
export function createControlPlane(options: ControlPlaneOptions): ControlPlane {
  const { config, management, store, worker } = options;
  const nowS = () => Math.floor(options.now() / 1000);
  const administrators = new Map(management.administrators.map((a) => [a.id, a]));
  const documents = new Set(management.administrators.map((a) => a.dwk));
  const resolver = new ControlPlaneResolver(options.resolver, administrators, documents);

  /**
   * Every control-plane request is signed under the AAuth profile and
   * covers Content-Digest and Content-Type: the owning agent with its
   * agent token (`jwt`), an administrator with its enrolled key
   * (`jwks_uri`). A browser session never authenticates here.
   *
   * @spec mission-aauth-management#endpoint
   * @spec mission-aauth-management#authorization
   */
  const authenticate = (req: IncomingMessage, body: Buffer): Promise<VerifiedRequest> =>
    verifyRequest(
      {
        method: req.method ?? "POST",
        url: `${options.endpointOrigin}${req.url ?? "/"}`,
        headers: req.headers,
        body,
      },
      {
        resolver,
        now: options.now,
        replayCache: options.replayCache,
        requireBodyComponents: true,
        additionalComponents: BODY_COMPONENTS,
        acceptedTokenTypes: ["aa-agent+jwt"],
        acceptedSchemes: documents.size > 0 ? ["jwt", "jwks_uri"] : ["jwt"],
        ...(documents.size > 0 ? { acceptedDocuments: [...documents] } : {}),
        windowSeconds: options.windowSeconds,
      },
    );

  const classify = (verified: VerifiedRequest): Caller => {
    if (verified.scheme === "jwks_uri" && verified.signer) {
      const admin = administrators.get(verified.signer.id);
      if (!admin) throw new SignatureError("unknown_key", "no administrator is registered");
      return { role: "administrator", id: admin.id, admin };
    }
    const token = verified.token as VerifiedToken;
    const id = token.payload.sub as string;
    // @spec mission-aauth-management#authorization: a sub-agent MUST NOT
    // call this endpoint; an Agent Token alone confers no administrative
    // privilege.
    const admitted =
      management.admitOwningAgent &&
      token.payload.parent_agent === undefined &&
      config.agents.has(id);
    return { role: "owning_agent", id, admitted };
  };

  const actorOf = (caller: Caller) => ({ id: caller.id, role: caller.role });
  const policyOf = (caller: Caller) =>
    caller.role === "administrator" ? `administrator:${caller.id}` : "owning-agent";
  const callerKey = (caller: Caller) => `${caller.role} ${caller.id}`;
  const agentsOf = (admin: AdministratorEntry): string[] =>
    [...config.agents.values()].filter((a) => admin.persons.has(a.person)).map((a) => a.agent);

  const digest = (s256: string) =>
    createHmac("sha256", options.probeKey).update(s256).digest("base64url").slice(0, 22);

  /**
   * The mission under the caller's authorization for `action`, by one
   * lookup keyed by that authorization and `s256` together. A caller with
   * no authorization for the action misses without a lookup.
   *
   * @spec mission-aauth-management#errors
   * @spec mission-aauth-management#owning-agent
   */
  const authorized = (caller: Caller, action: ControlAction, s256: string): MissionRecord => {
    let record: MissionRecord | undefined;
    try {
      if (caller.role === "owning_agent") {
        record = caller.admitted ? store.findOwnedMission(caller.id, s256) : undefined;
      } else if (caller.admin.actions.has(action)) {
        record = store.findMissionAmong(agentsOf(caller.admin), s256);
      }
    } catch {
      throw serverError("mission state is unavailable");
    }
    if (!record) {
      options.surface({
        type: "control_plane_miss",
        agent: caller.id,
        detail: `a control-plane reference missed (keyed digest ${digest(s256)})`,
      });
      throw notFound();
    }
    if (missionS256(record.blob) !== s256) {
      options.surface({
        type: "mission_integrity_failure",
        agent: record.agent,
        detail: "a persisted blob fails its s256",
      });
      throw serverError("mission state is unavailable");
    }
    return record;
  };

  /**
   * Expiry is applied before state is read: an active mission at or past
   * `expires_at` is terminated `expired` at that instant, attributed to
   * the PS scheduler. Returns the mission as it now stands.
   *
   * @spec mission-aauth-management#expiry
   */
  const applyExpiry = (record: MissionRecord, at: number): MissionRecord => {
    if (record.state !== "active" || at < record.expiresAt) return record;
    store.terminate(record.agent, record.s256, "expired", record.expiresAt, {
      actor: SCHEDULER,
      decision: "permit",
      policy: "expires_at",
    });
    return store.findOwnedMission(record.agent, record.s256) ?? record;
  };

  /**
   * The residual of a terminated mission at `at`. Counters count Tracked
   * Credentials (Person Tokens and Auth Tokens alike); a credential is
   * confirmed when every recipient it was revoked at answered `200`.
   * `complete` holds only when every credential is confirmed or expired
   * and no untracked access mode could serve the mission, so it stays
   * false while any Person Token is live and unconfirmed (D299).
   * `residual_until` is the latest `exp` among live unconfirmed
   * credentials, omitted when there are none.
   *
   * @spec mission-aauth-management#terminate
   * @spec mission-aauth-management#residuals
   */
  const tokenResidual = (s256: string, at: number): Record<string, unknown> => {
    const tokens = store.missionTokens(s256);
    const byToken = new Map<string, { confirmed: boolean; attempted: boolean }>();
    for (const r of store.revocations(s256)) {
      const k = JSON.stringify([r.iss, r.jti]);
      const seen = byToken.get(k) ?? { confirmed: true, attempted: false };
      seen.confirmed &&= r.state === "confirmed";
      seen.attempted ||= r.attempts > 0;
      byToken.set(k, seen);
    }
    let attempted = 0;
    let confirmed = 0;
    let until: number | undefined;
    for (const t of tokens) {
      const r = byToken.get(JSON.stringify([t.iss, t.jti]));
      if (r?.attempted) attempted += 1;
      if (r?.confirmed) confirmed += 1;
      else if (t.exp > at) until = Math.max(until ?? t.exp, t.exp);
    }
    const residual: Record<string, unknown> = {
      tracked: tokens.length,
      revocation_attempted: attempted,
      revocation_confirmed: confirmed,
    };
    if (until !== undefined) residual.residual_until = rfc3339(until);
    residual.complete = until === undefined && !management.untrackedAccess;
    return residual;
  };

  /**
   * The status representation of `record` as observed at `at`. The blob's
   * own `approved_at` and `expires_at` are reported; the blob itself never
   * is. Terminal members appear exactly when the mission is terminated.
   * This PS accepts no `update`, so `accepted_updates` is 0 and
   * `latest_update_s256` is absent.
   *
   * @spec mission-aauth-management#status
   */
  const representation = (record: MissionRecord, at: number): Record<string, unknown> => {
    let blob: Record<string, unknown>;
    try {
      blob = JSON.parse(record.blob.toString("utf8"));
    } catch {
      throw serverError("mission state is unavailable");
    }
    const body: Record<string, unknown> = {
      mission_s256: record.s256,
      mission_status: record.state,
      approved_at: blob.approved_at,
    };
    if (blob.expires_at !== undefined) body.expires_at = blob.expires_at;
    const terminated = record.state === "terminated";
    if (terminated) {
      body.terminated_at = rfc3339(record.terminatedAt as number);
      body.termination_reason = record.terminationReason;
    }
    body.observed_at = rfc3339(at);
    body.fresh_until = rfc3339(at + management.statusFreshSeconds);
    body.accepted_updates = 0;
    if (terminated) body.token_residual = tokenResidual(record.s256, at);
    return body;
  };

  /** @spec mission-aauth-management#status */
  const status = (caller: Caller, s256: string) => {
    const at = nowS();
    const body = store.atomically(() => {
      const record = applyExpiry(authorized(caller, "status", s256), at);
      const read: MissionLogEntry = {
        s256,
        at,
        event: "status_read",
        detail: { actor: actorOf(caller), decision: "permit", policy: policyOf(caller) },
      };
      store.appendLog([read]);
      return representation(record, at);
    });
    return { status: 200, body };
  };

  /**
   * A replacement must name another mission the caller may reference; a
   * failure is one `invalid_request` whatever held.
   */
  const checkReplacement = (caller: Caller, replacement: string, target: string) => {
    const refused = () =>
      invalidRequest("replacement_s256 does not name a mission this caller may reference");
    if (caller.role !== "administrator" || replacement === target) throw refused();
    let found: MissionRecord | undefined;
    try {
      found = store.findMissionAmong(agentsOf(caller.admin), replacement);
    } catch {
      throw serverError("mission state is unavailable");
    }
    if (!found) throw refused();
  };

  /**
   * `terminate`: validated, then under one transaction the caller's
   * authorization, expiry, the retained outcome of an earlier request with
   * this `request_id`, the replacement, the one active-to-terminated
   * transition with its log entry, revocation work for every unexpired
   * Tracked Credential, and this request's receipt. Revocation starts after
   * the commit; the answer waits at most `immediate_wait_ms` for it.
   *
   * @spec mission-aauth-management#terminate
   * @spec mission-aauth-management#idempotency
   * @spec mission-aauth-management#logging
   * @spec mission-aauth-management#token-consequences
   */
  const terminate = async (caller: Caller, s256: string, params: Record<string, unknown>) => {
    const reason = params.reason;
    if (typeof reason !== "string" || reason === "") throw invalidRequest("reason is required");
    const permitted: readonly string[] =
      caller.role === "administrator" ? REASONS.administrator : REASONS.owning_agent;
    if (!permitted.includes(reason)) {
      throw new PsError(
        400,
        "invalid_termination_reason",
        "the reason is unknown or not permitted for this caller",
      );
    }
    const requestId = params.request_id;
    if (typeof requestId !== "string" || !REQUEST_ID.test(requestId)) {
      throw invalidRequest("request_id must be 22 to 255 visible ASCII characters");
    }
    const purpose = params.purpose;
    if (purpose === undefined) {
      if (caller.role === "administrator") throw invalidRequest("purpose is required");
    } else if (typeof purpose !== "string" || purpose === "" || purpose.length > MAX_PURPOSE) {
      throw invalidRequest(`purpose must be a string of 1 to ${MAX_PURPOSE} characters`);
    }
    const replacement = params.replacement_s256;
    if (reason === "superseded") {
      if (replacement === undefined) throw invalidRequest("replacement_s256 is required");
      if (!isMissionS256(replacement)) throw invalidRequest("replacement_s256 is malformed");
    } else if (replacement !== undefined) {
      throw invalidRequest("replacement_s256 applies only to superseded");
    }
    const canonical = canonicalJson(params);
    const at = nowS();
    const actor = actorOf(caller);
    const policy = policyOf(caller);
    const outcome = store.atomically(() => {
      const record = applyExpiry(authorized(caller, "terminate", s256), at);
      const prior = store.findTerminateRequest(callerKey(caller), requestId);
      if (prior) {
        if (prior.s256 !== s256 || prior.body !== canonical) {
          throw new PsError(
            409,
            "idempotency_conflict",
            "request_id was used for a different request",
          );
        }
        store.appendLog([
          {
            s256,
            at,
            event: "terminate_replayed",
            detail: { actor, decision: "permit", policy, request_id: requestId },
          },
        ]);
        return { transitioned: false, receipt: prior.receipt, agent: record.agent };
      }
      if (reason === "superseded") checkReplacement(caller, replacement as string, s256);
      const tokens = store.missionTokens(s256);
      const live = tokens.filter((t) => t.exp > at);
      const detail: Record<string, unknown> = {
        actor,
        decision: "permit",
        policy,
        request_id: requestId,
      };
      if (purpose !== undefined) detail.purpose = purpose;
      if (replacement !== undefined) detail.replacement_s256 = replacement;
      detail.token_impact = { tracked: tokens.length, revocation_initiated: live.length };
      const transitioned = store.terminate(record.agent, s256, reason, at, detail);
      if (transitioned) {
        store.addRevocations(
          live.map((t) => ({
            iss: t.iss,
            jti: t.jti,
            recipient: t.aud,
            s256,
            kind: t.kind,
            exp: t.exp,
            state: "pending" as const,
            attempts: 0,
            nextAt: at,
            updatedAt: at,
          })),
        );
      } else {
        const later: Record<string, unknown> = {
          actor,
          decision: "permit",
          policy,
          request_id: requestId,
          requested_reason: reason,
        };
        if (purpose !== undefined) later.purpose = purpose;
        store.appendLog([{ s256, at, event: "termination_request_after_terminal", detail: later }]);
      }
      const ended = store.findOwnedMission(record.agent, s256);
      if (ended?.state !== "terminated") throw serverError("the termination did not commit");
      const receipt = {
        mission_s256: s256,
        mission_status: "terminated",
        terminated_at: rfc3339(ended.terminatedAt as number),
        termination_reason: ended.terminationReason,
      };
      store.recordTerminateRequest({
        caller: callerKey(caller),
        requestId,
        s256,
        body: canonical,
        receipt,
        at,
      });
      return { transitioned, receipt, agent: record.agent };
    });

    if (outcome.transitioned) {
      const wait = management.revocation.immediateWaitMs;
      const run = worker.runDue();
      if (wait > 0) {
        let timer: ReturnType<typeof setTimeout> | undefined;
        await Promise.race([
          run,
          new Promise<void>((resolve) => {
            timer = setTimeout(resolve, wait);
          }),
        ]);
        clearTimeout(timer);
      }
    }
    const observed = nowS();
    const record = store.findOwnedMission(outcome.agent, s256);
    if (!record) throw serverError("mission state is unavailable");
    // A replay repeats the committed receipt exactly; the rest is as observed now.
    return { status: 200, body: { ...representation(record, observed), ...outcome.receipt } };
  };

  return {
    async handle(req, segment, body) {
      const caller = classify(await authenticate(req, body));
      if (!isMissionS256(segment)) {
        throw invalidRequest("the mission_s256 path segment is malformed");
      }
      if (contentType(req) !== "application/json") {
        throw invalidRequest("Content-Type is not application/json");
      }
      const parsed = parseStrictJson(body.toString("utf8"));
      if (!parsed.ok) throw invalidRequest(`the body is not acceptable JSON (${parsed.why})`);
      const params = parsed.value;
      if (typeof params !== "object" || params === null || Array.isArray(params)) {
        throw invalidRequest("the body is not a JSON object");
      }
      const members = params as Record<string, unknown>;
      // The mission's identity comes from the path and from nowhere else.
      if (Object.hasOwn(members, "mission_s256")) {
        throw invalidRequest("the body must not carry mission_s256");
      }
      const action = members.action;
      if (action === undefined) throw invalidRequest("action is required");
      if (typeof action !== "string" || !(CONTROL_ACTIONS as readonly string[]).includes(action)) {
        throw invalidRequest("action is not recognized");
      }
      if (action === "status") return status(caller, segment);
      return terminate(caller, segment, members);
    },
  };
}
