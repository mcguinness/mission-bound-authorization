import { createHmac, randomBytes, randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import {
  generateSigningKey,
  InMemoryReplayCache,
  isServerIdentifier,
  type JwksResolver,
  mintToken,
  type ReplayCache,
  SignatureError,
  type SigningKey,
  type VerifiedRequest,
  type VerifiedToken,
  verifyRequest,
  verifyResourceToken,
} from "@mission/aauth-wire";
import {
  encodeBlob,
  isMissionS256,
  type MissionBlob,
  missionS256,
  parseRfc3339,
  rfc3339,
} from "./blob.js";
import type { AgentEntry, PsConfig } from "./config.js";
import { CONTROL_ACTIONS } from "./config.js";
import { type ControlPlane, createControlPlane, SCHEDULER } from "./control.js";
import { matchResourceToken, PsError, verifyPresentedToken } from "./presented.js";
import {
  createRevocationWorker,
  type OutboundTransport,
  type RevocationWorker,
} from "./revocation.js";
import type {
  IssuedTokenRecord,
  MissionControlStore,
  MissionLogEntry,
  MissionRecord,
  PsStore,
} from "./store.js";

/** The PS's endpoint paths, under its endpoint origin. */
export const PS_PATHS = {
  metadata: "/.well-known/aauth-person.json",
  jwks: "/.well-known/jwks.json",
  person: "/person",
  token: "/token",
  mission: "/mission",
  missionControl: "/mission-control",
} as const;

/** What the mission control plane needs beyond the PS itself. */
export interface ManagementOptions {
  /**
   * The same durable store as `store`, with the control plane's records:
   * a termination, its receipt and its revocation work commit together,
   * and every issuance path reads the state they wrote.
   */
  store: MissionControlStore;
  /** Sends revocation requests and resource-metadata fetches; the egress boundary. */
  transport: OutboundTransport;
  /** Wait `ms`. Default: a timer. */
  sleep?: (ms: number) => Promise<void>;
  /**
   * When the server listens, revocation work due is attempted at once and
   * then every this many milliseconds. Default 1000; 0 runs it only when a
   * termination commits or a caller asks (`revocations.runDue()`).
   */
  pollIntervalMs?: number;
}

export interface PersonServerOptions {
  config: PsConfig;
  store: PsStore;
  /** Discovers agent-provider, resource and person-server keys, under egress admission. */
  resolver: JwksResolver;
  /** The PS's signing key; generated per boot from `config.signingKey` when absent. */
  signingKey?: SigningKey;
  /** Milliseconds since the epoch. */
  now?: () => number;
  replayCache?: ReplayCache;
  /** Signature validity window in seconds. Default 60. */
  windowSeconds?: number;
  /**
   * The origin metadata publishes the endpoints under, and the one a
   * signature over a request to them covers: the signature base is built
   * from this origin and the raw request target, never from the request's
   * Host field, so a request signed for another server does not verify
   * here. Default: the issuer.
   */
  endpointOrigin?: string;
  /**
   * The mission control plane (AAuth Mission Management). It is served,
   * and published in metadata, only when this is given and the
   * configuration has `management`.
   */
  management?: ManagementOptions;
}

/**
 * An event surfaced to operators (AAuth -11 Section 6.7.2: tampering
 * evidence; the management companion's security log of control-plane
 * misses, which names a reference only by a keyed digest).
 */
export interface SecurityEvent {
  at: number;
  type:
    | "presented_token_mismatch"
    | "mission_integrity_failure"
    | "unowned_mission_reference"
    | "control_plane_miss";
  agent: string;
  detail: string;
}

export interface PersonServer {
  /** The Node request handler. */
  handler: (req: IncomingMessage, res: ServerResponse) => Promise<void>;
  /** Bind the handler on loopback (default `127.0.0.1`, an ephemeral port). */
  listen(options?: ListenOptions): Promise<RunningServer>;
  issuer: string;
  signingKey: SigningKey;
  store: PsStore;
  securityEvents: SecurityEvent[];
  /** The revocation work after termination; present with the control plane. */
  revocations?: RevocationWorker;
}

const NOT_THIS_AGENTS_MISSION = "mission_s256 does not name a mission of this agent";
const MAX_BODY_BYTES = 64 * 1024;
const MAX_SECURITY_EVENTS = 1000;

const invalidRequest = (detail: string) => new PsError(400, "invalid_request", detail);
const serverError = (detail: string) => new PsError(500, "server_error", detail);

/** Only the public members of a JWK. */
function publicJwk(jwk: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const name of ["kty", "crv", "x", "y", "n", "e", "alg"]) {
    if (jwk[name] !== undefined) out[name] = jwk[name];
  }
  return out;
}

function jsonObject(body: Buffer): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body.toString("utf8"));
  } catch {
    throw invalidRequest("the body is not JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw invalidRequest("the body is not a JSON object");
  }
  return parsed as Record<string, unknown>;
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new PsError(413, "invalid_request", "the body is too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

/**
 * Metadata and JWKS are cacheable: verifiers MUST cache JWKS responses and
 * SHOULD respect HTTP cache headers (AAuth -11 Section 11.4).
 */
const CACHEABLE = { "cache-control": "max-age=300" };

function send(
  res: ServerResponse,
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): void {
  const contentType = status >= 400 ? "application/problem+json" : "application/json";
  res.writeHead(status, { "content-type": contentType, "cache-control": "no-store", ...headers });
  res.end(JSON.stringify(body));
}

/**
 * The AAuth Person Server for the three-party route: its metadata and
 * JWKS, `mission_endpoint` (propose with deterministic approval, and the
 * owner's read of `{mission_endpoint}/{mission_s256}`), the person token
 * endpoint and the auth token endpoint in PS authorization access, and,
 * when configured, the mission control plane of AAuth Mission Management
 * (`status` and `terminate`, with revocation attempts after termination).
 *
 * Every endpoint authenticates the caller by an HTTP Message Signature
 * under the Signature-Key `jwt` scheme presenting an agent token (AAuth
 * -11 Section 11.3); a body request must cover Content-Digest and
 * Content-Type. The control plane also admits a configured administrator
 * signing under `jwks_uri` with an enrolled key. The PS signs tokens, and
 * its revocation requests under `jwks_uri`, with the key its `jwks_uri`
 * publishes.
 *
 * @spec aauth#section-7
 * @spec aauth#section-8
 */
export function createPersonServer(options: PersonServerOptions): PersonServer {
  const { config, store, resolver } = options;
  const issuer = config.issuer;
  const now = options.now ?? Date.now;
  const replayCache = options.replayCache ?? new InMemoryReplayCache();
  const signingKey =
    options.signingKey ?? generateSigningKey(config.signingKey.alg, config.signingKey.kid);
  const kid = signingKey.publicJwk.kid ?? config.signingKey.kid;
  const minter = { alg: signingKey.alg, privateKey: signingKey.privateKey, kid };
  const endpointOrigin = options.endpointOrigin ?? issuer;
  const securityEvents: SecurityEvent[] = [];

  const surface = (event: Omit<SecurityEvent, "at">) => {
    securityEvents.push({ at: Math.floor(now() / 1000), ...event });
    if (securityEvents.length > MAX_SECURITY_EVENTS) securityEvents.shift();
  };

  const metadata: Record<string, unknown> = {
    issuer,
    jwks_uri: `${issuer}${PS_PATHS.jwks}`,
    person_token_endpoint: `${endpointOrigin}${PS_PATHS.person}`,
    auth_token_endpoint: `${endpointOrigin}${PS_PATHS.token}`,
    mission_endpoint: `${endpointOrigin}${PS_PATHS.mission}`,
  };
  const jwks = { keys: [{ ...signingKey.publicJwk, kid, use: "sig" }] };
  const windowSeconds = options.windowSeconds ?? 60;

  /**
   * The mission control plane, when configured: `mission_control_endpoint`
   * and the actions it implements are published, and terminations start
   * revocation work.
   *
   * @spec mission-aauth-management#metadata
   */
  let control: ControlPlane | undefined;
  let revocations: RevocationWorker | undefined;
  if (options.management && !config.management) {
    throw new TypeError("the control plane needs the configuration's management member");
  }
  if (options.management && config.management) {
    revocations = createRevocationWorker({
      issuer,
      signingKey,
      kid,
      store: options.management.store,
      policy: config.management.revocation,
      transport: options.management.transport,
      now,
      sleep:
        options.management.sleep ??
        ((ms) => new Promise((resolve) => setTimeout(resolve, Math.max(0, ms)))),
    });
    control = createControlPlane({
      config,
      management: config.management,
      store: options.management.store,
      resolver,
      replayCache,
      windowSeconds,
      endpointOrigin,
      now,
      worker: revocations,
      surface: (event) => surface(event),
      probeKey: randomBytes(32),
    });
    metadata.mission_control_endpoint = `${endpointOrigin}${PS_PATHS.missionControl}`;
    metadata.mission_control_actions_supported = [...CONTROL_ACTIONS];
  }

  /**
   * A sub-agent never calls the PS directly (AAuth -11 Sections 10.2.2 and
   * 10.2.3), whatever the allowlist names; otherwise the deterministic
   * approver's agent allowlist, which is also the agent-person binding.
   */
  const requireAgent = (agentToken: VerifiedToken): AgentEntry => {
    if (agentToken.payload.parent_agent !== undefined) {
      throw new PsError(403, "denied", "a sub-agent does not call the person server directly");
    }
    const entry = config.agents.get(agentToken.payload.sub as string);
    if (!entry) {
      throw new PsError(
        403,
        "user_unreachable",
        "this person server has no person bound to this agent",
      );
    }
    return entry;
  };

  const terminated = (reason: string | undefined) =>
    new PsError(403, "mission_terminated", "the mission is no longer active", {
      mission_status: "terminated",
      ...(reason === undefined ? {} : { termination_reason: reason }),
    });

  /**
   * Ownership first, then state: the mission is looked up under the
   * requesting agent, so another agent's mission (active or terminated)
   * misses exactly as an absent one does and never reaches the state
   * check. A read that cannot establish state, or a persisted blob that no
   * longer digests to its `s256`, fails closed. A mission past
   * `expires_at` is terminated with reason `expired`.
   *
   * @spec aauth#section-8.2
   * @spec aauth#section-8.7
   * @spec aauth#section-8.8
   * @spec mission-aauth#reference
   */
  const gateMission = (
    agent: string,
    s256: string,
    nowS: number,
    notFound: () => PsError,
  ): MissionRecord => {
    let record: MissionRecord | undefined;
    try {
      record = store.findOwnedMission(agent, s256);
    } catch {
      throw serverError("mission state is unavailable");
    }
    if (!record) {
      surface({ type: "unowned_mission_reference", agent, detail: "a mission reference missed" });
      throw notFound();
    }
    if (missionS256(record.blob) !== s256) {
      surface({
        type: "mission_integrity_failure",
        agent,
        detail: "a persisted blob fails its s256",
      });
      throw serverError("mission state is unavailable");
    }
    if (record.state === "terminated") throw terminated(record.terminationReason);
    if (nowS >= record.expiresAt) {
      try {
        store.terminate(agent, s256, "expired", record.expiresAt, {
          actor: SCHEDULER,
          decision: "permit",
          policy: "expires_at",
        });
      } catch {
        // The refusal stands whether or not the transition was recorded.
      }
      throw terminated("expired");
    }
    return record;
  };

  const pairwiseSub = (person: string, resource: string): string =>
    createHmac("sha256", store.pairwiseKey()).update(`${person}\n${resource}`).digest("base64url");

  /**
   * The agent token that authenticated the request expired before its
   * issuance committed: the token in Signature-Key has no token endpoint
   * code, so the answer is 401 with Signature-Error (AAuth -11 Section
   * 11.9.3).
   */
  const agentTokenExpired = () =>
    new SignatureError("expired_jwt", "the agent token expired before the issuance committed");

  /**
   * The claims and record of a person token for `resource`, built without
   * an await so a caller can check them and write the record at the time
   * it read: `sub` pairwise for the agent's person at that resource,
   * `cnf.jwk` the key that signed the request, and `exp` capped at the
   * one-hour ceiling, the presenting agent token's `exp` and the mission's
   * `expires_at`. A token whose `exp` is not after `nowS` is refused, never
   * minted already expired.
   *
   * @spec aauth#section-7.1.2
   * @spec aauth#section-14.1
   */
  const personTokenFor = (
    entry: AgentEntry,
    agentToken: VerifiedToken,
    signerJwk: Record<string, unknown>,
    resource: string,
    mission: { s256: string; expiresAt: number } | undefined,
    nowS: number,
  ): { claims: Record<string, unknown>; record: IssuedTokenRecord; expiresIn: number } => {
    const person = config.persons.get(entry.person);
    if (!person) throw serverError("the agent's person is not configured");
    const caps = [nowS + config.lifetimes.personTokenSeconds, agentToken.payload.exp as number];
    if (mission) caps.push(mission.expiresAt);
    const exp = Math.min(...caps);
    if (exp <= nowS) throw agentTokenExpired();
    const jti = randomUUID();
    const sub = pairwiseSub(person.id, resource);
    const claims: Record<string, unknown> = {
      iss: issuer,
      dwk: "aauth-person.json",
      aud: resource,
      sub,
      jti,
      iat: nowS,
      exp,
      cnf: { jwk: publicJwk(signerJwk) },
    };
    if (mission) claims.mission_s256 = mission.s256;
    if (person.tenant !== undefined) claims.tenant = person.tenant;
    const record: IssuedTokenRecord = {
      iss: issuer,
      jti,
      kind: "person",
      aud: resource,
      exp,
      sub,
      agent: entry.agent,
      issuedAt: nowS,
    };
    if (mission) record.missionS256 = mission.s256;
    return { claims, record, expiresIn: exp - nowS };
  };

  const mint = (typ: "aa-person+jwt" | "aa-auth+jwt", claims: Record<string, unknown>) =>
    mintToken(typ, claims, minter);

  const record = (issued: IssuedTokenRecord[], log: MissionLogEntry[]) => {
    try {
      store.recordIssued(issued, log);
    } catch {
      throw serverError("the issued token could not be recorded");
    }
  };

  /**
   * Refuse parameters for paths this PS does not implement, rather than
   * ignoring them: an ignored `upstream_token` would issue for the wrong
   * person.
   */
  const refuseUnsupported = (params: Record<string, unknown>) => {
    if ("upstream_token" in params || "subagent_token" in params) {
      throw invalidRequest("call chaining and sub-agent requests are not supported here");
    }
  };

  /** @spec mission-aauth#ref-propagation: a governed agent's missionless token request. */
  const governedMissionless = () =>
    new PsError(
      403,
      "denied",
      "this agent is under mission governance; a missionless request is refused",
    );

  /**
   * POST {mission_endpoint}: the agent proposes, the deterministic
   * approver decides at once (agent allowlist, then description rules in
   * order), and an approval returns the blob bytes, their `s256` and a
   * person token for each approved resource. Every approved mission
   * carries `expires_at` (the binding's Lifecycle rule).
   *
   * @spec aauth#section-8.1
   * @spec aauth#section-8.2
   */
  const propose = async (
    res: ServerResponse,
    verified: VerifiedRequest,
    params: Record<string, unknown>,
  ) => {
    const agentToken = verified.token as VerifiedToken;
    const agent = agentToken.payload.sub as string;
    const entry = requireAgent(agentToken);
    const nowMs = now();
    const nowS = Math.floor(nowMs / 1000);
    if (typeof params.description !== "string" || params.description.trim() === "") {
      throw invalidRequest("description is required");
    }
    const description = params.description;
    let tools: { name: string; description: string }[] | undefined;
    if (params.tools !== undefined) {
      if (!Array.isArray(params.tools)) throw invalidRequest("tools is not an array");
      tools = params.tools.map((tool) => {
        const t = tool as { name?: unknown; description?: unknown } | null;
        if (
          typeof t !== "object" ||
          t === null ||
          typeof t.name !== "string" ||
          typeof t.description !== "string"
        ) {
          throw invalidRequest("each tool needs a name and a description");
        }
        return { name: t.name, description: t.description };
      });
    }
    let resources: string[] | undefined;
    if (params.resources !== undefined) {
      if (!Array.isArray(params.resources)) throw invalidRequest("resources is not an array");
      resources = [];
      for (const r of params.resources) {
        if (!isServerIdentifier(r))
          throw invalidRequest("each resource must be a server identifier");
        if (resources.includes(r)) throw invalidRequest("resources names a resource twice");
        resources.push(r);
      }
    }
    let requestedExpiry: number | undefined;
    if (params.expires_at !== undefined) {
      requestedExpiry = parseRfc3339(params.expires_at);
      if (requestedExpiry === undefined)
        throw invalidRequest("expires_at is not an RFC 3339 date-time");
      if (requestedExpiry <= nowS) throw invalidRequest("expires_at is not later than approval");
    }

    const lowered = description.toLowerCase();
    const rule = config.descriptionRules.find((r) => lowered.includes(r.contains.toLowerCase()));
    if ((rule?.decision ?? config.defaultDecision) === "deny") {
      throw new PsError(403, "denied", "the approver denied the mission proposal");
    }

    const expiresAt = Math.min(
      requestedExpiry ?? nowS + config.lifetimes.missionDefaultSeconds,
      nowS + config.lifetimes.missionMaxSeconds,
    );
    const blob: MissionBlob = {
      agent,
      approved_at: new Date(nowMs).toISOString(),
      expires_at: rfc3339(expiresAt),
      description,
    };
    if (tools) blob.approved_tools = tools;
    if (resources) blob.approved_resources = resources;
    const bytes = encodeBlob(blob);
    const s256 = missionS256(bytes);

    // From the time read above to the approval's commit nothing awaits, so
    // every check holds at the moment the mission and its person tokens are
    // recorded; the tokens are minted after, from claims already fixed.
    const built = (resources ?? []).map((resource) =>
      personTokenFor(entry, agentToken, verified.publicJwk, resource, { s256, expiresAt }, nowS),
    );
    const issued = built.map((t) => t.record);
    const mission: MissionRecord = {
      agent,
      s256,
      blob: bytes,
      approvedAt: nowS,
      expiresAt,
      state: "active",
    };
    try {
      store.approve(mission, issued, {
        s256,
        at: nowS,
        event: "approved",
        detail: { person_tokens: issued.map((t) => ({ jti: t.jti, aud: t.aud })) },
      });
    } catch {
      throw serverError("the approved mission could not be recorded");
    }
    const personTokens: Record<string, string> = {};
    for (const t of built) personTokens[t.record.aud] = await mint("aa-person+jwt", t.claims);
    const body: Record<string, unknown> = { s256, mission: bytes.toString("base64url") };
    if (resources) body.person_tokens = personTokens;
    send(res, 200, body);
  };

  /**
   * GET {mission_endpoint}/{mission_s256}: the owning agent reads the
   * exact blob bytes the PS persisted. A local read surface; AAuth -11
   * defines only POST at this URL. A malformed segment is
   * `invalid_request`; an absent mission and another agent's mission get
   * the same `mission_not_found`; only the owner learns `mission_terminated`.
   *
   * @spec aauth#section-8.2.1
   * @spec aauth#section-8.7
   */
  const retrieve = (res: ServerResponse, verified: VerifiedRequest, segment: string) => {
    const agentToken = verified.token as VerifiedToken;
    const agent = agentToken.payload.sub as string;
    requireAgent(agentToken);
    if (!isMissionS256(segment)) throw invalidRequest("the mission_s256 path segment is malformed");
    const record = gateMission(
      agent,
      segment,
      Math.floor(now() / 1000),
      () => new PsError(404, "mission_not_found", "no such mission"),
    );
    send(res, 200, { s256: record.s256, mission: record.blob.toString("base64url") });
  };

  /**
   * POST {person_token_endpoint}.
   *
   * @spec aauth#section-7.1
   * @spec mission-aauth#ref-propagation
   */
  const personToken = async (
    res: ServerResponse,
    verified: VerifiedRequest,
    params: Record<string, unknown>,
  ) => {
    const agentToken = verified.token as VerifiedToken;
    const agent = agentToken.payload.sub as string;
    const entry = requireAgent(agentToken);
    refuseUnsupported(params);
    const resource = params.resource;
    if (!isServerIdentifier(resource)) {
      throw invalidRequest("resource is missing or is not a server identifier");
    }
    // Read after the request was authenticated; from here to the record
    // nothing awaits, so the mission gate and the `exp` cap hold at the
    // moment the token is recorded. It is minted after, from fixed claims.
    const nowS = Math.floor(now() / 1000);
    let mission: MissionRecord | undefined;
    if (params.mission_s256 !== undefined) {
      if (!isMissionS256(params.mission_s256)) throw invalidRequest("mission_s256 is malformed");
      mission = gateMission(agent, params.mission_s256, nowS, () =>
        invalidRequest(NOT_THIS_AGENTS_MISSION),
      );
    } else if (entry.missionGoverned) {
      throw governedMissionless();
    }
    const minted = personTokenFor(entry, agentToken, verified.publicJwk, resource, mission, nowS);
    const log: MissionLogEntry[] = mission
      ? [
          {
            s256: mission.s256,
            at: nowS,
            event: "person_token_issued",
            detail: { jti: minted.record.jti, aud: resource },
          },
        ]
      : [];
    record([minted.record], log);
    const jwt = await mint("aa-person+jwt", minted.claims);
    send(res, 200, { person_token: jwt, expires_in: minted.expiresIn });
  };

  /**
   * POST {auth_token_endpoint}, PS authorization access: the resource
   * token verified (Section 6.7.2 steps 1 and 2), the presented token
   * verified against it (step 3), `ps` naming this PS, the mission gate
   * (step 4), then an auth token issued directly with `mission_s256`
   * copied from the resource token.
   *
   * @spec aauth#section-6.7.2
   * @spec aauth#section-7.2
   * @spec aauth#section-9.4.1
   * @spec mission-aauth#ref-propagation
   */
  const authToken = async (
    res: ServerResponse,
    verified: VerifiedRequest,
    params: Record<string, unknown>,
  ) => {
    const agentToken = verified.token as VerifiedToken;
    const agent = agentToken.payload.sub as string;
    const entry = requireAgent(agentToken);
    refuseUnsupported(params);
    if (typeof params.resource_token !== "string" || params.resource_token === "") {
      throw invalidRequest("resource_token is required");
    }
    if (typeof params.presented_token !== "string" || params.presented_token === "") {
      throw invalidRequest("presented_token is required");
    }
    const nowMs = now();
    const nowS = Math.floor(nowMs / 1000);

    // Steps 1 and 2: aud names this PS; agent_jkt is the request's key.
    let resourceToken: VerifiedToken;
    try {
      resourceToken = await verifyResourceToken(params.resource_token, {
        resolver,
        now: () => nowMs,
        audience: issuer,
        agentJkt: verified.thumbprint,
      });
    } catch (err) {
      if (!(err instanceof SignatureError)) throw err;
      if (err.code === "expired_jwt") {
        throw new PsError(400, "expired_resource_token", "the resource token has expired");
      }
      throw new PsError(400, "invalid_resource_token", err.detail);
    }

    // Step 3.
    const presented = await verifyPresentedToken(
      params.presented_token,
      resourceToken,
      resolver,
      nowMs,
    );
    try {
      matchResourceToken(presented, resourceToken);
    } catch (err) {
      if (err instanceof PsError)
        surface({ type: "presented_token_mismatch", agent, detail: err.detail });
      throw err;
    }
    const rt = resourceToken.payload;
    if (rt.ps !== issuer)
      throw new PsError(400, "invalid_resource_token", "ps does not name this person server");

    // Step 4: the mission is this agent's, active and unexpired.
    let mission: MissionRecord | undefined;
    const notFound = () => new PsError(400, "invalid_resource_token", NOT_THIS_AGENTS_MISSION);
    if (rt.mission_s256 !== undefined) {
      if (typeof rt.mission_s256 !== "string") throw notFound();
      mission = gateMission(agent, rt.mission_s256, nowS, notFound);
    } else if (entry.missionGoverned) {
      throw governedMissionless();
    }

    // @spec aauth#section-7.2.3: a resource token carrying `interaction`
    // needs the resource's own user-facing flow completed before any auth
    // token. This PS has no interaction surface and no channel to the
    // person, so it refuses, whatever the claim holds.
    if (rt.interaction !== undefined) {
      throw new PsError(
        403,
        "user_unreachable",
        "the resource requires an interaction this person server cannot conduct",
      );
    }

    // The issuance commit. Key resolution and verification above awaited,
    // and time passed: the clock is read again, and every time- and
    // state-dependent check runs again at that time, with no await before
    // the record is written. The token is minted after, from fixed claims.
    const at = Math.floor(now() / 1000);
    if ((rt.exp as number) <= at) {
      throw new PsError(400, "expired_resource_token", "the resource token has expired");
    }
    if ((presented.payload.exp as number) <= at) {
      throw new PsError(400, "expired_presented_token", "the presented token has expired");
    }
    if (mission) mission = gateMission(agent, mission.s256, at, notFound);
    const caps = [
      at + config.lifetimes.authTokenSeconds,
      agentToken.payload.exp as number,
      presented.payload.exp as number,
    ];
    if (mission) caps.push(mission.expiresAt);
    const exp = Math.min(...caps);
    if (exp <= at) throw agentTokenExpired();
    const jti = randomUUID();
    const claims: Record<string, unknown> = {
      iss: issuer,
      dwk: "aauth-person.json",
      aud: rt.iss,
      ps: issuer,
      sub: rt.sub,
      jti,
      iat: at,
      exp,
      cnf: { jwk: publicJwk(verified.publicJwk) },
    };
    for (const name of ["scope", "account", "tenant"] as const) {
      if (typeof rt[name] === "string") claims[name] = rt[name];
    }
    if (mission) claims.mission_s256 = mission.s256;
    const issued: IssuedTokenRecord = {
      iss: issuer,
      jti,
      kind: "auth",
      aud: rt.iss as string,
      exp,
      sub: rt.sub as string,
      agent,
      issuedAt: at,
    };
    const log: MissionLogEntry[] = [];
    if (mission) {
      issued.missionS256 = mission.s256;
      const detail: Record<string, unknown> = { jti, aud: rt.iss, presented_jti: rt.presented_jti };
      if (typeof rt.scope === "string") detail.scope = rt.scope;
      if (typeof params.justification === "string") detail.justification = params.justification;
      log.push({ s256: mission.s256, at, event: "auth_token_issued", detail });
    }
    record([issued], log);
    const jwt = await mint("aa-auth+jwt", claims);
    send(res, 200, { auth_token: jwt, expires_in: exp - at });
  };

  const authenticate = async (req: IncomingMessage, body: Buffer): Promise<VerifiedRequest> => {
    return verifyRequest(
      {
        method: req.method ?? "GET",
        url: `${endpointOrigin}${req.url ?? "/"}`,
        headers: req.headers,
        body,
      },
      {
        resolver,
        now,
        replayCache,
        requireBodyComponents: true,
        acceptedTokenTypes: ["aa-agent+jwt"],
        windowSeconds,
      },
    );
  };

  const handler = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    try {
      const path = (req.url ?? "/").split("?")[0] ?? "/";
      const method = req.method ?? "GET";
      if (path === PS_PATHS.metadata || path === PS_PATHS.jwks) {
        if (method !== "GET")
          return send(
            res,
            405,
            { error: "invalid_request", detail: "method not allowed" },
            { allow: "GET" },
          );
        return send(res, 200, path === PS_PATHS.metadata ? metadata : jwks, CACHEABLE);
      }
      // @spec mission-aauth-management#endpoint: every action is a POST to
      // a mission's own control-plane URL; none is defined at the bare URL.
      if (control && path.startsWith(`${PS_PATHS.missionControl}/`)) {
        if (method !== "POST") {
          return send(
            res,
            405,
            { error: "invalid_request", detail: "method not allowed" },
            { allow: "POST" },
          );
        }
        const segment = path.slice(PS_PATHS.missionControl.length + 1);
        const answer = await control.handle(req, segment, await readBody(req));
        return send(res, answer.status, answer.body);
      }
      const missionUrl = path.startsWith(`${PS_PATHS.mission}/`)
        ? path.slice(PS_PATHS.mission.length + 1)
        : undefined;
      const posts = [PS_PATHS.person, PS_PATHS.token, PS_PATHS.mission] as string[];
      if (!posts.includes(path) && missionUrl === undefined) {
        return send(res, 404, { error: "invalid_request", detail: "no such endpoint" });
      }
      const allowed = missionUrl === undefined ? "POST" : "GET";
      if (method !== allowed) {
        return send(
          res,
          405,
          { error: "invalid_request", detail: "method not allowed" },
          { allow: allowed },
        );
      }
      const body = await readBody(req);
      let verified: VerifiedRequest;
      try {
        verified = await authenticate(req, body);
      } catch (err) {
        if (err instanceof SignatureError) {
          return send(res, 401, { error: err.code, detail: err.detail }, err.headers);
        }
        throw err;
      }
      if (missionUrl !== undefined) return retrieve(res, verified, missionUrl);
      const params = jsonObject(body);
      if (path === PS_PATHS.person) return await personToken(res, verified, params);
      if (path === PS_PATHS.token) return await authToken(res, verified, params);
      return await propose(res, verified, params);
    } catch (err) {
      if (err instanceof PsError) {
        return send(res, err.status, { error: err.code, detail: err.detail, ...err.extra });
      }
      // The request's own token failing after authentication: the agent
      // token expired before an issuance committed.
      if (err instanceof SignatureError) {
        return send(res, 401, { error: err.code, detail: err.detail }, err.headers);
      }
      return send(res, 500, { error: "server_error", detail: "internal error" });
    }
  };

  const pollIntervalMs = options.management?.pollIntervalMs ?? 1000;
  const server: PersonServer = {
    handler,
    /**
     * Listen, and with the control plane resume revocation work: what is
     * due runs at once, after a restart included, then on the interval.
     *
     * @spec mission-aauth-management#races-and-failures
     */
    listen: async (listenOptions) => {
      const running = await listen(handler, listenOptions);
      if (!revocations || pollIntervalMs <= 0) return running;
      const worker = revocations;
      worker.start(pollIntervalMs);
      return {
        ...running,
        close: async () => {
          worker.stop();
          await running.close();
        },
      };
    },
    issuer,
    signingKey,
    store,
    securityEvents,
  };
  if (revocations) server.revocations = revocations;
  return server;
}

export interface ListenOptions {
  /** Default 0, an ephemeral port. */
  port?: number;
  /** Default `127.0.0.1`. */
  host?: string;
}

export interface RunningServer {
  server: Server;
  /** `http://host:port`, where the server listens (a transport address, not an identifier). */
  origin: string;
  port: number;
  close(): Promise<void>;
}

/** Serve `handler` over HTTP on loopback. */
export function listen(
  handler: (req: IncomingMessage, res: ServerResponse) => Promise<void>,
  options: ListenOptions = {},
): Promise<RunningServer> {
  const host = options.host ?? "127.0.0.1";
  const server = createServer((req, res) => {
    void handler(req, res);
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port ?? 0, host, () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      const shown = host.includes(":") ? `[${host}]` : host;
      resolve({
        server,
        origin: `http://${shown}:${port}`,
        port,
        close: () =>
          new Promise<void>((done) => {
            server.closeAllConnections();
            server.close(() => done());
          }),
      });
    });
  });
}
