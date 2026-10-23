/**
 * @spec authority-server#join-assertion, authority-server#join-assertion-request,
 * authority-server#join-assertion-artifact, authority-server#submission-errors (#1454):
 * the MAS's Mission Join Assertion endpoint.
 *
 * The caller (a PEP, or the client acting for it) asks the MAS to verify the
 * join of an acting estate credential to a Mission centrally and to mint a
 * signed, sender-bound assertion of it for one consuming PDP.
 *
 * - Caller authentication. Private-key JWT, the Mission Status endpoint's
 *   authenticator (`authenticateLifecycleClient`, #1407), with the
 *   assertion's `aud` naming this endpoint, as §join-assertion requires.
 *   The request body is JSON, so `client_assertion_type` and
 *   `client_assertion` travel as top-level JSON members; the draft names no
 *   carriage for a JSON body (a reported gap).
 * - Visibility. A Mission is visible to its `client_id` and to the clients
 *   enrolled (`enrolledJoinPdps`, keyed by client) for the Mission's
 *   enforcement scope: an enrolled scope that some entry of the Mission's
 *   Authority Set overlaps, under the matcher Mission Status scopes its
 *   entries with. The reference MAS holds no delegate actor records, so no
 *   delegate is in the set. Any other caller, and an unknown Mission, get
 *   one `not_found`.
 * - Minting checks (`join_failed`, 403): the Mission is `active`; the
 *   `audience` names a client enrolled for its enforcement scope; the acting
 *   token is active and carries exactly one `cnf` confirmation; its subject
 *   and client join the Mission. The deployment establishes the token and
 *   evaluates the join (`JoinAssertionDeployment`): the MAS calls the
 *   deployment's AS, never changes it.
 * - The assertion. `typ` `mission-join+jwt`, signed with the Status key and
 *   algorithm; `mission` (`id`, `issuer`, `authority_hash`), `token`
 *   (`sha256` and the one confirmation member), `join` (`client_id`,
 *   `disposition`, `depth` for a delegate), `aud` the consuming PDP,
 *   `mapping_version` where the deployment's mapping contract names one, and
 *   an `exp` never past the acting token's.
 * - Re-read after every await (#1454 review). The acting token is
 *   established, and the assertion signed, over awaits during which the
 *   Mission can change. After the token check and join evaluation, and again
 *   after signing, the Mission is read again with its expiry materialized: one
 *   no longer `active`, one whose `authority_hash` changed since the first
 *   read, or an audience no longer enrolled for it refuses `join_failed`, and
 *   nothing is returned, cached or recorded. A cached assertion is served only
 *   after the first of these re-reads.
 * - Cache. Keyed on (`issuer`, `mission_id`), the token digest and the
 *   `audience`. A cached assertion is served only after the caller and every
 *   minting check pass again, and only while the join it carries is the join
 *   evaluated now.
 * - Rate limit. Per authenticated caller (`rate_limited`, 429).
 * - Each minting is a join evidence event, held in process memory.
 */

import { entryOverlapsResource } from "@mission/core";
import { accessTokenHash } from "@mission/mcp-payments";
import { ExpansionRateLimiter } from "../kernel/expansion.js";
import type { MissionKernel } from "../kernel/kernel.js";
import type { MissionRecord } from "../kernel/types.js";

/** The advertised endpoint's path, published as `mission_join_assertion_endpoint`. */
export const JOIN_ASSERTION_ENDPOINT_PATH = "/mission/join-assertion";

/** The ceiling this MAS puts on an assertion's life, beneath the acting token's own. */
export const DEFAULT_JOIN_ASSERTION_LIFETIME_S = 300;

/** The default per-caller bound: requests per window. */
export const DEFAULT_JOIN_ASSERTION_RATE_LIMIT = { max: 60, windowSeconds: 60 } as const;

/** One confirmation: the thumbprint of the token's key, or of the certificate it is bound to. */
export type TokenConfirmation = { jkt: string } | { "x5t#S256": string };

/** The acting token as the deployment's AS established it. */
export interface ActingToken {
  /** The issuer of the acting token: the deployment's AS. */
  issuer: string;
  subject: string;
  clientId: string;
  /** Its confirmation, if any: a token with none is never minted for. */
  cnf?: TokenConfirmation;
  /** Its expiry, epoch seconds. */
  exp: number;
}

export type ActingTokenResult =
  | { ok: true; token: ActingToken }
  /** `inactive`: the AS reports it inactive, or it fails validation; `unavailable`: the AS could not be asked. */
  | { ok: false; reason: "inactive" | "unavailable" };

/** The result of the MAS's client and delegate evaluation. */
export interface JoinEvaluation {
  /** The joining client, in the Mission's client namespace. */
  clientId: string;
  disposition: "client" | "delegate";
  /** A delegate's depth from the deployment's actor records. */
  depth?: number;
  /** The mapping contract version the joins were evaluated under. */
  mappingVersion?: string;
}

/**
 * What the deployment supplies: how it establishes an acting token at its
 * AS (validation or introspection), and how it evaluates the subject and
 * client joins under its documented mappings and delegate policy.
 */
export interface JoinAssertionDeployment {
  establishActingToken(form: { accessToken: string } | { tokenSha256: string }): Promise<ActingTokenResult>;
  evaluateJoin(token: ActingToken, mission: MissionRecord): JoinEvaluation | undefined;
  maxLifetimeSeconds?: number;
  rateLimit?: { max: number; windowSeconds: number };
}

/** A join evidence event: one minting. */
export interface JoinAssertionEvent {
  mission: { issuer: string; id: string };
  token: { sha256: string } & TokenConfirmation;
  join: { client_id: string; disposition: "client" | "delegate"; depth?: number };
  caller: string;
  audience: string;
  mapping_version?: string;
  iat: number;
  exp: number;
}

export type JoinAssertionAnswer = { status: number; body: Record<string, unknown> };

type Json = Record<string, unknown>;

type ParsedRequest = {
  missionId: string;
  audience: string;
  token: { accessToken: string } | { tokenSha256: string; confirmation: TokenConfirmation };
};

const err = (status: number, error: string, description?: string): JoinAssertionAnswer => ({
  status,
  body: { error, ...(description ? { error_description: description } : {}) },
});

const isString = (v: unknown): v is string => typeof v === "string" && v.length > 0;

/** The request body this endpoint will read at all (bytes). */
const MAX_BODY_BYTES = 64 * 1024;

/** Read the body, drained past the cap; `undefined` when it exceeds it. */
export async function readJoinAssertionBody(req: AsyncIterable<unknown>): Promise<string | undefined> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    size += buf.length;
    if (size <= MAX_BODY_BYTES) chunks.push(buf);
  }
  return size > MAX_BODY_BYTES ? undefined : Buffer.concat(chunks).toString("utf8");
}

/**
 * @spec authority-server#join-assertion-request: a JSON object carrying
 * `mission_id`, a string `audience`, and exactly one token form: the acting
 * `access_token`, or `token_sha256` with exactly one of `token_jkt` and
 * `token_x5t`.
 */
export function parseJoinAssertionRequest(body: Json): ParsedRequest | string {
  if (!isString(body.mission_id)) return "mission_id is required";
  if (!isString(body.audience)) return "audience is required";
  const pair = [body.token_sha256, body.token_jkt, body.token_x5t].some((v) => v !== undefined);
  if (body.access_token !== undefined) {
    if (!isString(body.access_token)) return "access_token must be a string";
    if (pair) return "send access_token or the digest pair, not both";
    return { missionId: body.mission_id, audience: body.audience, token: { accessToken: body.access_token } };
  }
  if (!isString(body.token_sha256)) return "access_token, or token_sha256 with one thumbprint, is required";
  const jkt = body.token_jkt;
  const x5t = body.token_x5t;
  if ((jkt === undefined) === (x5t === undefined)) return "token_sha256 needs exactly one of token_jkt and token_x5t";
  const thumbprint = jkt ?? x5t;
  if (!isString(thumbprint)) return "the thumbprint must be a string";
  return {
    missionId: body.mission_id,
    audience: body.audience,
    token: { tokenSha256: body.token_sha256, confirmation: jkt !== undefined ? { jkt: thumbprint } : { "x5t#S256": thumbprint } },
  };
}

const sameConfirmation = (a: TokenConfirmation, b: TokenConfirmation): boolean =>
  "jkt" in a ? "jkt" in b && a.jkt === b.jkt : "x5t#S256" in b && a["x5t#S256"] === b["x5t#S256"];

const sameJoin = (a: JoinEvaluation, b: JoinEvaluation): boolean =>
  a.clientId === b.clientId && a.disposition === b.disposition && a.depth === b.depth && a.mappingVersion === b.mappingVersion;

interface CachedAssertion {
  jws: string;
  exp: number;
  join: JoinEvaluation;
}

export interface JoinAssertionServiceDeps {
  issuer: string;
  kernel: MissionKernel;
  deployment: JoinAssertionDeployment;
  /** The enforcement scopes enrolled for a client (`enrolledJoinPdps`). */
  enrolledScopes: (clientId: string) => readonly string[];
  /** The Mission Status endpoint's client authentication, its assertion `aud` this endpoint. */
  authenticate: (params: Record<string, string>, authorization: string) => Promise<{ ok: true; clientId: string } | { ok: false; description: string; retryAfterS?: number }>;
}

export class JoinAssertionService {
  private readonly cache = new Map<string, CachedAssertion>();
  private readonly limiter: ExpansionRateLimiter;
  private readonly minted: JoinAssertionEvent[] = [];

  constructor(private readonly deps: JoinAssertionServiceDeps) {
    const limit = deps.deployment.rateLimit ?? DEFAULT_JOIN_ASSERTION_RATE_LIMIT;
    this.limiter = new ExpansionRateLimiter(limit.max, limit.windowSeconds, () => deps.kernel.nowDate().getTime());
  }

  /** The join evidence events this MAS has recorded, oldest first. */
  events(): readonly JoinAssertionEvent[] {
    return this.minted;
  }

  /** Whether `clientId` is enrolled for a scope some entry of the Mission's Authority Set overlaps. */
  private enrolledFor(clientId: string, record: MissionRecord): boolean {
    const scopes = this.deps.enrolledScopes(clientId);
    return scopes.length > 0 && record.authority_set.some((e) => scopes.some((s) => entryOverlapsResource(e, s)));
  }

  /**
   * @spec authority-server#join-assertion-request (#1454 review): "The MAS
   * mints an assertion only for a Mission in the `active` state", so the
   * Mission is read again, its expiry materialized, after each await that
   * follows the first read. A Mission no longer `active`, one whose
   * `authority_hash` changed since `first`, or an `audience` no longer
   * enrolled for it refuses `join_failed`.
   */
  private recheck(first: MissionRecord, audience: string): JoinAssertionAnswer | undefined {
    const current = this.deps.kernel.currentRecord(first.id);
    if (!current || current.state !== "active") return err(403, "join_failed", "the Mission is not active");
    if (current.authority_hash !== first.authority_hash) return err(403, "join_failed", "the Mission's authority changed");
    if (!this.enrolledFor(audience, current)) {
      return err(403, "join_failed", "the audience names no PDP enrolled for the Mission's enforcement scope");
    }
    return undefined;
  }

  /** One request: the raw body as the route read it, and the request's `Authorization` header. */
  async handle(raw: string, contentType: string, authorization: string): Promise<JoinAssertionAnswer> {
    if ((contentType.split(";")[0] ?? "").trim().toLowerCase() !== "application/json") {
      return err(400, "invalid_join_request", "the request body must be application/json");
    }
    let body: unknown;
    try {
      body = JSON.parse(raw);
    } catch {
      return err(400, "invalid_join_request", "the request body is not JSON");
    }
    if (body === null || typeof body !== "object" || Array.isArray(body)) {
      return err(400, "invalid_join_request", "the request body must be a JSON object");
    }
    const json = body as Json;

    // Caller authentication, before anything about a Mission is read.
    const params: Record<string, string> = {};
    for (const name of ["client_assertion_type", "client_assertion", "client_id", "client_secret"] as const) {
      if (typeof json[name] === "string") params[name] = json[name] as string;
    }
    const auth = await this.deps.authenticate(params, authorization);
    if (!auth.ok) {
      return auth.retryAfterS !== undefined ? err(503, "unavailable", auth.description) : err(400, "invalid_client", auth.description);
    }
    const caller = auth.clientId;

    // @spec authority-server#join-assertion-request: "The MAS MUST
    // rate-limit assertion requests per caller."
    const admitted = this.limiter.admit("join-assertion", caller);
    if (!admitted.ok) return { status: 429, body: { error: "rate_limited", retry_after: admitted.retryAfterS } };

    const request = parseJoinAssertionRequest(json);
    if (typeof request === "string") return err(400, "invalid_join_request", request);

    // Visibility: the Mission's client and the clients enrolled for its
    // enforcement scope. Unknown and invisible answer alike.
    const record = this.deps.kernel.currentRecord(request.missionId);
    if (!record || (caller !== record.client_id && !this.enrolledFor(caller, record))) {
      return err(404, "not_found", "Mission reference is not found or not visible.");
    }

    // The minting checks, applied on every request, a cached answer included.
    if (record.state !== "active") return err(403, "join_failed", "the Mission is not active");
    if (!this.enrolledFor(request.audience, record)) {
      return err(403, "join_failed", "the audience names no PDP enrolled for the Mission's enforcement scope");
    }
    const sha256 = "accessToken" in request.token ? accessTokenHash(request.token.accessToken) : request.token.tokenSha256;
    const established = await this.deps.deployment.establishActingToken(
      "accessToken" in request.token ? { accessToken: request.token.accessToken } : { tokenSha256: sha256 },
    );
    if (!established.ok) {
      return established.reason === "unavailable"
        ? err(503, "unavailable", "the acting token's authorization server could not be reached")
        : err(403, "join_failed", "the acting token is not active");
    }
    const token = established.token;
    const nowS = Math.floor(this.deps.kernel.nowDate().getTime() / 1000);
    if (token.exp <= nowS) return err(403, "join_failed", "the acting token is not active");
    // @spec authority-server#join-assertion-request: "The MAS MUST NOT mint an
    // assertion for a token without a `cnf` key."
    if (!token.cnf) return err(403, "join_failed", "the acting token carries no cnf confirmation");
    if (!("accessToken" in request.token) && !sameConfirmation(request.token.confirmation, token.cnf)) {
      return err(403, "join_failed", "the reported thumbprint is not the acting token's confirmation");
    }
    const join = this.deps.deployment.evaluateJoin(token, record);
    if (!join) return err(403, "join_failed", "the acting token does not join the Mission");
    // The Mission may have changed while the token was established: read it
    // again before serving a cached assertion or signing a new one.
    const beforeSigning = this.recheck(record, request.audience);
    if (beforeSigning) return beforeSigning;

    // @spec authority-server#join-assertion-request: "The cache key is the
    // qualified Mission reference (`issuer`, `mission_id`), the token digest,
    // and the `audience`."
    const key = JSON.stringify([record.issuer, record.id, sha256, request.audience]);
    const held = this.cache.get(key);
    if (held && held.exp > nowS && sameJoin(held.join, join)) return { status: 200, body: { assertion: held.jws } };

    const lifetime = this.deps.deployment.maxLifetimeSeconds ?? DEFAULT_JOIN_ASSERTION_LIFETIME_S;
    // @spec authority-server#join-assertion-artifact: `exp` "MUST NOT exceed
    // the access token's remaining lifetime".
    const exp = Math.min(token.exp, nowS + lifetime);
    const tokenClaim = { sha256, ...token.cnf };
    const joinClaim = {
      client_id: join.clientId,
      disposition: join.disposition,
      ...(join.disposition === "delegate" && join.depth !== undefined ? { depth: join.depth } : {}),
    };
    // The `mission` descriptor: id, issuer and the audit anchor only (never
    // `approval_context_commitment`).
    const claims: Json = {
      mission: { id: record.id, issuer: record.issuer, authority_hash: record.authority_hash },
      token: tokenClaim,
      join: joinClaim,
      ...(join.mappingVersion !== undefined ? { mapping_version: join.mappingVersion } : {}),
    };
    const jws = await this.deps.kernel.signJoinAssertion(claims, { audience: request.audience, iat: nowS, exp });
    // And again after signing: an assertion refused here is neither cached
    // nor recorded as a join evidence event.
    const afterSigning = this.recheck(record, request.audience);
    if (afterSigning) return afterSigning;
    this.cache.set(key, { jws, exp, join });
    this.minted.push({
      mission: { issuer: record.issuer, id: record.id },
      token: tokenClaim,
      join: joinClaim,
      caller,
      audience: request.audience,
      ...(join.mappingVersion !== undefined ? { mapping_version: join.mappingVersion } : {}),
      iat: nowS,
      exp,
    });
    return { status: 200, body: { assertion: jws } };
  }
}
