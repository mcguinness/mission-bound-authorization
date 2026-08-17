/**
 * @spec txn-authorization#challenge-redemption, #two-phase-expiry,
 * #failure-semantics — the `transaction_authorization_endpoint`.
 *
 * The Presenting Client submits the RS-signed challenge together with the
 * Mission-bound access token as an RFC 8693 `subject_token`, authenticates as
 * itself, and proves possession of the challenge's `cnf` key. Initial
 * validation only ADMITS a workflow; the authorization result is the fresh
 * decision at completion, and the upstream pending/polling vocabulary carries
 * the states in between. Nothing here defines a second error vocabulary.
 */

import {
  missionInvariantsEqual,
  readTxnMissionClaim,
  SUBJECT_TOKEN_TYPE_ACCESS_TOKEN,
  type TxnChallengeClaims,
} from "@mission/core";
import {
  calculateJwkThumbprint,
  createLocalJWKSet,
  decodeProtectedHeader,
  jwtVerify,
  type CryptoKey,
  type JWK,
} from "jose";
import { randomBytes } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { isSubsetSet } from "../kernel/derive.js";
import { GateError, type MissionKernel } from "../kernel/kernel.js";
import {
  ChallengeError,
  type ChallengeIssuers,
  issueTxnToken,
  validateChallenge,
} from "../kernel/txn-challenge.js";
import type { AuthorityEntry } from "../kernel/types.js";
import type { DpopProofReplay } from "./dpop-replay.js";

/**
 * The subset of the Access Request Service this endpoint uses. Structural so
 * the AS package needs no compile-time dependency on the ARS.
 */
export interface TxnArs {
  openForTxn(input: {
    txn: string;
    missionId: string;
    action: string;
    parameter_digest: string;
    subject: string;
  }): { taskId: string; state: string };
  getTask(taskId: string):
    | {
        state: string;
        approval?: { id: string; approved_at: string; approved_until: string; parameter_digest: string };
      }
    | undefined;
}

/** The minimal Koa-ish context the AS's custom routes are handed. */
export interface TxnCtx {
  method: string;
  path: string;
  status: number;
  body: unknown;
  req: IncomingMessage;
  res: ServerResponse;
  set: (name: string, value: string) => void;
  get: (name: string) => string;
}

/**
 * @spec txn-authorization#challenge-redemption step 4 — the destination
 * resource policy consulted at admission. Deny ends the flow before any
 * approval is opened.
 */
export type DestinationPolicy = (input: {
  resource: string;
  action: string;
  missionId: string;
  clientId: string;
  subject: string;
  authorizationDetails: AuthorityEntry[];
}) => { decision: "permit" | "deny"; reason?: string };

export interface TxnAuthorizationOptions {
  /** The accepted Challenge-Issuing Resources and their published keys. */
  challengeIssuers: ChallengeIssuers;
  ars: TxnArs;
  /** Signs the transaction token. */
  tokenKey: CryptoKey;
  tokenKid: string;
  /**
   * @spec txn-authorization#two-phase-expiry — the pending workflow's OWN
   * deployment-declared lifetime, independent of the challenge's `exp`.
   */
  workflowLifetimeSeconds: number;
  /** Deployment maximum for an issued transaction token (seconds). */
  maxTokenLifetimeSeconds: number;
  /** Poll cadence advertised to the client (seconds). */
  pollIntervalSeconds?: number;
  destinationPolicy?: DestinationPolicy;
}

export interface TxnAuthorizationDeps {
  issuer: string;
  kernel: MissionKernel;
  /** Registered clients, for private_key_jwt authentication at this endpoint. */
  clients: Record<string, unknown>[];
  /** This AS's published keys, for verifying the presented `subject_token`. */
  publicJwks: { keys: JWK[] };
  dpopProofReplay: DpopProofReplay;
  now: () => Date;
  txn?: TxnAuthorizationOptions;
}

/** The admitted workflow's pinned state. */
interface TxnWorkflow {
  id: string;
  taskId: string;
  challenge: TxnChallengeClaims;
  clientId: string;
  subject: string;
  missionId: string;
  action: string;
  /** Epoch seconds the WORKFLOW expires (not the challenge). */
  expiresAtS: number;
  /** `subject_token`'s own expiry, pinned at admission. */
  subjectTokenExpS: number;
  state: "pending" | "issued" | "denied";
  issuedToken?: string;
  issuedExpS?: number;
}

const DEFAULT_POLL_INTERVAL_S = 5;

function fail(ctx: TxnCtx, status: number, error: string, description?: string): void {
  ctx.status = status;
  ctx.body = { error, ...(description ? { error_description: description } : {}) };
  ctx.set("cache-control", "no-store");
}

/**
 * The endpoint. `transaction_challenge` (+ `subject_token`) is an initial
 * submission; `transaction_authorization_id` is a poll.
 */
export async function handleTransactionAuthorization(
  deps: TxnAuthorizationDeps,
  ctx: TxnCtx,
  workflows: Map<string, TxnWorkflow>,
): Promise<void> {
  const txn = deps.txn;
  if (!txn) {
    fail(ctx, 501, "temporarily_unavailable", "transaction authorization is not configured");
    return;
  }
  const params = await readParams(ctx.req);

  // The TAS authenticates the Presenting Client. `client_id` on the issued
  // token is THIS authenticated identity, never a request assertion.
  const clientId = await authenticateClient(deps, params);
  if (!clientId) {
    fail(ctx, 401, "invalid_client", "client authentication failed");
    return;
  }

  // Proof of possession of the challenge's `cnf` key, bound to this endpoint.
  const proven = await verifyDpop(deps, ctx);
  if (!proven) {
    fail(ctx, 400, "invalid_dpop_proof", "a DPoP proof of the challenge cnf key is required");
    return;
  }

  const pollId = params.transaction_authorization_id;
  if (typeof pollId === "string" && pollId) {
    await poll(deps, txn, ctx, workflows, pollId, clientId, proven);
    return;
  }
  await admit(deps, txn, ctx, workflows, params, clientId, proven);
}

/**
 * @spec txn-authorization#challenge-redemption — initial submission. The seven
 * ordered checks run here through step 5; steps 6 and 7 are the completion.
 */
async function admit(
  deps: TxnAuthorizationDeps,
  txn: TxnAuthorizationOptions,
  ctx: TxnCtx,
  workflows: Map<string, TxnWorkflow>,
  params: Record<string, unknown>,
  clientId: string,
  provenJkt: string,
): Promise<void> {
  const challengeJws = params.transaction_challenge;
  const subjectToken = params.subject_token;
  if (typeof challengeJws !== "string" || !challengeJws) {
    fail(ctx, 400, "invalid_request", "transaction_challenge is required");
    return;
  }
  if (typeof subjectToken !== "string" || !subjectToken) {
    fail(ctx, 400, "invalid_request", "subject_token is required");
    return;
  }
  if (params.subject_token_type !== SUBJECT_TOKEN_TYPE_ACCESS_TOKEN) {
    fail(ctx, 400, "invalid_request", "subject_token_type must be an access token");
    return;
  }

  // @spec txn-authorization#two-phase-expiry — the challenge's `exp` bounds
  // ADMISSION: a late challenge is refused here, into a NEW workflow, never
  // revived into an existing one.
  let challenge: TxnChallengeClaims;
  try {
    challenge = await validateChallenge(challengeJws, txn.challengeIssuers, deps.issuer);
  } catch (e) {
    const code = e instanceof ChallengeError ? e.code : "invalid_claims";
    fail(ctx, 400, "invalid_grant", `challenge rejected (${code})`);
    return;
  }

  // 1. `subject_token`'s audience against the challenge's `iss`, and its `cnf`
  //    against the proof presented on THIS request (which is also the key the
  //    challenge committed to).
  let subject: Record<string, unknown>;
  try {
    ({ payload: subject } = (await jwtVerify(subjectToken, createLocalJWKSet(deps.publicJwks as never), {
      issuer: deps.issuer,
    })) as { payload: Record<string, unknown> });
  } catch {
    fail(ctx, 400, "invalid_grant", "subject_token did not verify");
    return;
  }
  const aud = subject.aud;
  const audiences = Array.isArray(aud) ? aud : typeof aud === "string" ? [aud] : [];
  if (!audiences.includes(challenge.iss)) {
    fail(ctx, 400, "invalid_grant", "subject_token was not issued for the challenged resource");
    return;
  }
  const subjectCnf = (subject.cnf as { jkt?: string } | undefined)?.jkt;
  if (!subjectCnf || subjectCnf !== provenJkt || challenge.cnf.jkt !== provenJkt) {
    fail(ctx, 400, "invalid_grant", "the challenge, subject_token and proof are not the same key");
    return;
  }

  // 2. Exact equality of the challenge's `mission` and `subject_token`'s
  //    Mission invariants.
  if (!missionInvariantsEqual(challenge.mission, subject.mission)) {
    fail(ctx, 400, "invalid_grant", "challenge mission does not match subject_token");
    return;
  }

  // 3. The challenge's `authorization_details` within `subject_token`'s
  //    Authority Set under the subset rule, and applying to the challenge's
  //    resource. The Mission's CURRENT effective set is the funnel, so a
  //    contained capability cannot be laundered through an approval.
  const requested = challenge.authorization_details as unknown as AuthorityEntry[];
  const missionId = challenge.mission.id;
  const record = deps.kernel.get(missionId);
  if (!record) {
    fail(ctx, 400, "invalid_grant", "unknown mission");
    return;
  }
  const active = deps.kernel.applyExpiry(record);
  if (active.state !== "active") {
    fail(ctx, 400, "invalid_grant", "mission is not active");
    return;
  }
  if (!requested.every((e) => e.resource === challenge.iss)) {
    fail(ctx, 400, "invalid_grant", "challenge authority does not apply to the challenged resource");
    return;
  }
  const subjectAuthority = (subject.authorization_details as AuthorityEntry[] | undefined) ?? [];
  const effective = deps.kernel.effectiveAuthoritySet(active);
  if (!isSubsetSet(requested, subjectAuthority) || !isSubsetSet(requested, effective)) {
    fail(ctx, 400, "invalid_grant", "challenge authority is outside the Authority Set");
    return;
  }

  // 4. `requires_action_approval` and destination resource policy.
  const action = requested[0]?.actions?.[0] ?? challenge.reason;
  const subjectId = principalOf(subject, challenge);
  const policy = txn.destinationPolicy?.({
    resource: challenge.iss,
    action,
    missionId,
    clientId,
    subject: subjectId,
    authorizationDetails: requested,
  });
  if (policy && policy.decision !== "permit") {
    fail(ctx, 400, "access_denied", policy.reason ?? "destination policy denied the operation");
    return;
  }

  // 5. Obtain or resolve a governed approval, bound to `txn`, the operation,
  //    `parameter_digest`, the resource, the Mission, the origin principal and
  //    the presenter key.
  const { taskId } = txn.ars.openForTxn({
    txn: challenge.txn,
    missionId,
    action,
    parameter_digest: challenge.parameter_digest,
    subject: subjectId,
  });

  const nowS = Math.floor(deps.now().getTime() / 1000);
  const id = `txa_${randomBytes(12).toString("base64url")}`;
  workflows.set(id, {
    id,
    taskId,
    challenge,
    clientId,
    subject: subjectId,
    missionId,
    action,
    expiresAtS: nowS + txn.workflowLifetimeSeconds,
    subjectTokenExpS: typeof subject.exp === "number" ? subject.exp : nowS,
    state: "pending",
  });
  ctx.status = 200;
  ctx.body = {
    transaction_authorization_id: id,
    expires_in: txn.workflowLifetimeSeconds,
    interval: txn.pollIntervalSeconds ?? DEFAULT_POLL_INTERVAL_S,
  };
  ctx.set("cache-control", "no-store");
}

/**
 * @spec txn-authorization#failure-semantics — the upstream pending/polling
 * states, applied unchanged. An admitted workflow still refuses here when a
 * fresh input no longer holds.
 */
async function poll(
  deps: TxnAuthorizationDeps,
  txn: TxnAuthorizationOptions,
  ctx: TxnCtx,
  workflows: Map<string, TxnWorkflow>,
  id: string,
  clientId: string,
  provenJkt: string,
): Promise<void> {
  const wf = workflows.get(id);
  // A workflow is only ever visible to the client and key that admitted it; an
  // unknown id and a foreign id are indistinguishable from the outside.
  if (!wf || wf.clientId !== clientId || wf.challenge.cnf.jkt !== provenJkt) {
    fail(ctx, 400, "invalid_grant", "unknown transaction_authorization_id");
    return;
  }
  if (wf.state === "denied") {
    fail(ctx, 400, "access_denied");
    return;
  }
  const nowS = Math.floor(deps.now().getTime() / 1000);
  if (wf.state === "issued" && wf.issuedToken) {
    // At most one authorization result per workflow: repeated polling after a
    // decision returns the SAME token, never a second issuance.
    respondWithToken(ctx, wf.issuedToken, (wf.issuedExpS ?? nowS) - nowS);
    return;
  }
  if (nowS >= wf.expiresAtS) {
    fail(ctx, 400, "expired_token");
    return;
  }
  const task = txn.ars.getTask(wf.taskId);
  if (task?.state === "denied") {
    wf.state = "denied";
    fail(ctx, 400, "access_denied");
    return;
  }
  // 6. The approval's status, scope, grant time, maximum age and
  //    `approved_until`.
  if (!task || task.state !== "approved" || !task.approval) {
    fail(ctx, 400, "authorization_pending");
    return;
  }
  const approval = task.approval;
  if (approval.parameter_digest !== wf.challenge.parameter_digest) {
    fail(ctx, 400, "access_denied", "approval is not bound to the challenged operation");
    return;
  }
  const approvedUntilS = Math.floor(Date.parse(approval.approved_until) / 1000);
  if (!Number.isFinite(approvedUntilS) || approvedUntilS <= nowS) {
    fail(ctx, 400, "access_denied", "approval is no longer current");
    return;
  }

  // Completion of step 6 alone MUST NOT issue: the Mission's current state is
  // re-gated here, at the moment of issuance.
  let gated;
  try {
    gated = deps.kernel.gateActive(wf.missionId);
  } catch (e) {
    if (e instanceof GateError) {
      fail(ctx, 400, "access_denied", e.message);
      return;
    }
    throw e;
  }

  const exp = Math.min(
    approvedUntilS,
    wf.subjectTokenExpS,
    Math.floor(Date.parse(gated.expires_at) / 1000),
    wf.expiresAtS,
    nowS + txn.maxTokenLifetimeSeconds,
  );
  if (exp <= nowS) {
    fail(ctx, 400, "access_denied", "no lifetime remains for a transaction token");
    return;
  }
  const token = await issueTxnToken({
    txn: wf.challenge.txn,
    audience: wf.challenge.iss,
    mission: wf.challenge.mission as unknown as Record<string, unknown>,
    authorizationDetails: wf.challenge.authorization_details as unknown as unknown[],
    approval,
    approvedUntil: new Date(exp * 1000).toISOString(),
    cnfJkt: wf.challenge.cnf.jkt,
    key: txn.tokenKey,
    kid: txn.tokenKid,
    issuer: deps.issuer,
  });
  wf.state = "issued";
  wf.issuedToken = token;
  wf.issuedExpS = exp;
  respondWithToken(ctx, token, exp - nowS);
}

/** The standard OAuth token response; no bespoke members ride alongside it. */
function respondWithToken(ctx: TxnCtx, accessToken: string, expiresIn: number): void {
  ctx.status = 200;
  ctx.body = { access_token: accessToken, token_type: "DPoP", expires_in: Math.max(1, expiresIn) };
  ctx.set("cache-control", "no-store");
}

/**
 * The verified effective subject: the origin principal where the Origin
 * Principal profile applies, otherwise the Mission's subject. Never the
 * Approver.
 */
function principalOf(subjectToken: Record<string, unknown>, challenge: TxnChallengeClaims): string {
  const origin = challenge.mission.subject ?? readTxnMissionClaim(subjectToken.mission)?.subject;
  return origin ? origin.sub : String(subjectToken.sub ?? "");
}

/**
 * Client authentication (private_key_jwt), the same idiom the token endpoint's
 * confidential clients use. The assertion's `jti` is single-use within the
 * proof window, in its own namespace so it cannot collide with a DPoP `jti`.
 */
async function authenticateClient(
  deps: TxnAuthorizationDeps,
  params: Record<string, unknown>,
): Promise<string | undefined> {
  const assertion = params.client_assertion;
  if (
    typeof assertion !== "string" ||
    params.client_assertion_type !== "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
  ) {
    return undefined;
  }
  const clientId = typeof params.client_id === "string" ? params.client_id : undefined;
  const client = deps.clients.find(
    (c) => typeof c.client_id === "string" && (clientId === undefined || c.client_id === clientId),
  );
  const jwks = client?.jwks as { keys: JWK[] } | undefined;
  if (!client || !jwks?.keys?.length) return undefined;
  try {
    const { payload } = await jwtVerify(assertion, createLocalJWKSet(jwks as never), {
      issuer: client.client_id as string,
      subject: client.client_id as string,
      audience: [deps.issuer, `${deps.issuer}/transaction`],
    });
    if (typeof payload.jti !== "string" || !deps.dpopProofReplay.check(`ca:${payload.jti}`)) {
      return undefined;
    }
    return client.client_id as string;
  } catch {
    return undefined;
  }
}

/**
 * Verify the DPoP proof presented on this request and return the proven key
 * thumbprint. The proof is bound to THIS endpoint (htu/htm) and its `jti` is
 * single-use within the acceptance window.
 */
async function verifyDpop(deps: TxnAuthorizationDeps, ctx: TxnCtx): Promise<string | undefined> {
  const proofJws = ctx.get("dpop");
  if (!proofJws) return undefined;
  try {
    const header = decodeProtectedHeader(proofJws);
    const jwk = header.jwk as (JWK & { d?: string }) | undefined;
    if (!jwk || jwk.d !== undefined) return undefined;
    const jkt = await calculateJwkThumbprint(jwk as never);
    const { payload } = await jwtVerify(proofJws, jwk as never, { typ: "dpop+jwt" });
    if (payload.htu !== `${deps.issuer}/transaction` || payload.htm !== "POST") return undefined;
    if (typeof payload.jti !== "string" || !deps.dpopProofReplay.check(payload.jti)) return undefined;
    return jkt;
  } catch {
    return undefined;
  }
}

/** Read a form-encoded (or JSON) request body. */
async function readParams(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const text = Buffer.concat(chunks).toString("utf8");
  if (!text) return {};
  if (text.trimStart().startsWith("{")) {
    try {
      return JSON.parse(text) as Record<string, unknown>;
    } catch {
      return {};
    }
  }
  return Object.fromEntries(new URLSearchParams(text));
}

/** A fresh, empty workflow table (one per provider instance). */
export function newTxnWorkflows(): Map<string, TxnWorkflow> {
  return new Map();
}

export type { TxnWorkflow };
