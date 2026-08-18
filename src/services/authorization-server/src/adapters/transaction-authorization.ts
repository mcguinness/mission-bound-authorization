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
  type JsonValue,
  type TxnChallengeClaims,
} from "@mission/core";
import {
  calculateJwkThumbprint,
  createLocalJWKSet,
  decodeJwt,
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
  validateChallenge,
} from "../kernel/txn-challenge.js";
import { mintTransactionToken } from "../kernel/transaction-token.js";
import type { AuthorityEntry } from "../kernel/types.js";
import { TxnWorkflowStore, type TxnWorkflowRecord } from "../kernel/txn-workflow-store.js";
import { DPOP_PROOF_REPLAY_WINDOW_S, type DpopProofReplay } from "./dpop-replay.js";

/**
 * The subset of the Access Request Service this endpoint uses. Structural so
 * the AS package needs no compile-time dependency on the ARS.
 */
export interface TxnArs {
  openForTxn(input: {
    txn: string;
    /** The Challenge-Issuing Resource `txn` is scoped to (the challenge `iss`). */
    resource: string;
    missionId: string;
    action: string;
    parameter_digest: string;
    subject: string;
    /**
     * @spec txn-authorization#applicability — why this operation is under an
     * action-bound approval: the matched entry's `requires_action_approval`
     * Common Constraint or the deployment's destination policy said so, as
     * opposed to the endpoint's own profile requirement.
     */
    requires_action_approval: boolean;
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
 * approval is opened; `requires_approval` is the deployment's own half of the
 * approval requirement, OR'd with the matched entry's Common Constraint.
 */
export type DestinationPolicy = (input: {
  resource: string;
  action: string;
  missionId: string;
  clientId: string;
  subject: string;
  authorizationDetails: AuthorityEntry[];
}) => { decision: "permit" | "deny"; reason?: string; requires_approval?: boolean };

/**
 * @spec txn-authorization#challenge-redemption step 7 — the inputs the fresh
 * authorization decision runs on. The verified approval is CONTEXT here, never
 * a bearer bypass.
 */
export interface FreshDecisionInput {
  txn: string;
  missionId: string;
  /** The Challenge-Issuing Resource (the challenge `iss`). */
  resource: string;
  action: string;
  /** The operation's `authorization_details` `type` as pinned at admission. */
  operationType: string;
  clientId: string;
  subject: string;
  parameterDigest: string;
  authorizationDetails: AuthorityEntry[];
  cnfJkt: string;
  approval: { id: string; approved_at: string; approved_until: string; parameter_digest: string };
}

/**
 * The deployment's entitlement and resource-policy decision, run FRESH at
 * redemption completion. Required: without it there is no step 7, and
 * completing step 6 alone must never issue.
 */
export type FreshDecision = (
  input: FreshDecisionInput,
) => Promise<{ decision: "permit" | "deny"; reason?: string }>;

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
  /**
   * @spec txn-authorization#challenge-redemption step 7 — the fresh
   * entitlement/policy decision at completion.
   */
  freshDecision: FreshDecision;
  /** Maximum age of an approval at the moment it is relied on (seconds). */
  maxApprovalAgeSeconds?: number;
  /** Poll cadence advertised to the client (seconds). */
  pollIntervalSeconds?: number;
  destinationPolicy?: DestinationPolicy;
  /** The pending-workflow table; defaulted per provider instance when unset. */
  store?: TxnWorkflowStore;
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
  workflows: TxnWorkflowStore,
): Promise<void> {
  const txn = deps.txn;
  if (!txn) {
    fail(ctx, 501, "temporarily_unavailable", "transaction authorization is not configured");
    return;
  }
  const store = txn.store ?? workflows;
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
    await poll(deps, txn, ctx, store, pollId, clientId, proven);
    return;
  }
  await admit(deps, txn, ctx, store, params, clientId, proven);
}

/**
 * @spec txn-authorization#challenge-redemption — initial submission. The seven
 * ordered checks run here through step 5; steps 6 and 7 are the completion.
 */
async function admit(
  deps: TxnAuthorizationDeps,
  txn: TxnAuthorizationOptions,
  ctx: TxnCtx,
  workflows: TxnWorkflowStore,
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

  // 1. `subject_token`'s CLASS, audience against the challenge's `iss`, and its
  //    `cnf` against the proof presented on THIS request (which is also the key
  //    the challenge committed to).
  //
  //    The class is pinned POSITIVELY to the RFC 9068 access-token type this AS
  //    mints. Every other credential it signs -- above all a transaction token,
  //    which carries an audience, the Mission invariants, an authority set and a
  //    `cnf` of its own -- would otherwise satisfy the checks below and be
  //    replayable here as the subject's credential.
  let subject: Record<string, unknown>;
  try {
    ({ payload: subject } = (await jwtVerify(subjectToken, createLocalJWKSet(deps.publicJwks as never), {
      issuer: deps.issuer,
      typ: "at+jwt",
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

  // 4. `requires_action_approval` and destination resource policy. The
  //    requirement is the matched effective entry's Common Constraint OR the
  //    deployment's destination policy, so a delegated leaf carrying an
  //    ancestor's requirement is gated here even where deployment policy is
  //    silent about the action. The constraint is monotonic: either source
  //    alone establishes it, and neither can shed the other's.
  const action = requested[0]?.actions?.[0] ?? challenge.reason;
  const subjectId = principalOf(subject, challenge);
  const entryRequiresApproval =
    requiresActionApproval(subjectAuthority, challenge.iss, action) ||
    requiresActionApproval(effective, challenge.iss, action);
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
  const requiresApproval = entryRequiresApproval || policy?.requires_approval === true;

  const nowS = Math.floor(deps.now().getTime() / 1000);

  // @spec txn-authorization#two-phase-expiry — the admission insert IS the
  // reservation, and it runs BEFORE any approval is opened: a repeated (or
  // concurrent) initial submission of the SAME admitted challenge loses the
  // race, returns the existing pending workflow, and never opens a second
  // approval. The row is created with no task; only the winner opens one.
  const { record: workflow, won } = workflows.admit({
    id: `txa_${randomBytes(12).toString("base64url")}`,
    taskId: "",
    challenge,
    clientId,
    subject: subjectId,
    missionId,
    action,
    // Pinned: a superseded Operation Profile version stays recognized for as
    // long as this workflow references it.
    operationType: String(requested[0]?.type ?? ""),
    // @spec txn-authorization#two-phase-expiry — the workflow's own
    // deployment-declared lifetime, NOT the challenge's remaining window.
    expiresAtS: nowS + txn.workflowLifetimeSeconds,
    subjectTokenExpS: typeof subject.exp === "number" ? subject.exp : nowS,
    missionExpS: Math.floor(Date.parse(active.expires_at) / 1000),
    // Actor context from EITHER upstream carrier; its presence is what makes
    // `act` REQUIRED on the issued token.
    ...(subject.act !== undefined
      ? { act: subject.act }
      : challenge.act !== undefined
        ? { act: challenge.act }
        : {}),
    state: "pending",
  });

  // 5. Obtain or resolve a governed approval, bound to `txn`, the operation,
  //    `parameter_digest`, the resource, the Mission, the origin principal and
  //    the presenter key. This endpoint opens one for every admitted operation;
  //    the requirement above travels with it as the basis it rests on. An
  //    empty `taskId` on a workflow this caller did not win means an earlier
  //    submission reserved the slot and did not reach the ARS; opening is
  //    idempotent, so the retry resolves to that same approval.
  if (won || workflow.taskId === "") {
    const { taskId } = txn.ars.openForTxn({
      txn: challenge.txn,
      resource: challenge.iss,
      missionId,
      action,
      parameter_digest: challenge.parameter_digest,
      subject: subjectId,
      requires_action_approval: requiresApproval,
    });
    workflows.recordTask(workflow.id, taskId);
  }
  respondAdmitted(ctx, txn, workflow, nowS);
}

function respondAdmitted(
  ctx: TxnCtx,
  txn: TxnAuthorizationOptions,
  workflow: TxnWorkflowRecord,
  nowS: number,
): void {
  ctx.status = 200;
  ctx.body = {
    transaction_authorization_id: workflow.id,
    expires_in: Math.max(1, workflow.expiresAtS - nowS),
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
  workflows: TxnWorkflowStore,
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
    // decision returns the SAME token (same jti), never a second issuance.
    respondWithToken(ctx, wf.issuedToken, (wf.issuedExpS ?? nowS) - nowS, wf.challenge.authorization_details);
    return;
  }
  // @spec txn-authorization#two-phase-expiry — the workflow's OWN lifetime is
  // what expires here. An async approval completing after the challenge's exp
  // but within this window still issues; the challenge exp is already consumed.
  if (nowS >= wf.expiresAtS) {
    fail(ctx, 400, "expired_token");
    return;
  }
  // The workflow reserved admission but has not opened its approval yet (a
  // crash between the two, or a concurrent submission still in flight). There
  // is nothing to decide on yet; the workflow's own lifetime bounds the wait.
  if (!wf.taskId) {
    fail(ctx, 400, "authorization_pending");
    return;
  }
  const task = txn.ars.getTask(wf.taskId);
  if (task?.state === "denied") {
    workflows.setState(wf.id, "denied");
    fail(ctx, 400, "access_denied");
    return;
  }
  // 6. The approval's status, scope, grant time, maximum age and
  //    `approved_until`.
  if (!task || task.state !== "approved" || !task.approval) {
    fail(ctx, 400, "authorization_pending");
    return;
  }
  // The approval is only ever SATISFIED by approval state. A stronger
  // authentication context on `subject_token` (RFC 9470 step-up) proves who is
  // present; it never stands in for this, and nothing below reads it.
  const approval = task.approval;
  if (approval.parameter_digest !== wf.challenge.parameter_digest) {
    fail(ctx, 400, "access_denied", "approval is not bound to the challenged operation");
    return;
  }
  const approvedUntilS = Math.floor(Date.parse(approval.approved_until) / 1000);
  const approvedAtS = Math.floor(Date.parse(approval.approved_at) / 1000);
  const maxAgeS = txn.maxApprovalAgeSeconds ?? 300;
  if (!Number.isFinite(approvedUntilS) || approvedUntilS <= nowS) {
    fail(ctx, 400, "access_denied", "approval is no longer current");
    return;
  }
  if (!Number.isFinite(approvedAtS) || nowS - approvedAtS > maxAgeS) {
    fail(ctx, 400, "access_denied", "approval is older than the maximum age");
    return;
  }

  // 7. The FRESH authorization decision. Completion of step 6 alone MUST NOT
  //    issue and MUST NOT bypass this: every input below is re-read NOW, not
  //    replayed from admission.
  if (wf.subjectTokenExpS <= nowS) {
    fail(ctx, 400, "access_denied", "subject_token is no longer valid");
    return;
  }
  let gated;
  try {
    // The lineage-grade active gate, not a bare derivation gate: a non-active
    // ancestor refuses here too.
    gated = deps.kernel.gateActive(wf.missionId);
  } catch (e) {
    if (e instanceof GateError) {
      fail(ctx, 400, "access_denied", e.message);
      return;
    }
    throw e;
  }
  // Containment may have narrowed the Mission since admission, so the subset
  // rule is recomputed against the CURRENT effective set, never the pinned one.
  const permitted = wf.challenge.authorization_details as unknown as AuthorityEntry[];
  if (!isSubsetSet(permitted, deps.kernel.effectiveAuthoritySet(gated))) {
    fail(ctx, 400, "access_denied", "challenge authority is no longer within the effective Authority Set");
    return;
  }
  const fresh = await txn.freshDecision({
    txn: wf.challenge.txn,
    missionId: wf.missionId,
    resource: wf.challenge.iss,
    action: wf.action,
    operationType: wf.operationType,
    clientId: wf.clientId,
    subject: wf.subject,
    parameterDigest: wf.challenge.parameter_digest,
    authorizationDetails: permitted,
    cnfJkt: wf.challenge.cnf.jkt,
    approval,
  });
  if (fresh.decision !== "permit") {
    fail(ctx, 400, "access_denied", fresh.reason ?? "the fresh authorization decision denied the operation");
    return;
  }

  // @spec txn-authorization#transaction-token — the earliest of approval
  // freshness, subject_token validity, Mission expiry (pinned AND current, so a
  // Mission extended mid-workflow cannot widen it), the workflow's remaining
  // lifetime, and the deployment maximum. Never the challenge's exp.
  const exp = Math.min(
    approvedUntilS,
    wf.subjectTokenExpS,
    wf.missionExpS,
    Math.floor(Date.parse(gated.expires_at) / 1000),
    wf.expiresAtS,
    nowS + txn.maxTokenLifetimeSeconds,
  );
  if (exp <= nowS) {
    fail(ctx, 400, "access_denied", "no lifetime remains for a transaction token");
    return;
  }

  // At most one authorization result per `txn`: the slot is taken exactly once,
  // so a second token under a different jti is structurally impossible.
  if (!workflows.reserveIssuance(wf.challenge.txn, wf.id)) {
    if (workflows.issuanceHolder(wf.challenge.txn) === wf.id) {
      // THIS workflow holds the slot. Serve its stored token; a poll that
      // catches the mint mid-flight stays pending rather than reading a
      // terminal denial off a workflow that is about to issue.
      const current = workflows.get(wf.id);
      if (current?.issuedToken) {
        respondWithToken(
          ctx,
          current.issuedToken,
          (current.issuedExpS ?? nowS) - nowS,
          current.challenge.authorization_details,
        );
        return;
      }
      fail(ctx, 400, "authorization_pending");
      return;
    }
    fail(ctx, 400, "access_denied", "this transaction already produced an authorization result");
    return;
  }
  // @spec txn-authorization#transaction-token — `parameter_digest` is copied
  // only after it has been verified against the challenge (the approval above
  // is bound to the same value), and `mission` is the challenge's profiled
  // members, value-equal by construction.
  const tokenJti = `mtt_${randomBytes(12).toString("base64url")}`;
  const token = await mintTransactionToken({
    issuer: deps.issuer,
    audience: wf.challenge.iss,
    jti: tokenJti,
    expS: exp,
    subject: wf.subject,
    clientId: wf.clientId,
    txn: wf.challenge.txn,
    authorizationDetails: wf.challenge.authorization_details,
    parameterDigest: wf.challenge.parameter_digest,
    mission: wf.challenge.mission,
    cnfJkt: wf.challenge.cnf.jkt,
    ...(wf.act !== undefined ? { act: wf.act as never } : {}),
    key: txn.tokenKey,
    kid: txn.tokenKid,
  });
  workflows.recordIssued(wf.id, token, tokenJti, exp);
  respondWithToken(ctx, token, exp - nowS, wf.challenge.authorization_details);
}

/**
 * The standard OAuth token response; no bespoke members ride alongside it.
 * `authorization_details` is the RFC 9396 response parameter, carrying the
 * EXACT permitted set -- identical to the token's own claim -- so a client
 * learns what was authorized without inspecting the token.
 */
function respondWithToken(
  ctx: TxnCtx,
  accessToken: string,
  expiresIn: number,
  authorizationDetails: JsonValue[],
): void {
  ctx.status = 200;
  ctx.body = {
    access_token: accessToken,
    token_type: "DPoP",
    expires_in: Math.max(1, expiresIn),
    authorization_details: authorizationDetails,
  };
  ctx.set("cache-control", "no-store");
}

/**
 * @spec txn-authorization#applicability — whether the entry covering this
 * operation carries the `requires_action_approval` Common Constraint. The
 * kernel normalizes the constraint onto every delegated child entry at
 * creation, so the effective entry a leaf presents carries an ancestor's
 * requirement even where the child's own proposal omitted the member.
 */
function requiresActionApproval(
  entries: readonly AuthorityEntry[],
  resource: string,
  action: string,
): boolean {
  return entries.some(
    (e) =>
      e.resource === resource &&
      e.actions.includes(action) &&
      e.constraints?.requires_action_approval === true,
  );
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
 *
 * The ASSERTION names the client: RFC 7523 fixes `iss` and `sub` to the client
 * identifier, so the registered record is selected from that identity and
 * verified under THAT client's keys alone. A `client_id` parameter is only ever
 * corroboration and MUST agree; an assertion no registered client claims is
 * refused rather than checked against some other client's record.
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
  let asserted: string | undefined;
  try {
    const claims = decodeJwt(assertion);
    asserted = typeof claims.iss === "string" && claims.iss === claims.sub ? claims.iss : undefined;
  } catch {
    return undefined;
  }
  if (!asserted) return undefined;
  const presented = typeof params.client_id === "string" ? params.client_id : undefined;
  if (presented !== undefined && presented !== asserted) return undefined;
  const client = deps.clients.find((c) => c.client_id === asserted);
  const jwks = client?.jwks as { keys: JWK[] } | undefined;
  if (!client || !jwks?.keys?.length) return undefined;
  try {
    const { payload } = await jwtVerify(assertion, createLocalJWKSet(jwks as never), {
      issuer: asserted,
      subject: asserted,
      audience: [deps.issuer, `${deps.issuer}/transaction`],
    });
    // @spec RFC 7523 §3 — `exp` is REQUIRED on a client assertion. jose only
    // validates it when present, so an assertion omitting it would otherwise
    // authenticate forever.
    if (typeof payload.exp !== "number") return undefined;
    if (typeof payload.jti !== "string" || !deps.dpopProofReplay.check(`ca:${payload.jti}`)) {
      return undefined;
    }
    return asserted;
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
    // @spec RFC 9449 §4.2/§4.3 — `iat` is REQUIRED and the proof is only
    // accepted within a short window around it, in BOTH directions: a captured
    // proof stops being usable, and a future-dated one never starts. The window
    // is the replay cache's, so a jti is remembered at least as long as a proof
    // bearing it can be accepted.
    if (typeof payload.iat !== "number") return undefined;
    const nowS = Math.floor(deps.now().getTime() / 1000);
    if (Math.abs(nowS - payload.iat) > DPOP_PROOF_REPLAY_WINDOW_S) return undefined;
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

/** A fresh workflow table (one per provider instance). */
export function newTxnWorkflows(): TxnWorkflowStore {
  return new TxnWorkflowStore();
}
