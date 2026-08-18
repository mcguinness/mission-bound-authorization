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
  SUBJECT_TOKEN_TYPE_ACCESS_TOKEN,
  txnApprovalBindingDigest,
  type JsonValue,
  type TxnApprovalBinding,
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
import type { AuthorityEntry, MissionRecord } from "../kernel/types.js";
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
    /**
     * @spec txn-authorization#challenge-redemption step 5 — the COMPLETE
     * transaction the approval is bound to: `txn` and the resource, the
     * Mission, the operation's profile type and entry, the parameters' digest,
     * BOTH identities, the authenticated client, and the presenter key. The
     * approver adjudicates THIS, and nothing else can later claim it.
     */
    binding: TxnApprovalBinding;
    /** {@link txnApprovalBindingDigest} of `binding`; travels with the approval. */
    binding_digest: string;
  }): { taskId: string; state: string };
  getTask(taskId: string):
    | {
        state: string;
        approval?: {
          id: string;
          approved_at: string;
          approved_until: string;
          parameter_digest: string;
          /**
           * The binding the approval was OPENED under. Absent is never
           * equal to anything the TAS recomputes, so an approval that does
           * not carry one is refused like any other mismatch.
           */
          binding_digest?: string;
        };
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
  /**
   * The DESTINATION-LOCAL subject: the `subject_token`'s own `sub`, in this
   * Authorization Server's namespace. This is what OAuth's `sub` means and what
   * the transaction token carries.
   */
  subject: string;
  /**
   * @spec mission#the-mission-claim — the issuer-qualified ORIGIN principal,
   * where the Origin Principal profile applies. It travels ALONGSIDE the local
   * subject, never in place of it: the cross-domain profile separates the two
   * deliberately, and a policy that needs the originating identity reads this
   * member rather than a local `sub` silently overwritten with a foreign value.
   */
  originPrincipal?: { iss: string; sub: string };
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
  /**
   * @spec txn-authorization#challenge-redemption step 1, step 7 — whether the
   * credential behind `jti` is STILL LIVE according to the issuer's own
   * records, resolved through the same issuance index introspection answers
   * from. A `subject_token`'s `exp` is a claim the credential makes about
   * itself; individual revocation (its delegation family destroyed, its grant
   * gone) happens at the issuer and is invisible in the JWT. Without this a
   * revoked credential keeps redeeming until its nominal expiry.
   */
  subjectTokenLive: (jti: string) => Promise<boolean>;
  now: () => Date;
  txn?: TxnAuthorizationOptions;
}

const DEFAULT_POLL_INTERVAL_S = 5;

/**
 * Tolerance for clock disagreement between the Access Request Service that
 * stamps an approval and the Transaction Authorization Server that relies on
 * it (seconds). Bounded and explicit: without it a future-dated `approved_at`
 * would defeat the maximum-age check simply by being far enough ahead.
 */
const CLOCK_SKEW_S = 30;

/**
 * @spec txn-authorization#challenge-redemption step 5 — the COMPLETE
 * transaction an approval is opened against, recomputed from the workflow's
 * PINNED state. Admission builds it once; completion rebuilds it and compares
 * digests, so an approval adjudicated for any other transaction (another
 * Mission, principal, client, presenter key, operation or parameter set) is
 * refused however it reaches this workflow's task id.
 */
function approvalBindingFor(wf: {
  challenge: TxnChallengeClaims;
  clientId: string;
  subject: string;
  operationType: string;
}): TxnApprovalBinding {
  const origin = wf.challenge.mission.subject;
  return {
    resource: wf.challenge.iss,
    txn: wf.challenge.txn,
    mission: wf.challenge.mission,
    operation_type: wf.operationType,
    authorization_details: wf.challenge.authorization_details,
    parameter_digest: wf.challenge.parameter_digest,
    subject: wf.subject,
    ...(origin ? { origin_principal: origin } : {}),
    client_id: wf.clientId,
    cnf_jkt: wf.challenge.cnf.jkt,
  };
}

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
  // @spec txn-authorization#challenge-redemption step 1 — the credential's
  // IDENTITY, not merely its claims: `jti` is what the issuer's records are
  // consulted under. A credential this AS cannot name is one it cannot check
  // the liveness of, so it is refused rather than trusted on its `exp` alone.
  const subjectJti = subject.jti;
  if (typeof subjectJti !== "string" || !subjectJti) {
    fail(ctx, 400, "invalid_grant", "subject_token carries no jti");
    return;
  }
  if (!(await deps.subjectTokenLive(subjectJti))) {
    fail(ctx, 400, "invalid_grant", "subject_token is no longer live");
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
  // @spec mission#the-mission-claim — the workflow's subject is the
  // `subject_token`'s OWN `sub`: the principal in THIS Authorization Server's
  // namespace, which is what the transaction token's `sub` means. The
  // issuer-qualified origin principal stays in `mission.subject`, preserved
  // verbatim on the copied claim; flattening it into `sub` would put a foreign
  // namespace's identifier in a local OAuth subject and lose the qualification
  // the cross-domain profile exists to keep.
  const subjectId = String(subject.sub ?? "");
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
    subjectTokenJti: subjectJti,
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
    const binding = approvalBindingFor(workflow);
    let taskId: string;
    try {
      ({ taskId } = txn.ars.openForTxn({
        txn: challenge.txn,
        resource: challenge.iss,
        missionId,
        action,
        parameter_digest: challenge.parameter_digest,
        subject: workflow.subject,
        requires_action_approval: requiresApproval,
        binding,
        binding_digest: txnApprovalBindingDigest(binding),
      }));
    } catch {
      // The correlation identity is already held by a DIFFERENT transaction.
      // Resolving to its approval would grant this operation one adjudicated
      // for something else, so admission fails closed here.
      fail(ctx, 400, "invalid_grant", "this txn is already bound to a different transaction");
      return;
    }
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
  if (wf.state === "issued" && wf.issuedToken) {
    // At most one authorization result per workflow: repeated polling after a
    // decision returns the SAME token (same jti), never a second issuance.
    const servedAtS = Math.floor(deps.now().getTime() / 1000);
    respondWithToken(
      ctx,
      wf.issuedToken,
      (wf.issuedExpS ?? servedAtS) - servedAtS,
      wf.challenge.authorization_details,
    );
    return;
  }
  // The completion checks, run as ONE pass. They run TWICE: once before the
  // fresh decision, and again immediately before the mint. An `await` on a
  // deployment's decision is a real window -- a revocation, a containment, an
  // expiry or a lifecycle transition can land inside it -- and a token minted
  // on inputs read before that window would be authorized by a state that no
  // longer holds. One helper, so the two passes cannot drift apart.
  const before = await completionChecks(deps, txn, wf, workflows);
  if (!before.ok) {
    fail(ctx, 400, before.error, before.description);
    return;
  }

  // 7. The FRESH authorization decision. Completion of step 6 alone MUST NOT
  //    issue and MUST NOT bypass this: every input below is re-read NOW, not
  //    replayed from admission.
  const fresh = await txn.freshDecision({
    txn: wf.challenge.txn,
    missionId: wf.missionId,
    resource: wf.challenge.iss,
    action: wf.action,
    operationType: wf.operationType,
    clientId: wf.clientId,
    subject: wf.subject,
    ...(wf.challenge.mission.subject ? { originPrincipal: wf.challenge.mission.subject } : {}),
    parameterDigest: wf.challenge.parameter_digest,
    authorizationDetails: before.permitted,
    cnfJkt: wf.challenge.cnf.jkt,
    approval: before.approval,
  });
  if (fresh.decision !== "permit") {
    fail(ctx, 400, "access_denied", fresh.reason ?? "the fresh authorization decision denied the operation");
    return;
  }

  // The fence: the whole pass again, on a RE-READ clock and re-read state, with
  // nothing between it and the mint. A permit is a statement about the moment
  // it was computed, not a licence to issue later.
  const after = await completionChecks(deps, txn, wf, workflows);
  if (!after.ok) {
    fail(ctx, 400, after.error, after.description);
    return;
  }
  const nowS = after.nowS;
  const exp = after.exp;

  // @spec txn-authorization#transaction-token — `parameter_digest` is copied
  // only after it has been verified against the challenge (the approval above
  // is bound to the same value), and `mission` is the challenge's profiled
  // members, value-equal by construction.
  //
  // The mint runs BEFORE the issuance slot is taken: a signing error here
  // leaves nothing reserved, so a later poll completes cleanly instead of
  // pending forever against a wedged, token-less reservation.
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

  // At most one authorization result per (resource, txn): reserving the slot
  // and storing the token commit together, so a taken slot ALWAYS has its
  // token and a second token under a different jti is structurally impossible.
  if (!workflows.reserveAndRecordIssuance(wf.challenge.iss, wf.challenge.txn, wf.id, token, tokenJti, exp)) {
    if (workflows.issuanceHolder(wf.challenge.iss, wf.challenge.txn) === wf.id) {
      // A concurrent poll of THIS workflow won the slot: its token is already
      // stored (the reserve-and-record is atomic), so the losing mint is
      // discarded -- never returned, never observable -- and the stored token
      // is served, stably.
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
    }
    fail(ctx, 400, "access_denied", "this transaction already produced an authorization result");
    return;
  }
  respondWithToken(ctx, token, exp - nowS, wf.challenge.authorization_details);
}

/** One completion pass that refused, with the wire error it maps to. */
interface CompletionRefusal {
  ok: false;
  error: string;
  description?: string;
}

/** One completion pass that held, with everything the mint needs. */
interface CompletionPass {
  ok: true;
  /** The clock THIS pass read. */
  nowS: number;
  approval: NonNullable<ReturnType<TxnArs["getTask"]>>["approval"] & object;
  /** The permitted set, as pinned on the challenge. */
  permitted: AuthorityEntry[];
  /** The token's exp, computed from THIS pass's clock and Mission state. */
  exp: number;
}

/**
 * @spec txn-authorization#challenge-redemption steps 6 and 7,
 * #two-phase-expiry — every condition a transaction token's issuance rests on,
 * evaluated against the state and the clock AS OF THIS CALL.
 *
 * It is one function because it runs twice: before the deployment's fresh
 * decision, and again immediately before the mint. Nothing here is replayed
 * from admission except what the profile PINS (the challenge snapshot, the
 * `subject_token`'s own terms, the Mission's expiry at admission); everything
 * else -- the clock, the approval, the credential's liveness, Mission state,
 * the effective Authority Set -- is re-read.
 */
async function completionChecks(
  deps: TxnAuthorizationDeps,
  txn: TxnAuthorizationOptions,
  wf: TxnWorkflowRecord,
  workflows: TxnWorkflowStore,
): Promise<CompletionPass | CompletionRefusal> {
  const nowS = Math.floor(deps.now().getTime() / 1000);
  // @spec txn-authorization#two-phase-expiry — the workflow's OWN lifetime is
  // what expires here. An async approval completing after the challenge's exp
  // but within this window still issues; the challenge exp is already consumed.
  if (nowS >= wf.expiresAtS) return { ok: false, error: "expired_token" };
  // The workflow reserved admission but has not opened its approval yet (a
  // crash between the two, or a concurrent submission still in flight). There
  // is nothing to decide on yet; the workflow's own lifetime bounds the wait.
  if (!wf.taskId) return { ok: false, error: "authorization_pending" };

  const task = txn.ars.getTask(wf.taskId);
  if (task?.state === "denied") {
    workflows.setState(wf.id, "denied");
    return { ok: false, error: "access_denied" };
  }
  // 6. The approval's status, scope, grant time, maximum age and
  //    `approved_until`.
  if (!task || task.state !== "approved" || !task.approval) {
    return { ok: false, error: "authorization_pending" };
  }
  // The approval is only ever SATISFIED by approval state. A stronger
  // authentication context on `subject_token` (RFC 9470 step-up) proves who is
  // present; it never stands in for this, and nothing below reads it.
  const approval = task.approval;
  if (approval.parameter_digest !== wf.challenge.parameter_digest) {
    return { ok: false, error: "access_denied", description: "approval is not bound to the challenged operation" };
  }
  // The approval is bound to the WHOLE transaction, not to its parameters: the
  // digest above identifies the operation's parameters, and the same parameters
  // are reachable under another Mission, principal, client or presenter key.
  // The expected binding is recomputed from THIS workflow's pinned state, so an
  // approval opened under any other transaction is refused here -- before the
  // fresh decision ever sees it as context.
  if (approval.binding_digest !== txnApprovalBindingDigest(approvalBindingFor(wf))) {
    return { ok: false, error: "access_denied", description: "approval is not bound to this transaction" };
  }
  const approvedUntilS = Math.floor(Date.parse(approval.approved_until) / 1000);
  const approvedAtS = Math.floor(Date.parse(approval.approved_at) / 1000);
  const maxAgeS = txn.maxApprovalAgeSeconds ?? 300;
  if (!Number.isFinite(approvedUntilS) || approvedUntilS <= nowS) {
    return { ok: false, error: "access_denied", description: "approval is no longer current" };
  }
  if (!Number.isFinite(approvedAtS) || nowS - approvedAtS > maxAgeS) {
    return { ok: false, error: "access_denied", description: "approval is older than the maximum age" };
  }
  // Approval time sanity, bounded by an explicit skew allowance. A grant time
  // in the FUTURE would otherwise pass the maximum-age check by construction
  // (its age is negative), and an approval whose validity ends before it began
  // never described a window at all.
  if (approvedAtS > nowS + CLOCK_SKEW_S) {
    return { ok: false, error: "access_denied", description: "approval was granted in the future" };
  }
  if (approvedUntilS < approvedAtS) {
    return { ok: false, error: "access_denied", description: "approval validity ends before it was granted" };
  }

  // The subject's credential, on BOTH terms: the expiry it asserts about
  // itself, and whether the issuer still stands behind it. Individual
  // revocation is invisible in the JWT, so the second is the authoritative one.
  if (wf.subjectTokenExpS <= nowS) {
    return { ok: false, error: "access_denied", description: "subject_token is no longer valid" };
  }
  if (!(await deps.subjectTokenLive(wf.subjectTokenJti))) {
    return { ok: false, error: "access_denied", description: "subject_token is no longer live" };
  }

  let gated: MissionRecord;
  try {
    // The lineage-grade active gate, not a bare derivation gate: a non-active
    // ancestor refuses here too.
    gated = deps.kernel.gateActive(wf.missionId);
  } catch (e) {
    if (e instanceof GateError) return { ok: false, error: "access_denied", description: e.message };
    throw e;
  }
  // Containment may have narrowed the Mission since admission, so the subset
  // rule is recomputed against the CURRENT effective set, never the pinned one.
  const permitted = wf.challenge.authorization_details as unknown as AuthorityEntry[];
  if (!isSubsetSet(permitted, deps.kernel.effectiveAuthoritySet(gated))) {
    return {
      ok: false,
      error: "access_denied",
      description: "challenge authority is no longer within the effective Authority Set",
    };
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
    return { ok: false, error: "access_denied", description: "no lifetime remains for a transaction token" };
  }
  return { ok: true, nowS, approval, permitted, exp };
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
