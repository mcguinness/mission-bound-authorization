/**
 * @spec mission#rs-enforcement, runtime (PEP), authzen (envelope)
 *
 * The resource-server PEP for the payments estate. Validates the DPoP-bound
 * token and mission claim, builds the AuthZEN envelope (context.actor via
 * @mission/actor-chain, parameter_digest), obtains a PDP decision, retains
 * the Decision Evidence the PDP emitted with it, and emits its own Refusal
 * Records and Execution Evidence. Core enforcement tier (M4); the
 * transaction-assurance tier (permits/leases) lands in M5. Presents the selected
 * capability definition from the same snapshot discovery serves (#657 B2).
 */

import { randomUUID } from "node:crypto";
import { type ActObject, buildContextActor, flattenActChain } from "@mission/actor-chain";
import {
  type ActionPhase,
  type CredentialAuthorityEntry,
  coveringCredentialEntries,
  credentialEntriesFromAuthority,
  entryMatchesTarget,
  establishOperationTarget,
  type IdempotencyScope,
  idempotencyScopeDigest,
  isActionPhase,
  type JsonValue,
  type OperationContract,
  type OperationTargetResolution,
  type PropagatedMissionReference,
  TXN_AUTHORIZATION_REQUIRED,
  type TxnMissionClaim,
} from "@mission/core";
import { getTracer } from "@mission/telemetry";
import {
  type AudienceContext,
  type AudienceValidation,
  type AuthorityEntry,
  type BoundaryEstablishment,
  type ClaimChannel,
  committedEntry,
  type DecisionEvidenceObject,
  type DecisionFn,
  type DecisionOptions,
  type DelegatePolicy,
  type Decision,
  EnforcementBoundaryContext,
  lineageScopeDigests,
  type EntitlementResolver,
  type JoinMappingContract,
  evaluate,
  type EvaluateOptions,
  isDecisionChannelRefusal,
  type EvaluationRequest,
  type Fga,
  idempotencyScopeOf,
  type MissionStateObservation,
  type MissionView,
  newRecordId,
  operationIdentity,
  parseStateObservation,
  type OriginPrincipal,
  type PrincipalMappingResolver,
  RUNTIME_POSTURE,
  relationForAction,
  stalenessBound,
  stateSourcePlacement,
  type StateSourcePlacement,
} from "@mission/pdp";
import {
  buildEffectiveParams,
  buildListEffectiveParams,
  type EffectiveParams,
  type ListEffectiveParams,
  parameterDigest,
} from "./effective-params.js";
import type {
  EvidenceStore,
  ExecutionEvidenceObject,
  PepRefusalDenialReason,
  RuntimeHopReference,
} from "./evidence.js";
import type { PaymentsStore } from "./payments-store.js";
import { operationKey } from "./transaction.js";
import { signChallenge } from "./txn-challenge.js";
import type { PendingOperation } from "./txn-store.js";
import { PaymentsToolCatalog, type CapabilityCatalog, type CapabilitySnapshot } from "./tool-catalog.js";
import { admitArguments } from "./intake.js";

export const CANONICAL_RESOURCE = process.env.MCP_PAYMENTS_RESOURCE ?? "http://localhost:4403/mcp";

/**
 * @spec runtime#runtime-conformance (#853, D487): this PEP's location in the
 * Enforcement Scope Statement, the key it establishes its enforcement
 * boundary under.
 */
export const PAYMENTS_PEP_LOCATION = "mcp-payments-pep";

/**
 * @spec runtime#runtime-conformance, runtime-oauth#token-validation (#853,
 * D487): the payments PEP's boundary context over the published statement.
 * The shipped statement declares the boundary `CANONICAL_RESOURCE`, the
 * protected resource's RFC 9728 `resource` string, and no audience alias.
 */
export function paymentsBoundaryContext(statement: unknown = RUNTIME_POSTURE): EnforcementBoundaryContext {
  return new EnforcementBoundaryContext(statement, PAYMENTS_PEP_LOCATION);
}

/**
 * @spec runtime#runtime-conformance (#853, D487): the caller-visible refusal
 * when this PEP cannot establish its enforcement boundary. It has no Refusal
 * Record: the record REQUIRES an `audience`, and none is invented.
 */
export const BOUNDARY_UNRESOLVABLE = "boundary_unresolvable";

/**
 * @spec runtime#boundary-identifier-change step 1 (#853 review): the
 * caller-visible refusal while the version in force declares this PEP's
 * boundary but a bound consumer (a published key set, a settlement verifier,
 * the PDP's claim domain) is not yet provisioned for it. No producer uses the
 * new identifier until every consumer accepts it, so, as for
 * {@link BOUNDARY_UNRESOLVABLE}, no record is made.
 */
export const BOUNDARY_UNPROVISIONED = "boundary_unprovisioned";

/**
 * @spec runtime-evidence#execution-evidence-object `error` (#853, D487): the
 * disposition of a permit whose enforcement boundary is no longer the one
 * this PEP establishes, after a declared cutover invalidated the permits
 * decided under the previous boundary. The cutover is an operator control,
 * and the closed set names that `kill_switch`.
 */
export const BOUNDARY_CUTOVER_ERROR = "kill_switch";
/** The tool-id base for this server's capabilities (@spec runtime-evidence#evidence-extensions `capability_source.tool_id`). */
export const TOOL_BASE = "mcp://payments.demo/tools";

/**
 * @spec txn-authorization#offline-verification — present exactly when the
 * credential presented on THIS request was a transaction token. The retry of a
 * challenged operation carries the transaction token as its SOLE OAuth
 * credential, so these are the verified claims the enforcement path works from;
 * a credential carrying this marker authorizes the challenged operation and
 * nothing else.
 */
export interface TxnCredential {
  /** The `txn` the credential is bound to; consumption is keyed on it. */
  txn: string;
  jti: string;
  iatS: number;
  expS: number;
  /** The token's own `parameter_digest`, already matched to the pending operation. */
  parameterDigest: string;
}

/** Validated token facts the PEP works from (token validation is upstream). */
/**
 * Fields common to both a Mission-bound and an ordinary (baseline-Join)
 * credential; see {@link MissionBoundTokenFacts}, {@link OrdinaryTokenFacts},
 * and {@link TokenFacts} below for why they are split.
 */
export interface CommonTokenFacts {
  /** Credential issuer/expiry established by the token verifier; never raw claims. */
  credential?: EvaluationRequest["context"]["credential"];
  sub: string;
  clientId: string;
  clientInstanceId?: string;
  act?: ActObject;
  /**
   * @spec authzen#pdp-request rule 10 — this resource's own issuer identity
   * (the `iss` every ordinary token here verifies against), carried so the
   * envelope can populate `subject.properties.iss`: the authenticated
   * destination-local token subject's home issuer. A resource-wide constant,
   * not read from the presented token.
   */
  iss?: string;
  cnfJkt: string;
  /**
   * @spec continuation: the access token's `jti`, carried so an action taken
   * under a continued credential attributes to the specific hop (below).
   * Absent for non-JWT or older tokens.
   */
  jti?: string;
  /**
   * @spec continuation: the token's top-level `identity_continuation_handle`
   * when present (the new-hop continuation handle from the ID-JAG lineage).
   */
  identityContinuationHandle?: string;
  /**
   * @spec txn-authorization#offline-verification — present when the credential
   * for this request was a transaction token (see {@link TxnCredential}).
   * Absent for every ordinary Mission-bound credential.
   */
  txn?: TxnCredential;
  /**
   * @spec runtime-oauth#token-validation, runtime#boundary-identifier-change
   * (#853, D487): the enforcement boundary, and the statement version that
   * declared it, this credential's `aud` was validated against. Every server
   * validator sets it ({@link ValidatedBoundary}). The PEP refuses the request
   * when the boundary or version it establishes for the decision is not this
   * one, so a cutover between validation and decision never moves a
   * credential into a boundary that did not accept it. Absent only on facts a
   * caller assembled without a server validator.
   */
  validatedBoundary?: ValidatedBoundary;
}

/** The boundary and statement version a credential's audience was validated against. */
export interface ValidatedBoundary {
  boundary: string;
  version: string;
}

/** A credential carrying the `mission` claim: the ordinary, pre-#557 shape. */
export interface MissionBoundTokenFacts extends CommonTokenFacts {
  mission: {
    id: string;
    issuer: string;
    /**
     * @spec mission#the-mission-claim (#702) — NOT on the baseline `mission`
     * claim; carried into the AuthZEN envelope only when the validated token
     * happens to carry it (a companion profile's own extension member).
     * Present-then-check downstream ({@link evaluate.ts}'s view-consistency
     * rule 1), never required.
     */
    authority_hash?: string;
    /**
     * @spec cross-domain#mission-subject — the verified token's immutable
     * origin principal, present only where the Origin Principal profile
     * applies. Carried unchanged from the validated claim into the AuthZEN
     * envelope's `context.mission.subject`, never from an unverified request
     * value.
     */
    subject?: OriginPrincipal;
  };
  /**
   * @spec txn-authorization#resource-challenge — the VERIFIED token's whole
   * `mission` claim. A challenge copies it unchanged (including the invariant
   * origin principal where the Origin Principal profile applies), so the
   * resource must keep the claim it verified, not just the two members the
   * PDP envelope needs. Absent for a credential whose claim is not the
   * profiled shape; the resource then issues no challenge.
   */
  missionClaim?: TxnMissionClaim;
  /**
   * @spec runtime#input-authority, runtime-oauth#authorization-details-mapping
   * (#825) — the authority the VERIFIED credential itself carries: an access
   * token's `authorization_details`, an attenuation chain's leaf `tools` with
   * every restriction they carry, a transaction token's pinned operation
   * entry. It is its own bound, checked before the PDP is asked: a broader
   * Mission never repairs it, and its absence never falls back to the
   * Mission.
   */
  credentialAuthority: readonly CredentialAuthorityEntry[];
}

/**
 * @spec authority-server#mission-join (#557 review point 5) — an ordinary
 * OAuth credential validated for a configured MAS-governed route
 * (`PepDeps.masJoin`), carrying NO `mission` claim at all. `mission`/
 * `missionClaim` are explicitly typed `undefined` (never simply omitted from
 * the type), so `TokenFacts` below is a genuine discriminated union on
 * `mission`'s presence, not a single hybrid shape with an optional field a
 * caller could forget to check. `Pep.enforceInner` branches on `token.mission`
 * once, at the top: present ({@link MissionBoundTokenFacts}), the
 * credential-carried claim governs exactly as before; absent (this type),
 * `enforceInner` resolves the baseline mapping Join against a PEP-supplied
 * propagated reference (`RequestSignals.missionReference`) before anything
 * else runs, and the PDP itself denies `mission_binding_failed` on a failed
 * subject/client join, never falling back to an unjoined decision (#557
 * review point 1).
 */
export interface OrdinaryTokenFacts extends CommonTokenFacts {
  mission?: undefined;
  missionClaim?: undefined;
  /**
   * @spec authority-server#mission-join rule 8 (bound 1) — the credential's
   * own `scope` claim, verbatim from the verified token. It is what the
   * acting credential carries AS ISSUED, the input a deployment's
   * `resolveOrdinaryAuthority` evaluator maps to authority; absent on a
   * credential that carries no `scope` at all, which that evaluator then
   * resolves to no authority rather than to an unbounded one. Never read on
   * the Mission-bound path, where the Mission's own Authority Set governs.
   */
  scope?: string;
}

/**
 * @spec authority-server#mission-join (#557 review point 5) — a discriminated
 * union on `mission`'s presence, not `MissionBoundTokenFacts["mission"]`
 * made optional on one hybrid interface: the previous single-interface shape
 * with `mission?:` let a caller reach `token.mission!.id` (an unsafe
 * assertion, `demo/src/server.ts`'s prior shape) instead of the type system
 * proving presence. `validateToken`/`validateMissionToken` (server.ts) now
 * return `Promise<MissionBoundTokenFacts>` specifically, so a caller of
 * either needs no assertion at all; `validateOrdinaryToken` returns
 * `Promise<OrdinaryTokenFacts>`. `TokenFacts` remains the type for a call
 * site that accepts either (`Pep.enforce`, `toolsList`, `execute`, ...),
 * where `if (token.mission)` narrows exactly as it always has.
 */
export type TokenFacts = MissionBoundTokenFacts | OrdinaryTokenFacts;

export interface ActionMapping {
  action: string;
  /**
   * @spec runtime#classification — the action class this deployment assigns
   * the crossing, by the class predicates (the payments Operation Profile,
   * `src/docs/operation-profile-payments-v1.md`). Every entry carries one, so
   * no mediated crossing reaches the PDP unclassified and falls back to the
   * default; the class is sent on every decision request and recorded in
   * Decision Evidence with `class_source: "deployment"`.
   */
  actionClass: "consequential_read" | "consequential_write" | "irreversible_action" | "external_commitment";
  /**
   * The execution tier the crossing routes to: `transaction-assurance` takes
   * the single-use permit, execution lease, and connector path. Absent means
   * the core read and write paths. Kept apart from {@link actionClass}: a
   * class is a classification, not a routing decision.
   */
  tier?: "transaction-assurance";
  /**
   * @spec runtime#compound-actions — the phase of the crossing this tool
   * makes, when the Operation Profile places the operation in a compound
   * action. Absent for an ordinary operation that is no phase of one.
   *
   * This is the AUTHORITATIVE value: the PEP supplies it on the decision
   * request and compares the permit's `conditions.action_phase` against it at
   * use, and it MUST NOT be taken from an agent-supplied argument. It is
   * pinned against the trusted catalog's own per-tool declaration
   * (`CATALOG_TOOL_BINDINGS`) by a consistency test, so the profile and the
   * served catalog cannot drift.
   */
  phase?: ActionPhase;
  /**
   * @spec resource-access#resource-matching (#1276, D447, D457): this
   * operation's documented, trusted operation contract: how the PEP
   * establishes its target before any authority is matched. The payments
   * contract is service-level: every payments tool acts on the service
   * {@link CANONICAL_RESOURCE} names, and actions and constraints determine
   * the permitted operations within it
   * (`src/docs/operation-profile-payments-v1.md`).
   *
   * Absent means no contract: the operation is refused before any decision
   * request, never matched against the protected resource's metadata
   * identifier or the token's audience by default. A finer contract form is
   * unsupported and refuses too, and declarations naming different targets
   * are ambiguous and refuse. Never read from an agent argument.
   */
  target?: OperationContract | readonly OperationContract[];
  needsInvoice: boolean;
  /**
   * @spec runtime#idempotency, authzen#parameter-digest (#917, #918): the
   * Operation Profile defines an idempotency key for this operation: a
   * non-idempotent high-consequence one, whose key the PDP claims, or a
   * reversible write electing the "short validity window combined with an
   * idempotency key" control (@spec runtime#permit-binding), whose key this
   * PEP reserves. The caller supplies `idempotency_key` (one key per intended
   * execution) and this PEP forwards it unchanged as
   * `action.properties.idempotency_key`; it never enters `parameter_digest`,
   * which is built from store state alone.
   */
  idempotencyKey?: true;
  /**
   * @spec runtime#read-binding — this action's unfiltered form requests a
   * bulk, cross-vendor result, which the read-binding floor MUST bind: a
   * supplied `vendor_id` binds through the ordinary vendor-constraint check
   * every invoice-scoped action uses; absent one, the returned set binds to
   * the matched Authority Set entry's OWN vendor scope, never the
   * unconstrained store (see the `bindsVendorScope` branch in
   * {@link Pep.enforceInner}).
   */
  bindsVendorScope?: boolean;
  /**
   * @spec runtime#input-authority (#825) — the operation targets one vendor,
   * named by its `vendor_id` argument. The PEP resolves that vendor from
   * authoritative store state, so the credential bound sees the vendor the
   * operation reaches; an argument naming no stored vendor is refused
   * `unknown_vendor` before any decision (#1251, D484).
   */
  targetsVendor?: true;
  /**
   * @spec resource-access#initial-common-constraints (#1266): the operation
   * addresses recipients. The PEP resolves every final recipient from the
   * vendor's own remittance routing (lists expanded), carries them as the
   * `recipient_domain` fact, binds a routed set into `parameter_digest`, and
   * the connector sends to exactly that set. Recipients it cannot resolve
   * refuse the operation before any decision.
   */
  reachesRecipients?: true;
}

/**
 * The recipient members an invoice-scoped operation's effective parameters
 * carry: none for an operation that addresses no one or a vendor with no
 * routing of its own (its default address is a function of `vendor_id`, which
 * the digest already binds), the routed set otherwise, and `null` when the
 * routing cannot be resolved.
 */
export function recipientParams(
  reachesRecipients: boolean,
  payments: PaymentsStore,
  vendorId: string,
): { recipients?: string[] } | null {
  if (!reachesRecipients) return {};
  const resolved = payments.remittanceRecipients(vendorId);
  if (!resolved) return null;
  return resolved.routed ? { recipients: resolved.recipients } : {};
}

/**
 * The enforcement surface's trusted Operation Profile.
 *
 * @spec runtime#compound-actions — `payments:payment.execute` is a compound
 * action whose three crossings SHARE that one action identifier:
 * `check_transfer` (preflight, no reservation and no external effect),
 * `hold_transfer` (prepare, a hold that is state and never commit authority),
 * and `execute_wire_transfer` (commit, the irreversible effect). All three
 * normalize the SAME effect inputs over the same invoice, so they produce one
 * identical `parameter_digest`: the phase is the only thing distinguishing a
 * prepare permit from a commit permit, which is exactly what the phase
 * binding exists to catch.
 */
/**
 * @spec resource-access#resource-matching (#1276, D447, D452, D457): the
 * payments operation contract: explicitly service-level. Every payments tool
 * acts on the service {@link CANONICAL_RESOURCE} identifies, so an `exact`
 * entry naming that identifier covers the tool's action there, and actions
 * and constraints determine the permitted operations within the service.
 * Declared per tool below, never assumed for a tool that omits it.
 */
const PAYMENTS_SERVICE_CONTRACT: OperationContract = Object.freeze({ service: CANONICAL_RESOURCE });

const TOOL_ACTIONS: Record<string, ActionMapping> = {
  list_invoices: { action: "payments:invoice.list", actionClass: "consequential_read", target: PAYMENTS_SERVICE_CONTRACT, needsInvoice: false, bindsVendorScope: true },
  get_invoice: { action: "payments:invoice.read", actionClass: "consequential_read", target: PAYMENTS_SERVICE_CONTRACT, needsInvoice: true },
  lookup_vendor: { action: "payments:vendor.read", actionClass: "consequential_read", target: PAYMENTS_SERVICE_CONTRACT, needsInvoice: false, targetsVendor: true },
  schedule_payment: { action: "payments:payment.schedule", actionClass: "consequential_write", target: PAYMENTS_SERVICE_CONTRACT, needsInvoice: true, idempotencyKey: true },
  cancel_scheduled_payment: { action: "payments:payment.schedule.cancel", actionClass: "consequential_write", target: PAYMENTS_SERVICE_CONTRACT, needsInvoice: true, idempotencyKey: true },
  check_transfer: { action: "payments:payment.execute", phase: "preflight", actionClass: "consequential_read", target: PAYMENTS_SERVICE_CONTRACT, needsInvoice: true },
  hold_transfer: { action: "payments:payment.execute", phase: "prepare", actionClass: "consequential_write", target: PAYMENTS_SERVICE_CONTRACT, needsInvoice: true },
  execute_wire_transfer: { action: "payments:payment.execute", phase: "commit", actionClass: "irreversible_action", tier: "transaction-assurance", target: PAYMENTS_SERVICE_CONTRACT, needsInvoice: true, idempotencyKey: true },
  send_remittance_email: { action: "payments:remittance.send", actionClass: "external_commitment", tier: "transaction-assurance", target: PAYMENTS_SERVICE_CONTRACT, needsInvoice: true, idempotencyKey: true, reachesRecipients: true },
};

/**
 * @spec runtime#read-binding — synthetic check object for a bulk
 * `list_invoices` request whose bound vendor set is EMPTY: an entry whose
 * `vendors` allowlist is empty (its own constraint refuses the placeholder),
 * or an unconstrained entry over a store with no invoices. There is no vendor
 * to name, and no FGA object type here supports a wildcard check target, so
 * this fixed placeholder is the request object; no stored Resource-policy
 * entitlement names it, so the deployment's policy refuses it (#828 step 5).
 */
const UNSCOPED_VENDOR_OBJECT = "__unscoped__";

/**
 * @spec runtime#read-binding: the pure normal-form derivation for a bound
 * `list_invoices` read, over the CURRENT matched entry, the caller's
 * (possibly absent) store-resolved `vendor_id`, and the vendors the payments
 * store's invoices currently name. Used at decision time (against the entry
 * `enforceInner` just matched) and again at {@link Pep.reverifyList} (against
 * a freshly loaded entry and a fresh store read), so a change to the
 * Mission's own authority, or to the vendors the store holds invoices for,
 * between those two calls recomputes a DIFFERENT normal form rather than
 * silently repeating the stale one. `requestedVendorId`'s in-scope test
 * mirrors the FGA/entry-constraint check the request goes on to face: a
 * requested vendor that is (no longer) in the entry's `constraints.vendors`
 * normalizes to an EMPTY scope, never to `[requestedVendorId]` regardless of
 * authority. An unconstrained entry's scope is every vendor the read would
 * return (#828 step 5), so the digest, the result filter and Resource policy
 * all name the same actual targets.
 */
function deriveVendorScope(
  entry: AuthorityEntry | undefined,
  requestedVendorId: string | undefined,
  invoiceVendorIds: readonly string[],
): { vendor_scope: string[]; vendor_scope_source: "requested" | "entry" | "all" } {
  const allowedVendors = entry?.constraints?.vendors;
  if (requestedVendorId !== undefined) {
    const inScope = !allowedVendors || allowedVendors.includes(requestedVendorId);
    return { vendor_scope: inScope ? [requestedVendorId] : [], vendor_scope_source: "requested" };
  }
  if (allowedVendors) {
    return { vendor_scope: [...allowedVendors].sort(), vendor_scope_source: "entry" };
  }
  return { vendor_scope: [...new Set(invoiceVendorIds)].sort(), vendor_scope_source: "all" };
}

/**
 * @spec authzen#response-context, runtime#decision-output: the permit's
 * decision CONDITIONS live NESTED inside `decision.context.conditions`
 * (never as flat top-level members): the declarative constraints on RELYING
 * on the permit that the draft names verbatim ("a request binding, a
 * validity bound, a use limit"), which map 1:1 onto the profile's own
 * condition names: `parameter_digest` (request binding), `valid_until`
 * (validity bound), `use_limit` (use limit). A member inside `conditions`
 * this PEP does not recognize makes the permit unusable; a top-level member
 * OUTSIDE `conditions` (decision metadata such as `decision_id`,
 * `policy_view_id`, `action_class`, `class_source`, `entry_digest`, or a
 * profile response member such as `evaluation_id`/`reason`) is accepted
 * without enumeration: this PEP reads the specific ones it needs and
 * otherwise ignores what it does not, since the profile's must-understand
 * rule for an unrecognized member is scoped to `conditions` alone, never to
 * the whole response context.
 */
/**
 * @spec authzen#response-context — the permit's decision conditions live
 * NESTED under `decision.context.conditions`. One accessor, so no site
 * re-derives the nesting.
 */
function conditionsOf(decision: Decision | undefined): Record<string, unknown> | undefined {
  return decision?.context.conditions as Record<string, unknown> | undefined;
}

const RECOGNIZED_CONDITIONS: ReadonlySet<string> = new Set([
  "parameter_digest",
  "valid_until",
  "use_limit",
  // @spec runtime#compound-actions, authzen#response-context `action_phase` —
  // this PEP recognizes and ENFORCES the phase condition (Pep.verifyPermitAtUse
  // compares it against the crossing's own Operation Profile phase at use).
  // Recognition has to land with, or before, the comparison: a PEP that
  // enforced the condition without recognizing it would refuse every permit
  // carrying one as an unrecognized member instead.
  "action_phase",
]);

/**
 * One condition comparison the executing PEP makes before releasing an
 * effect. EVERY row runs at EVERY use of the permit: no row may opt out of
 * the last one, because the comparison a row skips there is a comparison the
 * crossing was never held to. The rows carried a `timeSensitive` flag that
 * excused `action_phase` from the pre-effect stage on the premise that a
 * phase cannot move while an awaited read is pending; the Operation Profile
 * is live, so it can, and a crossing removed from it after admission was
 * released on the strength of a comparison that no longer held.
 *
 * Every comparator is therefore SYNCHRONOUS over state already in hand (the
 * clock, the retained attempt, the in-memory Operation Profile). That is what
 * makes running the whole table at the final boundary free: it adds no
 * awaited read, so it cannot widen the window between the last check and the
 * effect. A comparator that needed an awaited read would have to be ordered
 * ahead of the time comparison below rather than admitted here as it stands.
 *
 * `failure` returns the enumerated Execution Evidence `error` for a failed
 * comparison, or `undefined` when it holds. Every value here is already in
 * that closed set (@spec runtime-evidence#execution-evidence-object); this
 * seam adds none.
 */
interface PermitUseCheck {
  name: string;
  failure: (
    attempt: ExecutionAttempt,
    ctx: { now: Date; profile: ActionMapping | undefined; boundary: BoundaryEstablishment },
  ) => string | undefined;
}

const PERMIT_USE_CHECKS: readonly PermitUseCheck[] = [
  {
    // @spec runtime#runtime-conformance, runtime#permit-binding (#853, D487):
    // a permit binds the enforcement boundary it was decided at. The boundary
    // is re-established from the declaration at every use, so a permit
    // decided before a declared cutover, a cacheable read's or one phase of a
    // multi-phase operation included, is unusable after it: the in-flight
    // operation is refused and restarts under the new boundary, never carried
    // across. The disposition keeps the permit's original `audience`. The
    // statement version is compared too: the permit's credential was
    // validated under that version's audience rule, which a later version can
    // narrow while keeping the identifier.
    name: "enforcement_boundary",
    failure: (attempt, { boundary }) =>
      boundary.ok && boundary.boundary === attempt.audience && boundary.version === attempt.boundaryVersion
        ? undefined
        : BOUNDARY_CUTOVER_ERROR,
  },
  {
    // @spec runtime#compound-actions — "The executing PEP MUST compare the
    // permit's bound phase with the phase of the crossing before releasing an
    // effect. Unequal phases, an absent binding where the Operation Profile
    // identifies a phase, or a phase that cannot be established MUST cause
    // refusal, fail closed". The converse is the AuthZEN rule that a phase
    // condition on a crossing whose profile declares no phase "is invalid
    // there", which is the last arm below.
    name: "action_phase",
    failure: (attempt, { profile }) => {
      // The profile no longer places this tool at all: the crossing's phase
      // cannot be established at use, which refuses rather than defaulting to
      // "no phase" and letting a phase-bound permit through. The profile is
      // re-read at each use, never snapshotted at admission: a snapshot would
      // still answer with the phase the crossing has since lost.
      if (!profile) return "phase_mismatch";
      const crossing = profile.phase;
      const bound = attempt.permitBoundPhase;
      if (crossing === undefined) return bound === undefined ? undefined : "phase_mismatch";
      // Absent where required, and unknown or malformed where required, are
      // the same refusal: neither establishes the phase the permit bound.
      if (!isActionPhase(bound)) return "phase_mismatch";
      return bound === crossing ? undefined : "phase_mismatch";
    },
  },
  {
    // @spec resource-access#resource-matching (#1276, D447, D457): "MUST
    // execute the operation on the target it matched: matching a different
    // target never authorizes the execution." The target is re-established
    // from the LIVE Operation Profile at every use, exactly as the phase is,
    // and compared with the target the permit was decided on. A contract that
    // moved, or that no longer establishes one target, refuses: a permit is
    // never carried to another target, cacheable reads included.
    //
    // `target_drift` is the closed set's value for a bound decision input
    // that "differs or cannot be established at use"; the Runtime Evidence
    // text names Evaluation-Context Binding there, so this use awaits the
    // #1276 specification change to name the operation target (coordination
    // item, not a new value).
    name: "operation_target",
    failure: (attempt, { profile }) => {
      const current = establishOperationTarget(profile?.target);
      return current.ok && current.target === attempt.operationTarget ? undefined : "target_drift";
    },
  },
  {
    // @spec authzen#response-context, runtime-evidence#execution-evidence-object
    // `permit_expired` — the permit authorizes INITIATION within its validity
    // bound. `valid_until` is REQUIRED on a permit, so an absent or
    // unparseable bound establishes no live window at all and is treated as
    // elapsed: the fail-closed reading, never a permit relied on without one.
    name: "valid_until",
    failure: (attempt, { now }) => {
      const validUntilMs =
        typeof attempt.permitValidUntil === "string" ? Date.parse(attempt.permitValidUntil) : Number.NaN;
      if (!Number.isFinite(validUntilMs)) return "permit_expired";
      return now.getTime() <= validUntilMs ? undefined : "permit_expired";
    },
  },
];

/**
 * @spec runtime#state-freshness, authzen#context-audience-freshness: a loaded
 * MissionView paired with the Mission state observation of the read that
 * produced it, in the AuthZEN profile's own members. `freshness_at` MUST be
 * the time the loader itself read authoritative state, not the time of the
 * `loadView` call that returns it; the two coincide for a synchronous live
 * read (`mode: "fresh"`, the current production loader) and diverge the
 * moment a cache sits in front of one, in which case the cached observation
 * time travels with the data. The PEP propagates this verbatim; it never
 * stamps its own clock over it (Finding 1).
 */
export interface LoadedView {
  view: MissionView;
  observation: MissionStateObservation;
}

/**
 * @spec authority-server#reference-tuple — the canonical (`issuer`,
 * `mission_id`) pair a Mission reference is compared as, whether the source
 * is a credential's own `mission` claim or a PEP-supplied Mission Join
 * reference. `loadView` is keyed on this pair, not `id` alone, so a same-id
 * collision under a different issuer is a load-time miss rather than
 * something each call site must separately catch.
 */
export interface MissionReference {
  id: string;
  issuer: string;
}

/**
 * @spec authority-server#reference-tuple — verifies the loader honored the
 * canonical (issuer, id) key it was asked for, rather than trusting it: not
 * every `loadView` implementation enforces this itself (a fixture matching
 * on `id` alone is common in tests, and the negative-boundary tests for
 * {@link Pep.enforceInner}'s own `mission_reference_conflict` check
 * deliberately keep one). A consumer with no comparable use for that
 * distinction — {@link Pep.reverifyList}, `McpPaymentsServer.toolsList` —
 * MUST resolve `loadView` through this wrapper rather than calling it
 * directly, so a same-id different-issuer collision is a plain miss for
 * them too, never a silently consumed wrong Mission (#685 review). It is
 * NOT used by `enforceInner`: that call site needs to tell "no Mission"
 * apart from "wrong issuer" for its own `mission_reference_conflict`
 * refusal, so it checks the issuer itself and reports the distinction.
 */
export function loadCheckedView(
  loadView: (ref: MissionReference) => LoadedView | undefined,
  ref: MissionReference,
): LoadedView | undefined {
  const loaded = loadView(ref);
  if (!loaded || loaded.view.id !== ref.id || loaded.view.issuer !== ref.issuer) return undefined;
  return loaded;
}

export interface PepDeps {
  payments: PaymentsStore;
  evidence: EvidenceStore;
  fga: Fga;
  modelId: string;
  /**
   * The PDP's view of a mission plus the state source's own freshness
   * assertion (in a real deployment fetched from AS/Status). The loader
   * asserts `freshness`; the PEP only propagates it (@spec
   * runtime#state-freshness). Keyed by the canonical (issuer, id) pair
   * (@spec authority-server#reference-tuple): a loader MUST resolve only the
   * Mission whose issuer matches the one supplied, returning `undefined` on
   * a same-id different-issuer request rather than the wrong Mission.
   */
  loadView: (ref: MissionReference) => LoadedView | undefined;
  instanceEpoch: string;
  now?: () => Date;
  /** Trusted catalog serving this executor, never a caller-supplied digest. */
  capabilityCatalog?: CapabilityCatalog;
  /**
   * @spec runtime#compound-actions — the trusted Operation Profile this PEP
   * derives each crossing's action and phase from, resolved on EVERY lookup
   * so a configuration change between a Decision and its use is observed
   * rather than cached. Defaults to this module's {@link TOOL_ACTIONS}.
   *
   * Injectable so a conformance test can prove the phase comes from here and
   * nowhere else: an agent-supplied `action_phase` argument cannot move it,
   * and a crossing whose profile entry is gone at use has no establishable
   * phase and refuses rather than releasing an effect.
   */
  operationProfile?: () => Record<string, ActionMapping>;
  /**
   * @spec authzen#response-context — the permit `conditions` members this PEP
   * recognizes. Defaults to {@link RECOGNIZED_CONDITIONS}. Injectable so a
   * conformance test can stand up a PEP whose recognized set LACKS
   * `action_phase` and observe the must-understand rule: such a PEP treats a
   * permit carrying the condition as invalid rather than executing it.
   */
  recognizedConditions?: ReadonlySet<string>;
  /**
   * @spec runtime#runtime-conformance, runtime-oauth#token-validation (#853,
   * D487): the declared boundary context this PEP establishes its enforcement
   * boundary from, independently of any credential's `aud` and any Authority
   * Set entry. Defaults to {@link paymentsBoundaryContext} over the published
   * statement. The server validates `aud` against the same context.
   */
  boundary?: EnforcementBoundaryContext;
  /** Deployment policy: which actions require an action-bound approval (M6). */
  requiresActionApproval?: (action: string, actionClass: string | undefined) => boolean;
  maxApprovalAgeSeconds?: number;
  /**
   * @spec runtime#state-freshness, authzen#context-audience-freshness: the
   * enforcement scope's declared state-source placement. Defaults to the
   * published Enforcement Scope Statement's; injectable so a test can stand up
   * the other placement. Forwarded to the PDP's `stateSourcePlacement`.
   */
  stateSourcePlacement?: StateSourcePlacement;
  /**
   * @spec cross-domain#origin-principal-mapping — resolves
   * `context.mission.subject` to a destination-local mapping; forwarded to
   * the PDP's `principalMapping` unchanged. Absent, the PDP denies every
   * request claiming the cross-domain Origin Principal profile
   * `principal_mapping_failed`; a request not claiming the profile never
   * carries `mission.subject`, so this deployment is unaffected either way.
   */
  principalMapping?: PrincipalMappingResolver;
  /**
   * @spec cross-domain#dual-axis — resolves current entitlement for the
   * mapped local principal; forwarded to the PDP's `entitlement` unchanged.
   */
  entitlement?: EntitlementResolver;
  /**
   * @spec cross-domain#dual-axis — the declared maximum staleness (seconds)
   * of a principal-entitlement resolution; forwarded to the PDP's
   * `entitlementStalenessBoundSeconds` unchanged.
   */
  entitlementStalenessBoundSeconds?: number;
  /**
   * @spec authority-server#mission-join (#557) — enables the baseline MAS
   * Join gateway path for a credential validated with no `mission` claim
   * (`TokenFacts.mission` absent). ABSENT (the default): `enforceInner`
   * refuses `unknown_mission` for such a credential, exactly the prior
   * behavior; this deployment claims no MAS-governed route at all.
   */
  masJoin?: {
    /**
     * @spec authority-server#mission-join rule 4 (#557) — the deployment's
     * static delegate ceiling (which client ids may join as a delegate, and
     * each one's own maxDepth). Forwarded to the PDP's `delegatePolicy`
     * unchanged; the PDP resolves rules 3-6 itself (#557 review point 1),
     * this PEP no longer calls `resolveBaselineJoin` directly.
     */
    delegatePolicy?: DelegatePolicy;
    /**
     * @spec authority-server#mission-join rule 8 — the acting credential's
     * OWN authority bound (one of the permit's three independently
     * evaluated bounds, alongside the joined Mission's authority and
     * current Resource policy, the latter enforced downstream by the
     * existing FGA/PDP call unchanged). ABSENT: the joined route fails
     * closed with `out_of_authority` on every request -- rule 8 cannot be
     * honestly evaluated without a credential-authority source, so an
     * unconfigured deployment gets a working Join with no usable permit,
     * never a silently unbounded one. A deployment supplies this to
     * evaluate its own OAuth-scope-to-authority model; none is provided
     * here (see the PR's documented remainder).
     */
    resolveOrdinaryAuthority?: (token: TokenFacts) => AuthorityEntry[] | undefined;
    /**
     * @spec authority-server#mission-join rule 5 (#557) — the deployment's
     * own currently-recorded actor depth for a delegate client under a
     * Mission, "evaluated from the deployment's actor records rather than
     * from a Mission-bound token's `act` chain": resolved FRESH per
     * request (never a token's own `act` chain) and carried onto the PDP
     * request as `context.mission_join.delegate_depth`. `ActorRecords`
     * (`actor-records.ts`) is this deployment's own record store and
     * satisfies this hook directly.
     *
     * The hook takes the CANONICAL Mission reference (issuer and id, @spec
     * authority-server#reference-tuple) rather than a bare `mission_id`, and
     * the Mission's OWN `client_id`, which is depth 0. Both are facts of the
     * request the PEP already holds (the propagated reference it selected and
     * the Mission view it loaded), so a record store keyed on the canonical
     * pair is satisfied without binding an issuer or a Mission client at
     * construction, which would re-collapse the issuer distinction the store
     * exists to keep.
     *
     * Absent (including an absent hook): the delegate has no actor record
     * under the Mission, so the PDP denies `mission_binding_failed` whether or
     * not any `max_depth` is declared. An unconfigured deployment therefore
     * fails closed on the delegate disposition; the direct-client
     * disposition consults no depth at all.
     */
    resolveDelegateDepth?: (
      mission: MissionReference,
      clientId: string,
      missionClientId: string,
    ) => number | undefined;
    /**
     * @spec authority-server#mapping-contract (#818): the deployment's
     * versioned mapping contract, for a route whose credentials come from an
     * issuer outside the Mission's subject and client namespace. Called ONCE
     * per joined request; that one snapshot supplies the credential bound
     * (its scope mapping, in place of `resolveOrdinaryAuthority`), the client
     * the actor-record lookup is keyed on, and the PDP's subject and client
     * join (forwarded as `joinMapping`), so one request applies one contract
     * version throughout. A source with no usable snapshot returns
     * `UNRESOLVED_JOIN_MAPPING`, which resolves nothing. Absent: the
     * shared-namespace hooks above, unchanged.
     */
    mappingContract?: () => JoinMappingContract;
    /**
     * @spec authority-server#high-consequence-binding (#818): forwarded to
     * the PDP as `missionBoundOnlyClasses`: the action classes this route
     * admits only under a Mission-bound credential, so a joined request in one
     * is denied rather than evaluated under the join.
     */
    missionBoundOnlyClasses?: ReadonlySet<string>;
  };
  /** PDP signer + ARS endpoint for requestable denials (M6). */
  requestable?: { sign: import("jose").CryptoKey; kid: string; endpoint: string };
  /**
   * @spec runtime-evidence#decision-evidence-object,
   * runtime#agent-isolated-evidence-emission (#741, PR #753 review) — the PDP
   * decision entry point this PEP submits to: a decision function (co-resident
   * `createDecisionPoint().decide`, or a client over the remote decision
   * channel), NEVER an emission path. The PDP's Decision Evidence emitter is
   * bound inside that construction and closed over there, so this enforcement
   * component can ask for a decision and verify what comes back, and holds no
   * capability to have a record signed under the decision point's identity.
   *
   * Absent, the co-resident `evaluate` runs with no emission path and no
   * Resource policy bound (#828), so it refuses to decide and this PEP
   * records `pdp_unreachable`: nothing executes on an unbound decision.
   */
  decide?: DecisionFn;
  /**
   * @spec runtime#idempotency (#917, owner ruling 2026-10-02): the claim
   * channel the same decision channel offers this PEP: settlement of a
   * redeemed attempt's outcome from its signed Execution Evidence, and the
   * reconciliation reads. Absent, nothing settles and the PDP keeps every
   * claim this PEP's permits hold suppressed until its window closes.
   */
  claims?: ClaimChannel;
  /**
   * @spec txn-authorization#resource-challenge — this resource's txn-challenge
   * signing key (the key published at its `txn_challenge_jwks_uri`). When
   * configured AND the client signalled `Accept-Txn-Challenge`, an
   * `action_approval_required` denial returns a signed challenge. `asIssuer` is
   * the Transaction Authorization Server, used as the challenge `aud`; the
   * client discovers its endpoint from Authorization Server metadata
   * (`transaction_authorization_endpoint`), never from the challenge.
   */
  challengeSigner?: {
    sign: import("jose").CryptoKey;
    kid: string;
    alg?: string;
    asIssuer: string;
    /** Admission window for the challenge (seconds). */
    lifetimeSeconds?: number;
  };
  /**
   * Per-instance revocation (M12 / D19): "iss sub" keys of agent instances the
   * PEP refuses. Revoking one sub-agent instance kills only that instance;
   * other actors in the chain (the orchestrator) keep working.
   */
  revokedInstances?: Set<string>;
  /**
   * Optional observer for tooling/demos: receives the AuthZEN request the PEP
   * built and the raw PDP decision for each enforced action. Never affects
   * the decision; unset in production.
   */
  observe?: (e: {
    tool: string;
    args: Record<string, unknown>;
    token: TokenFacts;
    envelope: EvaluationRequest;
    decision: Decision;
    effective?: EffectiveParams;
  }) => void;
}

/**
 * @spec txn-authorization#resource-challenge — per-request client signals the
 * enforcement path reads. `acceptTxnChallenge` is the `Accept-Txn-Challenge`
 * header: a client that does not signal it never receives a challenge.
 */
export interface RequestSignals {
  acceptTxnChallenge?: boolean;
  /**
   * @spec authority-server#reference-propagation — the propagated Mission
   * Reference the transport carried (HTTP `Mission-Reference` or the MCP
   * `_meta` key), parsed but UNVERIFIED: a selection assertion the
   * enforcement path checks against the credential-carried reference.
   * `{ malformed: true }` is carried, not dropped, because unusable
   * carriage denies where governance requires a reference.
   */
  missionReference?: PropagatedMissionReference;
}

export interface ActionApprovalInput {
  id: string;
  approved_at: string;
  /** ARAP: the approval's validity bound; carried to the PDP for the now-check. */
  approved_until?: string;
  parameter_digest: string;
  state?: string;
}

export interface EnforceResult {
  capabilitySnapshot?: CapabilitySnapshot;
  permitted: boolean;
  decision?: Decision;
  denial_reason?: string;
  refusal_reason?: string;
  effective?: EffectiveParams;
  /**
   * @spec runtime#read-binding: present on a permitted `bindsVendorScope`
   * action (list_invoices): the NORMALIZED parameters `parameter_digest`
   * binds on the wire. `Pep.reverifyList` recomputes this same normal form
   * immediately before execution and refuses on a mismatch, the read-binding
   * counterpart of `effective`/{@link Pep.reverify} for a write.
   */
  listEffective?: ListEffectiveParams;
  /**
   * @spec runtime#read-binding — present on a permitted `bindsVendorScope`
   * action (list_invoices): the vendor ids the bound result set is limited
   * to, the normalized `vendor_scope` (for an unconstrained entry, every
   * vendor the store held invoices for at the decision).
   */
  list_vendor_scope?: string[];
  /** Present on a requestable denial: the ARAP access-request context. */
  access_request?: { endpoint: string; denial_binding: string; binding_token: string; expires_at: string };
  /**
   * @spec txn-authorization#resource-challenge — present when the action falls
   * under the profile and the client signalled `Accept-Txn-Challenge`. `error`
   * and `transaction_challenge` are the upstream wire members the caller
   * surfaces verbatim; `pending` is the operation the resource RETAINS for the
   * later offline verification and never puts on the wire.
   */
  challenge?: {
    error: typeof TXN_AUTHORIZATION_REQUIRED;
    transaction_challenge: string;
    pending: PendingOperation;
  };
  /**
   * @spec I-D.draft-zehavi-oauth-rar-metadata §4 — present on a genuine
   * out_of_authority denial: the requested (resource, action) is absent from
   * the Mission's Authority Set entirely. One GRAIN of the family's
   * graduated-challenge remediation (composes with, does not replace,
   * access_request/`challenge` above and the AuthZEN ARAP requestable
   * denial): the actionable authorization_details the client could propose
   * next on the standard authorization_details request parameter
   * (@spec mission#authority-proposal).
   */
  insufficient_authorization?: InsufficientAuthorization;
  /**
   * @spec authority-server#mission-join (#557) — the governing Mission
   * {id, issuer} for this decision, ALWAYS present on a permit: the
   * credential's own claim on the Mission-bound path, or the baseline
   * Join's resolved reference on the joined path (where `token.mission`
   * itself stays absent). The caller (server.ts) uses this, never
   * `token.mission`, for anything past the permit -- operation keys,
   * connector calls, execution evidence -- so a joined credential's write
   * actually executes, not merely permits.
   */
  resolvedMission?: { id: string; issuer: string; authority_hash?: string };
  /**
   * @spec runtime-evidence#execution-evidence-object (issue #786) — present on
   * every permit, built only after the permit's Decision Evidence verified and
   * was retained. Every post-permit failure disposes through it, so the caller
   * never assembles a record of its own.
   */
  attempt?: ExecutionAttempt;
  /**
   * @spec runtime#idempotency (#918): present on a permit for a keyed
   * reversible write. The (idempotency scope, `idempotency_key`) pair this
   * PEP reserves, and the operation identity it is reserved under, projected
   * from the same evaluation request the PDP decided, so the scope is built
   * from this PEP's verified credential and governing Mission and never from
   * an agent argument. `idempotencyKey` is the key that request carried, absent
   * when it carried none. Absent as a whole when the actor has no stable
   * identity to scope the key on, which {@link writeReservationUnkeyable}
   * then marks.
   */
  writeReservation?: WriteReservationScope;
  /**
   * @spec runtime#idempotency (#918, #1016 review): present on a permit for a
   * keyed reversible write whose actor has no stable identity (an
   * instance-profiled leaf with no client), so no pair exists to reserve. The
   * write path refuses it before any effect.
   */
  writeReservationUnkeyable?: true;
}

/** @spec runtime#idempotency (#918): the pair a keyed reversible write reserves. */
export interface WriteReservationScope {
  scope: IdempotencyScope;
  scopeDigest: string;
  /**
   * @spec runtime#idempotency, runtime#boundary-identifier-change (#853
   * review): the digests of the same scope under each identifier the
   * request's boundary replaces (`lineageScopeDigests`). Retrieval and the
   * reservation's own transaction read a key held under any of them as held,
   * so a declared change never makes a reserved or completed key fresh.
   */
  lineageScopeDigests: readonly string[];
  operationIdentity: string;
  idempotencyKey?: string;
}

/**
 * @spec runtime-evidence#execution-evidence-object (issue #786): the
 * post-permit disposition context. It is created ONCE per request, after the
 * response and its Decision Evidence have been verified and retained, and
 * carries only authorization facts copied from the retained Decision and the
 * verified credential, never an agent argument or an unverified response
 * member.
 *
 * `executionId` is the one execution identity of this disposition attempt:
 * every emission retry reuses it, and a distinct attempt (a rejected replay
 * included) carries its own, so no attempt can overwrite another's completed
 * record. Durable capacity reservation and cross-restart dedup storage are
 * #594 W4-4; this is the stable input they build on.
 */
export interface ExecutionAttempt {
  /** The permit's authenticated evaluation identifier (`decision_id`). */
  evaluationId: string;
  /** The governing Mission, from `resolvedMission`, never `token.mission`. */
  mission: { id: string; issuer: string; authority_hash?: string };
  /**
   * @spec runtime#permit-binding (#853, D487): the enforcement boundary the
   * permit was decided at, exactly as this PEP sent it in
   * `resource.properties.audience`. Every disposition record of this permit
   * carries it, and the `enforcement_boundary` use check compares the
   * boundary this PEP establishes now against it before every release.
   */
  audience: string;
  /**
   * @spec runtime#boundary-identifier-change (#853, D487): the statement
   * version that declared {@link audience} when the permit was decided, and
   * against which the request's credential was validated. The
   * `enforcement_boundary` use check refuses the permit once another version
   * is in force.
   *
   * #1327 re-review: read from the permit's retained Decision Evidence row
   * (its `boundary_version`, `evidence.ts`), which records it when the
   * permit is first retained, never from the request that happens to
   * receive the permit: a PDP retransmission re-presents an earlier permit,
   * which keeps its own version. Absent where that row records none, which
   * no version in force matches.
   */
  boundaryVersion?: string;
  /**
   * @spec resource-access#resource-matching (#1276, D457): the operation
   * target the permit was decided on, exactly as this PEP sent it in
   * `resource.properties.operation_target`. The `operation_target` use check
   * compares the target the live Operation Profile establishes against it
   * before every release.
   */
  operationTarget: string;
  action: string;
  /**
   * The tool whose crossing this attempt is about to make. The PEP re-derives
   * the crossing's authoritative phase from its own Operation Profile under
   * this name at every check, so a profile that no longer places the tool
   * leaves the phase unestablishable at use.
   */
  tool: string;
  /**
   * @spec authzen#response-context — the permit's `conditions.action_phase`
   * EXACTLY as the verified decision carried it, unnarrowed: a missing,
   * unknown or malformed value has to stay distinguishable from a valid one,
   * so the comparison at use can refuse it rather than coerce it.
   */
  permitBoundPhase?: unknown;
  /**
   * @spec authzen#response-context — the permit's `conditions.valid_until`,
   * the validity bound on INITIATING an effect under it. Copied from the
   * verified decision, never recomputed locally and never extended.
   */
  permitValidUntil?: unknown;
  /**
   * @spec runtime-evidence#execution-evidence-object
   * `authorized_parameter_digest`: taken from the RETAINED Decision Evidence,
   * not from `decision.context.conditions`, since the member MUST be absent
   * when the linked record carries no `parameter_digest`.
   */
  authorizedParameterDigest?: string;
  /** One execution identity per disposition attempt; reused for emission retries. */
  executionId: string;
  /**
   * @spec runtime#idempotency (#917, owner ruling 2026-10-02): set once this
   * attempt's single-use redemption succeeded (D28). Only a redeeming
   * attempt settles the PDP's idempotency claim: an attempt that never held
   * the redemption, a duplicate refused as `permit_consumed` included, says
   * nothing about what the permit did.
   */
  redeemed?: boolean;
  /** Payments-domain join keys (reconcile.ts), not spec members. */
  permitId: string;
  joinKey: string;
  hopReference?: RuntimeHopReference;
  /**
   * Re-observe this operation's effective parameter digest from CURRENT
   * authoritative state, at the moment of the disposition. `undefined` means
   * the operation binds no parameters, or its target can no longer be
   * resolved; it is never a licence to repeat the authorized digest, which
   * would assert an observation that was not made.
   */
  observeEffectiveDigest: () => string | undefined;
}

/**
 * The result of one post-permit disposition. `recorded: false` carries the
 * reason no valid record could be emitted: the disposition still refuses the
 * action, and the gap is an open defect rather than a fabricated record.
 */
export type SuppressOutcome =
  | { recorded: true }
  | { recorded: false; gap: "effective_parameter_digest_unobservable" | "emission_failed" };

/**
 * The typed result of a pre-execution recheck. `error` names the gate that
 * actually failed, so a caller cannot report a capability or lease failure as
 * a parameter comparison. A failing recheck has already disposed through
 * {@link Pep.suppressExecution}.
 */
export type ReverifyOutcome =
  | { ok: true; effectiveParameterDigest?: string }
  | { ok: false; error: string; disposition: SuppressOutcome };

/** Every caller-visible diagnostic this PEP refuses with on its Refusal Record path (`refuse`, `recordRefusal`). */
export type PepRefusalDiagnostic =
  | "unknown_tool"
  | "invalid_request"
  | "unknown_mission"
  | "unknown_invoice"
  | "unknown_vendor"
  | "operation_target_unresolvable"
  | "out_of_authority"
  | "instance_revoked"
  | "mission_reference_conflict"
  | "state_unavailable"
  | "capability_source_unresolvable"
  | "decision_evidence_unverifiable"
  | "channel_failure"
  | "pdp_unreachable"
  | "unresolvable_recipients"
  | "credential_boundary_changed";

/**
 * @spec runtime-evidence#pre-decision-refusal (issue #786) — the deployment's
 * caller-visible refusal diagnostic mapped to the enumerated value the SIGNED
 * Refusal Record carries. "This member carries an enumerated value, never a
 * deployment's own diagnostic string ... A deployment publishes the mapping it
 * uses": this constant is that mapping, and the two surfaces stay separate.
 * It is exhaustive over {@link PepRefusalDiagnostic}, a diagnostic that is
 * already an enumerated value included, so nothing reaches a signed record
 * unmapped (#1148, D379).
 */
export const PRE_DECISION_DENIAL_REASON: Readonly<Record<PepRefusalDiagnostic, PepRefusalDenialReason>> = Object.freeze({
  // No such action at this enforcement surface.
  unknown_tool: "request_unsupported",
  // Intake (operation-profile-payments-v1, D316, D334): the PEP established
  // the action, and the supplied arguments fail its served input schema (an
  // unknown or authoritative member, a missing required member, a wrong type,
  // a pattern miss). Never `request_unsupported`, which names an action this
  // surface does not implement; no PDP evaluated the request, so it is not
  // the PDP's `parameter_violation` either.
  invalid_request: "request_invalid",
  // The Mission the request names cannot be established from local state.
  unknown_mission: "state_unavailable",
  // The named target object does not resolve here.
  unknown_invoice: "target_unresolvable",
  unknown_vendor: "target_unresolvable",
  // @spec resource-access#resource-matching (#1276, D447): the operation's
  // trusted contract establishes no one target (none declared, a form this
  // surface does not support, or declarations naming different targets), so
  // the operation is refused before any decision request.
  operation_target_unresolvable: "target_unresolvable",
  // The acting credential's OWN authority does not cover the request (an
  // attenuated leaf, or the baseline-Join rule-8 bound), determined before any
  // decision request. Distinct from the PDP's evaluated `out_of_authority`
  // denial, which this member must not duplicate.
  out_of_authority: "credential_authority_insufficient",
  // One instance of the delegation chain is revoked, so the credential's own
  // authority no longer covers any request. Allocated to
  // `credential_authority_insufficient`, whose definition is exactly an
  // authority bound the PEP establishes before any decision request, NOT to
  // `token_invalid`, which names a credential that failed validation. A
  // revoked instance presents a well-formed credential whose authority was
  // withdrawn, and an auditor must be able to tell those apart. The
  // operator-facing distinction stays on the caller-visible diagnostic.
  instance_revoked: "credential_authority_insufficient",
  // Already enumerated values, carried unchanged.
  mission_reference_conflict: "mission_reference_conflict",
  state_unavailable: "state_unavailable",
  capability_source_unresolvable: "capability_source_unresolvable",
  decision_evidence_unverifiable: "decision_evidence_unverifiable",
  channel_failure: "channel_failure",
  pdp_unreachable: "pdp_unreachable",
  // The recipients the operation addresses cannot be resolved from the
  // resource's own routing records (#1266): its target does not resolve.
  unresolvable_recipients: "target_unresolvable",
  // @spec runtime-oauth#token-validation, runtime#boundary-identifier-change
  // (#853, D487): the credential's `aud` was validated against a boundary or
  // statement version other than the one this request is decided at (a
  // cutover fell between validation and decision). It is not validated for
  // the established boundary: a token-validation failure there.
  credential_boundary_changed: "token_invalid",
});

/** Whether `diagnostic` is one this PEP refuses with on its Refusal Record path. */
export function isPepRefusalDiagnostic(diagnostic: string): diagnostic is PepRefusalDiagnostic {
  return Object.hasOwn(PRE_DECISION_DENIAL_REASON, diagnostic);
}

/** A refusal diagnostic with no mapping to the closed `denial_reason` set (#1148). */
export class UnmappedRefusalDiagnosticError extends Error {
  constructor(readonly diagnostic: string) {
    super(`refusal diagnostic ${JSON.stringify(diagnostic)} has no mapping to a Refusal Record denial_reason`);
    this.name = "UnmappedRefusalDiagnosticError";
  }
}

/**
 * The enumerated Refusal Record `denial_reason` for a caller-visible
 * diagnostic. A diagnostic outside {@link PRE_DECISION_DENIAL_REASON} throws
 * before anything is signed (#1148, D379): the refusal fails visibly, and no
 * generic or mislabelled reason is substituted.
 */
export function signedDenialReason(diagnostic: string): PepRefusalDenialReason {
  if (!isPepRefusalDiagnostic(diagnostic)) throw new UnmappedRefusalDiagnosticError(diagnostic);
  return PRE_DECISION_DENIAL_REASON[diagnostic];
}

/**
 * @spec I-D.draft-zehavi-oauth-rar-metadata §4 — the insufficient_authorization
 * WWW-Authenticate error, plus its `authorization_remediation` parameter
 * (base64url JSON: `{ authorization_details }`). `www_authenticate` is the
 * header VALUE the RS would set on a raw HTTP response; this RS's tokens are
 * DPoP-bound (`bearer_methods_supported: ["dpop"]` above), so the auth-scheme
 * is `DPoP`, not the draft's Bearer example. It travels as a field here (not
 * a literal header) because a PEP denial rides inside an MCP CallToolResult at
 * HTTP 200, not a raw per-call HTTP response -- mcp-http-transport.ts's
 * unauthorized() is the one site that sets a real www-authenticate header, and
 * it fires only pre-dispatch (missing/invalid credential), before the PEP.
 */
export interface InsufficientAuthorization {
  www_authenticate: string;
  authorization_remediation: string;
}

/** Build the insufficient_authorization grain for one or more actionable
 * authorization_details entries (@spec I-D.draft-zehavi-oauth-rar-metadata §4). */
export function buildInsufficientAuthorization(authorizationDetails: AuthorityEntry[]): InsufficientAuthorization {
  const authorization_remediation = Buffer.from(
    JSON.stringify({ authorization_details: authorizationDetails }),
    "utf8",
  ).toString("base64url");
  const www_authenticate =
    'DPoP error="insufficient_authorization", ' +
    'error_description="the requested action is outside the Mission\'s Authority Set", ' +
    `authorization_remediation=${authorization_remediation}`;
  return { www_authenticate, authorization_remediation };
}

/**
 * @spec runtime-evidence#execution-evidence-object `obligation_outcomes`:
 * "one object per attached obligation, with `id` (REQUIRED ...), `type`
 * (REQUIRED ...)". This PEP implements no obligation type, so every attached
 * obligation is `unsupported`.
 *
 * Returns `undefined` when ANY attached obligation does not identify itself.
 * Omitting one entry would break one-outcome-per-attached-obligation while
 * still reading as a complete list, and `id`/`type` cannot be invented. That
 * case is an outstanding representation gap (issue #786): the operation is
 * still refused with zero effect, and the record carries no fabricated entry.
 */
function obligationOutcomes(
  obligations: readonly unknown[],
): ExecutionEvidenceObject["obligation_outcomes"] | undefined {
  const named: NonNullable<ExecutionEvidenceObject["obligation_outcomes"]> = [];
  for (const raw of obligations) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
    const { id, type } = raw as { id?: unknown; type?: unknown };
    if (typeof id !== "string" || id.length === 0 || typeof type !== "string" || type.length === 0) {
      return undefined;
    }
    named.push({ id, type, outcome: "unsupported", error: "no obligation type is implemented at this PEP" });
  }
  return named;
}

/**
 * What a refusing PEP had established before it refused: the target object
 * (@spec runtime-evidence#pre-decision-refusal `resource`, "when the refusing
 * component established one") and, after the evaluation request was built,
 * that request (@spec runtime-evidence#request-digest-worked).
 */
interface RefusalEstablished {
  resource?: TargetObject;
  evaluationRequest?: EvaluationRequest;
}

/**
 * The target object this PEP resolves for a crossing: the AuthZEN
 * `resource` identity and its object-scoped members, before the request's
 * `resource.properties.audience` is added.
 */
type TargetObject = {
  type: string;
  id: string;
  properties?: {
    vendor_id?: string;
    vendor_ids?: string[];
    issued_at?: string;
    tenant?: string;
    data_classification?: string;
  };
};

export class Pep {
  readonly capabilityCatalog: CapabilityCatalog;
  private readonly now: () => Date;
  /** @spec authzen#context-audience-freshness: who supplies Mission state for this enforcement scope. */
  private readonly placement: StateSourcePlacement;
  /** @spec runtime#runtime-conformance (#853, D487): where this PEP's boundary is declared. */
  readonly boundaryContext: EnforcementBoundaryContext;
  constructor(private readonly deps: PepDeps) {
    this.capabilityCatalog = deps.capabilityCatalog ?? new PaymentsToolCatalog();
    this.now = deps.now ?? (() => new Date());
    this.placement = deps.stateSourcePlacement ?? stateSourcePlacement(RUNTIME_POSTURE);
    this.boundaryContext = deps.boundary ?? paymentsBoundaryContext();
  }

  /**
   * @spec runtime#runtime-conformance (#853, D487): the enforcement boundary
   * this PEP establishes now, from its declared location and the active
   * version alone.
   */
  boundary(): BoundaryEstablishment {
    return this.boundaryContext.establish(this.now());
  }

  /**
   * @spec runtime-oauth#token-validation (#853, D487): whether a verified
   * credential's `aud` names the boundary this PEP establishes now, directly
   * or through an alias declared for `context`'s issuer and token profile.
   */
  validateAudience(aud: unknown, context: AudienceContext): AudienceValidation {
    return this.boundaryContext.validateAudience(aud, context, this.now());
  }

  /**
   * @spec runtime#runtime-conformance, runtime-oauth#token-validation,
   * runtime#boundary-identifier-change (#853, D487): the boundary this
   * request is decided at, established now, and held to the boundary the
   * credential was validated against. A boundary that cannot be established
   * refuses with no record. A credential validated against another boundary
   * or statement version (a cutover fell between validation and this point)
   * is refused `credential_boundary_changed`, recorded at the boundary
   * established now: it is never relabeled into a boundary that did not
   * accept it. The caller retries, and its credential is validated afresh.
   */
  private async requestBoundary(
    token: TokenFacts,
    action: string,
  ): Promise<{ ok: true; boundary: string; version: string } | { ok: false; refusal_reason: string }> {
    const established = this.boundary();
    if (!established.ok) {
      return {
        ok: false,
        refusal_reason: established.reason === "consumer_unprovisioned" ? BOUNDARY_UNPROVISIONED : BOUNDARY_UNRESOLVABLE,
      };
    }
    const validated = token.validatedBoundary;
    if (validated !== undefined && (validated.boundary !== established.boundary || validated.version !== established.version)) {
      await this.recordRefusal(established.boundary, token, "credential_boundary_changed", action);
      return { ok: false, refusal_reason: "credential_boundary_changed" };
    }
    return established;
  }

  /**
   * @spec runtime#compound-actions — "The PEP derives the crossing's phase
   * from its trusted Operation Profile". Every read of a crossing's action,
   * class and phase goes through here, and the profile is resolved on each
   * call rather than captured once, so a Decision and its use always ask the
   * profile as it is at that moment.
   */
  toolAction(tool: string): ActionMapping | undefined {
    return (this.deps.operationProfile?.() ?? TOOL_ACTIONS)[tool];
  }

  /** Whether the current Operation Profile has a tool for `action` that addresses recipients (#1266). */
  private reachesRecipients(action: string): boolean {
    const profile = this.deps.operationProfile?.() ?? TOOL_ACTIONS;
    return Object.values(profile).some((m) => m.action === action && m.reachesRecipients === true);
  }

  /**
   * @spec resource-access#resource-matching (#1276, D447, D457): the
   * operation target this surface establishes for `tool`, from the trusted
   * contract its LIVE Operation Profile declares, independently of any
   * presented entry, the token's audience, and the caller's arguments. A
   * missing, unsupported or ambiguous contract establishes none.
   */
  operationTargetFor(tool: string): OperationTargetResolution {
    return establishOperationTarget(this.toolAction(tool)?.target);
  }

  /** The permit `conditions` members this PEP recognizes (@spec authzen#response-context). */
  private recognizedConditions(): ReadonlySet<string> {
    return this.deps.recognizedConditions ?? RECOGNIZED_CONDITIONS;
  }

  /**
   * @spec operation-profile-payments-v1 "Parameter schemas and normalization"
   * (D316, #1106): the tool-boundary intake, run by every server path before
   * any decision work. NFC-normalizes the arguments and validates them against
   * the tool's served input schema as a closed schema; the caller uses the
   * returned `args`, never the raw ones, for enforcement and execution. A
   * violation is refused `invalid_request` with one Refusal Record carrying
   * `request_invalid` (@spec runtime-evidence#pre-decision-refusal, D334) and
   * no PDP call. An unknown tool passes through to {@link enforce}, which
   * refuses it `unknown_tool` (`request_unsupported`); a schema that cannot be
   * read is refused `capability_source_unresolvable`, never admitted
   * unvalidated.
   */
  async intake(
    tool: string,
    args: Record<string, unknown>,
    token: TokenFacts,
  ): Promise<{ ok: true; args: Record<string, unknown> } | { ok: false; refusal_reason: string }> {
    const mapping = this.toolAction(tool);
    if (!mapping) return { ok: true, args };
    // @spec runtime#runtime-conformance (#853, D487): no boundary, no record:
    // a Refusal Record REQUIRES an `audience`, and none is invented.
    const established = await this.requestBoundary(token, mapping.action);
    if (!established.ok) return { ok: false, refusal_reason: established.refusal_reason };
    const boundary = established.boundary;
    let inputSchema: unknown;
    try {
      inputSchema = (this.capabilityCatalog.toolDefinitions([tool])[0] as { inputSchema?: unknown } | undefined)?.inputSchema;
    } catch {
      await this.recordRefusal(boundary, token, "capability_source_unresolvable", mapping.action);
      return { ok: false, refusal_reason: "capability_source_unresolvable" };
    }
    const admitted = admitArguments(inputSchema, args);
    if (admitted.ok) return admitted;
    await this.recordRefusal(boundary, token, "invalid_request", mapping.action);
    return { ok: false, refusal_reason: "invalid_request" };
  }

  /**
   * Enforce one tool call. Returns the decision; the caller executes only on
   * `permitted`. Records Decision Evidence (always) and a Refusal Record on
   * a PEP-side refusal (e.g. unknown mission, missing invoice).
   */
  async enforce(
    tool: string,
    args: Record<string, unknown>,
    token: TokenFacts,
    actionApproval?: ActionApprovalInput,
    signals?: RequestSignals,
  ): Promise<EnforceResult> {
    return getTracer("pep").startActiveSpan(`pep.enforce ${tool}`, async (span) => {
      span.setAttribute("mission.tool", tool);
      // @spec authority-server#mission-join (#557): absent for an ordinary
      // credential on the baseline-Join path; enforceInner resolves it.
      if (token.mission) span.setAttribute("mission.id", token.mission.id);
      try {
        const res = await this.enforceInner(tool, args, token, actionApproval, signals);
        span.setAttribute("mission.permitted", res.permitted);
        if (res.denial_reason) span.setAttribute("mission.denial_reason", res.denial_reason);
        if (res.refusal_reason) span.setAttribute("mission.refusal_reason", res.refusal_reason);
        return res;
      } finally {
        span.end();
      }
    });
  }

  private async enforceInner(
    tool: string,
    args: Record<string, unknown>,
    token: TokenFacts,
    actionApproval?: ActionApprovalInput,
    signals?: RequestSignals,
  ): Promise<EnforceResult> {
    // @spec runtime#runtime-conformance (#853, D487): the boundary is
    // established first, from the declaration alone, and every decision
    // input, binding and record of this request uses this one value. A
    // boundary that cannot be established refuses with no Refusal Record:
    // the record REQUIRES an `audience`, and none is invented.
    const mapping = this.toolAction(tool);
    const establishedBoundary = await this.requestBoundary(token, mapping?.action ?? tool);
    if (!establishedBoundary.ok) return { permitted: false, refusal_reason: establishedBoundary.refusal_reason };
    const { boundary, version: boundaryVersion } = establishedBoundary;
    if (!mapping) return await this.refuse(boundary, token, "unknown_tool", tool);

    let view: MissionView;
    let observation: MissionStateObservation;
    // The governing Mission anchor for the AuthZEN envelope below: the
    // credential's own claim on the Mission-bound path, or the PEP-supplied
    // propagated reference (rule 1) on the baseline-Join path (never a raw
    // request value either way; on the Join path this is what makes the
    // PDP's own view-consistency check meaningful rather than tautological
    // -- see the else branch below).
    let missionAnchor: { id: string; issuer: string; authority_hash?: string; subject?: OriginPrincipal };
    // @spec authority-server#mission-join (#557 review point 1) — set only
    // on the baseline-Join path, below: signals the PDP request to carry
    // `context.mission_join` and run rules 3-6 itself. `delegateDepth` is
    // rule 5's per-request actor-depth fact (absent on the direct-client
    // case, where no delegate policy is consulted at all).
    let isBaselineJoin = false;
    let delegateDepth: number | undefined;
    // @spec authority-server#mapping-contract (#818): the one contract
    // snapshot this joined request applies, forwarded to the PDP below.
    let joinMapping: JoinMappingContract | undefined;
    // @spec authority-server#mapping-contract (#818 review P2): set when that
    // snapshot cannot resolve anything (absent, invalidated or stale). The
    // mapping is unresolved, so the join fails `mission_binding_failed` at the
    // PDP; this PEP never reports it as a credential with no authority.
    let joinMappingUnavailable = false;
    // @spec authzen#context-credential (#825, D312) — the credential's own
    // authority as the PDP receives it: the Mission-bound credential's
    // verified entries, or, on the baseline-Join path, the entries the
    // deployment's resolver maps the ordinary credential's authority to.
    let carriedAuthority: readonly CredentialAuthorityEntry[] | undefined;

    if (token.mission) {
      // @spec authority-server#reference-verification — a propagated Mission
      // Reference is a selection assertion, never authority. This credential
      // carries the `mission` claim, so the credential-carried reference
      // governs: a propagated reference naming a different Mission, and a
      // malformed reference where governance requires one (every tool here
      // is governed), deny as `mission_reference_conflict`, never a silent
      // pick-one and never a silent ignore.
      const propagated = signals?.missionReference;
      if (propagated) {
        const matches =
          !("malformed" in propagated) &&
          propagated.id === token.mission.id &&
          propagated.issuer === token.mission.issuer;
        if (!matches) return await this.refuse(boundary, token, "mission_reference_conflict", mapping.action);
      }

      const loaded = this.deps.loadView({ id: token.mission.id, issuer: token.mission.issuer });
      if (!loaded) return await this.refuse(boundary, token, "unknown_mission", mapping.action);

      // @spec authority-server#reference-verification — the locally loaded
      // Mission view is the PEP's own binding source; a credential whose
      // mission claim names a different issuer than the view it selects is
      // reference sources disagreeing on the canonical (issuer, id) pair,
      // refused as mission_reference_conflict, never resolved by picking one.
      if (loaded.view.issuer !== token.mission.issuer) {
        return await this.refuse(boundary, token, "mission_reference_conflict", mapping.action, loaded.view);
      }
      view = loaded.view;
      observation = loaded.observation;
      missionAnchor = token.mission;
    } else {
      // @spec authority-server#mission-join (#557): an ordinary credential
      // with no `mission` claim, joined against a PEP-supplied propagated
      // Mission reference (rule 1). ABSENT masJoin config: this deployment
      // claims no MAS-governed route, so refuse exactly as the prior
      // behavior would have (an unrecognized/no-claim credential).
      if (!this.deps.masJoin) return await this.refuse(boundary, token, "unknown_mission", mapping.action);

      // @spec authority-server#reference-verification (#557, #972 item 13,
      // D289) — this route is MAS-governed, so governance requires a
      // reference here. A MISSING reference and a MALFORMED one are both
      // unusable carriage, refused `mission_reference_conflict` rather than
      // parsed on a best-effort basis or reported as an unknown Mission.
      // `unknown_mission` stays for a supplied, well-formed reference that
      // does not resolve (below): a Mission named but not found.
      const propagated = signals?.missionReference;
      if (!propagated) return await this.refuse(boundary, token, "mission_reference_conflict", mapping.action);
      if ("malformed" in propagated) {
        return await this.refuse(boundary, token, "mission_reference_conflict", mapping.action);
      }

      const loaded = this.deps.loadView({ id: propagated.id, issuer: propagated.issuer });
      if (!loaded) return await this.refuse(boundary, token, "unknown_mission", mapping.action, undefined, propagated.id);

      // Rule 8, bound 1: the acting credential's OWN authority, resolved by a
      // PEP-side deployment hook over TokenFacts (@spec
      // authority-server#mission-join rule 8 note; #557 review point 1 moves
      // rules 3-6, the subject/client/delegate join proper, into the PDP
      // below). The PEP carries it to the PDP as context.credential.authority,
      // which enforces it as its own bound (D312, D340). No evaluator
      // configured -> fail closed (see PepDeps.masJoin doc): a working Join
      // with no usable permit, never a silently unbounded one.
      // @spec authority-server#mapping-contract (#818): under a mapping
      // contract the credential bound is the contract's scope mapping, read
      // from the same snapshot the PDP's join applies, for the credential's
      // own verified issuer and `scope`.
      joinMapping = this.deps.masJoin.mappingContract?.();
      // @spec authority-server#mapping-contract (#818 review P2): a contract
      // with no usable snapshot is an unresolved mapping, not a credential
      // without authority. The request carries an empty credential authority
      // (nothing is mapped) to the PDP, whose join denies it
      // `mission_binding_failed`; a usable contract whose scope mapping
      // grants nothing for this action stays `out_of_authority` below.
      joinMappingUnavailable = joinMapping !== undefined && !joinMapping.usable(this.now());
      const ordinaryAuthority = joinMappingUnavailable
        ? []
        : joinMapping
          ? joinMapping.credentialAuthority({
              issuer: token.credential?.issuer ?? "",
              scope: token.mission ? undefined : token.scope,
              resource: CANONICAL_RESOURCE,
              now: this.now(),
            })
          : this.deps.masJoin.resolveOrdinaryAuthority?.(token);
      if (!ordinaryAuthority) return await this.refuse(boundary, token, "out_of_authority", mapping.action, loaded.view);
      // The same entries reach the PDP as the credential bound, so a remote
      // PDP enforces them too rather than only this non-empty gate. Entries
      // the bound cannot read in full refuse here, never reach it narrowed.
      try {
        carriedAuthority = credentialEntriesFromAuthority(ordinaryAuthority);
      } catch {
        return await this.refuse(boundary, token, "out_of_authority", mapping.action, loaded.view);
      }

      // Rules 3, 4, 5, 6 (subject/client join, delegate narrowing, uniform
      // mission_binding_failed with no fallback) are NOT resolved here anymore:
      // `context.mission_join` below tells the PDP to resolve them itself,
      // against the Mission's own view -- the PDP is the party that can
      // verify the credential inputs and tell whether the join actually ran
      // (#557 review point 1). The view is never filtered by the credential
      // (D340): a filter would drop a Mission entry broader than the
      // credential (refusing an action the credential covers), and the PDP's
      // full-set proof (D335) needs the committed set. The credential's own
      // bound rides the request as context.credential.authority instead.
      view = loaded.view;
      observation = loaded.observation;
      missionAnchor = { id: propagated.id, issuer: propagated.issuer };
      isBaselineJoin = true;
      // Rule 5's actor records name clients in the Mission's namespace, so
      // under a mapping contract the lookup is keyed on the client the
      // contract maps this credential's client to. No mapped client, no
      // record: an absent depth, which the PDP denies on the delegate
      // disposition.
      const depthClientId = joinMapping
        ? joinMapping.clientFor({ iss: token.credential?.issuer ?? "", clientId: token.clientId }, this.now())
        : token.clientId;
      delegateDepth =
        depthClientId === undefined
          ? undefined
          : this.deps.masJoin.resolveDelegateDepth?.(
              { id: propagated.id, issuer: propagated.issuer },
              depthClientId,
              loaded.view.client_id,
            );
    }

    // @spec authzen#context-audience-freshness: where the declared placement
    // has this PEP supply state, the observation is REQUIRED with every member
    // its `mode` requires. A loader read that does not yield one is state this
    // PEP cannot establish: a pre-decision refusal, @spec
    // runtime-evidence#pre-decision-refusal `state_unavailable`, never a
    // decision request carrying a malformed observation.
    if (this.placement === "pep" && parseStateObservation(observation) === undefined) {
      return await this.refuse(boundary, token, "state_unavailable", mapping.action, view);
    }

    // Per-instance revocation (M12): refuse if any actor in the chain is
    // revoked, keyed on (act.iss, act.sub). Kills one instance, not the chain.
    if (this.deps.revokedInstances?.size) {
      for (const hop of flattenActChain(token.act)) {
        if (this.deps.revokedInstances.has(`${hop.iss} ${hop.sub}`)) {
          return await this.refuse(boundary, token, "instance_revoked", mapping.action, view);
        }
      }
    }

    // @spec resource-access#resource-matching (#1276, D447, D457): "Before
    // matching authority, the resource server establishes the operation's
    // target". From the tool's trusted contract only: never an entry, the
    // token's audience, or an argument (an agent-supplied `operation_target`
    // or `resource` argument is never read). No one target, no operation:
    // refused before any decision request, with no fallback to this
    // resource's metadata identifier.
    const established = this.operationTargetFor(tool);
    if (!established.ok) return await this.refuse(boundary, token, "operation_target_unresolvable", mapping.action, view);
    const operationTarget = established.target;

    // Effective parameters from authoritative store state (D34).
    let effective: EffectiveParams | undefined;
    let listEffective: ListEffectiveParams | undefined;
    let listDigest: string | undefined;
    let amount: { amount: string; currency: string } | undefined;
    let resourceObj: TargetObject = { type: "server", id: CANONICAL_RESOURCE };
    let listVendorScope: string[] | undefined;
    let targetVendorId: string | undefined;
    let recipients: string[] | undefined;
    let recipientsRouted = false;
    if (mapping.targetsVendor) {
      // @spec authzen#context-credential, authzen#runtime-denial-classification
      // (D324): the target is the vendor the store resolved, never the
      // argument, and it rides the request so the credential bound and the
      // Mission's vendor constraint both evaluate the target this PEP
      // established. A vendor read is a read of that vendor object.
      //
      // @spec runtime-evidence#pre-decision-refusal (#1251, D484): a vendor
      // the store does not hold is refused here, before the credential bound,
      // any decision request or any Resource-policy query, as get_invoice
      // refuses an unknown invoice; a credential naming that vendor never
      // reaches a decision. No server-resource fallback remains.
      const targetVendor = this.deps.payments.getVendor(String(args.vendor_id ?? ""));
      if (targetVendor === undefined) return await this.refuse(boundary, token, "unknown_vendor", mapping.action, view);
      targetVendorId = targetVendor.id;
      // @spec resource-access#initial-common-constraints (#1266): the
      // vendor record's own tenant, the ownership fact a `tenant` bound reads.
      resourceObj = {
        type: "vendor",
        id: targetVendorId,
        properties: {
          vendor_id: targetVendorId,
          ...(typeof targetVendor.tenant === "string" ? { tenant: targetVendor.tenant } : {}),
        },
      };
    }
    if (mapping.needsInvoice) {
      const invoiceId = String(args.invoice_id ?? "");
      const invoice = this.deps.payments.getInvoice(invoiceId);
      if (!invoice) return await this.refuse(boundary, token, "unknown_invoice", mapping.action, view);
      const vendor = this.deps.payments.getVendor(invoice.vendor_id);
      if (!vendor) {
        return await this.refuse(boundary, token, "unknown_vendor", mapping.action, view, undefined, {
          resource: { type: "invoice", id: invoice.id },
        });
      }
      // @spec resource-access#initial-common-constraints (#1266): every
      // recipient the operation reaches, from the vendor's own routing.
      if (mapping.reachesRecipients) {
        const resolved = this.deps.payments.remittanceRecipients(vendor.id);
        if (!resolved) {
          return await this.refuse(boundary, token, "unresolvable_recipients", mapping.action, view, undefined, {
            resource: { type: "invoice", id: invoice.id },
          });
        }
        recipients = resolved.recipients;
        recipientsRouted = resolved.routed;
      }
      // The operation target is the effective parameters' `resource`, so the
      // parameter digest, the operation key and every recheck bind it too.
      // The routed set binds into the digest; a vendor's default address is
      // a function of `vendor_id`, which the digest already binds.
      const bound = recipients && recipientsRouted ? { recipients } : {};
      effective = buildEffectiveParams({ action: mapping.action, invoice, vendor, resource: operationTarget, ...bound });
      amount = effective.amount;
      // @spec resource-access#initial-common-constraints (#1266): the
      // invoice's issuance instant is this service's own record, never an
      // argument; an invoice with none carries no fact, which satisfies no
      // issuance bound. The invoice version the parameter digest binds moves
      // with any change to it, so a changed fact refuses at reverification.
      resourceObj = {
        type: "invoice",
        id: invoice.id,
        properties: {
          vendor_id: vendor.id,
          ...(typeof invoice.issued_at === "string" ? { issued_at: invoice.issued_at } : {}),
          // The tenant that owns the invoice is its vendor's, from the vendor
          // record, whose version the parameter digest also binds.
          ...(typeof vendor.tenant === "string" ? { tenant: vendor.tenant } : {}),
          // The invoice's own classification label, from its record.
          ...(typeof invoice.classification === "string" ? { data_classification: invoice.classification } : {}),
        },
      };
    } else if (mapping.bindsVendorScope) {
      // @spec runtime#read-binding — "a consequential read whose parameters
      // ... request a bulk or export-like result ... MUST bind those
      // parameters. A deployment MUST NOT classify such a read as not
      // materially affecting the resource set." list_invoices without
      // vendor_id is exactly that bulk form. `deriveVendorScope` is this
      // action's Operation Profile: it normalizes (entry, requested vendor_id)
      // to the canonical form above, which is what actually enters
      // `parameter_digest` below; previously nothing did, so no digest ever
      // reached the PDP request or the reverification the write/transaction
      // paths already perform.
      const entry = view.authority_set.find(
        (e) => entryMatchesTarget(e, operationTarget) && e.actions.includes(mapping.action),
      );
      // @spec runtime#input-resource-policy (#828 step 5): a named vendor_id
      // is the vendor the payments store resolved, never the argument, as
      // for lookup_vendor (D324); a vendor the store does not hold is refused
      // here, before any decision, as get_invoice refuses an unknown invoice
      // and lookup_vendor an unknown vendor (D484).
      let requestedVendorId: string | undefined;
      if (args.vendor_id !== undefined) {
        requestedVendorId = this.deps.payments.getVendor(String(args.vendor_id))?.id;
        if (requestedVendorId === undefined) return await this.refuse(boundary, token, "unknown_vendor", mapping.action, view);
      }
      const scope = deriveVendorScope(entry, requestedVendorId, this.deps.payments.invoiceVendorIds());
      listEffective = buildListEffectiveParams({ action: mapping.action, resource: operationTarget, ...scope });
      listDigest = parameterDigest(listEffective);
      // The RESULT-SET filter (server.ts's execute()) is a SEPARATE,
      // additional authorization-enforcement control, not the binding itself:
      // every source filters to exactly the normalized scope, so an invoice
      // for a vendor the decision never named is never returned.
      listVendorScope = scope.vendor_scope;
      if (requestedVendorId !== undefined) {
        // A named vendor_id binds through the SAME vendor-constraint check
        // every invoice-scoped action here uses (out-of-scope -> denied
        // out_of_authority at the FGA step below, same as get_invoice).
        resourceObj = { type: "vendor", id: requestedVendorId, properties: { vendor_id: requestedVendorId } };
      } else {
        // Bulk form: bind the RESULT SET to the normalized scope, the
        // entry's own allowlist (never the unconstrained store) or, for an
        // unconstrained entry, every vendor the store holds invoices for.
        // A vendor-constrained entry's set-level authority is the Mission
        // Record's own entry.constraints.vendors, read directly here, not
        // derived from the FGA check below.
        //
        // @spec runtime#read-binding: finding 3 (PR #612 author review), the
        // FGA/PDP request names the FULL collection, not just one
        // representative member: `vendor_ids` carries every vendor this read
        // is about to return, and evaluateInner's step 6a checks each one
        // independently, as Resource policy checks every member at step 6b
        // (a denial on ANY member denies the whole read, with no narrowed
        // result). An empty set still denies, since UNSCOPED_VENDOR_OBJECT
        // names no real vendor. `id`/`vendor_id` still name one representative member
        // (the step-6 single check, unchanged, still runs first) so every
        // OTHER single-object caller of this request shape is unaffected;
        // `vendor_ids` is what makes the per-member check happen at all. The
        // Decision Evidence this permit produces still anchors the FULL entry
        // (entry_digest, @spec authzen#decision-evidence-object): that proves
        // the Mission's OWN ceiling, never Resource policy's independent
        // per-member say, which is what this member now actually proves.
        const representative = scope.vendor_scope[0] ?? UNSCOPED_VENDOR_OBJECT;
        resourceObj = {
          type: "vendor",
          id: representative,
          properties: { vendor_id: representative, vendor_ids: scope.vendor_scope },
        };
      }
    }

    // @spec runtime#input-authority, runtime-oauth#authorization-details-mapping
    // (#825) — the credential bound, on the target this PEP resolved: the
    // action must fall within the verified credential's own authority, one
    // whole entry at a time, before the PDP evaluates the Mission bound. A
    // broader Mission or an allowing resource policy never repairs a narrower
    // credential, and a Mission-bound credential that carries no authority
    // never falls back to the Mission's. On the ordinary-token (MAS Join)
    // path the same check applies to the resolver's entries (rule 8, bound 1).
    //
    // Only what this PEP can establish refuses here: resource, action, every
    // vendor reached and the amount. An entry's discharge condition and
    // approval requirement turn on Mission state and approvals the PDP holds,
    // so they reach the PDP with the credential's authority and the PDP
    // decides them (D312).
    const establishedFacts = {
      // #1276, D457: the operation target, matched with the Resource Access
      // matcher, as the PDP will match it.
      resource: operationTarget,
      action: mapping.action,
      vendorIds: (effective
        ? [effective.vendor_id]
        : targetVendorId !== undefined
          ? [targetVendorId]
          : resourceObj.type === "vendor" && resourceObj.id !== UNSCOPED_VENDOR_OBJECT
          ? ((resourceObj.properties?.vendor_ids as readonly string[] | undefined) ?? [resourceObj.id])
          : []) as readonly string[],
      ...(amount ? { amount } : {}),
      // @spec resource-access#rs-enforcement (#1266): the facts the
      // implemented Common Constraints read, as this PEP established them
      // above (the same values the decision request carries).
      constraintFacts: {
        ...(resourceObj.properties?.issued_at !== undefined
          ? { resourceIssuedAt: resourceObj.properties.issued_at }
          : {}),
        ...(resourceObj.properties?.tenant !== undefined ? { tenant: resourceObj.properties.tenant } : {}),
        ...(resourceObj.properties?.data_classification !== undefined
          ? { dataClassification: [resourceObj.properties.data_classification] }
          : {}),
        // `time_window` reads this PEP's own clock, at this check; every
        // later use is held to the permit's `valid_until`, which the PDP caps
        // at the window's end (PERMIT_USE_CHECKS).
        now: this.now().getTime(),
        ...(recipients ? { recipients } : {}),
        tool,
      },
    };
    if (token.mission !== undefined) {
      const covered =
        Array.isArray(token.credentialAuthority) &&
        coveringCredentialEntries(token.credentialAuthority, establishedFacts).length > 0;
      carriedAuthority = token.credentialAuthority;
      if (!covered) {
        await this.recordRefusal(boundary, token, "out_of_authority", mapping.action, view, undefined, { resource: resourceObj });
        return { permitted: false, denial_reason: "out_of_authority" };
      }
    } else if (
      !joinMappingUnavailable &&
      carriedAuthority !== undefined &&
      coveringCredentialEntries(carriedAuthority, establishedFacts).length === 0
    ) {
      // The Mission's view itself is never filtered by the credential (D340).
      // An unavailable mapping contract skips this gate only so the PDP's join
      // reports it (`mission_binding_failed`); its empty credential authority
      // still permits nothing there (#818 review P2).
      return await this.refuse(boundary, token, "out_of_authority", mapping.action, view);
    }

    // Actor facts and capability presentation originate at the enforcement surface.
    const contextActor = buildContextActor({
      ...(token.clientId !== undefined ? { clientId: token.clientId } : {}),
      ...(token.clientInstanceId !== undefined ? { clientInstanceId: token.clientInstanceId } : {}),
      ...(token.act !== undefined ? { act: token.act } : {}),
    });

    let capability: ReturnType<CapabilityCatalog["resolve"]>;
    try { capability = this.capabilityCatalog.resolve(tool); }
    catch {
      return this.refuse(boundary, token, "capability_source_unresolvable", mapping.action, view, undefined, { resource: resourceObj });
    }
    const capabilitySnapshot = capability.catalog_sourced ? capability.snapshot : undefined;
    if (effective && capabilitySnapshot) effective.capability_snapshot = capabilitySnapshot;
    if (listEffective && capabilitySnapshot) listEffective.capability_snapshot = capabilitySnapshot;

    const req: EvaluationRequest = {
      // @spec authzen#pdp-request rule 10 — `subject.properties.iss` is this
      // resource's own verified issuer identity, carried on TokenFacts by
      // the token validator that authenticated this request, never anything
      // client-supplied.
      subject: { id: token.sub, ...(token.iss !== undefined ? { properties: { iss: token.iss } } : {}) },
      // @spec authzen#context-audience-freshness, authzen#pdp-request: this
      // PEP's protected-resource identifier rides `resource.properties.audience`
      // on every request, beside the target object's own resource-scoped
      // members. @spec resource-access#resource-matching (#1276, D457): the
      // operation target this PEP established rides beside it, and the PDP
      // matches the credential's and the Mission's entries against the
      // target, never against the audience or `type`/`id`.
      resource: {
        ...resourceObj,
        properties: { ...resourceObj.properties, audience: boundary, operation_target: operationTarget },
      },
      // @spec authzen#parameter-digest `idempotency_key` (#917): forwarded
      // exactly as the caller supplied it, distinct from `parameter_digest`.
      // A missing or malformed key is the PDP's to refuse; this PEP neither
      // mints one nor repairs one.
      action: {
        name: mapping.action,
        ...({
              properties: {
                // @spec resource-access#initial-common-constraints (#1266): the
                // tool this PEP dispatched the operation to, from its
                // Operation Profile, never an argument.
                tool,
                ...(mapping.idempotencyKey && typeof args.idempotency_key === "string"
                  ? { idempotency_key: args.idempotency_key }
                  : {}),
                // @spec resource-access#initial-common-constraints (#1266): the
                // resolved recipients, from this resource's records only.
                ...(recipients ? { recipients } : {}),
              },
            }),
      },
      context: {
        mission: {
          // @spec authority-server#mission-join rule 1/2, #557 review point
          // 1 — `missionAnchor.id`, not `view.id`: on the Mission-bound path
          // this is the credential's OWN verified claim; on the baseline-
          // Join path it is the REAL propagated reference (rule 1), not a
          // copy of the loaded view's own id. Sourcing this from `view`
          // instead would make the PDP's step-1 view-consistency check
          // compare the loaded view against itself -- tautological, unable
          // to catch a loader that resolved the wrong Mission.
          id: missionAnchor.id,
          issuer: missionAnchor.issuer,
          // @spec mission#the-mission-claim, authzen#context-mission (#702) —
          // NOT on the baseline claim; carried into the envelope only when
          // the verified token's own profile added it. Present-then-check
          // downstream (evaluate.ts's view-consistency rule 1). Always
          // absent on the baseline-Join path (#557): an ordinary credential
          // carries no such extension member.
          ...(missionAnchor.authority_hash !== undefined
            ? { authority_hash: missionAnchor.authority_hash }
            : {}),
          // @spec cross-domain#mission-subject, authzen#context-mission — the
          // verified token's immutable origin principal, carried unchanged;
          // never populated from `args` or any other unverified request value.
          ...(missionAnchor.subject !== undefined ? { subject: missionAnchor.subject } : {}),
        },
        // @spec runtime#state-freshness, authzen#context-audience-freshness:
        // under `pep` placement, the observation is the loader's OWN
        // assertion of the state it read and when, propagated exactly as
        // `loadView` returned it. The PEP never stamps its own clock here
        // (Finding 1): doing so would relabel a cached or relayed observation
        // as fresh at the moment it happened to be consumed, rather than at
        // the moment it was actually read. Supplying it keeps a
        // high-consequence action class (irreversible_action,
        // external_commitment) from being denied `stale_state` merely for
        // omitting the member (the PDP's #608 GAP 2 fail-closed fix). Under
        // `pdp` placement the member is absent: the PDP establishes state
        // from its own read.
        ...(this.placement === "pep" ? { mission_state_observation: observation } : {}),
        actor: contextActor,
        // @spec authzen#context-credential (#825, D312): verified facts only,
        // and the credential's own authority on every decision, so the PDP
        // enforces the credential bound itself.
        credential: {
          ...(typeof token.credential?.issuer === "string" ? { issuer: token.credential.issuer } : {}),
          ...(typeof token.credential?.expires_at === "string" ? { expires_at: token.credential.expires_at } : {}),
          ...(carriedAuthority !== undefined ? { authority: carriedAuthority } : {}),
        },
        // @spec capability-binding#context-capability-source — the PEP supplies
        // the binding for a catalog-sourced action, and omits the member entirely
        // for a non-catalog one.
        ...(capability.catalog_sourced ? { capability_source: capability.binding } : {}),
        ...(effective ? { parameter_digest: parameterDigest(effective) } : {}),
        ...(listDigest ? { parameter_digest: listDigest } : {}),
        ...(amount ? { amount } : {}),
        action_class: mapping.actionClass,
        // @spec authzen#context-action-phase — supplied from THIS surface's
        // trusted Operation Profile (`mapping.phase`), never from `args`: an
        // agent-supplied `action_phase` argument is not read anywhere on this
        // path, so it cannot select or move the phase of a crossing.
        ...(mapping.phase !== undefined ? { action_phase: mapping.phase } : {}),
        ...(actionApproval ? { action_approval: actionApproval } : {}),
        // @spec authority-server#mission-join (#557 review point 1) —
        // present exactly on the baseline-Join path: tells the PDP to
        // resolve rules 3-6 itself against this envelope's already-
        // authenticated subject/context.actor.client_id, rather than
        // trusting a pre-narrowed view the PEP resolved outside the PDP.
        ...(isBaselineJoin
          ? { mission_join: { ...(delegateDepth !== undefined ? { delegate_depth: delegateDepth } : {}) } }
          : {}),
      } as EvaluationRequest["context"],
    };

    // @spec runtime-evidence#decision-evidence-object (#741, PR #753 review):
    // typed as `DecisionOptions`, so this file cannot name an emission path at
    // all. The decision point applies its own; absent one, the co-resident
    // `evaluate` runs unevidenced and the retention check below refuses the
    // permit.
    const decisionOptions: DecisionOptions = {
      view,
      fga: this.deps.fga,
      modelId: this.deps.modelId,
      now: this.now,
      stalenessBound,
      relationForAction,
      ...(this.deps.requiresActionApproval ? { requiresActionApproval: this.deps.requiresActionApproval } : {}),
      ...(this.deps.maxApprovalAgeSeconds ? { maxApprovalAgeSeconds: this.deps.maxApprovalAgeSeconds } : {}),
      ...(this.deps.requestable ? { requestable: this.deps.requestable } : {}),
      stateSourcePlacement: this.placement,
      // @spec authzen#pdp-request rule 1: under `pdp` placement the
      // co-resident PDP's own read is the loader read that produced `view`;
      // a remote PDP resolves its own on its side of the channel.
      ...(this.placement === "pdp" ? { stateObservedAt: observation.freshness_at } : {}),
      ...(this.deps.principalMapping ? { principalMapping: this.deps.principalMapping } : {}),
      ...(this.deps.entitlement ? { entitlement: this.deps.entitlement } : {}),
      ...(this.deps.entitlementStalenessBoundSeconds !== undefined
        ? { entitlementStalenessBoundSeconds: this.deps.entitlementStalenessBoundSeconds }
        : {}),
      // @spec authority-server#mission-join rule 4 (#557 review point 1) —
      // forwarded to the PDP unchanged; consulted only when this request
      // carries `context.mission_join` above.
      // @spec authority-server#mapping-contract (#818): under a mapping
      // contract, the delegate policy is the one that contract version states.
      ...(joinMapping?.delegatePolicy !== undefined
        ? { delegatePolicy: joinMapping.delegatePolicy }
        : this.deps.masJoin?.delegatePolicy !== undefined
          ? { delegatePolicy: this.deps.masJoin.delegatePolicy }
          : {}),
      // @spec authority-server#mapping-contract, #high-consequence-binding
      // (#818): the snapshot this request already applied, and the classes
      // this route reserves for Mission-bound credentials.
      ...(joinMapping ? { joinMapping } : {}),
      ...(this.deps.masJoin?.missionBoundOnlyClasses !== undefined
        ? { missionBoundOnlyClasses: this.deps.masJoin.missionBoundOnlyClasses }
        : {}),
    };
    // @spec authzen#failure-condition-coverage, runtime#outage-radius — the
    // decision call is guarded. A call that threw obtained no decision, and
    // "an unavailable gate is not permission": a transport error the channel
    // did not classify, a failure before the channel's own guard (request
    // serialization, channel authentication material), and a defect inside
    // the decision point all fail closed here as `pdp_unreachable`, the
    // reason the classified branch below already gives an unobtainable
    // decision. This is the PEP's own refusal path, never a policy denial: no
    // PDP evidence or evaluation identifier is attributed, nothing executes,
    // and the operator timeline keeps the Refusal Record.
    let decision: Decision;
    try {
      // With no decision point, `evaluate` runs with no Resource policy bound
      // (this PEP holds none, #828), so it refuses to decide: `pdp_unreachable`.
      decision = await (this.deps.decide ?? ((r: EvaluationRequest, o: DecisionOptions) => evaluate(r, o as EvaluateOptions)))(req, decisionOptions);
    } catch {
      return this.refuse(boundary, token, "pdp_unreachable", mapping.action, view, undefined, { evaluationRequest: req, resource: req.resource });
    }
    // @spec authzen#failure-condition-coverage — a local channel failure is
    // not a PDP decision. It has no PDP evidence/evaluation identifier, and
    // must take the PEP's own pre-decision Refusal Record path.
    if (isDecisionChannelRefusal(decision)) {
      // @spec authzen#failure-condition-coverage, authzen#transport-behavior —
      // the table scopes `channel_failure` to "PEP-PDP channel authentication
      // or integrity fails", so only an unauthenticated, malformed or
      // oversized response takes it. A reachable PDP that returned no decision
      // (timeout, transport failure, or any non-2xx status, 429 and 503
      // included) is "no decision obtainable within its policy window":
      // `pdp_unreachable`, per the same document's overload rule.
      const cause = String(decision.context.denial_reason);
      const integrityFailures = new Set([
        "decision_channel_unauthenticated_response",
        "decision_channel_malformed_response",
        "decision_channel_response_too_large",
      ]);
      const reason = integrityFailures.has(cause) ? "channel_failure" : "pdp_unreachable";
      return this.refuse(boundary, token, reason, mapping.action, view, undefined, { evaluationRequest: req, resource: req.resource });
    }

    this.deps.observe?.({ tool, args, token, envelope: req, decision, ...(effective ? { effective } : {}) });

    // @spec runtime-evidence#decision-evidence-object, #decision-evidence-integrity;
    // runtime#agent-isolated-evidence-emission (#741) — the PDP built and
    // signed this record on its own emission path, from the decision it
    // reached. This PEP verifies it (byte equality, signature, protected
    // header, and the key-to-emitter and key-to-audience binding) and
    // retains it VERBATIM. It reconstructs nothing: a record assembled here
    // would authenticate this PEP's reading of a decision under the decision
    // point's identity, which is the defect this path exists to close, and
    // the enforcement path holds no PDP evidence key to sign one with.
    //
    // The record is retrospective evidence of what the PDP decided, never
    // authorization to act (@spec authzen#permit-binding-split): the permit
    // this PEP acts on is `decision` itself, and the retention below changes
    // nothing about that.
    const emitted = decision.context.decision_evidence as DecisionEvidenceObject | undefined;
    // #1327 re-review: a newly retained record binds the version this request
    // was established at; a re-presented one keeps the version it was first
    // retained under.
    const retention = emitted
      ? await this.deps.evidence.retainDecision(emitted, { boundaryVersion })
      : ({ retained: false, reason: "absent" } as const);
    if (!retention.retained && decision.decision) {
      // Fail closed on a permit: an action whose decision left no verifiable
      // Decision Evidence is refused rather than executed. A denial keeps its
      // own denial reason, which is the more useful one, and denies either way.
      return this.refuse(boundary, token, "decision_evidence_unverifiable", mapping.action, view, undefined, {
        evaluationRequest: req,
        resource: req.resource,
      });
    }

    if (!decision.decision) {
      const ar = decision.context.access_request as EnforceResult["access_request"] | undefined;
      const result: EnforceResult = {
        permitted: false,
        decision,
        denial_reason: decision.context.denial_reason as string,
        ...(effective ? { effective } : {}),
        ...(ar ? { access_request: ar } : {}),
      };
      // @spec txn-authorization#resource-challenge — on an
      // action_approval_required denial the resource normalizes the operation,
      // computes the runtime parameter_digest, and returns a signed challenge.
      // The client's Accept-Txn-Challenge signal GATES it: without the signal a
      // client that cannot redeem a challenge just sees the denial. `mission`,
      // `parameter_digest` and `cnf` are derived HERE, from the request and the
      // verified token; nothing the client supplied can replace them.
      if (
        this.deps.challengeSigner &&
        signals?.acceptTxnChallenge &&
        decision.context.denial_reason === "action_approval_required" &&
        effective &&
        token.missionClaim &&
        view
      ) {
        const signer = this.deps.challengeSigner;
        // Exactly one operation-scoped entry: the active Mission's entry for
        // this resource+action narrowed to the single gated action (keeping the
        // entry's constraints), so the approval and the transaction token are
        // scoped to the operation being approved, not the whole entry. It is
        // the entry as the Mission Issuer committed it (`committedEntry`, D335:
        // no PDP-local member such as the loader's `join_delegation`), less
        // its issuer provenance.
        const requested = view.authority_set
          .filter((e) => entryMatchesTarget(e, operationTarget) && e.actions.includes(mapping.action))
          .map((e) => {
            const { capability_sources: _issuerProvenance, ...committed } = committedEntry(e);
            return { ...committed, actions: [mapping.action] };
          }) as unknown as JsonValue[];
        const digest = parameterDigest(effective);
        const signed = await signChallenge(
          {
            txn: randomUUID(),
            authorization_details: requested,
            parameter_digest: digest,
            mission: token.missionClaim,
            cnf: { jkt: token.cnfJkt },
            iss: CANONICAL_RESOURCE,
            aud: signer.asIssuer,
            reason: "action_approval_required",
            ...(signer.lifetimeSeconds !== undefined ? { lifetimeSeconds: signer.lifetimeSeconds } : {}),
            ...(token.act !== undefined ? { act: token.act as unknown as JsonValue } : {}),
          },
          signer.sign,
          signer.kid,
          signer.alg ?? "ES256",
        );
        result.challenge = {
          error: TXN_AUTHORIZATION_REQUIRED,
          transaction_challenge: signed.challenge,
          pending: {
            txn: signed.txn,
            resource: CANONICAL_RESOURCE,
            challengeJti: signed.jti,
            mission: token.missionClaim,
            action: mapping.action,
            parameterDigest: digest,
            authorizationDetails: requested,
            cnfJkt: token.cnfJkt,
            // @spec txn-authorization#challenge-redemption — the verified
            // subject, under the SAME rule the Transaction Authorization Server
            // mints `sub` by: the credential's OWN `sub`, in the issuing
            // Authorization Server's namespace. The origin principal, where the
            // Origin Principal profile applies, stays issuer-qualified inside
            // the `mission` claim and is covered by the mission-invariants
            // equality check -- never flattened into a local subject. The
            // retained operation and the token that comes back must agree.
            subject: token.sub,
          },
        };
      }
      // @spec I-D.draft-zehavi-oauth-rar-metadata §4 (insufficient_authorization
      // grain, additive to the grains above): only on a GENUINE out_of_authority
      // denial -- the (resource, action) pair is absent from the Mission's
      // Authority Set entirely, not merely denied for THIS target object
      // (deriveContextualTuples/FGA can still return out_of_authority for the
      // matched entry when the specific object's relationship is denied for
      // some other reason; a vendor-constraint exclusion is instead
      // parameter_violation, @spec authzen#runtime-denial-classification #801)
      // -- propose the missing entry back. Deliberately NOT emitted for authority_contained:
      // that is the family's monotonic trust ratchet (@spec containment);
      // handing back "here's how to ask again" for a deliberately narrowed
      // capability would contradict restore-only-via-Expansion.
      if (
        decision.context.denial_reason === "out_of_authority" &&
        !view.authority_set.some((e) => entryMatchesTarget(e, operationTarget) && e.actions.includes(mapping.action))
      ) {
        result.insufficient_authorization = buildInsufficientAuthorization([
          { type: "mission_resource_access", resource: operationTarget, actions: [mapping.action] },
        ]);
      }
      return result;
    }

    // @spec runtime-evidence#execution-evidence-object (issue #786) — the
    // permit is in hand and its Decision Evidence verified and retained, so
    // every failure from here on is a post-permit disposition, not a
    // pre-decision refusal. The attempt context is built ONCE, here, and
    // carries authorization facts from the RETAINED record (the authorized
    // digest included) rather than from the response context or the request.
    const retained = retention.retained ? retention.record.content : undefined;
    // @spec runtime#boundary-identifier-change (#1327 re-review): the version
    // the permit was decided under, from its retained row, never the one
    // established for this request. A PDP retransmission re-presents an
    // earlier permit; given the version now in force it would pass the
    // `enforcement_boundary` use check after a cutover.
    const permitVersion = retention.retained ? retention.record.boundary_version : undefined;
    const attempt: ExecutionAttempt = {
      evaluationId: decision.context.decision_id as string,
      mission: {
        id: missionAnchor.id,
        issuer: missionAnchor.issuer,
        ...(missionAnchor.authority_hash !== undefined ? { authority_hash: missionAnchor.authority_hash } : {}),
      },
      audience: boundary,
      ...(permitVersion !== undefined ? { boundaryVersion: permitVersion } : {}),
      operationTarget,
      action: mapping.action,
      tool,
      // @spec authzen#response-context — the permit's own bound conditions,
      // copied from the VERIFIED decision at the one point the permit is in
      // hand. `verifyPermitAtUse` compares only these retained values against
      // the crossing it is about to make, so no later step reconstructs
      // authorization from an agent argument or from retrospective evidence.
      ...(conditionsOf(decision)?.action_phase !== undefined
        ? { permitBoundPhase: conditionsOf(decision)?.action_phase }
        : {}),
      ...(conditionsOf(decision)?.valid_until !== undefined
        ? { permitValidUntil: conditionsOf(decision)?.valid_until }
        : {}),
      ...(retained?.parameter_digest !== undefined
        ? { authorizedParameterDigest: retained.parameter_digest }
        : {}),
      executionId: newRecordId("exe"),
      permitId: decision.context.decision_id as string,
      // The digest-bound operation key where the operation binds parameters;
      // a non-bound action supplies its own key rather than an operation key
      // with an absent digest baked into it.
      joinKey:
        retained?.parameter_digest !== undefined
          ? operationKey(missionAnchor.id, mapping.action, retained.parameter_digest, mapping.phase)
          : `op:${missionAnchor.id}:${mapping.action}`,
      ...(token.jti !== undefined
        ? {
            hopReference: {
              jti: token.jti,
              mission_id: missionAnchor.id,
              ...(token.identityContinuationHandle
                ? { continuation_handle: token.identityContinuationHandle }
                : {}),
            },
          }
        : {}),
      observeEffectiveDigest: () => {
        if (effective) {
          const invoice = this.deps.payments.getInvoice(effective.invoice_id);
          const vendor = invoice ? this.deps.payments.getVendor(invoice.vendor_id) : undefined;
          // The target is gone: no digest over "the parameters actually
          // attempted" exists to observe. Declining is the honest answer.
          if (!invoice || !vendor) return undefined;
          const bound = recipientParams(effective.recipients !== undefined || this.reachesRecipients(effective.action), this.deps.payments, vendor.id);
          if (!bound) return undefined;
          const fresh = buildEffectiveParams({
            action: effective.action,
            invoice,
            vendor,
            resource: effective.resource,
            ...bound,
          });
          return parameterDigest(fresh);
        }
        if (listEffective) {
          const loaded = loadCheckedView(this.deps.loadView, {
            id: missionAnchor.id,
            issuer: missionAnchor.issuer,
          });
          const entry = loaded?.view.authority_set.find(
            (e) => entryMatchesTarget(e, listEffective.resource) && e.actions.includes(listEffective.action),
          );
          const requestedVendorId =
            listEffective.vendor_scope_source === "requested" ? listEffective.vendor_scope[0] : undefined;
          const fresh = buildListEffectiveParams({
            action: listEffective.action,
            resource: listEffective.resource,
            ...deriveVendorScope(entry, requestedVendorId, this.deps.payments.invoiceVendorIds()),
          });
          return parameterDigest(fresh);
        }
        return undefined;
      },
    };

    // @spec authzen#response-context, runtime#decision-output: "a condition
    // the enforcing component does not recognize makes the permit unusable."
    // The check is scoped to `decision.context.conditions` ONLY (the
    // profile's must-understand rule names conditions specifically, never
    // the whole response context): a permit's `conditions` carries the
    // three genuine reliance constraints (parameter_digest = request
    // binding, valid_until = validity bound, use_limit = use limit). ANY
    // other member inside `conditions` is one this PEP does not recognize,
    // so the permit it rides on is unusable: refuse with zero effect, never
    // ignore.
    const conditions = decision.context.conditions as Record<string, unknown> | undefined;
    const recognized = this.recognizedConditions();
    const unrecognizedConditions = conditions
      ? Object.keys(conditions).filter((k) => !recognized.has(k))
      : [];
    if (unrecognizedConditions.length > 0) {
      // Post-permit: a permit was obtained and is unusable, so this is a
      // suppressed disposition of that permit, never a Refusal Record
      // (@spec runtime-evidence#pre-decision-refusal boundary rule).
      await this.suppressExecution(attempt, "condition_unrecognized");
      return { permitted: false, refusal_reason: "unrecognized_condition" };
    }

    // @spec authzen#obligations: an obligation MAY accompany a permit; the
    // PEP MUST fulfill every obligation before releasing the action's effect
    // and MUST treat an unrecognized or unfulfillable obligation as an
    // effective deny, the obligations-lane counterpart of the conditions
    // check above. This PEP implements NO obligation type yet, so ANY
    // obligation present is, by definition, unfulfillable: its mere presence
    // is a deny, never a silently granted permit and never folded into the
    // conditions refusal reason above (a distinct rule, a distinct reason).
    const obligations = decision.context.obligations as unknown[] | undefined;
    if (obligations && obligations.length > 0) {
      // @spec runtime-evidence#execution-evidence-object `obligation_outcomes`
      // ("one object per attached obligation"): the failing entries are named
      // when every attached obligation identifies itself, and the member is
      // omitted entirely when one does not. A partial list would read as
      // complete, and `id`/`type` are REQUIRED and cannot be invented.
      const outcomes = obligationOutcomes(obligations);
      await this.suppressExecution(attempt, "obligation_unfulfilled", {
        ...(outcomes ? { obligationOutcomes: outcomes } : {}),
      });
      return { permitted: false, refusal_reason: "unfulfillable_obligation" };
    }

    // @spec runtime#idempotency (#918): the pair a keyed reversible write
    // reserves, from the request exactly as the PDP received it, through the
    // shared scope projection (its actor is `idempotencyScopeActor`'s stable
    // identity, never the raw leaf). An actor with no stable identity (an
    // instance-profiled leaf with no client) yields no scope and so no pair,
    // which is marked: the write path then refuses before any effect, since a
    // key it cannot scope cannot be reserved. Nothing here throws after the
    // permit.
    let writeReservation: WriteReservationScope | undefined;
    const keyedWrite = mapping.idempotencyKey === true && mapping.actionClass === "consequential_write";
    const scope = keyedWrite ? idempotencyScopeOf(req) : undefined;
    if (scope) {
      const key = req.action.properties?.idempotency_key;
      writeReservation = {
        scope,
        scopeDigest: idempotencyScopeDigest(scope),
        lineageScopeDigests: lineageScopeDigests(this.boundaryContext.declaration, scope),
        operationIdentity: operationIdentity(req),
        ...(typeof key === "string" ? { idempotencyKey: key } : {}),
      };
    }

    return {
      permitted: true,
      decision,
      attempt,
      ...(writeReservation ? { writeReservation } : {}),
      ...(keyedWrite && !scope ? { writeReservationUnkeyable: true as const } : {}),
      resolvedMission: {
        id: missionAnchor.id,
        issuer: missionAnchor.issuer,
        ...(missionAnchor.authority_hash !== undefined ? { authority_hash: missionAnchor.authority_hash } : {}),
      },
      ...(effective ? { effective } : {}),
      ...(listEffective ? { listEffective } : {}),
      ...(capabilitySnapshot ? { capabilitySnapshot } : {}),
      ...(listVendorScope ? { list_vendor_scope: listVendorScope } : {}),
    };
  }

  /**
   * @spec runtime-evidence#execution-evidence-object (issue #786): the ONE
   * post-permit disposition writer. Every exit that fails an obtained permit
   * routes here, so error classification, evidence linkage and the
   * caller-visible failure have a single owner, and no exit assembles a
   * record of its own or emits a Refusal Record for a permit it held.
   *
   * The record links to the retained Decision by `evaluation_id`, and its
   * authorization facts come from {@link ExecutionAttempt}, never from the
   * agent's arguments or an unverified response. `role` is `pep`: nothing
   * executed, so the executor did not dispose of this permit.
   *
   * The effective digest is OBSERVED here, at the disposition, and the record
   * is not emitted at all when an authorized digest is present and no
   * observation can be made ({@link SuppressOutcome} `gap`). Emitting a
   * sentinel would fabricate an observation; emitting the record without the
   * member would be invalid under the present schema. That case is #786's
   * declared outstanding defect, joint with #594.
   *
   * Emission is awaited so signing and retention complete before the caller
   * learns the outcome, and one retry reuses the same execution identity. A
   * durable queue for a still-failing emission is #594 W4-4.
   */
  async suppressExecution(
    attempt: ExecutionAttempt,
    error: string,
    opts: { obligationOutcomes?: ExecutionEvidenceObject["obligation_outcomes"] } = {},
  ): Promise<SuppressOutcome> {
    const observed = attempt.observeEffectiveDigest();
    if (attempt.authorizedParameterDigest !== undefined && observed === undefined) {
      return { recorded: false, gap: "effective_parameter_digest_unobservable" };
    }
    const input = {
      permitId: attempt.permitId,
      opKey: attempt.joinKey,
      execution_id: attempt.executionId,
      evaluation_id: attempt.evaluationId,
      mission_id: attempt.mission.id,
      audience: attempt.audience,
      // The pair is carried together or not at all: the authorized member MUST
      // be absent when the linked Decision Evidence carries no
      // `parameter_digest`, and an effective digest alone commits nothing.
      ...(attempt.authorizedParameterDigest !== undefined && observed !== undefined
        ? {
            authorized_parameter_digest: attempt.authorizedParameterDigest,
            effective_parameter_digest: observed,
          }
        : {}),
      outcome: "suppressed" as const,
      error,
      ...(opts.obligationOutcomes ? { obligation_outcomes: opts.obligationOutcomes } : {}),
      ...(attempt.hopReference ? { hop_reference: attempt.hopReference } : {}),
    };
    for (let tries = 0; tries < 2; tries += 1) {
      try {
        const recorded = await this.deps.evidence.recordExecution(CANONICAL_RESOURCE, "pep", input);
        // A suppression after redemption is the redeeming attempt's proof of
        // no effect: it settles the claim `failed`.
        if (attempt.redeemed) await this.settleClaim(recorded.content);
        return { recorded: true };
      } catch {
        /* one retry, on the SAME execution identity: a retained record is
           returned rather than duplicated, so this cannot double-emit. */
      }
    }
    return { recorded: false, gap: "emission_failed" };
  }

  /**
   * @spec runtime#idempotency (#917, owner ruling 2026-10-02): tell the
   * PDP's claim domain how a REDEEMED attempt ended, with the attempt's own
   * PEP-signed Execution Evidence over the authenticated decision channel.
   * Redemption, the lease and the effect stay here (D28); the PDP is told,
   * never asked to redeem. Best effort by design: a settlement that fails to
   * arrive leaves the claim suppressed, and reconciliation resolves it from
   * the same evidence later.
   */
  async settleClaim(record: ExecutionEvidenceObject): Promise<void> {
    if (!this.deps.claims) return;
    try {
      await this.deps.claims.settle(record);
    } catch {
      /* resolved by reconciliation */
    }
  }

  /**
   * @spec runtime#compound-actions, runtime#execution-reverification — the ONE
   * pre-effect verification seam, called from every dispatch path.
   *
   * Both phase MUSTs are unconditional, and this deployment has three dispatch
   * paths (`callReadTool`, `callWriteTool`, `callTransactionTool`), only the
   * last of which reaches a connector. A preflight crossing releases no
   * connector effect and still MUST refuse a `commit` permit, so the
   * comparison belongs here, in front of every crossing, rather than beside
   * the one commit point.
   *
   * Every dispatch path calls it TWICE, and both calls run the WHOLE table:
   *
   * - at admission, BEFORE any state the crossing would burn (the transaction
   *   path's single-use permit redemption included) and before any awaited
   *   capability, parameter or resource read. A wrong-phase or expired
   *   presentation therefore consumes nothing, and the legitimate crossing
   *   that follows still finds its own redemption available.
   * - again after the last awaited read and immediately before the effect is
   *   released. Both the clock and the Operation Profile can move while a
   *   resolver call is pending, so the admission call is never the last word
   *   on either: the permit is held to the same comparisons at the boundary
   *   it crosses. Moving a comparison earlier must not enlarge the unchecked
   *   interval, which is why the earlier call ADDS to the later one rather
   *   than replacing part of it.
   *
   * Running the table is synchronous over state already in hand, so the
   * second call opens no new awaited window before the effect. Within it, the
   * rows run in table order and each reads the clock at its own turn, so the
   * `valid_until` comparison is the LAST thing decided before release.
   *
   * What this seam governs is whether the permit may still INITIATE an
   * effect. Once an effect has started, how long it may run is the execution
   * lease's question (`executionLeaseMs` / `TransactionEngine.leaseValid`),
   * and an expired permit is never permission to restart an operation whose
   * effect already committed.
   *
   * Every comparator is a row in one table, so a coordinated condition added
   * later (issue #773's `evaluation_context_digest`) joins this seam as
   * another row rather than a competing check on another path.
   */
  async verifyPermitAtUse(attempt: ExecutionAttempt): Promise<ReverifyOutcome> {
    const error = this.permitUseFailure(attempt);
    if (error !== undefined) {
      const disposition = await this.suppressExecution(attempt, error);
      return { ok: false, error, disposition };
    }
    return { ok: true };
  }

  /**
   * The same table {@link verifyPermitAtUse} runs, in the same order, with
   * nothing recorded: the first failing comparison's error, or `undefined`
   * when every row holds. For a boundary whose attempt already holds its one
   * disposition (#918's release of a retained result, after its
   * `operation_already_claimed` record was written), where a second record
   * under the same execution identity would be refused.
   */
  permitUseFailure(attempt: ExecutionAttempt): string | undefined {
    for (const check of PERMIT_USE_CHECKS) {
      const now = this.now();
      const error = check.failure(attempt, {
        now,
        profile: this.toolAction(attempt.tool),
        boundary: this.boundaryContext.establish(now),
      });
      if (error !== undefined) return error;
    }
    return undefined;
  }

  /**
   * @spec operation-profile (parameter binding / TOCTOU): re-verify the
   * effective parameters immediately before execution. A digest mismatch
   * (record changed under us) suppresses the permit, it never executes.
   * The result names the gate that failed, so a caller cannot report a
   * capability failure as a parameter comparison.
   */
  async reverify(
    effective: EffectiveParams,
    expectedDigest: string,
    token: TokenFacts,
    attempt: ExecutionAttempt,
  ): Promise<ReverifyOutcome> {
    const capability = await this.reverifyCapability(effective.capability_snapshot, token, effective.action, attempt);
    if (!capability.ok) return capability;
    const invoice = this.deps.payments.getInvoice(effective.invoice_id);
    const vendor = invoice ? this.deps.payments.getVendor(invoice.vendor_id) : undefined;
    if (!invoice || !vendor) {
      // The permit's target no longer resolves. The parameters it bound cannot
      // be met, so the disposition is a parameter mismatch; the record itself
      // is the outstanding case above (no effective digest is observable).
      const disposition = await this.suppressExecution(attempt, "parameter_mismatch");
      return { ok: false, error: "parameter_mismatch", disposition };
    }
    // @spec resource-access#initial-common-constraints (#1266): the routed
    // recipients re-resolved now; a routing that changed, or no longer
    // resolves, is a parameter mismatch.
    const bound = recipientParams(effective.recipients !== undefined || this.reachesRecipients(effective.action), this.deps.payments, vendor.id);
    if (!bound) {
      const disposition = await this.suppressExecution(attempt, "parameter_mismatch");
      return { ok: false, error: "parameter_mismatch", disposition };
    }
    const fresh = buildEffectiveParams({ action: effective.action, invoice, vendor, resource: effective.resource, ...bound });
    const freshDigest = parameterDigest(fresh);
    if (freshDigest !== expectedDigest) {
      const disposition = await this.suppressExecution(attempt, "parameter_mismatch");
      return { ok: false, error: "parameter_mismatch", disposition };
    }
    return { ok: true, effectiveParameterDigest: freshDigest };
  }

  /**
   * @spec runtime#read-binding (parameter binding / TOCTOU): the list-read
   * counterpart of {@link reverify}. The authoritative source for a bound
   * list read's normal form is the Mission's OWN authority-set entry, not
   * the payments store, so this re-loads the CURRENT MissionView (never the
   * one `enforceInner` matched) and recomputes {@link deriveVendorScope}
   * against it. A Mission-authority change landing in the decision->execute
   * window (a narrower successor entry, containment, the entry disappearing)
   * recomputes a DIFFERENT normal form and is caught here as a digest
   * mismatch, refused, never executed on the stale scope the permit was
   * decided against. `requestedVendorId` is recovered from `effective` itself
   * (present, as `vendor_scope[0]`, exactly when `vendor_scope_source` is
   * `"requested"`), so no separate input needs to be threaded through.
   */
  async reverifyList(
    effective: ListEffectiveParams,
    expectedDigest: string,
    token: TokenFacts,
    attempt: ExecutionAttempt,
  ): Promise<ReverifyOutcome> {
    const capability = await this.reverifyCapability(effective.capability_snapshot, token, effective.action, attempt);
    if (!capability.ok) return capability;
    // @spec authority-server#mission-join (#557): the CURRENT view, reloaded
    // against the ATTEMPT's governing Mission, so a baseline-Join read
    // reverifies against the reference the Join resolved. The former
    // fallback recorded a parameter mismatch for a credential carrying no
    // `mission` claim without comparing any digest, a false reason issue
    // #786 removes rather than reclassifies.
    const loaded = loadCheckedView(this.deps.loadView, {
      id: attempt.mission.id,
      issuer: attempt.mission.issuer,
    });
    const entry = loaded?.view.authority_set.find(
      (e) => entryMatchesTarget(e, effective.resource) && e.actions.includes(effective.action),
    );
    const requestedVendorId =
      effective.vendor_scope_source === "requested" ? effective.vendor_scope[0] : undefined;
    const fresh = buildListEffectiveParams({
      action: effective.action,
      resource: effective.resource,
      ...deriveVendorScope(entry, requestedVendorId, this.deps.payments.invoiceVendorIds()),
    });
    const freshDigest = parameterDigest(fresh);
    if (freshDigest !== expectedDigest) {
      const disposition = await this.suppressExecution(attempt, "parameter_mismatch");
      return { ok: false, error: "parameter_mismatch", disposition };
    }
    return { ok: true, effectiveParameterDigest: freshDigest };
  }

  /**
   * @spec capability-binding#context-capability-source — re-resolve the
   * capability definition the permit was decided against, immediately before
   * the action. A moved or unresolvable snapshot is its OWN error: the
   * snapshot is excluded from `parameter_digest` (effective-params.ts), so
   * reporting a parameter mismatch would assert a comparison that never
   * failed.
   *
   * This is the POST-PERMIT call site, which is why it suppresses. The
   * pre-decision resolution failure is a different call site
   * (`enforceInner`'s catch), keeps its Refusal Record, and the two are
   * separated by call site, never by the reason string they share.
   */
  async reverifyCapability(
    snapshot: CapabilitySnapshot | undefined,
    token: TokenFacts,
    action: string,
    attempt: ExecutionAttempt,
  ): Promise<ReverifyOutcome> {
    if (!snapshot) return { ok: true };
    try {
      const current = this.capabilityCatalog.resolve(snapshot.tool);
      if (current.catalog_sourced && current.snapshot.id === snapshot.id) return { ok: true };
    } catch { /* unavailable at invocation is also a refusal */ }
    const disposition = await this.suppressExecution(attempt, "capability_source_unresolvable");
    return { ok: false, error: "capability_source_unresolvable", disposition };
  }

  private async refuse(
    boundary: string,
    token: TokenFacts,
    reason: PepRefusalDiagnostic,
    action: string,
    view?: MissionView,
    missionIdOverride?: string,
    established?: RefusalEstablished,
  ): Promise<EnforceResult> {
    await this.recordRefusal(boundary, token, reason, action, view, missionIdOverride, established);
    return { permitted: false, refusal_reason: reason };
  }

  /**
   * @spec runtime-evidence#pre-decision-refusal (issue #649): `mission` is
   * present only when `view` was successfully loaded (an ESTABLISHED
   * reference, per the spec's own rule: absent is not itself a defect, it is
   * exactly what an establishment failure like `unknown_mission` looks
   * like). `missionId` (the wrapper's store-level correlation key) is
   * separate and always present: the resolved view's id, else the
   * credential's own CLAIMED reference, else `missionIdOverride` for a
   * baseline-Join refusal that precedes both (@spec
   * authority-server#mission-join, #557) -- "unknown" is the last resort for
   * a refusal that never identified a Mission at all. This lets an operator
   * timeline bucket a pre-establishment refusal under the mission the
   * caller named, without the signed record itself asserting that
   * reference was ever verified.
   *
   * `reason` is the caller-visible diagnostic; the signed record carries the
   * enumerated pre-decision value {@link signedDenialReason} maps it to
   * (@spec runtime-evidence#pre-decision-refusal: "this member carries an
   * enumerated value, never a deployment's own diagnostic string"). The two
   * surfaces are deliberately separate, and only the signed one is
   * interoperable.
   *
   * `boundary` is the enforcement boundary this request established
   * (@spec runtime#runtime-conformance, #853, D487): the record's `audience`,
   * whatever `aud` the credential carried. A denial needs no permit for it.
   */
  private async recordRefusal(
    boundary: string,
    token: TokenFacts,
    reason: PepRefusalDiagnostic,
    action: string,
    view?: MissionView,
    missionIdOverride?: string,
    established?: RefusalEstablished,
  ): Promise<void> {
    const missionId = view?.id ?? token.mission?.id ?? missionIdOverride ?? "unknown";
    await this.deps.evidence.recordRefusal(CANONICAL_RESOURCE, "pep", {
      missionId,
      audience: boundary,
      action: { name: action },
      denial_reason: signedDenialReason(reason),
      subject: { id: token.sub, ...(token.iss !== undefined ? { properties: { iss: token.iss } } : {}) },
      ...(view !== undefined
        ? { mission: { id: view.id, issuer: view.issuer, authority_hash: view.authority_hash } }
        : {}),
      // @spec runtime-evidence#pre-decision-refusal: the target object this
      // PEP established before refusing, reduced to its identity. It also
      // enters a pre-request digest as `resource`.
      ...(established?.resource !== undefined
        ? { resource: { type: established.resource.type, id: established.resource.id } }
        : {}),
      // @spec runtime-evidence#request-digest-worked: a refusal after the
      // request was built digests that request as submitted.
      ...(established?.evaluationRequest !== undefined ? { evaluation_request: established.evaluationRequest } : {}),
    });
  }
}


export { TOOL_ACTIONS };
