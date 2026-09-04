/**
 * @spec mission#rs-enforcement, runtime (PEP), authzen (envelope)
 *
 * The resource-server PEP for the payments estate. Validates the DPoP-bound
 * token and mission claim, builds the AuthZEN envelope (context.actor via
 * @mission/actor-chain, parameter_digest), obtains a PDP decision, retains
 * the Decision Evidence the PDP emitted with it, and emits its own Refusal
 * Records and Execution Evidence. Core enforcement tier (M4); the
 * transaction-assurance tier (permits/leases) lands in M5. Does not present
 * `context.capability_source` on the PDP request envelope (#657; see
 * `sourceDigestOf` below), and no longer carries it on the retained Decision
 * Evidence either (#741: the PDP emits and signs that record, from its own
 * validated inputs).
 */

import { createHash, randomUUID } from "node:crypto";
import { type ActObject, buildContextActor, flattenActChain } from "@mission/actor-chain";
import {
  type JsonValue,
  type PropagatedMissionReference,
  TXN_AUTHORIZATION_REQUIRED,
  type TxnMissionClaim,
} from "@mission/core";
import { getTracer } from "@mission/telemetry";
import {
  type AuthorityEntry,
  type DecisionEvidenceEmitter,
  type DecisionEvidenceObject,
  type DelegatePolicy,
  type Decision,
  type EntitlementResolver,
  evaluate,
  type EvaluationRequest,
  type Fga,
  type Freshness,
  type MissionView,
  type OriginPrincipal,
  type PrincipalMappingResolver,
  relationForAction,
  stalenessBoundSeconds,
} from "@mission/pdp";
import {
  buildEffectiveParams,
  buildListEffectiveParams,
  type EffectiveParams,
  type ListEffectiveParams,
  parameterDigest,
} from "./effective-params.js";
import type { EvidenceStore } from "./evidence.js";
import type { PaymentsStore } from "./payments-store.js";
import { signChallenge } from "./txn-challenge.js";
import type { PendingOperation } from "./txn-store.js";

export const CANONICAL_RESOURCE = process.env.MCP_PAYMENTS_RESOURCE ?? "http://localhost:4403/mcp";
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
   * @spec attenuation#mission-binding-check: present when the credential was a
   * Mission-bound Attenuating Agent Token chain. The effective authority is the
   * leaf's narrowed tools, expressed as {resource, actions}; an action within
   * the Mission but outside this leaf is denied `out_of_authority` (below).
   * Absent for an ordinary Mission-bound token (no leaf narrowing).
   */
  leafAuthority?: ReadonlyArray<{ resource: string; actions: readonly string[] }>;
  /**
   * @spec txn-authorization#offline-verification — present when the credential
   * for this request was a transaction token (see {@link TxnCredential}).
   * Absent for every ordinary Mission-bound credential.
   */
  txn?: TxnCredential;
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
 * else runs, and the PDP itself denies `mission_mismatch` on a failed
 * subject/client join, never falling back to an unjoined decision (#557
 * review point 1).
 */
export interface OrdinaryTokenFacts extends CommonTokenFacts {
  mission?: undefined;
  missionClaim?: undefined;
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
  actionClass?: "irreversible_action" | "external_commitment";
  needsInvoice: boolean;
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
}

const TOOL_ACTIONS: Record<string, ActionMapping> = {
  list_invoices: { action: "payments:invoice.list", needsInvoice: false, bindsVendorScope: true },
  get_invoice: { action: "payments:invoice.read", needsInvoice: true },
  lookup_vendor: { action: "payments:vendor.read", needsInvoice: false },
  schedule_payment: { action: "payments:payment.schedule", needsInvoice: true },
  execute_wire_transfer: { action: "payments:payment.execute", actionClass: "irreversible_action", needsInvoice: true },
  send_remittance_email: { action: "payments:remittance.send", actionClass: "external_commitment", needsInvoice: true },
};

/**
 * @spec runtime#read-binding — synthetic FGA check object for a bulk
 * `list_invoices` request under an entry with NO `vendors` constraint at
 * all (entitled to every vendor already). There is no specific vendor to
 * name, and no FGA object type here supports a wildcard check target, so
 * this fixed placeholder stands in for "the entry's own scope, whatever it
 * is" under the same contextual-tuple pattern every other action uses
 * (the injected tuple names exactly the object being checked).
 */
const UNSCOPED_VENDOR_OBJECT = "__unscoped__";

/**
 * @spec runtime#read-binding: the pure normal-form derivation for a bound
 * `list_invoices` read, over the CURRENT matched entry and the caller's
 * (possibly absent) `vendor_id`. Used at decision time (against the entry
 * `enforceInner` just matched) and again at {@link Pep.reverifyList} (against
 * a freshly loaded entry), so a change to the Mission's own authority between
 * those two calls recomputes a DIFFERENT normal form rather than silently
 * repeating the stale one. `requestedVendorId`'s in-scope test mirrors the
 * FGA/entry-constraint check the request goes on to face: a requested vendor
 * that is (no longer) in the entry's `constraints.vendors` normalizes to an
 * EMPTY scope, never to `[requestedVendorId]` regardless of authority.
 */
function deriveVendorScope(
  entry: AuthorityEntry | undefined,
  requestedVendorId: string | undefined,
): { vendor_scope: string[]; vendor_scope_source: "requested" | "entry" | "all" } {
  const allowedVendors = entry?.constraints?.vendors;
  if (requestedVendorId !== undefined) {
    const inScope = !allowedVendors || allowedVendors.includes(requestedVendorId);
    return { vendor_scope: inScope ? [requestedVendorId] : [], vendor_scope_source: "requested" };
  }
  if (allowedVendors) {
    return { vendor_scope: [...allowedVendors].sort(), vendor_scope_source: "entry" };
  }
  return { vendor_scope: [], vendor_scope_source: "all" };
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
const RECOGNIZED_CONDITIONS = new Set(["parameter_digest", "valid_until", "use_limit"]);

/**
 * @spec runtime#state-freshness: a loaded MissionView paired with the
 * authenticated freshness of the read that produced it. `freshness.observed_at`
 * MUST be the time the loader itself read authoritative state, not the time
 * of the `loadView` call that returns it; the two coincide for a synchronous
 * live read (the current production loader) and diverge the moment a cache
 * sits in front of one, in which case the cached observation time travels
 * with the data. The PEP propagates this verbatim; it never stamps its own
 * clock over it (Finding 1).
 */
export interface LoadedView {
  view: MissionView;
  freshness: Freshness;
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
  /**
   * @deprecated The digest this seam carries is `sourceDigestOf`'s whole-
   * server-card hash (#657), not a valid `source_digest` (JCS over one
   * capability's extracted definition). Optional (#657/#730): no longer read
   * for the PDP request envelope (`context.capability_source` was removed
   * there), and a new caller need not supply it. When present, the retained
   * Decision Evidence's `capability_source` coordinated extension member
   * (@spec runtime-evidence#evidence-extensions, issue #649) still carries
   * it, reusing exactly this value; when absent, `capability_source` is
   * simply omitted from that record too (it is itself OPTIONAL there).
   * Removed once #657 PR B replaces it with the real per-action
   * capability-binding resolver. See `sourceDigestOf` below.
   */
  sourceDigest?: string;
  /** Deployment policy: which actions require an action-bound approval (M6). */
  requiresActionApproval?: (action: string, actionClass: string | undefined) => boolean;
  maxApprovalAgeSeconds?: number;
  /**
   * @spec runtime#state-freshness: "A runtime deployment MUST define the
   * Mission state source it trusts for each enforcement scope." The
   * mechanisms this deployment trusts as `context.freshness.source`; forwarded
   * to the PDP's `allowedFreshnessSources` unchanged.
   */
  allowedFreshnessSources?: ReadonlySet<string>;
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
     * request as `context.mission_join.delegate_depth`. Absent (including
     * an absent hook): the PDP treats depth as unbounded, so a
     * `max_depth`-bearing delegate policy or entry denies closed.
     */
    resolveDelegateDepth?: (clientId: string, missionId: string) => number | undefined;
  };
  /** PDP signer + ARS endpoint for requestable denials (M6). */
  requestable?: { sign: import("jose").CryptoKey; kid: string; endpoint: string };
  /**
   * @spec runtime-evidence#decision-evidence-object,
   * runtime#agent-isolated-evidence-emission (#741) — the PDP's Decision
   * Evidence emission path, constructed once at wiring and forwarded to
   * `EvaluateOptions.evidence` unchanged, exactly as `requestable` forwards
   * the PDP's denial-binding signer. This PEP never invokes it: it verifies
   * and retains what comes back on the decision context. Absent, the PDP
   * emits no Decision Evidence and this PEP refuses to release a permitted
   * action rather than executing an unevidenced decision.
   */
  decisionEvidence?: DecisionEvidenceEmitter;
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
   * to. Absent only when the matched entry carries no vendor constraint and
   * the caller requested no `vendor_id` (entitled to, and requesting, every
   * vendor already).
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

export class Pep {
  private readonly now: () => Date;
  constructor(private readonly deps: PepDeps) {
    this.now = deps.now ?? (() => new Date());
  }

  toolAction(tool: string): ActionMapping | undefined {
    return TOOL_ACTIONS[tool];
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
    const mapping = this.toolAction(tool);
    if (!mapping) return await this.refuse(token, "unknown_tool", tool);

    let view: MissionView;
    let freshness: Freshness;
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
        if (!matches) return await this.refuse(token, "mission_reference_conflict", mapping.action);
      }

      const loaded = this.deps.loadView({ id: token.mission.id, issuer: token.mission.issuer });
      if (!loaded) return await this.refuse(token, "unknown_mission", mapping.action);

      // @spec authority-server#reference-verification — the locally loaded
      // Mission view is the PEP's own binding source; a credential whose
      // mission claim names a different issuer than the view it selects is
      // reference sources disagreeing on the canonical (issuer, id) pair,
      // refused as mission_reference_conflict, never resolved by picking one.
      if (loaded.view.issuer !== token.mission.issuer) {
        return await this.refuse(token, "mission_reference_conflict", mapping.action, loaded.view);
      }
      view = loaded.view;
      freshness = loaded.freshness;
      missionAnchor = token.mission;
    } else {
      // @spec authority-server#mission-join (#557): an ordinary credential
      // with no `mission` claim, joined against a PEP-supplied propagated
      // Mission reference (rule 1). ABSENT masJoin config: this deployment
      // claims no MAS-governed route, so refuse exactly as the prior
      // behavior would have (an unrecognized/no-claim credential).
      if (!this.deps.masJoin) return await this.refuse(token, "unknown_mission", mapping.action);

      const propagated = signals?.missionReference;
      if (!propagated || "malformed" in propagated) return await this.refuse(token, "unknown_mission", mapping.action);

      const loaded = this.deps.loadView({ id: propagated.id, issuer: propagated.issuer });
      if (!loaded) return await this.refuse(token, "unknown_mission", mapping.action, undefined, propagated.id);

      // Rule 8, bound 1: the acting credential's OWN authority (a PEP-side
      // deployment hook over TokenFacts, not a PDP concern -- @spec
      // authority-server#mission-join rule 8 note; #557 review point 1
      // moves rules 3-6, the subject/client/delegate join proper, into the
      // PDP below, but rule 8's credential-authority bound stays exactly
      // where it was). No evaluator configured -> fail closed (see
      // PepDeps.masJoin doc): a working Join with no usable permit, never a
      // silently unbounded one.
      const ordinaryAuthority = this.deps.masJoin.resolveOrdinaryAuthority?.(token);
      if (!ordinaryAuthority) return await this.refuse(token, "out_of_authority", mapping.action, loaded.view);
      const boundAuthority = loaded.view.authority_set.filter((e) =>
        ordinaryAuthority.some((o) => o.resource === e.resource && e.actions.every((a) => o.actions.includes(a))),
      );
      if (boundAuthority.length === 0) return await this.refuse(token, "out_of_authority", mapping.action, loaded.view);

      // Rules 3, 4, 5, 6 (subject/client join, delegate narrowing, uniform
      // mission_mismatch with no fallback) are NOT resolved here anymore:
      // `context.mission_join` below tells the PDP to resolve them itself,
      // against this (rule-8-narrowed) view -- the PDP is the party that
      // can verify the credential inputs and tell whether the join actually
      // ran (#557 review point 1).
      view = { ...loaded.view, authority_set: boundAuthority };
      freshness = loaded.freshness;
      missionAnchor = { id: propagated.id, issuer: propagated.issuer };
      isBaselineJoin = true;
      delegateDepth = this.deps.masJoin.resolveDelegateDepth?.(token.clientId, propagated.id);
    }

    // @spec attenuation#mission-binding-check: when the credential is an
    // Attenuating Agent Token chain, the effective authority is the leaf's
    // narrowed tools. An action within the Mission but OUTSIDE the leaf is
    // denied here, reusing the existing out_of_authority DenialReason, before
    // the Mission-level PDP check (which still enforces the Mission and, via
    // view.state, the kill switch). Absent leafAuthority, this is a no-op.
    if (
      token.leafAuthority &&
      !token.leafAuthority.some(
        (e) => e.resource === CANONICAL_RESOURCE && e.actions.includes(mapping.action),
      )
    ) {
      await this.recordRefusal(token, "out_of_authority", mapping.action, view);
      return { permitted: false, denial_reason: "out_of_authority" };
    }

    // Per-instance revocation (M12): refuse if any actor in the chain is
    // revoked, keyed on (act.iss, act.sub). Kills one instance, not the chain.
    if (this.deps.revokedInstances?.size) {
      for (const hop of flattenActChain(token.act)) {
        if (this.deps.revokedInstances.has(`${hop.iss} ${hop.sub}`)) {
          return await this.refuse(token, "instance_revoked", mapping.action, view);
        }
      }
    }

    // Effective parameters from authoritative store state (D34).
    let effective: EffectiveParams | undefined;
    let listEffective: ListEffectiveParams | undefined;
    let listDigest: string | undefined;
    let amount: { amount: string; currency: string } | undefined;
    let resourceObj: EvaluationRequest["resource"] = { type: "server", id: CANONICAL_RESOURCE };
    let listVendorScope: string[] | undefined;
    if (mapping.needsInvoice) {
      const invoiceId = String(args.invoice_id ?? "");
      const invoice = this.deps.payments.getInvoice(invoiceId);
      if (!invoice) return await this.refuse(token, "unknown_invoice", mapping.action, view);
      const vendor = this.deps.payments.getVendor(invoice.vendor_id);
      if (!vendor) return await this.refuse(token, "unknown_vendor", mapping.action, view);
      effective = buildEffectiveParams({ action: mapping.action, invoice, vendor, resource: CANONICAL_RESOURCE });
      amount = effective.amount;
      resourceObj = { type: "invoice", id: invoice.id, properties: { vendor_id: vendor.id } };
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
        (e) => e.resource === CANONICAL_RESOURCE && e.actions.includes(mapping.action),
      );
      const requestedVendorId = args.vendor_id !== undefined ? String(args.vendor_id) : undefined;
      const scope = deriveVendorScope(entry, requestedVendorId);
      listEffective = buildListEffectiveParams({ action: mapping.action, resource: CANONICAL_RESOURCE, ...scope });
      listDigest = parameterDigest(listEffective);
      // The RESULT-SET filter (server.ts's execute()) is a SEPARATE,
      // additional authorization-enforcement control, not the binding itself:
      // "all" (unconstrained entry) filters nothing (undefined = every
      // vendor), the other two sources filter to exactly the normalized scope.
      listVendorScope = scope.vendor_scope_source === "all" ? undefined : scope.vendor_scope;
      if (requestedVendorId !== undefined) {
        // A named vendor_id binds through the SAME vendor-constraint check
        // every invoice-scoped action here uses (out-of-scope -> denied
        // out_of_authority at the FGA step below, same as get_invoice).
        resourceObj = { type: "vendor", id: requestedVendorId, properties: { vendor_id: requestedVendorId } };
      } else if (scope.vendor_scope_source === "entry") {
        // Bulk form, vendor-constrained entry: bind the RESULT SET to the
        // entry's own scope (never the unconstrained store). The set-level
        // authority is the Mission Record's own entry.constraints.vendors,
        // read directly here, not derived from the FGA check below.
        //
        // @spec runtime#read-binding: finding 3 (PR #612 author review), the
        // FGA/PDP request names the FULL collection, not just one
        // representative member: `vendor_ids` carries every vendor this read
        // is about to return, and evaluateInner's step 6a checks each one
        // independently (a denial on ANY member denies the whole read). An
        // empty allowlist still denies, since UNSCOPED_VENDOR_OBJECT names no
        // real vendor. `id`/`vendor_id` still name one representative member
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
      } else {
        // Bulk form, unconstrained entry: already entitled to every vendor,
        // so the read is bound to that full, documented scope, not an
        // accident of the tool's default arguments.
        resourceObj = { type: "vendor", id: UNSCOPED_VENDOR_OBJECT, properties: {} };
      }
    }

    // @spec authzen#context-actor: the actor chain this request presents,
    // built once and evaluated by the PDP, which is also what carries onto
    // the Decision Evidence the PDP emits (#741). `capability_source` is not
    // built here at all: the member left the decision request envelope with
    // #657/#730, so no validated PDP-side input carries it, and a PEP-supplied
    // copy would be caller-asserted record content (@spec
    // runtime#agent-isolated-evidence-emission). It is OPTIONAL, so the record
    // omits it until #657's per-action capability-binding resolver supplies it
    // from the PDP's own verified inputs.
    const contextActor = buildContextActor({
      ...(token.clientId !== undefined ? { clientId: token.clientId } : {}),
      ...(token.clientInstanceId !== undefined ? { clientInstanceId: token.clientInstanceId } : {}),
      ...(token.act !== undefined ? { act: token.act } : {}),
    });

    const req: EvaluationRequest = {
      // @spec authzen#pdp-request rule 10 — `subject.properties.iss` is this
      // resource's own verified issuer identity, carried on TokenFacts by
      // the token validator that authenticated this request, never anything
      // client-supplied.
      subject: { id: token.sub, ...(token.iss !== undefined ? { properties: { iss: token.iss } } : {}) },
      resource: resourceObj,
      action: { name: mapping.action },
      context: {
        audience: CANONICAL_RESOURCE,
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
        // @spec runtime#state-freshness: `freshness` is the loader's OWN
        // assertion of when it read authoritative state, propagated exactly
        // as `loadView` returned it. The PEP never stamps its own clock here
        // (Finding 1): doing so would relabel a cached or relayed
        // observation as fresh at the moment it happened to be consumed,
        // rather than at the moment it was actually read. Supplying it keeps
        // a high-consequence action class (irreversible_action,
        // external_commitment) from being denied `stale_state` merely for
        // omitting the member (the PDP's #608 GAP 2 fail-closed fix).
        freshness,
        actor: contextActor,
        // `context.capability_source` intentionally absent (#657): see
        // `sourceDigestOf` below for what stood here and why it was removed
        // from the PDP-facing request envelope. The retained Decision
        // Evidence below still carries `capability_source` (a coordinated
        // extension member of the signed record, @spec
        // runtime-evidence#evidence-extensions), reusing `capabilitySource`
        // computed above -- that is a distinct, evidentiary use, not a
        // second copy of what this request envelope presents to the PDP.
        ...(effective ? { parameter_digest: parameterDigest(effective) } : {}),
        ...(listDigest ? { parameter_digest: listDigest } : {}),
        ...(amount ? { amount } : {}),
        ...(mapping.actionClass ? { action_class: mapping.actionClass } : {}),
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

    const decision = await evaluate(req, {
      view,
      fga: this.deps.fga,
      modelId: this.deps.modelId,
      now: this.now,
      stalenessBoundSeconds,
      relationForAction,
      ...(this.deps.requiresActionApproval ? { requiresActionApproval: this.deps.requiresActionApproval } : {}),
      ...(this.deps.maxApprovalAgeSeconds ? { maxApprovalAgeSeconds: this.deps.maxApprovalAgeSeconds } : {}),
      ...(this.deps.requestable ? { requestable: this.deps.requestable } : {}),
      // @spec runtime-evidence#decision-evidence-object (#741): the PDP
      // signs the record it emits; this PEP holds no key that could.
      ...(this.deps.decisionEvidence ? { evidence: this.deps.decisionEvidence } : {}),
      ...(this.deps.allowedFreshnessSources ? { allowedFreshnessSources: this.deps.allowedFreshnessSources } : {}),
      ...(this.deps.principalMapping ? { principalMapping: this.deps.principalMapping } : {}),
      ...(this.deps.entitlement ? { entitlement: this.deps.entitlement } : {}),
      ...(this.deps.entitlementStalenessBoundSeconds !== undefined
        ? { entitlementStalenessBoundSeconds: this.deps.entitlementStalenessBoundSeconds }
        : {}),
      // @spec authority-server#mission-join rule 4 (#557 review point 1) —
      // forwarded to the PDP unchanged; consulted only when this request
      // carries `context.mission_join` above.
      ...(this.deps.masJoin?.delegatePolicy !== undefined ? { delegatePolicy: this.deps.masJoin.delegatePolicy } : {}),
    });

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
    const retention = emitted
      ? await this.deps.evidence.retainDecision(emitted)
      : ({ retained: false, reason: "absent" } as const);
    if (!retention.retained && decision.decision) {
      // Fail closed on a permit: an action whose decision left no verifiable
      // Decision Evidence is refused rather than executed. A denial keeps its
      // own denial reason, which is the more useful one, and denies either way.
      return this.refuse(token, "decision_evidence_unverifiable", mapping.action, view);
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
        // scoped to the operation being approved, not the whole entry.
        const requested = view.authority_set
          .filter((e) => e.resource === CANONICAL_RESOURCE && e.actions.includes(mapping.action))
          .map((e) => ({ ...e, actions: [mapping.action] })) as unknown as JsonValue[];
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
      // (deriveContextualTuples/FGA can also return out_of_authority when the
      // entry exists but the specific object is excluded) -- propose the
      // missing entry back. Deliberately NOT emitted for authority_contained:
      // that is the family's monotonic trust ratchet (@spec containment);
      // handing back "here's how to ask again" for a deliberately narrowed
      // capability would contradict restore-only-via-Expansion.
      if (
        decision.context.denial_reason === "out_of_authority" &&
        !view.authority_set.some((e) => e.resource === CANONICAL_RESOURCE && e.actions.includes(mapping.action))
      ) {
        result.insufficient_authorization = buildInsufficientAuthorization([
          { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: [mapping.action] },
        ]);
      }
      return result;
    }

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
    const unrecognizedConditions = conditions
      ? Object.keys(conditions).filter((k) => !RECOGNIZED_CONDITIONS.has(k))
      : [];
    if (unrecognizedConditions.length > 0) {
      await this.recordRefusal(token, "unrecognized_condition", mapping.action, view);
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
      await this.recordRefusal(token, "unfulfillable_obligation", mapping.action, view);
      return { permitted: false, refusal_reason: "unfulfillable_obligation" };
    }

    return {
      permitted: true,
      decision,
      resolvedMission: {
        id: missionAnchor.id,
        issuer: missionAnchor.issuer,
        ...(missionAnchor.authority_hash !== undefined ? { authority_hash: missionAnchor.authority_hash } : {}),
      },
      ...(effective ? { effective } : {}),
      ...(listEffective ? { listEffective } : {}),
      ...(listVendorScope ? { list_vendor_scope: listVendorScope } : {}),
    };
  }

  /**
   * @spec operation-profile (parameter binding / TOCTOU): re-verify the
   * effective parameters immediately before execution. A digest mismatch
   * (record changed under us) is a refusal, not an execution.
   */
  async reverify(effective: EffectiveParams, expectedDigest: string, token: TokenFacts): Promise<boolean> {
    const invoice = this.deps.payments.getInvoice(effective.invoice_id);
    const vendor = invoice ? this.deps.payments.getVendor(invoice.vendor_id) : undefined;
    if (!invoice || !vendor) {
      await this.recordRefusal(token, "parameter_mismatch", effective.action);
      return false;
    }
    const fresh = buildEffectiveParams({ action: effective.action, invoice, vendor, resource: effective.resource });
    if (parameterDigest(fresh) !== expectedDigest) {
      await this.recordRefusal(token, "parameter_mismatch", effective.action);
      return false;
    }
    return true;
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
  async reverifyList(effective: ListEffectiveParams, expectedDigest: string, token: TokenFacts): Promise<boolean> {
    // @spec authority-server#mission-join (#557): the baseline-Join gateway
    // path is not wired into read-binding reverification (a documented
    // remainder -- doing so needs the resolved Mission anchor threaded back
    // through the caller's post-decision call, which this PR does not
    // build). Fails closed rather than dereferencing an absent claim.
    if (!token.mission) {
      await this.recordRefusal(token, "parameter_mismatch", effective.action);
      return false;
    }
    const loaded = loadCheckedView(this.deps.loadView, { id: token.mission.id, issuer: token.mission.issuer });
    const entry = loaded?.view.authority_set.find(
      (e) => e.resource === effective.resource && e.actions.includes(effective.action),
    );
    const requestedVendorId =
      effective.vendor_scope_source === "requested" ? effective.vendor_scope[0] : undefined;
    const fresh = buildListEffectiveParams({
      action: effective.action,
      resource: effective.resource,
      ...deriveVendorScope(entry, requestedVendorId),
    });
    if (parameterDigest(fresh) !== expectedDigest) {
      await this.recordRefusal(token, "parameter_mismatch", effective.action);
      return false;
    }
    return true;
  }

  private async refuse(
    token: TokenFacts,
    reason: string,
    action: string,
    view?: MissionView,
    missionIdOverride?: string,
  ): Promise<EnforceResult> {
    await this.recordRefusal(token, reason, action, view, missionIdOverride);
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
   */
  private async recordRefusal(
    token: TokenFacts,
    reason: string,
    action: string,
    view?: MissionView,
    missionIdOverride?: string,
  ): Promise<void> {
    const missionId = view?.id ?? token.mission?.id ?? missionIdOverride ?? "unknown";
    await this.deps.evidence.recordRefusal(CANONICAL_RESOURCE, "pep", {
      missionId,
      audience: CANONICAL_RESOURCE,
      action: { name: action },
      denial_reason: reason,
      subject: { id: token.sub, ...(token.iss !== undefined ? { properties: { iss: token.iss } } : {}) },
      ...(view !== undefined
        ? { mission: { id: view.id, issuer: view.issuer, authority_hash: view.authority_hash } }
        : {}),
    });
  }
}

/**
 * Vestigial (#657): hashes the whole `serverCard` via ordinary
 * `JSON.stringify`, not a JCS-canonical digest over one capability's
 * extracted definition, which is what the capability-binding draft's
 * `source_digest` requires. Not a valid `catalog_digest` either, since
 * parsing and reserializing `serverCard` loses the exact retrieved octets
 * that member requires. Formerly attached to every enforced tool call as
 * `context.capability_source`; removed from the PDP request envelope
 * entirely (`enforceInner` presents no such member there, and no PDP here
 * ever typed or verified one) because presenting the wrong bytes read as
 * coverage this deployment did not have. Still feeds the retained Decision
 * Evidence's own `capability_source` (issue #649: a non-authoritative,
 * OPTIONAL coordinated extension member of the signed record, never
 * something the PDP evaluated) alongside existing tests, the demo stack,
 * and the eval harness, which still construct `PepDeps.sourceDigest` with
 * it; all three drop it once #657 PR A/B land the real per-action binding.
 *
 * @deprecated Do not add new callers. Tracked for removal in #657 PR B.
 */
export function sourceDigestOf(serverCard: unknown): string {
  return `sha-256:${createHash("sha256").update(JSON.stringify(serverCard), "utf8").digest("base64url")}`;
}

export { TOOL_ACTIONS };
