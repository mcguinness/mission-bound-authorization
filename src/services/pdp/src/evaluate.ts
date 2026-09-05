/**
 * @spec authzen#pdp-request (envelope binding, context.audience rule)
 * @spec authzen#denial-response, authzen#runtime-denial-classification
 * @spec runtime (abstract decision contract)
 *
 * The stateless PDP decision function (D28): a pure function of the envelope,
 * the loaded MissionView, the FGA authority check, the clock, and freshness
 * inputs. Permit properties are declared; the PEP owns redemption state.
 */

import { type ContextActor, validateContextActor } from "@mission/actor-chain";
import {
  AUTHORITY_ENTRY_TYP,
  compareAmounts,
  computeAnchor,
  type EntitlementObservation,
  entitlementPermits,
  type EntitlementResolver,
  isValidAmount,
  MISSION_ORIGIN_SUBJECT_TYP,
  type OriginPrincipal,
  type PrincipalMappingObservation,
  type PrincipalMappingResolver,
} from "@mission/core";
import { getTracer } from "@mission/telemetry";
import { SignJWT, type CryptoKey } from "jose";
import type {
  DecisionEvidenceEmitter,
  DecisionEvidenceObject,
  RuntimeActionClass,
  RuntimeConditions,
  RuntimePrincipalMapping,
  RuntimeCapabilitySource,
} from "./decision-evidence.js";
import { runtimeCapabilitySourceOf } from "./decision-evidence.js";
import type { Fga } from "./fga.js";
import { type DelegatePolicy, resolveBaselineJoin } from "./mas-join.js";
import {
  type AuthorityEntry,
  deriveContextualTuples,
  joinViewId,
  MISSION_RESOURCE_ACCESS_TYPE,
  type MissionView,
  policyViewId,
} from "./policy-view.js";

export type { EntitlementObservation, EntitlementResolver, OriginPrincipal, PrincipalMappingObservation, PrincipalMappingResolver } from "@mission/core";

/**
 * @spec runtime#classification — the high-consequence classes (a closed
 * set the draft defines by predicate: irreversible, external-commitment,
 * privileged-administration). @spec runtime#state-freshness — these are
 * the classes for which "the state source MUST be an active freshness
 * mechanism", never token-lifetime expiry alone; below this floor, token
 * expiry is itself a conforming state source, so absence of
 * `context.freshness` is not by itself a fail-closed signal there.
 */
const HIGH_CONSEQUENCE_ACTION_CLASSES = new Set(["irreversible_action", "external_commitment", "privileged_administration"]);

/**
 * @spec runtime#state-freshness: the default allowed future skew for
 * `observed_at`, seconds. Small enough to absorb ordinary clock drift
 * between a state source and the PDP without meaningfully widening even the
 * tightest published staleness bound (30s for irreversible_action);
 * configurable per deployment via `EvaluateOptions.freshnessSkewToleranceSeconds`.
 */
const DEFAULT_FRESHNESS_SKEW_TOLERANCE_SECONDS = 5;

/** @spec authzen#context-approval */
export interface ActionApproval {
  id: string;
  approved_at: string;
  /** ARAP: the approval's validity bound; the PDP refuses once now > this. */
  approved_until?: string;
  parameter_digest: string;
  state?: string;
}

/**
 * @spec runtime#state-freshness: a Mission state observation, asserted by
 * whichever state source produced it (a status call, introspection, a
 * Lifecycle Signal, or a loader's own live read). `observed_at` MUST be the
 * time the source actually read authoritative state, never the time a later
 * consumer happened to use the observation; that is what keeps a cached or
 * relayed observation honestly stale instead of relabeled fresh at
 * consumption (Finding 1). `source` names the mechanism, checked against the
 * deployment's configured set (below).
 */
export interface Freshness {
  observed_at: string;
  source: string;
}

export interface EvaluationRequest {
  subject: {
    id: string;
    type?: string;
    /**
     * @spec authzen#pdp-request rule 10 — `subject.properties.iss` describes
     * the authenticated destination-local token subject's home issuer,
     * consulted only for a request claiming the cross-domain Origin
     * Principal profile (`context.mission.subject` present). Absent there,
     * the PDP cannot represent an issuer-qualified local subject and denies
     * `principal_mapping_failed`, never falls back to a bare `sub`
     * comparison.
     */
    properties?: { iss?: string };
  };
  /**
   * Fine-grained target object (Resource-policy only), NOT the entry match.
   * `vendor_ids`, when present, names the FULL collection a bound bulk read
   * resolves to (@spec runtime#read-binding): `id`/`vendor_id` above still
   * name one REPRESENTATIVE member (so every existing single-object caller
   * is unaffected), but Resource policy is checked against EVERY member of
   * `vendor_ids`, not just the representative one (see evaluateInner's
   * step 6a).
   */
  resource: { type: string; id: string; properties?: { vendor_id?: string; vendor_ids?: string[] } };
  action: { name: string };
  context: {
    audience: string; // matched against the approved entry's resource
    mission: {
      id: string;
      issuer: string;
      /**
       * @spec mission#the-mission-claim, authzen#context-mission (#702) —
       * NOT part of the baseline `mission` claim; carried only where a
       * companion profile or the PEP's own view adds it. When present, rule
       * 1 below checks it for strict equality against the loaded view;
       * absence is never itself a denial (authzen#pdp-request rule 5).
       */
      authority_hash?: string;
      policy_view_id?: string;
      /**
       * @spec cross-domain#mission-subject, authzen#pdp-request rule 10 —
       * the immutable origin principal, REQUIRED for a request claiming the
       * cross-domain Origin Principal profile and OPTIONAL otherwise. The
       * PEP populates it only from a verified token or delegation chain,
       * never from an unverified request value (@spec authzen#context-mission).
       */
      subject?: OriginPrincipal;
    };
    actor?: ContextActor;
    capability_source?: RuntimeCapabilitySource;
    freshness?: Freshness;
    parameter_digest?: string;
    amount?: { amount: string; currency: string };
    action_class?: string;
    action_approval?: ActionApproval;
    /**
     * @spec authority-server#mission-join (#557 review point 1) — present
     * EXACTLY on the baseline-Join path: an ordinary credential carrying no
     * `mission` claim, joined against a PEP-supplied propagated Mission
     * reference. Its presence is what tells the PDP to run rules 3-6 (the
     * subject/client/delegate join) itself, resolved here against the
     * already-authenticated `subject`/`context.actor.client_id` this
     * envelope already carries, rather than trusting a pre-narrowed
     * `MissionView` a PEP helper resolved outside the PDP's view: "the spec
     * assigns the subject/client/delegate join to the PDP... the PDP cannot
     * verify the authenticated credential inputs or tell whether the join
     * occurred" otherwise. Absent on every ordinary Mission-bound request;
     * this whole step is then a complete no-op, byte-for-byte unchanged.
     */
    mission_join?: {
      /**
       * @spec authority-server#mission-join rule 5 — the deployment's own
       * currently-recorded actor depth for `context.actor.client_id` under
       * this Mission, a REQUEST fact the PEP resolves fresh and carries
       * here (never looked up by the PDP from static configuration, and
       * never read from a token's own `act` chain). Absent is unbounded
       * depth: a `max_depth`-bearing delegate policy or entry denies
       * closed, never assumes a shallow default.
       */
      delegate_depth?: number;
    };
  };
}

export type DenialReason =
  | "capability_drift"
  | "out_of_authority"
  | "authority_contained"
  /**
   * @spec discharge#runtime, runtime#input-authority — the entry was approved and
   * its `terminal_when` completion condition has FIRED, so the Mission Issuer
   * discharged it: the task it was granted for is done. Distinct from
   * `authority_contained` (trust lost) and from `out_of_authority` (never
   * approved), and never expansion-eligible in the containment sense: a
   * discharged entry retired itself.
   */
  | "authority_discharged"
  | "stale_state"
  | "view_inconsistent"
  | "mission_inactive"
  | "actor_invalid"
  | "constraint_exceeded"
  | "action_approval_required"
  | "unsupported_authorization_type"
  /**
   * @spec cross-domain#dual-axis, authzen#pdp-request rule 10 — the
   * cross-domain Origin Principal profile's registered extension reason: a
   * failed, missing, ambiguous, or stale mapping from `context.mission.subject`
   * to the authenticated local subject, or a failed, missing, or stale
   * current-entitlement result for the mapped principal. One reason covers
   * every sub-cause of either step; the profile does not distinguish them at
   * the enforcement point.
   */
  | "principal_mapping_failed"
  /**
   * @spec authority-server#mission-join rule 6 (#557) — the baseline MAS
   * Join's uniform denial: "A failure of the subject or client join MUST be
   * denied with the `mission_mismatch` denial reason ... The PDP MUST NOT
   * fall back to evaluating the action against the referenced Mission's
   * authority when the join fails." Distinct from the bare string
   * `"mission_mismatch"` used in two unrelated enums elsewhere in this tree
   * (authorization-server/src/adapters/provider.ts's Protected Events
   * rejection, and mcp-payments/src/server.ts's `"txn_mission_mismatch"`
   * transaction-authorization refusal): neither is this `DenialReason`.
   */
  | "mission_mismatch";

export interface Decision {
  decision: boolean;
  context: Record<string, unknown>;
}

export interface EvaluateOptions {
  view: MissionView;
  fga: Fga;
  modelId: string;
  now: () => Date;
  /** Published staleness bound per action class, seconds. */
  stalenessBoundSeconds: (actionClass: string | undefined) => number;
  /** Map an action name to the FGA relation and object type it needs. */
  relationForAction: (action: string) => { relation: "payer" | "reader"; needsAmount: boolean } | null;
  /** Deployment/Resource policy: does this action require an action-bound approval? */
  requiresActionApproval?: (action: string, actionClass: string | undefined) => boolean;
  /** Max approval age (seconds) the PDP enforces on context.action_approval. */
  maxApprovalAgeSeconds?: number;
  /** For requestable denials: sign the PDP denial binding + the ARS endpoint. */
  requestable?: { sign: CryptoKey; kid: string; endpoint: string };
  /**
   * @spec runtime-evidence#decision-evidence-object,
   * runtime#agent-isolated-evidence-emission (#741) — the PDP's own Decision
   * Evidence emission path: {@link evaluate} builds the record from the
   * decision it just reached and signs it here, then returns the complete
   * signed object at `context.decision_evidence`. Injected once at wiring,
   * the same way `requestable` carries the PDP's denial-binding signer.
   *
   * There is deliberately no seam here for a caller to supply the record,
   * the emitter identity, the decision, or the sequence position: the
   * emitter owns all four. Absent, no Decision Evidence is emitted and a
   * PEP that requires it refuses the action rather than executing an
   * unevidenced decision.
   */
  evidence?: DecisionEvidenceEmitter;
  /**
   * @spec runtime#state-freshness: "A runtime deployment MUST define the
   * Mission state source it trusts for each enforcement scope." A presented
   * `context.freshness.source` outside this set is untrusted, denied the
   * same way as a stale or malformed observation. Omitting this option
   * denies every presented freshness: absent a declared set, no source is
   * trusted, never the reverse (fail closed on missing config, not open).
   */
  allowedFreshnessSources?: ReadonlySet<string>;
  /**
   * @spec runtime#state-freshness: allowed future clock skew for
   * `observed_at`, seconds (default `DEFAULT_FRESHNESS_SKEW_TOLERANCE_SECONDS`).
   * Beyond this, a future-dated observation denies rather than passing
   * through on the negative age it produces.
   */
  freshnessSkewToleranceSeconds?: number;
  /**
   * @spec cross-domain#origin-principal-mapping, authzen#pdp-request rule 10
   * — resolves `context.mission.subject` to a destination-local mapping for
   * a request claiming the cross-domain Origin Principal profile ("The PDP
   * is authoritative for the mapping in the default placement"). Absent,
   * the same fail-closed-on-unconfigured idiom as `allowedFreshnessSources`
   * applies: every request claiming the profile denies `principal_mapping_failed`;
   * a deployment not claiming the profile never sets `context.mission.subject`,
   * so it is unaffected either way.
   */
  principalMapping?: PrincipalMappingResolver;
  /**
   * @spec cross-domain#dual-axis — resolves current entitlement for the
   * mapped local principal. Absent fails closed the same way as a missing
   * `principalMapping`.
   */
  entitlement?: EntitlementResolver;
  /**
   * @spec cross-domain#dual-axis: "a deployment claiming this profile MUST
   * declare the source and maximum staleness of local principal entitlement,
   * separately from its Mission-state freshness declaration." Seconds;
   * deliberately its own option, never collapsed into `stalenessBoundSeconds`
   * (Mission-state freshness) or the mapping's own `valid_until`. Absent
   * fails every cross-domain-profile request closed.
   */
  entitlementStalenessBoundSeconds?: number;
  /**
   * @spec authority-server#mission-join rule 4 (#557) — the deployment's
   * static delegate ceiling: which client ids may join as a delegate, and
   * each one's own maxDepth. Consulted only when the request carries
   * `context.mission_join` (the baseline-Join path); absent there, no
   * delegate is authorized (rule 4's "never a default", the same
   * fail-closed-on-unconfigured idiom as `allowedFreshnessSources`).
   */
  delegatePolicy?: DelegatePolicy;
}

/**
 * @spec runtime-evidence#decision-evidence-object,
 * runtime#agent-isolated-evidence-emission (#741, PR #753 review) — the
 * decision options a component OUTSIDE the PDP's emission boundary supplies:
 * everything {@link evaluate} needs except {@link EvaluateOptions.evidence}.
 * The emission path is bound at PDP construction
 * (`createDecisionPoint`, {@link ./decision-point.js}) and never travels
 * through a caller's options object: an enforcement component that could put
 * an emitter there holds the capability to have an arbitrary record signed
 * under the decision point's identity, which is the defect this split closes.
 */
export type DecisionOptions = Omit<EvaluateOptions, "evidence">;

/**
 * The PDP's decision entry point as an enforcement component sees it: submit
 * the evaluation request, receive the decision, with the PDP-built, PDP-signed
 * record at `context.decision_evidence` when the decision point behind it
 * emits one. This is the ONLY decision-side capability a PEP holds; it can ask
 * for a decision, and it can verify and retain what comes back, but it cannot
 * emit.
 *
 * The in-process implementation applies the caller's {@link DecisionOptions}
 * (the Mission view, the FGA client, the deployment's policy hooks) to
 * {@link evaluate}. A remote wrapper ignores them: the PDP server resolves its
 * own options on its side of the channel.
 */
export type DecisionFn = (req: EvaluationRequest, opts: DecisionOptions) => Promise<Decision>;

let decisionCounter = 0;
function newDecisionId(): string {
  decisionCounter += 1;
  return `dec_${decisionCounter}_${Math.floor(performance.now())}`;
}

export async function evaluate(req: EvaluationRequest, opts: EvaluateOptions): Promise<Decision> {
  return getTracer("pdp").startActiveSpan("pdp.evaluate", async (span) => {
    try {
      const decision = await evaluateInner(req, opts);
      span.setAttribute("mission.action", req.action.name);
      span.setAttribute("mission.decision", decision.decision);
      if (decision.context.denial_reason) {
        span.setAttribute("mission.denial_reason", String(decision.context.denial_reason));
      }
      if (opts.evidence) {
        decision.context.decision_evidence = await emitDecisionEvidence(req, opts, opts.evidence, decision);
      }
      return decision;
    } finally {
      span.end();
    }
  });
}

/**
 * @spec runtime-evidence#decision-evidence-object, #decision-evidence-integrity;
 * runtime#agent-isolated-evidence-emission (#741) — build and sign the
 * Decision Evidence for the decision just reached, and return the complete
 * signed object for carriage at `context.decision_evidence`.
 *
 * Every member comes from this evaluation's own state: the request envelope
 * the PDP validated, the Mission view it decided against, and the decision
 * context it just produced. Carriage does not change treatment: the record
 * is retrospective evidence of what the PDP decided, never authorization to
 * act (@spec authzen#permit-binding-split).
 */
async function emitDecisionEvidence(
  req: EvaluationRequest,
  opts: EvaluateOptions,
  emitter: DecisionEvidenceEmitter,
  decision: Decision,
): Promise<DecisionEvidenceObject> {
  const { view } = opts;
  // @spec cross-domain#origin-principal-mapping, runtime-evidence#principal_mapping,
  // runtime-evidence#evidence-pii — the decision context carries the RAW
  // origin/local {iss, sub} pairs (an ephemeral, in-process decision
  // contract); the SIGNED record must not. The PDP composed those pairs, so
  // the PDP is what anchors them (the family anchor idiom, typ
  // mission-origin-subject) before they are signed into a retained record.
  const raw = decision.context.principal_mapping as
    | {
        origin: OriginPrincipal;
        local: OriginPrincipal;
        policy: { id: string; version: string };
        observed_at: string;
        valid_until: string;
      }
    | undefined;
  const principal_mapping: RuntimePrincipalMapping | undefined = raw
    ? {
        origin: computeAnchor(MISSION_ORIGIN_SUBJECT_TYP, view.issuer, raw.origin as never),
        local: computeAnchor(MISSION_ORIGIN_SUBJECT_TYP, view.issuer, raw.local as never),
        policy: raw.policy,
        observed_at: raw.observed_at,
        valid_until: raw.valid_until,
      }
    : undefined;
  const capability_source = runtimeCapabilitySourceOf(req.context.capability_source);
  return emitter.emit({
    ...(capability_source ? { capability_source } : {}),
    mission: {
      id: view.id,
      issuer: view.issuer,
      policy_view_id: decision.context.policy_view_id as string,
      authority_hash: view.authority_hash,
    },
    subject: {
      id: req.subject.id,
      ...(req.subject.properties?.iss !== undefined ? { properties: { iss: req.subject.properties.iss } } : {}),
    },
    resource: { type: req.resource.type, id: req.resource.id },
    action: { name: req.action.name },
    audience: req.context.audience,
    evaluation_id: decision.context.evaluation_id as string,
    decision: decision.decision ? "permit" : "deny",
    evaluated_at: opts.now().toISOString(),
    ...(req.context.action_class !== undefined
      ? { action_class: req.context.action_class as RuntimeActionClass }
      : {}),
    ...(req.context.actor !== undefined ? { actor: req.context.actor } : {}),
    ...(principal_mapping !== undefined ? { principal_mapping } : {}),
    ...(req.context.parameter_digest !== undefined ? { parameter_digest: req.context.parameter_digest } : {}),
    ...(decision.context.conditions !== undefined
      ? { conditions: decision.context.conditions as RuntimeConditions }
      : {}),
    ...(decision.context.denial_reason !== undefined
      ? { denial_reason: decision.context.denial_reason as string }
      : {}),
    ...(decision.context.entry_digest !== undefined
      ? { entry_digest: decision.context.entry_digest as string }
      : {}),
  });
}

async function evaluateInner(req: EvaluationRequest, opts: EvaluateOptions): Promise<Decision> {
  const { view, fga, modelId, now } = opts;
  const pvid = policyViewId(view, modelId);
  const actionClass = req.context.action_class;
  const decisionId = newDecisionId();
  // @spec cross-domain#origin-principal-mapping, runtime-evidence#principal_mapping
  // — set once step 4a below validates the mapping (before entitlement lookup,
  // so it is present on an entitlement-caused principal_mapping_failed denial
  // too, per "recorded on Decision Evidence and Refusal Records"). Declared
  // here, ahead of `base`, so every earlier `deny()` (steps 1-3) closes over
  // the same binding without a temporal-dead-zone reference.
  let principalMapping: PrincipalMappingObservation | undefined;
  // @spec authority-server#mission-join (#557 review point 1) — set once
  // step 4b below resolves the baseline Join, so `join_view_id` (below) is
  // present on the SAME decision's Decision Evidence/Refusal Record
  // regardless of which later step denies. Declared here, ahead of `base`,
  // for the same temporal-dead-zone reason `principalMapping` is.
  let joinedAuthority: { disposition: "direct" | "delegate"; clientId: string; authoritySet: AuthorityEntry[] } | undefined;
  // @spec authzen#response-context: `evaluation_id` is the profile's own
  // REQUIRED correlation identifier (ARAP's `evaluation_id`), additive
  // alongside the pre-existing `decision_id` deployment metadata (still load-
  // bearing as the permit id downstream: server.ts's redeemPermit/
  // operationKey). Both carry the SAME value; this is a carriage addition,
  // never a rename.
  const base = (extra: Record<string, unknown>) => ({
    decision_id: decisionId,
    evaluation_id: decisionId,
    policy_view_id: pvid,
    // @spec authority-server#mission-join (#557 review point 4) — a SEPARATE
    // commitment for a baseline-Join decision, additive alongside
    // policy_view_id (never replacing it): distinguishes a joined decision
    // from a direct Mission-bound one, and one joined view (a given
    // subject/client/delegate-narrowed authority set) from another.
    ...(joinedAuthority ? { join_view_id: joinViewId(view, modelId, joinedAuthority) } : {}),
    ...(actionClass ? { action_class: actionClass, class_source: "deployment" } : {}),
    ...(principalMapping
      ? {
          principal_mapping: {
            origin: req.context.mission.subject,
            local: principalMapping.local,
            policy: principalMapping.policy,
            observed_at: principalMapping.observed_at,
            valid_until: principalMapping.valid_until,
          },
        }
      : {}),
    ...extra,
  });
  // @spec authzen#response-context: `reason` is the profile's own response
  // member for the denial classification; `denial_reason` (the pre-existing
  // deployment field, also the Decision Evidence member name per
  // authzen#failure-condition-coverage) is kept alongside it, additive.
  const deny = (denial_reason: DenialReason): Decision => ({
    decision: false,
    context: base({ denial_reason, reason: denial_reason }),
  });

  // 1. View consistency (@spec: view_inconsistent). `id`/`issuer` are the
  // mandatory identity check; `authority_hash` and `policy_view_id` (#702:
  // authority_hash is no longer on the baseline claim) are present-then-check
  // — a caller that supplies either MUST match, but neither's absence is
  // itself a denial (@spec authzen#pdp-request rule 5).
  if (
    req.context.mission.id !== view.id ||
    req.context.mission.issuer !== view.issuer ||
    (req.context.mission.authority_hash !== undefined &&
      req.context.mission.authority_hash !== view.authority_hash) ||
    (req.context.mission.policy_view_id !== undefined && req.context.mission.policy_view_id !== pvid)
  ) {
    return deny("view_inconsistent");
  }

  // 2. Mission state (@spec: mission_inactive).
  if (view.state !== "active") return deny("mission_inactive");

  // 3. Freshness against the staleness bound (@spec: stale_state).
  // @spec runtime#state-freshness: "The PDP MUST refuse a consequential
  // action when it cannot establish, within the deployment's published
  // staleness bound, that the Mission is `active`." An absent
  // `context.freshness` on a high-consequence action class means Mission
  // state cannot be established at all, which is not weaker than state
  // established-but-stale: it MUST fail closed the same way, never pass
  // through as if no staleness bound applied. Below the high-consequence
  // floor the draft treats token-lifetime expiry as itself a conforming
  // state source, so an absent member there is not by itself a refusal.
  const skewToleranceMs = (opts.freshnessSkewToleranceSeconds ?? DEFAULT_FRESHNESS_SKEW_TOLERANCE_SECONDS) * 1000;
  if (req.context.freshness) {
    const observedAtMs = Date.parse(req.context.freshness.observed_at);
    const ageMs = now().getTime() - observedAtMs;
    const sourceTrusted = opts.allowedFreshnessSources?.has(req.context.freshness.source) ?? false;
    // A malformed timestamp (non-finite), one dated far enough in the future
    // to be fabricated rather than ordinary clock drift, or a source outside
    // the deployment's declared set: none of these let the PDP actually
    // establish Mission state from this observation, so each denies the same
    // way as present-but-stale (@spec runtime#state-freshness, "cannot
    // establish ... within the staleness bound"), never permits on an
    // unverifiable input.
    if (
      !Number.isFinite(observedAtMs) ||
      ageMs < -skewToleranceMs ||
      ageMs > opts.stalenessBoundSeconds(actionClass) * 1000 ||
      !sourceTrusted
    ) {
      return deny("stale_state");
    }
  } else if (actionClass !== undefined && HIGH_CONSEQUENCE_ACTION_CLASSES.has(actionClass)) {
    return deny("stale_state");
  }

  // 4. Actor chain shape/consistency (@spec: actor_invalid).
  if (req.context.actor) {
    try {
      validateContextActor(req.context.actor, { subject: req.subject.id });
    } catch {
      return deny("actor_invalid");
    }
  }

  // 4a. Cross-domain Origin Principal dual-axis mapping and entitlement
  // (@spec cross-domain#dual-axis, authzen#pdp-request rule 10). Applies
  // only to a request claiming the profile (`context.mission.subject`
  // present); a deployment not claiming it is completely unaffected, this
  // block never partially runs. Runs before the authority-entry match: WHO
  // the mapped local principal is gates WHAT they can do, not the reverse.
  if (req.context.mission.subject) {
    const origin: OriginPrincipal = req.context.mission.subject;
    const localIss = req.subject.properties?.iss;

    // @spec cross-domain#origin-principal-mapping — "The PDP is
    // authoritative for the mapping in the default placement." A missing
    // resolver, a missing/ambiguous/disabled mapping (`resolve` returns
    // undefined), a mapping stale beyond its OWN `valid_until`, or a mapped
    // local principal that does not equal the authenticated request subject
    // (rule 10's `require mapped_subject == (subject.properties.iss,
    // subject.id)`) are all "a failed ... result" at this step: one
    // classification, no bypass on any sub-cause. A network/store failure
    // inside the resolver is the SAME kind of failed result, not a distinct
    // authorization outcome or an unclassified transport exception (#686
    // review): caught here and normalized to the identical denial, so it
    // takes the ordinary evidence path rather than escaping evaluate().
    let mappingResult: PrincipalMappingObservation | undefined;
    try {
      mappingResult = await opts.principalMapping?.resolve({ origin, audience: req.context.audience });
    } catch {
      mappingResult = undefined;
    }
    // The explicit undefined check (rather than folding it into
    // `mappingEstablished` below) is also what lets TypeScript narrow
    // `mappingResult` for every use after this point.
    if (mappingResult === undefined) return deny("principal_mapping_failed");
    const validUntilMs = Date.parse(mappingResult.valid_until);
    const mappingEstablished =
      Number.isFinite(validUntilMs) &&
      now().getTime() <= validUntilMs &&
      localIss !== undefined &&
      mappingResult.local.iss === localIss &&
      mappingResult.local.sub === req.subject.id;
    if (!mappingEstablished) return deny("principal_mapping_failed");
    // Bound to `base()` from here on: a subsequent denial at any later step
    // (including the entitlement check just below) still carries the
    // principal_mapping evidence object, since the mapping itself is fully
    // established at this point.
    principalMapping = mappingResult;

    // @spec cross-domain#dual-axis — "Mission-state freshness and
    // entitlement freshness are separate declarations and MUST NOT be
    // collapsed into one timestamp": entitlement is resolved and
    // freshness-checked against its OWN declared bound, never
    // `stalenessBoundSeconds`. A missing resolver, a missing entitlement
    // result, `entitled !== true`, or entitlement staler than the bound each
    // deny the same way ("entitlement staleness beyond the declared bound
    // denies likewise"). The same skew floor step 3 applies to
    // `context.freshness` applies here too (@spec runtime#state-freshness,
    // GAP 3, #612): a bare `age <= bound` check alone lets a future-dated
    // `observed_at` produce a negative age that trivially satisfies any
    // bound, so a future timestamp must be rejected on its own, not merely
    // relied on to eventually exceed the bound.
    // A throwing entitlement resolver is likewise a failed result, not a
    // transport exception (#686 review): caught and normalized the same way
    // as a throwing mapping resolver, above.
    const entitlementBoundS = opts.entitlementStalenessBoundSeconds;
    let entitlement: EntitlementObservation | undefined;
    if (entitlementBoundS !== undefined) {
      try {
        entitlement = await opts.entitlement?.resolve({ local: mappingResult.local, audience: req.context.audience });
      } catch {
        entitlement = undefined;
      }
    }
    const observedAtMs = entitlement ? Date.parse(entitlement.observed_at) : NaN;
    const entitlementAgeMs = now().getTime() - observedAtMs;
    // @spec cross-domain#dual-axis (#744) -- the OPTIONAL action- and
    // resource-scoped grain of the same observation. Absent `authority`
    // keeps the audience-scoped grain exactly as before. Present, it is
    // intersected with this request's own (resource, action) pair, so an
    // entitlement gap on one action denies that action alone and leaves the
    // rest of the delegated set evaluable. The resource matched here is
    // `context.audience`, the same member step 5 below matches an authority
    // entry's `resource` against; the AuthZEN `resource.id` names the
    // object instance, a different namespace the delegated set is not keyed
    // by.
    const entitlementCurrent =
      entitlementBoundS !== undefined &&
      entitlement !== undefined &&
      entitlement.entitled === true &&
      Number.isFinite(observedAtMs) &&
      entitlementAgeMs >= -skewToleranceMs &&
      entitlementAgeMs <= entitlementBoundS * 1000 &&
      (entitlement.authority === undefined ||
        entitlementPermits(entitlement.authority, req.context.audience, req.action.name));
    if (!entitlementCurrent) return deny("principal_mapping_failed");
  }

  // 4b. Baseline MAS Join (@spec authority-server#mission-join rules 3-6,
  // #557 review point 1): resolved HERE, in the PDP -- the party that can
  // verify the credential inputs (the ALREADY-AUTHENTICATED subject and
  // context.actor.client_id this envelope already carries) and can tell
  // whether the join actually ran, unlike a PEP-side helper the PDP never
  // observes. Present exactly on the baseline-Join path (an ordinary
  // credential carrying no `mission` claim, `context.mission_join` set); a
  // Mission-bound request never carries it, so this block is a complete
  // no-op for the existing path -- byte-for-byte unchanged.
  if (req.context.mission_join) {
    const clientId = req.context.actor?.client_id;
    if (typeof clientId !== "string" || !clientId) return deny("mission_mismatch");
    const joined = resolveBaselineJoin({
      view,
      subject: { iss: req.subject.properties?.iss ?? "", sub: req.subject.id },
      clientId,
      ...(req.context.mission_join.delegate_depth !== undefined
        ? { delegateDepth: req.context.mission_join.delegate_depth }
        : {}),
      ...(opts.delegatePolicy !== undefined ? { delegatePolicy: opts.delegatePolicy } : {}),
    });
    // Rule 6: uniform mission_mismatch, no fallback to the unjoined view --
    // `joinedAuthority` stays undefined on failure, so step 5 below never
    // sees `view.authority_set` for this request either.
    if (!joined.ok) return deny("mission_mismatch");
    joinedAuthority = { disposition: joined.disposition, clientId, authoritySet: joined.authoritySet };
  }

  // 5. Authority entry match: the approved entry's resource is matched
  //    against context.audience (NOT the AuthZEN resource member). On the
  //    baseline-Join path (4b above), matched against the JOINED authority
  //    set, never the Mission's raw view.authority_set.
  // @spec runtime#input-authority — "For any other `authorization_details`
  // type, the PDP MUST evaluate the action under that type's documented
  // runtime semantics and MUST refuse if it does not understand or cannot
  // enforce those semantics." The PDP understands exactly one type, so
  // recognition is a whitelist: an entry whose `type` is not
  // MISSION_RESOURCE_ACCESS_TYPE never matches by resource/actions alone,
  // even if the AS admission layer's type closure ever broke upstream (a
  // new entry type admitted, a deserialization change). It falls through
  // fail-closed by construction, never by an explicit blocklist entry
  // that could omit a case.
  const candidateAuthoritySet = joinedAuthority?.authoritySet ?? view.authority_set;
  const entry: AuthorityEntry | undefined = candidateAuthoritySet.find(
    (e) =>
      e.type === MISSION_RESOURCE_ACCESS_TYPE &&
      e.resource === req.context.audience &&
      e.actions.includes(req.action.name),
  );
  if (!entry) {
    // @spec authzen#failure-condition-coverage: the mapping table keeps
    // `out_of_authority` ("Action outside the Authority Set") and
    // `unsupported_authorization_type` ("Unsupported authorization_details
    // type") as two different failure kinds, not two degrees of the same
    // one: the first means the PDP understood the entry and it was
    // insufficient; the second means the PDP could not evaluate the
    // entry's semantics at all. An entry that matches this request's
    // resource/actions under a type other than MISSION_RESOURCE_ACCESS_TYPE
    // is exactly the second case. This arm is reached only when no
    // RECOGNIZED-type entry matched above, so skip-not-shortcircuit is
    // unaffected: a mixed authority_set with a valid recognized entry
    // elsewhere for the same resource/actions still permits there.
    const unrecognizedTypeMatch = candidateAuthoritySet.some(
      (e) =>
        e.type !== MISSION_RESOURCE_ACCESS_TYPE &&
        e.resource === req.context.audience &&
        e.actions.includes(req.action.name),
    );
    if (unrecognizedTypeMatch) return deny("unsupported_authorization_type");
    return deny("out_of_authority");
  }

  // 5a. Containment overlay: the entry WAS approved (step 5 matched), but the
  //     containment delta covers this (resource, action) pair, so the issuer
  //     narrowed the effective authority after approval. Ordering is
  //     load-bearing: `out_of_authority` (step 5) stays "never approved";
  //     `authority_contained` means "approved, trust lost". A contained entry
  //     with no `actions` contains all the entry's actions.
  const containment = view.containment;
  if (containment) {
    const contained = containment.contained.some(
      (c) => c.resource === entry.resource && (c.actions === undefined || c.actions.includes(req.action.name)),
    );
    if (contained) {
      return {
        decision: false,
        context: base({
          denial_reason: "authority_contained",
          reason: "authority_contained",
          containment_version: containment.version,
        }),
      };
    }
  }

  // 5b. Discharge overlay: the entry WAS approved (step 5 matched), but its
  //     `terminal_when` completion condition has fired and the Mission Issuer
  //     committed the discharge, so the entry no longer derives and MUST NOT be
  //     honored at the point of use either (@spec discharge#runtime: a PEP/PDP that
  //     recognizes `terminal_when` denies a discharged entry, closing the window
  //     between discharge and token expiry). Keyed by the entry commitment, the
  //     same `entry_digest` a permit already carries, so an equivalence class of
  //     byte-identical entries is covered by one delta member. Ordering mirrors
  //     5a: `out_of_authority` stays "never approved", `authority_contained` is
  //     "approved, trust lost", `authority_discharged` is "approved, work done".
  const dischargedDigests = view.discharged?.entry_digests;
  if (dischargedDigests?.length) {
    const digest = computeAnchor(AUTHORITY_ENTRY_TYP, view.issuer, entry as never);
    if (dischargedDigests.includes(digest)) {
      return {
        decision: false,
        context: base({
          denial_reason: "authority_discharged",
          reason: "authority_discharged",
          entry_digest: digest,
        }),
      };
    }
  }

  // @spec capability-binding#capability-verification — applicability comes
  // ONLY from recorded policy for this action. A presented member cannot opt
  // out, substitute another action's binding, or create applicability.
  const bindings = entry.capability_sources?.filter(b => b.action === req.action.name) ?? [];
  if (bindings.length) {
    const presented = runtimeCapabilitySourceOf(req.context.capability_source);
    const recorded = presented && bindings.find(b => b.tool_id === presented.tool_id);
    if (!presented || !recorded || !runtimeCapabilitySourceOf(recorded) ||
        presented.source_digest !== recorded.source_digest ||
        presented.source_uri !== recorded.source_uri ||
        presented.operation_ref !== recorded.operation_ref ||
        (recorded.catalog_digest !== undefined && presented.catalog_digest !== recorded.catalog_digest)) {
      return deny("capability_drift");
    }
  }

  const mapping = opts.relationForAction(req.action.name);
  if (!mapping) return deny("out_of_authority");

  // 6. FGA authority check with contextual tuples derived from the record.
  const vendorId = req.resource.properties?.vendor_id ?? "";
  const tuples = deriveContextualTuples({
    view,
    entry,
    target: {
      objectType: req.resource.type === "vendor" ? "vendor" : "invoice",
      objectId: req.resource.id,
      vendorId,
    },
    relation: mapping.relation,
  });
  if (tuples.length === 0) return deny("out_of_authority"); // constraint excluded target
  const allowed = await fga.checkWithContext(
    { user: `mission:${view.id}`, relation: mapping.relation, object: `${req.resource.type}:${req.resource.id}` },
    tuples,
  );
  if (!allowed) return deny("out_of_authority");

  // 6a. @spec runtime#read-binding: a bound bulk/cross-tenant read names a
  // COLLECTION, not one object: the check above names only the entry's first
  // (representative) member, which proves Resource policy permits THAT
  // member, never that it permits every OTHER member the read actually
  // returns. `entry_digest` (Decision Evidence) anchors the Mission
  // ceiling (what the Authority Set allows), not what Resource policy
  // independently permits per object. When the request names the full
  // collection (`resource.properties.vendor_ids`), every member is checked
  // independently here; the FIRST refusal denies the WHOLE read
  // out_of_authority. Narrowing the response to just the permitted subset
  // is deliberately not done instead: the response contract has no lane for
  // a partially narrowed permit (@spec authzen#response-context), so
  // inventing one here would be a new, uncoordinated wire member; fail
  // closed on the whole read is the choice this contract already supports.
  const vendorIds = req.resource.properties?.vendor_ids;
  if (vendorIds) {
    for (const memberVendorId of vendorIds) {
      const memberTuples = deriveContextualTuples({
        view,
        entry,
        target: { objectType: "vendor", objectId: memberVendorId, vendorId: memberVendorId },
        relation: mapping.relation,
      });
      if (memberTuples.length === 0) return deny("out_of_authority");
      const memberAllowed = await fga.checkWithContext(
        { user: `mission:${view.id}`, relation: mapping.relation, object: `vendor:${memberVendorId}` },
        memberTuples,
      );
      if (!memberAllowed) return deny("out_of_authority");
    }
  }

  // 7. Numeric constraint (overlay, O-6): per-payment cap.
  // @spec runtime#input-parameters: keyed on the constraint's OWN presence
  // (`entry.constraints?.max_amount`), never on whether the mapped action's
  // input schema happens to carry an amount (`mapping.needsAmount`): a bound
  // `max_amount` the PDP cannot supply the input for (no `context.amount`)
  // or cannot evaluate (unparseable amount or cap, mismatched currency) MUST
  // refuse, the same "cannot supply the declared inputs for" case the
  // Parameters rule names, never fall through as unenforced. Absent a bound
  // `max_amount`, `needsAmount` alone never synthesizes an amount
  // requirement that isn't there.
  const cap = entry.constraints?.max_amount;
  if (cap) {
    const amt = req.context.amount;
    // @spec mission#max-amount — exact decimal-value comparison at the
    // enforcement point, never IEEE-754 float; an absent amount or a
    // malformed amount on either side fails closed (denied), never
    // silently permitted.
    if (
      !amt ||
      amt.currency !== cap.currency ||
      !isValidAmount(amt.amount) ||
      !isValidAmount(cap.amount) ||
      compareAmounts(amt.amount, cap.amount) > 0
    ) {
      return deny("constraint_exceeded");
    }
  }

  // 8. Action-bound approval (@spec authzen#context-approval): when policy
  //    requires one, the presented approval MUST match the request's
  //    parameter_digest and be within the max approval age; else deny
  //    action_approval_required, marked requestable (@spec requestable-denials).
  // @spec txn-authorization#applicability — the requirement is the DEPLOYMENT
  // predicate OR the matched entry's effective Common Constraint, so a
  // delegated leaf carrying `requires_action_approval: true` is gated even
  // where deployment policy alone would not gate the action.
  if (
    opts.requiresActionApproval?.(req.action.name, actionClass) ||
    entry.constraints?.requires_action_approval === true
  ) {
    const appr = req.context.action_approval;
    const maxAge = (opts.maxApprovalAgeSeconds ?? 300) * 1000;
    const valid =
      appr !== undefined &&
      appr.parameter_digest === req.context.parameter_digest &&
      now().getTime() - Date.parse(appr.approved_at) <= maxAge &&
      // ARAP: honor the approval's validity bound when present.
      (appr.approved_until === undefined || now().getTime() <= Date.parse(appr.approved_until));
    if (!valid) {
      const ctx: Record<string, unknown> = base({
        denial_reason: "action_approval_required",
        reason: "action_approval_required",
        ...(req.context.parameter_digest ? { parameter_digest: req.context.parameter_digest } : {}),
      });
      if (opts.requestable && req.context.parameter_digest) {
        // ARAP: the access request is valid only while the denial binding is.
        const requestableExp = Math.floor(now().getTime() / 1000) + 300;
        const binding = await new SignJWT({
          decision_id: decisionId,
          mission_id: view.id,
          action: req.action.name,
          parameter_digest: req.context.parameter_digest,
        })
          .setProtectedHeader({ alg: "ES256", kid: opts.requestable.kid, typ: "pdp-denial-binding+jwt" })
          .setIssuedAt()
          .setExpirationTime(requestableExp)
          .sign(opts.requestable.sign);
        ctx.access_request = {
          endpoint: opts.requestable.endpoint,
          denial_binding: decisionId,
          binding_token: binding,
          expires_at: new Date(requestableExp * 1000).toISOString(),
        };
      }
      return { decision: false, context: ctx };
    }
  }

  // Permit (@spec authzen#response-context permit shape). Properties
  // declared; PEP redeems. `entry_digest` (the evidence resolved-scope
  // anchor, @spec authzen#decision-evidence-object) is NOT one of the
  // profile's `conditions`: it is not named among the response-context
  // lanes at all, so it stays top-level deployment metadata, unchanged.
  // `conditions` carries the profile's three named condition members:
  // `valid_until` (REQUIRED; was `permit_expires_at`), `use_limit`
  // (REQUIRED exactly 1 for a high-consequence-class permit; was the
  // boolean `single_use`), and `parameter_digest` (CONDITIONAL, present
  // when the action was parameter-bound).
  const permitTtl = actionClass === "irreversible_action" ? 120 : 300;
  const validUntil = new Date(now().getTime() + permitTtl * 1000).toISOString();
  // @spec runtime#classification: the high-consequence classes are
  // irreversible_action, external_commitment, and privileged_administration
  // (this deployment defines no privileged_administration action), the same
  // pairing policy.ts's stalenessBoundSeconds already keys its tight bound
  // on. Previously this checked only "irreversible_action", so a
  // send_remittance_email (external_commitment) permit never carried a use
  // limit at all: a genuine value-level bug this migration also fixes.
  const highConsequence = actionClass === "irreversible_action" || actionClass === "external_commitment";
  return {
    decision: true,
    context: base({
      entry_digest: computeAnchor(AUTHORITY_ENTRY_TYP, view.issuer, entry as never),
      conditions: {
        valid_until: validUntil,
        ...(highConsequence ? { use_limit: 1 } : {}),
        ...(req.context.parameter_digest ? { parameter_digest: req.context.parameter_digest } : {}),
      },
    }),
  };
}
