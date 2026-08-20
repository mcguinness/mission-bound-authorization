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
import { AUTHORITY_ENTRY_TYP, compareAmounts, computeAnchor, isValidAmount } from "@mission/core";
import { getTracer } from "@mission/telemetry";
import { SignJWT, type CryptoKey } from "jose";
import type { Fga } from "./fga.js";
import {
  type AuthorityEntry,
  deriveContextualTuples,
  MISSION_RESOURCE_ACCESS_TYPE,
  type MissionView,
  policyViewId,
} from "./policy-view.js";

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
  subject: { id: string; type?: string };
  /** Fine-grained target object (Resource-policy only), NOT the entry match. */
  resource: { type: string; id: string; properties?: { vendor_id?: string } };
  action: { name: string };
  context: {
    audience: string; // matched against the approved entry's resource
    mission: { id: string; authority_hash: string; policy_view_id?: string };
    actor?: ContextActor;
    freshness?: Freshness;
    parameter_digest?: string;
    amount?: { amount: string; currency: string };
    action_class?: string;
    action_approval?: ActionApproval;
  };
}

export type DenialReason =
  | "out_of_authority"
  | "authority_contained"
  | "stale_state"
  | "view_inconsistent"
  | "mission_inactive"
  | "actor_invalid"
  | "constraint_exceeded"
  | "action_approval_required"
  | "unsupported_authorization_type";

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
}

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
      return decision;
    } finally {
      span.end();
    }
  });
}

async function evaluateInner(req: EvaluationRequest, opts: EvaluateOptions): Promise<Decision> {
  const { view, fga, modelId, now } = opts;
  const pvid = policyViewId(view, modelId);
  const actionClass = req.context.action_class;
  const decisionId = newDecisionId();
  const base = (extra: Record<string, unknown>) => ({
    decision_id: decisionId,
    policy_view_id: pvid,
    ...(actionClass ? { action_class: actionClass, class_source: "deployment" } : {}),
    ...extra,
  });
  const deny = (denial_reason: DenialReason): Decision => ({
    decision: false,
    context: base({ denial_reason }),
  });

  // 1. View consistency (@spec: view_inconsistent).
  if (
    req.context.mission.id !== view.id ||
    req.context.mission.authority_hash !== view.authority_hash ||
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
  if (req.context.freshness) {
    const observedAtMs = Date.parse(req.context.freshness.observed_at);
    const ageMs = now().getTime() - observedAtMs;
    const skewToleranceMs =
      (opts.freshnessSkewToleranceSeconds ?? DEFAULT_FRESHNESS_SKEW_TOLERANCE_SECONDS) * 1000;
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

  // 5. Authority entry match: the approved entry's resource is matched
  //    against context.audience (NOT the AuthZEN resource member).
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
  const entry: AuthorityEntry | undefined = view.authority_set.find(
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
    const unrecognizedTypeMatch = view.authority_set.some(
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
        context: base({ denial_reason: "authority_contained", containment_version: containment.version }),
      };
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

  // 7. Numeric constraint (overlay, O-6): per-payment cap.
  if (mapping.needsAmount) {
    const cap = entry.constraints?.max_amount;
    const amt = req.context.amount;
    if (cap && amt) {
      // @spec mission#max-amount — exact decimal-value comparison at the
      // enforcement point, never IEEE-754 float; a malformed amount on
      // either side fails closed (denied), never silently permitted.
      if (
        amt.currency !== cap.currency ||
        !isValidAmount(amt.amount) ||
        !isValidAmount(cap.amount) ||
        compareAmounts(amt.amount, cap.amount) > 0
      ) {
        return deny("constraint_exceeded");
      }
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

  // Permit (@spec authzen permit shape). Properties declared; PEP redeems.
  // The PDP's evidence contribution stays in the decision context (D28/D32):
  // entry_digest anchors the Authority Set entry the permit was evaluated
  // against (@spec authzen#decision-evidence-object, resolved-scope anchor).
  const permitTtl = actionClass === "irreversible_action" ? 120 : 300;
  const nowIso = new Date(now().getTime() + permitTtl * 1000).toISOString();
  return {
    decision: true,
    context: base({
      permit_expires_at: nowIso,
      single_use: actionClass === "irreversible_action",
      entry_digest: computeAnchor(AUTHORITY_ENTRY_TYP, view.issuer, entry as never),
      ...(req.context.parameter_digest ? { parameter_digest: req.context.parameter_digest } : {}),
    }),
  };
}
