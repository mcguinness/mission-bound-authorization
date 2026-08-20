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
import { type AuthorityEntry, deriveContextualTuples, type MissionView, policyViewId } from "./policy-view.js";

/** @spec authzen#context-approval */
export interface ActionApproval {
  id: string;
  approved_at: string;
  /** ARAP: the approval's validity bound; the PDP refuses once now > this. */
  approved_until?: string;
  parameter_digest: string;
  state?: string;
}

export interface EvaluationRequest {
  subject: { id: string; type?: string };
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
    mission: { id: string; authority_hash: string; policy_view_id?: string };
    actor?: ContextActor;
    freshness?: { observed_at: string; source: string };
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
  | "action_approval_required";

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
    ...(actionClass ? { action_class: actionClass, class_source: "deployment" } : {}),
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
  if (req.context.freshness) {
    const ageMs = now().getTime() - Date.parse(req.context.freshness.observed_at);
    if (ageMs > opts.stalenessBoundSeconds(actionClass) * 1000) return deny("stale_state");
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
  const entry: AuthorityEntry | undefined = view.authority_set.find(
    (e) => e.resource === req.context.audience && e.actions.includes(req.action.name),
  );
  if (!entry) return deny("out_of_authority");

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
