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
import type { Fga } from "./fga.js";
import { type AuthorityEntry, deriveContextualTuples, type MissionView, policyViewId } from "./policy-view.js";

export interface EvaluationRequest {
  subject: { id: string; type?: string };
  /** Fine-grained target object (Resource-policy only), NOT the entry match. */
  resource: { type: string; id: string; properties?: { vendor_id?: string } };
  action: { name: string };
  context: {
    audience: string; // matched against the approved entry's resource
    mission: { id: string; authority_hash: string; policy_view_id?: string };
    actor?: ContextActor;
    freshness?: { observed_at: string; source: string };
    parameter_digest?: string;
    amount?: { amount: string; currency: string };
    action_class?: string;
  };
}

export type DenialReason =
  | "out_of_authority"
  | "stale_state"
  | "view_inconsistent"
  | "mission_inactive"
  | "actor_invalid"
  | "constraint_exceeded";

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
}

let decisionCounter = 0;
function newDecisionId(): string {
  decisionCounter += 1;
  return `dec_${decisionCounter}_${Math.floor(performance.now())}`;
}

export async function evaluate(req: EvaluationRequest, opts: EvaluateOptions): Promise<Decision> {
  const { view, fga, modelId, now } = opts;
  const pvid = policyViewId(view, modelId);
  const actionClass = req.context.action_class;
  const base = (extra: Record<string, unknown>) => ({
    decision_id: newDecisionId(),
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
      if (amt.currency !== cap.currency || Number.parseFloat(amt.amount) > Number.parseFloat(cap.amount)) {
        return deny("constraint_exceeded");
      }
    }
  }

  // Permit (@spec authzen permit shape). Properties declared; PEP redeems.
  const permitTtl = actionClass === "irreversible_action" ? 120 : 300;
  const nowIso = new Date(now().getTime() + permitTtl * 1000).toISOString();
  return {
    decision: true,
    context: base({
      permit_expires_at: nowIso,
      single_use: actionClass === "irreversible_action",
      ...(req.context.parameter_digest ? { parameter_digest: req.context.parameter_digest } : {}),
    }),
  };
}
