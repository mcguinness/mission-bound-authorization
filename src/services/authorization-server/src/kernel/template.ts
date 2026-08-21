/**
 * @spec draft-mcguinness-oauth-mission-template
 *
 * Mission Template dispatch: a human consents ONCE to a ceiling + dispatch
 * policy + bounds (the {@link MissionTemplate}); a dispatcher then instantiates
 * ORDINARY Missions from it at machine speed. Each instance is a normal
 * MissionRecord (its own `msn_` id, integrity anchors, lifecycle) built exactly
 * as {@link createExpansion} builds a successor, so every downstream mechanism
 * (containment, gating, expansion, cascade) applies unchanged.
 *
 * The safety property is the DOUBLE INTERSECTION: the instance Authority Set is
 * a subset of BOTH the derivation-policy ceiling (the untrusted intent is first
 * derived under the kernel's policy) AND the template ceiling (that derived set
 * is then re-derived under a synthetic policy whose ceiling is the template's).
 * Nothing the dispatcher proposes can widen past either ceiling. The APPROVER of
 * record on every instance is the TEMPLATE's approver (the consenting human),
 * never the dispatcher.
 *
 * A standalone kernel module (mirrors kernel/expansion.ts and
 * kernel/child-delegation.ts): pure functions over {@link MissionKernel} and
 * {@link TemplateStore}, not kernel methods, wired to no endpoint here.
 */

import { randomBytes } from "node:crypto";
import { authorityHash, computeAnchor, intentHash, type JsonValue, MISSION_TEMPLATE_TYP, proposalHash } from "@mission/core";
import { deriveAuthoritySet, isSubsetSet } from "./derive.js";
import { IntentError } from "./intent.js";
import type { MissionKernel } from "./kernel.js";
import { newMissionId } from "./mission-id.js";
import {
  type MissionTemplate,
  type TemplateCreate,
  type TemplateState,
  TemplateStore,
} from "./template-store.js";
import {
  type ApprovalBasis,
  type AuthorityEntry,
  type MissionIntent,
  type IntentSubmissionEvidenceFact,
  type MissionRecord,
  type TemplateRef,
  TERMINAL_STATES,
} from "./types.js";

// Re-export the persisted types so the template module is the single public
// surface for the feature (TemplateRef itself rides the types.ts star-export).
export { TemplateStore };
export type { MissionTemplate, TemplateCreate, TemplateState, TemplateRef };

/** @spec mission-template — a bad template definition (creation-time refusal),
 *  distinct from a dispatch-time {@link DispatchError}. */
export class TemplateError extends Error {}

/**
 * @spec mission-template#dispatch-refusals — why a dispatch was refused.
 * `template_not_active` covers BOTH a revoked and an expired template (there is
 * no separate expiry reason). `out_of_template_ceiling` is the empty double
 * intersection; a policy-empty intent surfaces as {@link IntentError} instead
 * (matching `kernel.approve`), never as this reason.
 */
export type DispatchReason =
  | "template_not_active"
  | "dispatcher_not_allowed"
  | "recipient_not_allowed"
  | "out_of_template_ceiling"
  | "dispatch_prohibited_class"
  | "max_active_exceeded"
  | "rate_exceeded";

export class DispatchError extends Error {
  constructor(
    readonly reason: DispatchReason,
    message: string,
  ) {
    super(message);
  }
}

/** The consented body of a template (@spec mission-template): what the human
 *  approves. Hashed under {@link MISSION_TEMPLATE_TYP} to `template_hash`;
 *  excludes the generated id, lifecycle state, and creation time. */
export interface CreateTemplateInput {
  template_version: string;
  issuer: string;
  /** The consenting human; the approver of record on every dispatched instance. */
  approver: { iss: string; sub: string };
  ceiling: AuthorityEntry[];
  dispatch_policy: string;
  dispatchers: string[];
  recipients: string[];
  per_instance_lifetime_s: number;
  max_active: number;
  rate_per_min: number;
  approval_event_id: string;
  expires_at: string;
}

/**
 * @spec mission-template — create (consent to) a Mission Template.
 * `template_hash = computeAnchor(MISSION_TEMPLATE_TYP, issuer, body)` commits to
 * the consented body. IDEMPOTENT by `approval_event_id`: a repeat returns the
 * template that approval already created (so a retried consent never mints a
 * second template nor a mismatched hash).
 */
export function createTemplate(store: TemplateStore, input: CreateTemplateInput): MissionTemplate {
  if (input.ceiling.length === 0) {
    throw new TemplateError("template ceiling must be non-empty");
  }
  if (input.per_instance_lifetime_s <= 0 || !Number.isFinite(input.per_instance_lifetime_s)) {
    throw new TemplateError("per_instance_lifetime_s must be a positive number of seconds");
  }
  if (input.max_active <= 0 || !Number.isInteger(input.max_active)) {
    throw new TemplateError("max_active must be a positive integer");
  }
  if (input.rate_per_min <= 0 || !Number.isInteger(input.rate_per_min)) {
    throw new TemplateError("rate_per_min must be a positive integer");
  }

  // Idempotency first: return the already-consented template unchanged rather
  // than recomputing the hash (a body change would need a NEW approval event).
  const existing = store.getByApprovalEvent(input.approval_event_id);
  if (existing) return existing;

  const templateBody = {
    template_version: input.template_version,
    ceiling: input.ceiling,
    dispatch_policy: input.dispatch_policy,
    dispatchers: input.dispatchers,
    recipients: input.recipients,
    per_instance_lifetime_s: input.per_instance_lifetime_s,
    max_active: input.max_active,
    rate_per_min: input.rate_per_min,
    approver: input.approver,
    expires_at: input.expires_at,
  };
  const template_hash = computeAnchor(
    MISSION_TEMPLATE_TYP,
    input.issuer,
    templateBody as unknown as JsonValue,
  );
  const id = `tmpl_${randomBytes(18).toString("base64url")}`;
  const create: TemplateCreate = { ...input, id, template_hash };
  return store.create(create);
}

export interface DispatchInput {
  /** The Mission Template to instantiate from. */
  templateId: string;
  /**
   * Caller-supplied dispatch event identifier. The instance's
   * `approval_event_id` is `"dsp_" + dispatchEventId`, so a retried dispatch
   * (same id) is idempotent and returns the same instance.
   */
  dispatchEventId: string;
  /** The dispatching actor; MUST be in the template's `dispatchers`. */
  dispatcher: string;
  /** The receiving actor; MUST be in `recipients`; becomes the instance `client_id`. */
  recipient: string;
  /** The instance's OWN Mission Intent (untrusted, derived under policy first). */
  intent: MissionIntent;
  /**
   * @spec mission#authority-proposal — the dispatcher's authority proposal,
   * submitted on the standard `authorization_details` parameter of the
   * dispatch grant (already validated at intake). Bounds the FIRST derivation
   * (narrowing mode under the policy ceiling); the template ceiling then
   * intersects as before. Recorded on the instance and committed by
   * `proposal_hash` iff present; absent means template-mode derivation.
   */
  proposedAuthority?: AuthorityEntry[];
  /** The subject the instance acts for. */
  subject: { iss: string; sub: string };
  /**
   * @spec mission#intent-submission-evidence — the VERIFIED Intent Submission
   * Evidence facts of the dispatch submission (stage-2 output). Landed on the
   * instance record's `submission_evidence`, outside all anchors.
   */
  submissionEvidence?: IntentSubmissionEvidenceFact[];
  /**
   * The version of the derivation policy the passed `kernel` derives under
   * (e.g. `DERIVATION_POLICY.policy_version`). Recorded on the instance as its
   * `policy_version`; the kernel exposes no getter, so the caller supplies it.
   */
  policyVersion: string;
  /**
   * @spec mission-template#prohibited-class — high-consequence actions no
   * template dispatch may confer (from config, e.g. `payments:payment.execute`).
   * An instance whose final authority includes one is refused
   * `dispatch_prohibited_class`, even when it is within both ceilings.
   */
  dispatchProhibitedActions?: readonly string[];
}

export interface DispatchResult {
  mission: MissionRecord;
  template: MissionTemplate;
}

/** The earliest of several {ms, iso} candidates, returning the winner's iso
 *  VERBATIM (never re-serialized, so a clamp preserves the exact input string). */
function earliestIso(candidates: Array<{ ms: number; iso: string }>): string {
  return candidates.reduce((a, b) => (b.ms < a.ms ? b : a)).iso;
}

/**
 * @spec mission-template#dispatch — instantiate an ordinary Mission from a
 * template. Structure mirrors {@link createChildMission}: resolve the template,
 * idempotency-guard, gate, derive-and-prove authority, clamp expiry, assemble
 * lineage, insert. The gates (in order): idempotency, template active + not
 * expired, dispatcher allowed, recipient allowed, max-active, rate, double
 * intersection, prohibited-class.
 */
export function dispatchFromTemplate(
  kernel: MissionKernel,
  store: TemplateStore,
  input: DispatchInput,
): DispatchResult {
  const template = store.get(input.templateId);
  // Unknown template: a plain Error (mirrors createChildMission's unknown
  // parent), NOT a DispatchError — the reason union has no "unknown" member.
  if (!template) throw new Error(`unknown template ${input.templateId}`);

  const approvalEventId = `dsp_${input.dispatchEventId}`;

  // a. Idempotency: a caller-supplied dispatch id makes retries idempotent.
  // Checked BEFORE the gates so a retry after the template was revoked/expired
  // still returns the instance the first dispatch created. `approval_event_id`
  // is globally unique, so guard the pathological case of the SAME dispatch id
  // reused against a DIFFERENT template (which would otherwise silently return a
  // mismatched {mission, template} pair).
  const existing = kernel.findByApprovalEvent(approvalEventId);
  if (existing) {
    if (existing.template?.id !== template.id) {
      throw new Error(
        `dispatch event ${input.dispatchEventId} is already bound to template ${existing.template?.id}`,
      );
    }
    return { mission: existing, template };
  }

  const nowMs = kernel.nowDate().getTime();

  // b. Template gate.
  if (template.state !== "active") {
    throw new DispatchError("template_not_active", `template ${template.id} is ${template.state}`);
  }
  if (Date.parse(template.expires_at) <= nowMs) {
    throw new DispatchError("template_not_active", `template ${template.id} is expired`);
  }
  if (!template.dispatchers.includes(input.dispatcher)) {
    throw new DispatchError("dispatcher_not_allowed", `dispatcher ${input.dispatcher} is not permitted`);
  }
  if (!template.recipients.includes(input.recipient)) {
    throw new DispatchError("recipient_not_allowed", `recipient ${input.recipient} is not permitted`);
  }
  // max-active: count non-terminal instances (store rows filtered by kernel state).
  const active = store.activeInstanceCount(template.id, (missionId) => {
    const m = kernel.get(missionId);
    return !m || TERMINAL_STATES.has(m.state);
  });
  if (active >= template.max_active) {
    throw new DispatchError(
      "max_active_exceeded",
      `template ${template.id} has ${active} active instances (max ${template.max_active})`,
    );
  }
  // rate: dispatches in the trailing 60s window.
  const sinceIso = new Date(nowMs - 60_000).toISOString();
  if (store.dispatchesSince(template.id, sinceIso) >= template.rate_per_min) {
    throw new DispatchError(
      "rate_exceeded",
      `template ${template.id} exceeded ${template.rate_per_min} dispatches/min`,
    );
  }

  // c. Double intersection. FIRST: derive under the kernel's derivation policy
  // (the untrusted intent, bounded by the dispatcher's proposal where one was
  // submitted, @spec mission#authority-proposal). An intent empty under the
  // POLICY throws IntentError here and is deliberately NOT caught — it must
  // surface exactly as it would from kernel.approve, not be mislabeled
  // out_of_template_ceiling.
  const proposal = input.proposedAuthority?.length ? input.proposedAuthority : undefined;
  const derived = kernel.derive(input.intent, proposal);
  // SECOND: re-derive that set under a synthetic policy whose ceiling is the
  // template's. Reusing deriveAuthoritySet gives a result that is a subset of
  // both the derived set and the template ceiling. An empty result here IS the
  // template ceiling refusing the intent.
  let final: AuthorityEntry[];
  try {
    // The policy-derived set plays the PROPOSAL role for the second
    // derivation (the third parameter, @spec mission#authority-proposal
    // carriage: the Intent itself carries no authority members), narrowing it
    // under the template ceiling.
    final = deriveAuthoritySet(
      input.intent,
      { policy_version: template.template_version, ceiling: template.ceiling },
      derived,
    );
  } catch (e) {
    if (e instanceof IntentError) {
      throw new DispatchError(
        "out_of_template_ceiling",
        `intent yields no Authority Set within template ${template.id}'s ceiling`,
      );
    }
    throw e;
  }
  // Belt-and-suspenders: the final set MUST be a subset of BOTH ceilings. This
  // is load-bearing, not decorative: a template ceiling entry that (mistakenly)
  // carried a delegation/children grant the policy ceiling lacked would be
  // INHERITED by the second derivation and widen past the policy; isSubsetSet
  // against `derived` catches exactly that and refuses structurally.
  if (!(isSubsetSet(final, template.ceiling) && isSubsetSet(final, derived))) {
    throw new Error(`dispatch from ${template.id} violated the double-intersection invariant`);
  }

  // d. Prohibited-class guard: refuse high-consequence actions regardless of
  // ceiling membership.
  const prohibited = new Set(input.dispatchProhibitedActions ?? []);
  if (prohibited.size > 0 && final.some((e) => e.actions.some((a) => prohibited.has(a)))) {
    throw new DispatchError(
      "dispatch_prohibited_class",
      `instance authority includes a dispatch-prohibited action`,
    );
  }

  // e. Build a NORMAL MissionRecord (as expansion.ts does). Anchors are over
  // the INSTANCE's own intent and `final` set (never the template body). The
  // approver is the TEMPLATE's approver: the human of record, not the
  // dispatcher. expires_at is the earliest of the intent's, now+lifetime, and
  // the template's expiry (verbatim strings; only now+lifetime is synthesized).
  const nowIso = kernel.nowDate().toISOString();
  const lifetimeMs = nowMs + template.per_instance_lifetime_s * 1000;
  const expiresAt = earliestIso([
    { ms: Date.parse(input.intent.expires_at), iso: input.intent.expires_at },
    { ms: lifetimeMs, iso: new Date(lifetimeMs).toISOString() },
    { ms: Date.parse(template.expires_at), iso: template.expires_at },
  ]);
  const id = newMissionId();
  const templateRef: TemplateRef = {
    id: template.id,
    issuer: template.issuer,
    template_version: template.template_version,
    template_hash: template.template_hash,
    dispatch_policy: template.dispatch_policy,
  };
  // @spec mission#approval-basis, mission-template#template-lineage —
  // standing consent to the template ceiling activates this instance:
  // consent_principal is the template's human (== approver, unchanged);
  // activation is the template lineage + this dispatch event;
  // activation_actor is the Dispatcher client; root_commitment is the
  // template's own integrity anchor.
  const approvalBasis: ApprovalBasis = {
    type: "template",
    consent_principal: template.approver,
    activation: {
      template_id: template.id,
      template_version: template.template_version,
      template_hash: template.template_hash,
      dispatch_event_id: input.dispatchEventId,
    },
    activation_actor: { iss: template.issuer, sub: input.dispatcher },
    root_commitment: template.template_hash,
    // @spec mission#mission-record (#580) — from the RETAINED template
    // record (the consent instant of this exact template version), never
    // from the dispatch request.
    approved_at: template.created_at,
  };
  const record: MissionRecord = {
    id,
    issuer: template.issuer,
    state: "active",
    intent: input.intent,
    ...(proposal ? { proposed_authority: proposal } : {}),
    authority_set: final,
    intent_hash: intentHash(template.issuer, input.intent as never),
    ...(proposal ? { proposal_hash: proposalHash(template.issuer, proposal as never) } : {}),
    ...(input.submissionEvidence?.length ? { submission_evidence: input.submissionEvidence } : {}),
    authority_hash: authorityHash(template.issuer, final as never),
    subject: input.subject,
    approver: template.approver,
    approval_basis: approvalBasis,
    client_id: input.recipient,
    policy_version: input.policyVersion,
    approval_event_id: approvalEventId,
    created_at: nowIso,
    expires_at: expiresAt,
    version: 1,
    max_derivations: input.intent.controls?.max_derivations ?? null,
    derivation_count: 0,
    grant_id: null,
    status_list_idx: null,
    template: templateRef,
  };

  // f. Insert the instance and record the dispatch (audit + rate/max-active).
  kernel.insertRecord(record);
  store.recordDispatch({
    dispatchEventId: input.dispatchEventId,
    templateId: template.id,
    missionId: id,
  });
  return { mission: record, template };
}
