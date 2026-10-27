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
import {
  actionOutsideGrammar,
  authorityHash,
  carriesHttpUserinfo,
  canonicalize,
  computeAnchor,
  entryDelegateMatcherViolation,
  intentHash,
  isAbsoluteUri,
  type JsonValue,
  MISSION_TEMPLATE_TYP,
  proposalHash,
  refusedEntryMember,
  unsupportedActionFamily,
  unsupportedDelegationMember,
  unsupportedEntryMember,
} from "@mission/core";
import {
  assertApproverMayActivate,
  assertLocalPrincipal,
  assertSubjectDiscipline,
  type AuthoritySourceResolution,
  type AuthoritySourceResolver,
  type BoundAuthoritySourceCatalog,
  bindingOf,
  catalogAuthoritySourceResolver,
  resolveApprovalSource,
} from "./authority-source.js";
import {
  activationPolicyMatches,
  mintActivationPolicyRef,
  type RegisteredActivationPolicy,
  verifiedActivationPolicy,
} from "./activation-policy.js";
import { signApprovalGovernanceRecord } from "./approval-governance.js";
import { audienceReferences, inheritedAudiences } from "./approved-audience.js";
import { inheritCapabilitySources, resolveFreshCapabilitySources, type CapabilitySourceResolver } from "./capability-binding.js";
import { UniqueViolationError } from "@mission/store";
import { CreationIdempotencyStore, type CreationReservation, creationFingerprint } from "./creation-idempotency.js";
import { deriveAuthoritySetWithProvenance, isSubsetSet } from "./derive.js";
import type { RetainedOrigin } from "./eligibility-provenance.js";
import { IntentError } from "./intent.js";
import type { MissionKernel } from "./kernel.js";
import { newMissionId } from "./mission-id.js";
import {
  STANDING_CONSENT_LIMIT_MEMBER,
  standingConsentMaximumOf,
  withinStandingConsentMaximum,
} from "./standing-consent-limit.js";
import {
  assertStandingPaymentCeiling,
  assertStandingPaymentTemplateBounds,
  isHumanFloorConsent,
  maxBudgetRefusal,
  type ProhibitedPredicateMapping,
  StandingPaymentBudgetError,
  type StandingPaymentStore,
  type StandingPaymentTerms,
  StandingPaymentTermsError,
  standingPaymentPredicateRefusal,
  standingPaymentTermsOf,
  type TemplateConsentProvenance,
} from "./standing-payment.js";
import {
  assertTemplateRecord,
  buildTemplateRecord,
  parseTemplateRecordingRule,
  templateGovernanceGate,
  templateRecordingRuleFor,
  templateRecordingRuleRef,
} from "./template-approval-record.js";
import {
  type MissionTemplate,
  type TemplateCreate,
  type TemplateRecipients,
  type TemplateSourceBinding,
  type TemplateState,
  TemplateStore,
} from "./template-store.js";
import {
  type ApprovalBasis,
  type AuthorityEntry,
  type AuthoritySource,
  type MissionIntent,
  type IntentSubmissionEvidenceEntry,
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
 * no separate expiry reason). `review_overdue` is a template whose most recent
 * human approval is older than its `review_cadence_s`
 * (@spec mission-template#template-consent), and `agent_not_selected` a
 * template listing several Agents whose Dispatch Policy selects none; both are
 * implementation-local, with no registered wire value (D205). `out_of_template_ceiling` is the empty double
 * intersection; a policy-empty intent surfaces as {@link IntentError} instead
 * (matching `kernel.approve`), never as this reason. `dispatch_policy_changed`
 * is a Dispatch Policy whose snapshot no longer matches the `digest` the
 * template committed (@spec mission#standing-consent-bases).
 */
export type DispatchReason =
  | "template_not_active"
  | "review_overdue"
  | "dispatcher_not_allowed"
  | "dispatch_policy_changed"
  | "agent_not_selected"
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

/**
 * @spec mission-template#dispatch — the same (Dispatcher, dispatch_event_id)
 * presented with a different operation fingerprint. Not a Dispatch refusal
 * reason: the adapter answers `invalid_request` with an `error_description`
 * and no `mission_denial_reason`, as the expansion profile's durable
 * reservation does.
 */
export class DispatchMismatchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DispatchMismatchError";
  }
}

export type { TemplateRecipients };

/** The consented body of a template (@spec mission-template): what the human
 *  approves. Hashed under {@link MISSION_TEMPLATE_TYP} to `template_hash`;
 *  excludes the generated id, lifecycle state, and creation time. */
export interface CreateTemplateInput {
  template_version: string;
  issuer: string;
  /** The consenting human; the approver of record on every dispatched instance. */
  approver: { iss: string; sub: string };
  ceiling: AuthorityEntry[];
  /**
   * @spec mission-template#the-mission-template, mission#standing-consent-bases
   * — the Dispatch Policy the human consents to, named by `id` and `version`.
   * The Mission Issuer commits it as an activation policy reference whose
   * `digest` it computes from the snapshot it holds; a request-body digest is
   * never a fact.
   */
  dispatch_policy: { id: string; version: string };
  /** `allowed_dispatchers`: a non-empty array of `client_id` strings. */
  dispatchers: string[];
  recipients: TemplateRecipients;
  per_instance_lifetime_s: number;
  max_active: number;
  rate_per_min: number;
  /**
   * @spec mission-template#the-mission-template — `review_cadence`: the
   * maximum age, in seconds, of the template's most recent human approval
   * before Dispatch stops (@spec mission-template#template-consent).
   */
  review_cadence_s: number;
  approval_event_id: string;
  expires_at: string;
}

/**
 * A template proposed for consent: the body without the approver and the
 * approval event, which the human consent supplies (@spec
 * mission-template#template-consent).
 */
export type TemplateProposalBody = Omit<CreateTemplateInput, "approver" | "approval_event_id">;

const nonEmptyString = (v: unknown): v is string => typeof v === "string" && v.length > 0;

/**
 * @spec mission-template#the-mission-template — the typed `allowed_dispatchers`
 * and `allowed_recipients` entries, refused at template consent when malformed.
 */
function assertDispatchersAndRecipients(input: TemplateProposalBody): void {
  if (!Array.isArray(input.dispatchers) || input.dispatchers.length === 0 || !input.dispatchers.every(nonEmptyString)) {
    throw new TemplateError("template dispatchers must be a non-empty array of client_id strings");
  }
  const r = input.recipients as unknown;
  if (r === null || typeof r !== "object" || Array.isArray(r)) {
    throw new TemplateError("template recipients must be an object with subjects and agents");
  }
  const { subjects, agents } = r as Partial<TemplateRecipients>;
  if (
    !Array.isArray(subjects) ||
    subjects.length === 0 ||
    !subjects.every((s) => s !== null && typeof s === "object" && nonEmptyString(s.iss) && nonEmptyString(s.sub))
  ) {
    throw new TemplateError("template recipients.subjects must be a non-empty array of {iss, sub}");
  }
  if (!Array.isArray(agents) || agents.length === 0 || !agents.every(nonEmptyString)) {
    throw new TemplateError("template recipients.agents must be a non-empty array of client_id strings");
  }
}

/**
 * @spec mission-template#the-mission-template, mission-template#template-consent:
 * the checks on a template body that need no approver, refused at a
 * proposal and again at consent: the same body is refused at both.
 */
export function assertTemplateBody(input: TemplateProposalBody): void {
  if (!Array.isArray(input.ceiling) || input.ceiling.length === 0) {
    throw new TemplateError("template ceiling must be non-empty");
  }
  // @spec resource-access#entry-validation (#1278, D457): a template ceiling
  // entry carrying `locations`, whatever its value, is refused at consent,
  // naming the entry, rather than stored and refused only at dispatch.
  input.ceiling.forEach((entry, i) => {
    const member = refusedEntryMember(entry);
    if (member !== undefined) {
      throw new TemplateError(`ceiling[${i}] carries ${member}, which the mission_resource_access type does not use`);
    }
    // @spec mission#subset (#1399, D538): likewise any member outside the
    // supported set, which dispatch derivation would otherwise drop.
    const unsupported = unsupportedEntryMember(entry);
    if (unsupported !== undefined) {
      throw new TemplateError(
        `ceiling[${i}] carries ${unsupported}, which is not a supported member of the mission_resource_access type`,
      );
    }
    // @spec resource-access#resource-access-type (D634): likewise a
    // `delegation` member this authorization server does not implement, which
    // dispatch derivation would otherwise carry unchanged.
    const delegationMember = unsupportedDelegationMember(entry);
    if (delegationMember !== undefined) {
      throw new TemplateError(
        `ceiling[${i}] carries ${delegationMember}, which is not a supported delegation member`,
      );
    }
    // @spec resource-access#entry-validation (#1310, #1376, #1625): the
    // per-entry rules proposal intake applies, so the Approver never consents
    // to, and dispatch never derives from, an entry no proposal could carry.
    if (typeof entry.resource !== "string" || !isAbsoluteUri(entry.resource)) {
      throw new TemplateError(
        `ceiling[${i}] has resource ${JSON.stringify(entry.resource)}, which is not an RFC 3986 absolute URI`,
      );
    }
    if (carriesHttpUserinfo(entry.resource)) {
      throw new TemplateError(`ceiling[${i}] has resource ${JSON.stringify(entry.resource)}, which carries a userinfo subcomponent`);
    }
    const malformedAction = actionOutsideGrammar(entry);
    if (malformedAction !== undefined) {
      throw new TemplateError(
        `ceiling[${i}] has action ${JSON.stringify(malformedAction)}, which is neither an action identifier nor an action family`,
      );
    }
    // @spec resource-access#subset (#1377, D538, D684): likewise an action
    // family, unsupported input refused at consent rather than at dispatch.
    const family = unsupportedActionFamily(entry);
    if (family !== undefined) {
      throw new TemplateError(`ceiling[${i}] carries the action family ${family}, which this authorization server does not support`);
    }
    // @spec resource-access#resource-contract (#249, D553): template consent
    // does not assemble or validate a contract reference against
    // configuration, so this surface takes the conformance alternative: "An
    // authorization server that does not implement this section refuses a
    // proposed or carried entry that carries `resource_contract` ... and never
    // drops the member."
    if (entry.resource_contract !== undefined) {
      throw new TemplateError(
        `ceiling[${i}] carries resource_contract, which template consent does not assemble from configuration; refusing rather than dropping it`,
      );
    }
  });
  // @spec resource-access#matching-allowed-delegates, child-delegation#fanout
  // (#1373): a template ceiling entry whose `allowed_delegates` or
  // `allowed_child_actors` carries a malformed delegate matcher is refused at
  // consent, naming the entry, rather than stored and refused only when a
  // dispatch derives from it.
  input.ceiling.forEach((entry, i) => {
    const violation = entryDelegateMatcherViolation(entry);
    if (violation !== undefined) throw new TemplateError(`ceiling[${i}] ${violation}`);
  });
  if (input.per_instance_lifetime_s <= 0 || !Number.isFinite(input.per_instance_lifetime_s)) {
    throw new TemplateError("per_instance_lifetime_s must be a positive number of seconds");
  }
  if (input.max_active <= 0 || !Number.isInteger(input.max_active)) {
    throw new TemplateError("max_active must be a positive integer");
  }
  if (input.rate_per_min <= 0 || !Number.isInteger(input.rate_per_min)) {
    throw new TemplateError("rate_per_min must be a positive integer");
  }
  if (!Number.isInteger(input.review_cadence_s) || input.review_cadence_s <= 0) {
    throw new TemplateError("review_cadence_s must be a positive integer number of seconds");
  }
  assertDispatchersAndRecipients(input);
  const named = input.dispatch_policy as unknown;
  if (
    !named ||
    typeof named !== "object" ||
    !nonEmptyString((named as { id?: unknown }).id) ||
    !nonEmptyString((named as { version?: unknown }).version)
  ) {
    throw new TemplateError("dispatch_policy must be an object with a non-empty id and version");
  }
}

/**
 * @spec capability-binding#conformance: the Template Ceiling a template
 * commits. At this trusted establishment boundary, request-body bindings are
 * never facts: every caller-supplied capability binding is discarded and the
 * trusted bindings are resolved fresh. The consent page renders this ceiling,
 * so the human reviews what the template commits.
 */
export function templateCeiling(ceiling: AuthorityEntry[], resolver?: CapabilitySourceResolver): AuthorityEntry[] {
  return resolver
    ? resolveFreshCapabilitySources(ceiling.map(({ capability_sources: _drop, ...entry }) => entry), resolver)
    : ceiling;
}

/**
 * @spec mission#standing-consent-bases: the consented template commits the
 * Dispatch Policy's content: the issuer mints the reference from the snapshot
 * it holds for that id and version, and refuses a policy it does not hold.
 */
export function pinDispatchPolicy(
  issuer: string,
  dispatchPolicies: DispatchPolicies | undefined,
  named: { id: string; version: string },
): NonNullable<ReturnType<typeof mintActivationPolicyRef>> {
  const dispatch_policy = mintActivationPolicyRef(issuer, dispatchPolicies, named.id, named.version);
  if (!dispatch_policy) {
    throw new TemplateError(`dispatch_policy ${named.id} version ${named.version} is not a Dispatch Policy this issuer holds`);
  }
  // @spec mission-template#template-consent, derivation-limits#effective-limit
  // (#1119, D327): the Dispatch Policy states the per-instance derivation-limit
  // maximum the consent commits under `template_hash`. A malformed statement
  // is refused here, at consent, never discovered at a dispatch.
  const held = dispatchPolicies?.[named.id];
  if (held && standingConsentMaximumOf(held) === undefined) {
    throw new TemplateError(
      `dispatch_policy ${named.id} states a malformed ${STANDING_CONSENT_LIMIT_MEMBER}: an integer of at least 1, or null`,
    );
  }
  return dispatch_policy;
}

/**
 * @spec mission-template — create (consent to) a Mission Template.
 * `template_hash = computeAnchor(MISSION_TEMPLATE_TYP, issuer, body)` commits to
 * the consented body. IDEMPOTENT by `approval_event_id`: a repeat returns the
 * template that approval already created (so a retried consent never mints a
 * second template nor a mismatched hash).
 *
 * @spec mission#approval-event (step 3), mission#authority-sources — template
 * consent IS an approval event, so it establishes the template's
 * `authority_source` from the injected trusted catalog, keyed on the
 * `recipients` (each recipient Subject through each recipient Agent, #827)
 * and never from the request body. Each pair commits its own root, and every
 * pair MUST share one provenance, or the template is refused: a template
 * whose instances would draw on two kinds of authority has no single
 * provenance to inherit. The established source and the per-recipient roots
 * are provenance and stay OUTSIDE `template_hash`, exactly as
 * `authority_source` stays outside both Mission anchors.
 */
export function createTemplate(
  store: TemplateStore,
  input: CreateTemplateInput,
  options: {
    authoritySourceCatalog: BoundAuthoritySourceCatalog;
    authoritySourceResolver?: AuthoritySourceResolver;
    capabilityResolver?: CapabilitySourceResolver;
    /**
     * @spec mission#standing-consent-bases — the Dispatch Policies this issuer
     * holds; the template commits the named policy's snapshot digest.
     */
    dispatchPolicies?: DispatchPolicies;
    /**
     * @spec mission#transformation-capabilities (#1503 finding 7, D733): the
     * audiences the trusted mapping assigns each ceiling entry at this
     * consent ({@link MissionKernel.mappedEntryAudiences}), retained with the
     * template. Absent, or returning undefined, the template retains no
     * association, and its instances carry no entry in any token.
     */
    entryAudiences?: (entries: readonly AuthorityEntry[]) => string[][] | undefined;
    /**
     * @spec mission-template#prohibited-classes (#813): present exactly where
     * the `standing-payment-dispatch` capability is on. A template whose
     * Dispatch Policy designates the standing payment is then created only
     * from a human consent at the approval floor, with its ceiling and bounds
     * meeting the workflow's conditions and its budget identity pinned.
     */
    standingPayment?: StandingPaymentConsentOptions;
  },
): MissionTemplate {
  assertTemplateBody(input);

  // @spec mission#approval-event (step 3), mission#authority-sources (#829) ,
  // the approver is a principal of this deployment's issuer namespace, checked
  // BEFORE the idempotency return: a retry carrying a foreign or malformed
  // approver under a known approval event is refused, never handed the
  // template that event created. Only the namespace is checked here;
  // activation (gate 2) still runs only for a new template, so a legitimate
  // retry after the template expired or was revoked returns it unchanged.
  try {
    assertLocalPrincipal(options.authoritySourceCatalog, input.approver, "approver");
  } catch (e) {
    throw new TemplateError((e as Error).message);
  }

  // Idempotency first: return the already-consented template unchanged rather
  // than recomputing the hash (a body change would need a NEW approval event).
  const existing = store.getByApprovalEvent(input.approval_event_id);
  if (existing) return existing;

  const { authority_source, source_bindings } = establishTemplateAuthoritySource(input, options);
  const ceiling = templateCeiling(input.ceiling, options.capabilityResolver);

  const dispatch_policy = pinDispatchPolicy(input.issuer, options.dispatchPolicies, input.dispatch_policy);
  // @spec mission-template#template-consent (#813): the consent provenance
  // of a standing-payment template, retained outside `template_hash`.
  const consent_provenance = standingPaymentConsentOf(
    input,
    ceiling,
    verifiedActivationPolicy(input.issuer, options.dispatchPolicies, dispatch_policy),
    options.standingPayment,
  );
  const templateBody = {
    template_version: input.template_version,
    ceiling,
    dispatch_policy,
    dispatchers: input.dispatchers,
    recipients: input.recipients,
    per_instance_lifetime_s: input.per_instance_lifetime_s,
    max_active: input.max_active,
    rate_per_min: input.rate_per_min,
    review_cadence_s: input.review_cadence_s,
    approver: input.approver,
    expires_at: input.expires_at,
  };
  const template_hash = computeAnchor(
    MISSION_TEMPLATE_TYP,
    input.issuer,
    templateBody as unknown as JsonValue,
  );
  const id = `tmpl_${randomBytes(18).toString("base64url")}`;
  // @spec mission#transformation-capabilities (D733 ruling 2): template
  // consent is the approval event every instance draws on, so the ceiling's
  // association is retained here, outside `template_hash`.
  const ceiling_audiences = options.entryAudiences?.(ceiling);
  const create: TemplateCreate = {
    ...input,
    ceiling,
    dispatch_policy,
    id,
    template_hash,
    authority_source,
    source_bindings,
    ...(ceiling_audiences ? { ceiling_audiences } : {}),
    ...(consent_provenance ? { consent_provenance } : {}),
  };
  return store.create(create);
}

/**
 * @spec mission-template#prohibited-classes, mission-template#template-consent
 * (#813): what a standing-payment template's consent needs under the
 * `standing-payment-dispatch` capability.
 */
export interface StandingPaymentConsentOptions {
  /**
   * The provenance the approval surface established for this consent: the
   * Approver's login on the browser surface at the approval floor, under the
   * render revision the decision approved. Absent on the service-token
   * stand-in and the boot seed, which therefore never create one.
   */
  consent?: TemplateConsentProvenance;
  /** Whether `sub` is a registered client (an Agent or Dispatcher), which never consents. */
  isClient?: (sub: string) => boolean;
  /** The kernel's standing-payment store, where the budget identity is pinned. */
  budgets?: StandingPaymentStore;
  /** The consent instant's clock; the system clock when absent. */
  now?: () => Date;
}

/**
 * @spec mission-template#prohibited-classes, mission-template#template-consent
 * (#813, D830 ruling 1): a template whose committed Dispatch Policy designates
 * the standing payment is consented only by a human at the approval floor on
 * the approval surface, never a Dispatcher, an Agent, an agent-held key or an
 * assertion; its ceiling and bounds meet the workflow's conditions; and its
 * budget identity is the one pinned for that policy id, so a re-consent or a
 * policy successor never silently starts a fresh counter. Returns the
 * provenance to retain, or undefined for a template that does not designate
 * the workflow (or where the capability is off).
 */
function standingPaymentConsentOf(
  input: CreateTemplateInput,
  ceiling: readonly AuthorityEntry[],
  held: DispatchPolicy | undefined,
  options: StandingPaymentConsentOptions | undefined,
): TemplateConsentProvenance | undefined {
  if (!options || !held) return undefined;
  let terms: StandingPaymentTerms | undefined;
  try {
    terms = standingPaymentTermsOf(held);
  } catch (e) {
    throw new TemplateError(`dispatch_policy ${input.dispatch_policy.id}: ${(e as Error).message}`);
  }
  if (!terms) return undefined;
  const consent = options.consent;
  if (
    !consent ||
    !isHumanFloorConsent(consent) ||
    consent.principal.iss !== input.approver.iss ||
    consent.principal.sub !== input.approver.sub
  ) {
    throw new TemplateError(
      "a standing-payment template is consented only by a human Approver at the approval floor on the approval surface; this consent establishes none",
    );
  }
  const sub = consent.principal.sub;
  if (input.dispatchers.includes(sub) || input.recipients.agents.includes(sub) || options.isClient?.(sub) === true) {
    throw new TemplateError(
      `the consenting principal ${sub} is a Dispatcher or an Agent; a standing-payment template is consented by a human`,
    );
  }
  try {
    assertStandingPaymentTemplateBounds(input);
    assertStandingPaymentCeiling(terms, ceiling, "the Template Ceiling");
  } catch (e) {
    if (e instanceof StandingPaymentTermsError) throw new TemplateError(e.message);
    throw e;
  }
  if (!options.budgets) {
    throw new TemplateError("no standing-payment budget store is configured, so the budget identity cannot be pinned");
  }
  try {
    options.budgets.bindBudget(input.dispatch_policy.id, terms.budget, (options.now?.() ?? new Date()).toISOString());
  } catch (e) {
    if (e instanceof StandingPaymentBudgetError) throw new TemplateError(e.message);
    throw e;
  }
  return consent;
}

/**
 * @spec mission#approval-event (step 3) — gates 1 and 2 at template consent.
 * Gate 3 (the source ceiling) and gate 4 (subject discipline) belong to
 * DISPATCH: a template ceiling is standing consent, and both the derived set
 * an instance commits and the Subject it acts for exist only per instance.
 */
function establishTemplateAuthoritySource(
  input: CreateTemplateInput,
  options: { authoritySourceCatalog: BoundAuthoritySourceCatalog; authoritySourceResolver?: AuthoritySourceResolver },
): { authority_source: AuthoritySource; source_bindings: TemplateSourceBinding[] } {
  const catalog = options.authoritySourceCatalog;
  const resolver = options.authoritySourceResolver ?? catalogAuthoritySourceResolver(catalog);
  if (input.recipients.agents.length === 0) {
    throw new TemplateError("template recipients.agents must be non-empty");
  }
  // @spec mission#authority-sources (#827): resolve every recipient Subject
  // through every recipient Agent, through the same resolver an approval
  // uses, and record each pair's root. The pairs may resolve different roots
  // (two people sharing one agent registration), but they share ONE
  // provenance, or no template: the template's `authority_source` is the one
  // provenance every instance inherits. Gate 2 runs once per distinct root.
  let provenance: AuthoritySource | undefined;
  let provenanceBytes: string | undefined;
  const activated = new Set<string>();
  const source_bindings: TemplateSourceBinding[] = [];
  for (const subject of input.recipients.subjects) {
    for (const agent of input.recipients.agents) {
      let resolved: AuthoritySourceResolution;
      try {
        resolved = resolveApprovalSource(catalog, resolver, {
          deployment: catalog.deployment,
          subject,
          clientId: agent,
        });
      } catch (e) {
        throw new TemplateError((e as Error).message);
      }
      const bytes = canonicalize(resolved.provenance as unknown as JsonValue);
      if (provenanceBytes !== undefined && bytes !== provenanceBytes) {
        throw new TemplateError(
          "template recipients draw on more than one authority source; a template has one source",
        );
      }
      provenance = resolved.provenance;
      provenanceBytes = bytes;
      if (!activated.has(resolved.rootId)) {
        try {
          assertApproverMayActivate(catalog, resolved.entry, input.approver);
        } catch (e) {
          throw new TemplateError((e as Error).message);
        }
        activated.add(resolved.rootId);
      }
      source_bindings.push({
        subject: { iss: resolved.principal.iss, sub: resolved.principal.sub },
        agent,
        binding: bindingOf(resolved),
      });
    }
  }
  return { authority_source: provenance as AuthoritySource, source_bindings };
}

export interface DispatchInput {
  /** The Mission Template to instantiate from. */
  templateId: string;
  /**
   * @spec mission-template#dispatch — the caller-supplied dispatch event
   * identifier: with the Dispatcher, the reservation key of the creation
   * idempotency apparatus (`op: dispatch`). A retried Dispatch (same key, same
   * fingerprint) returns the same instance; the same key with a different
   * fingerprint is refused. The instance's `approval_event_id` is allocated
   * per reservation, never derived from this identifier.
   */
  dispatchEventId: string;
  /**
   * The creation idempotency store the reservation lives in (the adapter's
   * shared store; a fresh store over `kernel` when absent). Its retention is
   * the published retry horizon: once a key's tombstone expires, the key
   * admits a new reservation and a new instance.
   */
  idempotency?: CreationIdempotencyStore;
  /** The Dispatcher's verified presenter confirmation (DPoP `jkt`), the fingerprint's `cnf`. */
  presenterJkt?: string;
  /** The presented Intent Submission Evidence entries, for the fingerprint's `evidence`. */
  presentedEvidence?: IntentSubmissionEvidenceEntry[];
  /** The dispatching actor; MUST be in the template's `dispatchers`. */
  dispatcher: string;
  /**
   * @spec mission-template#the-mission-template, mission#standing-consent-bases
   * — the deployment's held Dispatch Policy snapshots. Dispatch verifies the
   * template's committed digest against the named snapshot and reads the Agent
   * selection rule of a template that lists several Agents from that snapshot
   * alone. The caller never names the Agent: the Mission Issuer selects it
   * ({@link selectDispatchAgent}).
   */
  dispatchPolicies?: DispatchPolicies;
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
  /**
   * @spec mission-template#prohibited-classes (#813): present exactly where
   * the `standing-payment-dispatch` capability is on. A template whose
   * committed Dispatch Policy designates the standing payment then dispatches
   * through the capability-aware admission; every other template, and every
   * template with the capability off, dispatches exactly as without it.
   */
  standingPayment?: StandingPaymentDispatchOptions;
}

/** @spec mission-template#prohibited-classes (#813): the standing-payment admission's inputs. */
export interface StandingPaymentDispatchOptions {
  /** The deployment's published prohibited-predicate mapping. */
  mapping: ProhibitedPredicateMapping;
}

export interface DispatchResult {
  mission: MissionRecord;
  template: MissionTemplate;
  /**
   * Set only when the result recovers a recorded Dispatch: the delivery the
   * adapter recorded for it ({@link recordDispatchDelivery}), if any.
   */
  recovered?: { delivery?: Record<string, unknown> };
}

/**
 * @spec mission-template#the-mission-template, mission#standing-consent-bases
 * — a deployment Dispatch Policy: the exact snapshot the Mission Issuer holds
 * and evaluates, whose digest a template commits. The policy IS its snapshot:
 * no rule is evaluated from anywhere else, so a change to what Dispatch does
 * is a change to the committed bytes. Its Agent selection rule, for a template
 * whose `allowed_recipients` lists more than one Agent, is the JSON snapshot's
 * `select_agent` member: the `client_id` it names ({@link selectDispatchAgent}).
 */
export type DispatchPolicy = RegisteredActivationPolicy;

/** The deployment's Dispatch Policies, keyed by a template's `dispatch_policy.id`. */
export type DispatchPolicies = Readonly<Record<string, DispatchPolicy>>;

/**
 * @spec mission-template#the-mission-template — select a dispatched
 * instance's Agent: the one listed Agent directly; with several, the Agent the
 * template's Dispatch Policy selection rule names. `agents` is an allowlist,
 * not a selection rule, so its order is never consulted. The rule is read only
 * from the held snapshot whose digest the template committed
 * (@spec mission#standing-consent-bases): a snapshot that no longer matches
 * selects nothing. The rule sees only that snapshot, never Dispatcher input.
 * Undefined when no Agent can be selected.
 */
export function selectDispatchAgent(template: MissionTemplate, policies?: DispatchPolicies): string | undefined {
  const { agents } = template.recipients;
  if (agents.length === 1) return agents[0];
  if (!activationPolicyMatches(template.issuer, policies, template.dispatch_policy)) return undefined;
  const policy = (policies as DispatchPolicies)[template.dispatch_policy.id] as DispatchPolicy;
  return selectionRuleOf(policy);
}

/** The JSON snapshot's `select_agent` member, when it is a non-empty string. */
function selectionRuleOf(policy: DispatchPolicy): string | undefined {
  if (policy.content_type !== "application/json") return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(policy.content);
  } catch {
    return undefined;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
  const agent = (parsed as { select_agent?: unknown }).select_agent;
  return nonEmptyString(agent) ? agent : undefined;
}

/**
 * @spec mission-template#dispatch — instantiate an ordinary Mission from a
 * template. Structure mirrors {@link createChildMission}: resolve the template,
 * idempotency-guard, gate, derive-and-prove authority, clamp expiry, assemble
 * lineage, insert. The gates (in order): idempotency, template active + not
 * expired, review not overdue, dispatcher allowed, Agent selected, recipient
 * allowed, max-active, rate, double intersection, prohibited-class.
 */
/** The Dispatch's idempotency context: its template, store, fingerprint, and recovery. */
interface DispatchIdempotency {
  template: MissionTemplate;
  idem: CreationIdempotencyStore;
  presenterJkt: string;
  fingerprint: string;
  recover(op: NonNullable<ReturnType<CreationIdempotencyStore["find"]>>): DispatchResult;
  /** The recorded Dispatch for this key, recovered; undefined when the key is free. */
  lookup(): DispatchResult | undefined;
}

function dispatchIdempotency(kernel: MissionKernel, store: TemplateStore, input: DispatchInput): DispatchIdempotency {
  const template = store.get(input.templateId);
  // Unknown template: a plain Error (mirrors createChildMission's unknown
  // parent), NOT a DispatchError — the reason union has no "unknown" member.
  if (!template) throw new Error(`unknown template ${input.templateId}`);

  // @spec mission-template#dispatch — the creation idempotency apparatus under
  // `op: dispatch`: reservation key (authenticated Dispatcher,
  // dispatch_event_id), fingerprint over the parsed inputs with `source` the
  // template_id. The reservation, not the identifier, carries idempotency.
  const idem = input.idempotency ?? new CreationIdempotencyStore(kernel);
  const presenterJkt = input.presenterJkt ?? "";
  const fingerprint = creationFingerprint({
    op: "dispatch",
    iss: template.issuer,
    client: input.dispatcher,
    source: template.id,
    cnf: { jkt: presenterJkt },
    intent: input.intent,
    ...(input.proposedAuthority?.length ? { proposal: input.proposedAuthority } : {}),
    ...(input.presentedEvidence?.length ? { evidence: input.presentedEvidence } : {}),
  });
  /** Recover a recorded Dispatch, or refuse a reused key with a different fingerprint. */
  const recover = (op: NonNullable<ReturnType<CreationIdempotencyStore["find"]>>): DispatchResult => {
    if (op.op !== "dispatch" || op.fingerprint !== fingerprint) {
      throw new DispatchMismatchError(
        `dispatch_event_id ${input.dispatchEventId} was already used for a different dispatch request`,
      );
    }
    const recorded = op.missionId ? kernel.get(op.missionId) : undefined;
    if (!recorded) throw new Error(`recorded dispatch instance ${op.missionId ?? "(none)"} not found`);
    return { mission: recorded, template, recovered: op.delivery ? { delivery: op.delivery } : {} };
  };
  const lookup = (): DispatchResult | undefined => {
    // @spec mission#authority-sources (#829): the instance's Subject is a
    // principal of this deployment's issuer namespace, checked BEFORE the
    // idempotency return: a retry carrying a foreign or malformed Subject under
    // a known dispatch id is refused, never handed the instance that id
    // created. Only the namespace is checked here; gate 4 (subject discipline)
    // still runs only for a new instance.
    kernel.assertDeploymentPrincipal(input.subject, "subject");
    // Look up (Dispatcher, dispatch_event_id): another Dispatcher's identical
    // dispatch_event_id is a different key. A reused key with a different
    // fingerprint (another template, intent, proposal, evidence or presenter
    // key) is refused, never handed the recorded instance.
    const existing = idem.find(input.dispatcher, input.dispatchEventId);
    return existing ? recover(existing) : undefined;
  };
  return { template, idem, presenterJkt, fingerprint, recover, lookup };
}

/**
 * @spec mission-template#dispatch, mission#intent-submission-evidence — the
 * completed-operation recovery lookup alone, for an adapter that must recover
 * a completed Dispatch BEFORE re-verifying its Intent Submission Evidence (an
 * artifact that expired after completion MUST NOT break recovery). Returns the
 * recorded instance, undefined when the key admits a new Dispatch, or throws
 * {@link DispatchMismatchError}.
 */
export function findDispatch(kernel: MissionKernel, store: TemplateStore, input: DispatchInput): DispatchResult | undefined {
  return dispatchIdempotency(kernel, store, input).lookup();
}

/**
 * @spec mission-template#grant-type, expansion#creation-recovery: record the
 * access token a Dispatch delivered under its reservation key (authenticated
 * Dispatcher, dispatch_event_id), so a retry recovers that delivery instead of
 * deriving again.
 */
export function recordDispatchDelivery(
  kernel: MissionKernel,
  input: Pick<DispatchInput, "dispatcher" | "dispatchEventId" | "idempotency">,
  delivery: Record<string, unknown>,
): void {
  (input.idempotency ?? new CreationIdempotencyStore(kernel)).recordDelivery(
    input.dispatcher,
    input.dispatchEventId,
    delivery,
  );
}

export function dispatchFromTemplate(
  kernel: MissionKernel,
  store: TemplateStore,
  input: DispatchInput,
): DispatchResult {
  const { template, idem, presenterJkt, fingerprint, recover, lookup } = dispatchIdempotency(kernel, store, input);

  // a. Idempotency BEFORE the gates, so a retry after the template was
  // revoked/expired, or its review fell overdue, still returns the instance
  // the first Dispatch created.
  const recovered = lookup();
  if (recovered) return recovered;

  // @spec mission#standing-consent-bases, mission-template#dispatch — the
  // instance's approval_event_id identifies THIS Dispatch: allocated with the
  // reservation and retained with the instance, never derived from the
  // reusable dispatch_event_id, so a key reused after its tombstone expires
  // creates a new instance under a new value.
  const approvalEventId = `dsp_${randomBytes(16).toString("base64url")}`;

  // @spec mission#approval-event (step 4) — ONE clock read for the whole
  // dispatch: the gates below, the instance's `created_at`, and the
  // `per_instance_lifetime_s` addend are all measured from this instant, so the
  // lifetime a dispatched instance gets is exactly the lifetime its record
  // records.
  const nowIso = kernel.nowDate().toISOString();
  const nowMs = Date.parse(nowIso);

  // b. Template gate.
  if (template.state !== "active") {
    throw new DispatchError("template_not_active", `template ${template.id} is ${template.state}`);
  }
  if (Date.parse(template.expires_at) <= nowMs) {
    throw new DispatchError("template_not_active", `template ${template.id} is expired`);
  }
  // @spec mission-template#template-consent — standing consent decays: no
  // dispatch from a template whose most recent human approval is OLDER than
  // its `review_cadence` (strictly: at exactly the bound, dispatch proceeds).
  // The approval instant is the template's `created_at`, the same instant
  // every instance records as `approval_basis.approved_at`. A fresh human
  // approval re-consents as a new template.
  if (nowMs - Date.parse(template.created_at) > template.review_cadence_s * 1000) {
    throw new DispatchError(
      "review_overdue",
      `template ${template.id} approval is older than its review cadence of ${template.review_cadence_s}s`,
    );
  }
  if (!template.dispatchers.includes(input.dispatcher)) {
    throw new DispatchError("dispatcher_not_allowed", `dispatcher ${input.dispatcher} is not permitted`);
  }
  // @spec mission-template#dispatch (step 3), mission#standing-consent-bases —
  // verify the Dispatch Policy snapshot this issuer would evaluate against the
  // `digest` the template committed: a policy edited after consent, even
  // under an unchanged version, never adjudicates a Dispatch. The verified
  // snapshot is retained with the instance below.
  const dispatchPolicy = verifiedActivationPolicy(template.issuer, input.dispatchPolicies, template.dispatch_policy);
  if (!dispatchPolicy) {
    throw new DispatchError(
      "dispatch_policy_changed",
      `template ${template.id} dispatch policy ${template.dispatch_policy.id} no longer matches its committed digest`,
    );
  }
  // #1119: consent refuses a malformed maximum, so a verified snapshot states
  // a usable one; a template consented before that check is re-consented.
  const dispatchMaximum = standingConsentMaximumOf(dispatchPolicy);
  if (!dispatchMaximum) {
    throw new DispatchError(
      "dispatch_policy_changed",
      `template ${template.id} dispatch policy ${template.dispatch_policy.id} states no usable ${STANDING_CONSENT_LIMIT_MEMBER}; re-consent the template`,
    );
  }
  // @spec mission-template#prohibited-classes (#813): under the
  // `standing-payment-dispatch` capability, a template whose verified
  // Dispatch Policy states standing-payment terms dispatches through the
  // capability-aware admission below. A statement that no longer parses
  // admits nothing.
  let standing: StandingPaymentTerms | undefined;
  if (input.standingPayment) {
    try {
      standing = standingPaymentTermsOf(dispatchPolicy);
    } catch (e) {
      throw new DispatchError(
        "dispatch_prohibited_class",
        `template ${template.id} dispatch policy ${template.dispatch_policy.id} states unusable standing-payment terms: ${(e as Error).message}`,
      );
    }
  }
  // @spec metering#bounds (#813, ruling 2): `max_budget` is a standing-payment
  // instance's bound; on any other dispatch nothing would meter it.
  if (input.intent.max_budget !== undefined && !standing) {
    throw new IntentError("invalid_request", "max_budget is admitted only on the dispatch of a standing-payment template");
  }
  // @spec mission-template#the-mission-template — the Mission Issuer selects
  // the instance's Agent under the Dispatch Policy, never from Dispatcher
  // input. It is committed below as the instance's `client_id`; a retried
  // Dispatch returns the committed instance at the idempotency check above
  // and never selects again.
  const recipient = selectDispatchAgent(template, input.dispatchPolicies);
  if (recipient === undefined) {
    throw new DispatchError(
      "agent_not_selected",
      `template ${template.id} lists several agents and its dispatch policy selects none`,
    );
  }
  // `allowed_recipients`: the selected Agent must be a listed agent (a policy
  // that names an unlisted one is refused), and the established Subject must
  // equal a listed subject in BOTH `iss` and `sub`; the lists are independent.
  if (!template.recipients.agents.includes(recipient)) {
    throw new DispatchError("recipient_not_allowed", `recipient ${recipient} is not permitted`);
  }
  if (!template.recipients.subjects.some((s) => s.iss === input.subject.iss && s.sub === input.subject.sub)) {
    throw new DispatchError(
      "recipient_not_allowed",
      `subject ${input.subject.iss} ${input.subject.sub} is not a permitted recipient`,
    );
  }
  // max-active: count non-terminal instances (store rows filtered by the
  // OBSERVED kernel state: an instance past its `expires_at` is terminated
  // whether or not that transition has been persisted).
  const isTerminal = (missionId: string): boolean => {
    const m = kernel.observedRecord(missionId);
    return !m || TERMINAL_STATES.has(m.state);
  };
  const sinceIso = new Date(nowMs - 60_000).toISOString();
  /** The concurrency and rate bounds over `dispatched` instances and the trailing 60s `recent` count. */
  const assertDispatchBounds = (dispatched: readonly string[] | number, recent: number): void => {
    const active = typeof dispatched === "number" ? dispatched : dispatched.filter((m) => !isTerminal(m)).length;
    if (active >= template.max_active) {
      throw new DispatchError(
        "max_active_exceeded",
        `template ${template.id} has ${active} active instances (max ${template.max_active})`,
      );
    }
    // rate: dispatches in the trailing 60s window.
    if (recent >= template.rate_per_min) {
      throw new DispatchError(
        "rate_exceeded",
        `template ${template.id} exceeded ${template.rate_per_min} dispatches/min`,
      );
    }
  };
  // @spec mission-template#prohibited-classes (#813): a standing payment's
  // bounds are read from, and its dispatch counted in, the kernel database
  // inside the instance's creation transaction (below), never the template
  // store's own database after it.
  if (!standing) {
    assertDispatchBounds(store.activeInstanceCount(template.id, isTerminal), store.dispatchesSince(template.id, sinceIso));
  }

  // c. Double intersection. FIRST: derive under the kernel's derivation policy
  // (the untrusted intent, bounded by the dispatcher's proposal where one was
  // submitted, @spec mission#authority-proposal). An intent empty under the
  // POLICY throws IntentError here and is deliberately NOT caught — it must
  // surface exactly as it would from kernel.approve, not be mislabeled
  // out_of_template_ceiling.
  const proposal = input.proposedAuthority?.length ? input.proposedAuthority : undefined;
  const first = kernel.deriveWithProvenance(input.intent, proposal);
  const derived = first.entries;
  // SECOND: re-derive that set under a synthetic policy whose ceiling is the
  // template's. Reusing deriveAuthoritySet gives a result that is a subset of
  // both the derived set and the template ceiling. An empty result here IS the
  // template ceiling refusing the intent.
  let final: AuthorityEntry[];
  // @spec resource-access#delegate-eligibility: each instance entry keeps the
  // origin its policy derivation recorded and the template ceiling entry's,
  // index-aligned with `final` through the capability inheritance below.
  let provenance: RetainedOrigin[];
  // @spec child-delegation#fanout (#1304): the child-actor origins, the same
  // way and kept apart: a template ceiling `children` grant without
  // `allowed_child_actors` defers to the child-creation policy even where the
  // policy derivation took a list.
  let childActorProvenance: RetainedOrigin[];
  try {
    // The policy-derived set plays the PROPOSAL role for the second
    // derivation (the third parameter, @spec mission#authority-proposal
    // carriage: the Intent itself carries no authority members), narrowing it
    // under the template ceiling.
    ({ entries: final, provenance, childActorProvenance } = deriveAuthoritySetWithProvenance(
      input.intent,
      { policy_version: template.template_version, ceiling: template.ceiling },
      derived,
      first.provenance,
      first.childActorProvenance,
    ));
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
  // The `derived` half runs on the PRE-INHERITANCE set, and must stay there:
  // derivation never reads `capability_sources`, so the policy-derived set
  // structurally carries none and an inherited binding would read as one the
  // grantor lacks. Keep the two halves separate; recombining them refuses
  // every dispatch from a ceiling that records a binding.
  if (!isSubsetSet(final, derived)) {
    throw new Error(`dispatch from ${template.id} violated the double-intersection invariant`);
  }
  // @spec capability-binding#capability-source-binding — carry the template
  // ceiling's recorded bindings for every retained catalog-sourced action,
  // before the ceiling half of the invariant and before `authority_hash`
  // below. The consenting human's ceiling is the grantor; the dispatcher's
  // proposal contributes nothing here.
  final = inheritCapabilitySources(final, template.ceiling);
  if (!isSubsetSet(final, template.ceiling)) {
    throw new Error(`dispatch from ${template.id} violated the double-intersection invariant`);
  }

  // d. Prohibited-class guard: refuse high-consequence actions regardless of
  // ceiling membership. @spec mission-template#prohibited-classes (#813):
  // under the `standing-payment-dispatch` capability, a standing-payment
  // template's instance goes through the capability-aware admission instead;
  // every other dispatch keeps the configured refusal unchanged.
  if (standing && input.standingPayment) {
    const refusal = standingPaymentAdmissionRefusal(kernel, template, standing, input, final);
    if (refusal) throw new DispatchError("dispatch_prohibited_class", refusal);
  } else {
    const prohibited = new Set(input.dispatchProhibitedActions ?? []);
    if (prohibited.size > 0 && final.some((e) => e.actions.some((a) => prohibited.has(a)))) {
      throw new DispatchError(
        "dispatch_prohibited_class",
        `instance authority includes a dispatch-prohibited action`,
      );
    }
  }

  // @spec mission#authority-sources, mission#approval-event (step 3) — a
  // dispatched instance is a DRAWDOWN on the template's standing consent, so
  // it inherits the template's established `authority_source` verbatim: the
  // member is immutable, and re-establishing it per dispatch would let a
  // dispatch change provenance with no approval event. What re-runs at each
  // dispatch, against catalog and governance state current at that moment, is
  // gate 3 (the source ceiling, so a source narrowed since consent refuses)
  // and gate 4 (subject discipline, since the Subject is per instance). Both
  // run before the instance's anchors are computed.
  const authoritySource = template.authority_source;
  // @spec mission#authority-sources (#827): the instance inherits the root
  // its own recipient pair committed at consent: this Subject through the
  // selected Agent, never another recipient's root through a shared
  // registration.
  const recipientRoot = store.sourceBinding(template.id, input.subject, recipient);
  if (!recipientRoot) {
    throw new IntentError(
      "access_denied",
      `template ${template.id} committed no authority-source root for this recipient`,
    );
  }
  const resolvedRoot = kernel.assertInheritedAuthoritySource(recipientRoot, final);
  kernel.assertInheritedSubjectDiscipline(resolvedRoot, input.subject);

  // e. Build a NORMAL MissionRecord (as expansion.ts does). Anchors are over
  // the INSTANCE's own intent and `final` set (never the template body). The
  // approver is the TEMPLATE's approver: the human of record, not the
  // dispatcher. expires_at is established through the single effective-expiry
  // hook: the earliest of the requested ceiling, this deployment's
  // `max_mission_lifetime_s`, the template's own expiry, and
  // `created_at + per_instance_lifetime_s`, the addend measured from the exact
  // instant the instance commits.
  const expiresAt = kernel.resolveEffectiveExpiry({
    requested: input.intent.expires_at,
    createdAt: nowIso,
    ceilings: {
      template: {
        expiresAt: template.expires_at,
        instanceLifetimeS: template.per_instance_lifetime_s,
      },
    },
  });
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
    eligibility_provenance: provenance,
    child_actor_provenance: childActorProvenance,
    intent_hash: intentHash(template.issuer, input.intent as never),
    ...(proposal ? { proposal_hash: proposalHash(template.issuer, proposal as never) } : {}),
    ...(input.submissionEvidence?.length ? { submission_evidence: input.submissionEvidence } : {}),
    authority_hash: authorityHash(template.issuer, final as never),
    subject: input.subject,
    approval_basis: approvalBasis,
    authority_source: authoritySource,
    client_id: recipient,
    policy_version: input.policyVersion,
    approval_event_id: approvalEventId,
    created_at: nowIso,
    expires_at: expiresAt,
    version: 1,
    // @spec mission#derivation-issuance-policy — the dispatched instance's
    // own requested ceiling, clamped by this deployment's policy ceiling
    // exactly like an ordinary Mission approval. @spec
    // mission-template#dispatch, derivation-limits#effective-limit (#1119,
    // D327): established afresh for this instance, never above the maximum
    // the committed Dispatch Policy states, and never absent where it is
    // finite, whatever the deployment's ceiling has since become.
    derivation_limit: withinStandingConsentMaximum(
      kernel.resolveDerivationLimit(input.intent.requested_derivation_limit),
      dispatchMaximum,
    ),
    derivation_count: 0,
    grant_id: null,
    status_list_idx: null,
    template: templateRef,
  };

  // f. Reserve, insert the instance, and complete the reservation in ONE
  // kernel-db transaction (@spec mission-template#dispatch: the reservation and
  // the dispatched Mission's identifier commit atomically with the instance).
  // A concurrent duplicate loses on the reservation's primary key and recovers
  // the winner's outcome.
  const reservation: CreationReservation = {
    clientId: input.dispatcher,
    creationRequestId: input.dispatchEventId,
    op: "dispatch",
    fingerprint,
    cnfJkt: presenterJkt,
    sourceMissionId: template.id,
  };
  try {
    idem.createCompleted(reservation, () => {
      // @spec mission-template#prohibited-classes (#813): a standing payment's
      // concurrency and rate bounds are read, and its dispatch counted, in
      // this transaction, and its Approval Governance Record is gated here at
      // the creation instant: a refusal rolls back the reservation and the
      // count with it, and a crash cannot leave an instance without its
      // accounting or accounting without its instance.
      const governed =
        standing && input.standingPayment
          ? admitStandingPaymentInCallerTx(kernel, {
              template,
              terms: standing,
              mapping: input.standingPayment.mapping,
              record,
              dispatchEventId: input.dispatchEventId,
              assertBounds: () =>
                assertDispatchBounds(
                  kernel.standingPayments.dispatchedInstances(template.id),
                  kernel.standingPayments.dispatchesSince(template.id, sinceIso),
                ),
            })
          : undefined;
      kernel.insertRecord(record, undefined, {
        source: { inherited: recipientRoot },
        // @spec mission#standing-consent-bases: the Dispatch Policy snapshot
        // verified above, retained for this instance's audit horizon.
        activationPolicies: [{ ref: template.dispatch_policy, snapshot: dispatchPolicy }],
        // @spec mission#transformation-capabilities (#1503 finding 7, D733
        // ruling 2): a dispatch is no approval of its own: each instance entry
        // keeps the association the template ceiling retained at consent,
        // never the mapping current at this dispatch.
        audiences: { inherited: inheritedAudiences(final, audienceReferences(template.ceiling, template.ceiling_audiences)) },
      });
      governed?.retain();
      return { missionId: id, value: undefined };
    });
  } catch (e) {
    if (e instanceof UniqueViolationError) {
      const winner = idem.find(input.dispatcher, input.dispatchEventId);
      if (winner) return recover(winner);
    }
    throw e;
  }
  // Audit + rate/max-active trail (the template store's own database). A
  // standing payment's trail is the kernel-database accounting committed with
  // the instance above.
  if (!standing) {
    store.recordDispatch({
      dispatchEventId: input.dispatchEventId,
      templateId: template.id,
      missionId: id,
    });
  }
  return { mission: record, template };
}

/**
 * @spec mission-template#prohibited-classes (#813, D814, D830): the
 * conditions a standing-payment instance meets before anything commits, each
 * refused `dispatch_prohibited_class`: the template's retained consent is a
 * human consent at the approval floor and never the Dispatcher's; the budget
 * identity is the one pinned for the policy; the Intent carries a USD
 * `max_budget` within the policy's per-instance maximum; the ceiling and the
 * instance meet the workflow's conditions; and only the designated
 * operation's `irreversible_action` predicate is waived. Returns the reason,
 * or undefined.
 */
function standingPaymentAdmissionRefusal(
  kernel: MissionKernel,
  template: MissionTemplate,
  terms: StandingPaymentTerms,
  input: DispatchInput,
  final: readonly AuthorityEntry[],
): string | undefined {
  const consent = template.consent_provenance;
  if (
    !consent ||
    !isHumanFloorConsent(consent) ||
    consent.principal.iss !== template.approver.iss ||
    consent.principal.sub !== template.approver.sub
  ) {
    return `template ${template.id} carries no human consent at the approval floor; a standing payment is dispatched only under one`;
  }
  if (template.dispatchers.includes(consent.principal.sub) || template.recipients.agents.includes(consent.principal.sub)) {
    return `template ${template.id} was consented by a Dispatcher or an Agent, not a human`;
  }
  const pinned = kernel.standingPayments.budgetBinding(template.dispatch_policy.id);
  if (!pinned || pinned.owner !== terms.budget.owner || pinned.id !== terms.budget.id) {
    return `the budget ${terms.budget.owner}/${terms.budget.id} is not the identity pinned for Dispatch Policy ${template.dispatch_policy.id}`;
  }
  const budget = maxBudgetRefusal(input.intent.max_budget, terms);
  if (budget) return budget;
  try {
    assertStandingPaymentTemplateBounds(template);
    assertStandingPaymentCeiling(terms, template.ceiling, "the Template Ceiling");
    assertStandingPaymentCeiling(terms, final, "the instance Authority Set");
  } catch (e) {
    if (e instanceof StandingPaymentTermsError) return e.message;
    throw e;
  }
  return standingPaymentPredicateRefusal(
    (input.standingPayment as StandingPaymentDispatchOptions).mapping,
    terms,
    final,
    input.dispatchProhibitedActions ?? [],
  );
}

/**
 * @spec mission-template#prohibited-classes, approval-governance#atomic-commitment
 * (#813): inside the instance's creation transaction, at its creation instant:
 * check the concurrency and rate bounds from the kernel-database accounting,
 * count this dispatch, then run the Approval Governance gate over the whole
 * instance and build, check and sign its record. A refusal throws before the
 * instance is inserted, and the transaction rolls everything back. The
 * returned `retain` records the admission and the record after the insert.
 */
function admitStandingPaymentInCallerTx(
  kernel: MissionKernel,
  args: {
    template: MissionTemplate;
    terms: StandingPaymentTerms;
    mapping: ProhibitedPredicateMapping;
    record: MissionRecord;
    dispatchEventId: string;
    assertBounds: () => void;
  },
): { retain: () => void } {
  const { template, terms, record } = args;
  args.assertBounds();
  kernel.standingPayments.recordDispatchInCallerTx({
    missionId: record.id,
    templateId: template.id,
    dispatchEventId: args.dispatchEventId,
    at: record.created_at,
  });
  const classification: Record<string, string[]> = {};
  for (const entry of template.ceiling) {
    for (const action of entry.actions) {
      const classes = args.mapping.classesOf(entry, action);
      if (classes) classification[action] = [...new Set([...(classification[action] ?? []), ...classes])];
    }
  }
  const rule = templateRecordingRuleFor(template.dispatch_policy, terms, classification);
  const ruleRef = templateRecordingRuleRef(record.issuer, rule);
  const maxBudget = record.intent.max_budget as NonNullable<MissionRecord["intent"]["max_budget"]>;
  const gate = templateGovernanceGate(parseTemplateRecordingRule(rule.content), {
    deciding: template.dispatch_policy,
    approved_at: template.created_at,
    authority: record.authority_set,
    consumptionBound: true,
    decided_at: record.created_at,
  });
  if (!gate.ok) {
    throw new DispatchError(
      "dispatch_prohibited_class",
      `the standing payment's Approval Governance record cannot be committed: ${gate.reason}: ${gate.detail}`,
    );
  }
  const basis = record.approval_basis as Extract<ApprovalBasis, { type: "template" }>;
  const unsigned = buildTemplateRecord(record, ruleRef, template.dispatch_policy);
  assertTemplateRecord(unsigned, basis, ruleRef, template.dispatch_policy);
  const signed = signApprovalGovernanceRecord(unsigned, kernel.statusSigner());
  const consent = template.consent_provenance as TemplateConsentProvenance;
  return {
    retain: () => {
      kernel.standingPayments.recordAdmissionInCallerTx({
        mission_id: record.id,
        template_id: template.id,
        dispatch_policy: template.dispatch_policy,
        budget: { owner: terms.budget.owner, id: terms.budget.id },
        max_budget: { amount: maxBudget.amount, currency: maxBudget.currency },
        admitted_at: record.created_at,
      });
      kernel.templateApprovalRecords.retainInCallerTx(record.id, record.issuer, ruleRef, rule, {
        approval_event_id: record.approval_event_id,
        intent_hash: record.intent_hash,
        authority: record.authority_set,
        consumption_bound: { amount: maxBudget.amount, currency: maxBudget.currency },
        deciding: template.dispatch_policy,
        consent: {
          template_id: template.id,
          template_hash: template.template_hash,
          principal: template.approver,
          approved_at: template.created_at,
          provenance: consent,
        },
        decided_at: record.created_at,
      });
      kernel.governanceRecords.retainInCallerTx(record.id, signed);
    },
  };
}
