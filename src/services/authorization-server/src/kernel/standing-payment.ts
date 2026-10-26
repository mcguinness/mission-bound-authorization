/**
 * @spec mission-template#prohibited-classes (#813, D814, D830): the one
 * standing-payment dispatch workflow this reference implements, behind the
 * opt-in `standing-payment-dispatch` capability (disabled and unclaimed).
 *
 * A Mission Template whose Dispatch Policy states a `standing_payment` member
 * DESIGNATES the workflow: recurring payment of approved invoices through
 * `payments:payment.execute`. Under the capability, a Dispatch from it may
 * confer that one operation unattended, and only that operation's
 * `irreversible_action` predicate is waived. Every other prohibited predicate
 * any action satisfies (external commitment, privileged administration, the
 * runtime profile's external-communication predicate, cross-domain authority)
 * stays refused `dispatch_prohibited_class`.
 *
 * The terms live in the Dispatch Policy snapshot, so the template commits them
 * through `dispatch_policy.digest` and the approved policy is the one
 * authoritative home of every limit (ruling 5): the committed destinations
 * `{vendor_id: payee_account}` (ruling 4), the per-payment bound, the single
 * resource, the budget `{owner, id, currency, limit, per_instance_max}`
 * (rulings 1, 2), and the Approval Governance recency ceiling with its
 * class-named exceptions (ruling 9). Expiry, review cadence, dispatch rate
 * and concurrency are the template's own `expires_at`, `review_cadence_s`,
 * `rate_per_min` and `max_active`.
 *
 * This module also holds the kernel-database state the workflow needs: the
 * budget identity pinned per Dispatch Policy (ruling 1), each admitted
 * instance (its budget identity and `max_budget`, read by the lineage
 * refusals and by the budget binding), and the dispatch accounting that
 * commits in the instance's own creation transaction.
 */
import {
  type ActivationPolicyRef,
  type ActivationPolicySnapshot,
  activationPolicyDigest,
  compareAmounts,
  isCurrencyCode,
  isRfc3339Instant,
  isValidAmount,
} from "@mission/core";
import { type Database, withTransaction } from "@mission/store";
import type { RegisteredActivationPolicy } from "./activation-policy.js";
import type { ActivationPolicySnapshotStore } from "./activation-policy-snapshots.js";
import { IntentError } from "./intent.js";
import type { AuthorityEntry, MissionIntent, MissionRecord } from "./types.js";

/** The Dispatch Policy snapshot member that designates the workflow. */
export const STANDING_PAYMENT_MEMBER = "standing_payment";

/** The one designated operation whose `irreversible_action` predicate is waivable. */
export const STANDING_PAYMENT_OPERATION = "payments:payment.execute";

/** The one currency the workflow meters (D814: USD). */
export const STANDING_PAYMENT_CURRENCY = "USD";

/** The one waivable predicate. */
export const WAIVABLE_PREDICATE = "irreversible_action";

/**
 * Ruling 9: the reference-local key of the consumption-bound high-risk class
 * (Approval Governance names no identifier for it).
 */
export const CONSUMPTION_BOUND_CLASS = "consumption_bound";

/** A class an Approval Governance class-named exception may name here. */
export type GovernanceExceptionClass = "irreversible_action" | "consumption_bound";

/** An amount in the one metered currency. */
export interface UsdAmount {
  amount: string;
  currency: string;
}

/** Ruling 1: the budget, qualified within its owner's accounting domain. */
export interface StandingPaymentBudget {
  owner: string;
  id: string;
  currency: string;
  /** The standing-consent limit across every instance and successor. */
  limit: string;
  /** Ruling 2: the largest `max_budget` one instance's Intent may carry. */
  per_instance_max: string;
}

/**
 * @spec approval-governance#recency-declarations: the recency ceiling, the
 * clock-skew allowance, and each class-named exception with its own maximum
 * age, committed in the retained policy snapshot (ruling 9).
 */
export interface StandingPaymentGovernance {
  recency: {
    ceilings: { default: number };
    clock_skew_s: number;
    exceptions: Partial<Record<GovernanceExceptionClass, { max_age_s: number }>>;
  };
}

/** The standing-payment terms a Dispatch Policy commits. */
export interface StandingPaymentTerms {
  operation: string;
  resource: string;
  /** Ruling 4: the committed beneficiaries as concrete destinations. */
  destinations: Record<string, string>;
  /** The per-payment bound. */
  max_amount: UsdAmount;
  budget: StandingPaymentBudget;
  approval_governance: StandingPaymentGovernance;
}

/** A malformed or unusable standing-payment statement, or a ceiling defect. */
export class StandingPaymentTermsError extends Error {}

/** A deployment configuration fault, refused at construction. */
export class StandingPaymentConfigError extends Error {}

/** A budget identity a later consent would change (ruling 1). */
export class StandingPaymentBudgetError extends Error {}

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);
const nonEmpty = (v: unknown): v is string => typeof v === "string" && v.length > 0;
const exactly = (o: Record<string, unknown>, keys: readonly string[]): boolean =>
  Object.keys(o).length === keys.length && keys.every((k) => Object.hasOwn(o, k));
const positiveInteger = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) > 0;
const nonNegativeInteger = (v: unknown): v is number =>
  Number.isSafeInteger(v) && (v as number) >= 0;

function usdAmount(v: unknown, at: string): UsdAmount {
  if (!isObject(v) || !exactly(v, ["amount", "currency"])) {
    throw new StandingPaymentTermsError(`${at} is not {amount, currency}`);
  }
  if (typeof v.amount !== "string" || !isValidAmount(v.amount)) {
    throw new StandingPaymentTermsError(`${at}.amount is not a decimal amount`);
  }
  if (!isCurrencyCode(v.currency) || v.currency !== STANDING_PAYMENT_CURRENCY) {
    throw new StandingPaymentTermsError(`${at}.currency is not ${STANDING_PAYMENT_CURRENCY}`);
  }
  return { amount: v.amount, currency: v.currency };
}

const EXCEPTION_CLASSES: readonly GovernanceExceptionClass[] = [
  "irreversible_action",
  "consumption_bound",
];

function parseTerms(raw: unknown): StandingPaymentTerms {
  const fail = (why: string): never => {
    throw new StandingPaymentTermsError(`${STANDING_PAYMENT_MEMBER}: ${why}`);
  };
  if (
    !isObject(raw) ||
    !exactly(raw, [
      "operation",
      "resource",
      "destinations",
      "max_amount",
      "budget",
      "approval_governance",
    ])
  ) {
    return fail(
      "members are not operation, resource, destinations, max_amount, budget, approval_governance",
    );
  }
  if (!nonEmpty(raw.operation)) fail("operation is not a non-empty string");
  if (!nonEmpty(raw.resource)) fail("resource is not a non-empty string");
  const destinations = raw.destinations;
  if (!isObject(destinations) || Object.keys(destinations).length === 0) {
    fail(
      "destinations commits no beneficiary: it is a non-empty object of vendor_id to payee_account",
    );
  }
  for (const [vendor, account] of Object.entries(destinations as Record<string, unknown>)) {
    if (!nonEmpty(vendor) || !nonEmpty(account))
      fail("each destination is a vendor_id naming a non-empty payee_account");
  }
  const maxAmount = usdAmount(raw.max_amount, `${STANDING_PAYMENT_MEMBER}.max_amount`);
  const budget = raw.budget;
  if (
    !isObject(budget) ||
    !exactly(budget, ["owner", "id", "currency", "limit", "per_instance_max"])
  ) {
    return fail("budget is not {owner, id, currency, limit, per_instance_max}");
  }
  if (!nonEmpty(budget.owner) || !nonEmpty(budget.id))
    fail("budget owner and id are non-empty strings");
  if (budget.currency !== STANDING_PAYMENT_CURRENCY)
    fail(`budget currency is not ${STANDING_PAYMENT_CURRENCY}`);
  if (typeof budget.limit !== "string" || !isValidAmount(budget.limit))
    fail("budget limit is not a decimal amount");
  if (typeof budget.per_instance_max !== "string" || !isValidAmount(budget.per_instance_max)) {
    fail("budget per_instance_max is not a decimal amount");
  }
  if (compareAmounts(budget.per_instance_max as string, budget.limit as string) > 0) {
    fail("budget per_instance_max is above the budget limit");
  }
  const governance = raw.approval_governance;
  if (!isObject(governance) || !exactly(governance, ["recency"]))
    fail("approval_governance is not {recency}");
  const recency = (governance as Record<string, unknown>).recency;
  if (!isObject(recency) || !exactly(recency, ["ceilings", "clock_skew_s", "exceptions"])) {
    fail("approval_governance.recency is not {ceilings, clock_skew_s, exceptions}");
  }
  const r = recency as Record<string, unknown>;
  if (
    !isObject(r.ceilings) ||
    !exactly(r.ceilings, ["default"]) ||
    !positiveInteger(r.ceilings.default)
  ) {
    fail("approval_governance.recency.ceilings is not {default} with a positive integer ceiling");
  }
  if (!nonNegativeInteger(r.clock_skew_s))
    fail("approval_governance.recency.clock_skew_s is not a non-negative integer");
  if (!isObject(r.exceptions)) fail("approval_governance.recency.exceptions is not an object");
  for (const [cls, exception] of Object.entries(r.exceptions as Record<string, unknown>)) {
    if (!(EXCEPTION_CLASSES as readonly string[]).includes(cls)) {
      fail(
        `approval_governance.recency.exceptions names ${cls}, which is not a class-named exception this workflow admits`,
      );
    }
    if (
      !isObject(exception) ||
      !exactly(exception, ["max_age_s"]) ||
      !positiveInteger(exception.max_age_s)
    ) {
      fail(
        `approval_governance.recency.exceptions.${cls} is not {max_age_s} with a positive integer`,
      );
    }
  }
  return {
    operation: raw.operation as string,
    resource: raw.resource as string,
    destinations: { ...(destinations as Record<string, string>) },
    max_amount: maxAmount,
    budget: budget as unknown as StandingPaymentBudget,
    approval_governance: governance as unknown as StandingPaymentGovernance,
  };
}

/**
 * The standing-payment terms a Dispatch Policy snapshot states. Undefined when
 * the snapshot does not designate the workflow: it is not a JSON object, or
 * states no `standing_payment` member. Throws {@link StandingPaymentTermsError}
 * for a member that is present but malformed, so a designating policy is never
 * read as an ordinary one.
 */
export function standingPaymentTermsOf(
  policy: ActivationPolicySnapshot,
): StandingPaymentTerms | undefined {
  if (policy.content_type !== "application/json") return undefined;
  let parsed: unknown;
  try {
    const text =
      typeof policy.content === "string"
        ? policy.content
        : new TextDecoder().decode(policy.content);
    parsed = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (!isObject(parsed) || !Object.hasOwn(parsed, STANDING_PAYMENT_MEMBER)) return undefined;
  return parseTerms(parsed[STANDING_PAYMENT_MEMBER]);
}

/**
 * @spec mission-template#prohibited-classes (#813): the ceiling conditions of
 * a standing-payment template, refused at consent and again at dispatch: one
 * exact resource, the policy's; no `delegation` member (no child and no
 * delegation in the ceiling, ruling 3); the designated operation present; and
 * every entry naming it bounded per payment in USD at or below the policy's
 * `max_amount`, its `vendors` non-empty and within the committed destinations.
 * Throws {@link StandingPaymentTermsError} naming the defect.
 */
export function assertStandingPaymentCeiling(
  terms: StandingPaymentTerms,
  entries: readonly AuthorityEntry[],
  what: string,
): void {
  const fail = (why: string): never => {
    throw new StandingPaymentTermsError(`${what}: ${why}`);
  };
  if (terms.operation !== STANDING_PAYMENT_OPERATION) {
    fail(
      `the Dispatch Policy designates ${terms.operation}, which is not ${STANDING_PAYMENT_OPERATION}`,
    );
  }
  let named = false;
  entries.forEach((entry, i) => {
    if (entry.resource !== terms.resource || (entry.resource_match ?? "exact") !== "exact") {
      fail(
        `entry ${i} names ${entry.resource}; a standing-payment ceiling names exactly one resource, ${terms.resource}`,
      );
    }
    if (entry.delegation !== undefined) {
      fail(
        `entry ${i} carries delegation; a standing-payment ceiling admits no child and no delegation`,
      );
    }
    if (!entry.actions.includes(terms.operation)) return;
    named = true;
    const cap = entry.constraints?.max_amount;
    if (!cap) fail(`entry ${i} names ${terms.operation} with no per-payment max_amount`);
    const bound = cap as UsdAmount;
    if (bound.currency !== STANDING_PAYMENT_CURRENCY) {
      fail(
        `entry ${i} bounds ${terms.operation} in ${bound.currency}, not ${STANDING_PAYMENT_CURRENCY}`,
      );
    }
    if (!isValidAmount(bound.amount) || compareAmounts(bound.amount, terms.max_amount.amount) > 0) {
      fail(
        `entry ${i} bounds each payment above the Dispatch Policy's max_amount of ${terms.max_amount.amount}`,
      );
    }
    const vendors = entry.constraints?.vendors;
    if (!vendors || vendors.length === 0)
      fail(`entry ${i} names ${terms.operation} with no committed destination`);
    const uncommitted = (vendors as string[]).find((v) => !Object.hasOwn(terms.destinations, v));
    if (uncommitted !== undefined) {
      fail(
        `entry ${i} names vendor ${uncommitted}, which the Dispatch Policy commits no destination for`,
      );
    }
  });
  if (!named) fail(`no entry names ${terms.operation}`);
}

/**
 * @spec mission-template#prohibited-classes: the template-level conditions:
 * an RFC 3339 expiry (the review cadence, dispatch rate and concurrency limits
 * are the template body's own positive integers, checked for every template).
 */
export function assertStandingPaymentTemplateBounds(body: { expires_at?: unknown }): void {
  if (typeof body.expires_at !== "string" || !isRfc3339Instant(body.expires_at)) {
    throw new StandingPaymentTermsError(
      "a standing-payment template states an RFC 3339 expires_at",
    );
  }
}

/** The prohibited predicates of the Prohibited Classes section. */
export type ProhibitedPredicate =
  | "irreversible_action"
  | "external_commitment"
  | "privileged_administration"
  | "external_communication"
  | "cross_domain";

const PROHIBITED_CLASSES: ReadonlySet<string> = new Set([
  "irreversible_action",
  "external_commitment",
  "privileged_administration",
]);

/**
 * @spec mission-template#prohibited-classes: the deployment's published
 * mapping from an action, at an entry's resource, to the predicates it
 * satisfies: the runtime action classes of its classification, the
 * external-communication predicate, and whether the resource is cross-domain.
 */
export interface ProhibitedPredicateMapping {
  /** The classes the classification gives `action` at `entry`, or undefined when it is unclassified there. */
  classesOf(entry: AuthorityEntry, action: string): readonly string[] | undefined;
  /** Actions satisfying the runtime profile's external-communication predicate. */
  externalCommunicationActions: ReadonlySet<string>;
  /** Whether authority at `resource` is cross-domain. */
  isCrossDomain(resource: string): boolean;
}

/** The prohibited predicates `action` at `entry` satisfies, or undefined when the mapping does not classify it. */
export function prohibitedPredicatesOf(
  mapping: ProhibitedPredicateMapping,
  entry: AuthorityEntry,
  action: string,
): ProhibitedPredicate[] | undefined {
  const classes = mapping.classesOf(entry, action);
  if (classes === undefined) return undefined;
  const out = new Set<ProhibitedPredicate>();
  for (const cls of classes) if (PROHIBITED_CLASSES.has(cls)) out.add(cls as ProhibitedPredicate);
  if (mapping.externalCommunicationActions.has(action)) out.add("external_communication");
  if (mapping.isCrossDomain(entry.resource)) out.add("cross_domain");
  return [...out];
}

/** The predicates the published classification's action classes carry. */
export const CLASS_PREDICATES: ReadonlySet<ProhibitedPredicate> = new Set<ProhibitedPredicate>([
  "irreversible_action",
  "external_commitment",
  "privileged_administration",
]);

/** Every prohibited predicate. */
export const ALL_PROHIBITED_PREDICATES: ReadonlySet<ProhibitedPredicate> =
  new Set<ProhibitedPredicate>([...CLASS_PREDICATES, "external_communication", "cross_domain"]);

/** An action the published mapping classifies as prohibited that the configured set leaves out. */
export interface DispatchProhibitedCoverageGap {
  action: string;
  resource: string;
  predicates: ProhibitedPredicate[];
}

/** A configured dispatch-prohibited set narrower than the published mapping, refused at construction. */
export class DispatchProhibitedCoverageError extends Error {}

/**
 * @spec mission-template#prohibited-classes: "The deployment's configured
 * dispatch-prohibited action set MUST cover every action the published
 * mapping classifies as irreversible, external-commitment, or
 * privileged-administration, as satisfying the runtime profile's
 * external-communication predicate, or as cross-domain." The gaps: each
 * classified action (at each classified resource) satisfying one of
 * `predicates` that `configured` leaves out, and each external-communication
 * action left out wherever it is classified or not.
 */
export function dispatchProhibitedCoverageGaps(
  configured: readonly string[],
  classification: ReadonlyArray<{ resource: string; actions: Readonly<Record<string, string>> }>,
  mapping: ProhibitedPredicateMapping,
  predicates: ReadonlySet<ProhibitedPredicate> = ALL_PROHIBITED_PREDICATES,
): DispatchProhibitedCoverageGap[] {
  const covered = new Set(configured);
  const gaps: DispatchProhibitedCoverageGap[] = [];
  for (const c of classification) {
    for (const action of Object.keys(c.actions).sort()) {
      if (covered.has(action)) continue;
      const entry: AuthorityEntry = {
        type: "mission_resource_access",
        resource: c.resource,
        actions: [action],
      };
      const found = (prohibitedPredicatesOf(mapping, entry, action) ?? []).filter((p) =>
        predicates.has(p),
      );
      if (found.length > 0) gaps.push({ action, resource: c.resource, predicates: found });
    }
  }
  if (predicates.has("external_communication")) {
    for (const action of [...mapping.externalCommunicationActions].sort()) {
      if (!covered.has(action) && !gaps.some((g) => g.action === action)) {
        gaps.push({ action, resource: "*", predicates: ["external_communication"] });
      }
    }
  }
  return gaps;
}

/**
 * @spec mission-template#prohibited-classes: refuse construction where the
 * configured dispatch-prohibited set leaves out an action the published
 * mapping classifies as prohibited under `predicates`, naming every gap.
 */
export function assertDispatchProhibitedCoverage(
  configured: readonly string[],
  classification: ReadonlyArray<{ resource: string; actions: Readonly<Record<string, string>> }>,
  mapping: ProhibitedPredicateMapping,
  predicates: ReadonlySet<ProhibitedPredicate> = ALL_PROHIBITED_PREDICATES,
): void {
  const gaps = dispatchProhibitedCoverageGaps(configured, classification, mapping, predicates);
  if (gaps.length > 0) {
    throw new DispatchProhibitedCoverageError(
      `the configured dispatch-prohibited action set leaves out ${gaps
        .map((g) => `${g.action} at ${g.resource} (${g.predicates.join(", ")})`)
        .join("; ")}, which the published mapping classifies as prohibited`,
    );
  }
}

/**
 * @spec mission-template#prohibited-classes (#813): the capability-aware
 * prohibited-class admission over a dispatched instance's final authority.
 * Only the designated operation's `irreversible_action` predicate is waived.
 * An action the mapping does not classify, an action in the configured
 * dispatch-prohibited set other than the designated operation, and any other
 * prohibited predicate refuse. Returns the reason, or undefined when the only
 * prohibited predicate present is the waivable one.
 */
export function standingPaymentPredicateRefusal(
  mapping: ProhibitedPredicateMapping,
  terms: StandingPaymentTerms,
  authority: readonly AuthorityEntry[],
  configuredProhibited: readonly string[],
): string | undefined {
  const configured = new Set(configuredProhibited);
  for (const entry of authority) {
    for (const action of entry.actions) {
      const designated = action === terms.operation && action === STANDING_PAYMENT_OPERATION;
      if (configured.has(action) && !designated) {
        return `${action} is a dispatch-prohibited action no standing payment waives`;
      }
      const predicates = prohibitedPredicatesOf(mapping, entry, action);
      if (predicates === undefined) {
        return `the published mapping does not classify ${action} at ${entry.resource}; unclassified authority is refused`;
      }
      const unwaived = predicates.filter((p) => !(designated && p === WAIVABLE_PREDICATE));
      if (unwaived.length > 0) {
        return `${action} at ${entry.resource} satisfies the prohibited predicate ${unwaived.join(", ")}, which no standing payment waives`;
      }
    }
  }
  return undefined;
}

/**
 * @spec mission-template#prohibited-classes (#813): the startup coverage
 * check. Every Dispatch Policy that designates the workflow names the
 * designated operation, and the published mapping classifies it at the
 * policy's resource, as the irreversible action the waiver is for. A policy
 * naming an operation the mapping does not cover refuses construction.
 */
export function assertStandingPaymentCoverage(
  policies: Readonly<Record<string, ActivationPolicySnapshot>>,
  mapping: ProhibitedPredicateMapping,
): void {
  for (const [id, held] of Object.entries(policies)) {
    let terms: StandingPaymentTerms | undefined;
    try {
      terms = standingPaymentTermsOf(held);
    } catch (e) {
      throw new StandingPaymentConfigError(`Dispatch Policy ${id}: ${(e as Error).message}`);
    }
    if (!terms) continue;
    if (terms.operation !== STANDING_PAYMENT_OPERATION) {
      throw new StandingPaymentConfigError(
        `Dispatch Policy ${id} designates ${terms.operation}; only ${STANDING_PAYMENT_OPERATION} is a standing payment`,
      );
    }
    const probe: AuthorityEntry = {
      type: "mission_resource_access",
      resource: terms.resource,
      actions: [terms.operation],
    };
    const classes = mapping.classesOf(probe, terms.operation);
    if (classes === undefined) {
      throw new StandingPaymentConfigError(
        `Dispatch Policy ${id} names ${terms.operation} at ${terms.resource}, which the published mapping does not cover`,
      );
    }
    if (!classes.includes(WAIVABLE_PREDICATE)) {
      throw new StandingPaymentConfigError(
        `Dispatch Policy ${id} names ${terms.operation} at ${terms.resource}, which the published mapping does not classify as ${WAIVABLE_PREDICATE}`,
      );
    }
  }
}

/**
 * @spec mission-template#standing-payment-exception, metering#aggregate-bounds,
 * metering#topology (#813, #816, D830 rulings 1, 2 and 5): what the
 * deployment's Enforcement Scope Statement fails to declare for one
 * designating Dispatch Policy, or `undefined` when it declares all of it. The
 * statement must claim `budget_metering`, declare it under the Exact
 * enforcement profile, and list the policy's budget (its owner and id) with
 * the policy's currency and limit and a `policies` entry equal, member for
 * member, to the policy's committed `{id, version, digest}` (the digest the
 * Mission Issuer computes over the snapshot it holds). Read structurally:
 * the PDP's loader refuses a malformed declaration on its own side.
 */
export function standingPaymentExactProfileGap(
  issuer: string,
  id: string,
  held: RegisteredActivationPolicy,
  terms: StandingPaymentTerms,
  statement: unknown,
): string | undefined {
  const ref = { id, version: held.version, digest: activationPolicyDigest(issuer, held) };
  const budget = `${terms.budget.owner}/${terms.budget.id}`;
  if (!isObject(statement) || !Array.isArray(statement.claims) || !statement.claims.includes("budget_metering")) {
    return "the Enforcement Scope Statement does not claim budget_metering";
  }
  const declared = isObject(statement.extensions) ? statement.extensions.budget_metering : undefined;
  if (!isObject(declared) || declared.enforcement_profile !== "exact") {
    return "the Enforcement Scope Statement does not declare budget_metering under the exact enforcement profile";
  }
  const entry = (Array.isArray(declared.budgets) ? declared.budgets : []).find(
    (b): b is Record<string, unknown> => isObject(b) && b.owner === terms.budget.owner && b.budget_id === terms.budget.id,
  );
  if (!entry) return `the Enforcement Scope Statement's budget_metering declares no budget ${budget}`;
  if (
    entry.currency !== terms.budget.currency ||
    typeof entry.limit !== "string" ||
    !isValidAmount(entry.limit) ||
    compareAmounts(entry.limit, terms.budget.limit) !== 0
  ) {
    return `the Enforcement Scope Statement declares budget ${budget} with another currency or limit than the policy's ${terms.budget.limit} ${terms.budget.currency}`;
  }
  const listed =
    Array.isArray(entry.policies) &&
    entry.policies.some((p) => isObject(p) && p.id === ref.id && p.version === ref.version && p.digest === ref.digest);
  if (!listed) {
    return `the Enforcement Scope Statement's budget ${budget} does not list Dispatch Policy ${ref.id} version ${ref.version} with digest ${ref.digest}`;
  }
  return undefined;
}

/**
 * @spec mission-template#standing-payment-exception (#813, #816): the startup
 * exact-profile check, beside {@link assertStandingPaymentCoverage}. Under the
 * capability, every Dispatch Policy designating the workflow has its budget
 * metered exactly by the deployment's PDP, as the Enforcement Scope Statement
 * declares ({@link standingPaymentExactProfileGap}); otherwise construction is
 * refused, so no standing-payment Dispatch is ever admitted against a budget
 * no runtime meters. A deployment that states no statement refuses too.
 */
export function assertStandingPaymentExactProfile(
  issuer: string,
  policies: Readonly<Record<string, RegisteredActivationPolicy>>,
  statement: unknown,
): void {
  for (const [id, held] of Object.entries(policies)) {
    let terms: StandingPaymentTerms | undefined;
    try {
      terms = standingPaymentTermsOf(held);
    } catch (e) {
      throw new StandingPaymentConfigError(`Dispatch Policy ${id}: ${(e as Error).message}`);
    }
    if (!terms) continue;
    const gap = standingPaymentExactProfileGap(issuer, id, held, terms, statement);
    if (gap !== undefined) {
      throw new StandingPaymentConfigError(
        `Dispatch Policy ${id} designates a standing payment, but ${gap}: its budget is not metered under the Exact profile`,
      );
    }
  }
}

/**
 * @spec mission#approval-authentication, mission-template#template-consent
 * (#813): the provenance of a human consent at the approval floor, retained
 * with the template outside `template_hash`. Only the approval surface's
 * decision establishes it; the service-token stand-in and the boot seed have
 * none.
 */
export interface TemplateConsentProvenance {
  /** The Approver's login on the browser approval surface; never a headless service. */
  interactive: true;
  principal: { iss: string; sub: string };
  acr: string;
  auth_time: number;
  /** The approval-authentication floors the consent satisfied. */
  floors: string[];
  /** The render revision the decision approved. */
  render_revision: string;
  /** The template proposal decided. */
  proposal_id: string;
  decided_at: string;
}

/** Whether `v` is a consent provenance the approval surface established. */
export function isHumanFloorConsent(v: unknown): v is TemplateConsentProvenance {
  if (!isObject(v) || v.interactive !== true) return false;
  const p = v.principal;
  return (
    isObject(p) &&
    nonEmpty(p.iss) &&
    nonEmpty(p.sub) &&
    nonEmpty(v.acr) &&
    Number.isSafeInteger(v.auth_time) &&
    Array.isArray(v.floors) &&
    v.floors.length > 0 &&
    v.floors.every(nonEmpty) &&
    nonEmpty(v.render_revision) &&
    nonEmpty(v.proposal_id) &&
    typeof v.decided_at === "string" &&
    isRfc3339Instant(v.decided_at)
  );
}

/** One admitted standing-payment instance, as retained. */
export interface StandingPaymentAdmission {
  mission_id: string;
  template_id: string;
  dispatch_policy: ActivationPolicyRef;
  budget: { owner: string; id: string };
  max_budget: UsdAmount;
  admitted_at: string;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS standing_payment_budget_bindings (
  policy_id TEXT PRIMARY KEY,
  budget_owner TEXT NOT NULL,
  budget_id TEXT NOT NULL,
  bound_at TEXT NOT NULL,
  UNIQUE (budget_owner, budget_id)
) STRICT;
CREATE TABLE IF NOT EXISTS standing_payment_admissions (
  mission_id TEXT PRIMARY KEY,
  template_id TEXT NOT NULL,
  dispatch_policy_json TEXT NOT NULL,
  budget_owner TEXT NOT NULL,
  budget_id TEXT NOT NULL,
  max_budget_json TEXT NOT NULL,
  admitted_at TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS standing_payment_dispatches (
  mission_id TEXT PRIMARY KEY,
  template_id TEXT NOT NULL,
  dispatch_event_id TEXT NOT NULL,
  dispatched_at TEXT NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS standing_payment_dispatches_by_template
  ON standing_payment_dispatches (template_id, dispatched_at);
`;

/**
 * The workflow's state on the kernel database: never in the template store's
 * own in-memory database, so a restart neither forgets a budget identity nor
 * resets the dispatch accounting, and the accounting commits in the creation
 * transaction of the instance it counts.
 */
export class StandingPaymentStore {
  constructor(private readonly db: Database) {
    db.exec(SCHEMA);
  }

  /**
   * Ruling 1: pin the budget identity a Dispatch Policy commits, keyed by the
   * policy's `id` (stable across its versions; the reference's template
   * identifier is minted per consent). A later consent under the same policy
   * id whose budget differs is a policy successor that would silently start a
   * fresh counter, and is refused; so is a budget already pinned to another
   * policy, which would let two standing approvals share one counter
   * unannounced. Idempotent for the same pair.
   */
  bindBudget(policyId: string, budget: { owner: string; id: string }, at: string): void {
    withTransaction(this.db, () => {
      const pinned = this.budgetBinding(policyId);
      if (pinned) {
        if (pinned.owner !== budget.owner || pinned.id !== budget.id) {
          throw new StandingPaymentBudgetError(
            `Dispatch Policy ${policyId} commits budget ${pinned.owner}/${pinned.id}; a successor naming ${budget.owner}/${budget.id} would start a fresh counter`,
          );
        }
        return;
      }
      const other = this.db
        .prepare(
          "SELECT policy_id FROM standing_payment_budget_bindings WHERE budget_owner = ? AND budget_id = ?",
        )
        .get(budget.owner, budget.id) as { policy_id: string } | undefined;
      if (other) {
        throw new StandingPaymentBudgetError(
          `budget ${budget.owner}/${budget.id} is committed by Dispatch Policy ${other.policy_id}, not ${policyId}`,
        );
      }
      this.db
        .prepare(
          "INSERT INTO standing_payment_budget_bindings (policy_id, budget_owner, budget_id, bound_at) VALUES (?, ?, ?, ?)",
        )
        .run(policyId, budget.owner, budget.id, at);
    });
  }

  /** The budget identity pinned for a Dispatch Policy id, if any. */
  budgetBinding(policyId: string): { owner: string; id: string } | undefined {
    const row = this.db
      .prepare(
        "SELECT budget_owner, budget_id FROM standing_payment_budget_bindings WHERE policy_id = ?",
      )
      .get(policyId) as { budget_owner: string; budget_id: string } | undefined;
    return row ? { owner: row.budget_owner, id: row.budget_id } : undefined;
  }

  /** Record an admitted instance; only in its creation transaction. */
  recordAdmissionInCallerTx(admission: StandingPaymentAdmission): void {
    if (!this.db.inTransaction)
      throw new Error(
        "a standing-payment admission is recorded only in the instance's creation transaction",
      );
    this.db
      .prepare(
        `INSERT INTO standing_payment_admissions
         (mission_id, template_id, dispatch_policy_json, budget_owner, budget_id, max_budget_json, admitted_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        admission.mission_id,
        admission.template_id,
        JSON.stringify(admission.dispatch_policy),
        admission.budget.owner,
        admission.budget.id,
        JSON.stringify(admission.max_budget),
        admission.admitted_at,
      );
  }

  /** The admission of one instance, if it was admitted as a standing payment. */
  admission(missionId: string): StandingPaymentAdmission | undefined {
    const row = this.db
      .prepare("SELECT * FROM standing_payment_admissions WHERE mission_id = ?")
      .get(missionId) as
      | {
          mission_id: string;
          template_id: string;
          dispatch_policy_json: string;
          budget_owner: string;
          budget_id: string;
          max_budget_json: string;
          admitted_at: string;
        }
      | undefined;
    if (!row) return undefined;
    return {
      mission_id: row.mission_id,
      template_id: row.template_id,
      dispatch_policy: JSON.parse(row.dispatch_policy_json) as ActivationPolicyRef,
      budget: { owner: row.budget_owner, id: row.budget_id },
      max_budget: JSON.parse(row.max_budget_json) as UsdAmount,
      admitted_at: row.admitted_at,
    };
  }

  /** Record one dispatch for the concurrency and rate bounds; only in the instance's creation transaction. */
  recordDispatchInCallerTx(input: {
    missionId: string;
    templateId: string;
    dispatchEventId: string;
    at: string;
  }): void {
    if (!this.db.inTransaction)
      throw new Error(
        "standing-payment dispatch accounting commits only in the instance's creation transaction",
      );
    this.db
      .prepare(
        "INSERT INTO standing_payment_dispatches (mission_id, template_id, dispatch_event_id, dispatched_at) VALUES (?, ?, ?, ?)",
      )
      .run(input.missionId, input.templateId, input.dispatchEventId, input.at);
  }

  /** The template's dispatched instances, in dispatch order. */
  dispatchedInstances(templateId: string): string[] {
    return (
      this.db
        .prepare(
          "SELECT mission_id FROM standing_payment_dispatches WHERE template_id = ? ORDER BY dispatched_at, mission_id",
        )
        .all(templateId) as Array<{ mission_id: string }>
    ).map((r) => r.mission_id);
  }

  /** Dispatches of a template at or after `sinceIso`. ISO UTC strings compare chronologically. */
  dispatchesSince(templateId: string, sinceIso: string): number {
    const row = this.db
      .prepare(
        "SELECT COUNT(*) AS n FROM standing_payment_dispatches WHERE template_id = ? AND dispatched_at >= ?",
      )
      .get(templateId, sinceIso) as { n: number };
    return row.n;
  }
}

/**
 * Ruling 3: the standing-payment instance a Mission's lineage descends from:
 * the Mission itself, or the first predecessor in its successor chain, that
 * was admitted as a standing payment. Undefined for any other lineage.
 * Successors keep the instance's budget identity and consumption; children,
 * delegation, and cross-organization or cross-domain derivations of any
 * Mission in such a lineage are refused until their accounting is supported.
 */
export function standingPaymentRootOf(
  kernel: { get(id: string): MissionRecord | undefined; standingPayments: StandingPaymentStore },
  record: MissionRecord,
): StandingPaymentAdmission | undefined {
  const seen = new Set<string>();
  for (
    let m: MissionRecord | undefined = record;
    m && !seen.has(m.id);
    m = m.predecessor ? kernel.get(m.predecessor) : undefined
  ) {
    seen.add(m.id);
    const admission = kernel.standingPayments.admission(m.id);
    if (admission) return admission;
  }
  return undefined;
}

/**
 * @spec metering#metering, metering#capacity-across-missions,
 * mission-template#standing-payment-exception (#813, #816, D830 rulings 1, 2,
 * 4, 5): the budget binding a Mission in a standing-payment lineage is
 * metered under, as the PDP's view carries it (`MissionView.budget`). The
 * shape is the PDP's `MissionBudgetBinding`, member for member.
 */
export interface StandingPaymentBudgetBinding {
  owner: string;
  budget_id: string;
  currency: string;
  /** The approved policy's shared limit. */
  limit: string;
  /** The dispatched instance's committed Dispatch Policy. */
  policy: ActivationPolicyRef;
  /** The committed destinations, `{vendor_id: payee_account}`. */
  destinations: Record<string, string>;
  instance: { max_budget: UsdAmount; root_mission_id: string };
}

/**
 * What the kernel derives for one Mission: `unbound` outside every
 * standing-payment lineage; `bound` with its binding; `underivable` for a
 * Mission it records as a standing payment whose binding it cannot derive,
 * which the PDP must refuse rather than evaluate as unmetered.
 */
export type StandingPaymentBudgetBindingResult =
  | { kind: "unbound" }
  | { kind: "bound"; binding: StandingPaymentBudgetBinding }
  | { kind: "underivable"; reason: string };

/**
 * @spec metering#metering, mission-template#standing-payment-exception (#813,
 * #816, decision d): derive a Mission's budget binding from the kernel's own
 * committed state, never from a template store or a request. The successor
 * chain is walked to the dispatched instance ({@link standingPaymentRootOf}),
 * whose admission names the committed Dispatch Policy, the budget identity
 * pinned at consent and the instance's `max_budget`. The policy's terms are
 * read from the snapshot the instance's activation retained, verified against
 * its committed digest. The binding carries the budget's owner, id, currency
 * and limit and the committed destinations from those terms, and the
 * instance bound keyed by the dispatched instance, so a successor continues
 * both of its predecessor's counters.
 *
 * Underivable, and refused by the PDP: the instance record or its committed
 * reference is missing or disagrees with the admission; the snapshot is not
 * retained (pruned past its horizon) or no longer reproduces its digest; its
 * terms do not parse; they name another budget than the pinned one; or the
 * Mission's Intent does not carry the instance's `max_budget`.
 */
export function standingPaymentBudgetBindingOf(
  kernel: {
    get(id: string): MissionRecord | undefined;
    standingPayments: StandingPaymentStore;
    activationPolicySnapshots: Pick<ActivationPolicySnapshotStore, "verify">;
  },
  record: MissionRecord,
): StandingPaymentBudgetBindingResult {
  const root = standingPaymentRootOf(kernel, record);
  if (!root) return { kind: "unbound" };
  const underivable = (reason: string): StandingPaymentBudgetBindingResult => ({ kind: "underivable", reason });
  const instance = kernel.get(root.mission_id);
  const ref = root.dispatch_policy;
  const committed = instance?.template?.dispatch_policy;
  if (!instance || !committed) return underivable(`standing-payment instance ${root.mission_id} commits no Dispatch Policy`);
  if (committed.id !== ref.id || committed.version !== ref.version || committed.digest !== ref.digest) {
    return underivable(`standing-payment instance ${root.mission_id} commits another Dispatch Policy than its admission`);
  }
  const check = kernel.activationPolicySnapshots.verify(instance.issuer, ref);
  if (check.status !== "verified") {
    return underivable(`Dispatch Policy ${ref.id} version ${ref.version}: retained snapshot ${check.status}`);
  }
  let terms: StandingPaymentTerms | undefined;
  try {
    terms = standingPaymentTermsOf({ content_type: check.snapshot.content_type, content: check.snapshot.content });
  } catch (e) {
    return underivable(e instanceof Error ? e.message : "malformed standing-payment terms");
  }
  if (!terms) return underivable(`Dispatch Policy ${ref.id} version ${ref.version} states no standing payment`);
  if (terms.budget.owner !== root.budget.owner || terms.budget.id !== root.budget.id) {
    return underivable(`Dispatch Policy ${ref.id} names another budget than the one pinned at consent`);
  }
  const cap = record.intent.max_budget;
  if (!cap || cap.currency !== root.max_budget.currency || !isValidAmount(cap.amount) || compareAmounts(cap.amount, root.max_budget.amount) !== 0) {
    return underivable(`mission ${record.id} does not carry the max_budget of standing-payment instance ${root.mission_id}`);
  }
  return {
    kind: "bound",
    binding: {
      owner: terms.budget.owner,
      budget_id: terms.budget.id,
      currency: terms.budget.currency,
      limit: terms.budget.limit,
      policy: { id: ref.id, version: ref.version, digest: ref.digest },
      destinations: { ...terms.destinations },
      instance: {
        max_budget: { amount: root.max_budget.amount, currency: root.max_budget.currency },
        root_mission_id: root.mission_id,
      },
    },
  };
}

/**
 * Ruling 3: refuse a derivation of a Mission in a standing-payment lineage.
 * Throws {@link StandingPaymentLineageError}; the caller maps it onto its own
 * refusal.
 */
export class StandingPaymentLineageError extends Error {}

export function assertNotStandingPaymentLineage(
  kernel: Parameters<typeof standingPaymentRootOf>[0],
  record: MissionRecord,
  derivation: string,
): void {
  const root = standingPaymentRootOf(kernel, record);
  if (root) {
    throw new StandingPaymentLineageError(
      `mission ${record.id} descends from standing-payment instance ${root.mission_id}; ${derivation} would not share its budget accounting, so it is refused (#813)`,
    );
  }
}

/**
 * Ruling 2: the `max_budget` a standing-payment instance's Intent carries, in
 * USD and not above the policy's per-instance maximum. Returns the reason it
 * is refused, or undefined.
 */
export function maxBudgetRefusal(
  maxBudget: UsdAmount | undefined,
  terms: StandingPaymentTerms,
): string | undefined {
  if (!maxBudget) return "a standing-payment instance's Intent carries max_budget";
  if (maxBudget.currency !== terms.budget.currency) {
    return `max_budget is in ${maxBudget.currency}, not the budget's ${terms.budget.currency}`;
  }
  if (!isValidAmount(maxBudget.amount)) return "max_budget.amount is not a decimal amount";
  if (compareAmounts(maxBudget.amount, terms.budget.per_instance_max) > 0) {
    return `max_budget of ${maxBudget.amount} is above the Dispatch Policy's per_instance_max of ${terms.budget.per_instance_max}`;
  }
  return undefined;
}

/**
 * @spec metering#bounds, mission-template#prohibited-classes (#813, D830
 * rulings 2 and 3): a successor of a standing-payment instance keeps the
 * instance's budget identity (it descends from the same admitted instance)
 * and keeps its Intent's `max_budget` exactly, so the instance bound its
 * accumulated consumption is measured against never moves. A successor of
 * any other Mission carries none: nothing would meter it.
 */
export function assertSuccessorMaxBudget(
  kernel: Parameters<typeof standingPaymentRootOf>[0],
  predecessor: MissionRecord,
  intent: MissionIntent,
): void {
  const root = standingPaymentRootOf(kernel, predecessor);
  const cap = intent.max_budget;
  if (!root) {
    if (cap !== undefined) {
      throw new IntentError(
        "invalid_request",
        "max_budget is admitted only on a standing-payment instance and its successors",
      );
    }
    return;
  }
  const kept = predecessor.intent.max_budget ?? root.max_budget;
  if (
    !cap ||
    cap.currency !== kept.currency ||
    !isValidAmount(cap.amount) ||
    compareAmounts(cap.amount, kept.amount) !== 0
  ) {
    throw new IntentError(
      "invalid_request",
      `a successor of standing-payment instance ${root.mission_id} keeps its max_budget of ${kept.amount} ${kept.currency}`,
    );
  }
}
