/**
 * @spec metering#metering, metering#topology, metering#retry,
 * metering#aggregate-bounds, metering#capacity-across-missions (#816, D814,
 * D830): the PDP's exact `max_budget` metering, as declared and as bound.
 *
 * Two inputs meet here, and neither comes from the decision request:
 *
 * - The deployment's `budget_metering` declaration, an Enforcement Scope
 *   Statement extension the claim domain reads from its own statement. It
 *   names the unit, the Exact profile and the single-writer topology the
 *   reservation runs under, the reserve-then-commit posture, the settlement
 *   intake, the actions it meters, and each budget it meters: its owner and
 *   id, a disclosure copy of the approved limit, and every committed
 *   Dispatch Policy that commits the budget, each by `id`, `version` and
 *   `digest`.
 * - A Mission's {@link MissionBudgetBinding}, a PDP-local member of the
 *   loaded Mission view (`MissionView.budget`), derived from the committed
 *   policy snapshot by the decision point's own source
 *   ({@link MissionBudgetSource}), which replaces whatever the caller's view
 *   carries. It never enters `req.context`, so it is not part of the
 *   authorization binding or the cache key, and a metered decision is never
 *   answered from a stored decision (`idempotency-claims.ts`).
 *
 * Each metered decision charges two counters in the claim's own
 * transaction: the instance counter (`counter_scope` `mission`, keyed by the
 * first Mission of the successor chain, limited by the Intent's
 * `max_budget`) and the shared counter (`counter_scope` `standing_consent`,
 * keyed by budget owner and budget id, limited by the approved policy's
 * limit). Either one refuses.
 *
 * This module is the pure part: the declaration's loader findings, the
 * binding's shape, and exact minor-unit arithmetic. Amounts are decimal
 * strings converted to integer minor units of the declared unit, never
 * binary floating point.
 */

import { type ActionPhase, canonicalDigest, compareAmounts, isActionPhase, isCurrencyCode, isValidAmount } from "@mission/core";
import type { EnforcementScopeFinding } from "./enforcement-scope.js";

/**
 * @spec metering#metering (#813, #816, decision d): a decision point that
 * would meter budgets without its own binding source, refused at
 * construction.
 */
export class BudgetMeteringConfigError extends Error {
  constructor(why: string) {
    super(why);
    this.name = "BudgetMeteringConfigError";
  }
}

/** The extension's name in `claims` and under `extensions`. */
export const BUDGET_METERING_EXTENSION = "budget_metering";

/**
 * The counter key classes this PDP meters a budget under: `mission` for the
 * instance's own `max_budget` (an Expansion successor continues its
 * predecessor's Mission counter), `standing_consent` for the budget shared by
 * a standing approval's instances and their successors.
 */
export type BudgetCounterScope = "mission" | "standing_consent";

/**
 * @spec metering#bounds `max_budget`: the Intent member's shape, the same
 * `{amount, currency}` the `max_amount` Common Constraint takes.
 */
export interface BudgetAmount {
  amount: string;
  currency: string;
}

/**
 * @spec metering#aggregate-bounds (#816): the committed Dispatch Policy a
 * budget's limit was approved under, identified by its `id`, `version` and
 * `digest` (a `sha-256:` canonical digest). Compared member for member.
 */
export interface DispatchPolicyRef {
  id: string;
  version: string;
  digest: string;
}

const POLICY_MEMBERS = ["id", "version", "digest"];
const DIGEST_FORMAT = /^sha-256:[A-Za-z0-9_-]{43}$/;

/** Whether `value` is exactly `{id, version, digest}` with a `sha-256:` digest. */
export function isDispatchPolicyRef(value: unknown): value is DispatchPolicyRef {
  return (
    object(value) &&
    nonEmpty(value.id) &&
    nonEmpty(value.version) &&
    typeof value.digest === "string" &&
    DIGEST_FORMAT.test(value.digest) &&
    Object.keys(value).every((k) => POLICY_MEMBERS.includes(k))
  );
}

/**
 * The budget a Mission is bound to, as this PDP holds it beside the Mission
 * view (`MissionView.budget`). PDP-local: derived by the loader from the
 * kernel's committed policy snapshot, never read from a decision request. A
 * view without one is unmetered.
 *
 * The policy is the authoritative home of `limit`; the Enforcement Scope
 * Statement discloses a copy, and a binding that disagrees with the
 * declaration (limit, policy `id`, `version` or `digest`, owner, budget or
 * currency) is a budget this PDP cannot meter (`constraint_unsupported`).
 */
export interface MissionBudgetBinding {
  /** The accounting domain that owns the budget; with `budget_id` it keys the shared counter. */
  owner: string;
  /** `budget.id` from the human-approved Dispatch Policy, qualified within `owner`. */
  budget_id: string;
  /** The one currency of the budget, the policy's limit and the instance bound; compared exactly, never converted. */
  currency: string;
  /** The approved policy's shared limit, a decimal string in `currency`. */
  limit: string;
  /** The committed Dispatch Policy the limit was approved under. */
  policy: DispatchPolicyRef;
  /**
   * @spec mission-template#standing-payment-exception (#813, D830 ruling 4):
   * the committed destinations, `{vendor_id: payee_account}`, from the same
   * policy snapshot. Non-empty. The payee the enforcing PEP establishes for
   * the metered action is compared with the entry for its vendor.
   */
  destinations: Readonly<Record<string, string>>;
  /** The instance bound. */
  instance: {
    /** The instance Intent's `max_budget`. */
    max_budget: BudgetAmount;
    /**
     * The first Mission of the successor chain (the dispatched instance).
     * With the view's issuer it keys the instance counter, so a successor
     * draws on its predecessor's consumption, never on a fresh counter.
     */
    root_mission_id: string;
  };
}

/** One metered operation: the action, and the phase of a compound action it is metered at. */
export interface MeteredAction {
  action: string;
  /** REQUIRED: the phase the action is charged at (`commit` for a payment). */
  phase: ActionPhase;
}

/**
 * @spec metering#metering (#816, decision h): the phases of a metered
 * compound action its metered phase's charge covers. They charge nothing and
 * are not refused; any other phase of the action that carries an amount
 * (`compensate` included) is refused `constraint_unsupported`.
 */
export const COVERED_PHASES: ReadonlySet<ActionPhase> = new Set<ActionPhase>(["preflight", "prepare"]);

/**
 * One declared budget: its owner and id (the shared counter's key), its
 * counter class, the disclosure copy of the approved limit, and every
 * committed Dispatch Policy that commits this budget. Every template that
 * commits one budget shares its counter, so instances under any listed
 * policy draw on the same `standing_consent` counter.
 */
export interface BudgetDeclaration {
  /** The accounting domain that owns the budget. */
  owner: string;
  budget_id: string;
  counter_scope: "standing_consent";
  currency: string;
  limit: string;
  /** Non-empty and distinct: the committed Dispatch Policies whose approved limit is `limit`. */
  policies: readonly DispatchPolicyRef[];
}

/**
 * @spec metering#settlement-contract (#816): the one settlement intake this
 * reference implements: the decision channel's claim settlement
 * (`ClaimChannel.settle` and `reconcile`), through which the executing PEP
 * delivers its signed Execution Evidence to the PDP claim domain that holds
 * the counters. A declaration naming any other intake is refused.
 */
export const CLAIM_SETTLEMENT_INTAKE = "pdp-claim-settlement:execution-evidence";

/**
 * The `budget_metering` Enforcement Scope Statement extension: the
 * deployment's declaration of what this PDP meters and how. A
 * reference-statement representation, not a Runtime wire member.
 */
export interface BudgetMeteringDeclaration {
  /** The counter unit: the currency, and the minor-unit exponent amounts are counted in. */
  unit: { currency: string; exponent: number };
  enforcement_profile: "exact";
  topology: "local-single-writer";
  reserve_posture: "reserve_then_commit";
  /**
   * @spec metering#settlement-contract: "The deployment MUST name the
   * settlement intake ... in its Enforcement Scope Statement", and the
   * intake feeds the consistency domain that holds the counter. Exactly
   * {@link CLAIM_SETTLEMENT_INTAKE}.
   */
  settlement_intake: typeof CLAIM_SETTLEMENT_INTAKE;
  metered_actions: readonly MeteredAction[];
  budgets: readonly BudgetDeclaration[];
}

const DECLARATION_MEMBERS = new Set([
  "unit",
  "enforcement_profile",
  "topology",
  "reserve_posture",
  "settlement_intake",
  "metered_actions",
  "budgets",
]);
const BUDGET_MEMBERS = new Set(["owner", "budget_id", "counter_scope", "currency", "limit", "policies"]);
/** The widest minor-unit exponent a counter takes; every count stays a safe integer. */
const MAX_EXPONENT = 9;

const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const nonEmpty = (v: unknown): v is string => typeof v === "string" && v.length > 0;

/**
 * Exact conversion of a decimal amount to integer minor units of a unit with
 * `exponent` fractional digits, or `undefined` when the amount is malformed,
 * carries a nonzero digit the unit cannot count, or exceeds a safe integer.
 */
export function minorUnits(amount: unknown, exponent: number): number | undefined {
  if (typeof amount !== "string" || !isValidAmount(amount)) return undefined;
  const [whole, fraction = ""] = amount.split(".") as [string, string?];
  if (/[^0]/.test(fraction.slice(exponent))) return undefined;
  const scaled = BigInt(whole + fraction.slice(0, exponent).padEnd(exponent, "0"));
  if (scaled > BigInt(Number.MAX_SAFE_INTEGER)) return undefined;
  return Number(scaled);
}

/** The decimal string of `minor` minor units at `exponent`, for evidence and alerts. */
export function decimalOf(minor: number, exponent: number): string {
  const digits = String(minor).padStart(exponent + 1, "0");
  return exponent === 0 ? digits : `${digits.slice(0, -exponent)}.${digits.slice(-exponent)}`;
}

/**
 * A stable, committed counter identifier: the `sha-256:` digest of the
 * counter's scope and key, so a Decision Evidence `metering` entry names the
 * counter without carrying a lineage or owner identifier raw
 * (@spec metering#metering-evidence `counter_id`).
 */
export function budgetCounterId(scope: BudgetCounterScope, key: Record<string, string>): string {
  return canonicalDigest({ counter_scope: scope, ...key });
}

/** Whether `value` is a non-empty `{vendor_id: payee_account}` map of non-empty strings. */
function isDestinations(value: unknown): value is Record<string, string> {
  return (
    object(value) &&
    Object.keys(value).length > 0 &&
    Object.entries(value).every(([vendor, account]) => vendor.length > 0 && nonEmpty(account))
  );
}

/** Whether `value` is a binding of the documented shape; a malformed one is a budget this PDP cannot meter. */
export function isMissionBudgetBinding(value: unknown): value is MissionBudgetBinding {
  if (!object(value)) return false;
  const instance = value.instance;
  return (
    nonEmpty(value.owner) &&
    nonEmpty(value.budget_id) &&
    isCurrencyCode(value.currency) &&
    typeof value.limit === "string" &&
    isValidAmount(value.limit) &&
    isDispatchPolicyRef(value.policy) &&
    isDestinations(value.destinations) &&
    object(instance) &&
    nonEmpty(instance.root_mission_id) &&
    object(instance.max_budget) &&
    typeof instance.max_budget.amount === "string" &&
    isValidAmount(instance.max_budget.amount) &&
    isCurrencyCode(instance.max_budget.currency)
  );
}

/**
 * @spec metering#metering, mission-template#standing-payment-exception (#813,
 * #816, decision d): the value a PDP-side source gives for a Mission it
 * records as budget-bound but whose binding it cannot derive (the committed
 * policy snapshot is gone or no longer verifies, its terms do not parse, or
 * they disagree with the admission). Carried as `MissionView.budget` in place
 * of a binding: every decision on the Mission that would otherwise permit is
 * denied `constraint_unsupported`, never evaluated as unmetered.
 */
export interface UnderivableBudget {
  readonly underivable: true;
}

/** The one {@link UnderivableBudget} value. */
export const UNDERIVABLE_BUDGET: UnderivableBudget = Object.freeze({ underivable: true as const });

/**
 * @spec metering#metering (#816, decision d): the PDP-side source of a
 * Mission's budget binding, bound at decision-point construction. It answers
 * for the Mission the request names: its binding, {@link UNDERIVABLE_BUDGET},
 * or `undefined` for a Mission that is not budget-bound. What the caller's
 * view carries is never consulted.
 */
export type MissionBudgetSource = (mission: { id: string; issuer: string }) => MissionBudgetBinding | UnderivableBudget | undefined;

/**
 * @spec mission-template#standing-payment-exception, authzen#parameter-digest,
 * authzen#pdp-consistency-checks check 8 (#813, D830 ruling 4): whether the
 * payee the enforcing PEP established for a budget-bound Mission's metered
 * action is the destination the approved policy commits for its vendor.
 *
 * The PEP establishes the payee from the resource's own records, never from
 * tool arguments, and supplies it inside `action.properties.parameters`, the
 * normalized parameter object `parameter_digest` is computed over. The PDP
 * recomputes that digest and requires it to equal the request's
 * `parameter_digest`, so the payee compared here is the one the permit binds
 * and execution reverification re-establishes before release. The object's
 * `vendor_id` must be the request's vendor and its `amount` the request's
 * amount (the amount the budget is charged), and its `payee_account` must
 * equal `destinations[vendor_id]`. Absent parameters, a digest that does not
 * match, a vendor without a committed destination, or another payee account
 * all fail: a changed bank account inherits no approval.
 */
export function committedDestinationHolds(input: {
  parameters: unknown;
  parameterDigest: unknown;
  vendorId: unknown;
  amount: unknown;
  destinations: Readonly<Record<string, string>>;
}): boolean {
  const { parameters, destinations } = input;
  if (!object(parameters) || typeof input.parameterDigest !== "string") return false;
  let recomputed: string;
  try {
    recomputed = canonicalDigest(parameters as never);
  } catch {
    return false;
  }
  if (recomputed !== input.parameterDigest) return false;
  const vendor = parameters.vendor_id;
  if (!nonEmpty(vendor) || vendor !== input.vendorId) return false;
  const stated = parameters.amount;
  const requested = input.amount;
  if (!object(stated) || !object(requested) || stated.amount !== requested.amount || stated.currency !== requested.currency) {
    return false;
  }
  // A vendor with no committed destination reads `undefined` (or an inherited
  // member), which no payee account string equals.
  return nonEmpty(parameters.payee_account) && parameters.payee_account === destinations[vendor];
}

/** Whether the declaration meters `action` at `phase`. A request that names no phase is metered whenever its action is. */
export function metersAction(declaration: BudgetMeteringDeclaration, action: string, phase: ActionPhase | undefined): boolean {
  return declaration.metered_actions.some(
    (m) => m.action === action && (phase === undefined || m.phase === phase),
  );
}

/**
 * Whether the declaration names `action` at any phase. Of the declared
 * action's unmetered phases, only {@link COVERED_PHASES} are covered by its
 * metered phase's charge.
 */
export function declaresMeteredAction(declaration: BudgetMeteringDeclaration, action: string): boolean {
  return declaration.metered_actions.some((m) => m.action === action);
}

/**
 * @spec metering#topology, metering#retry, metering#aggregate-bounds (#816):
 * the loader findings for a `budget_metering` declaration, checked wherever
 * it appears (claimed or not), so a malformed one refuses the statement and
 * with it the claim domain. Closed: an unknown member is refused rather
 * than read as a wider declaration.
 */
export function budgetMeteringFindings(statement: unknown): EnforcementScopeFinding[] {
  const extensions = object(statement) && object(statement.extensions) ? statement.extensions : undefined;
  const declared = extensions?.[BUDGET_METERING_EXTENSION];
  if (declared === undefined) return [];
  const member = `extensions.${BUDGET_METERING_EXTENSION}`;
  const findings: EnforcementScopeFinding[] = [];
  const push = (at: string, problem: string): void => {
    findings.push({ member: at, problem });
  };
  if (!object(declared)) {
    push(member, "declaration must be an object");
    return findings;
  }
  for (const key of Object.keys(declared)) {
    if (!DECLARATION_MEMBERS.has(key)) push(member, `unknown member ${key}`);
  }
  const unit = declared.unit;
  const unitOk =
    object(unit) &&
    isCurrencyCode(unit.currency) &&
    typeof unit.exponent === "number" &&
    Number.isSafeInteger(unit.exponent) &&
    unit.exponent >= 0 &&
    unit.exponent <= MAX_EXPONENT &&
    Object.keys(unit).every((k) => k === "currency" || k === "exponent");
  if (!unitOk) push(`${member}.unit`, `unit must be exactly {currency, exponent}: a currency code and a whole exponent from 0 to ${MAX_EXPONENT}`);
  if (declared.enforcement_profile !== "exact") push(member, "enforcement_profile must be exact: the budget counter runs under the Exact profile only");
  if (declared.topology !== "local-single-writer") push(member, "topology must be local-single-writer, the claim domain's topology");
  if (declared.reserve_posture !== "reserve_then_commit") push(member, "reserve_posture must be reserve_then_commit");
  if (declared.settlement_intake === undefined) {
    push(member, "missing the settlement intake");
  } else if (declared.settlement_intake !== CLAIM_SETTLEMENT_INTAKE) {
    push(member, `settlement_intake must be ${CLAIM_SETTLEMENT_INTAKE}, the claim settlement that feeds the counters' domain`);
  }

  const actions = declared.metered_actions;
  if (!Array.isArray(actions) || actions.length === 0) {
    push(`${member}.metered_actions`, "must be a non-empty array of {action, phase}");
  } else {
    const seen = new Set<string>();
    actions.forEach((raw, i) => {
      const at = `${member}.metered_actions[${i}]`;
      if (!object(raw) || !nonEmpty(raw.action)) {
        push(at, "entry must name an action");
        return;
      }
      if (raw.phase === undefined) push(at, "entry must name the phase the action is charged at");
      else if (!isActionPhase(raw.phase)) push(at, `phase ${String(raw.phase)} is not an action phase`);
      if (Object.keys(raw).some((k) => k !== "action" && k !== "phase")) push(at, "entry carries a member other than action and phase");
      const id = `${raw.action}\u0000${String(raw.phase ?? "")}`;
      if (seen.has(id)) push(at, "duplicate metered action");
      seen.add(id);
    });
  }

  const budgets = declared.budgets;
  if (!Array.isArray(budgets) || budgets.length === 0) {
    push(`${member}.budgets`, "must be a non-empty array of declared budgets");
  } else {
    const ids = new Set<string>();
    budgets.forEach((raw, i) => {
      const at = `${member}.budgets[${i}]`;
      if (!object(raw)) {
        push(at, "entry must be an object");
        return;
      }
      for (const key of Object.keys(raw)) {
        if (!BUDGET_MEMBERS.has(key)) push(at, `unknown member ${key}`);
      }
      if (!nonEmpty(raw.owner)) push(at, "missing the budget owner");
      if (!nonEmpty(raw.budget_id)) push(at, "missing the budget id");
      // The shared counter's key is (owner, budget id): one declaration per key.
      const key = JSON.stringify([raw.owner, raw.budget_id]);
      if (ids.has(key)) push(at, `duplicate budget ${String(raw.budget_id)} of owner ${String(raw.owner)}`);
      ids.add(key);
      if (raw.counter_scope !== "standing_consent") push(at, "counter_scope must be standing_consent");
      if (!isCurrencyCode(raw.currency) || (unitOk && raw.currency !== (unit as { currency: string }).currency)) {
        push(at, "currency must be the unit's currency");
      }
      if (unitOk && minorUnits(raw.limit, (unit as { exponent: number }).exponent) === undefined) {
        push(at, "limit must be a decimal amount the unit counts exactly");
      } else if (!unitOk && (typeof raw.limit !== "string" || !isValidAmount(raw.limit))) {
        push(at, "limit must be a decimal amount");
      }
      const policies = raw.policies;
      if (!Array.isArray(policies) || policies.length === 0) {
        push(at, "policies must be a non-empty list of the committed Dispatch Policies that commit this budget");
      } else {
        const seen = new Set<string>();
        policies.forEach((ref, j) => {
          if (!isDispatchPolicyRef(ref)) {
            push(`${at}.policies[${j}]`, "must be exactly {id, version, digest} (a sha-256: digest), a committed Dispatch Policy");
            return;
          }
          // One committed version is one reference: a second digest for it is a conflict.
          const key = JSON.stringify([ref.id, ref.version]);
          if (seen.has(key)) push(`${at}.policies[${j}]`, `duplicate policy ${ref.id} version ${ref.version}`);
          seen.add(key);
        });
      }
    });
  }
  return findings;
}

/** A counter one charge debits: its scope, its key, its committed identifier, and the limit this decision applies. */
export interface BudgetCounterCharge {
  scope: BudgetCounterScope;
  key: Record<string, string>;
  id: string;
  limitMinor: number;
}

/** What a budget binding and an amount resolve to under a declaration. */
export type BudgetChargeResolution =
  /** The binding cannot be metered here: undeclared budget, another owner, currency, limit, or policy id, version or digest. */
  | { kind: "unsupported" }
  /** The request's amount is not one the unit counts exactly. */
  | { kind: "amount_invalid" }
  | { kind: "charge"; amountMinor: number; currency: string; exponent: number; counters: readonly [BudgetCounterCharge, BudgetCounterCharge] };

/**
 * @spec metering#aggregate-bounds, metering#capacity-across-missions (#816,
 * D830 rulings 1, 2, 5): resolve one charge. The binding must name a budget
 * the declaration lists under the same (owner, budget id), in the declared
 * currency, with the declared limit (compared by value) and a Dispatch
 * Policy the budget lists (`id`, `version` and `digest` of one listed
 * reference, each exactly); the request's amount must be in that currency
 * too (no conversion). The counter keys never include the policy, so every
 * listed policy and every version draws on one shared counter. The instance
 * counter comes first, then the shared one.
 */
export function resolveBudgetCharge(
  declaration: BudgetMeteringDeclaration,
  binding: unknown,
  issuer: string,
  amount: BudgetAmount,
): BudgetChargeResolution {
  if (!isMissionBudgetBinding(binding)) return { kind: "unsupported" };
  const { currency, exponent } = declaration.unit;
  const declared = declaration.budgets.find((b) => b.owner === binding.owner && b.budget_id === binding.budget_id);
  if (!declared) return { kind: "unsupported" };
  if (
    binding.currency !== currency ||
    declared.currency !== currency ||
    binding.instance.max_budget.currency !== currency ||
    amount.currency !== currency
  ) {
    return { kind: "unsupported" };
  }
  if (compareAmounts(binding.limit, declared.limit) !== 0) return { kind: "unsupported" };
  const { policy } = binding;
  if (!declared.policies.some((p) => p.id === policy.id && p.version === policy.version && p.digest === policy.digest)) {
    return { kind: "unsupported" };
  }
  const sharedLimit = minorUnits(declared.limit, exponent);
  const instanceLimit = minorUnits(binding.instance.max_budget.amount, exponent);
  if (sharedLimit === undefined || instanceLimit === undefined) return { kind: "unsupported" };
  const amountMinor = minorUnits(amount.amount, exponent);
  if (amountMinor === undefined) return { kind: "amount_invalid" };
  const instanceKey = { issuer, mission_id: binding.instance.root_mission_id };
  const sharedKey = { owner: binding.owner, budget_id: binding.budget_id };
  return {
    kind: "charge",
    amountMinor,
    currency,
    exponent,
    counters: [
      { scope: "mission", key: instanceKey, id: budgetCounterId("mission", instanceKey), limitMinor: instanceLimit },
      { scope: "standing_consent", key: sharedKey, id: budgetCounterId("standing_consent", sharedKey), limitMinor: sharedLimit },
    ],
  };
}
