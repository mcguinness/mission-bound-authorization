/**
 * @spec runtime#input-authority, runtime-oauth#authorization-details-mapping
 * (#825) — the credential authority bound: the authority the verified access
 * credential itself carries, evaluated independently of the current effective
 * Mission authority. A broader Mission, or an allowing resource policy, never
 * repairs a narrower credential.
 *
 * Fail-closed throughout. A credential whose authority this module cannot read
 * in full (an unknown entry type or member, or a constraint this enforcement
 * point cannot evaluate) is refused when it is verified, never normalized into
 * a broader grant; and an entry whose condition cannot be established at this
 * enforcement point never permits.
 */

import type { AATConstraint, AATTools } from "./attenuation-chain.js";
import { parseAatToolId } from "./attenuation-chain.js";
import type { AuthorityEntry, TerminalWhenCondition } from "./authority-entry.js";
import { conditionCanonicalBytes } from "./authority-subset.js";
import {
  type CommonConstraintKey,
  type ConstraintFacts,
  commonConstraintGatesOverMembers,
  IMPLEMENTED_COMMON_CONSTRAINTS,
  isImplementedCommonConstraint,
  validCommonConstraint,
} from "./common-constraints.js";
import { compareAmounts, isCurrencyCode, isValidAmount } from "./decimal-amount.js";
import { entryMatchesTarget, resourceMatchViolation } from "./operation-target.js";
import {
  type ResourceContractRef,
  resourceContractOf,
  resourceContractViolation,
  sameResourceContract,
} from "./resource-contract.js";

/** One entry of a verified credential's authority. */
export interface CredentialAuthorityEntry {
  type: "mission_resource_access";
  resource: string;
  /**
   * @spec resource-access#resource-matching (#1276): carried only when the
   * credential states it; absent is `exact`. Both forms Resource Access
   * defines are enforced, through the one matcher.
   */
  resource_match?: "exact" | "prefix";
  actions: string[];
  /**
   * @spec resource-access#resource-contract (#249, D553): the contract the
   * entry authorizes operations under. "A resource server MUST NOT treat an
   * entry carrying `resource_contract` as authorizing an operation unless it
   * performs that operation under exactly the referenced contract"
   * ({@link entryCoversFacts}).
   */
  resource_contract?: ResourceContractRef;
  constraints?: {
    max_amount?: { amount: string; currency: string };
    vendors?: string[];
    requires_action_approval?: boolean;
    terminal_when?: TerminalWhenCondition[];
    /** @spec resource-access#initial-common-constraints (#1266), read through common-constraints.ts. */
    resource_issued_after?: string;
    resource_issued_before?: string;
    tenant?: string;
    time_window?: { not_before?: string; not_after?: string };
    recipient_domain?: string;
    data_classification?: string[];
    allowed_tools?: string[];
  };
}

/** Thrown when a credential's authority cannot be read in full. */
export class CredentialAuthorityError extends Error {}

/**
 * Entry members a credential may carry beyond the ones this bound evaluates:
 * `delegation` is a grant to delegate further, and `capability_sources` is a
 * catalog binding the Mission bound checks; neither restricts an action at the
 * point of use, so neither can be lost by not evaluating it here.
 */
const IGNORED_ENTRY_MEMBERS = new Set(["delegation", "capability_sources"]);
const EVALUATED_ENTRY_MEMBERS = new Set([
  "type",
  "resource",
  "resource_match",
  "actions",
  "constraints",
  // @spec resource-access#rs-enforcement (#249): "`resource_contract` is
  // enforced as {{resource-contract}} requires", by the contract comparison
  // of {@link entryCoversFacts}.
  "resource_contract",
]);
const CONSTRAINT_KEYS = new Set<string>([
  "max_amount",
  "vendors",
  "requires_action_approval",
  "terminal_when",
  // @spec resource-access#rs-enforcement (#1266): each implemented Common
  // Constraint, evaluated against the facts the enforcement point establishes.
  ...IMPLEMENTED_COMMON_CONSTRAINTS,
]);

/** @spec discharge#terminal-when — `1*64( ALPHA / DIGIT / "-" / "_" / ":" / "." )`. */
const DISCHARGE_AUTHORITY = /^[A-Za-z0-9\-_:.]{1,64}$/;

const nonEmptyString = (v: unknown): v is string => typeof v === "string" && v.length > 0;
const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

function parseConstraints(
  value: unknown,
  at: string,
): CredentialAuthorityEntry["constraints"] | undefined {
  if (value === undefined) return undefined;
  if (!isObject(value)) throw new CredentialAuthorityError(`${at}.constraints must be an object`);
  const out: NonNullable<CredentialAuthorityEntry["constraints"]> = {};
  for (const key of Object.keys(value)) {
    if (!CONSTRAINT_KEYS.has(key))
      throw new CredentialAuthorityError(`${at}.constraints.${key} is not enforceable here`);
  }
  if (value.max_amount !== undefined) {
    const cap = value.max_amount;
    if (
      !isObject(cap) ||
      typeof cap.amount !== "string" ||
      !isValidAmount(cap.amount) ||
      // @spec resource-access#initial-common-constraints (#1595, D727).
      !isCurrencyCode(cap.currency)
    ) {
      throw new CredentialAuthorityError(`${at}.constraints.max_amount is malformed`);
    }
    out.max_amount = { amount: cap.amount, currency: cap.currency };
  }
  if (value.vendors !== undefined) {
    if (!Array.isArray(value.vendors) || !value.vendors.every(nonEmptyString)) {
      throw new CredentialAuthorityError(
        `${at}.constraints.vendors must be an array of vendor identifiers`,
      );
    }
    out.vendors = [...value.vendors];
  }
  if (value.requires_action_approval !== undefined) {
    if (typeof value.requires_action_approval !== "boolean") {
      throw new CredentialAuthorityError(
        `${at}.constraints.requires_action_approval must be a boolean`,
      );
    }
    out.requires_action_approval = value.requires_action_approval;
  }
  if (value.terminal_when !== undefined) {
    // @spec discharge#terminal-when — the shape the AS admits: one or more
    // conditions, each exactly { event_type, discharge_authority? }, the
    // authority in its registered syntax, no two sharing a canonical form.
    // An unknown member is refused, never dropped: condition identity is the
    // whole object's canonical bytes, so ignoring a member misreads it.
    const conditions = value.terminal_when;
    if (!Array.isArray(conditions) || conditions.length === 0) {
      throw new CredentialAuthorityError(`${at}.constraints.terminal_when is malformed`);
    }
    const seen = new Set<string>();
    for (const c of conditions) {
      const bytes = conditionCanonicalBytes(c);
      if (bytes === undefined) {
        throw new CredentialAuthorityError(
          `${at}.constraints.terminal_when carries a condition other than { event_type, discharge_authority? }`,
        );
      }
      if (seen.has(bytes)) {
        throw new CredentialAuthorityError(
          `${at}.constraints.terminal_when carries two identical conditions`,
        );
      }
      seen.add(bytes);
      const authority = (c as TerminalWhenCondition).discharge_authority;
      if (authority !== undefined && !DISCHARGE_AUTHORITY.test(authority)) {
        throw new CredentialAuthorityError(
          `${at}.constraints.terminal_when carries a malformed discharge_authority`,
        );
      }
    }
    out.terminal_when = (conditions as TerminalWhenCondition[]).map((c) => ({ ...c }));
  }
  // @spec resource-access#initial-common-constraints (#1266): a malformed
  // value refuses the credential, never reads as an absent bound.
  for (const key of Object.keys(value)) {
    if (!isImplementedCommonConstraint(key)) continue;
    if (!validCommonConstraint(key, value[key])) {
      throw new CredentialAuthorityError(`${at}.constraints.${key} is malformed`);
    }
    (out as Record<string, unknown>)[key] = structuredClone(value[key]);
  }
  return out;
}

/**
 * Read a verified credential's `authorization_details` as its authority. The
 * value MUST be an array of `mission_resource_access` entries; anything this
 * enforcement point cannot evaluate refuses the whole credential.
 */
export function parseCredentialAuthority(value: unknown): readonly CredentialAuthorityEntry[] {
  if (!Array.isArray(value))
    throw new CredentialAuthorityError("authorization_details must be an array");
  return Object.freeze(
    value.map((raw, i) => {
      const at = `authorization_details[${i}]`;
      if (!isObject(raw)) throw new CredentialAuthorityError(`${at} must be an object`);
      if (raw.type !== "mission_resource_access") {
        throw new CredentialAuthorityError(
          `${at}.type ${JSON.stringify(raw.type)} is not understood`,
        );
      }
      for (const key of Object.keys(raw)) {
        if (!EVALUATED_ENTRY_MEMBERS.has(key) && !IGNORED_ENTRY_MEMBERS.has(key)) {
          throw new CredentialAuthorityError(`${at}.${key} is not understood`);
        }
      }
      if (!nonEmptyString(raw.resource))
        throw new CredentialAuthorityError(`${at}.resource must be a non-empty string`);
      // @spec resource-access#rs-enforcement (#1276): an entry whose
      // `resource_match` this enforcement point does not recognize, or a
      // `prefix` entry whose `resource` it cannot match (a query, or no `//`
      // authority), cannot be evaluated in full, so it refuses the whole
      // credential like any other such member, never read as `exact`.
      const matchViolation = resourceMatchViolation(raw);
      if (matchViolation !== undefined) {
        throw new CredentialAuthorityError(`${at}: ${matchViolation}; not enforceable here`);
      }
      if (
        !Array.isArray(raw.actions) ||
        raw.actions.length === 0 ||
        !raw.actions.every(nonEmptyString)
      ) {
        throw new CredentialAuthorityError(
          `${at}.actions must be a non-empty array of action identifiers`,
        );
      }
      const constraints = parseConstraints(raw.constraints, at);
      // @spec resource-access#entry-validation (#249): a malformed reference
      // cannot be enforced, so it refuses the whole credential, never reads
      // as an entry without one.
      if (raw.resource_contract !== undefined) {
        const violation = resourceContractViolation(raw.resource_contract);
        if (violation !== undefined) throw new CredentialAuthorityError(`${at}: ${violation}`);
      }
      const resourceContract = resourceContractOf(raw.resource_contract);
      const entry: CredentialAuthorityEntry = {
        type: "mission_resource_access",
        resource: raw.resource,
        ...(raw.resource_match === "exact" || raw.resource_match === "prefix"
          ? { resource_match: raw.resource_match }
          : {}),
        actions: [...raw.actions],
        ...(resourceContract !== undefined ? { resource_contract: resourceContract } : {}),
        ...(constraints !== undefined ? { constraints } : {}),
      };
      return Object.freeze(entry);
    }),
  );
}

function amountCapFromRange(
  name: string,
  c: AATConstraint,
  at: string,
): { amount: string; currency: string } {
  if (c.constraint_type !== "range" || typeof c.max !== "number" || c.min !== undefined) {
    throw new CredentialAuthorityError(`${at}.${name} must be a range carrying only max`);
  }
  const amount = String(c.max);
  // The deployment's argument naming (`amount_` and the currency in lower
  // case, attenuation#root-mapping "under the deployment's rules"): exactly
  // three lower-case ASCII letters, mapped to the upper-case code; any other
  // suffix is malformed, never folded (#1595, D727).
  const suffix = name.slice("amount_".length);
  const currency = /^[a-z]{3}$/.test(suffix) ? suffix.toUpperCase() : "";
  if (!isCurrencyCode(currency) || !isValidAmount(amount))
    throw new CredentialAuthorityError(`${at}.${name} is malformed`);
  return { amount, currency };
}

/**
 * @spec attenuation#root-mapping — an attenuation token's `tools` map as
 * credential authority entries, one per tool. Strict: a tool argument this
 * enforcement point cannot evaluate (an unknown argument, a `min` bound, an
 * `exact` constraint) refuses, so a narrowing never disappears in mapping.
 */
export function credentialEntriesFromAatTools(
  tools: AATTools,
): readonly CredentialAuthorityEntry[] {
  return Object.freeze(
    Object.entries(tools).map(([toolId, args]) => {
      const at = `tools[${JSON.stringify(toolId)}]`;
      const { resource, action } = parseAatToolId(toolId);
      const constraints: NonNullable<CredentialAuthorityEntry["constraints"]> = {};
      for (const [name, c] of Object.entries(args)) {
        if (name === "vendor") {
          if (
            c.constraint_type !== "enum" ||
            !Array.isArray(c.values) ||
            !c.values.every(nonEmptyString)
          ) {
            throw new CredentialAuthorityError(
              `${at}.vendor must be an enum of vendor identifiers`,
            );
          }
          constraints.vendors = [...c.values];
        } else if (name.startsWith("amount_")) {
          if (constraints.max_amount)
            throw new CredentialAuthorityError(`${at} carries more than one amount bound`);
          constraints.max_amount = amountCapFromRange(name, c, at);
        } else {
          throw new CredentialAuthorityError(`${at}.${name} is not enforceable here`);
        }
      }
      const entry: CredentialAuthorityEntry = {
        type: "mission_resource_access",
        resource,
        actions: [action],
        ...(Object.keys(constraints).length > 0 ? { constraints } : {}),
      };
      return Object.freeze(entry);
    }),
  );
}

/** What the enforcement point established about the action it is about to authorize. */
export interface CredentialTarget {
  /**
   * @spec resource-access#resource-matching (#1276, D457): the operation
   * target the enforcement point established from its trusted operation
   * contract, never the token's audience and never an entry's `resource`.
   */
  resource: string;
  action: string;
  /**
   * Every vendor the action reaches, resolved by the enforcement point: one
   * for a single object, every member for a collection, empty when the action
   * names no vendor.
   */
  vendorIds: readonly string[];
  /** The action's amount, resolved by the enforcement point, when it has one. */
  amount?: { amount: string; currency: string };
  /**
   * @spec resource-access#resource-contract (#249, D553): the contract the
   * enforcement point will perform the operation under, resolved against its
   * own trusted declarations; absent when it performs under none. An entry
   * covers the action only when its own reference equals this one, absent
   * against absent ({@link entryCoversFacts}).
   */
  resourceContract?: ResourceContractRef;
  /**
   * @spec resource-access#rs-enforcement (#1266): the authoritative facts the
   * implemented Common Constraints read, established by the enforcement point
   * from its own records. An absent fact satisfies no bound that reads it.
   */
  constraintFacts?: ConstraintFacts;
  /**
   * @spec resource-access#initial-common-constraints (#1266): for an action
   * over a collection, each member's own facts, established by the
   * enforcement point from its own records. Present, every member is
   * evaluated and one that fails or lacks a fact denies the whole action.
   */
  constraintMembers?: readonly ConstraintFacts[];
  /**
   * Whether this enforcement path independently requires an action-bound
   * approval for the action, so an entry demanding one is honored.
   */
  approvalEnforced: boolean;
}

/** The facts about an action an enforcement point establishes by itself. */
export type CredentialFacts = Omit<CredentialTarget, "approvalEnforced">;

/**
 * Whether an entry names the action's operation target and action, before any
 * constraint. The target is matched with the Resource Access matcher
 * (@spec resource-access#resource-matching, #1276).
 */
export function entryMatchesAction(
  entry: CredentialAuthorityEntry,
  facts: Pick<CredentialFacts, "resource" | "action">,
): boolean {
  return entryMatchesTarget(entry, facts.resource) && entry.actions.includes(facts.action);
}

/** The constraint gates an evaluation of one entry reached, and whether each held. */
export interface CredentialConstraintTrace {
  satisfied: boolean;
  /** The keys whose gate ran, in order; a gate after a failed one is never reached. */
  evaluated: ("vendors" | "max_amount" | CommonConstraintKey)[];
}

/**
 * Evaluate an entry's establishable constraints gate by gate, `vendors`, then
 * `max_amount`, then each implemented Common Constraint (common-constraints.ts),
 * stopping at the first that fails. `evaluated` is what Decision Evidence may
 * record for the entry: a check never reached is never listed
 * (@spec runtime-evidence#decision-evidence-object).
 */
export function credentialConstraintGates(
  entry: CredentialAuthorityEntry,
  facts: Pick<CredentialFacts, "vendorIds" | "amount" | "constraintFacts" | "constraintMembers">,
): CredentialConstraintTrace {
  const c = entry.constraints;
  const evaluated: CredentialConstraintTrace["evaluated"] = [];
  if (c?.vendors !== undefined) {
    evaluated.push("vendors");
    const vendors = c.vendors;
    if (facts.vendorIds.length === 0 || !facts.vendorIds.every((v) => vendors.includes(v))) {
      return { satisfied: false, evaluated };
    }
  }
  if (c?.max_amount !== undefined) {
    evaluated.push("max_amount");
    const amt = facts.amount;
    if (
      !amt ||
      amt.currency !== c.max_amount.currency ||
      !isValidAmount(amt.amount) ||
      compareAmounts(amt.amount, c.max_amount.amount) > 0
    ) {
      return { satisfied: false, evaluated };
    }
  }
  const common = commonConstraintGatesOverMembers(
    c,
    facts.constraintFacts ?? {},
    facts.constraintMembers,
  );
  evaluated.push(...common.evaluated);
  if (!common.satisfied) return { satisfied: false, evaluated };
  return { satisfied: true, evaluated };
}

/**
 * Whether an entry covers the action on the facts an enforcement point
 * establishes by itself: resource, action, every vendor reached and the
 * amount. The entry's discharge condition and approval requirement are not
 * judged here: they turn on Mission state and approvals the PDP holds, so a
 * PEP refuses only what these facts already rule out and the PDP decides the
 * rest (@spec runtime#input-authority, D312).
 */
export function entryCoversFacts(entry: CredentialAuthorityEntry, facts: CredentialFacts): boolean {
  return (
    entryMatchesAction(entry, facts) &&
    // @spec resource-access#resource-contract (#249): "A resource server MUST
    // NOT treat an entry carrying `resource_contract` as authorizing an
    // operation unless it performs that operation under exactly the
    // referenced contract". An entry without one covers only an operation
    // performed under no contract; whether the resource requires one is the
    // enforcement point's own check.
    sameResourceContract(entry.resource_contract, facts.resourceContract) &&
    credentialConstraintGates(entry, facts).satisfied
  );
}

/**
 * The credential entries that cover the action on establishable facts, in
 * order. Each is a whole-entry candidate; the PDP applies the discharge and
 * approval conditions of the one it relies on.
 */
export function coveringCredentialEntries(
  entries: readonly CredentialAuthorityEntry[],
  facts: CredentialFacts,
): readonly CredentialAuthorityEntry[] {
  return entries.filter((entry) => entryCoversFacts(entry, facts));
}

function entryPermits(entry: CredentialAuthorityEntry, target: CredentialTarget): boolean {
  if (!entryCoversFacts(entry, target)) return false;
  const c = entry.constraints;
  // A discharge condition is evaluated against Mission state this check does
  // not hold, so an entry carrying one cannot be shown undischarged here.
  if (c?.terminal_when !== undefined && c.terminal_when.length > 0) return false;
  if (c?.requires_action_approval === true && !target.approvalEnforced) return false;
  return true;
}

/**
 * Whether the credential's own authority covers the action. One entry must
 * permit it whole: an action from one entry never combines with a constraint
 * satisfied by another.
 */
export function credentialAuthorityPermits(
  entries: readonly CredentialAuthorityEntry[],
  target: CredentialTarget,
): boolean {
  return entries.some((entry) => entryPermits(entry, target));
}

/** A Mission Authority Set entry read as credential authority (for fixtures and projections). */
export function credentialEntriesFromAuthority(
  entries: readonly AuthorityEntry[],
): readonly CredentialAuthorityEntry[] {
  // @spec resource-access#resource-matching (#1276): `resource_match` is
  // carried, so a `prefix` entry is read as `prefix`, never as `exact`.
  // @spec resource-access#resource-contract (#249): the reference is carried,
  // so the entry is read under the contract it was approved under.
  return parseCredentialAuthority(
    entries.map(({ type, resource, resource_match, actions, resource_contract, constraints }) => ({
      type,
      resource,
      ...(resource_match !== undefined ? { resource_match } : {}),
      actions,
      ...(resource_contract !== undefined ? { resource_contract } : {}),
      ...(constraints ? { constraints } : {}),
    })),
  );
}
