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
import { compareAmounts, isValidAmount } from "./decimal-amount.js";

/** One entry of a verified credential's authority. */
export interface CredentialAuthorityEntry {
  type: "mission_resource_access";
  resource: string;
  actions: string[];
  constraints?: {
    max_amount?: { amount: string; currency: string };
    vendors?: string[];
    requires_action_approval?: boolean;
    terminal_when?: TerminalWhenCondition[];
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
const EVALUATED_ENTRY_MEMBERS = new Set(["type", "resource", "actions", "constraints"]);
const CONSTRAINT_KEYS = new Set([
  "max_amount",
  "vendors",
  "requires_action_approval",
  "terminal_when",
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
      !nonEmptyString(cap.currency)
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
      const entry: CredentialAuthorityEntry = {
        type: "mission_resource_access",
        resource: raw.resource,
        actions: [...raw.actions],
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
  const currency = name.slice("amount_".length).toUpperCase();
  if (!currency || !isValidAmount(amount))
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
  /** The canonical resource identifier the action targets. */
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
   * Whether this enforcement path independently requires an action-bound
   * approval for the action, so an entry demanding one is honored.
   */
  approvalEnforced: boolean;
}

/** The facts about an action an enforcement point establishes by itself. */
export type CredentialFacts = Omit<CredentialTarget, "approvalEnforced">;

/**
 * Whether an entry covers the action on the facts an enforcement point
 * establishes by itself: resource, action, every vendor reached and the
 * amount. The entry's discharge condition and approval requirement are not
 * judged here: they turn on Mission state and approvals the PDP holds, so a
 * PEP refuses only what these facts already rule out and the PDP decides the
 * rest (@spec runtime#input-authority, D312).
 */
export function entryCoversFacts(entry: CredentialAuthorityEntry, facts: CredentialFacts): boolean {
  if (entry.resource !== facts.resource || !entry.actions.includes(facts.action)) return false;
  const c = entry.constraints;
  if (!c) return true;
  if (c.vendors !== undefined) {
    if (facts.vendorIds.length === 0) return false;
    if (!facts.vendorIds.every((v) => c.vendors?.includes(v))) return false;
  }
  if (c.max_amount !== undefined) {
    const amt = facts.amount;
    if (!amt || amt.currency !== c.max_amount.currency || !isValidAmount(amt.amount)) return false;
    if (compareAmounts(amt.amount, c.max_amount.amount) > 0) return false;
  }
  return true;
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
  return parseCredentialAuthority(
    entries.map(({ type, resource, actions, constraints }) => ({
      type,
      resource,
      actions,
      ...(constraints ? { constraints } : {}),
    })),
  );
}
