/**
 * @spec mission#authorization-derivation
 * @spec mission#subset
 * Mechanical derivation of the Authority Set from the Intent (and the
 * authority proposal, where one was submitted on the standard
 * `authorization_details` parameter, @spec mission#authority-proposal) under
 * the derivation policy ceiling. Intent and proposal are untrusted: nothing
 * they propose can widen past the ceiling (the compromised-shaper property).
 */

import { compareAmounts, isValidAmount } from "@mission/core";
import type { JsonValue } from "@mission/core";
import { IntentError } from "./intent.js";
import type { AuthorityEntry, DelegateMatcher, MissionIntent } from "./types.js";

/**
 * @spec mission#common-constraints — every `constraints` member name the core
 * defines as a specification-defined Common Constraint (the initial registry:
 * {{common-constraints}}). `max_amount` is IMPLEMENTED below; the rest are
 * not (the derivation engine narrows only `max_amount`/`vendors` today).
 * `vendors` is deliberately absent: it is a deployment-defined key, not a
 * registered Common Constraint, so it is out of scope for the fail-closed
 * rule and keeps its existing (implemented) handling.
 */
const REGISTERED_COMMON_CONSTRAINTS = new Set([
  "max_amount",
  "resource_issued_after",
  "resource_issued_before",
  "tenant",
  "recipient_domain",
  "time_window",
  "data_classification",
  "allowed_tools",
  "requires_action_approval",
]);

/** Common Constraint keys this derivation engine implements narrowing for. */
const IMPLEMENTED_COMMON_CONSTRAINTS = new Set(["max_amount"]);

/**
 * @spec mission#common-constraints — FAIL CLOSED (refuse the derivation)
 * when either operand carries a registered-but-unimplemented Common
 * Constraint. Silently dropping it (the prior behavior) would widen effective
 * authority: the operand's narrowing intent would vanish from the derived
 * entry with no trace. A key that is registered AND implemented (`max_amount`)
 * or that is not registered at all (deployment-defined, e.g. `vendors`) passes
 * through untouched.
 */
function assertNoUnimplementedCommonConstraint(constraints: AuthorityEntry["constraints"]): void {
  if (!constraints) return;
  for (const key of Object.keys(constraints)) {
    if (REGISTERED_COMMON_CONSTRAINTS.has(key) && !IMPLEMENTED_COMMON_CONSTRAINTS.has(key)) {
      throw new IntentError(
        "invalid_authorization_details",
        `registered Common Constraint '${key}' is not implemented by this derivation engine; refusing rather than silently dropping it`,
      );
    }
  }
}

export interface DerivationPolicy {
  policy_version: string;
  ceiling: readonly AuthorityEntry[];
}

/**
 * @spec mission#authority-proposal — `proposal` is the client-submitted
 * `authorization_details` array (the standard request parameter pushed
 * alongside `mission_intent`), already validated at intake
 * (validateAuthorityProposal). Narrowing mode (RECOMMENDED) applies when a
 * proposal is present; template mode (no proposal) derives from task + policy
 * alone. Semantics are unchanged from the retired Intent-carried member: the
 * proposal is untrusted and can never widen past the policy ceiling.
 */
export function deriveAuthoritySet(
  intent: MissionIntent,
  policy: DerivationPolicy,
  proposal?: readonly AuthorityEntry[],
): AuthorityEntry[] {
  const proposals = proposal?.length
    ? proposal
    : // Template mode: no concrete proposal derives the full policy ceiling
      // narrowed to the Intent's resources.
      policy.ceiling.filter((c) => intent.resources.includes(c.resource));

  const derived: AuthorityEntry[] = [];
  for (const proposal of proposals) {
    const ceiling = policy.ceiling.find((c) => c.resource === proposal.resource);
    if (!ceiling) continue;
    const entry = intersect(proposal, ceiling);
    if (entry) derived.push(entry);
  }
  if (derived.length === 0) {
    // @spec mission#submission-via-par: derivation failure is distinct from syntax.
    throw new IntentError("invalid_authorization_details", "Intent yields no valid Authority Set");
  }
  return derived;
}

/** Narrow proposal by ceiling; the result is a subset of both. */
function intersect(proposal: AuthorityEntry, ceiling: AuthorityEntry): AuthorityEntry | null {
  const actions = proposal.actions.filter((a) => ceiling.actions.includes(a));
  if (actions.length === 0) return null;
  // @spec mission#common-constraints — fail closed before narrowing anything:
  // an unimplemented registered key on EITHER operand must refuse, never
  // silently vanish from the derived entry below.
  assertNoUnimplementedCommonConstraint(proposal.constraints);
  assertNoUnimplementedCommonConstraint(ceiling.constraints);
  const entry: AuthorityEntry = { type: "mission_resource_access", resource: ceiling.resource, actions };
  const constraints: NonNullable<AuthorityEntry["constraints"]> = {};
  const ceilCap = ceiling.constraints?.max_amount;
  const propCap = proposal.constraints?.max_amount;
  const cap = minAmount(propCap, ceilCap);
  if (cap) constraints.max_amount = cap;
  const ceilVendors = ceiling.constraints?.vendors;
  const propVendors = proposal.constraints?.vendors;
  const vendors = ceilVendors
    ? propVendors
      ? propVendors.filter((v) => ceilVendors.includes(v))
      : [...ceilVendors]
    : propVendors;
  if (vendors) {
    if (vendors.length === 0) return null;
    constraints.vendors = vendors;
  }
  if (Object.keys(constraints).length > 0) entry.constraints = constraints;
  const delegation = narrowDelegation(proposal.delegation, ceiling.delegation);
  if (delegation) entry.delegation = delegation;
  return entry;
}

function minAmount(
  a: { amount: string; currency: string } | undefined,
  b: { amount: string; currency: string } | undefined,
): { amount: string; currency: string } | undefined {
  if (!a) return b;
  if (!b) return a;
  if (a.currency !== b.currency) return b; // ceiling wins on currency mismatch
  // @spec mission#max-amount — exact decimal-value comparison (never
  // IEEE-754 float): a malformed amount on either side refuses the
  // derivation rather than comparing as a silently-coerced NaN.
  if (!isValidAmount(a.amount) || !isValidAmount(b.amount)) {
    const bad = !isValidAmount(a.amount) ? a.amount : b.amount;
    throw new IntentError("invalid_authorization_details", `malformed max_amount value: ${JSON.stringify(bad)}`);
  }
  return compareAmounts(a.amount, b.amount) <= 0 ? a : b;
}

// ---------------------------------------------------------------------------
// @spec attenuation#delegation, child-delegation#fanout — delegation narrowing.
//
// `delegation` is a GRANT, not a restriction, so its carry rules INVERT the
// constraints (max_amount/vendors) idiom on the ceiling-absent branch:
//   - ceiling absent  -> result absent  (a capability the ceiling never granted
//     CANNOT be introduced by the untrusted proposal; the compromised-shaper
//     property). This is the DELIBERATE OPPOSITE of the vendors ceiling-absent
//     branch, which takes the proposal's.
//   - ceiling present, proposal omits -> INHERIT the ceiling's delegation
//     unchanged (exactly like `[...ceilVendors]` / minAmount(undefined,cap)=cap;
//     how a base mission acquires the delegable `children` on-switch).
//   - both present -> narrow. `max_depth` -> min. `allowed_delegates` is a
//     RESTRICTION *inside* an already-granted delegation, so it mirrors
//     `constraints.vendors` EXACTLY (ceiling-absent takes the proposal's; a
//     proposal volunteering a narrower delegate list is safe) — NOT the grant
//     flip. `children` is itself a GRANT (its PRESENCE is the child-creation
//     on-switch, {{child-delegation#fanout}}), so it takes the SAME flip one
//     level down. Unrecognized companion members are carried from the CEILING,
//     never the proposal: the derivation cannot evaluate semantics it does not
//     recognize, so a proposal-sourced unknown member would break the
//     untrusted-proposal property.
// ---------------------------------------------------------------------------

type Delegation = NonNullable<AuthorityEntry["delegation"]>;
type JsonObject = { [k: string]: JsonValue };

/** View a delegation/children object as an open JSON record (all-JSON at runtime). */
function jsonRec(v: object): { [k: string]: JsonValue | undefined } {
  return v as unknown as { [k: string]: JsonValue | undefined };
}

function asJsonObject(v: JsonValue | undefined): JsonObject | undefined {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as JsonObject) : undefined;
}

function asNum(v: JsonValue | undefined): number | undefined {
  return typeof v === "number" ? v : undefined;
}

function matcherKey(m: DelegateMatcher): string {
  return JSON.stringify([m.sub ?? null, m.sub_profile ?? null]);
}

function cloneMatcher(m: DelegateMatcher): DelegateMatcher {
  const out: DelegateMatcher = {};
  if (m.sub !== undefined) out.sub = m.sub;
  if (m.sub_profile !== undefined) out.sub_profile = m.sub_profile;
  return out;
}

function readMatchers(v: JsonValue | undefined): DelegateMatcher[] | undefined {
  if (!Array.isArray(v)) return undefined;
  return v.map((el) => {
    const o = asJsonObject(el);
    const m: DelegateMatcher = {};
    if (o && typeof o.sub === "string") m.sub = o.sub;
    if (o && typeof o.sub_profile === "string") m.sub_profile = o.sub_profile;
    return m;
  });
}

function matchersToJson(ms: DelegateMatcher[]): JsonValue {
  return ms.map((m) => cloneMatcher(m) as JsonObject);
}

/** min that inherits by default from the ceiling (mirrors minAmount). */
function minNum(a: number | undefined, b: number | undefined): number | undefined {
  if (a === undefined) return b;
  if (b === undefined) return a;
  return Math.min(a, b);
}

/**
 * Narrow a matcher list as a RESTRICTION, mirroring `constraints.vendors`:
 * ceiling-absent takes the proposal's; proposal-absent inherits the ceiling's;
 * both present -> proposal ∩ ceiling on the (sub, sub_profile) identity. Unlike
 * vendors an empty intersection does NOT kill the entry: delegation is a policy
 * on an otherwise-valid entry, so an empty delegate list just means "delegable
 * to nobody", never "the authority is void".
 */
function narrowMatchers(
  proposal: DelegateMatcher[] | undefined,
  ceiling: DelegateMatcher[] | undefined,
): DelegateMatcher[] | undefined {
  if (!ceiling) return proposal?.map(cloneMatcher);
  if (!proposal) return ceiling.map(cloneMatcher);
  const ceilKeys = new Set(ceiling.map(matcherKey));
  return proposal.filter((m) => ceilKeys.has(matcherKey(m))).map(cloneMatcher);
}

/** Narrow the `children` GRANT member-wise (both objects present). */
function narrowChildren(
  proposal: JsonObject | undefined,
  ceiling: JsonObject | undefined,
): JsonObject | undefined {
  if (!ceiling) return undefined; // GRANT flip: no children on-switch in the ceiling
  if (!proposal) return structuredClone(ceiling); // inherit the ceiling's children
  const out: JsonObject = {};
  // Unrecognized members carried from the CEILING (never the proposal).
  for (const k of Object.keys(ceiling)) {
    if (k === "max_children" || k === "max_child_depth" || k === "allowed_child_actors") continue;
    const v = ceiling[k];
    if (v !== undefined) out[k] = structuredClone(v);
  }
  const maxChildren = minNum(asNum(proposal.max_children), asNum(ceiling.max_children));
  if (maxChildren !== undefined) out.max_children = maxChildren;
  const maxChildDepth = minNum(asNum(proposal.max_child_depth), asNum(ceiling.max_child_depth));
  if (maxChildDepth !== undefined) out.max_child_depth = maxChildDepth;
  const actors = narrowMatchers(
    readMatchers(proposal.allowed_child_actors),
    readMatchers(ceiling.allowed_child_actors),
  );
  if (actors) out.allowed_child_actors = matchersToJson(actors);
  return out;
}

function narrowDelegation(
  proposal: AuthorityEntry["delegation"],
  ceiling: AuthorityEntry["delegation"],
): AuthorityEntry["delegation"] | undefined {
  if (!ceiling) return undefined; // GRANT flip (see block comment above)
  if (!proposal) return structuredClone(ceiling); // inherit unchanged
  const out: Delegation = { max_depth: Math.min(proposal.max_depth, ceiling.max_depth) };
  // Unrecognized companion members carried from the CEILING, never the proposal.
  const ceilRec = jsonRec(ceiling);
  for (const k of Object.keys(ceiling)) {
    if (k === "max_depth" || k === "allowed_delegates" || k === "children") continue;
    const v = ceilRec[k];
    if (v !== undefined) out[k] = structuredClone(v);
  }
  const delegates = narrowMatchers(proposal.allowed_delegates, ceiling.allowed_delegates);
  if (delegates) out.allowed_delegates = delegates;
  const children = narrowChildren(asJsonObject(proposal.children), asJsonObject(ceiling.children));
  if (children) out.children = children;
  return out;
}

/** @spec mission#subset — entry-wise subset test (resource byte-exact). */
export function isSubsetEntry(candidate: AuthorityEntry, granted: AuthorityEntry): boolean {
  if (candidate.type !== granted.type) return false;
  if (candidate.resource !== granted.resource) return false;
  if (!candidate.actions.every((a) => granted.actions.includes(a))) return false;
  const gCap = granted.constraints?.max_amount;
  const cCap = candidate.constraints?.max_amount;
  if (gCap) {
    if (!cCap) return false;
    if (cCap.currency !== gCap.currency) return false;
    // @spec mission#max-amount — exact decimal-value comparison. A malformed
    // amount on either side fails closed (not a subset) rather than comparing
    // via IEEE-754 float coercion; isSubsetEntry stays a total, non-throwing
    // predicate so its callers (e.g. child-delegation's strict-subset gate)
    // keep treating it as a plain boolean.
    if (!isValidAmount(cCap.amount) || !isValidAmount(gCap.amount)) return false;
    if (compareAmounts(cCap.amount, gCap.amount) > 0) return false;
  }
  const gVendors = granted.constraints?.vendors;
  const cVendors = candidate.constraints?.vendors;
  if (gVendors) {
    if (!cVendors) return false;
    if (!cVendors.every((v) => gVendors.includes(v))) return false;
  }
  // @spec attenuation#delegation, child-delegation#attenuation — delegation is a
  // GRANT and NARROWS: the direction is the OPPOSITE of the constraint rules
  // above. A candidate that OMITS delegation the grantor has is strictly
  // narrower (the child simply does not re-delegate) and PASSES; a candidate
  // that INTRODUCES delegation the grantor lacks FAILS.
  const gDel = granted.delegation;
  const cDel = candidate.delegation;
  if (cDel && !gDel) return false; // introduces delegation the grantor lacks
  if (gDel && cDel) {
    if (cDel.max_depth > gDel.max_depth) return false;
    // allowed_delegates is a RESTRICTION -> subset direction mirrors vendors.
    if (!matchersSubset(cDel.allowed_delegates, gDel.allowed_delegates)) return false;
    if (!childrenNoBroader(asJsonObject(cDel.children), asJsonObject(gDel.children))) return false;
  }
  // gDel present, cDel absent -> PASS: the child does not re-delegate.
  return true;
}

/** A restriction-list subset test mirroring the vendors rule: grantor-absent is
 *  unconstrained (any candidate ⊆); grantor-present + candidate-absent is
 *  broader (fails); both present requires candidate ⊆ granted on identity. */
function matchersSubset(
  candidate: DelegateMatcher[] | undefined,
  granted: DelegateMatcher[] | undefined,
): boolean {
  if (!granted) return true;
  if (!candidate) return false;
  const gKeys = new Set(granted.map(matcherKey));
  return candidate.every((m) => gKeys.has(matcherKey(m)));
}

/** A cap (max_children/max_child_depth) is no broader: grantor-unbounded admits
 *  any candidate; grantor-bounded + candidate-unbounded is broader (fails). */
function capNoBroader(candidate: number | undefined, granted: number | undefined): boolean {
  if (granted === undefined) return true;
  if (candidate === undefined) return false;
  return candidate <= granted;
}

/** `children` is a GRANT: candidate introducing it where the grantor has none
 *  FAILS; candidate omitting it PASSES; both present narrow member-wise. */
function childrenNoBroader(
  candidate: JsonObject | undefined,
  granted: JsonObject | undefined,
): boolean {
  if (candidate && !granted) return false; // introduces the child-creation on-switch
  if (!candidate) return true; // omits -> strictly narrower
  if (!capNoBroader(asNum(candidate.max_children), asNum(granted?.max_children))) return false;
  if (!capNoBroader(asNum(candidate.max_child_depth), asNum(granted?.max_child_depth))) return false;
  return matchersSubset(
    readMatchers(candidate.allowed_child_actors),
    readMatchers(granted?.allowed_child_actors),
  );
}

export function isSubsetSet(candidate: AuthorityEntry[], granted: AuthorityEntry[]): boolean {
  return candidate.every((c) => granted.some((g) => isSubsetEntry(c, g)));
}
