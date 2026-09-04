/**
 * @spec mission#authorization-derivation
 * @spec mission#subset
 * Mechanical derivation of the Authority Set from the Intent (and the
 * authority proposal, where one was submitted on the standard
 * `authorization_details` parameter, @spec mission#authority-proposal) under
 * the derivation policy ceiling. Intent and proposal are untrusted: nothing
 * they propose can widen past the ceiling (the compromised-shaper property).
 */

import { capabilitySourceIdentity, compareAmounts, isValidAmount } from "@mission/core";
import type { CapabilitySourceBinding, JsonValue } from "@mission/core";
import { conditionsNoBroader, unionConditions } from "./discharge.js";
import { IntentError } from "./intent.js";
import type { AuthorityEntry, DelegateMatcher, MissionIntent, MissionRecord } from "./types.js";

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
  // @spec discharge#terminal-when — a specification-defined Common Constraint
  // registered by the Status profile (its completion capability), IMPLEMENTED
  // below: entry completion conditions, narrowed by union.
  "terminal_when",
]);

/**
 * Common Constraint keys this derivation engine implements narrowing for.
 * `terminal_when` (@spec discharge#terminal-when) joins them: its narrowing is the
 * UNION of the two condition arrays ({@link unionConditions}), the direction
 * the subset rule fixes (a candidate must carry every reference condition and
 * MAY add more).
 */
const IMPLEMENTED_COMMON_CONSTRAINTS = new Set([
  "max_amount",
  "requires_action_approval",
  "terminal_when",
]);

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
  /**
   * @spec mission#derivation-issuance-policy — the deployment's own ceiling on
   * `derivation_limit`, independent of any client `requested_derivation_limit`.
   * `null`/absent means the deployment imposes no ceiling of its own, so the
   * effective value is the client's request unchanged (or `null`, unbounded,
   * if the client requested nothing either). See {@link resolveDerivationLimit}.
   */
  derivation_limit_ceiling?: number | null;
}

/**
 * @spec mission#derivation-issuance-policy — resolve the immutable, effective
 * `derivation_limit` a Mission Record commits: `min(policy ceiling, client
 * request)` when both are present, whichever alone is present when only one
 * is, and `null` (no ceiling: not "unbounded by omission" as a special case,
 * simply the absence of any established ceiling) when neither is. A request
 * can only narrow the policy ceiling, never widen past it.
 */
export function resolveDerivationLimit(
  requested: number | null | undefined,
  policyCeiling: number | null | undefined,
): number | null {
  const req = requested ?? null;
  const ceil = policyCeiling ?? null;
  if (req === null) return ceil;
  if (ceil === null) return req;
  return Math.min(req, ceil);
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
  // @spec mission#error-mapping — captured BEFORE the template-mode fallback
  // below reassigns `proposals`: whether the client actually submitted an
  // `authorization_details` proposal is the sole discriminator between the
  // two empty-result error codes this function can throw.
  const hasProposal = Boolean(proposal?.length);
  const proposals = hasProposal
    ? (proposal as readonly AuthorityEntry[])
    : // Template mode / configured-mapping: no concrete proposal derives the
      // full policy ceiling narrowed to the Intent's target_resources.
      policy.ceiling.filter((c) => intent.target_resources.includes(c.resource));

  // @spec mission#authorization-derivation (#743, review #745 P2) — a
  // SUBMITTED proposal element is intersected against EVERY ceiling entry
  // sharing its resource, not just the first (`Array.prototype.find`, the
  // prior shape): a single resource MAY be governed by more than one ceiling
  // entry (e.g. a money-carrying group and a non-money group split along the
  // actions each carries genuinely different constraints for), and one
  // proposal element MAY legitimately span several of them, each
  // contributing its own narrowed fragment. NOT de-duplicated: two
  // byte-identical proposal entries (the discharge equivalence-class case,
  // @spec discharge#terminal-when) must still derive two separate entries,
  // exactly as the prior single-`find` shape did for each proposal element in
  // turn. For any ceiling with exactly one entry per resource (every
  // deployment before #743's split), this is a no-op: one matching entry is
  // exactly what `find` already returned.
  //
  // In CONFIGURED-MAPPING mode (no submitted proposal) `proposal` here is
  // already one of the ceiling entries selected by the `proposals` fallback
  // above, not untrusted client input. Fanning it across every same-resource
  // ceiling entry AGAIN would cross-multiply: two same-resource entries whose
  // constraints partially overlap would derive not the two mapped entries but
  // up to four, including synthetic cross-fragments neither entry ever
  // proposed (review #745). That does not widen the semantic union (each
  // cross-fragment is still a subset of both ceiling entries), but it changes
  // the rendered/committed Authority Set and therefore `authority_hash`,
  // which is load-bearing across this family. Configured-mapping instead
  // validates/self-intersects each mapped candidate once: `[proposal]` is the
  // sole "ceiling" it fans across, so `intersect(entry, entry)` reconstructs
  // the entry unchanged rather than pairing it with its siblings.
  const derived: AuthorityEntry[] = [];
  for (const proposal of proposals) {
    const matchingCeilings = hasProposal
      ? policy.ceiling.filter((c) => c.resource === proposal.resource)
      : [proposal];
    for (const ceiling of matchingCeilings) {
      const entry = intersect(proposal, ceiling);
      if (entry) derived.push(entry);
    }
  }
  if (derived.length === 0) {
    // @spec mission#error-mapping: a submitted RAR proposal that derives
    // nothing is invalid_authorization_details (an actual proposal was
    // invalid against the ceiling); a configured-mapping result that derives
    // nothing is access_denied (no proposal existed to be invalid — the
    // request was well-formed and AS policy alone yields no authority).
    throw new IntentError(
      hasProposal ? "invalid_authorization_details" : "access_denied",
      hasProposal
        ? "Intent yields no valid Authority Set from the submitted proposal"
        : "Intent yields no valid Authority Set under configured-mapping policy",
    );
  }
  return derived;
}

/**
 * Narrow proposal by ceiling; the result is a subset of both.
 *
 * @spec capability-binding#capability-source-binding — `capability_sources` is
 * NEVER read from either operand here. The derived entry is built member by
 * member below, so a proposal carrying the member cannot inject a binding (the
 * compromised-shaper property this function already applies to `delegation`),
 * and a ceiling entry cannot pre-seed one either: bindings originate only in
 * the validating server's trusted catalog resolution and are attached in
 * `approve`, before `authority_hash`.
 */
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
  // @spec txn-authorization#applicability — monotonic OR: `true` on EITHER
  // operand narrows, so a ceiling that requires action-bound approval cannot be
  // shed by a proposal that omits the member (and `false` is just omission).
  if (ceiling.constraints?.requires_action_approval === true || proposal.constraints?.requires_action_approval === true) {
    constraints.requires_action_approval = true;
  }
  // @spec discharge#terminal-when, discharge#subset-extension — monotonic UNION: the
  // derived entry carries every completion condition either operand names, so a
  // ceiling condition cannot be shed by a proposal that omits it and a proposal
  // MAY add its own (an added condition only discharges sooner, a narrowing).
  // Deduplicated by condition identity and sorted by canonical bytes, so the
  // derived array is reproducible.
  const conditions = unionConditions(
    proposal.constraints?.terminal_when,
    ceiling.constraints?.terminal_when,
  );
  if (conditions) constraints.terminal_when = conditions;
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
  // @spec txn-authorization#applicability — a delegated child MUST preserve
  // `requires_action_approval: true`; dropping it (or restating it as `false`,
  // which is equivalent to omission) would WIDEN, so it is not a subset.
  if (granted.constraints?.requires_action_approval === true &&
      candidate.constraints?.requires_action_approval !== true) {
    return false;
  }
  // @spec discharge#subset-extension — a derived entry carries every parent
  // completion condition unchanged and MAY add more: dropping or altering one
  // WIDENS (a verifier cannot tell from opaque event types whether a changed
  // condition discharges earlier or later), so it is not a subset.
  if (!conditionsNoBroader(candidate.constraints?.terminal_when, granted.constraints?.terminal_when)) {
    return false;
  }
  // @spec capability-binding#capability-source-binding — MONOTONIC derivation:
  // a candidate retaining a catalog-sourced action carries every binding the
  // grantor recorded for that action, byte-identical, and introduces none the
  // grantor lacks. Dropping the action entirely is narrower and already passes
  // through the actions-subset test above.
  if (!capabilitySourcesNoBroader(candidate, granted)) return false;
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

/**
 * @spec capability-binding#capability-source-binding — the capability clause of
 * the subset rule, in BOTH directions.
 *
 * A binding is a recorded FACT about a catalog-sourced action, not a
 * restriction, so neither the constraint direction nor the delegation
 * direction alone is right:
 *   - every binding the grantor recorded for an action the candidate RETAINS
 *     appears byte-identical in the candidate; retaining a catalog-sourced
 *     action with a dropped or altered binding widens (the candidate would be
 *     bound to a capability the grantor never recorded), so it fails;
 *   - every binding the candidate carries appears byte-identical among the
 *     grantor's; introducing one the grantor lacks is the GRANT direction and
 *     fails, exactly as introducing `delegation` does.
 *
 * Total and non-throwing, like the rest of {@link isSubsetEntry}: comparison
 * is over canonical bytes, with a value that cannot be canonicalized treated
 * as matching nothing (fail closed) rather than throwing.
 */
function capabilitySourcesNoBroader(candidate: AuthorityEntry, granted: AuthorityEntry): boolean {
  const cSources = candidate.capability_sources ?? [];
  const gSources = granted.capability_sources ?? [];
  if (cSources.length === 0 && gSources.length === 0) return true;
  const cKeys = cSources.map(bindingKey);
  const gKeys = gSources.map(bindingKey);
  if (cKeys.includes(null) || gKeys.includes(null)) return false;
  const gSet = new Set(gKeys);
  if (!cKeys.every((k) => gSet.has(k))) return false; // introduces an unrecorded binding
  const cSet = new Set(cKeys);
  return gSources.every(
    (g, i) => !candidate.actions.includes(g.action) || cSet.has(gKeys[i] as string),
  );
}

/** Canonical bytes of one binding, or null when it cannot be canonicalized. */
function bindingKey(binding: CapabilitySourceBinding): string | null {
  try {
    return capabilitySourceIdentity(binding);
  } catch {
    return null;
  }
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

/**
 * The `constraints` keys this PROJECTION can intersect. Everything else (a
 * registered-but-unimplemented Common Constraint, or a deployment-defined key
 * this code does not model) makes a pairing unprojectable: see
 * {@link projectThroughEffective}, which drops such a fragment rather than
 * guessing at, or silently discarding, a narrowing it cannot evaluate.
 */
const PROJECTABLE_CONSTRAINTS = new Set([
  "max_amount",
  "vendors",
  "requires_action_approval",
  // @spec discharge#terminal-when — projectable: the fragment carries the UNION of
  // both sides' conditions, which is no broader than either.
  "terminal_when",
]);

function onlyProjectableConstraints(constraints: AuthorityEntry["constraints"]): boolean {
  if (!constraints) return true;
  return Object.keys(constraints).every((k) => PROJECTABLE_CONSTRAINTS.has(k));
}

/** min of two matcher RESTRICTION lists: absent means unconstrained on that side. */
function intersectMatchers(
  a: DelegateMatcher[] | undefined,
  b: DelegateMatcher[] | undefined,
): DelegateMatcher[] | undefined {
  if (!a) return b?.map(cloneMatcher);
  if (!b) return a.map(cloneMatcher);
  const bKeys = new Set(b.map(matcherKey));
  return a.filter((m) => bKeys.has(matcherKey(m))).map(cloneMatcher);
}

/**
 * `children` is a GRANT nested inside `delegation`: the intersection carries it
 * only where BOTH sides do (omitting is a subset of both, {@link
 * isSubsetEntry}'s childrenNoBroader), and an unrecognized member on either
 * side drops it rather than being carried unevaluated.
 */
function intersectChildren(a: JsonObject | undefined, b: JsonObject | undefined): JsonObject | undefined {
  if (!a || !b) return undefined;
  const known = new Set(["max_children", "max_child_depth", "allowed_child_actors"]);
  if (![...Object.keys(a), ...Object.keys(b)].every((k) => known.has(k))) return undefined;
  const out: JsonObject = {};
  const maxChildren = minNum(asNum(a.max_children), asNum(b.max_children));
  if (maxChildren !== undefined) out.max_children = maxChildren;
  const maxChildDepth = minNum(asNum(a.max_child_depth), asNum(b.max_child_depth));
  if (maxChildDepth !== undefined) out.max_child_depth = maxChildDepth;
  const actors = intersectMatchers(
    readMatchers(a.allowed_child_actors),
    readMatchers(b.allowed_child_actors),
  );
  if (actors) out.allowed_child_actors = matchersToJson(actors);
  return out;
}

/**
 * `delegation` is a GRANT, so the SUBSET-OF-BOTH intersection is the
 * conservative one: carried only where both sides grant it (a candidate that
 * omits delegation, or an effective side that does, yields a fragment WITHOUT
 * it, which {@link isSubsetEntry} accepts against both). `max_depth` takes the
 * min; `allowed_delegates` is a restriction, so it takes the intersection of
 * the present lists (an empty one means "delegable to nobody", never a void
 * entry); an unrecognized companion member on either side drops delegation
 * entirely, since a member this code cannot evaluate must not ride through.
 */
function intersectDelegation(
  a: AuthorityEntry["delegation"],
  b: AuthorityEntry["delegation"],
): AuthorityEntry["delegation"] | undefined {
  if (!a || !b) return undefined;
  const known = new Set(["max_depth", "allowed_delegates", "children"]);
  if (![...Object.keys(a), ...Object.keys(b)].every((k) => known.has(k))) return undefined;
  const out: Delegation = { max_depth: Math.min(a.max_depth, b.max_depth) };
  const delegates = intersectMatchers(a.allowed_delegates, b.allowed_delegates);
  if (delegates) out.allowed_delegates = delegates;
  const children = intersectChildren(asJsonObject(a.children), asJsonObject(b.children));
  if (children) out.children = children;
  return out;
}

/**
 * One candidate x effective pairing: the non-empty intersection FRAGMENT, or
 * null where no fragment can be a subset of both. Fail-closed-by-DROPPING and
 * total (never throws), unlike {@link intersect}, which is the derivation-time
 * GRANT narrowing and refuses loudly.
 */
function intersectForProjection(
  candidate: AuthorityEntry,
  effective: AuthorityEntry,
): AuthorityEntry | null {
  if (candidate.type !== effective.type) return null;
  if (candidate.resource !== effective.resource) return null;
  const actions = candidate.actions.filter((a) => effective.actions.includes(a));
  if (actions.length === 0) return null;
  // A constraint key this projection cannot intersect makes the pairing
  // unprovable in BOTH directions: keeping it could widen past the effective
  // side, dropping it could widen past the candidate. Drop the fragment.
  if (!onlyProjectableConstraints(candidate.constraints)) return null;
  if (!onlyProjectableConstraints(effective.constraints)) return null;
  const constraints: NonNullable<AuthorityEntry["constraints"]> = {};
  const cCap = candidate.constraints?.max_amount;
  const eCap = effective.constraints?.max_amount;
  if (cCap || eCap) {
    if (cCap && eCap) {
      // Different currencies are incomparable: no value is at or below both,
      // so no fragment can be a subset of both sides.
      if (cCap.currency !== eCap.currency) return null;
      if (!isValidAmount(cCap.amount) || !isValidAmount(eCap.amount)) return null;
      constraints.max_amount = compareAmounts(cCap.amount, eCap.amount) <= 0 ? cCap : eCap;
    } else {
      const only = (cCap ?? eCap) as { amount: string; currency: string };
      if (!isValidAmount(only.amount)) return null;
      constraints.max_amount = only;
    }
  }
  const cVendors = candidate.constraints?.vendors;
  const eVendors = effective.constraints?.vendors;
  if (cVendors && eVendors) {
    const vendors = cVendors.filter((v) => eVendors.includes(v));
    if (vendors.length === 0) return null; // no vendor is permitted by both
    constraints.vendors = vendors;
  } else if (cVendors || eVendors) {
    constraints.vendors = [...((cVendors ?? eVendors) as string[])];
  }
  // @spec txn-authorization#applicability — monotonic OR: `true` on EITHER side
  // narrows, and `false` is equivalent to omission.
  if (
    candidate.constraints?.requires_action_approval === true ||
    effective.constraints?.requires_action_approval === true
  ) {
    constraints.requires_action_approval = true;
  }
  // @spec discharge#terminal-when — the union of both sides' completion
  // conditions: the fragment stays a subset of both (each side's conditions are
  // all present). A malformed condition makes the pairing unprovable, and this
  // projection is fail-closed-by-DROPPING rather than throwing.
  let conditions: NonNullable<AuthorityEntry["constraints"]>["terminal_when"];
  try {
    conditions = unionConditions(
      candidate.constraints?.terminal_when,
      effective.constraints?.terminal_when,
    );
  } catch {
    return null;
  }
  if (conditions) constraints.terminal_when = conditions;
  // @spec capability-binding#capability-source-binding — the fragment must
  // satisfy `isSubsetEntry` against BOTH sides, and a recorded binding is
  // monotonic in both directions there (it must be retained for a retained
  // action, and may not be introduced). A fragment can therefore carry only
  // bindings both sides recorded byte-identically for the retained actions;
  // where the two sides disagree, no fragment is a subset of both and the
  // pairing drops, exactly as an unprojectable constraint does.
  const sources = projectCapabilitySources(candidate, effective, actions);
  if (sources === null) return null;
  const entry: AuthorityEntry = { type: candidate.type, resource: candidate.resource, actions };
  if (Object.keys(constraints).length > 0) entry.constraints = constraints;
  if (sources) entry.capability_sources = sources;
  const delegation = intersectDelegation(candidate.delegation, effective.delegation);
  if (delegation) entry.delegation = delegation;
  return entry;
}

/**
 * The retained-action bindings both sides agree on: `undefined` where neither
 * side records any, `null` where the pairing is unprovable (the two sides
 * disagree, or a binding cannot be canonicalized). Total, like the rest of
 * this projection, which is fail-closed-by-DROPPING rather than throwing.
 */
function projectCapabilitySources(
  candidate: AuthorityEntry,
  effective: AuthorityEntry,
  actions: string[],
): CapabilitySourceBinding[] | null | undefined {
  const retained = new Set(actions);
  const forRetained = (e: AuthorityEntry) =>
    (e.capability_sources ?? []).filter((b) => retained.has(b.action));
  const cSources = forRetained(candidate);
  const eSources = forRetained(effective);
  if (cSources.length === 0 && eSources.length === 0) return undefined;
  const byKey = new Map<string, CapabilitySourceBinding>();
  for (const b of cSources) {
    const key = bindingKey(b);
    if (key === null) return null;
    byKey.set(key, b);
  }
  const eKeys = new Set<string>();
  for (const b of eSources) {
    const key = bindingKey(b);
    if (key === null) return null;
    eKeys.add(key);
  }
  if (byKey.size !== eKeys.size) return null;
  for (const key of byKey.keys()) if (!eKeys.has(key)) return null;
  return [...byKey.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([, b]) => b);
}

/**
 * @spec mission#introspection, containment#containment-plane,
 * issuance-grant#effective-set-projection — project a candidate Authority Set
 * through a TARGET's current effective set: ENTRY-WISE INTERSECTION. Each
 * candidate entry is paired against EVERY effective entry sharing its `type`
 * and `resource`, and each pairing contributes its non-empty intersection
 * fragment: actions intersected, `max_amount` the smaller (exact decimal
 * comparison), `vendors` intersected, `requires_action_approval` OR-ed,
 * `delegation` carried only where both sides grant it and then narrowed. The
 * result satisfies BOTH `isSubsetSet(result, candidate)` and
 * `isSubsetSet(result, effective)`, which is the whole point: it is the
 * authority the credential still holds under the Mission's current narrowing.
 *
 * The prior implementation matched only the FIRST effective entry per resource
 * and carried the candidate's `constraints`/`delegation` through UNCHANGED.
 * That was sound while containment (whose `remove` shape is `{resource,
 * actions}` only) was the sole narrowing mechanism, since containment cannot
 * narrow a `max_amount`, and it is WRONG for any mechanism that can: a
 * discharged `pay` entry capped at 1000 projected through a surviving entry
 * capped at 100 kept 1000. Constraint values are therefore intersected now,
 * which means a narrowing the EFFECTIVE side carries is inherited where the
 * candidate has none: that is not a widening, because the effective set is by
 * construction the Mission's own current authority, and the fragment stays a
 * subset of the candidate too (a constraint the candidate omits is a
 * constraint it was unbounded by).
 *
 * Total and fail-closed-by-DROPPING, never by throwing (unlike {@link
 * deriveAuthoritySet}, correct at derivation time): a pairing this code cannot
 * prove is dropped, including one whose sides carry a constraint key outside
 * {@link PROJECTABLE_CONSTRAINTS}, a malformed `max_amount`, or mismatched
 * currencies. Identical fragments are de-duplicated and the result follows
 * `candidate` order. Shared by the refresh/code rar re-projection (provider.ts
 * rarThroughEffectiveSet, continuation-grant.ts) and the introspection
 * credential/Mission-authority intersection (@spec
 * mission#caller-authorization-and-minimization).
 */
export function projectThroughEffective(
  candidate: readonly AuthorityEntry[],
  effective: readonly AuthorityEntry[],
): AuthorityEntry[] {
  const out: AuthorityEntry[] = [];
  const seen = new Set<string>();
  for (const detail of candidate) {
    for (const eff of effective) {
      const fragment = intersectForProjection(detail, eff);
      if (!fragment) continue;
      // Field construction is order-stable (intersectForProjection builds every
      // fragment the same way), so the serialization is a usable identity.
      const key = JSON.stringify(fragment);
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(fragment);
    }
  }
  return out;
}

/**
 * @spec issuance-grant#effective-set-projection (#617 review 1) — the
 * Mission-state / Effective Authority Set RESOLUTION SEAM. The projection's
 * input is "the Mission's current Effective Authority Set", resolved through
 * the Mission Status operation or an equivalent authenticated, audience-scoped
 * source. In this deployment the local kernel IS that source (it structurally
 * satisfies this interface), but the seam is explicit so a consuming AS can
 * inject a remote one, which owns its own caching and published staleness
 * bound.
 */
export interface EffectiveAuthoritySource {
  effectiveAuthoritySet(record: MissionRecord): AuthorityEntry[];
}

/**
 * @spec issuance-grant#effective-set-projection (#617 review 1) — a TRANSIENT
 * authority-source failure: the source is unavailable, failed verification, or
 * reported a rolled-back state `version`. It is NEVER authority exhaustion, so
 * it must not surface as `invalid_grant` (which tells a client its
 * authorization is gone) and must not consume a single-use credential: the
 * profile maps it to `temporarily_unavailable` with HTTP 503 at the token
 * endpoint, leaving the presented grant or refresh token retryable. A source
 * raises this instead of returning an empty set, which would be
 * indistinguishable from a fully narrowed Mission.
 */
export class SourceUnavailableError extends Error {}

/**
 * @spec containment#derivation-gating, status#conformance,
 * issuance-grant#effective-set-projection (issue #589) — the Effective
 * Authority Set projection PRIMITIVE for an already-issued credential's
 * `rar`: project it through the Mission's CURRENT effective set (resolved
 * through the {@link EffectiveAuthoritySource} passed in, the local kernel
 * unless a deployment injects a remote one; a {@link SourceUnavailableError}
 * from it propagates to the caller as the TRANSIENT class, never as a
 * collapse),
 * which composes every issuer-held narrowing mechanism the kernel runs
 * (today: containment; structured so discharge and future mechanisms slot
 * in there without a caller-side change). NEVER bypassed on an absent
 * containment record: `effectiveAuthoritySet` already returns the approved
 * set unchanged when nothing narrows it, so calling through unconditionally
 * is a no-op for an unnarrowed Mission and stays live for every future
 * mechanism that computation composes. A caller MUST resolve `record` first
 * (a grant with no resolvable Mission carries no narrowing mechanism, which
 * is a different case from a Mission with nothing currently narrowed) and
 * MUST NOT special-case that resolution on `record.containment` presence.
 *
 * `collapsed` is true exactly when a non-empty `rar` projects to an empty
 * one: the credential's authority is now entirely contained (or otherwise
 * narrowed away). Reported rather than thrown, so callers on different
 * surfaces (a throwing OAuth grant hook vs. a reporting delivery path)
 * choose their own failure shape; both current call sites (provider.ts's
 * code/refresh rar projection, continuation-grant.ts's resumed-delivery
 * projection) treat a `collapsed` result as `invalid_grant`.
 */
export function projectRarThroughMission(
  source: EffectiveAuthoritySource,
  record: MissionRecord,
  rar: readonly AuthorityEntry[],
): { projected: AuthorityEntry[]; collapsed: boolean } {
  const projected = projectThroughEffective(rar, source.effectiveAuthoritySet(record));
  return { projected, collapsed: rar.length > 0 && projected.length === 0 };
}
