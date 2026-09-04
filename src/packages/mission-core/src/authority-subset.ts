/** Shared, binding-neutral authority comparisons. Pure extraction for #762. */
import { canonicalize, type JsonValue } from "./canonicalize.js";
import { capabilitySourceIdentity, type CapabilitySourceBinding } from "./capability-binding.js";
import { compareAmounts, isValidAmount } from "./decimal-amount.js";
import type { AuthorityEntry, DelegateMatcher, TerminalWhenCondition } from "./authority-entry.js";

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


export function conditionCanonicalBytes(condition: unknown): string | undefined {
  if (condition === null || typeof condition !== "object" || Array.isArray(condition)) return undefined;
  const c = condition as Record<string, unknown>;
  if (typeof c.event_type !== "string") return undefined;
  if (c.discharge_policy !== undefined && typeof c.discharge_policy !== "string") return undefined;
  for (const k of Object.keys(c)) {
    if (k !== "event_type" && k !== "discharge_policy") return undefined;
  }
  return canonicalize(condition as JsonValue);
}

/**
 * @spec discharge#subset-extension — a candidate condition array is NO BROADER
 * than a reference array when it contains every reference condition, compared
 * structurally after canonicalization; it MAY add further conditions. Total and
 * non-throwing (a malformed condition on either side fails closed), so
 * `isSubsetEntry` stays a plain predicate.
 */
export function conditionsNoBroader(
  candidate: readonly TerminalWhenCondition[] | undefined,
  reference: readonly TerminalWhenCondition[] | undefined,
): boolean {
  if (!reference?.length) return true; // the reference constrains nothing
  if (!candidate?.length) return false; // dropping a parent condition WIDENS
  const held = new Set<string>();
  for (const c of candidate) {
    const bytes = conditionCanonicalBytes(c);
    if (bytes === undefined) return false;
    held.add(bytes);
  }
  return reference.every((r) => {
    const bytes = conditionCanonicalBytes(r);
    return bytes !== undefined && held.has(bytes);
  });
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
