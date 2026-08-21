/**
 * @spec status#completion, status#terminal-when, status#discharge,
 * status#discharge-operation, status#discharge-authority,
 * status#discharge-anti-oracle, status#discharge-result, status#visibility
 *
 * Entry DISCHARGE: the selectors, digests, authority mapping, and refusal
 * classes of the Status profile's `discharge` operation. The kernel funnel
 * itself lives in kernel.ts beside `contain()` (the sibling issuer-held
 * narrowing overlay); everything here is the vocabulary that funnel and the
 * lifecycle endpoint share.
 *
 * Two digest SPECIES are in play, and they are not interchangeable
 * (@spec mission#commitment-mechanisms):
 *  - `entry_digest` is an ENVELOPE ANCHOR over the immutable Mission-record
 *    entry: `computeAnchor(AUTHORITY_ENTRY_TYP, iss, entry)`. Two byte-identical
 *    entries share one digest, which is exactly what makes the latch an
 *    equivalence-class latch.
 *  - `condition_digest` and the event assertion FINGERPRINT are
 *    CANONICAL-OBJECT digests: `sha-256:` over the JCS serialization with NO
 *    envelope, because protocol context already fixes what each commits.
 */

import { createHash } from "node:crypto";
import { AUTHORITY_ENTRY_TYP, canonicalize, computeAnchor, type JsonValue } from "@mission/core";
import { IntentError } from "./intent.js";
import type { AuthorityEntry, TerminalWhenCondition } from "./types.js";

/**
 * @spec status#discharge-operation — `event_id`:
 * `1*128( ALPHA / DIGIT / "-" / "_" / ":" / "." )`.
 */
export const DISCHARGE_EVENT_ID_RE = /^[A-Za-z0-9\-_:.]{1,128}$/;

/**
 * @spec status#terminal-when — `discharge_policy`:
 * `1*64( ALPHA / DIGIT / "-" / "_" / ":" / "." )`, opaque.
 */
export const DISCHARGE_POLICY_RE = /^[A-Za-z0-9\-_:.]{1,64}$/;

/** @spec status#discharge-operation — `evidence_ref` is a URI, max 512 chars. */
export const EVIDENCE_REF_MAX_CHARS = 512;

/** The family's prefixed digest form (@spec mission#commitment-mechanisms). */
export const DIGEST_PREFIX = "sha-256:";

/** `sha-256:` over the JCS serialization, no envelope: a canonical-object digest. */
function canonicalObjectDigest(value: JsonValue): string {
  return `${DIGEST_PREFIX}${createHash("sha256").update(canonicalize(value), "utf8").digest("base64url")}`;
}

/**
 * @spec status#discharge-operation — the Authority Set entry commitment of a
 * `mission_resource_access` entry, computed over the immutable Mission-record
 * entry, NEVER over a narrowed token projection.
 */
export function entryDigest(iss: string, entry: AuthorityEntry): string {
  return computeAnchor(AUTHORITY_ENTRY_TYP, iss, entry as unknown as JsonValue);
}

/**
 * @spec status#terminal-when — condition IDENTITY: the canonical bytes of the
 * single condition object. The registration's no-duplicate rule, the
 * intersection's dedup/sort order, and `condition_digest` all key on this one
 * value. Total: a structurally invalid condition yields `undefined` rather than
 * throwing, so the non-throwing subset predicate can fail closed on it.
 */
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
 * @spec status#terminal-when — `condition_digest`: a canonical-object digest
 * over the exact canonical bytes of the single condition object, the same
 * canonical form that fixes condition identity.
 */
export function conditionDigest(condition: TerminalWhenCondition): string {
  const bytes = conditionCanonicalBytes(condition);
  if (bytes === undefined) {
    throw new IntentError(
      "invalid_authorization_details",
      "terminal_when condition is not a { event_type, discharge_policy? } object",
    );
  }
  return `${DIGEST_PREFIX}${createHash("sha256").update(bytes, "utf8").digest("base64url")}`;
}

/** The entry's completion conditions, or undefined when it carries none. */
export function terminalWhenOf(entry: AuthorityEntry): TerminalWhenCondition[] | undefined {
  const conditions = entry.constraints?.terminal_when;
  return conditions?.length ? conditions : undefined;
}

/**
 * @spec status#discharge-idempotency — the EVENT ASSERTION FINGERPRINT's input:
 * a semantic assertion object, never raw form bytes. `nonce`, client
 * authentication material, the DPoP proof, and transport headers are outside
 * it: none of them enter the object and none of them affect its value.
 */
export interface DischargeAssertion {
  mission_id: string;
  entry_digest: string;
  condition_digest: string;
  event_type: string;
  event_id: string;
  evidence_ref?: string;
  evidence_digest?: string;
  observed_at?: string;
}

/**
 * @spec status#discharge-idempotency — the assertion fingerprint: the JSON
 * object with exactly the decoded members `operation` (the literal
 * `discharge`), `mission_id`, `entry_digest`, `condition_digest`,
 * `event_type`, `event_id` and, when present, `evidence_ref`,
 * `evidence_digest`, `observed_at`; canonicalized and digested as a
 * canonical-object digest.
 */
export function dischargeAssertionFingerprint(a: DischargeAssertion): string {
  return canonicalObjectDigest({
    operation: "discharge",
    mission_id: a.mission_id,
    entry_digest: a.entry_digest,
    condition_digest: a.condition_digest,
    event_type: a.event_type,
    event_id: a.event_id,
    ...(a.evidence_ref !== undefined ? { evidence_ref: a.evidence_ref } : {}),
    ...(a.evidence_digest !== undefined ? { evidence_digest: a.evidence_digest } : {}),
    ...(a.observed_at !== undefined ? { observed_at: a.observed_at } : {}),
  } as JsonValue);
}

/**
 * @spec status#discharge-operation — one `discharge` delivery as the kernel
 * funnel takes it: the AUTHENTICATED discharge authority plus the request's own
 * selectors and audit metadata. The Mission Identifier is the funnel's own
 * argument. `evidence_ref` / `evidence_digest` are bounded audit metadata: the
 * AS never dereferences the reference and neither member is authorization
 * input. `observed_at` is a caller assertion, validated for syntax and
 * reasonable clock bounds only.
 */
export interface DischargeRequest {
  /** The authenticated discharge authority the mapping is checked against. */
  authority: string;
  entry_digest: string;
  condition_digest: string;
  event_type: string;
  event_id: string;
  evidence_ref?: string;
  evidence_digest?: string;
  observed_at?: string;
}

/** @spec status#discharge-result — the three outcomes, and only these three. */
export type DischargeOutcome = "discharged" | "already_discharged" | "terminal_noop";

/**
 * @spec status#discharge-result — the `discharge_result` object the signed
 * Mission Status Response carries as a sibling of `mission`. `prior_version` /
 * `current_version` are the versions of the commit THIS result reports: this
 * request's own commit, or, for the replayed event case, the versions the
 * ORIGINAL commit produced. Equal for `already_discharged` and `terminal_noop`.
 */
export interface DischargeResult {
  entry_digest: string;
  condition_digest: string;
  event_id: string;
  outcome: DischargeOutcome;
  prior_version: number;
  current_version: number;
}

/**
 * @spec status#discharge-anti-oracle — the six refusal classes that COLLAPSE to
 * the endpoint's `not_found`. The reason is carried here for the issuer's own
 * audit record only; it MUST NOT reach the wire, where all six are one
 * indistinguishable response.
 */
export type DischargeRefusalReason =
  | "unknown_mission"
  | "unknown_entry"
  | "no_terminal_when"
  | "unknown_condition"
  | "event_type_mismatch"
  // No mapping was pinned for this condition at record creation: fail closed
  // (the pin is written in insertRecord's transaction, so this marks a store
  // predating the pin funnel, never a policy question).
  | "unpinned_mapping"
  | "unauthorized_target";

/** @spec status#discharge-anti-oracle — collapses to `not_found` on the wire. */
export class DischargeNotFoundError extends Error {
  constructor(
    readonly reason: DischargeRefusalReason,
    message: string,
  ) {
    super(message);
  }
}

/**
 * @spec status#discharge-idempotency — the same (discharge authority,
 * mission_id, entry_digest, condition_digest, event_id) tuple asserted with a
 * DIFFERENT fingerprint: refused `conflict` (409).
 */
export class DischargeConflictError extends Error {}

/**
 * @spec status#discharge-authority — one AS-side discharge-authority mapping:
 * WHICH authenticated principal may assert WHICH event types. Never a raw
 * principal structure a requesting client can select: a condition names a
 * mapping by opaque selector, and the AS resolves it.
 */
export interface DischargeAuthorityMapping {
  mapping_id: string;
  mapping_version: string;
  /**
   * The event types this mapping's principals may assert. Absent on a
   * BASELINE mapping, which is already keyed by `event_type`.
   */
  event_types?: string[];
  /** The authenticated principals (discharge authorities) this mapping admits. */
  principals: string[];
}

/**
 * @spec status#discharge-authority — the issuer-held discharge-authority
 * policy: `policies` resolves a condition's `discharge_policy` selector,
 * `baseline` is the mapping keyed by `event_type` for a condition carrying no
 * selector. FAIL CLOSED by construction: an absent policy resolves nothing, so
 * every discharge joins the `not_found` collapse until a deployment configures
 * one, and a selector that maps to nothing refuses the derivation that would
 * introduce the condition.
 */
export interface DischargeAuthorityPolicy {
  policies?: Readonly<Record<string, DischargeAuthorityMapping>>;
  baseline?: Readonly<Record<string, DischargeAuthorityMapping>>;
}

/**
 * @spec status#discharge-authority — resolve the mapping for one condition:
 * the `discharge_policy` selector when the condition carries one, else the
 * baseline mapping keyed by `event_type`. `undefined` means "maps to nothing".
 */
export function resolveConditionMapping(
  policy: DischargeAuthorityPolicy | undefined,
  condition: TerminalWhenCondition,
): DischargeAuthorityMapping | undefined {
  if (condition.discharge_policy !== undefined) return policy?.policies?.[condition.discharge_policy];
  return policy?.baseline?.[condition.event_type];
}

/**
 * @spec status#discharge-authority — target authorization: the authenticated
 * principal is admitted by the resolved mapping FOR this event type. A
 * `mission_lifecycle` grant, or being the Subject/Approver/an administrator,
 * never reaches here: the scope gate is separate and this mapping is keyed by
 * event type, not by who may revoke the Mission.
 */
export function mappingPermits(
  mapping: DischargeAuthorityMapping,
  principal: string,
  eventType: string,
): boolean {
  if (mapping.event_types !== undefined && !mapping.event_types.includes(eventType)) return false;
  return mapping.principals.includes(principal);
}

/**
 * @spec status#discharge-authority — resolve and validate every
 * `discharge_policy` selector carried by these entries, refusing when one maps
 * to nothing. Called at every point where a condition FIRST enters an immutable
 * Mission-record entry: the derivation (`MissionKernel.derive`, so Mission
 * creation, expansion, and template dispatch refuse early and typed) and
 * `insertRecord`, the single record-creation funnel, which also covers child
 * creation (whose Authority Set is a requested subset, not a fresh derivation).
 * A requesting client therefore cannot select an arbitrary otherwise-valid
 * policy for a condition it adds, nor fall back to an unapproved default.
 *
 * Also enforces the condition SHAPE and the registration's no-duplicate rule
 * (@spec status#terminal-when): a value carrying two identical conditions is
 * refused, since identity is byte equality of the canonical form.
 */
export function assertDischargePoliciesResolvable(
  entries: readonly AuthorityEntry[],
  policy: DischargeAuthorityPolicy | undefined,
): void {
  for (const entry of entries) {
    const conditions = entry.constraints?.terminal_when;
    if (conditions === undefined) continue;
    if (!Array.isArray(conditions) || conditions.length === 0) {
      throw new IntentError(
        "invalid_authorization_details",
        "terminal_when must be an array of one or more completion conditions",
      );
    }
    const seen = new Set<string>();
    for (const condition of conditions) {
      const bytes = conditionCanonicalBytes(condition);
      if (bytes === undefined) {
        throw new IntentError(
          "invalid_authorization_details",
          "terminal_when condition is not a { event_type, discharge_policy? } object",
        );
      }
      if (seen.has(bytes)) {
        throw new IntentError(
          "invalid_authorization_details",
          "terminal_when carries two identical conditions",
        );
      }
      seen.add(bytes);
      if (
        condition.discharge_policy !== undefined &&
        !DISCHARGE_POLICY_RE.test(condition.discharge_policy)
      ) {
        throw new IntentError(
          "invalid_authorization_details",
          `malformed discharge_policy selector: ${JSON.stringify(condition.discharge_policy)}`,
        );
      }
      if (resolveConditionMapping(policy, condition) === undefined) {
        // The refusal is the point: an unchecked mapping choice for a newly
        // added condition could force a premature discharge, which is a
        // denial of service on the task (@spec status#completion-security).
        throw new IntentError(
          "invalid_authorization_details",
          condition.discharge_policy !== undefined
            ? `discharge_policy '${condition.discharge_policy}' maps to no discharge-authority mapping`
            : `no baseline discharge-authority mapping for event_type '${condition.event_type}'`,
        );
      }
    }
  }
}

/**
 * @spec status#terminal-when, status#subset-extension — the UNION of two
 * condition arrays, deduplicated by condition identity and sorted by the
 * lexicographic order of the canonical bytes, so the intersected entry is one
 * reproducible array. Union is the narrowing direction: the result contains
 * every condition of BOTH operands, so it is no broader than either (an added
 * condition can only discharge sooner). Refuses a malformed condition and a
 * duplicate within one operand rather than silently normalizing it.
 */
export function unionConditions(
  a: readonly TerminalWhenCondition[] | undefined,
  b: readonly TerminalWhenCondition[] | undefined,
): TerminalWhenCondition[] | undefined {
  if (!a?.length && !b?.length) return undefined;
  const byBytes = new Map<string, TerminalWhenCondition>();
  for (const operand of [a, b]) {
    if (!operand?.length) continue;
    const seen = new Set<string>();
    for (const condition of operand) {
      const bytes = conditionCanonicalBytes(condition);
      if (bytes === undefined) {
        throw new IntentError(
          "invalid_authorization_details",
          "terminal_when condition is not a { event_type, discharge_policy? } object",
        );
      }
      if (seen.has(bytes)) {
        throw new IntentError(
          "invalid_authorization_details",
          "terminal_when carries two identical conditions",
        );
      }
      seen.add(bytes);
      if (!byBytes.has(bytes)) byBytes.set(bytes, cloneCondition(condition));
    }
  }
  return [...byBytes.entries()].sort(([x], [y]) => (x < y ? -1 : x > y ? 1 : 0)).map(([, c]) => c);
}

/** A structural copy carrying only the closed member set. */
function cloneCondition(condition: TerminalWhenCondition): TerminalWhenCondition {
  return {
    event_type: condition.event_type,
    ...(condition.discharge_policy !== undefined
      ? { discharge_policy: condition.discharge_policy }
      : {}),
  };
}

/**
 * @spec status#subset-extension — a candidate condition array is NO BROADER
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
