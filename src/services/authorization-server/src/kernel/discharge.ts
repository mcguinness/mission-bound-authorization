/**
 * @spec discharge#completion, discharge#terminal-when, discharge#discharge,
 * discharge#discharge-commit, discharge#discharge-operation,
 * discharge#discharge-authority, discharge#discharge-anti-oracle,
 * discharge#discharge-result, discharge#discharge-receipt, discharge#visibility
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
import { conditionCanonicalBytes } from "@mission/core";
export { conditionCanonicalBytes, conditionsNoBroader } from "@mission/core";
import type { AuthorityEntry, TerminalWhenCondition } from "./types.js";

/**
 * @spec discharge#discharge-operation — `event_id`:
 * `1*128( ALPHA / DIGIT / "-" / "_" / ":" / "." )`.
 */
export const DISCHARGE_EVENT_ID_RE = /^[A-Za-z0-9\-_:.]{1,128}$/;

/**
 * @spec discharge#terminal-when — `discharge_authority`:
 * `1*64( ALPHA / DIGIT / "-" / "_" / ":" / "." )`, opaque.
 */
export const DISCHARGE_AUTHORITY_RE = /^[A-Za-z0-9\-_:.]{1,64}$/;

/**
 * @spec discharge#discharge-receipt — the Discharge Receipt's JWS `typ`. A
 * consumer validates it EXACTLY and never accepts a receipt as a Mission
 * Status Response, or the reverse.
 */
export const DISCHARGE_RECEIPT_TYP = "mission-discharge-receipt+jwt";

/** @spec discharge#iana-receipt — the Discharge Receipt's HTTP media type. */
export const DISCHARGE_RECEIPT_MEDIA_TYPE = "application/mission-discharge-receipt+jwt";

/** @spec discharge#discharge-operation — `evidence_ref` is a URI, max 512 chars. */
export const EVIDENCE_REF_MAX_CHARS = 512;

/** The family's prefixed digest form (@spec mission#commitment-mechanisms). */
export const DIGEST_PREFIX = "sha-256:";

/** `sha-256:` over the JCS serialization, no envelope: a canonical-object digest. */
function canonicalObjectDigest(value: JsonValue): string {
  return `${DIGEST_PREFIX}${createHash("sha256").update(canonicalize(value), "utf8").digest("base64url")}`;
}

/**
 * @spec discharge#discharge-operation — the Authority Set entry commitment of a
 * `mission_resource_access` entry, computed over the immutable Mission-record
 * entry, NEVER over a narrowed token projection.
 */
export function entryDigest(iss: string, entry: AuthorityEntry): string {
  return computeAnchor(AUTHORITY_ENTRY_TYP, iss, entry as unknown as JsonValue);
}

/**
 * @spec discharge#terminal-when — condition IDENTITY: the canonical bytes of the
 * single condition object. The registration's no-duplicate rule, the
 * intersection's dedup/sort order, and `condition_digest` all key on this one
 * value. Total: a structurally invalid condition yields `undefined` rather than
 * throwing, so the non-throwing subset predicate can fail closed on it.
 */

/**
 * @spec discharge#terminal-when — `condition_digest`: a canonical-object digest
 * over the exact canonical bytes of the single condition object, the same
 * canonical form that fixes condition identity.
 */
export function conditionDigest(condition: TerminalWhenCondition): string {
  const bytes = conditionCanonicalBytes(condition);
  if (bytes === undefined) {
    throw new IntentError(
      "invalid_authorization_details",
      "terminal_when condition is not a { event_type, discharge_authority? } object",
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
 * @spec discharge#discharge-idempotency — the EVENT ASSERTION FINGERPRINT's input:
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
 * @spec discharge#discharge-idempotency — the assertion fingerprint: the JSON
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
 * @spec discharge#discharge-operation, discharge#condition-selectors — the two
 * target forms a `discharge` request names its target in, EXACTLY ONE of them:
 * a condition selector the Mission Issuer resolves to its target, or the digest
 * pair a caller holding the record entry computes itself.
 */
export type DischargeTargetForm =
  | { condition_selector: string; entry_digest?: never; condition_digest?: never }
  | { entry_digest: string; condition_digest: string; condition_selector?: never };

/**
 * @spec discharge#discharge-operation — one `discharge` delivery as the kernel
 * funnel takes it: the AUTHENTICATED discharge authority plus the request's own
 * target form and audit metadata. The Mission Identifier is the funnel's own
 * argument. `evidence_ref` / `evidence_digest` are bounded audit metadata: the
 * AS never dereferences the reference and neither member is authorization
 * input. `observed_at` is a caller assertion, validated for syntax and
 * reasonable clock bounds only.
 */
export type DischargeRequest = DischargeTargetForm & {
  /** The authenticated discharge authority the mapping is checked against. */
  authority: string;
  event_type: string;
  event_id: string;
  evidence_ref?: string;
  evidence_digest?: string;
  observed_at?: string;
};

/** @spec discharge#discharge-result — the three outcomes, and only these three. */
export type DischargeOutcome = "discharged" | "already_discharged" | "terminal_noop";

/**
 * @spec discharge#discharge-result — the `discharge_result` object the signed
 * Mission Status Response carries as a sibling of `mission`. The target form
 * and `event_id` are echoed AS THE CURRENT REQUEST SENT THEM: a selector-form
 * request's result never carries a digest it did not send. `prior_version` /
 * `new_version` are the versions of the commit THIS result reports: this
 * request's own commit, or, for the replayed event case, the versions the
 * ORIGINAL commit produced. Equal for `already_discharged` and `terminal_noop`.
 * An envelope signed with the earlier `current_version` member is returned
 * from the replay store byte for byte, never re-signed.
 */
export type DischargeResult = DischargeTargetForm & {
  event_id: string;
  outcome: DischargeOutcome;
  prior_version: number;
  new_version: number;
  /**
   * @spec discharge#discharge-result, discharge#discharge-carryover — present
   * only when the discharge was forwarded after carryover: the qualified
   * reference to the old child the request targeted. The envelope's `mission`
   * and the versions then describe the replacement that changed.
   */
  forwarded_from?: { issuer: string; id: string };
};

/** The request's own target form, exactly as sent, for the result echo. */
export function targetFormOf(input: DischargeTargetForm): DischargeTargetForm {
  return input.condition_selector !== undefined
    ? { condition_selector: input.condition_selector }
    : { entry_digest: input.entry_digest, condition_digest: input.condition_digest };
}

/**
 * @spec discharge#discharge-anti-oracle — the refusal classes that COLLAPSE to
 * the endpoint's `not_found`. The reason is carried here for the issuer's own
 * audit record only; it MUST NOT reach the wire, where all of them are one
 * indistinguishable response.
 */
export type DischargeRefusalReason =
  | "unknown_mission"
  // @spec discharge#discharge-anti-oracle — a condition_selector that resolves to
  // no target, or to a target outside the request's mission_id.
  | "unknown_selector"
  | "unknown_entry"
  | "no_terminal_when"
  | "unknown_condition"
  | "event_type_mismatch"
  // No mapping was pinned for this condition at record creation: fail closed
  // (the pin is written in insertRecord's transaction, so this marks a store
  // predating the pin funnel, never a policy question).
  | "unpinned_mapping"
  | "unauthorized_target";

/** @spec discharge#discharge-anti-oracle — collapses to `not_found` on the wire. */
export class DischargeNotFoundError extends Error {
  constructor(
    readonly reason: DischargeRefusalReason,
    message: string,
  ) {
    super(message);
  }
}

/**
 * @spec discharge#discharge-carryover ("Resolution") — the recorded carryover
 * chain could not be followed: a cycle, a carried row naming a replacement
 * that neither exists nor left a tombstone, or a pairing naming an entry its
 * replacement does not hold. This is a traversal FAILURE, never a proven
 * absence of authority, so it is never acknowledged as `terminal_noop`: the
 * endpoint answers with its server-error path, after the caller was
 * authorized for the target it named (so it discloses nothing to anyone
 * else), and commits nothing.
 */
export class DischargeTraversalError extends Error {}

/**
 * @spec discharge#discharge-idempotency — the same (discharge authority,
 * mission_id, entry_digest, condition_digest, event_id) tuple asserted with a
 * DIFFERENT fingerprint: refused `conflict` (409).
 */
export class DischargeConflictError extends Error {}

/**
 * @spec discharge#discharge-authority — one AS-side discharge-authority mapping:
 * WHICH authenticated principal may assert WHICH event types. Never a raw
 * principal structure a requesting client can select: a condition names a
 * mapping by its opaque `discharge_authority` name, and the AS resolves it.
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
 * @spec discharge#discharge-authority — the issuer-held discharge-authority
 * policy: `policies` resolves a condition's `discharge_authority` value,
 * `baseline` is the mapping keyed by `event_type` for a condition carrying no
 * `discharge_authority`. FAIL CLOSED by construction: an absent policy resolves
 * nothing, so every discharge joins the `not_found` collapse until a deployment
 * configures one, and a value that maps to nothing refuses the derivation that
 * would introduce the condition.
 */
export interface DischargeAuthorityPolicy {
  policies?: Readonly<Record<string, DischargeAuthorityMapping>>;
  baseline?: Readonly<Record<string, DischargeAuthorityMapping>>;
}

/**
 * @spec discharge#discharge-authority — resolve the mapping for one condition:
 * the `discharge_authority` value when the condition carries one, else the
 * baseline mapping keyed by `event_type`. `undefined` means "maps to nothing".
 */
export function resolveConditionMapping(
  policy: DischargeAuthorityPolicy | undefined,
  condition: TerminalWhenCondition,
): DischargeAuthorityMapping | undefined {
  if (condition.discharge_authority !== undefined) return policy?.policies?.[condition.discharge_authority];
  return policy?.baseline?.[condition.event_type];
}

/**
 * @spec discharge#discharge-authority — target authorization: the authenticated
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
 * @spec discharge#discharge-authority — resolve and validate every
 * `discharge_authority` value carried by these entries, refusing when one maps
 * to nothing. Called at every point where a condition FIRST enters an immutable
 * Mission-record entry: the derivation (`MissionKernel.derive`, so Mission
 * creation, expansion, and template dispatch refuse early and typed) and
 * `insertRecord`, the single record-creation funnel, which also covers child
 * creation (whose Authority Set is a requested subset, not a fresh derivation).
 * A requesting client therefore cannot select an arbitrary otherwise-valid
 * policy for a condition it adds, nor fall back to an unapproved default.
 *
 * Also enforces the condition SHAPE and the registration's no-duplicate rule
 * (@spec discharge#terminal-when): a value carrying two identical conditions is
 * refused, since identity is byte equality of the canonical form.
 */
export function assertDischargeAuthoritiesResolvable(
  entries: readonly AuthorityEntry[],
  policy: DischargeAuthorityPolicy | undefined,
  /**
   * @spec discharge#discharge-authority — a condition that does NOT first enter
   * this record (a carryover replacement's carried condition, whose pin is
   * inherited): its shape is still checked, its resolution is not repeated.
   */
  carried?: (entry: AuthorityEntry, condition: TerminalWhenCondition) => boolean,
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
          "terminal_when condition is not a { event_type, discharge_authority? } object",
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
        condition.discharge_authority !== undefined &&
        !DISCHARGE_AUTHORITY_RE.test(condition.discharge_authority)
      ) {
        throw new IntentError(
          "invalid_authorization_details",
          `malformed discharge_authority value: ${JSON.stringify(condition.discharge_authority)}`,
        );
      }
      if (carried?.(entry, condition)) continue;
      if (resolveConditionMapping(policy, condition) === undefined) {
        // The refusal is the point: an unchecked mapping choice for a newly
        // added condition could force a premature discharge, which is a
        // denial of service on the task (@spec discharge#completion-security).
        throw new IntentError(
          "invalid_authorization_details",
          condition.discharge_authority !== undefined
            ? `discharge_authority '${condition.discharge_authority}' maps to no discharge-authority mapping`
            : `no baseline discharge-authority mapping for event_type '${condition.event_type}'`,
        );
      }
    }
  }
}

/**
 * @spec discharge#terminal-when, discharge#subset-extension — the UNION of two
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
          "terminal_when condition is not a { event_type, discharge_authority? } object",
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
    ...(condition.discharge_authority !== undefined
      ? { discharge_authority: condition.discharge_authority }
      : {}),
  };
}
