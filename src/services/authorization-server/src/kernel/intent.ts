/**
 * @spec mission#submission-via-par
 * @spec mission#mission-intent
 * @spec mission#intent-submission-evidence
 * @spec mission#authority-proposal
 * Mission Intent Submission intake. The `mission_intent` parameter VALUE is
 * the Submission envelope `{ intent, evidence }` (its own closed top level):
 * strict parse (duplicate member names rejected), bounded size, the semantic
 * `intent` validated exactly as before (closed top level, required members),
 * and typed Intent Submission Evidence entries dispatched by REQUIRED `type`
 * (unknown type or a failing entry refused — never silently ignored; count
 * and size bounded). `intent_hash` commits exactly the semantic `intent`
 * object, never the envelope or its `evidence` array. The retired bare-Intent
 * parameter shape is refused. The Intent is pure task context; the authority
 * proposal rides the standard `authorization_details` parameter and is
 * validated by {@link validateAuthorityProposal} (advertised type + published
 * schema + resource containment), the same intake rules that previously
 * applied to the retired `proposed_authority` Intent member.
 */

import {
  computeAnchor,
  DuplicateMemberError,
  intentHash,
  type JsonValue,
  MISSION_INTENT_EVIDENCE_TYP,
  parseStrictJson,
} from "@mission/core";
import { type AmountBindingCandidate, amountBearingBindingError } from "@mission/demo-data";
import {
  SUPPORTED_AUTHORIZATION_DETAILS_TYPES,
  validateMissionResourceAccessSchema,
} from "./authorization-details-metadata.js";
import type {
  AuthorityEntry,
  IntentSubmissionEvidenceEntry,
  IntentSubmissionEvidenceFact,
  MissionIntent,
  MissionIntentSubmission,
} from "./types.js";

// @spec mission#authority-proposal — `proposed_authority` is deliberately NOT
// in this set: the Intent carries no authority members, and an Intent carrying
// the retired member is refused as an unknown top-level member by the
// closed-top-level rule below (@spec mission#submission-via-par).
const TOP_LEVEL = new Set([
  "goal",
  "goal_lang",
  "target_resources",
  "expires_at",
  "task_bounds",
  "success_criteria",
  "purpose",
  "requested_derivation_limit",
]);

const MAX_INTENT_BYTES = 65536;
const MAX_ARRAY_LEN = 64;
const MAX_GOAL_CHARS = 4096;

/**
 * @spec mission#mission-intent — `goal_lang` well-formedness: a faithful
 * RFC 5646 Section 2.1 ABNF check (langtag / privateuse / grandfathered),
 * plus the no-duplicate-singleton and no-duplicate-variant rules. Syntactic
 * only: the AS never verifies the prose is in the declared language, and no
 * registry validity lookup is performed. No maximum length is imposed
 * beyond the Intent's own size bound: RFC 5646 Section 4.4.1's 35
 * characters is a minimum support capacity, not a cap, and longer valid
 * tags exist.
 */
const BCP47_GRANDFATHERED = new Set([
  // irregular
  "en-gb-oed", "i-ami", "i-bnn", "i-default", "i-enochian", "i-hak",
  "i-klingon", "i-lux", "i-mingo", "i-navajo", "i-pwn", "i-tao", "i-tay",
  "i-tsu", "sgn-be-fr", "sgn-be-nl", "sgn-ch-de",
  // regular
  "art-lojban", "cel-gaulish", "no-bok", "no-nyn", "zh-guoyu", "zh-hakka",
  "zh-min", "zh-min-nan", "zh-xiang",
]);

function isWellFormedBcp47(tag: string): boolean {
  const lower = tag.toLowerCase();
  if (BCP47_GRANDFATHERED.has(lower)) return true;
  const subs = lower.split("-");
  if (subs.some((s) => s.length === 0 || s.length > 8 || !/^[a-z0-9]+$/.test(s))) return false;
  const isAlpha = (s: string) => /^[a-z]+$/.test(s);
  const isDigits = (s: string) => /^[0-9]+$/.test(s);
  // privateuse-only form: "x" 1*("-" 1*8alphanum)
  if (subs[0] === "x") return subs.length >= 2;
  let i = 0;
  // language = 2*3ALPHA ["-" extlang] / 4ALPHA / 5*8ALPHA
  const lang = subs[i] as string;
  if (!isAlpha(lang) || lang.length < 2) return false;
  i += 1;
  if (lang.length <= 3) {
    // extlang = 3ALPHA *2("-" 3ALPHA)
    let extlang = 0;
    while (i < subs.length && extlang < 3 && (subs[i] as string).length === 3 && isAlpha(subs[i] as string)) {
      i += 1;
      extlang += 1;
    }
  }
  // script = 4ALPHA
  if (i < subs.length && (subs[i] as string).length === 4 && isAlpha(subs[i] as string)) i += 1;
  // region = 2ALPHA / 3DIGIT (at most one)
  if (
    i < subs.length &&
    (((subs[i] as string).length === 2 && isAlpha(subs[i] as string)) ||
      ((subs[i] as string).length === 3 && isDigits(subs[i] as string)))
  ) {
    i += 1;
  }
  // variant = 5*8alphanum / (DIGIT 3alphanum), no duplicates
  const variants = new Set<string>();
  while (i < subs.length) {
    const s = subs[i] as string;
    const isVariant = s.length >= 5 || (s.length === 4 && /^[0-9]/.test(s));
    if (!isVariant) break;
    if (variants.has(s)) return false;
    variants.add(s);
    i += 1;
  }
  // extension = singleton 1*("-" 2*8alphanum); singletons unique, never "x"
  const singletons = new Set<string>();
  while (i < subs.length && (subs[i] as string).length === 1 && subs[i] !== "x") {
    const singleton = subs[i] as string;
    if (singletons.has(singleton)) return false;
    singletons.add(singleton);
    i += 1;
    let ext = 0;
    while (i < subs.length && (subs[i] as string).length >= 2) {
      i += 1;
      ext += 1;
    }
    if (ext === 0) return false;
  }
  // privateuse = "x" 1*("-" 1*8alphanum)
  if (i < subs.length && subs[i] === "x") {
    i += 1;
    if (i >= subs.length) return false;
    i = subs.length;
  }
  return i === subs.length;
}

/** @spec mission#submission-via-par — the envelope's own closed top level. */
const SUBMISSION_TOP_LEVEL = new Set(["intent", "evidence"]);

/**
 * @spec mission#intent-submission-evidence — configurable evidence bounds
 * (the AS bounds the number and total size of evidence entries). These are
 * the deployment defaults; a caller narrows them via
 * {@link SubmissionEvidenceBounds}.
 */
export const DEFAULT_MAX_EVIDENCE_ENTRIES = 8;
export const DEFAULT_MAX_EVIDENCE_ENTRY_BYTES = 16384;

export interface SubmissionEvidenceBounds {
  maxEvidenceEntries?: number;
  maxEvidenceEntryBytes?: number;
}

/**
 * @spec mission#intent-submission-evidence — the presenter the CONTAINING
 * exchange established (client authentication + possession). The presenter
 * conjunction: an evidence type binding a presenter (`client_id`, `cnf`) MUST
 * match THIS value; the assertion never authenticates or selects the
 * presenter. `cnf` is present where the exchange is sender-constrained (the
 * D69 token exchanges); PAR and dispatch establish the client alone.
 */
export interface IntentSubmissionPresenter {
  clientId: string;
  cnf?: { jkt: string };
}

/**
 * @spec mission#intent-submission-evidence — the stage-2 verification input
 * handed to a type's `verify`: the entry, the PROVISIONAL `intent_hash`
 * (computed over the submitted semantic intent BEFORE verification, per the
 * processing order), the AS issuer (the expected artifact audience), the
 * established presenter, and the evaluation time.
 */
export interface IntentSubmissionEvidenceVerifyInput {
  entry: IntentSubmissionEvidenceEntry;
  intentHash: string;
  issuer: string;
  presenter: IntentSubmissionPresenter;
  now: Date;
  /** Carrier-specific context (e.g. which submission carrier), advisory. */
  requestContext?: Record<string, unknown>;
}

/**
 * @spec mission#intent-submission-evidence — one registered Intent Submission
 * Evidence type: the TWO-STAGE interface the processing order requires.
 *  - Stage 1 `validate`: SYNCHRONOUS structural validation of the type's OWN
 *    closed member set (the RAR type-dispatch discipline), run at parse time —
 *    before the creation fingerprint is computed, so the fingerprint input is
 *    shape-valid. Throws {@link IntentError} (`invalid_mission_intent_evidence`).
 *  - Stage 2 `verify`: ASYNC verification (signature, issuer trust, audience,
 *    freshness, `intent_hash` equality, presenter conjunction, status/replay)
 *    returning the NORMALIZED verified output facts the Mission Record lands
 *    (the nested `facts` object of {@link IntentSubmissionEvidenceFact}). Any
 *    throw maps to `invalid_mission_intent_evidence`.
 */
export interface IntentSubmissionEvidenceType {
  validate(entry: Record<string, JsonValue>): void;
  verify(input: IntentSubmissionEvidenceVerifyInput): Promise<Record<string, JsonValue>>;
}

const EVIDENCE_TYPE_REGISTRY = new Map<string, IntentSubmissionEvidenceType>();

/**
 * @spec mission#intent-submission-evidence — the registry of Intent Submission
 * Evidence types this AS accepts, keyed by `type`. EMPTY as shipped — no
 * evidence-type profile is implemented — so every presented type is unknown
 * and refused, which is exactly the hook's rule for a deployment with no
 * registered types. {@link registerIntentSubmissionEvidenceType} is the
 * extension point an evidence-type profile implementation (or a test fixture)
 * uses.
 */
export const INTENT_SUBMISSION_EVIDENCE_TYPES: ReadonlyMap<string, IntentSubmissionEvidenceType> =
  EVIDENCE_TYPE_REGISTRY;

/** Register an evidence-type implementation (profile wiring / test fixtures). */
export function registerIntentSubmissionEvidenceType(
  type: string,
  impl: IntentSubmissionEvidenceType,
): void {
  EVIDENCE_TYPE_REGISTRY.set(type, impl);
}

/** Remove a registered evidence type (test-fixture cleanup). */
export function unregisterIntentSubmissionEvidenceType(type: string): void {
  EVIDENCE_TYPE_REGISTRY.delete(type);
}

export class IntentError extends Error {
  constructor(
    readonly code:
      | "invalid_request"
      | "invalid_authorization_details"
      // @spec mission#intent-submission-evidence — the core-registered error
      // code for evidence-type dispatch failures (unknown type, an entry
      // failing its type's validation, a policy-required type absent).
      // Envelope STRUCTURAL failures stay invalid_request.
      | "invalid_mission_intent_evidence"
      // @spec mission#error-mapping — a well-formed Intent that yields no
      // Authority Set under configured-mapping mode (no `authorization_details`
      // proposal was submitted, so nothing was ever proposed to be invalid):
      // the AS's own policy simply derives nothing for it. Distinct from
      // `invalid_authorization_details`, which requires an actual submitted
      // proposal to be invalid against.
      | "access_denied",
    message: string,
  ) {
    super(message);
  }
}

/**
 * @spec mission#submission-via-par — parse and validate the Mission Intent
 * Submission envelope: the exact VALUE of the `mission_intent` parameter on
 * every submission carrier (PAR, the expansion and child-creation exchanges,
 * template dispatch). Closed envelope top level (`intent`, `evidence`); the
 * retired bare-Intent shape (task members at the top level, no `intent`) is
 * refused; the semantic `intent` is validated by the same rules as before
 * ({@link validateMissionIntentObject}); `evidence` is validated by
 * {@link validateIntentSubmissionEvidence}. `intent_hash` commits exactly the
 * returned `intent` object — never this envelope.
 */
export function validateMissionIntentSubmission(
  raw: string,
  bounds: SubmissionEvidenceBounds = {},
): MissionIntentSubmission {
  if (Buffer.byteLength(raw, "utf8") > MAX_INTENT_BYTES) {
    throw new IntentError("invalid_request", "mission_intent exceeds size bound");
  }
  let parsed: JsonValue;
  try {
    parsed = parseStrictJson(raw);
  } catch (e) {
    if (e instanceof DuplicateMemberError) {
      throw new IntentError("invalid_request", e.message);
    }
    throw new IntentError("invalid_request", "mission_intent must be valid JSON");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new IntentError("invalid_request", "mission_intent must be a JSON object");
  }
  const obj = parsed as Record<string, JsonValue>;

  // The retired bare-Intent parameter shape: a top level with no `intent`
  // member (e.g. `goal` at the top) is the pre-envelope carriage and is
  // refused explicitly, not merely as an unknown member.
  if (obj.intent === undefined) {
    throw new IntentError(
      "invalid_request",
      "mission_intent must be a Mission Intent Submission envelope ({intent, evidence?}); the bare Mission Intent shape is not accepted",
    );
  }
  // The envelope's OWN closed top level (@spec mission#submission-via-par).
  for (const key of Object.keys(obj)) {
    if (!SUBMISSION_TOP_LEVEL.has(key)) {
      throw new IntentError("invalid_request", `unknown submission member: ${key}`);
    }
  }
  if (obj.intent === null || typeof obj.intent !== "object" || Array.isArray(obj.intent)) {
    throw new IntentError("invalid_request", "intent must be a JSON object");
  }
  const intent = validateMissionIntentObject(obj.intent as Record<string, JsonValue>);
  const evidence = validateIntentSubmissionEvidence(obj.evidence, bounds);
  return { intent, ...(evidence ? { evidence } : {}) };
}

/**
 * @spec mission#intent-submission-evidence — validate the OPTIONAL `evidence`
 * array of the Submission envelope. Every entry is an object with a REQUIRED
 * `type`; the selected type owns the entry's remaining members and validation
 * (dispatch through {@link INTENT_SUBMISSION_EVIDENCE_TYPES}). An unknown
 * type or an entry failing its type's stage-1 validation is refused —
 * evidence presented for admission is never silently ignored. `evidence`,
 * when present, MUST be a non-empty array; entry count and per-entry size are
 * bounded. Returns undefined only for ABSENT evidence.
 */
export function validateIntentSubmissionEvidence(
  raw: JsonValue | undefined,
  bounds: SubmissionEvidenceBounds = {},
): IntentSubmissionEvidenceEntry[] | undefined {
  if (raw === undefined) return undefined;
  if (!Array.isArray(raw)) {
    throw new IntentError("invalid_request", "evidence must be a JSON array");
  }
  const maxEntries = bounds.maxEvidenceEntries ?? DEFAULT_MAX_EVIDENCE_ENTRIES;
  const maxEntryBytes = bounds.maxEvidenceEntryBytes ?? DEFAULT_MAX_EVIDENCE_ENTRY_BYTES;
  // @spec mission#submission-via-par — `evidence`, when present, is a
  // NON-EMPTY array: an empty array presents nothing and is refused rather
  // than silently normalized away.
  if (raw.length === 0) {
    throw new IntentError("invalid_request", "evidence must be a non-empty array");
  }
  if (raw.length > maxEntries) {
    throw new IntentError("invalid_request", `evidence exceeds the entry-count bound (${maxEntries})`);
  }
  for (const entry of raw) {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new IntentError("invalid_request", "evidence entries must be objects");
    }
    const e = entry as Record<string, JsonValue>;
    if (typeof e.type !== "string" || e.type.length === 0) {
      throw new IntentError("invalid_request", "evidence entries require a type (non-empty string)");
    }
    if (Buffer.byteLength(JSON.stringify(e), "utf8") > maxEntryBytes) {
      throw new IntentError("invalid_request", `evidence entry exceeds the size bound (${maxEntryBytes} bytes)`);
    }
    const impl = EVIDENCE_TYPE_REGISTRY.get(e.type);
    if (!impl) {
      throw new IntentError("invalid_mission_intent_evidence", `unknown evidence type: ${e.type}`);
    }
    // Stage 1 only: the type's SYNCHRONOUS structural validation (closed
    // member set). Stage-2 verification (signature/freshness/binding) runs
    // later, via verifyIntentSubmissionEvidence — after the idempotency
    // recovery lookup on the exchanges, so an artifact that expired after a
    // completed operation cannot break that operation's recovery.
    impl.validate(e);
  }
  return raw as IntentSubmissionEvidenceEntry[];
}

/**
 * @spec mission#intent-submission-evidence — STAGE 2: verify the presented
 * (stage-1-validated) evidence and produce the normalized facts the Mission
 * Record lands. Runs per the processing order: the semantic intent is already
 * validated and the PROVISIONAL `intent_hash` computed (passed here); each
 * entry's type-specific verifier receives that hash, the AS issuer, the
 * presenter the containing exchange established, and the evaluation time.
 *
 * The ANTI-DOWNGRADE hook: `required` is the policy-resolved set of evidence
 * types this submission MUST present (resolved BEFORE derivation from global
 * or per-client configuration). A required type absent from the submission is
 * refused; successful processing without evidence never satisfies a
 * requirement. ALL verification failures map to
 * `invalid_mission_intent_evidence`.
 *
 * On IDEMPOTENT operations the completed-operation recovery lookup PRECEDES
 * this call: recovery of an already-completed request never re-verifies
 * evidence freshness or status.
 */
export async function verifyIntentSubmissionEvidence(
  evidence: IntentSubmissionEvidenceEntry[] | undefined,
  ctx: Omit<IntentSubmissionEvidenceVerifyInput, "entry">,
  required: readonly string[] = [],
): Promise<IntentSubmissionEvidenceFact[] | undefined> {
  const presented = new Set((evidence ?? []).map((e) => e.type));
  for (const type of required) {
    if (!presented.has(type)) {
      throw new IntentError(
        "invalid_mission_intent_evidence",
        `required evidence type absent: ${type}`,
      );
    }
  }
  if (!evidence || evidence.length === 0) return undefined;
  const facts: IntentSubmissionEvidenceFact[] = [];
  for (const entry of evidence) {
    const impl = EVIDENCE_TYPE_REGISTRY.get(entry.type);
    if (!impl) {
      throw new IntentError("invalid_mission_intent_evidence", `unknown evidence type: ${entry.type}`);
    }
    let verified: Record<string, JsonValue>;
    try {
      verified = await impl.verify({ ...ctx, entry });
    } catch (e) {
      if (e instanceof IntentError) throw e;
      throw new IntentError(
        "invalid_mission_intent_evidence",
        `evidence verification failed (${entry.type}): ${e instanceof Error ? e.message : "verifier error"}`,
      );
    }
    facts.push({
      type: entry.type,
      // The artifact digest as the record lands it: the family anchor idiom
      // over the entry AS PRESENTED (typ mission-intent-evidence).
      artifact_hash: computeAnchor(MISSION_INTENT_EVIDENCE_TYP, ctx.issuer, entry as never),
      verified_at: ctx.now.toISOString(),
      ...(Object.keys(verified).length ? { facts: verified } : {}),
    });
  }
  return facts;
}

/**
 * Compute the PROVISIONAL `intent_hash` for evidence verification (processing
 * order: validate the intent, compute the provisional hash, then verify).
 * Identical to the commitment the approval later records.
 */
export function provisionalIntentHash(issuer: string, intent: MissionIntent): string {
  return intentHash(issuer, intent as never);
}

/**
 * @spec mission#mission-intent — the SEMANTIC Mission Intent validator over a
 * raw JSON string (strict parse + {@link validateMissionIntentObject}). This
 * validates the bare Intent object — the value of the envelope's `intent`
 * member and the object `intent_hash` commits — NOT the `mission_intent`
 * parameter value, which is the Submission envelope
 * ({@link validateMissionIntentSubmission}).
 */
export function validateMissionIntent(raw: string): MissionIntent {
  if (Buffer.byteLength(raw, "utf8") > MAX_INTENT_BYTES) {
    throw new IntentError("invalid_request", "mission_intent exceeds size bound");
  }
  let parsed: JsonValue;
  try {
    parsed = parseStrictJson(raw);
  } catch (e) {
    if (e instanceof DuplicateMemberError) {
      throw new IntentError("invalid_request", e.message);
    }
    throw new IntentError("invalid_request", "mission_intent must be valid JSON");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new IntentError("invalid_request", "mission_intent must be a JSON object");
  }
  return validateMissionIntentObject(parsed as Record<string, JsonValue>);
}

/** The semantic-Intent rules over a parsed object (shared by the envelope
 *  parser and {@link validateMissionIntent}). */
function validateMissionIntentObject(obj: Record<string, JsonValue>): MissionIntent {
  // Closed top level (@spec mission#submission-via-par).
  for (const key of Object.keys(obj)) {
    if (!TOP_LEVEL.has(key)) {
      throw new IntentError("invalid_request", `unknown top-level member: ${key}`);
    }
  }

  const goal = obj.goal;
  if (typeof goal !== "string" || goal.length === 0 || goal.length > MAX_GOAL_CHARS) {
    throw new IntentError("invalid_request", "goal is required (string, <= 4096 chars)");
  }
  // @spec mission#mission-intent — a malformed `goal_lang` is refused
  // invalid_request at submission acceptance. Disclosure metadata only: it is
  // committed by intent_hash like every member and never feeds derivation.
  const goalLang = obj.goal_lang;
  if (goalLang !== undefined) {
    if (typeof goalLang !== "string" || !isWellFormedBcp47(goalLang)) {
      throw new IntentError("invalid_request", "goal_lang must be a well-formed BCP 47 language tag");
    }
  }
  const targetResources = obj.target_resources;
  if (!isStringArray(targetResources) || targetResources.length === 0 || targetResources.length > MAX_ARRAY_LEN) {
    throw new IntentError("invalid_request", "target_resources is required (non-empty string array)");
  }
  for (const r of targetResources) {
    if (!isAbsoluteUri(r)) throw new IntentError("invalid_request", `resource is not an absolute URI: ${r}`);
  }
  const expiresAt = obj.expires_at;
  if (typeof expiresAt !== "string" || Number.isNaN(Date.parse(expiresAt))) {
    throw new IntentError("invalid_request", "expires_at is required (RFC 3339 date-time)");
  }

  for (const member of ["task_bounds", "success_criteria"] as const) {
    const v = obj[member];
    if (v !== undefined && (!isStringArray(v) || v.length > MAX_ARRAY_LEN)) {
      throw new IntentError("invalid_request", `${member} must be a string array`);
    }
  }
  if (obj.purpose !== undefined && typeof obj.purpose !== "string") {
    throw new IntentError("invalid_request", "purpose must be a string");
  }

  // @spec mission#derivation-issuance-policy — the client-requested ceiling
  // (@spec mission#mission-intent's `requested_derivation_limit`). A request
  // only: the effective, AS-clamped `derivation_limit` is established at the
  // approval event, never copied verbatim (@spec mission#derivation-issuance-policy).
  const requestedDerivationLimit = obj.requested_derivation_limit;
  if (
    requestedDerivationLimit !== undefined &&
    (typeof requestedDerivationLimit !== "number" ||
      !Number.isInteger(requestedDerivationLimit) ||
      requestedDerivationLimit < 1)
  ) {
    throw new IntentError("invalid_request", "requested_derivation_limit must be an integer >= 1");
  }

  return obj as unknown as MissionIntent;
}

/**
 * @spec mission#authority-proposal — intake of the client-submitted authority
 * proposal: the standard `authorization_details` request parameter pushed
 * alongside `mission_intent`. The proposal rides the Intent's carriage rules
 * (PAR-only, bounded size, strict parse: duplicate member names are rejected
 * before canonicalization, @spec mission#canonicalization). Each entry MUST be
 * of an advertised type and MUST validate against that type's published JSON
 * Schema (refused `invalid_authorization_details`, never silently kept), and
 * each entry's `resource` MUST be among the Intent's `target_resources`
 * (refused `invalid_request`). An entry binding `max_amount` to an action the
 * deployment catalog marks not amount-bearing is refused
 * `invalid_authorization_details` (#743).
 */
export function validateAuthorityProposal(raw: string, targetResources: string[]): AuthorityEntry[] {
  if (Buffer.byteLength(raw, "utf8") > MAX_INTENT_BYTES) {
    throw new IntentError("invalid_request", "authorization_details exceeds size bound");
  }
  let parsed: JsonValue;
  try {
    parsed = parseStrictJson(raw);
  } catch (e) {
    if (e instanceof DuplicateMemberError) {
      throw new IntentError("invalid_request", e.message);
    }
    throw new IntentError("invalid_request", "authorization_details must be valid JSON");
  }
  if (!Array.isArray(parsed) || parsed.length > MAX_ARRAY_LEN) {
    throw new IntentError("invalid_request", "authorization_details must be a JSON array");
  }
  for (const entry of parsed) {
    validateProposedEntry(entry, targetResources);
  }
  return parsed as unknown as AuthorityEntry[];
}

function validateProposedEntry(entry: JsonValue, targetResources: string[]): void {
  if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
    throw new IntentError("invalid_request", "authorization_details entries must be objects");
  }
  const e = entry as Record<string, JsonValue>;
  // @spec mission#authority-proposal, I-D.draft-zehavi-oauth-rar-metadata — the
  // type MUST be one this AS advertises via
  // authorization_details_types_metadata_endpoint;
  // SUPPORTED_AUTHORIZATION_DETAILS_TYPES is that SAME key set (single source of
  // truth), so this can never drift from what the metadata endpoint publishes. An
  // unadvertised type is refused here, never silently carried into derivation.
  if (typeof e.type !== "string" || !SUPPORTED_AUTHORIZATION_DETAILS_TYPES.has(e.type)) {
    throw new IntentError("invalid_authorization_details", `unsupported authorization details type: ${String(e.type)}`);
  }
  // @spec mission#authority-proposal, I-D.draft-zehavi-oauth-rar-metadata — the
  // entry MUST also validate against that type's published JSON Schema. Only
  // mission_resource_access is implemented (the type check above already
  // refused anything else); a failing entry is refused
  // invalid_authorization_details, never silently kept.
  const schemaError = validateMissionResourceAccessSchema(e);
  if (schemaError) {
    throw new IntentError(
      "invalid_authorization_details",
      `authorization_details entry fails its published schema: ${schemaError}`,
    );
  }
  // #743 — the entry MUST NOT bind `max_amount` to an action the deployment
  // catalog marks not amount-bearing: an entry's constraints bind every action
  // in it, so such a cap is one no request for that action can ever satisfy.
  // Refused `invalid_authorization_details` (a request fault: the client
  // proposed it), by the SAME validator the typed config loader applies to a
  // configured ceiling entry, so a correct ceiling cannot be undone from the
  // proposal side. Runs AFTER the published-schema check, so a malformed
  // `max_amount` still refuses as a schema failure. An action the catalog does
  // not declare carries no claim and is not refused here.
  const amountError = amountBearingBindingError(e as unknown as AmountBindingCandidate);
  if (amountError) {
    throw new IntentError(
      "invalid_authorization_details",
      `authorization_details entry ${amountError}`,
    );
  }
  // @spec mission#authority-proposal: each proposed entry carrying `resource`
  // MUST have it among the Intent's `target_resources`; violated -> invalid_request.
  if (typeof e.resource === "string" && !targetResources.includes(e.resource)) {
    throw new IntentError("invalid_request", `authorization_details resource not among Intent target_resources: ${e.resource}`);
  }
}

function isStringArray(v: JsonValue | undefined): v is string[] {
  return Array.isArray(v) && v.every((x) => typeof x === "string");
}

function isAbsoluteUri(v: string): boolean {
  try {
    const u = new URL(v);
    return u.protocol.length > 0;
  } catch {
    return false;
  }
}
