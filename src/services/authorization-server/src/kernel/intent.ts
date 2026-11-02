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
  isAbsoluteUri,
  isCurrencyCode,
  isValidAmount,
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
// closed-top-level rule below (@spec mission#submission-via-par). The retired
// `success_criteria` member is refused the same way (@spec mission#mission-intent:
// completion outcomes are `goal` prose). Recorded Missions are never re-parsed
// here, so an earlier Intent that carried it keeps its record and intent_hash.
const TOP_LEVEL = new Set([
  "goal",
  "goal_lang",
  "target_resources",
  "expires_at",
  "task_bounds",
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
/**
 * @spec submission-evidence#verification-bounds (#1962) — the default
 * verification work one submission may impose, in units of one signature
 * verification (or a step of like cost): two per entry at the default entry
 * bound.
 */
export const DEFAULT_MAX_EVIDENCE_VERIFICATION_WORK = 16;

export interface SubmissionEvidenceBounds {
  maxEvidenceEntries?: number;
  maxEvidenceEntryBytes?: number;
  /** @spec submission-evidence#verification-bounds (#1962): the verification-work budget per submission. */
  maxVerificationWork?: number;
}

/**
 * @spec submission-evidence#verification-bounds (#1962) — the verification
 * work a submission has left. The dispatch charges one unit before each
 * entry's `verify` (its first signature verification); a type whose
 * verification does more (further signatures, a certificate chain, a key
 * fetch) MUST charge each further unit before doing it. A charge past the
 * budget throws `invalid_request`, so the excess work is never done.
 */
export interface IntentSubmissionEvidenceWork {
  charge(units: number): void;
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
 * @spec request-provenance#replay (#939 slice 2a-2, D1119 Q1): what a type
 * holds in a {@link SubmissionAdmission} while the containing submission is
 * decided: prepared, then committed, when the carrier accepts it under the
 * carrier's reference for the accepted submission; released otherwise.
 */
export interface SubmissionAdmissionHold {
  /**
   * Check, changing nothing, that the reservation can still commit under
   * `ref`, and return the step that commits it; undefined when it cannot
   * (it lapsed). The scope prepares every hold before it runs any step, in
   * one synchronous turn, so a prepared step does not fail.
   */
  prepare(ref: string): (() => void) | undefined;
  release(): void;
}

/**
 * @spec request-provenance#replay (#939 slice 2a-2, D1119 Q1): the admission
 * scope of one submission, owned by its carrier. A type that reserves state
 * while verifying (a replay pair) holds it here. The carrier commits the
 * scope when it accepts the submission and releases it on every other
 * outcome, thrown or not; the dispatch also releases it when verification
 * refuses, another entry's failure and the verification-work bound included.
 * Release is idempotent, a committed scope releases nothing, and a released
 * scope commits nothing.
 */
export class SubmissionAdmission {
  #state: "open" | "committed" | "released" = "open";
  readonly #holds: SubmissionAdmissionHold[] = [];

  /** `open` until the carrier commits or releases it. */
  get state(): "open" | "committed" | "released" {
    return this.#state;
  }

  /** Hold a reservation until the submission is decided. A settled scope releases it at once and refuses. */
  hold(hold: SubmissionAdmissionHold): void {
    if (this.#state !== "open") {
      hold.release();
      throw new Error(`the submission's admission is already ${this.#state}`);
    }
    this.#holds.push(hold);
  }

  /**
   * The carrier accepted the submission: commit every hold under `ref`, all
   * or nothing. Every hold is prepared before any commits; when one can no
   * longer commit, the scope releases every hold and throws, committing
   * none, so each still-valid assertion stays retryable.
   */
  commit(ref: string): void {
    if (this.#state === "committed") return;
    if (this.#state === "released") throw new Error("a released admission commits nothing");
    const steps: Array<() => void> = [];
    for (const hold of this.#holds) {
      let step: (() => void) | undefined;
      try {
        step = hold.prepare(ref);
      } catch (e) {
        this.release();
        throw e;
      }
      if (step === undefined) {
        this.release();
        throw new Error("a reservation lapsed before the submission was accepted: nothing is committed");
      }
      steps.push(step);
    }
    this.#state = "committed";
    for (const step of steps) step();
  }

  /** Any outcome but acceptance: release every hold, once. A committed scope releases nothing. */
  release(): void {
    if (this.#state !== "open") return;
    this.#state = "released";
    for (const hold of this.#holds) hold.release();
  }
}

/**
 * @spec request-provenance#replay (#939 slice 2a-2, D1119 Q1): a later step of
 * a submission the carrier already accepted, named by the carrier's
 * reference for it (`par:<jti>` for a pushed authorization request).
 */
export interface IntentSubmissionAcceptedReference {
  ref: string;
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
  /** The submission's remaining verification work (#1962). */
  work: IntentSubmissionEvidenceWork;
  /**
   * @spec request-provenance#replay (#939 slice 2a-2): the carrier's admission
   * scope for this submission, where the carrier decides acceptance; absent
   * on a carrier that holds no reservation.
   */
  admission?: SubmissionAdmission;
  /**
   * @spec request-provenance#replay (#939 slice 2a-2): set on a later step of
   * an accepted submission. A type with {@link IntentSubmissionEvidenceType.resume}
   * is resumed instead of verified; any other type is verified as before.
   */
  accepted?: IntentSubmissionAcceptedReference;
}

/**
 * @spec request-provenance#replay (#939 slice 2a-2): the input of a
 * {@link IntentSubmissionEvidenceType.resume}: the verification input with
 * the accepted reference required and no verification work, since a resume
 * verifies nothing.
 */
export type IntentSubmissionEvidenceResumeInput = Omit<IntentSubmissionEvidenceVerifyInput, "work" | "admission" | "accepted"> & {
  accepted: IntentSubmissionAcceptedReference;
};

/** What a resume returns: the facts and the time the original verification recorded. */
export interface IntentSubmissionEvidenceResumed {
  facts: Record<string, JsonValue>;
  /** The original verification's time, as the dispatch stamps it (ISO 8601). */
  verified_at: string;
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
 *    (the nested `facts` object of {@link IntentSubmissionEvidenceFact}). A
 *    verification failure maps to `invalid_mission_intent_evidence`; a charge
 *    past the verification-work bound ({@link IntentSubmissionEvidenceWork})
 *    refuses the submission `invalid_request`, even where the type catches it.
 */
export interface IntentSubmissionEvidenceType {
  validate(entry: Record<string, JsonValue>): void;
  verify(input: IntentSubmissionEvidenceVerifyInput): Promise<Record<string, JsonValue>>;
  /**
   * @spec request-provenance#replay (#939 slice 2a-2, D1119 Q1): OPTIONAL. A
   * later step of an accepted submission relies on the type's acceptance
   * record instead of verifying again: it returns the recorded facts with
   * the original verification time, and refuses when no record matches.
   * The dispatch charges no verification work for it.
   */
  resume?(input: IntentSubmissionEvidenceResumeInput): Promise<IntentSubmissionEvidenceResumed>;
}

/**
 * @spec mission#intent-submission-evidence (#939 slice 2a-2): the evidence
 * types one authorization server registers beside the process-wide registry
 * ({@link INTENT_SUBMISSION_EVIDENCE_TYPES}), consulted first. A type whose
 * verification holds per-AS state (trust, a replay store) is registered
 * here, so another AS in the same process does not accept it.
 */
export type IntentSubmissionEvidenceTypes = ReadonlyMap<string, IntentSubmissionEvidenceType>;

const EVIDENCE_TYPE_REGISTRY = new Map<string, IntentSubmissionEvidenceType>();

/** The registered implementation of `type`: this AS's own first, then the process-wide registry. */
function evidenceTypeFor(type: string, types: IntentSubmissionEvidenceTypes | undefined): IntentSubmissionEvidenceType | undefined {
  return types?.get(type) ?? EVIDENCE_TYPE_REGISTRY.get(type);
}

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
 * @spec mission#approval-commit (#1721, D845): the requested ceiling, or the
 * effective expiry a commit establishes, is not later than the instant it is
 * judged at. Its code stays `invalid_request`, the refusal at submission
 * acceptance and on every surface that maps it as it always has; a direct
 * approval decision tells it apart and completes the request `access_denied`.
 */
export class ExpiryPassedError extends IntentError {
  constructor(message: string) {
    super("invalid_request", message);
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
  opts: SubmissionIntakeOptions = {},
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
  const intent = validateMissionIntentObject(obj.intent as Record<string, JsonValue>, opts);
  // @spec mission#submission-processing (#1503 finding 12): the evidence
  // array's shape, its bounds and each entry's structure are step 1 checks
  // on every carrier. They run after the Intent's step 2 checks here, which
  // no client can observe: both refuse with invalid_request.
  const evidence = validateIntentSubmissionEvidence(obj.evidence, bounds, {
    dispatch: opts.deferEvidenceDispatch !== true,
    ...(opts.evidenceTypes ? { types: opts.evidenceTypes } : {}),
  });
  return { intent, ...(evidence ? { evidence } : {}) };
}

/** Options of {@link validateMissionIntentSubmission}. */
export interface SubmissionIntakeOptions extends IntentIntakeOptions {
  /** This AS's own evidence types, consulted before the process-wide registry (#939 slice 2a-2). */
  evidenceTypes?: IntentSubmissionEvidenceTypes;
  /**
   * @spec mission#submission-processing (#1411, #1503 finding 12): leave
   * evidence type dispatch ({@link dispatchIntentSubmissionEvidenceEntries})
   * to {@link verifyIntentSubmissionEvidence}, so a carrier that follows the
   * Submission Processing Order refuses an authority-proposal failure (step
   * 3) and a missing required type (step 5) before an unsupported type or a
   * type validation failure (step 6). The step 1 checks still run at parse:
   * the evidence array's shape and entry-count bound, and each entry's
   * structure and size bound ({@link checkIntentSubmissionEvidenceStructure}).
   */
  deferEvidenceDispatch?: boolean;
}

/**
 * @spec mission#intent-submission-evidence — validate the OPTIONAL `evidence`
 * array of the Submission envelope. Every entry is an object with a REQUIRED
 * `type`; the selected type owns the entry's remaining members and validation
 * (dispatch through {@link INTENT_SUBMISSION_EVIDENCE_TYPES}). An unknown
 * type or an entry failing its type's stage-1 validation is refused —
 * evidence presented for admission is never silently ignored. `evidence`,
 * when present, MUST be a non-empty array; entry count and per-entry size are
 * bounded. Returns undefined only for ABSENT evidence. With `dispatch: false`
 * only the step 1 checks run (the array's shape and bounds, and each
 * entry's structure and size), and type dispatch waits for
 * {@link verifyIntentSubmissionEvidence}.
 */
export function validateIntentSubmissionEvidence(
  raw: JsonValue | undefined,
  bounds: SubmissionEvidenceBounds = {},
  opts: { dispatch?: boolean; types?: IntentSubmissionEvidenceTypes } = {},
): IntentSubmissionEvidenceEntry[] | undefined {
  if (raw === undefined) return undefined;
  if (!Array.isArray(raw)) {
    throw new IntentError("invalid_request", "evidence must be a JSON array");
  }
  const maxEntries = bounds.maxEvidenceEntries ?? DEFAULT_MAX_EVIDENCE_ENTRIES;
  // @spec mission#submission-via-par — `evidence`, when present, is a
  // NON-EMPTY array: an empty array presents nothing and is refused rather
  // than silently normalized away.
  if (raw.length === 0) {
    throw new IntentError("invalid_request", "evidence must be a non-empty array");
  }
  if (raw.length > maxEntries) {
    throw new IntentError("invalid_request", `evidence exceeds the entry-count bound (${maxEntries})`);
  }
  checkIntentSubmissionEvidenceStructure(raw, bounds);
  if (opts.dispatch !== false) dispatchIntentSubmissionEvidenceEntries(raw, opts.types);
  return raw as IntentSubmissionEvidenceEntry[];
}

/**
 * @spec mission#intent-submission-evidence, mission#submission-processing
 * (#1503 finding 12): the structural evidence entry rules, a step 1 check
 * over EVERY entry before any entry is dispatched: an entry that is not an
 * object, lacks a `type`, or exceeds the per-entry size bound is refused
 * `invalid_request`.
 */
export function checkIntentSubmissionEvidenceStructure(
  entries: readonly JsonValue[],
  bounds: SubmissionEvidenceBounds = {},
): void {
  const maxEntryBytes = bounds.maxEvidenceEntryBytes ?? DEFAULT_MAX_EVIDENCE_ENTRY_BYTES;
  for (const entry of entries) {
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
  }
}

/**
 * @spec mission#intent-submission-evidence, mission#submission-processing
 * (step 6): type dispatch over structurally valid entries. An unknown type,
 * or an entry failing its type's synchronous validation, is refused
 * `invalid_mission_intent_evidence`.
 */
export function dispatchIntentSubmissionEvidenceEntries(
  entries: readonly JsonValue[],
  types?: IntentSubmissionEvidenceTypes,
): void {
  for (const entry of entries) {
    // Stage 1 only: the type's SYNCHRONOUS structural validation (closed
    // member set). Stage-2 verification (signature/freshness/binding) runs
    // later, via verifyIntentSubmissionEvidence, after the idempotency
    // recovery lookup on the exchanges, so an artifact that expired after a
    // completed operation cannot break that operation's recovery.
    dispatchEvidenceEntry(entry as Record<string, JsonValue>, types);
  }
}

/**
 * @spec mission#intent-submission-evidence: the structural entry rules for
 * every entry ({@link checkIntentSubmissionEvidenceStructure}), then type
 * dispatch ({@link dispatchIntentSubmissionEvidenceEntries}).
 */
export function checkIntentSubmissionEvidenceEntries(
  entries: readonly JsonValue[],
  bounds: SubmissionEvidenceBounds = {},
  types?: IntentSubmissionEvidenceTypes,
): void {
  checkIntentSubmissionEvidenceStructure(entries, bounds);
  dispatchIntentSubmissionEvidenceEntries(entries, types);
}

/**
 * @spec mission#intent-submission-evidence — type dispatch for one entry: an
 * unknown type, or an entry failing its type's synchronous validation, is
 * refused `invalid_mission_intent_evidence`.
 */
function dispatchEvidenceEntry(
  entry: Record<string, JsonValue>,
  types: IntentSubmissionEvidenceTypes | undefined,
): IntentSubmissionEvidenceType {
  const impl = evidenceTypeFor(String(entry.type), types);
  if (!impl) {
    throw new IntentError("invalid_mission_intent_evidence", `unknown evidence type: ${String(entry.type)}`);
  }
  impl.validate(entry);
  return impl;
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
 * requirement. Verification failures map to
 * `invalid_mission_intent_evidence`. A submission whose verification would
 * pass the verification-work bound is refused `invalid_request` instead
 * (@spec submission-evidence#verification-bounds, #1962), before the excess
 * work is done.
 *
 * On IDEMPOTENT operations the completed-operation recovery lookup PRECEDES
 * this call: recovery of an already-completed request never re-verifies
 * evidence freshness or status.
 *
 * @spec request-provenance#replay (#939 slice 2a-2, D1119 Q1): with
 * `ctx.accepted`, a type that defines `resume` is resumed from its
 * acceptance record, uncharged, and every other type is verified as before.
 * Any refusal here releases `ctx.admission`, so a reservation an earlier
 * entry made never outlives a refusal of its submission.
 */
export async function verifyIntentSubmissionEvidence(
  evidence: IntentSubmissionEvidenceEntry[] | undefined,
  ctx: Omit<IntentSubmissionEvidenceVerifyInput, "entry" | "work">,
  required: readonly string[] = [],
  bounds: SubmissionEvidenceBounds = {},
  types?: IntentSubmissionEvidenceTypes,
): Promise<IntentSubmissionEvidenceFact[] | undefined> {
  // A direct caller can pass entries no parse has checked: read a type
  // only where an entry is an object with a string `type`.
  const presented = new Set(
    (evidence ?? []).flatMap((e) => {
      const type = (e as unknown as { type?: unknown } | null)?.type;
      return typeof type === "string" ? [type] : [];
    }),
  );
  for (const type of required) {
    if (!presented.has(type)) {
      throw new IntentError(
        "invalid_mission_intent_evidence",
        `required evidence type absent: ${type}`,
      );
    }
  }
  if (!evidence || evidence.length === 0) return undefined;
  // The entry rules for every entry before any verification. A carrier that
  // deferred type dispatch at parse (@spec mission#submission-processing,
  // #1411) runs it here (step 6); the structural rules, and for any other
  // carrier the dispatch too, repeat the parse-time result.
  checkIntentSubmissionEvidenceEntries(evidence as unknown as JsonValue[], bounds, types);
  // @spec submission-evidence#verification-bounds (#1962): the work this
  // submission's verification may do, beyond the size and count bounds. A
  // refused charge is a refusal of the submission even where the type caught
  // it and returned.
  const budget = bounds.maxVerificationWork ?? DEFAULT_MAX_EVIDENCE_VERIFICATION_WORK;
  let spent = 0;
  let exceeded = false;
  const overBound = () =>
    new IntentError("invalid_request", `the submission's evidence exceeds the verification-work bound (${budget})`);
  const work: IntentSubmissionEvidenceWork = {
    charge(units) {
      if (!Number.isSafeInteger(units) || units < 0) {
        throw new Error(`verification work is a non-negative integer, not ${String(units)}`);
      }
      if (exceeded || spent + units > budget) {
        exceeded = true;
        throw overBound();
      }
      spent += units;
    },
  };
  const facts: IntentSubmissionEvidenceFact[] = [];
  // @spec request-provenance#replay (#939 slice 2a-2): the whole loop, so a
  // refusal after an earlier entry reserved (a later entry failing, or the
  // verification-work bound refusing after the catch) releases it.
  try {
    for (const entry of evidence) {
      const impl = evidenceTypeFor(entry.type, types);
      if (!impl) {
        throw new IntentError("invalid_mission_intent_evidence", `unknown evidence type: ${entry.type}`);
      }
      // The artifact digest as the record lands it: the family anchor idiom
      // over the entry AS PRESENTED (typ mission-intent-evidence).
      const artifactHash = () => computeAnchor(MISSION_INTENT_EVIDENCE_TYP, ctx.issuer, entry as never);
      if (ctx.accepted !== undefined && impl.resume !== undefined) {
        // A later step of an accepted submission: no signature is verified,
        // so no verification work is charged.
        const { admission: _admission, accepted, ...rest } = ctx;
        let resumed: IntentSubmissionEvidenceResumed;
        try {
          resumed = await impl.resume({ ...rest, entry, accepted });
        } catch (e) {
          if (e instanceof IntentError) throw e;
          throw new IntentError(
            "invalid_mission_intent_evidence",
            `evidence acceptance record refused (${entry.type}): ${e instanceof Error ? e.message : "verifier error"}`,
          );
        }
        facts.push({
          type: entry.type,
          artifact_hash: artifactHash(),
          verified_at: resumed.verified_at,
          ...(Object.keys(resumed.facts).length ? { facts: resumed.facts } : {}),
        });
        continue;
      }
      work.charge(1);
      let verified: Record<string, JsonValue>;
      try {
        verified = await impl.verify({ ...ctx, entry, work });
      } catch (e) {
        if (exceeded) throw overBound();
        if (e instanceof IntentError) throw e;
        throw new IntentError(
          "invalid_mission_intent_evidence",
          `evidence verification failed (${entry.type}): ${e instanceof Error ? e.message : "verifier error"}`,
        );
      }
      if (exceeded) throw overBound();
      facts.push({
        type: entry.type,
        artifact_hash: artifactHash(),
        verified_at: ctx.now.toISOString(),
        ...(Object.keys(verified).length ? { facts: verified } : {}),
      });
    }
  } catch (e) {
    ctx.admission?.release();
    throw e;
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
export function validateMissionIntent(raw: string, opts: IntentIntakeOptions = {}): MissionIntent {
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
  return validateMissionIntentObject(parsed as Record<string, JsonValue>, opts);
}

/**
 * @spec mission#mission-intent — intake-time options every Mission Intent
 * validator accepts. `now` is the submission-acceptance instant the
 * already-past `expires_at` refusal is judged against; it defaults to the
 * system clock, and the kernel supplies ITS clock so a deployment (or a test)
 * that injects one is judged against the same instant its records commit at.
 */
export interface IntentIntakeOptions {
  now?: Date;
  /**
   * @spec metering#bounds (#813, ruling 2): admit the `max_budget` member, an
   * object of exactly `amount` (a decimal amount) and `currency` (three
   * upper-case ASCII letters). Set only by a dispatch intake under the
   * `standing-payment-dispatch` capability and by the expansion of a
   * standing-payment instance; every other carrier refuses the member as
   * unknown.
   */
  admitMaxBudget?: boolean;
}

/** The semantic-Intent rules over a parsed object (shared by the envelope
 *  parser and {@link validateMissionIntent}). */
function validateMissionIntentObject(
  obj: Record<string, JsonValue>,
  opts: IntentIntakeOptions = {},
): MissionIntent {
  // Closed top level (@spec mission#submission-via-par).
  for (const key of Object.keys(obj)) {
    if (!TOP_LEVEL.has(key) && !(key === "max_budget" && opts.admitMaxBudget === true)) {
      throw new IntentError("invalid_request", `unknown top-level member: ${key}`);
    }
  }
  if (obj.max_budget !== undefined) {
    const cap = obj.max_budget;
    if (
      cap === null ||
      typeof cap !== "object" ||
      Array.isArray(cap) ||
      Object.keys(cap).length !== 2 ||
      typeof cap.amount !== "string" ||
      !isValidAmount(cap.amount) ||
      !isCurrencyCode(cap.currency)
    ) {
      throw new IntentError("invalid_request", "max_budget must be {amount, currency} with a decimal amount and a currency code");
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
  // @spec mission#mission-intent (#1310, D480): each value is one RFC 3986
  // absolute URI under the shared check, recorded and committed as submitted.
  for (const r of targetResources) {
    if (!isAbsoluteUri(r)) throw new IntentError("invalid_request", `resource is not an absolute URI: ${r}`);
  }
  const expiresAt = obj.expires_at;
  if (typeof expiresAt !== "string" || Number.isNaN(Date.parse(expiresAt))) {
    throw new IntentError("invalid_request", "expires_at is required (RFC 3339 date-time)");
  }
  // @spec mission#mission-intent — at submission acceptance the AS MUST refuse
  // an already-past requested ceiling with `invalid_request`. The requested
  // value is never rewritten forward: a Mission whose lifetime has already run
  // out is refused here rather than accepted and expired on arrival.
  // Acceptance does not freeze time; Mission creation re-checks the effective
  // expiry atomically at the commit (@spec mission#approval-event). A direct
  // approval decision that re-validates the request after this ceiling passed
  // maps the refusal to `access_denied` (@spec mission#approval-commit, #1721).
  if (Date.parse(expiresAt) <= (opts.now ?? new Date()).getTime()) {
    throw new ExpiryPassedError("expires_at is already past");
  }

  if (
    obj.task_bounds !== undefined &&
    (!isStringArray(obj.task_bounds) || obj.task_bounds.length > MAX_ARRAY_LEN)
  ) {
    throw new IntentError("invalid_request", "task_bounds must be a string array");
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

