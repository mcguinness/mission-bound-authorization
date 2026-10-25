/**
 * @spec runtime#evaluation-context-binding, authzen#context-evaluation-binding
 * (#773): the Evaluation-Context Binding declaration a deployment publishes in
 * its Enforcement Scope Statement, and the one reader the loader, the PDP and
 * the PEP apply to it.
 *
 * Runtime: "A claiming deployment MUST publish the covered classes and
 * operations, each operation's versioned binding descriptor, and whether it
 * reaches the verified or enforced property below. The descriptor MUST
 * identify each decision-relevant fact, its authoritative resolution
 * interface, normalization, and granularity: `revision` (an opaque version or
 * entity tag) or `effective_values` (the enumerated resolved fields)."
 *
 * The descriptor reference is `{id, version, digest}`, "`digest` (the
 * canonical-object digest of the descriptor). Published descriptor bytes MUST
 * remain immutable for that reference." Each declared document is hashed at
 * load, and one that does not hash to its own reference is refused, so a
 * changed document is never served under the reference it changed.
 *
 * Coverage is per declared operation: the extension is claimed per mediated
 * action class, and the statement names the operations of those classes it
 * covers. An operation the declaration does not list is not covered, whatever
 * its class, and a declaration without the statement's claim covers nothing:
 * "a declaration without a claim asserts nothing". An operation that is a
 * compound action lists the phases whose crossings carry the binding; each of
 * those crossings captures and checks its own context.
 *
 * A reference-statement representation of the runtime profile items, not a
 * wire member.
 */

import { ACTION_PHASES, type ActionPhase, isActionPhase } from "./action-phase.js";
import { canonicalDigest, type JsonValue } from "./canonicalize.js";
import { isAbsoluteUri } from "./operation-target.js";

/** The extension's name in the statement's `claims` and `extensions`. */
export const EVALUATION_CONTEXT_BINDING_EXTENSION = "evaluation_context_binding";

/** @spec runtime#evaluation-context-binding: the per-fact granularities. */
export const EVALUATION_CONTEXT_GRANULARITIES = ["revision", "effective_values"] as const;
export type EvaluationContextGranularity = (typeof EVALUATION_CONTEXT_GRANULARITIES)[number];

/** @spec runtime#evaluation-context-binding: the two declared properties. */
export const EVALUATION_CONTEXT_PROPERTIES = ["verified", "enforced"] as const;
export type EvaluationContextProperty = (typeof EVALUATION_CONTEXT_PROPERTIES)[number];

/** @spec runtime#evaluation-context-binding: the descriptor reference `{id, version, digest}`. */
export interface EvaluationContextBindingRef {
  id: string;
  version: string;
  digest: string;
}

/** The `sha-256:` canonical-object digest form, unpadded base64url. */
const DIGEST_FORM = /^sha-256:[A-Za-z0-9_-]{43}$/;

/** The members a descriptor reference carries, and no other. */
const REF_MEMBERS: readonly string[] = Object.freeze(["id", "version", "digest"]);

/**
 * @spec authzen#context-evaluation-binding: "`evaluation_context_digest` is
 * the prefixed canonical-object digest of the captured context". Whether
 * `value` has that form.
 */
export function isEvaluationContextDigest(value: unknown): value is string {
  return typeof value === "string" && DIGEST_FORM.test(value);
}

/**
 * @spec authzen#context-evaluation-binding: "`evaluation_context_binding` is
 * the versioned descriptor reference `{id, version, digest}`". The violation
 * for `value`, or undefined for a well-formed reference: an object with
 * exactly those members, `id` an absolute URI, `version` a non-empty string,
 * and `digest` in the canonical-object digest form.
 */
export function evaluationContextBindingViolation(value: unknown): string | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    return "must be an object";
  const o = value as Record<string, unknown>;
  const extra = Object.keys(o).find((k) => !REF_MEMBERS.includes(k));
  if (extra !== undefined) return `carries no member '${extra}'`;
  if (!isAbsoluteUri(o.id)) return "id must be an absolute URI";
  if (typeof o.version !== "string" || o.version.length === 0)
    return "version must be a non-empty string";
  if (!isEvaluationContextDigest(o.digest))
    return "digest must be sha-256: and an unpadded base64url SHA-256";
  return undefined;
}

/** Whether `value` is a well-formed descriptor reference. */
export function isEvaluationContextBindingRef(
  value: unknown,
): value is EvaluationContextBindingRef {
  return evaluationContextBindingViolation(value) === undefined;
}

/** Member-for-member equality of two references; a malformed value equals nothing. */
export function sameEvaluationContextBinding(a: unknown, b: unknown): boolean {
  if (!isEvaluationContextBindingRef(a) || !isEvaluationContextBindingRef(b)) return false;
  return a.id === b.id && a.version === b.version && a.digest === b.digest;
}

/**
 * One declared decision-relevant fact. `parameter` names the member of the
 * operation's normalized parameter object that carries the same value where
 * the two commitments overlap ("Overlapping commitments are permitted where
 * each preserves its distinct property"), so a deviation confined to such
 * members is context drift rather than a parameter deviation.
 */
export interface EvaluationContextFact {
  readonly name: string;
  readonly resolver: string;
  readonly granularity: EvaluationContextGranularity;
  readonly normalization: string;
  readonly parameter?: string;
}

/** One descriptor document: the target identities it resolves and the facts it declares. */
export interface EvaluationContextDescriptor {
  readonly id: string;
  readonly version: string;
  /** The resolved target identities the context commits, in the declared canonical order. */
  readonly targets: readonly string[];
  readonly facts: readonly EvaluationContextFact[];
}

/** One covered operation. */
export interface EvaluationContextOperation {
  readonly operation: string;
  readonly action_class: string;
  /** Present for a compound action: the phases whose crossings carry the binding. */
  readonly phases?: readonly ActionPhase[];
  readonly property: EvaluationContextProperty;
  readonly descriptor: EvaluationContextBindingRef;
}

/** A malformed declaration, refused at load. */
export class EvaluationContextBindingConfigError extends Error {
  constructor(why: string) {
    super(`evaluation_context_binding: ${why}`);
    this.name = "EvaluationContextBindingConfigError";
  }
}

const object = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === "object" && !Array.isArray(v);
const nonEmpty = (v: unknown): v is string => typeof v === "string" && v.length > 0;
const distinctStrings = (v: unknown): v is readonly string[] =>
  Array.isArray(v) && v.length > 0 && v.every(nonEmpty) && new Set(v).size === v.length;

/** The fact members this reader implements; any other member is refused, never ignored. */
const FACT_MEMBERS: readonly string[] = [
  "name",
  "resolver",
  "granularity",
  "normalization",
  "parameter",
];
const DOCUMENT_MEMBERS: readonly string[] = ["id", "version", "targets", "facts"];

function parseDescriptor(
  raw: unknown,
  at: string,
): { ref: EvaluationContextBindingRef; document: EvaluationContextDescriptor } {
  if (!object(raw)) throw new EvaluationContextBindingConfigError(`${at} must be an object`);
  const ref = { id: raw.id, version: raw.version, digest: raw.digest };
  const violation = evaluationContextBindingViolation(ref);
  if (violation !== undefined)
    throw new EvaluationContextBindingConfigError(`${at} reference ${violation}`);
  const doc = raw.document;
  if (!object(doc))
    throw new EvaluationContextBindingConfigError(`${at}.document must be an object`);
  const extra = Object.keys(doc).find((k) => !DOCUMENT_MEMBERS.includes(k));
  if (extra !== undefined)
    throw new EvaluationContextBindingConfigError(`${at}.document carries no member '${extra}'`);
  if (doc.id !== ref.id || doc.version !== ref.version) {
    throw new EvaluationContextBindingConfigError(
      `${at}.document names another id or version than its reference`,
    );
  }
  // "Published descriptor bytes MUST remain immutable for that reference."
  if (canonicalDigest(doc as JsonValue) !== ref.digest) {
    throw new EvaluationContextBindingConfigError(
      `${at}.document does not hash to its reference's digest`,
    );
  }
  if (!distinctStrings(doc.targets)) {
    throw new EvaluationContextBindingConfigError(
      `${at}.document.targets must be a non-empty list of distinct target types`,
    );
  }
  if (!Array.isArray(doc.facts) || doc.facts.length === 0) {
    throw new EvaluationContextBindingConfigError(
      `${at}.document.facts must declare at least one fact`,
    );
  }
  const names = new Set<string>();
  const parameters = new Set<string>();
  const facts = doc.facts.map((f, i): EvaluationContextFact => {
    const where = `${at}.document.facts[${i}]`;
    if (!object(f)) throw new EvaluationContextBindingConfigError(`${where} must be an object`);
    const unknown = Object.keys(f).find((k) => !FACT_MEMBERS.includes(k));
    if (unknown !== undefined)
      throw new EvaluationContextBindingConfigError(`${where} carries no member '${unknown}'`);
    if (!nonEmpty(f.name) || names.has(f.name))
      throw new EvaluationContextBindingConfigError(`${where} needs a distinct name`);
    names.add(f.name);
    if (!nonEmpty(f.resolver))
      throw new EvaluationContextBindingConfigError(`${where} names no authoritative resolver`);
    if (!(EVALUATION_CONTEXT_GRANULARITIES as readonly unknown[]).includes(f.granularity)) {
      throw new EvaluationContextBindingConfigError(
        `${where}.granularity must be revision or effective_values`,
      );
    }
    if (!nonEmpty(f.normalization))
      throw new EvaluationContextBindingConfigError(`${where} names no normalization`);
    if (f.parameter !== undefined && (!nonEmpty(f.parameter) || parameters.has(f.parameter))) {
      throw new EvaluationContextBindingConfigError(
        `${where}.parameter must name one parameter member, once`,
      );
    }
    if (nonEmpty(f.parameter)) parameters.add(f.parameter);
    return {
      name: f.name,
      resolver: f.resolver,
      granularity: f.granularity as EvaluationContextGranularity,
      normalization: f.normalization,
      ...(nonEmpty(f.parameter) ? { parameter: f.parameter } : {}),
    };
  });
  return {
    ref: { id: ref.id as string, version: ref.version as string, digest: ref.digest as string },
    document: Object.freeze({
      id: ref.id as string,
      version: ref.version as string,
      targets: [...doc.targets],
      facts,
    }),
  };
}

/** What a descriptor reference resolves to: its verified document, or nothing. */
export type EvaluationContextDescriptorResolution =
  | { ok: true; document: EvaluationContextDescriptor }
  | { ok: false };

/**
 * @spec runtime#evaluation-context-binding (#773): the parsed declaration.
 * Constructed over a whole Enforcement Scope Statement, so the claim and the
 * declaration are read together. A malformed declaration throws
 * {@link EvaluationContextBindingConfigError}; so does a claim with no
 * declaration, no covered class, a covered class with no operation, an
 * operation outside the covered classes, or an operation whose descriptor
 * reference resolves to no declared document.
 */
export class EvaluationContextBindingDeclarations {
  /** Whether the statement claims the extension. Only a claim makes {@link covers} true. */
  readonly claimed: boolean;
  readonly coveredClasses: readonly string[];
  readonly operations: readonly EvaluationContextOperation[];
  private readonly descriptors: ReadonlyArray<{
    ref: EvaluationContextBindingRef;
    document: EvaluationContextDescriptor;
  }>;

  constructor(statement: unknown) {
    const stmt = object(statement) ? statement : {};
    this.claimed =
      Array.isArray(stmt.claims) && stmt.claims.includes(EVALUATION_CONTEXT_BINDING_EXTENSION);
    const extensions = object(stmt.extensions) ? stmt.extensions : {};
    const raw = extensions[EVALUATION_CONTEXT_BINDING_EXTENSION];
    if (raw === undefined) {
      if (this.claimed)
        throw new EvaluationContextBindingConfigError("claimed with no declaration");
      this.coveredClasses = [];
      this.operations = [];
      this.descriptors = [];
      return;
    }
    if (!object(raw))
      throw new EvaluationContextBindingConfigError("the declaration must be an object");
    if (!distinctStrings(raw.covered_classes)) {
      throw new EvaluationContextBindingConfigError(
        "covered_classes must be a non-empty list of distinct classes",
      );
    }
    if (!Array.isArray(raw.descriptors) || raw.descriptors.length === 0) {
      throw new EvaluationContextBindingConfigError(
        "descriptors must declare at least one descriptor",
      );
    }
    const descriptors = raw.descriptors.map((d, i) => parseDescriptor(d, `descriptors[${i}]`));
    const keys = new Set<string>();
    for (const d of descriptors) {
      const key = JSON.stringify([d.ref.id, d.ref.version]);
      if (keys.has(key))
        throw new EvaluationContextBindingConfigError(
          `descriptor ${d.ref.id} version ${d.ref.version} is declared twice`,
        );
      keys.add(key);
    }
    if (!Array.isArray(raw.operations) || raw.operations.length === 0) {
      throw new EvaluationContextBindingConfigError(
        "operations must declare at least one covered operation",
      );
    }
    const classes = raw.covered_classes as readonly string[];
    const crossings = new Set<string>();
    const operations = raw.operations.map((o, i): EvaluationContextOperation => {
      const at = `operations[${i}]`;
      if (!object(o)) throw new EvaluationContextBindingConfigError(`${at} must be an object`);
      if (!nonEmpty(o.operation))
        throw new EvaluationContextBindingConfigError(`${at} names no operation`);
      if (!nonEmpty(o.action_class) || !classes.includes(o.action_class)) {
        throw new EvaluationContextBindingConfigError(`${at}.action_class is not a covered class`);
      }
      if (
        o.phases !== undefined &&
        !(
          distinctStrings(o.phases) &&
          (o.phases as readonly unknown[]).every((p) => isActionPhase(p))
        )
      ) {
        throw new EvaluationContextBindingConfigError(
          `${at}.phases must be distinct phases from ${ACTION_PHASES.join(", ")}`,
        );
      }
      if (!(EVALUATION_CONTEXT_PROPERTIES as readonly unknown[]).includes(o.property)) {
        throw new EvaluationContextBindingConfigError(
          `${at}.property must be verified or enforced`,
        );
      }
      const violation = evaluationContextBindingViolation(o.descriptor);
      if (violation !== undefined)
        throw new EvaluationContextBindingConfigError(`${at}.descriptor ${violation}`);
      if (!descriptors.some((d) => sameEvaluationContextBinding(d.ref, o.descriptor))) {
        throw new EvaluationContextBindingConfigError(
          `${at}.descriptor resolves to no declared descriptor`,
        );
      }
      const phases = o.phases as readonly ActionPhase[] | undefined;
      for (const phase of phases ?? [undefined]) {
        const key = JSON.stringify([o.operation, phase ?? null]);
        if (crossings.has(key))
          throw new EvaluationContextBindingConfigError(`${at} declares a crossing twice`);
        crossings.add(key);
      }
      const ref = o.descriptor as EvaluationContextBindingRef;
      return Object.freeze({
        operation: o.operation,
        action_class: o.action_class,
        ...(phases !== undefined ? { phases: [...phases] } : {}),
        property: o.property as EvaluationContextProperty,
        descriptor: { id: ref.id, version: ref.version, digest: ref.digest },
      });
    });
    for (const c of classes) {
      if (!operations.some((o) => o.action_class === c)) {
        throw new EvaluationContextBindingConfigError(`covered class ${c} declares no operation`);
      }
    }
    this.coveredClasses = [...classes];
    this.operations = operations;
    this.descriptors = descriptors;
  }

  /** The declared operation entry for one crossing, claimed or not. */
  private entry(action: string, phase: string | undefined): EvaluationContextOperation | undefined {
    return this.operations.find(
      (o) =>
        o.operation === action &&
        (o.phases === undefined
          ? phase === undefined
          : phase !== undefined && (o.phases as readonly string[]).includes(phase)),
    );
  }

  /**
   * Whether the crossing of `action` at `phase` carries the binding: the
   * statement claims the extension and lists that crossing. The one coverage
   * predicate the PDP and the PEP apply.
   */
  covers(action: string, phase: string | undefined): boolean {
    return this.claimed && this.entry(action, phase) !== undefined;
  }

  /** The covered crossing's operation entry, or undefined where it is not covered. */
  operation(action: string, phase: string | undefined): EvaluationContextOperation | undefined {
    return this.claimed ? this.entry(action, phase) : undefined;
  }

  /**
   * The document a reference names, verified against the reference's digest
   * now. An unknown `{id, version}` or bytes that no longer hash to the
   * reference resolve to nothing: such a descriptor is unrecoverable.
   */
  descriptor(ref: unknown): EvaluationContextDescriptorResolution {
    if (!isEvaluationContextBindingRef(ref)) return { ok: false };
    const found = this.descriptors.find(
      (d) => d.ref.id === ref.id && d.ref.version === ref.version,
    );
    if (!found || found.ref.digest !== ref.digest) return { ok: false };
    // The document interpreted is the one the reference commits: its bytes
    // are hashed again here, so a document that no longer hashes to the
    // reference is never read under it.
    if (canonicalDigest(found.document as unknown as JsonValue) !== ref.digest)
      return { ok: false };
    return { ok: true, document: found.document };
  }
}
