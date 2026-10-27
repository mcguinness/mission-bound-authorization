/**
 * @spec runtime#evaluation-context-binding (#773): the payments PEP's
 * capture, salt and re-resolution of the evaluation context.
 *
 * "The **evaluation context** of a decision is the set of resource-resolved
 * facts, declared decision-relevant by the Operation Profile, whose values
 * the decision depended on." The bound object "contains that reference, the
 * qualified Mission identity, operation and resolved target identities, the
 * normalized facts, and a secret salt with its version", committed with the
 * canonical-object digest of {{parameter-digest}}. The facts come from this
 * resource's authoritative interfaces, never from an agent argument: the
 * agent names the invoice, and every fact is read from the invoice and vendor
 * records that name resolves to in the payments store. A compensate crossing
 * (#252) reads its effect facts from the committed wire's own ledger record,
 * the effect the reversal offsets, never from the invoice as it reads now,
 * and reads from the store only the live resource facts its decision also
 * evaluates: the issuance and classification of the invoice the wire paid,
 * and the current tenant of the vendor the wire paid (#1693, D873).
 *
 * Salt posture: per-epoch secret material, with an explicit
 * restart-loses-bindings posture. Each version is fresh random material
 * held in memory only, and its identifier is random too, so a restarted
 * process never answers for a version it did not mint: every binding made
 * under a lost version is unrecoverable and fails closed before any effect,
 * never recomputed under a substitute. Rotation retains every earlier version
 * for the outstanding bindings that use it, or invalidates it explicitly. The
 * salt never leaves this module's caller: it is not logged, not sent in a
 * decision request and not recorded in evidence.
 */

import { createHmac, randomBytes, randomUUID } from "node:crypto";
import {
  canonicalDigest,
  canonicalize,
  type EvaluationContextBindingDeclarations,
  type EvaluationContextBindingRef,
  type EvaluationContextDescriptor,
  type EvaluationContextGranularity,
  type JsonValue,
} from "@mission/core";
import type { CommittedEffectSource, CommittedWire } from "./connectors.js";
import type { EffectiveParams } from "./effective-params.js";
import type { Invoice, PaymentsStore, Vendor } from "./payments-store.js";

/**
 * @spec runtime#evaluation-context-binding: "The salt MUST be unpredictable,
 * secret, qualified by Mission and version". One keeper per process: each
 * version is 32 bytes of fresh random material, and the salt for a Mission is
 * the HMAC-SHA-256 of that material over the canonical Mission reference, so
 * two Missions never share a salt. Nothing persists: constructing a keeper is
 * a new epoch, and every version an earlier keeper minted is unknown here.
 */
export class EvaluationContextSalts {
  private readonly material = new Map<string, Buffer>();
  private currentVersion: string | undefined;

  constructor() {
    this.currentVersion = this.mint();
  }

  private mint(): string {
    const version = `ecs_${randomUUID()}`;
    this.material.set(version, randomBytes(32));
    return version;
  }

  /** The version new bindings are made under, or undefined when none is live. */
  current(): string | undefined {
    return this.currentVersion !== undefined && this.material.has(this.currentVersion) ? this.currentVersion : undefined;
  }

  /** Whether bindings made under `version` can still be recomputed here. */
  live(version: string): boolean {
    return this.material.has(version);
  }

  /**
   * Begin a new version for new bindings. Earlier versions stay live for the
   * outstanding bindings that use them, unless `invalidatePrevious`, which
   * explicitly invalidates those bindings: each then fails closed at use.
   */
  rotate(opts: { invalidatePrevious?: boolean } = {}): string {
    if (opts.invalidatePrevious) this.material.clear();
    this.currentVersion = this.mint();
    return this.currentVersion;
  }

  /** Explicitly invalidate every binding made under `version`. */
  invalidate(version: string): void {
    this.material.delete(version);
  }

  /** The salt for `mission` under `version`, or undefined when that version is not live. */
  saltFor(version: string, mission: { issuer: string; id: string }): string | undefined {
    const secret = this.material.get(version);
    if (!secret) return undefined;
    return createHmac("sha256", secret)
      .update(canonicalize([mission.issuer, mission.id] as JsonValue), "utf8")
      .digest("base64url");
  }
}

/**
 * The store records a crossing's live facts are read from: the invoice, and
 * the vendor whose current record supplies the vendor facts. On a store
 * crossing that vendor is the one the invoice names now; on a compensate
 * crossing it is the vendor the committed wire paid (#1693, D873).
 */
export interface StoreRecords {
  invoice: Invoice;
  vendor: Vendor;
  payments: PaymentsStore;
}

/**
 * The records a fact or target is resolved from. An ordinary crossing reads
 * the invoice and vendor in this resource's store. A compensate crossing
 * (#252) reads the committed wire's ledger record and the operation key it
 * committed under, and beside them the store records of the invoice and the
 * vendor that wire paid, for the live facts its decision also evaluates.
 */
type ResolutionSources =
  | ({ kind: "store" } & StoreRecords)
  | ({ kind: "committed_wire"; wire: CommittedWire; reverses: string } & StoreRecords);

type SourceKind = ResolutionSources["kind"];

/**
 * One authoritative resolver. `sources` names the crossings it serves, so
 * the restriction is per fact: a compensate crossing reads its effect facts
 * (vendor, amount, payee, reversed operation) only from the wire record,
 * since no store resolver of those values serves it, and reads from the store
 * only the live resource facts its decision evaluates.
 */
interface FactResolver {
  sources: readonly SourceKind[];
  granularity: EvaluationContextGranularity;
  normalization: string;
  resolve: (s: ResolutionSources) => JsonValue | undefined;
}

const STORE_ONLY: readonly SourceKind[] = Object.freeze(["store"]);
const WIRE_ONLY: readonly SourceKind[] = Object.freeze(["committed_wire"]);
/** A live invoice fact a compensating decision evaluates as well (#252). */
const STORE_AND_COMPENSATE: readonly SourceKind[] = Object.freeze(["store", "committed_wire"]);

/** A string fact the record may omit: its value, or `null` when it carries none. */
const stringOrNull = (v: unknown): JsonValue => (typeof v === "string" ? v : null);

/**
 * The authoritative resolvers this resource implements, keyed by the
 * resolver a descriptor fact names, each with the granularity and
 * normalization it produces. A descriptor fact whose resolver, granularity or
 * normalization differs from these does not resolve, so a descriptor this
 * resource cannot honor is never captured under.
 */
export const PAYMENTS_FACT_RESOLVERS: Readonly<Record<string, FactResolver>> = Object.freeze({
  "payments-store:invoice.version": {
    sources: STORE_ONLY,
    granularity: "revision",
    normalization: "integer",
    resolve: ({ invoice }) => (Number.isSafeInteger(invoice.version) ? invoice.version : undefined),
  },
  "payments-store:invoice.vendor_id": {
    sources: STORE_ONLY,
    granularity: "effective_values",
    normalization: "string",
    resolve: ({ invoice }) => (typeof invoice.vendor_id === "string" && invoice.vendor_id.length > 0 ? invoice.vendor_id : undefined),
  },
  "payments-store:vendor.version": {
    sources: STORE_ONLY,
    granularity: "revision",
    normalization: "integer",
    resolve: ({ vendor }) => (Number.isSafeInteger(vendor.version) ? vendor.version : undefined),
  },
  "payments-store:invoice.amount": {
    sources: STORE_ONLY,
    granularity: "effective_values",
    normalization: "decimal-string-and-currency",
    resolve: ({ invoice }) =>
      typeof invoice.amount === "string" && typeof invoice.currency === "string"
        ? { amount: invoice.amount, currency: invoice.currency }
        : undefined,
  },
  "payments-store:invoice.payee_account": {
    sources: STORE_ONLY,
    granularity: "effective_values",
    normalization: "string",
    resolve: ({ invoice }) =>
      typeof invoice.payee_account === "string" && invoice.payee_account.length > 0 ? invoice.payee_account : undefined,
  },
  "payments-store:vendor.remittance_recipients": {
    sources: STORE_ONLY,
    granularity: "effective_values",
    normalization: "sorted-distinct-strings",
    // An enumerated target set: every final recipient, sorted and distinct,
    // the routed set or the vendor's default address alike.
    resolve: ({ vendor, payments }) => payments.remittanceRecipients(vendor.id)?.recipients,
  },
  // @spec resource-access#initial-common-constraints, runtime#compound-actions
  // (#1266, #252): the live resource facts the implemented Common Constraints
  // read (`resource_issued_after` and `_before`, `data_classification`,
  // `tenant`), exactly as the decision request carries them: the value, or
  // `null` when the record names none. On a compensate crossing they are the
  // only store facts: the issuance and classification of the invoice the
  // committed wire paid, and the tenant of the vendor it paid, below.
  "payments-store:invoice.issued_at": {
    sources: STORE_AND_COMPENSATE,
    granularity: "effective_values",
    normalization: "string-or-null",
    resolve: ({ invoice }) => stringOrNull(invoice.issued_at),
  },
  "payments-store:invoice.classification": {
    sources: STORE_AND_COMPENSATE,
    granularity: "effective_values",
    normalization: "string-or-null",
    resolve: ({ invoice }) => stringOrNull(invoice.classification),
  },
  // The tenant of the vendor the invoice names now: a store crossing's.
  "payments-store:vendor.tenant": {
    sources: STORE_ONLY,
    granularity: "effective_values",
    normalization: "string-or-null",
    resolve: ({ vendor }) => stringOrNull(vendor.tenant),
  },
  // @spec resource-access#initial-common-constraints, runtime#compound-actions
  // (#1693, D873): a compensate crossing's tenant is the current tenant of
  // the vendor the committed wire paid. The wire fixes which vendor the
  // reversal concerns, and that vendor's record in the store supplies its
  // tenant now, never the vendor the invoice names now.
  "payments-store:paid-vendor.tenant": {
    sources: WIRE_ONLY,
    granularity: "effective_values",
    normalization: "string-or-null",
    resolve: ({ vendor }) => stringOrNull(vendor.tenant),
  },
  // @spec runtime#compound-actions (#252): a compensate crossing's facts, read
  // from the committed wire's own ledger record: the vendor it paid, its
  // amount and currency, its payee, and the operation key it committed under.
  "ledger:wire.vendor_id": {
    sources: WIRE_ONLY,
    granularity: "effective_values",
    normalization: "string",
    resolve: (s) => (s.kind === "committed_wire" && s.wire.vendorId.length > 0 ? s.wire.vendorId : undefined),
  },
  "ledger:wire.amount": {
    sources: WIRE_ONLY,
    granularity: "effective_values",
    normalization: "decimal-string-and-currency",
    resolve: (s) => (s.kind === "committed_wire" ? { amount: s.wire.amount, currency: s.wire.currency } : undefined),
  },
  "ledger:wire.payee_account": {
    sources: WIRE_ONLY,
    granularity: "effective_values",
    normalization: "string",
    resolve: (s) => (s.kind === "committed_wire" && s.wire.payeeAccount.length > 0 ? s.wire.payeeAccount : undefined),
  },
  "ledger:wire.op_key": {
    sources: WIRE_ONLY,
    granularity: "effective_values",
    normalization: "string",
    resolve: (s) => (s.kind === "committed_wire" ? s.reverses : undefined),
  },
});

/**
 * The target identities this resource resolves, by declared target type: from
 * the store records, or from the committed wire's record for a compensate
 * crossing (the invoice and vendor that wire paid).
 */
const TARGET_RESOLVERS: Readonly<Record<string, (s: ResolutionSources) => string>> = Object.freeze({
  invoice: (s) => (s.kind === "store" ? s.invoice.id : s.wire.invoiceId),
  vendor: (s) => (s.kind === "store" ? s.vendor.id : s.wire.vendorId),
});

/**
 * @spec runtime#compound-actions (#252): the committed effect a compensate
 * crossing offsets, as the PEP established it from verified evidence: the
 * operation key it committed under and its Decision's `evaluation_id`, which
 * together name its ledger record.
 */
export interface CompensatedWireRef {
  opKey: string;
  evaluationId: string;
}

/** The crossing a context is captured for: an action, and its phase where it has one. */
export interface ContextOperation {
  action: string;
  phase?: string;
}

/**
 * The binding a PEP holds for one attempt, from its capture before the
 * decision request: the digest it sent, the descriptor reference it sent, and
 * the salt version it captured under. The facts themselves are not retained:
 * the digest commits them, and re-resolution recomputes it.
 */
export interface HeldEvaluationContext {
  digest: string;
  reference: EvaluationContextBindingRef;
  saltVersion: string;
  mission: { issuer: string; id: string };
  operation: ContextOperation;
  /** For a compensate crossing: the committed wire its facts are read from (#252). */
  compensates?: CompensatedWireRef;
}

/**
 * Where a context's facts are read. The invoice the request names, in the
 * payments store; or, with `compensates`, the committed wire's ledger record
 * through `committedEffects`, beside the store records of the invoice and
 * the vendor it paid.
 *
 * `records` (and, for a compensate crossing, `wire`) are records the caller
 * already resolved: a capture commits exactly them, so the decision request
 * the caller builds from the same records and the context it commits come
 * from one observation (the owner's #1663 review 3). Absent, they are read
 * here, as recomputation at use always does.
 */
interface ContextSubject {
  invoiceId: string;
  payments: PaymentsStore;
  compensates?: CompensatedWireRef;
  committedEffects?: CommittedEffectSource;
  records?: StoreRecords;
  wire?: CommittedWire;
}

/**
 * One synchronous read of the store records an invoice names: the invoice,
 * and the vendor it names now. `undefined` when either does not resolve.
 */
export function readStoreRecords(payments: PaymentsStore, invoiceId: string): StoreRecords | undefined {
  const invoice = payments.getInvoice(invoiceId);
  const vendor = invoice ? payments.getVendor(invoice.vendor_id) : undefined;
  return invoice && vendor ? { invoice, vendor, payments } : undefined;
}

/**
 * @spec runtime#compound-actions (#252, #1693, D873): one synchronous read of
 * the store records a committed wire names: the invoice it paid, and the
 * current record of the vendor it paid, never the vendor the invoice names
 * now. `undefined` when either does not resolve.
 */
function readPaidRecords(payments: PaymentsStore, wire: CommittedWire): StoreRecords | undefined {
  const invoice = payments.getInvoice(wire.invoiceId);
  const vendor = invoice ? payments.getVendor(wire.vendorId) : undefined;
  return invoice && vendor ? { invoice, vendor, payments } : undefined;
}

function resolutionSources(subject: ContextSubject): ResolutionSources | undefined {
  if (subject.compensates) {
    const wire =
      subject.wire ?? subject.committedEffects?.committedWire(subject.compensates.opKey, subject.compensates.evaluationId);
    if (!wire) return undefined;
    // The live facts are the invoice the committed wire paid and the vendor
    // it paid, as the compensating decision reads them (#1693, D873). Records
    // handed in must be those two: a different invoice or vendor does not
    // resolve.
    const records = subject.records ?? readPaidRecords(subject.payments, wire);
    if (!records || records.invoice.id !== wire.invoiceId || records.vendor.id !== wire.vendorId) return undefined;
    return { kind: "committed_wire", wire, reverses: subject.compensates.opKey, ...records };
  }
  const records = subject.records ?? readStoreRecords(subject.payments, subject.invoiceId);
  if (!records || records.invoice.id !== subject.invoiceId) return undefined;
  return { kind: "store", ...records };
}

/** Why a capture or recomputation could not establish the context. */
export type ContextUnavailable =
  | "not_covered"
  | "descriptor_unrecoverable"
  | "salt_unavailable"
  | "target_unresolvable"
  | "fact_unresolvable";

export type ContextCapture =
  | { ok: true; digest: string; held: HeldEvaluationContext; declaredParameters: ReadonlySet<string> }
  | { ok: false; reason: ContextUnavailable };

/**
 * Resolve the declared facts and targets for one operation under
 * `descriptor`, and commit them with the reference, the Mission, the
 * operation and the salt. Every value comes from the records the subject
 * resolves to (the store's, or a compensate crossing's committed wire);
 * nothing comes from an agent argument.
 */
function commit(
  input: ContextSubject & {
    descriptor: EvaluationContextDescriptor;
    reference: EvaluationContextBindingRef;
    mission: { issuer: string; id: string };
    operation: ContextOperation;
    salt: string;
    saltVersion: string;
  },
): { ok: true; digest: string } | { ok: false; reason: ContextUnavailable } {
  const sources = resolutionSources(input);
  if (!sources) return { ok: false, reason: "target_unresolvable" };
  const targets: Array<{ type: string; id: string }> = [];
  for (const type of input.descriptor.targets) {
    const resolve = TARGET_RESOLVERS[type];
    if (!resolve) return { ok: false, reason: "target_unresolvable" };
    targets.push({ type, id: resolve(sources) });
  }
  const facts: Record<string, JsonValue> = {};
  for (const fact of input.descriptor.facts) {
    const resolver = PAYMENTS_FACT_RESOLVERS[fact.resolver];
    if (
      !resolver ||
      !resolver.sources.includes(sources.kind) ||
      resolver.granularity !== fact.granularity ||
      resolver.normalization !== fact.normalization
    ) {
      return { ok: false, reason: "fact_unresolvable" };
    }
    const value = resolver.resolve(sources);
    if (value === undefined) return { ok: false, reason: "fact_unresolvable" };
    facts[fact.name] = value;
  }
  const committed = {
    descriptor: { id: input.reference.id, version: input.reference.version, digest: input.reference.digest },
    mission: { issuer: input.mission.issuer, id: input.mission.id },
    operation: { action: input.operation.action, ...(input.operation.phase !== undefined ? { phase: input.operation.phase } : {}) },
    targets,
    facts,
    salt: input.salt,
    salt_version: input.saltVersion,
  };
  return { ok: true, digest: canonicalDigest(committed as unknown as JsonValue) };
}

/**
 * @spec runtime#evaluation-context-binding: capture before the decision
 * request. The descriptor is the one the live declaration names for the
 * covered crossing, verified against its reference; the salt is the current
 * version's. A crossing the declaration does not cover is `not_covered`, for
 * the caller to skip; any other failure means the context cannot be captured,
 * which refuses before the decision request.
 */
export function captureEvaluationContext(
  input: ContextSubject & {
    declarations: EvaluationContextBindingDeclarations;
    salts: EvaluationContextSalts;
    mission: { issuer: string; id: string };
    operation: ContextOperation;
  },
): ContextCapture {
  const entry = input.declarations.operation(input.operation.action, input.operation.phase);
  if (!entry) return { ok: false, reason: "not_covered" };
  const resolved = input.declarations.descriptor(entry.descriptor);
  if (!resolved.ok) return { ok: false, reason: "descriptor_unrecoverable" };
  const saltVersion = input.salts.current();
  const salt = saltVersion === undefined ? undefined : input.salts.saltFor(saltVersion, input.mission);
  if (saltVersion === undefined || salt === undefined) return { ok: false, reason: "salt_unavailable" };
  const committed = commit({
    descriptor: resolved.document,
    reference: entry.descriptor,
    mission: input.mission,
    operation: input.operation,
    invoiceId: input.invoiceId,
    payments: input.payments,
    ...(input.compensates ? { compensates: input.compensates } : {}),
    ...(input.committedEffects ? { committedEffects: input.committedEffects } : {}),
    ...(input.records ? { records: input.records } : {}),
    ...(input.wire ? { wire: input.wire } : {}),
    salt,
    saltVersion,
  });
  if (!committed.ok) return committed;
  return {
    ok: true,
    digest: committed.digest,
    held: {
      digest: committed.digest,
      reference: { ...entry.descriptor },
      saltVersion,
      mission: { issuer: input.mission.issuer, id: input.mission.id },
      operation: { ...input.operation },
      ...(input.compensates ? { compensates: { ...input.compensates } } : {}),
    },
    declaredParameters: declaredParameterMembers(resolved.document),
  };
}

/**
 * @spec runtime#evaluation-context-binding, runtime-evidence#execution-evidence-object
 * `effective_evaluation_context_digest`: "It commits the attempted context
 * under the same descriptor and salt version." The facts are re-resolved
 * now, under the descriptor the binding committed (its `{id, version,
 * digest}` reference, resolved from the published declaration and verified
 * against its digest) and the salt version the binding was made under, so
 * the result is comparable with the authorized digest: unchanged facts give
 * an equal digest even when the operation's descriptor has changed since,
 * which the caller refuses as its own check. A committed descriptor that is
 * no longer published or no longer hashes to its reference, a salt version
 * this process no longer holds, and a fact or target that does not resolve
 * each leave the context unestablished: the caller records no effective
 * digest for it, never one computed under a substitute.
 */
export function recomputeEvaluationContext(input: {
  held: HeldEvaluationContext;
  declarations: EvaluationContextBindingDeclarations;
  salts: EvaluationContextSalts;
  invoiceId: string;
  payments: PaymentsStore;
  /** The committed-effect records a compensate crossing's binding re-reads (#252). */
  committedEffects?: CommittedEffectSource;
}): { ok: true; digest: string } | { ok: false; reason: ContextUnavailable } {
  const resolved = input.declarations.descriptor(input.held.reference);
  if (!resolved.ok) return { ok: false, reason: "descriptor_unrecoverable" };
  // The salt version is the one the binding was made under. A version this
  // process does not hold is unrecoverable: no substitute salt is used.
  const salt = input.salts.saltFor(input.held.saltVersion, input.held.mission);
  if (salt === undefined) return { ok: false, reason: "salt_unavailable" };
  return commit({
    descriptor: resolved.document,
    reference: input.held.reference,
    mission: input.held.mission,
    operation: input.held.operation,
    invoiceId: input.invoiceId,
    payments: input.payments,
    // A compensate crossing's binding re-reads the committed wire it was
    // captured from; a record that no longer answers leaves it unestablished.
    ...(input.held.compensates ? { compensates: input.held.compensates } : {}),
    ...(input.committedEffects ? { committedEffects: input.committedEffects } : {}),
    salt,
    saltVersion: input.held.saltVersion,
  });
}

/**
 * The parameter members a descriptor's facts also occupy, where the two
 * commitments overlap. A deviation confined to these members is a moved
 * authoritative fact; any other deviating member is a parameter deviation.
 */
export function declaredParameterMembers(descriptor: EvaluationContextDescriptor): ReadonlySet<string> {
  return new Set(descriptor.facts.flatMap((f) => (f.parameter !== undefined ? [f.parameter] : [])));
}

/**
 * The members of the parameter object whose values differ between what the
 * permit was decided on and what is about to be used, by canonical value.
 * The local invocation guard is not a parameter and is never compared.
 */
export function deviatingParameterMembers(decided: EffectiveParams, current: EffectiveParams): string[] {
  const { capability_snapshot: _a, ...a } = decided;
  const { capability_snapshot: _b, ...b } = current;
  const left = a as unknown as Record<string, JsonValue | undefined>;
  const right = b as unknown as Record<string, JsonValue | undefined>;
  const keys = new Set([...Object.keys(left), ...Object.keys(right)]);
  const same = (x: JsonValue | undefined, y: JsonValue | undefined): boolean =>
    x === undefined || y === undefined ? x === y : canonicalize(x) === canonicalize(y);
  return [...keys].filter((k) => !same(left[k], right[k])).sort();
}
