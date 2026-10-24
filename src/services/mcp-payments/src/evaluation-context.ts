/**
 * @spec runtime#evaluation-context-binding (#773): the payments PEP's
 * capture, salt and re-resolution of the evaluation context.
 *
 * "The **evaluation context** of a decision is the set of resource-resolved
 * facts, declared decision-relevant by the Operation Profile, whose values
 * the decision depended on." The bound object "contains that reference, the
 * qualified Mission identity, operation and resolved target identities, the
 * normalized facts, and a secret salt with its version", committed with the
 * canonical-object digest of {{parameter-digest}}. The facts come from the
 * payments store, this resource's authoritative interface, never from an
 * agent argument: the agent names the invoice, and every fact is read from
 * the invoice and vendor records that name resolves to.
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

/** The records a fact or target is resolved from: this resource's own store. */
interface ResolutionSources {
  invoice: Invoice;
  vendor: Vendor;
  payments: PaymentsStore;
}

/**
 * The authoritative resolvers this resource implements, keyed by the
 * resolver a descriptor fact names, each with the granularity and
 * normalization it produces. A descriptor fact whose resolver, granularity or
 * normalization differs from these does not resolve, so a descriptor this
 * resource cannot honor is never captured under.
 */
export const PAYMENTS_FACT_RESOLVERS: Readonly<
  Record<
    string,
    {
      granularity: EvaluationContextGranularity;
      normalization: string;
      resolve: (s: ResolutionSources) => JsonValue | undefined;
    }
  >
> = Object.freeze({
  "payments-store:invoice.version": {
    granularity: "revision",
    normalization: "integer",
    resolve: ({ invoice }) => (Number.isSafeInteger(invoice.version) ? invoice.version : undefined),
  },
  "payments-store:invoice.vendor_id": {
    granularity: "effective_values",
    normalization: "string",
    resolve: ({ invoice }) => (typeof invoice.vendor_id === "string" && invoice.vendor_id.length > 0 ? invoice.vendor_id : undefined),
  },
  "payments-store:vendor.version": {
    granularity: "revision",
    normalization: "integer",
    resolve: ({ vendor }) => (Number.isSafeInteger(vendor.version) ? vendor.version : undefined),
  },
  "payments-store:invoice.amount": {
    granularity: "effective_values",
    normalization: "decimal-string-and-currency",
    resolve: ({ invoice }) =>
      typeof invoice.amount === "string" && typeof invoice.currency === "string"
        ? { amount: invoice.amount, currency: invoice.currency }
        : undefined,
  },
  "payments-store:invoice.payee_account": {
    granularity: "effective_values",
    normalization: "string",
    resolve: ({ invoice }) =>
      typeof invoice.payee_account === "string" && invoice.payee_account.length > 0 ? invoice.payee_account : undefined,
  },
  "payments-store:vendor.remittance_recipients": {
    granularity: "effective_values",
    normalization: "sorted-distinct-strings",
    // An enumerated target set: every final recipient, sorted and distinct,
    // the routed set or the vendor's default address alike.
    resolve: ({ vendor, payments }) => payments.remittanceRecipients(vendor.id)?.recipients,
  },
});

/** The target identities this resource resolves, by declared target type. */
const TARGET_RESOLVERS: Readonly<Record<string, (s: ResolutionSources) => string>> = Object.freeze({
  invoice: ({ invoice }) => invoice.id,
  vendor: ({ vendor }) => vendor.id,
});

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
 * Resolve the declared facts and targets for one invoice-scoped operation
 * from the store, under `descriptor`, and commit them with the reference,
 * the Mission, the operation and the salt. Every value comes from the store
 * records `invoiceId` resolves to; nothing comes from an agent argument.
 */
function commit(input: {
  descriptor: EvaluationContextDescriptor;
  reference: EvaluationContextBindingRef;
  mission: { issuer: string; id: string };
  operation: ContextOperation;
  invoiceId: string;
  payments: PaymentsStore;
  salt: string;
  saltVersion: string;
}): { ok: true; digest: string } | { ok: false; reason: ContextUnavailable } {
  const invoice = input.payments.getInvoice(input.invoiceId);
  const vendor = invoice ? input.payments.getVendor(invoice.vendor_id) : undefined;
  if (!invoice || !vendor) return { ok: false, reason: "target_unresolvable" };
  const sources: ResolutionSources = { invoice, vendor, payments: input.payments };
  const targets: Array<{ type: string; id: string }> = [];
  for (const type of input.descriptor.targets) {
    const resolve = TARGET_RESOLVERS[type];
    if (!resolve) return { ok: false, reason: "target_unresolvable" };
    targets.push({ type, id: resolve(sources) });
  }
  const facts: Record<string, JsonValue> = {};
  for (const fact of input.descriptor.facts) {
    const resolver = PAYMENTS_FACT_RESOLVERS[fact.resolver];
    if (!resolver || resolver.granularity !== fact.granularity || resolver.normalization !== fact.normalization) {
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
export function captureEvaluationContext(input: {
  declarations: EvaluationContextBindingDeclarations;
  salts: EvaluationContextSalts;
  mission: { issuer: string; id: string };
  operation: ContextOperation;
  invoiceId: string;
  payments: PaymentsStore;
}): ContextCapture {
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
    },
    declaredParameters: declaredParameterMembers(resolved.document),
  };
}

/**
 * @spec runtime#evaluation-context-binding: "The executing PEP MUST
 * re-resolve the declared facts and recompute the bound context with its own
 * applicable descriptor". The applicable descriptor is the one the live
 * declaration names for the held crossing now; it is never the held
 * reference reinterpreted. A crossing no longer covered, a descriptor that
 * does not resolve, a salt version this process no longer holds, and a fact
 * or target that does not resolve each leave the context unestablished: the
 * caller records no effective digest for it. A descriptor that changed
 * recomputes under the new reference, which the digest commits, so the
 * result differs from the held one without any fact having moved.
 */
export function recomputeEvaluationContext(input: {
  held: HeldEvaluationContext;
  declarations: EvaluationContextBindingDeclarations;
  salts: EvaluationContextSalts;
  invoiceId: string;
  payments: PaymentsStore;
}): { ok: true; digest: string } | { ok: false; reason: ContextUnavailable } {
  const entry = input.declarations.operation(input.held.operation.action, input.held.operation.phase);
  if (!entry) return { ok: false, reason: "not_covered" };
  const resolved = input.declarations.descriptor(entry.descriptor);
  if (!resolved.ok) return { ok: false, reason: "descriptor_unrecoverable" };
  // The salt version is the one the binding was made under. A version this
  // process does not hold is unrecoverable: no substitute salt is used.
  const salt = input.salts.saltFor(input.held.saltVersion, input.held.mission);
  if (salt === undefined) return { ok: false, reason: "salt_unavailable" };
  return commit({
    descriptor: resolved.document,
    reference: entry.descriptor,
    mission: input.held.mission,
    operation: input.held.operation,
    invoiceId: input.invoiceId,
    payments: input.payments,
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
