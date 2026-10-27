/**
 * @spec operation-profile-payments-v1 (effective parameters + parameter digest)
 *
 * Effective parameters merge caller-supplied fields (normalized) with the
 * authoritative fields loaded from the payments store and the record
 * versions. parameter_digest binds decision to execution (D34/D36).
 */

import { createHash } from "node:crypto";
import { canonicalize, type CollectionMemberFacts, type JsonValue } from "@mission/core";
import type { Invoice, PaymentsStore, Vendor } from "./payments-store.js";
import type { CapabilitySnapshot } from "./tool-catalog.js";

export interface EffectiveParams {
  /** Local invocation guard, separate from the operation's parameter normal form. */
  capability_snapshot?: CapabilitySnapshot;
  action: string;
  invoice_id: string;
  /** The invoice record's version; absent on a reversal's form ({@link buildReversalParams}). */
  invoice_version?: number;
  vendor_id: string;
  /** The vendor record's version; absent on a reversal's form. */
  vendor_version?: number;
  amount: { amount: string; currency: string };
  payee_account: string;
  resource: string;
  /**
   * @spec runtime#compound-actions (#252): present exactly on a compensate
   * crossing's form: the operation key of the committed wire it offsets.
   */
  reverses?: string;
  /**
   * @spec resource-access#initial-common-constraints (#1266): every final
   * recipient the operation reaches, present only where the vendor record
   * names its own remittance routing, so the digest binds a set that is not
   * a function of `vendor_id` alone. A routing change between decision and
   * execution then refuses `parameter_mismatch`.
   */
  recipients?: string[];
}

export function buildEffectiveParams(input: {
  action: string;
  invoice: Invoice;
  vendor: Vendor;
  resource: string;
  recipients?: readonly string[];
}): EffectiveParams {
  const { action, invoice, vendor, resource } = input;
  return {
    action,
    invoice_id: invoice.id,
    invoice_version: invoice.version,
    vendor_id: vendor.id,
    vendor_version: vendor.version,
    amount: { amount: invoice.amount, currency: invoice.currency },
    payee_account: invoice.payee_account,
    resource,
    ...(input.recipients !== undefined ? { recipients: [...input.recipients] } : {}),
  };
}

/**
 * @spec runtime#compound-actions (#252): the normal form a compensate
 * crossing binds. Its effect parameters are the committed wire's, from that
 * wire's own ledger record, never the invoice as it reads now and never an
 * argument: the invoice and vendor the wire paid, its amount and currency,
 * its payee, the operation target, and the operation key of the wire it
 * offsets. `parameter_digest` over this form is what the compensating
 * Decision evaluates and binds, so a constraint such as a reversal ceiling is
 * evaluated against what will actually be offset.
 */
export function buildReversalParams(input: {
  action: string;
  wire: { invoiceId: string; vendorId: string; payeeAccount: string; amount: string; currency: string };
  resource: string;
  reverses: string;
}): EffectiveParams {
  const { action, wire, resource, reverses } = input;
  return {
    action,
    invoice_id: wire.invoiceId,
    vendor_id: wire.vendorId,
    amount: { amount: wire.amount, currency: wire.currency },
    payee_account: wire.payeeAccount,
    resource,
    reverses,
  };
}

/**
 * @spec runtime#read-binding: the normalized parameter form for a bound
 * LIST read (`list_invoices`): distinct from {@link EffectiveParams}
 * (invoice-shaped writes/reads), since a bulk read has no single invoice to
 * bind. `vendor_scope_source` is the canonical normal form's discriminator,
 * carried alongside `vendor_scope` so the digest never collapses two
 * different authorization postures that happen to enumerate the same vendor
 * ids: a caller-supplied `vendor_id` resolved by the store (`"requested"`),
 * the matched entry's own `constraints.vendors` allowlist (`"entry"`), and
 * an unconstrained entry (`"all"`) are three distinct normal forms, never one
 * collapsed case. `vendor_scope` is the sorted, deduped vendor id set: for
 * `"all"`, every vendor the payments store holds invoices for when the
 * scope is derived (#828 step 5), so the digest binds the read's actual
 * targets and a change to them between decision and execution is a
 * mismatch.
 */
export interface ListEffectiveParams {
  capability_snapshot?: CapabilitySnapshot;
  action: string;
  resource: string;
  vendor_scope: string[];
  vendor_scope_source: "requested" | "entry" | "all";
  /**
   * @spec resource-access#initial-common-constraints (#1266): present only
   * when an entry the read could rely on carries a bound that reads a member
   * fact (issuance, tenant, classification). Every invoice the read returns,
   * sorted by `id`, with the facts its records hold, so the digest binds them
   * and a changed, added or removed member is a mismatch before release.
   */
  members?: CollectionMemberFacts[];
}

export function buildListEffectiveParams(input: {
  action: string;
  resource: string;
  vendor_scope: string[];
  vendor_scope_source: "requested" | "entry" | "all";
  members?: CollectionMemberFacts[];
}): ListEffectiveParams {
  return {
    action: input.action,
    resource: input.resource,
    vendor_scope: input.vendor_scope,
    vendor_scope_source: input.vendor_scope_source,
    ...(input.members !== undefined ? { members: input.members } : {}),
  };
}

/**
 * @spec resource-access#initial-common-constraints (#1266): the members of a
 * bound `list_invoices` read, from the payments store: every invoice the read
 * returns (the requested vendor's, or every vendor's, within `vendorScope`),
 * each with its own record's issuance instant and classification label and
 * its vendor's tenant, where the records hold them, sorted by `id`. The same
 * filter execution applies, so the members are the result.
 */
export function listMembers(
  store: Pick<PaymentsStore, "listInvoices" | "getVendor">,
  vendorScope: readonly string[],
  requestedVendorId: string | undefined,
): CollectionMemberFacts[] {
  return store
    .listInvoices(requestedVendorId)
    .filter((invoice) => vendorScope.includes(invoice.vendor_id))
    .map((invoice) => {
      const tenant = store.getVendor(invoice.vendor_id)?.tenant;
      return {
        id: invoice.id,
        ...(typeof invoice.issued_at === "string" ? { issued_at: invoice.issued_at } : {}),
        ...(typeof tenant === "string" ? { tenant } : {}),
        ...(typeof invoice.classification === "string" ? { data_classification: invoice.classification } : {}),
      };
    })
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

/**
 * @spec authzen#parameter-digest `parameters` (#813): the normalized parameter
 * object, exactly what {@link parameterDigest} is computed over: the effective
 * parameters without the local invocation guard. A decision request that
 * carries it lets the PDP recompute the digest and read a raw value.
 */
export function normalizedParameters<T extends EffectiveParams | ListEffectiveParams>(
  params: T,
): Omit<T, "capability_snapshot"> {
  const { capability_snapshot: _localInvocationGuard, ...parameters } = params;
  return parameters;
}

export function parameterDigest(params: EffectiveParams | ListEffectiveParams): string {
  const canonical = canonicalize(normalizedParameters(params) as unknown as JsonValue);
  return `sha-256:${createHash("sha256").update(canonical, "utf8").digest("base64url")}`;
}
