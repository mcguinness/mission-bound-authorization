/**
 * @spec operation-profile-payments-v1 (effective parameters + parameter digest)
 *
 * Effective parameters merge caller-supplied fields (normalized) with the
 * authoritative fields loaded from the payments store and the record
 * versions. parameter_digest binds decision to execution (D34/D36).
 */

import { createHash } from "node:crypto";
import { canonicalize, type JsonValue } from "@mission/core";
import type { Invoice, Vendor } from "./payments-store.js";
import type { CapabilitySnapshot } from "./tool-catalog.js";

export interface EffectiveParams {
  /** Local invocation guard, separate from the operation's parameter normal form. */
  capability_snapshot?: CapabilitySnapshot;
  action: string;
  invoice_id: string;
  invoice_version: number;
  vendor_id: string;
  vendor_version: number;
  amount: { amount: string; currency: string };
  payee_account: string;
  resource: string;
}

export function buildEffectiveParams(input: {
  action: string;
  invoice: Invoice;
  vendor: Vendor;
  resource: string;
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
  };
}

/**
 * @spec runtime#read-binding: the normalized parameter form for a bound
 * LIST read (`list_invoices`): distinct from {@link EffectiveParams}
 * (invoice-shaped writes/reads), since a bulk read has no single invoice to
 * bind. `vendor_scope_source` is the canonical normal form's discriminator,
 * carried alongside `vendor_scope` so the digest never collapses two
 * different authorization postures that happen to enumerate the same vendor
 * ids: a caller-supplied `vendor_id` (`"requested"`), the matched entry's own
 * `constraints.vendors` allowlist (`"entry"`), and the explicit, deliberate
 * marker for an unconstrained entry (`"all"`) are three distinct normal
 * forms, never one collapsed case. `vendor_scope` is the sorted, deduped
 * vendor id set for the first two sources and empty for `"all"` (the
 * source discriminator alone carries that case's meaning, mirroring
 * `UNSCOPED_VENDOR_OBJECT`'s role as an explicit sentinel in pep.ts).
 */
export interface ListEffectiveParams {
  capability_snapshot?: CapabilitySnapshot;
  action: string;
  resource: string;
  vendor_scope: string[];
  vendor_scope_source: "requested" | "entry" | "all";
}

export function buildListEffectiveParams(input: {
  action: string;
  resource: string;
  vendor_scope: string[];
  vendor_scope_source: "requested" | "entry" | "all";
}): ListEffectiveParams {
  return {
    action: input.action,
    resource: input.resource,
    vendor_scope: input.vendor_scope,
    vendor_scope_source: input.vendor_scope_source,
  };
}

export function parameterDigest(params: EffectiveParams | ListEffectiveParams): string {
  const { capability_snapshot: _localInvocationGuard, ...parameters } = params;
  const canonical = canonicalize(parameters as unknown as JsonValue);
  return `sha-256:${createHash("sha256").update(canonical, "utf8").digest("base64url")}`;
}
