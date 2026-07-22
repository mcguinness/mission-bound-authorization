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

export interface EffectiveParams {
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

export function parameterDigest(params: EffectiveParams): string {
  const canonical = canonicalize(params as unknown as JsonValue);
  return `sha-256:${createHash("sha256").update(canonical, "utf8").digest("base64url")}`;
}
