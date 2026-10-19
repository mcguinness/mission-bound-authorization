/**
 * @spec operation-profile-payments-v1 (D34): the payments service is
 * authoritative for business state. Invoices carry a version; the PEP loads
 * them for effective parameters and re-verifies at commit. Agent-supplied
 * values for authoritative fields are never trusted.
 */

import { openStore, type Database } from "@mission/store";

const SCHEMA = `
CREATE TABLE vendors (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  status TEXT NOT NULL,
  tenant TEXT,
  version INTEGER NOT NULL DEFAULT 1
) STRICT;
CREATE TABLE invoices (
  id TEXT PRIMARY KEY,
  vendor_id TEXT NOT NULL,
  amount TEXT NOT NULL,
  currency TEXT NOT NULL,
  payee_account TEXT NOT NULL,
  status TEXT NOT NULL,
  issued_at TEXT,
  version INTEGER NOT NULL DEFAULT 1
) STRICT;
CREATE TABLE vendor_remittance (
  vendor_id TEXT NOT NULL,
  address TEXT NOT NULL,
  PRIMARY KEY (vendor_id, address)
) STRICT;
CREATE TABLE mail_lists (
  address TEXT NOT NULL,
  member TEXT NOT NULL,
  PRIMARY KEY (address, member)
) STRICT;
CREATE TABLE ledger (
  op_key TEXT PRIMARY KEY,
  invoice_id TEXT NOT NULL,
  amount TEXT NOT NULL,
  currency TEXT NOT NULL,
  permit_id TEXT NOT NULL,
  posted_at INTEGER NOT NULL
) STRICT;
`;

export interface Vendor {
  id: string;
  name: string;
  status: string;
  /**
   * @spec resource-access#initial-common-constraints (#1266): the tenant that
   * owns this vendor and, through it, the vendor's invoices, as this service
   * recorded it. The authoritative fact the `tenant` bound reads; absent
   * (`null`) when the record names none, which satisfies no tenant bound.
   */
  tenant?: string | null;
  version: number;
}
export interface Invoice {
  id: string;
  vendor_id: string;
  amount: string;
  currency: string;
  payee_account: string;
  status: string;
  /**
   * @spec resource-access#initial-common-constraints (#1266): the RFC 3339
   * instant the invoice was issued, as this service recorded it. The
   * authoritative fact `resource_issued_after`/`resource_issued_before` read;
   * absent (`null`) when the record carries none, which satisfies neither.
   */
  issued_at?: string | null;
  version: number;
}

/** The address remittance advice goes to for a vendor whose record names no remittance routing. */
export function defaultRemittanceAddress(vendorId: string): string {
  return `${vendorId}@vendor.example`;
}

/** How deep distribution-list expansion may nest before resolution refuses. */
const MAX_LIST_DEPTH = 8;

/**
 * @spec resource-access#initial-common-constraints (#1266): every recipient
 * an operation reaches, resolved by this service from its own records.
 * `routed` is true when the vendor record names its remittance routing, so
 * the resolved set is not a function of the vendor id alone.
 */
export interface ResolvedRecipients {
  recipients: string[];
  routed: boolean;
}

export class PaymentsStore {
  readonly db: Database;
  constructor() {
    this.db = openStore(SCHEMA);
  }

  seed(vendors: Omit<Vendor, "version">[], invoices: Omit<Invoice, "version">[]): void {
    const v = this.db.prepare("INSERT INTO vendors (id, name, status, tenant) VALUES (?, ?, ?, ?)");
    for (const x of vendors) v.run(x.id, x.name, x.status, x.tenant ?? null);
    const i = this.db.prepare(
      "INSERT INTO invoices (id, vendor_id, amount, currency, payee_account, status, issued_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    );
    for (const x of invoices) {
      i.run(x.id, x.vendor_id, x.amount, x.currency, x.payee_account, x.status, x.issued_at ?? null);
    }
  }

  getInvoice(id: string): Invoice | undefined {
    return this.db.prepare("SELECT * FROM invoices WHERE id = ?").get(id) as Invoice | undefined;
  }
  getVendor(id: string): Vendor | undefined {
    return this.db.prepare("SELECT * FROM vendors WHERE id = ?").get(id) as Vendor | undefined;
  }
  /** The distinct vendors the store's invoices name, sorted: an unbounded `list_invoices` read's actual targets (#828). */
  invoiceVendorIds(): string[] {
    const rows = this.db.prepare("SELECT DISTINCT vendor_id FROM invoices ORDER BY vendor_id").all() as { vendor_id: string }[];
    return rows.map((r) => r.vendor_id);
  }
  listInvoices(vendorId?: string): Invoice[] {
    return (
      vendorId
        ? this.db.prepare("SELECT * FROM invoices WHERE vendor_id = ?").all(vendorId)
        : this.db.prepare("SELECT * FROM invoices").all()
    ) as Invoice[];
  }

  /** Name a vendor's remittance addresses (seeding: no version change). */
  seedRemittance(vendorId: string, addresses: readonly string[]): void {
    const r = this.db.prepare("INSERT INTO vendor_remittance (vendor_id, address) VALUES (?, ?)");
    for (const a of addresses) r.run(vendorId, a);
  }

  /** Define (or, with no members, clear) a distribution list's membership. */
  setMailList(address: string, members: readonly string[]): void {
    this.db.prepare("DELETE FROM mail_lists WHERE address = ?").run(address);
    const m = this.db.prepare("INSERT INTO mail_lists (address, member) VALUES (?, ?)");
    for (const x of members) m.run(address, x);
  }

  /** Replace a vendor's remittance addresses (a changed authoritative fact: bumps the vendor's version). */
  setVendorRemittance(vendorId: string, addresses: readonly string[]): void {
    this.db.prepare("DELETE FROM vendor_remittance WHERE vendor_id = ?").run(vendorId);
    this.seedRemittance(vendorId, addresses);
    this.db.prepare("UPDATE vendors SET version = version + 1 WHERE id = ?").run(vendorId);
  }

  /**
   * Every final recipient of a vendor's remittance advice: the vendor's
   * remittance addresses, each distribution list among them expanded to its
   * members, recursively, sorted and deduplicated. A vendor with no routing
   * goes to {@link defaultRemittanceAddress}. `undefined` when the vendor is
   * unknown or the routing cannot be resolved (a list that contains itself,
   * nesting past the depth bound, or no final recipient at all): an
   * unresolved recipient set is never guessed at.
   */
  remittanceRecipients(vendorId: string): ResolvedRecipients | undefined {
    if (!this.getVendor(vendorId)) return undefined;
    const addresses = (
      this.db.prepare("SELECT address FROM vendor_remittance WHERE vendor_id = ? ORDER BY address").all(vendorId) as {
        address: string;
      }[]
    ).map((r) => r.address);
    if (addresses.length === 0) return { recipients: [defaultRemittanceAddress(vendorId)], routed: false };
    const members = this.db.prepare("SELECT member FROM mail_lists WHERE address = ? ORDER BY member");
    const out = new Set<string>();
    const expand = (address: string, path: readonly string[]): boolean => {
      const listed = (members.all(address) as { member: string }[]).map((r) => r.member);
      if (listed.length === 0) {
        out.add(address);
        return true;
      }
      if (path.includes(address) || path.length >= MAX_LIST_DEPTH) return false;
      return listed.every((m) => expand(m, [...path, address]));
    };
    if (!addresses.every((a) => expand(a, []))) return undefined;
    if (out.size === 0) return undefined;
    return { recipients: [...out].sort(), routed: true };
  }

  /** Change an invoice's recorded issuance instant (test hook for a changed authoritative fact: bumps version). */
  setInvoiceIssuedAt(id: string, issuedAt: string | null): void {
    this.db.prepare("UPDATE invoices SET issued_at = ?, version = version + 1 WHERE id = ?").run(issuedAt, id);
  }

  /** Change the tenant a vendor's record names (test hook for a changed authoritative fact: bumps version). */
  setVendorTenant(id: string, tenant: string | null): void {
    this.db.prepare("UPDATE vendors SET tenant = ?, version = version + 1 WHERE id = ?").run(tenant, id);
  }

  /** Mutate an invoice (test hook for TOCTOU: bumps version). */
  bumpInvoiceAmount(id: string, amount: string): void {
    this.db
      .prepare("UPDATE invoices SET amount = ?, version = version + 1 WHERE id = ?")
      .run(amount, id);
  }
}
