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
  version INTEGER NOT NULL DEFAULT 1
) STRICT;
CREATE TABLE invoices (
  id TEXT PRIMARY KEY,
  vendor_id TEXT NOT NULL,
  amount TEXT NOT NULL,
  currency TEXT NOT NULL,
  payee_account TEXT NOT NULL,
  status TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1
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
  version: number;
}
export interface Invoice {
  id: string;
  vendor_id: string;
  amount: string;
  currency: string;
  payee_account: string;
  status: string;
  version: number;
}

export class PaymentsStore {
  readonly db: Database;
  constructor() {
    this.db = openStore(SCHEMA);
  }

  seed(vendors: Omit<Vendor, "version">[], invoices: Omit<Invoice, "version">[]): void {
    const v = this.db.prepare("INSERT INTO vendors (id, name, status) VALUES (?, ?, ?)");
    for (const x of vendors) v.run(x.id, x.name, x.status);
    const i = this.db.prepare(
      "INSERT INTO invoices (id, vendor_id, amount, currency, payee_account, status) VALUES (?, ?, ?, ?, ?, ?)",
    );
    for (const x of invoices) i.run(x.id, x.vendor_id, x.amount, x.currency, x.payee_account, x.status);
  }

  getInvoice(id: string): Invoice | undefined {
    return this.db.prepare("SELECT * FROM invoices WHERE id = ?").get(id) as Invoice | undefined;
  }
  getVendor(id: string): Vendor | undefined {
    return this.db.prepare("SELECT * FROM vendors WHERE id = ?").get(id) as Vendor | undefined;
  }
  listInvoices(vendorId?: string): Invoice[] {
    return (
      vendorId
        ? this.db.prepare("SELECT * FROM invoices WHERE vendor_id = ?").all(vendorId)
        : this.db.prepare("SELECT * FROM invoices").all()
    ) as Invoice[];
  }

  /** Mutate an invoice (test hook for TOCTOU: bumps version). */
  bumpInvoiceAmount(id: string, amount: string): void {
    this.db
      .prepare("UPDATE invoices SET amount = ?, version = version + 1 WHERE id = ?")
      .run(amount, id);
  }
}
