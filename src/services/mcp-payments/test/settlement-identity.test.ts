/**
 * @spec runtime#security-considerations (#1270) — an operation key names one
 * request, not the business event it carries out. The ledger connector is the
 * resource of record for wires, and the invoice is a wire's settlement
 * identity: it settles each invoice at most once, whatever operation key a
 * later wire arrives under, and refuses that wire with no effect.
 */

import { describe, expect, it } from "vitest";
import { Connectors } from "../src/index.js";

const wire = (opKey: string, missionId: string, invoiceId = "inv-1") => ({
  opKey,
  invoiceId,
  payeeAccount: "acct-acme",
  amount: "125.00",
  currency: "USD",
  permitId: `permit-${opKey}`,
  missionId,
});

describe("settlement identity (@spec runtime#security-considerations, operation-profile-payments-v1)", () => {
  it("refuses a second wire for a settled invoice under another operation key and Mission, with no effect", () => {
    const connectors = new Connectors();
    expect(connectors.postWire(wire("op:msn_a:pay:d1", "msn_a"))).toEqual({ committed: true, deduped: false });
    expect(connectors.settled("inv-1")).toBe(true);

    const second = connectors.postWire(wire("op:msn_b:pay:d2", "msn_b"));
    expect(second).toEqual({ committed: false, deduped: false, refusal: "already_settled" });
    expect(connectors.ledgerEntries()).toHaveLength(1);
    expect(connectors.ledgerEntries()[0]?.mission_id).toBe("msn_a");
    expect(connectors.committedFor("permit-op:msn_b:pay:d2")).toBeUndefined();
  });

  it("dedupes a retry under the same operation key instead of refusing it", () => {
    const connectors = new Connectors();
    connectors.postWire(wire("op:msn_a:pay:d1", "msn_a"));
    expect(connectors.postWire(wire("op:msn_a:pay:d1", "msn_a"))).toEqual({ committed: true, deduped: true });
    expect(connectors.ledgerEntries()).toHaveLength(1);
  });

  it("settles each invoice independently", () => {
    const connectors = new Connectors();
    expect(connectors.postWire(wire("op:msn_a:pay:d1", "msn_a", "inv-1")).committed).toBe(true);
    expect(connectors.settled("inv-2")).toBe(false);
    expect(connectors.postWire(wire("op:msn_a:pay:d2", "msn_a", "inv-2")).committed).toBe(true);
    expect(connectors.ledgerEntries()).toHaveLength(2);
  });
});
