/**
 * @spec runtime#input-authority, runtime-oauth#authorization-details-mapping
 * (#825) — the credential authority bound, read and evaluated on its own.
 */

import { describe, expect, it } from "vitest";
import {
  CredentialAuthorityError,
  type CredentialTarget,
  coveringCredentialEntry,
  credentialAuthorityPermits,
  credentialEntriesFromAatTools,
  parseCredentialAuthority,
} from "../src/index.js";

const R = "https://payments.example/mcp";
const entry = (over: Record<string, unknown> = {}) => ({
  type: "mission_resource_access",
  resource: R,
  actions: ["payments:invoice.read"],
  ...over,
});
const target = (over: Partial<CredentialTarget> = {}): CredentialTarget => ({
  resource: R,
  action: "payments:invoice.read",
  vendorIds: ["acme"],
  ...over,
});

describe("parseCredentialAuthority: a credential's authority is read in full or refused (#825)", () => {
  it("reads mission_resource_access entries, ignoring only the grant and catalog-binding members", () => {
    const parsed = parseCredentialAuthority([
      entry({
        constraints: { vendors: ["acme"], max_amount: { amount: "100.00", currency: "USD" } },
        delegation: { max_depth: 1 },
        capability_sources: [],
      }),
    ]);
    expect(parsed).toEqual([
      {
        type: "mission_resource_access",
        resource: R,
        actions: ["payments:invoice.read"],
        constraints: { vendors: ["acme"], max_amount: { amount: "100.00", currency: "USD" } },
      },
    ]);
    expect(Object.isFrozen(parsed)).toBe(true);
  });

  it.each([
    ["absent", undefined],
    ["not an array", { type: "mission_resource_access" }],
    ["an unknown entry type", [entry({ type: "other_detail" })]],
    ["an unknown entry member", [entry({ locations: [R] })]],
    ["an empty resource", [entry({ resource: "" })]],
    ["no actions", [entry({ actions: [] })]],
    ["a non-string action", [entry({ actions: [1] })]],
    ["an unknown constraint", [entry({ constraints: { time_window: "business-hours" } })]],
    [
      "a non-decimal amount cap",
      [entry({ constraints: { max_amount: { amount: "1e3", currency: "USD" } } })],
    ],
    ["an amount cap without currency", [entry({ constraints: { max_amount: { amount: "10" } } })]],
    ["a malformed vendor list", [entry({ constraints: { vendors: "acme" } })]],
    ["a non-boolean approval flag", [entry({ constraints: { requires_action_approval: "yes" } })]],
    ["a malformed discharge condition", [entry({ constraints: { terminal_when: [{}] } })]],
  ])("refuses %s", (_label, value) => {
    expect(() => parseCredentialAuthority(value)).toThrow(CredentialAuthorityError);
  });
});

describe("credentialEntriesFromAatTools: attenuation tools keep every restriction (#825)", () => {
  it("maps each tool to one entry with its vendor and amount bounds", () => {
    expect(
      credentialEntriesFromAatTools({
        [`${R}#payments:invoice.read`]: {
          vendor: { constraint_type: "enum", values: ["acme"] },
          amount_usd: { constraint_type: "range", max: 200 },
        },
      }),
    ).toEqual([
      {
        type: "mission_resource_access",
        resource: R,
        actions: ["payments:invoice.read"],
        constraints: { vendors: ["acme"], max_amount: { amount: "200", currency: "USD" } },
      },
    ]);
  });

  it.each([
    ["a range lower bound", { amount_usd: { constraint_type: "range", max: 200, min: 10 } }],
    ["an exact constraint", { amount_usd: { constraint_type: "exact", value: 5 } }],
    ["an unknown argument", { region: { constraint_type: "enum", values: ["eu"] } }],
    ["a vendor bound that is not an enum", { vendor: { constraint_type: "exact", value: "acme" } }],
  ])("refuses %s rather than dropping it", (_label, args) => {
    expect(() =>
      credentialEntriesFromAatTools({ [`${R}#payments:invoice.read`]: args as never }),
    ).toThrow(CredentialAuthorityError);
  });
});

describe("credentialAuthorityPermits: one whole entry must cover the action (#825)", () => {
  it("permits an action an entry covers and refuses an action outside every entry", () => {
    const auth = parseCredentialAuthority([entry()]);
    expect(credentialAuthorityPermits(auth, target())).toBe(true);
    expect(credentialAuthorityPermits(auth, target({ action: "payments:vendor.read" }))).toBe(
      false,
    );
    expect(
      credentialAuthorityPermits(auth, target({ resource: "https://other.example/mcp" })),
    ).toBe(false);
    expect(credentialAuthorityPermits([], target())).toBe(false);
  });

  it("requires every target vendor to be listed, and a vendor-bound entry to have one", () => {
    const auth = parseCredentialAuthority([entry({ constraints: { vendors: ["acme"] } })]);
    expect(credentialAuthorityPermits(auth, target({ vendorIds: ["acme"] }))).toBe(true);
    expect(credentialAuthorityPermits(auth, target({ vendorIds: ["globex"] }))).toBe(false);
    expect(credentialAuthorityPermits(auth, target({ vendorIds: ["acme", "globex"] }))).toBe(false);
    expect(credentialAuthorityPermits(auth, target({ vendorIds: [] }))).toBe(false);
  });

  it("compares the amount as an exact decimal in the cap's own currency", () => {
    const auth = parseCredentialAuthority([
      entry({ constraints: { max_amount: { amount: "100.00", currency: "USD" } } }),
    ]);
    expect(
      credentialAuthorityPermits(auth, target({ amount: { amount: "100", currency: "USD" } })),
    ).toBe(true);
    expect(
      credentialAuthorityPermits(auth, target({ amount: { amount: "100.01", currency: "USD" } })),
    ).toBe(false);
    expect(
      credentialAuthorityPermits(auth, target({ amount: { amount: "50", currency: "EUR" } })),
    ).toBe(false);
    expect(credentialAuthorityPermits(auth, target())).toBe(false);
  });

  it("never combines an action from one entry with a constraint satisfied by another", () => {
    const auth = parseCredentialAuthority([
      entry({ actions: ["payments:invoice.read"], constraints: { vendors: ["globex"] } }),
      entry({ actions: ["payments:vendor.read"], constraints: { vendors: ["acme"] } }),
    ]);
    expect(
      credentialAuthorityPermits(
        auth,
        target({ action: "payments:invoice.read", vendorIds: ["acme"] }),
      ),
    ).toBe(false);
  });

  it("leaves an approval requirement and a discharge condition to the PDP, still bounded by the entry's other constraints", () => {
    // Both are evaluated where approval and Mission state are held
    // (@spec authzen#context-credential): coverage is resource, action,
    // vendor and amount.
    const approval = parseCredentialAuthority([
      entry({ constraints: { requires_action_approval: true, vendors: ["acme"] } }),
    ]);
    expect(coveringCredentialEntry(approval, target())).toBe(approval[0]);
    expect(credentialAuthorityPermits(approval, target({ vendorIds: ["globex"] }))).toBe(false);
    const discharge = parseCredentialAuthority([
      entry({ constraints: { terminal_when: [{ event_type: "invoice.paid" }] } }),
    ]);
    expect(credentialAuthorityPermits(discharge, target())).toBe(true);
    expect(credentialAuthorityPermits(discharge, target({ action: "payments:vendor.read" }))).toBe(
      false,
    );
  });

  it("prefers a covering entry that requires no approval, so approval is demanded only when every covering entry does", () => {
    const gated = entry({ constraints: { requires_action_approval: true } });
    const open = entry({ constraints: { vendors: ["acme"] } });
    const both = parseCredentialAuthority([gated, open]);
    expect(coveringCredentialEntry(both, target())).toBe(both[1]);
    // `open` does not cover globex, so only the gated entry does.
    expect(coveringCredentialEntry(both, target({ vendorIds: ["globex"] }))).toBe(both[0]);
    expect(
      coveringCredentialEntry(both, target({ action: "payments:vendor.read" })),
    ).toBeUndefined();
  });
});
