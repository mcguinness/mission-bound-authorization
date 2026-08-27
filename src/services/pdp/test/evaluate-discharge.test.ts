/**
 * @spec draft-mcguinness-mission-runtime (#input-authority), discharge#runtime,
 * discharge#visibility
 *
 * The PDP's authority input EXCLUDES a discharged entry: an entry whose
 * `terminal_when` completion condition has fired is refused at the point of use
 * even while the Mission stays `active`, which is what closes the window
 * between the discharge commit and token expiry.
 *
 * Two decision paths are proven, because a deployment can materialize the
 * policy view either way:
 *  - the DELTA path: the view carries the approved set plus the discharged entry
 *    commitments, and the PDP denies `authority_discharged`, telling
 *    approved-then-done apart from never-approved (the containment precedent);
 *  - the EFFECTIVE-SET path: the view is materialized from the Mission's
 *    effective set (what Mission Status and the introspection projection
 *    publish, @spec discharge#visibility), so the entry is simply absent and the
 *    action denies as out of authority.
 *
 * No OpenFGA is needed: every assertion here is a deny reached before the FGA
 * authority check, so the connection is deliberately a stub and this file never
 * skips.
 */

import {
  AUTHORITY_ENTRY_TYP,
  computeAnchor,
  type JsonValue,
} from "@mission/core";
import { describe, expect, it } from "vitest";
import { evaluate, type EvaluationRequest } from "../src/evaluate.js";
import type { MissionView } from "../src/policy-view.js";
import { relationForAction, stalenessBoundSeconds } from "../src/policy.js";

const RESOURCE = "http://localhost:4403/mcp";
const ISSUER = "https://as.test";
const NOW = new Date("2026-08-20T12:00:00Z");
const CLOSE_EVENT = "accounting-period-closed";

/** The approved set: a live read entry and a write entry that completes on the close. */
const READ_ENTRY = {
  type: "mission_resource_access" as const,
  resource: RESOURCE,
  actions: ["payments:invoice.read"],
};
const WRITE_ENTRY = {
  type: "mission_resource_access" as const,
  resource: RESOURCE,
  actions: ["payments:payment.execute"],
  constraints: {
    max_amount: { amount: "500.00", currency: "USD" },
    vendors: ["acme"],
    terminal_when: [{ event_type: CLOSE_EVENT, discharge_policy: "close-management-2026-q3" }],
  },
};

const writeDigest = computeAnchor(AUTHORITY_ENTRY_TYP, ISSUER, WRITE_ENTRY as unknown as JsonValue);

const view = (over: Partial<MissionView> = {}): MissionView => ({
  id: "msn_discharge_1",
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:testhash",
  authority_set: [READ_ENTRY, WRITE_ENTRY],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
  ...over,
});

const req = (action: string): EvaluationRequest => ({
  subject: { id: "alice" },
  resource: { type: "invoice", id: "inv-1", properties: { vendor_id: "acme" } },
  action: { name: action },
  context: {
    audience: RESOURCE,
    mission: { id: "msn_discharge_1", issuer: "https://as.test", authority_hash: "sha-256:testhash" },
    amount: { amount: "125.00", currency: "USD" },
  },
});

const opts = (v: MissionView) => ({
  view: v,
  // Never reached: every decision here denies before the FGA authority check.
  fga: {} as never,
  modelId: "model-discharge-test",
  now: () => NOW,
  stalenessBoundSeconds,
  relationForAction,
});

describe("discharged entries are excluded from the PDP's authority input", () => {
  it("denies authority_discharged for the discharged entry while the Mission stays active", async () => {
    const v = view({ version: 2, discharged: { entry_digests: [writeDigest] } });
    const dec = await evaluate(req("payments:payment.execute"), opts(v));
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("authority_discharged");
    expect(dec.context.reason).toBe("authority_discharged");
    expect(dec.context.entry_digest).toBe(writeDigest);
    // A deny never carries conditions (the permit-only response contract).
    expect(dec.context.conditions).toBeUndefined();
  });

  it("tells approved-then-discharged apart from never-approved", async () => {
    const v = view({ version: 2, discharged: { entry_digests: [writeDigest] } });
    const never = await evaluate(req("payments:remittance.send"), opts(v));
    expect(never.decision).toBe(false);
    expect(never.context.denial_reason).toBe("out_of_authority");
  });

  it("leaves an undischarged entry of the same Mission alone", async () => {
    const v = view({ version: 2, discharged: { entry_digests: [writeDigest] } });
    // The read entry is not discharged, so it reaches the FGA check rather than
    // denying on the discharge overlay: the stub connection makes that visible
    // as a thrown call, never as a discharge denial.
    await expect(evaluate(req("payments:invoice.read"), opts(v))).rejects.toThrow();
  });

  it("denies out_of_authority when the view is materialized from the effective set", async () => {
    // @spec discharge#visibility — Mission Status and the introspection projection
    // OMIT a discharged entry, so a view built from what they publish simply
    // does not contain it.
    const effective = view({ version: 2, authority_set: [READ_ENTRY] });
    const dec = await evaluate(req("payments:payment.execute"), opts(effective));
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("out_of_authority");
  });
});
