/**
 * M3 golden-file decision tests against a live OpenFGA (docker compose).
 * Exit criterion: in-authority allow, out-of-authority deny, revoked-mission
 * deny within bound. Skipped automatically when OpenFGA is unreachable.
 */

import { beforeAll, describe, expect, it } from "vitest";
import { Fga } from "../src/fga.js";
import { evaluate, type EvaluationRequest } from "../src/evaluate.js";
import type { MissionView } from "../src/policy-view.js";
import { relationForAction, stalenessBoundSeconds } from "../src/policy.js";

const API_URL = process.env.OPENFGA_HTTP_URL ?? "https://localhost:8080";
const KEY = process.env.OPENFGA_PRESHARED_KEY ?? "dev-preshared-key-change-me";
const CA = process.env.OPENFGA_CA_CERT; // dev CA path (channel matrix)
const RESOURCE = "http://localhost:4403/mcp";

async function reachable(): Promise<boolean> {
  try {
    if (CA) process.env.NODE_EXTRA_CA_CERTS = CA;
    const res = await fetch(`${API_URL}/healthz`, { headers: { authorization: `Bearer ${KEY}` } });
    return res.ok;
  } catch {
    return false;
  }
}

const up = await reachable();
const d = up ? describe : describe.skip;
if (!up) console.warn("OpenFGA unreachable; skipping M3 decision tests (docker compose up)");

let fga: Fga;
let modelId: string;
const NOW = new Date("2026-07-22T12:00:00Z");

const view = (over: Partial<MissionView> = {}): MissionView => ({
  id: "msn_test_1",
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: "sha-256:testhash",
  authority_set: [
    {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: ["payments:invoice.read", "payments:payment.execute"],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    },
  ],
  ...over,
});

const req = (over: Partial<EvaluationRequest> = {}): EvaluationRequest => ({
  subject: { id: "alice" },
  resource: { type: "invoice", id: "inv-1", properties: { vendor_id: "acme" } },
  action: { name: "payments:invoice.read" },
  context: {
    audience: RESOURCE,
    mission: { id: "msn_test_1", authority_hash: "sha-256:testhash" },
  },
  ...over,
});

const opts = (v: MissionView) => ({
  view: v,
  fga,
  modelId,
  now: () => NOW,
  stalenessBoundSeconds,
  relationForAction,
});

d("PDP decisions against OpenFGA (@spec authzen)", () => {
  beforeAll(async () => {
    const conn = await Fga.connect({ apiUrl: API_URL, presharedKey: KEY, caCertPath: CA });
    fga = conn.fga;
    modelId = conn.modelId;
  });

  it("in-authority read -> permit", async () => {
    const dec = await evaluate(req(), opts(view()));
    expect(dec.decision, JSON.stringify(dec.context)).toBe(true);
    expect(dec.context.policy_view_id).toMatch(/^sha-256:/);
    expect(dec.context.decision_id).toBeDefined();
  });

  it("in-authority execute under the cap -> permit with single_use for irreversible", async () => {
    const dec = await evaluate(
      req({
        action: { name: "payments:payment.execute" },
        context: {
          audience: RESOURCE,
          mission: { id: "msn_test_1", authority_hash: "sha-256:testhash" },
          amount: { amount: "125.00", currency: "USD" },
          action_class: "irreversible_action",
          parameter_digest: "sha-256:pd",
        },
      }),
      opts(view()),
    );
    expect(dec.decision, JSON.stringify(dec.context)).toBe(true);
    expect(dec.context.single_use).toBe(true);
    expect(dec.context.parameter_digest).toBe("sha-256:pd");
  });

  it("out-of-authority action -> deny out_of_authority", async () => {
    const dec = await evaluate(req({ action: { name: "payments:remittance.send" } }), opts(view()));
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("out_of_authority");
  });

  it("vendor outside the constraint -> deny out_of_authority (contextual tuple withheld)", async () => {
    const dec = await evaluate(
      req({ resource: { type: "invoice", id: "inv-3", properties: { vendor_id: "globex" } } }),
      opts(view()),
    );
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("out_of_authority");
  });

  it("over-cap execute -> deny constraint_exceeded", async () => {
    const dec = await evaluate(
      req({
        action: { name: "payments:payment.execute" },
        context: {
          audience: RESOURCE,
          mission: { id: "msn_test_1", authority_hash: "sha-256:testhash" },
          amount: { amount: "900.00", currency: "USD" },
        },
      }),
      opts(view()),
    );
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("constraint_exceeded");
  });

  it("revoked mission -> deny mission_inactive within the bound", async () => {
    const dec = await evaluate(req(), opts(view({ state: "revoked" })));
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("mission_inactive");
  });

  it("stale freshness beyond the bound -> deny stale_state", async () => {
    const dec = await evaluate(
      req({
        action: { name: "payments:payment.execute" },
        context: {
          audience: RESOURCE,
          mission: { id: "msn_test_1", authority_hash: "sha-256:testhash" },
          amount: { amount: "100.00", currency: "USD" },
          action_class: "irreversible_action",
          freshness: { observed_at: "2026-07-22T11:58:00Z", source: "status" }, // 120s > 30s bound
        },
      }),
      opts(view()),
    );
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("stale_state");
  });

  it("view inconsistency (authority_hash mismatch) -> deny view_inconsistent", async () => {
    const dec = await evaluate(
      req({ context: { audience: RESOURCE, mission: { id: "msn_test_1", authority_hash: "sha-256:WRONG" } } }),
      opts(view()),
    );
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("view_inconsistent");
  });

  it("wrong audience -> deny out_of_authority (entry matched on context.audience)", async () => {
    const dec = await evaluate(
      req({ context: { audience: "http://other/mcp", mission: { id: "msn_test_1", authority_hash: "sha-256:testhash" } } }),
      opts(view()),
    );
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("out_of_authority");
  });
});
