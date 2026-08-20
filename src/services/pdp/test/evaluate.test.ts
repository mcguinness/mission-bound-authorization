/**
 * M3 golden-file decision tests against a live OpenFGA (docker compose).
 * Exit criterion: in-authority allow, out-of-authority deny, revoked-mission
 * deny within bound. Skipped automatically when OpenFGA is unreachable.
 */

import { AUTHORITY_ENTRY_TYP, computeAnchor } from "@mission/core";
import { generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { Fga } from "../src/fga.js";
import { evaluate, type EvaluationRequest } from "../src/evaluate.js";
import { type MissionView, policyViewId } from "../src/policy-view.js";
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

  it("a permit's context carries the entry_digest resolved-scope anchor", async () => {
    const v = view();
    const dec = await evaluate(req(), opts(v));
    expect(dec.decision, JSON.stringify(dec.context)).toBe(true);
    // Recomputes over the Authority Set entry the PDP matched, issuer-bound.
    expect(dec.context.entry_digest).toBe(
      computeAnchor(AUTHORITY_ENTRY_TYP, v.issuer, v.authority_set[0] as never),
    );
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
          freshness: { observed_at: NOW.toISOString(), source: "status" },
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

  it("contained action -> deny authority_contained; never-granted action stays out_of_authority", async () => {
    // Same resource: payment.execute was approved then contained (delta), while
    // remittance.send was never approved. The PDP must tell them apart.
    const v = view({
      version: 2,
      containment: { version: 1, contained: [{ resource: RESOURCE, actions: ["payments:payment.execute"] }] },
    });
    const contained = await evaluate(
      req({
        action: { name: "payments:payment.execute" },
        context: {
          audience: RESOURCE,
          mission: { id: "msn_test_1", authority_hash: "sha-256:testhash" },
          amount: { amount: "125.00", currency: "USD" },
        },
      }),
      opts(v),
    );
    expect(contained.decision).toBe(false);
    expect(contained.context.denial_reason).toBe("authority_contained");
    expect(contained.context.containment_version).toBe(1);

    const neverGranted = await evaluate(req({ action: { name: "payments:remittance.send" } }), opts(v));
    expect(neverGranted.decision).toBe(false);
    expect(neverGranted.context.denial_reason).toBe("out_of_authority");
  });

  it("entry-level containment (no actions member) denies ALL the entry's actions", async () => {
    const v = view({ version: 2, containment: { version: 1, contained: [{ resource: RESOURCE }] } });
    for (const name of ["payments:invoice.read", "payments:payment.execute"]) {
      const dec = await evaluate(req({ action: { name } }), opts(v));
      expect(dec.decision, name).toBe(false);
      expect(dec.context.denial_reason, name).toBe("authority_contained");
    }
  });

  it("a permit on an uncontained action still carries entry_digest", async () => {
    const v = view({
      version: 2,
      containment: { version: 1, contained: [{ resource: RESOURCE, actions: ["payments:payment.execute"] }] },
    });
    const dec = await evaluate(req(), opts(v)); // invoice.read is uncontained
    expect(dec.decision, JSON.stringify(dec.context)).toBe(true);
    expect(dec.context.entry_digest).toBe(
      computeAnchor(AUTHORITY_ENTRY_TYP, v.issuer, v.authority_set[0] as never),
    );
  });

  it("a request pinning a pre-containment policy_view_id denies view_inconsistent after contain", async () => {
    // policyViewId commits mission_version, which contain() bumps: prove it moves.
    const before = view();
    const after = view({
      version: 2,
      containment: { version: 1, contained: [{ resource: RESOURCE, actions: ["payments:payment.execute"] }] },
    });
    const stalePvid = policyViewId(before, modelId);
    expect(policyViewId(after, modelId)).not.toBe(stalePvid);
    const dec = await evaluate(
      req({
        context: {
          audience: RESOURCE,
          mission: { id: "msn_test_1", authority_hash: "sha-256:testhash", policy_view_id: stalePvid },
        },
      }),
      opts(after),
    );
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("view_inconsistent");
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

  // --- ARAP: requestable-denial expires_at + approved_until honoring ---

  it("requestable action_approval_required denial carries access_request.expires_at (ARAP)", async () => {
    const pdpKey = (await generateKeyPair("ES256", { extractable: true })).privateKey;
    const dec = await evaluate(
      req({
        action: { name: "payments:payment.execute" },
        context: {
          audience: RESOURCE,
          mission: { id: "msn_test_1", authority_hash: "sha-256:testhash" },
          amount: { amount: "125.00", currency: "USD" },
          action_class: "irreversible_action",
          parameter_digest: "sha-256:pd",
          freshness: { observed_at: NOW.toISOString(), source: "status" },
        },
      }),
      {
        ...opts(view()),
        requiresActionApproval: () => true,
        maxApprovalAgeSeconds: 300,
        requestable: { sign: pdpKey, kid: "pdp-denial", endpoint: "https://ars.test/access-requests" },
      },
    );
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("action_approval_required");
    const ar = dec.context.access_request as { binding_token: string; expires_at: string };
    expect(ar.binding_token).toBeDefined();
    // RFC 3339 timestamp, bounded to the denial binding's validity (now + 300s).
    expect(ar.expires_at).toBeDefined();
    expect(Number.isNaN(Date.parse(ar.expires_at))).toBe(false);
    expect(Date.parse(ar.expires_at)).toBe(NOW.getTime() + 300_000);
  });

  it("an approval past approved_until -> deny action_approval_required (ARAP)", async () => {
    const dec = await evaluate(
      req({
        action: { name: "payments:payment.execute" },
        context: {
          audience: RESOURCE,
          mission: { id: "msn_test_1", authority_hash: "sha-256:testhash" },
          amount: { amount: "125.00", currency: "USD" },
          action_class: "irreversible_action",
          parameter_digest: "sha-256:pd",
          freshness: { observed_at: NOW.toISOString(), source: "status" },
          action_approval: {
            id: "apr_expired",
            approved_at: NOW.toISOString(), // fresh (within max age)
            approved_until: new Date(NOW.getTime() - 1000).toISOString(), // already past
            parameter_digest: "sha-256:pd",
          },
        },
      }),
      { ...opts(view()), requiresActionApproval: () => true, maxApprovalAgeSeconds: 300 },
    );
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("action_approval_required");
  });

  it("an approval within approved_until -> permit (ARAP positive control)", async () => {
    const dec = await evaluate(
      req({
        action: { name: "payments:payment.execute" },
        context: {
          audience: RESOURCE,
          mission: { id: "msn_test_1", authority_hash: "sha-256:testhash" },
          amount: { amount: "125.00", currency: "USD" },
          action_class: "irreversible_action",
          parameter_digest: "sha-256:pd",
          freshness: { observed_at: NOW.toISOString(), source: "status" },
          action_approval: {
            id: "apr_ok",
            approved_at: NOW.toISOString(),
            approved_until: new Date(NOW.getTime() + 60_000).toISOString(),
            parameter_digest: "sha-256:pd",
          },
        },
      }),
      { ...opts(view()), requiresActionApproval: () => true, maxApprovalAgeSeconds: 300 },
    );
    expect(dec.decision, JSON.stringify(dec.context)).toBe(true);
  });
});

d("entry-driven action approval (@spec txn-authorization#applicability)", () => {
  beforeAll(async () => {
    const conn = await Fga.connect({ apiUrl: API_URL, presharedKey: KEY, caCertPath: CA });
    fga = conn.fga;
    modelId = conn.modelId;
  });

  /** A view whose matched entry carries the Common Constraint, with no deployment predicate. */
  const gatedView = view({
    authority_set: [
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: ["payments:invoice.read", "payments:payment.execute"],
        constraints: {
          max_amount: { amount: "500.00", currency: "USD" },
          vendors: ["acme"],
          requires_action_approval: true,
        },
      },
    ],
  });

  it("denies an action the matched entry gates even when deployment policy does not", async () => {
    const decision = await evaluate(req(), opts(gatedView));
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("action_approval_required");
  });

  it("permits the same action once an approval bound to the parameters is presented", async () => {
    const decision = await evaluate(
      req({
        context: {
          audience: RESOURCE,
          mission: { id: "msn_test_1", authority_hash: "sha-256:testhash" },
          parameter_digest: "sha-256:gated-op",
          action_approval: {
            id: "apr_1",
            approved_at: NOW.toISOString(),
            parameter_digest: "sha-256:gated-op",
          },
        },
      }),
      opts(gatedView),
    );
    expect(decision.decision, JSON.stringify(decision.context)).toBe(true);
  });

  it("leaves an ungated entry unaffected", async () => {
    const decision = await evaluate(req(), opts(view()));
    expect(decision.decision, JSON.stringify(decision.context)).toBe(true);
  });
});

// --- substrate Basic Governance Gate (@spec mission-substrate#basic-gate) ---
//
// Unconditional (no live OpenFGA needed): every case below returns before
// evaluateInner ever reaches step 6's fga.checkWithContext, EXCEPT the first
// permit case, which supplies a stub Fga whose checkWithContext always
// resolves true. Runs unconditionally so this coverage is never sandbox-skipped.
describe("basic gate: active predicate, non-active outcome, unrecognized-fails-closed", () => {
  const stubFga = { checkWithContext: async () => true } as unknown as Fga;
  const gateOpts = (v: MissionView) => ({
    view: v,
    fga: stubFga,
    modelId: "unit-test-model",
    now: () => NOW,
    stalenessBoundSeconds,
    relationForAction,
  });

  it("active predicate true -> the gate proceeds to a decision (never the non-active outcome)", async () => {
    const dec = await evaluate(req(), gateOpts(view()));
    expect(dec.decision, JSON.stringify(dec.context)).toBe(true);
    expect(dec.context.denial_reason).toBeUndefined();
  });

  it("active predicate false -> the non-active outcome (mission_inactive), for every recognized non-active state, never a positive decision", async () => {
    for (const state of ["revoked", "expired", "suspended", "superseded"]) {
      const dec = await evaluate(req(), gateOpts(view({ state })));
      expect(dec.decision, state).toBe(false);
      expect(dec.context.denial_reason, state).toBe("mission_inactive");
    }
  });

  it("an action absent from the policy's action-to-relation map fails closed (out_of_authority), never reaching the FGA check", async () => {
    const dec = await evaluate(req({ action: { name: "payments:totally_unrecognized_action" } }), gateOpts(view()));
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("out_of_authority");
  });

  // @spec mission-substrate#propagation (no-bare-unverified-acceptance) --
  // proves the mismatch-refusal arm only: a supplied mission reference that
  // does not match the independently loaded, server-held view is refused.
  // It does NOT prove the complementary arm (that an accepted reference must
  // have arrived inside a verified credential rather than a bare parameter);
  // that arm is a token-binding/RS concern outside evaluate()'s pure-function
  // boundary, so this stays a partial mapping for the propagation surface.
  it("a supplied mission reference that mismatches the loaded view is refused, never silently accepted", async () => {
    const dec = await evaluate(
      req({ context: { audience: RESOURCE, mission: { id: "msn_test_1", authority_hash: "sha-256:WRONG" } } }),
      gateOpts(view()),
    );
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("view_inconsistent");
  });
});
