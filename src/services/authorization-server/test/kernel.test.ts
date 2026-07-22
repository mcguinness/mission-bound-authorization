import { DERIVATION_POLICY } from "@mission/demo-data";
import { generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
  deriveAuthoritySet,
  GateError,
  IntentError,
  isSubsetSet,
  LifecycleConflictError,
  MissionKernel,
  validateMissionIntent,
} from "../src/index.js";

const ISS = "https://as.test";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;

const intent = (over: Record<string, unknown> = {}) =>
  JSON.stringify({
    goal: "Pay Acme invoices for Q3",
    resources: [RESOURCE],
    expires_at: "2027-01-01T00:00:00Z",
    ...over,
  });

let kernel: MissionKernel;
beforeAll(async () => {
  const { privateKey } = await generateKeyPair("ES256");
  kernel = new MissionKernel({
    issuer: ISS,
    policy: DERIVATION_POLICY as never,
    statusKey: privateKey,
    statusKid: "as-status",
  });
});

const approve = (raw: string, n: number) =>
  kernel.approve({
    intent: validateMissionIntent(raw),
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-${n}`,
  });

describe("intent validation (@spec mission#submission-via-par)", () => {
  it("rejects unknown top-level members (closed top level)", () => {
    expect(() => validateMissionIntent(intent({ authority_hash: "sneaky" }))).toThrow(IntentError);
  });
  it("rejects duplicate member names", () => {
    expect(() => validateMissionIntent('{"goal":"x","goal":"y"}')).toThrow(/duplicate/);
  });
  it("rejects missing required members and bad expires_at", () => {
    expect(() => validateMissionIntent('{"goal":"x"}')).toThrow(IntentError);
    expect(() => validateMissionIntent(intent({ expires_at: "not-a-date" }))).toThrow(IntentError);
  });
  it("rejects max_derivations below 1", () => {
    expect(() => validateMissionIntent(intent({ controls: { max_derivations: 0 } }))).toThrow(
      /max_derivations/,
    );
  });
  it("rejects proposed_authority resources outside the Intent's resources", () => {
    expect(() =>
      validateMissionIntent(
        intent({
          proposed_authority: [
            { type: "mission_resource_access", resource: "https://other.example", actions: ["x"] },
          ],
        }),
      ),
    ).toThrow(/not among Intent resources/);
  });
});

describe("derivation (@spec mission#authorization-derivation)", () => {
  it("compromised shaper: an over-broad proposal never widens past the ceiling", () => {
    const broad = validateMissionIntent(
      intent({
        proposed_authority: [
          {
            type: "mission_resource_access",
            resource: RESOURCE,
            actions: ["payments:payment.execute", "payments:vendor.delete", "payments:invoice.read"],
            constraints: {
              max_amount: { amount: "999999.00", currency: "USD" },
              vendors: ["acme", "globex", "evilcorp"],
            },
          },
        ],
      }),
    );
    const derived = deriveAuthoritySet(broad, DERIVATION_POLICY as never);
    expect(isSubsetSet(derived, DERIVATION_POLICY.ceiling as never)).toBe(true);
    const entry = derived[0];
    expect(entry?.actions).not.toContain("payments:vendor.delete");
    expect(entry?.constraints?.max_amount?.amount).toBe("500.00");
    expect(entry?.constraints?.vendors).toEqual(["acme"]);
  });

  it("refuses an Intent yielding no authority with invalid_authorization_details", () => {
    const bad = validateMissionIntent(
      intent({
        proposed_authority: [
          { type: "mission_resource_access", resource: RESOURCE, actions: ["not:allowed"] },
        ],
      }),
    );
    try {
      deriveAuthoritySet(bad, DERIVATION_POLICY as never);
      expect.unreachable();
    } catch (e) {
      expect((e as IntentError).code).toBe("invalid_authorization_details");
    }
  });
});

describe("approval event and record (@spec mission#integrity-anchors)", () => {
  it("creates an active record with both anchors and is idempotent by approval_event_id", () => {
    const record = approve(intent(), 1);
    expect(record.state).toBe("active");
    expect(record.intent_hash).toMatch(/^sha-256:/);
    expect(record.authority_hash).toMatch(/^sha-256:/);
    expect(record.id).toMatch(/^msn_/);
    const again = approve(intent(), 1);
    expect(again.id).toBe(record.id);
  });
});

describe("lifecycle (@spec status#legal-transitions)", () => {
  it("enforces the legal-transitions table with idempotent success", () => {
    const r = approve(intent(), 2);
    expect(kernel.transition(r.id, "suspend").state).toBe("suspended");
    expect(kernel.transition(r.id, "suspend").state).toBe("suspended"); // idempotent
    expect(kernel.transition(r.id, "resume").state).toBe("active");
    expect(() => kernel.transition(r.id, "resume")).toThrow(LifecycleConflictError); // resume exception
    expect(kernel.transition(r.id, "revoke").state).toBe("revoked");
    expect(() => kernel.transition(r.id, "suspend")).toThrow(LifecycleConflictError); // terminal
    expect(kernel.transition(r.id, "revoke").state).toBe("revoked"); // idempotent on terminal
  });

  it("gates derivation on state and derivation cap (@spec mission#lifecycle)", () => {
    const r = approve(intent({ controls: { max_derivations: 2 } }), 3);
    kernel.gateDerivation(r.id);
    kernel.gateDerivation(r.id);
    expect(() => kernel.gateDerivation(r.id)).toThrow(GateError);
    const r2 = approve(intent(), 4);
    kernel.transition(r2.id, "suspend");
    expect(() => kernel.gateDerivation(r2.id)).toThrow(/suspended/);
  });

  it("expiry clock: past expires_at the mission is expired and non-deriving", () => {
    const r = approve(intent({ expires_at: "2020-01-01T00:00:00Z" }), 5);
    expect(() => kernel.gateDerivation(r.id)).toThrow(GateError);
    expect(kernel.get(r.id)?.state).toBe("expired");
  });
});

describe("signed status (@spec status#mission-status-response)", () => {
  it("emits a JWS with the mission object and audience-scoped authority", async () => {
    const r = approve(intent(), 6);
    const jws = await kernel.signedStatus(r.id, { audience: RESOURCE, requester: "svc:test", nonce: "n1" });
    const [h, p] = jws.split(".");
    const header = JSON.parse(Buffer.from(h as string, "base64url").toString());
    const payload = JSON.parse(Buffer.from(p as string, "base64url").toString());
    expect(header.typ).toBe("mission-status-response+jwt");
    expect(payload.mission.state).toBe("active");
    expect(payload.mission.fresh_until).toBeDefined();
    expect(payload.nonce).toBe("n1");
    expect(payload.authorization_details[0].resource).toBe(RESOURCE);
  });
});
