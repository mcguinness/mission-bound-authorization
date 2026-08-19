import { authorityHash, intentHash } from "@mission/core";
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
  type MissionRecord,
  validateAuthorityProposal,
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
      validateAuthorityProposal(
        JSON.stringify([
          { type: "mission_resource_access", resource: "https://other.example", actions: ["x"] },
        ]),
        [RESOURCE],
      ),
    ).toThrow(/not among Intent resources/);
  });

  // @spec mission#other-types, I-D.draft-zehavi-oauth-rar-metadata: a
  // proposal entry whose type is not one this AS advertises via the
  // authorization_details_types_metadata_endpoint MUST be refused.
  it("refuses a proposed_authority entry of an unadvertised type with invalid_authorization_details", () => {
    try {
      validateAuthorityProposal(
        JSON.stringify([{ type: "payment_initiation", resource: RESOURCE, actions: ["x"] }]),
        [RESOURCE],
      );
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(IntentError);
      expect((e as IntentError).code).toBe("invalid_authorization_details");
      expect((e as IntentError).message).toMatch(/unsupported authorization details type/);
    }
  });

  // @spec mission#other-types, I-D.draft-zehavi-oauth-rar-metadata: a
  // same-type entry that fails its published JSON Schema MUST be refused too
  // (never silently carried into derivation with a malformed constraint).
  it("refuses a same-type proposed_authority entry that fails its published schema", () => {
    const badVendors = JSON.stringify([
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: ["payments:invoice.read"],
        constraints: { vendors: "acme" },
      },
    ]);
    try {
      validateAuthorityProposal(badVendors, [RESOURCE]);
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(IntentError);
      expect((e as IntentError).code).toBe("invalid_authorization_details");
      expect((e as IntentError).message).toMatch(/fails its published schema/);
    }

    const badMaxAmount = JSON.stringify([
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: ["payments:invoice.read"],
        constraints: { max_amount: 100 },
      },
    ]);
    expect(() => validateAuthorityProposal(badMaxAmount, [RESOURCE])).toThrow(
      /fails its published schema/,
    );
  });

  // Regression: a schema-conformant proposal (the shape the published schema
  // and this check both accept) still validates and derives unchanged.
  it("still accepts a schema-conformant proposed_authority entry", () => {
    const proposal = validateAuthorityProposal(
      JSON.stringify([
        {
          type: "mission_resource_access",
          resource: RESOURCE,
          actions: ["payments:invoice.read"],
          constraints: { max_amount: { amount: "10.00", currency: "USD" }, vendors: ["acme"] },
        },
      ]),
      [RESOURCE],
    );
    const validated = validateMissionIntent(intent());
    const derived = deriveAuthoritySet(validated, DERIVATION_POLICY as never, proposal);
    expect(derived[0]?.constraints?.vendors).toEqual(["acme"]);
  });
});

describe("derivation (@spec mission#authorization-derivation)", () => {
  it("compromised shaper: an over-broad proposal never widens past the ceiling", () => {
    const broad = validateMissionIntent(intent());
    const proposal = validateAuthorityProposal(
      JSON.stringify([
        {
          type: "mission_resource_access",
          resource: RESOURCE,
          actions: ["payments:payment.execute", "payments:vendor.delete", "payments:invoice.read"],
          constraints: {
            max_amount: { amount: "999999.00", currency: "USD" },
            vendors: ["acme", "globex", "evilcorp"],
          },
        },
      ]),
      [RESOURCE],
    );
    const derived = deriveAuthoritySet(broad, DERIVATION_POLICY as never, proposal);
    expect(isSubsetSet(derived, DERIVATION_POLICY.ceiling as never)).toBe(true);
    const entry = derived[0];
    expect(entry?.actions).not.toContain("payments:vendor.delete");
    expect(entry?.constraints?.max_amount?.amount).toBe("500.00");
    expect(entry?.constraints?.vendors).toEqual(["acme"]);
  });

  it("refuses an Intent yielding no authority with invalid_authorization_details", () => {
    const bad = validateMissionIntent(intent());
    const proposal = validateAuthorityProposal(
      JSON.stringify([
        { type: "mission_resource_access", resource: RESOURCE, actions: ["not:allowed"] },
      ]),
      [RESOURCE],
    );
    try {
      deriveAuthoritySet(bad, DERIVATION_POLICY as never, proposal);
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

describe("mission record expiry ceiling (@spec mission#mission-record)", () => {
  it("commits an effective expires_at never later than the Intent's requested ceiling", () => {
    const raw = intent({ expires_at: "2026-12-01T00:00:00Z" });
    const requested = validateMissionIntent(raw);
    const record = approve(raw, 200);
    expect(Date.parse(record.expires_at)).toBeLessThanOrEqual(Date.parse(requested.expires_at));
  });
});

describe("approval basis (@spec mission#approval-basis)", () => {
  it("records a direct basis, round-tripped through the store, with approver == consent_principal == activation_actor", () => {
    const record = approve(intent(), 100);
    const stored = kernel.get(record.id);
    expect(stored?.approval_basis).toEqual({
      type: "direct",
      consent_principal: { iss: ISS, sub: "bob" },
      activation: { approval_event_id: "apev-100" },
      activation_actor: { iss: ISS, sub: "bob" },
      root_commitment: record.authority_hash,
    });
    // approver IS approval_basis.consent_principal (D48/O-38 convergence).
    expect(stored?.approver).toEqual(stored?.approval_basis.consent_principal);
    // Not folded into either integrity anchor: recomputing both from `intent`
    // and `authority_set` alone still matches, so approval_basis carries no
    // weight in the digests (the lock's hashing decision, made checkable).
    expect(record.intent_hash).toBe(intentHash(ISS, record.intent as never));
    expect(record.authority_hash).toBe(authorityHash(ISS, record.authority_set as never));
  });

  it("carries approval_basis.type as a read-only signal on the mission claim", () => {
    const record = approve(intent(), 101);
    const claim = kernel.missionClaim(kernel.get(record.id) as MissionRecord);
    expect(claim.approval_basis).toEqual({ type: "direct" });
  });
});

describe("approved context commitment (@spec mission-substrate#approved-context)", () => {
  it("the approved authority_set and its integrity anchor survive a state transition unchanged, while state and version (the mutable fields) advance", () => {
    const record = approve(intent(), 300);
    const authoritySetSnapshot = structuredClone(record.authority_set); // content snapshot, not a live reference
    const fresh = kernel.transition(record.id, "suspend");
    expect(fresh.authority_set).toEqual(authoritySetSnapshot);
    expect(fresh.authority_hash).toBe(record.authority_hash);
    expect(fresh.state).toBe("suspended");
    expect(fresh.version).toBeGreaterThan(record.version);
  });
});

describe("actor binding at approval (@spec mission-substrate#actor-binding)", () => {
  it("binds the Mission Context to the client_id Actor handle at approval, and the binding round-trips unchanged", () => {
    const record = approve(intent(), 301);
    expect(record.client_id).toBe("ap-agent");
    const stored = kernel.get(record.id);
    expect(stored?.client_id).toBe("ap-agent");
  });
});

describe("mission reference unguessability (@spec mission-substrate#reference)", () => {
  it("the Mission Reference's random component carries at least 128 bits of entropy", () => {
    const record = approve(intent(), 302);
    const suffix = record.id.replace(/^msn_/, "");
    const decoded = Buffer.from(suffix, "base64url");
    expect(decoded.length).toBeGreaterThanOrEqual(16); // 128-bit floor; the kernel mints 18 bytes (144 bits)
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

// The Controller's Basic Governance Gate (@spec mission-substrate#basic-gate)
// is realized here, not by the resource-side PDP: gateActive and
// gateDerivation are the AS's state-gated issuance and derivation paths. The
// active predicate is a whitelist (`state === "active"`), so any persisted
// value outside the recognized MissionState set fails closed by construction,
// never by an explicit blocklist entry.
describe("basic governance gate: state-gated issuance and derivation (@spec mission-substrate#basic-gate)", () => {
  it("active predicate true -> gateActive and gateDerivation proceed", () => {
    const r = approve(intent(), 400);
    expect(kernel.gateActive(r.id).state).toBe("active");
    expect(kernel.gateDerivation(r.id).state).toBe("active");
  });

  it("active predicate false -> gateActive and gateDerivation refuse, for every recognized non-active state", () => {
    const nonActive = ["suspended", "revoked", "expired", "completed", "superseded", "cascaded"] as const;
    nonActive.forEach((state, i) => {
      const r = approve(intent(), 401 + i);
      kernel.db.prepare("UPDATE missions SET state = ? WHERE id = ?").run(state, r.id);
      expect(() => kernel.gateActive(r.id), state).toThrow(GateError);
      expect(() => kernel.gateDerivation(r.id), state).toThrow(GateError);
    });
  });

  it("a persisted state value outside the recognized lifecycle set fails closed, never treated as active", () => {
    const r = approve(intent(), 410);
    kernel.db.prepare("UPDATE missions SET state = ? WHERE id = ?").run("quantum_supervened", r.id);
    try {
      kernel.gateActive(r.id);
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(GateError);
      expect((e as GateError).reason).toBe("mission_not_active");
    }
    try {
      kernel.gateDerivation(r.id);
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(GateError);
      expect((e as GateError).reason).toBe("mission_not_active");
    }
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
