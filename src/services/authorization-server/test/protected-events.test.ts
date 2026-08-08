/**
 * @spec containment#protected-events — the issuer's protected-event ingestion
 * endpoint (the HTTP wire that drives issuer-held containment policy). A trusted
 * source reports a protected event as a COMPACT JWS; the issuer verifies the
 * signature against the resolved source IDENTITY (not the transport origin),
 * requires the source trusted FOR the reported type, and applies containment
 * DETERMINISTICALLY via kernel.containOnEvent. BOTH accepted and rejected
 * reports are recorded issuer-side (fail closed). Also covers the fixed
 * (no-longer-discarded) Containment Evidence retention and the manual
 * break-glass path. OpenFGA-free: the PDP join lives in containment-pdp-e2e.
 */

import type { Server } from "node:http";
import { CANONICAL_RESOURCE, DEV_SERVICE_TOKEN, type SeededTrustedSource } from "@mission/demo-data";
import { type CryptoKey, generateKeyPair, importJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type BuiltAs, buildAuthorizationServer, validateMissionIntent } from "../src/index.js";
import type { MissionRecord } from "../src/kernel/types.js";

const PORT = 14496;
const ISSUER = `http://localhost:${PORT}`;
const RESOURCE = CANONICAL_RESOURCE;
const EXPIRES_AT = "2027-01-01T00:00:00Z";
const RULE_ID = "contain-external-comms-on-taint-v1";

let as: BuiltAs;
let server: Server;
let soc: SeededTrustedSource; // trusted for content.tainted_read (has a rule)
let harness: SeededTrustedSource; // advisory, trusted for egress.* (no rule)

const authority = () => [
  {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions: ["payments:invoice.read", "payments:remittance.send"],
    constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  },
];

const intent = (goal: string) =>
  validateMissionIntent(
    JSON.stringify({ goal, resources: [RESOURCE], expires_at: EXPIRES_AT, proposed_authority: authority() }),
  );

let seq = 0;
function approve(): MissionRecord {
  seq += 1;
  return as.kernel.approve({
    intent: intent(`Pay Acme invoices ${seq}`),
    subject: { iss: ISSUER, sub: "alice" },
    approver: { iss: ISSUER, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-pe-${seq}`,
  });
}

function eventPayload(missionId: string, type: string, source: string, event_id: string) {
  return { type, source, observed_at: new Date().toISOString(), event_id, mission_id: missionId };
}

/** Sign a protected-event report as `src`, with optional header/key overrides. */
async function sign(
  src: SeededTrustedSource,
  payload: Record<string, unknown>,
  override?: { kid?: string; alg?: string; key?: CryptoKey },
): Promise<string> {
  const alg = override?.alg ?? src.alg;
  const key = override?.key ?? ((await importJWK(src.privateJwk, src.alg)) as CryptoKey);
  return new SignJWT(payload).setProtectedHeader({ alg, kid: override?.kid ?? src.kid }).setIssuedAt().sign(key);
}

async function post(missionId: string, jws: string): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await fetch(`${ISSUER}/missions/${missionId}/protected-events`, {
    method: "POST",
    headers: { "content-type": "application/protected-event+jwt" },
    body: jws,
  });
  const text = await res.text();
  let body: Record<string, unknown> = {};
  try {
    body = JSON.parse(text) as Record<string, unknown>;
  } catch {
    body = { raw: text };
  }
  return { status: res.status, body };
}

const effectiveActions = (id: string): string[] => {
  const r = as.kernel.get(id);
  if (!r) return [];
  return as.kernel.effectiveAuthoritySet(r).flatMap((e) => e.actions);
};

describe("protected-event ingestion: JWS source verification -> deterministic containment", () => {
  beforeAll(async () => {
    as = await buildAuthorizationServer({ issuer: ISSUER, allowHeadlessAdjudication: true });
    server = as.provider.listen(PORT);
    soc = as.protectedEventSources.find((s) => s.source === "svc:soc") as SeededTrustedSource;
    harness = as.protectedEventSources.find((s) => s.source === "svc:harness-egress") as SeededTrustedSource;
    expect(soc, "svc:soc seeded from config").toBeDefined();
    expect(harness?.advisory, "svc:harness-egress is advisory").toBe(true);
  });
  afterAll(() => {
    server?.close();
  });

  it("trusted source + known type -> 200, containment applied, applied record + retained Containment Evidence", async () => {
    const m = approve();
    expect(effectiveActions(m.id)).toContain("payments:remittance.send");

    const jws = await sign(soc, eventPayload(m.id, "content.tainted_read", "svc:soc", "ev-applied-1"));
    const { status, body } = await post(m.id, jws);
    expect(status, JSON.stringify(body)).toBe(200);
    expect(body.containment_version).toBe(1);
    expect(body.removed).toEqual([{ resource: RESOURCE, actions: ["payments:remittance.send"] }]);

    // The removed capability is gone from the EFFECTIVE set (PDP denial is proven
    // in the OpenFGA e2e); the approved set + hash are untouched.
    expect(effectiveActions(m.id)).not.toContain("payments:remittance.send");
    expect(effectiveActions(m.id)).toContain("payments:invoice.read");

    const joined = as.issuerEvidence.forMission(m.id);
    expect(joined.ingestion).toHaveLength(1);
    expect(joined.ingestion[0]).toMatchObject({
      kind: "ingestion",
      outcome: "applied",
      event_type: "content.tainted_read",
      source: "svc:soc",
      rule_id: RULE_ID,
      event_id: "ev-applied-1",
    });
    expect(joined.ingestion[0]?.emitter).toEqual({ id: ISSUER, role: "issuer" });
    expect(joined.ingestion[0]?.advisory).toBeUndefined();
    // The Containment Evidence contain() returned is RETAINED (previously dropped).
    expect(joined.containment).toHaveLength(1);
    expect(joined.containment[0]?.policy).toBe(RULE_ID);
    expect(joined.containment[0]?.new_containment_version).toBe(1);
  });

  it("authenticated event, unknown event_type -> 422, no version bump, rejected record (advisory stamped)", async () => {
    const m = approve();
    const before = as.kernel.get(m.id)?.version;
    // harness-egress is TRUSTED for egress.destination_unlisted, but NO policy
    // rule maps it -> reject-and-record (422), NO containment, NO version bump.
    const jws = await sign(harness, eventPayload(m.id, "egress.destination_unlisted", "svc:harness-egress", "ev-422-1"));
    const { status, body } = await post(m.id, jws);
    expect(status, JSON.stringify(body)).toBe(422);
    expect(body.rejection_reason).toBe("unknown_event_type");
    expect(as.kernel.get(m.id)?.version).toBe(before);
    expect(as.kernel.get(m.id)?.containment).toBeUndefined();

    const rec = as.issuerEvidence.forMission(m.id).ingestion;
    expect(rec).toHaveLength(1);
    expect(rec[0]).toMatchObject({ outcome: "rejected", rejection_reason: "unknown_event_type", advisory: true });
    expect(as.issuerEvidence.forMission(m.id).containment).toHaveLength(0);
  });

  it("unknown event_type from a NON-advisory source -> 422, rejected record with advisory absent", async () => {
    const m = approve();
    const before = as.kernel.get(m.id)?.version;
    // svc:soc is trusted for content.integrity_alert (a class it reports) but NO
    // rule maps it -> 422, proving the 422 path is independent of advisory.
    const jws = await sign(soc, eventPayload(m.id, "content.integrity_alert", "svc:soc", "ev-422-nonadv-1"));
    const { status, body } = await post(m.id, jws);
    expect(status, JSON.stringify(body)).toBe(422);
    expect(body.rejection_reason).toBe("unknown_event_type");
    expect(as.kernel.get(m.id)?.version).toBe(before);
    const rec = as.issuerEvidence.forMission(m.id).ingestion[0];
    expect(rec?.outcome).toBe("rejected");
    expect(rec?.advisory).toBeUndefined(); // non-advisory source -> no advisory stamp
  });

  it("bad signature -> 403 + rejected record", async () => {
    const m = approve();
    const wrong = (await generateKeyPair("ES256", { extractable: true })).privateKey;
    // Claim source svc:soc + its kid, but sign with a DIFFERENT key.
    const jws = await sign(soc, eventPayload(m.id, "content.tainted_read", "svc:soc", "ev-badsig-1"), { key: wrong });
    const { status, body } = await post(m.id, jws);
    expect(status).toBe(403);
    expect(body.rejection_reason).toBe("bad_signature");
    expect(as.kernel.get(m.id)?.containment).toBeUndefined();
    expect(as.issuerEvidence.forMission(m.id).ingestion[0]?.rejection_reason).toBe("bad_signature");
  });

  it("unknown source -> 403 + rejected record", async () => {
    const m = approve();
    // A validly-structured JWS whose payload claims an unregistered source.
    const jws = await sign(soc, eventPayload(m.id, "content.tainted_read", "svc:evil", "ev-unk-src-1"));
    const { status, body } = await post(m.id, jws);
    expect(status).toBe(403);
    expect(body.rejection_reason).toBe("unknown_source");
    expect(as.issuerEvidence.forMission(m.id).ingestion[0]?.source).toBe("svc:evil");
  });

  it("source not trusted for that event_type -> 403 + rejected record", async () => {
    const m = approve();
    // svc:soc is trusted only for content.tainted_read.
    const jws = await sign(soc, eventPayload(m.id, "content.some_other_thing", "svc:soc", "ev-nottrusted-1"));
    const { status, body } = await post(m.id, jws);
    expect(status).toBe(403);
    expect(body.rejection_reason).toBe("source_not_trusted_for_type");
    expect(as.kernel.get(m.id)?.containment).toBeUndefined();
  });

  it("mission_id mismatch -> 403 + rejected record", async () => {
    const m = approve();
    // Verified payload claims a DIFFERENT mission than the :id path segment.
    const jws = await sign(soc, eventPayload("msn-other", "content.tainted_read", "svc:soc", "ev-mismatch-1"));
    const { status, body } = await post(m.id, jws);
    expect(status).toBe(403);
    expect(body.rejection_reason).toBe("mission_mismatch");
    expect(as.kernel.get(m.id)?.containment).toBeUndefined();
  });

  it("duplicate event_id -> idempotent (single containment, one committed event)", async () => {
    const m = approve();
    const jws = await sign(soc, eventPayload(m.id, "content.tainted_read", "svc:soc", "ev-dup-1"));
    const first = await post(m.id, jws);
    expect(first.status).toBe(200);
    expect(first.body.containment_version).toBe(1);
    // Re-sign the SAME event_id (fresh signature, same idempotency key).
    const jws2 = await sign(soc, eventPayload(m.id, "content.tainted_read", "svc:soc", "ev-dup-1"));
    const second = await post(m.id, jws2);
    expect(second.status).toBe(200);
    expect(second.body.containment_version).toBe(1); // no second bump
    expect(as.kernel.get(m.id)?.containment?.containment_version).toBe(1);
    expect(as.kernel.get(m.id)?.containment?.events).toHaveLength(1);
  });

  it("terminal mission -> 409 + rejected record (known type resolves a rule, then contain refuses)", async () => {
    const m = approve();
    as.kernel.transition(m.id, "revoke");
    const jws = await sign(soc, eventPayload(m.id, "content.tainted_read", "svc:soc", "ev-terminal-1"));
    const { status, body } = await post(m.id, jws);
    expect(status).toBe(409);
    expect(body.rejection_reason).toBe("mission_terminal");
    expect(as.issuerEvidence.forMission(m.id).ingestion[0]?.rejection_reason).toBe("mission_terminal");
  });

  it("manual break-glass contain (lifecycle endpoint) still works and retains Containment Evidence (policy manual)", async () => {
    const m = approve();
    const res = await fetch(`${ISSUER}/missions/${m.id}/lifecycle`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
      body: JSON.stringify({
        operation: "contain",
        event: {
          type: "manual_review",
          source: "svc:soc-analyst",
          observed_at: new Date().toISOString(),
          event_id: "ev-manual-1",
        },
        remove: [{ resource: RESOURCE, actions: ["payments:remittance.send"] }],
      }),
    });
    expect(res.status).toBe(200);
    expect(effectiveActions(m.id)).not.toContain("payments:remittance.send");
    const retained = as.issuerEvidence.forMission(m.id).containment;
    expect(retained).toHaveLength(1);
    expect(retained[0]?.policy).toBe("manual"); // break-glass, not a rule_id
  });
});
