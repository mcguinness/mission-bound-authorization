/**
 * Containment end-to-end across the enforcement chain: an active Mission; a
 * protected event (a simulated tainted read) reported via the lifecycle
 * `contain` operation over real HTTP removes payments:remittance.send; the
 * live PDP (OpenFGA-backed) then denies exactly that action with
 * `authority_contained` while other actions still permit; an Expansion
 * successor (a fresh approval) restores the capability and carries NO
 * containment. Joins the AS lifecycle surface with the PDP decision function.
 * Skipped automatically when OpenFGA is unreachable (docker compose up).
 */

import { type Server } from "node:http";
import { CANONICAL_RESOURCE, DEV_SERVICE_TOKEN, type SeededTrustedSource } from "@mission/demo-data";
import { type CryptoKey, importJWK, SignJWT } from "jose";
import {
  evaluate,
  Fga,
  type MissionView,
  policyViewId,
  relationForAction,
  stalenessBoundSeconds,
} from "@mission/pdp";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type AuthorityEntry, type BuiltAs, buildAuthorizationServer, createExpansion, validateMissionIntent } from "../src/index.js";

const PORT = 14495;
const ISSUER = `http://localhost:${PORT}`;
const RESOURCE = CANONICAL_RESOURCE;
const EXPIRES_AT = "2027-01-01T00:00:00Z";

const API_URL = process.env.OPENFGA_HTTP_URL ?? "https://localhost:8080";
const KEY = process.env.OPENFGA_PRESHARED_KEY ?? "dev-preshared-key-change-me";
const CA = process.env.OPENFGA_CA_CERT;

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
if (!up) console.warn("OpenFGA unreachable; skipping containment e2e (docker compose up)");

let as: BuiltAs;
let server: Server;
let fga: Fga;
let modelId: string;

const authority = (): AuthorityEntry[] => [
  {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions: ["payments:invoice.read", "payments:remittance.send"],
    constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  },
];

const intent = (goal: string) =>
  validateMissionIntent(
    JSON.stringify({
      goal,
      resources: [RESOURCE],
      expires_at: EXPIRES_AT,
    }),
  );

/** The PDP's view of a mission (the demo stack's viewFor mapping, incl. the containment delta). */
function viewFor(missionId: string): MissionView {
  const r = as.kernel.get(missionId);
  if (!r) throw new Error(`mission ${missionId} missing`);
  const fresh = as.kernel.applyExpiry(r);
  return {
    id: fresh.id,
    issuer: fresh.issuer,
    state: fresh.state,
    version: fresh.version,
    authority_hash: fresh.authority_hash,
    authority_set: fresh.authority_set,
    subject: fresh.subject,
    client_id: fresh.client_id,
    ...(fresh.containment
      ? {
          containment: {
            version: fresh.containment.containment_version,
            contained: fresh.containment.contained,
          },
        }
      : {}),
  };
}

const evalAction = async (missionId: string, action: string) => {
  const view = viewFor(missionId);
  return evaluate(
    {
      subject: { id: "alice" },
      resource: { type: "invoice", id: "inv-1", properties: { vendor_id: "acme" } },
      action: { name: action },
      context: { audience: RESOURCE, mission: { id: view.id, issuer: view.issuer, authority_hash: view.authority_hash } },
    },
    { view, fga, modelId, now: () => new Date(), stalenessBoundSeconds, relationForAction },
  );
};

d("containment end-to-end: taint -> contain -> authority_contained -> expansion restores", () => {
  beforeAll(async () => {
    as = await buildAuthorizationServer({ issuer: ISSUER, allowHeadlessAdjudication: true });
    server = as.provider.listen(PORT);
    const conn = await Fga.connect({ apiUrl: API_URL, presharedKey: KEY, caCertPath: CA });
    fga = conn.fga;
    modelId = conn.modelId;
  });
  afterAll(() => {
    server?.close();
  });

  it("runs the full sequence", async () => {
    // An active Mission approved for invoice.read + remittance.send.
    const mission = as.kernel.approve({
      intent: intent("Pay Acme invoices and send remittance"),
      proposedAuthority: authority(),
      subject: { iss: ISSUER, sub: "alice" },
      approver: { iss: ISSUER, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: "apev-cnt-e2e-1",
    });
    const preContainPvid = policyViewId(viewFor(mission.id), modelId);

    // Pre-containment: the approved action permits.
    const before = await evalAction(mission.id, "payments:remittance.send");
    expect(before.decision, JSON.stringify(before.context)).toBe(true);

    // A protected event (simulated tainted read) reported via the lifecycle
    // contain operation, over real HTTP.
    const res = await fetch(`${ISSUER}/missions/${mission.id}/lifecycle`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
      body: JSON.stringify({
        operation: "contain",
        event: {
          type: "tainted_read",
          source: "https://siem.example/detections",
          observed_at: new Date().toISOString(),
          event_id: "taint-e2e-1",
        },
        remove: [{ resource: RESOURCE, actions: ["payments:remittance.send"] }],
      }),
    });
    const body = (await res.json()) as { containment_version?: number; version?: number };
    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(body.containment_version).toBe(1);

    // The removed action denies authority_contained (approved, trust lost)...
    const contained = await evalAction(mission.id, "payments:remittance.send");
    expect(contained.decision).toBe(false);
    expect(contained.context.denial_reason).toBe("authority_contained");
    expect(contained.context.containment_version).toBe(1);
    // ...while an uncontained action still permits, and the policy view moved
    // (a client pinning the pre-containment policy_view_id goes stale).
    const still = await evalAction(mission.id, "payments:invoice.read");
    expect(still.decision, JSON.stringify(still.context)).toBe(true);
    expect(policyViewId(viewFor(mission.id), modelId)).not.toBe(preContainPvid);

    // An Expansion successor (a fresh approval) restores the capability.
    const expansion = createExpansion(as.kernel, {
      predecessorId: mission.id,
      intent: intent("Pay Acme invoices and send remittance (restored after containment review)"),
      proposedAuthority: authority(),
      approver: { iss: ISSUER, sub: "bob" },
      approvalEventId: "apev-cnt-e2e-succ",
      approvedUntil: EXPIRES_AT,
    });
    as.kernel.supersedeOnRedemption(expansion.successor.id);

    // The successor carries NO containment and permits the restored action.
    expect(as.kernel.get(expansion.successor.id)?.containment).toBeUndefined();
    const restored = await evalAction(expansion.successor.id, "payments:remittance.send");
    expect(restored.decision, JSON.stringify(restored.context)).toBe(true);

    // The superseded predecessor no longer authorizes anything.
    const superseded = await evalAction(mission.id, "payments:invoice.read");
    expect(superseded.decision).toBe(false);
    expect(superseded.context.denial_reason).toBe("mission_inactive");
  });

  it("a SIGNED protected event (JWS source-verified) drives the same PDP denial", async () => {
    const mission = as.kernel.approve({
      intent: intent("Pay Acme invoices via a signed protected-event path"),
      proposedAuthority: authority(),
      subject: { iss: ISSUER, sub: "alice" },
      approver: { iss: ISSUER, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: "apev-cnt-e2e-signed",
    });
    // Pre-containment: the approved action permits.
    expect((await evalAction(mission.id, "payments:remittance.send")).decision).toBe(true);

    // Report a protected event as the trusted svc:soc source, over real HTTP, as
    // a compact JWS (verified against the config-seeded source key, not the
    // transport origin). Containment applies DETERMINISTICALLY via the policy.
    const soc = as.protectedEventSources.find((s) => s.source === "svc:soc") as SeededTrustedSource;
    const key = (await importJWK(soc.privateJwk, soc.alg)) as CryptoKey;
    const jws = await new SignJWT({
      type: "content.tainted_read",
      source: "svc:soc",
      observed_at: new Date().toISOString(),
      event_id: "taint-e2e-signed-1",
      mission_id: mission.id,
    })
      .setProtectedHeader({ alg: soc.alg, kid: soc.kid })
      .setIssuedAt()
      .sign(key);
    const res = await fetch(`${ISSUER}/missions/${mission.id}/protected-events`, {
      method: "POST",
      headers: { "content-type": "application/protected-event+jwt" },
      body: jws,
    });
    const body = (await res.json()) as { containment_version?: number };
    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(body.containment_version).toBe(1);

    // The PDP now denies the removed action authority_contained.
    const contained = await evalAction(mission.id, "payments:remittance.send");
    expect(contained.decision).toBe(false);
    expect(contained.context.denial_reason).toBe("authority_contained");
    // The issuer retained an `applied` ingestion record + the Containment Evidence.
    const joined = as.issuerEvidence.forMission(mission.id);
    expect(joined.ingestion.some((r) => r.outcome === "applied" && r.rule_id)).toBe(true);
    expect(joined.containment).toHaveLength(1);
  });
});
