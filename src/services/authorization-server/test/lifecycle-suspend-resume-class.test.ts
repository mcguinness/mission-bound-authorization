/**
 * @spec status#conformance ("Mission Lifecycle, revoke only": "one that serves
 * `suspend` serves `resume`, without widening who may perform either"), #1724
 * C8 (D847).
 *
 * Three assemblies: revoke only, revoke with the other base operations
 * (`lifecycle-extended`), and the full reference provider. An operation is
 * served when a request naming an unknown Mission reaches the Mission lookup
 * (the not-found refusal), and unserved when it is refused `invalid_request`
 * before any lookup. Covered:
 *  - in every assembly, `suspend` is served only together with `resume`;
 *  - where both are served, a client the deployment authorizes for one of
 *    them only is refused the other, as an unknown Mission is refused.
 */
import type { Server } from "node:http";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  ALL_PROVIDER_CAPABILITIES,
  type BuiltAs,
  buildAuthorizationServer,
  MISSION_LIFECYCLE_SCOPE,
  type MissionRecord,
  type ProviderCapability,
  validateMissionIntent,
} from "../src/index.js";
import { type LifecycleTestClient, lifecycleRequest, newLifecycleClient } from "./lifecycle-endpoint.helper.js";

const STATUS_SURFACES: readonly ProviderCapability[] = ["status", "status-list", "discharge", "containment"];
const without = (off: readonly ProviderCapability[]): Set<ProviderCapability> =>
  new Set(ALL_PROVIDER_CAPABILITIES.filter((c) => !off.includes(c)));

const ASSEMBLIES: ReadonlyArray<{ name: string; port: number; capabilities?: Set<ProviderCapability> }> = [
  { name: "revoke only", port: 15402, capabilities: without(["lifecycle-extended", ...STATUS_SURFACES]) },
  { name: "revoke with the other base operations", port: 15403, capabilities: without(STATUS_SURFACES) },
  { name: "the full reference provider", port: 15404 },
];
const UNKNOWN_MISSION = "msn_unknown_0000000000000000000000";

type Running = { name: string; issuer: string; as: BuiltAs; server: Server };
const running: Running[] = [];
/** Authorized for every lifecycle operation. */
let operator: LifecycleTestClient;
/** Authorized for `suspend` only. */
let suspender: LifecycleTestClient;
/** Authorized for `resume` only. */
let resumer: LifecycleTestClient;
let approvals = 0;

function approve(r: Running): MissionRecord {
  approvals += 1;
  return r.as.kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({ goal: "Read Acme invoices", target_resources: [CANONICAL_RESOURCE], expires_at: "2027-01-01T00:00:00Z" }),
    ),
    proposedAuthority: [{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] }],
    subject: { iss: r.issuer, sub: "alice" },
    approver: { iss: r.issuer, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-suspend-resume-${approvals}`,
  });
}

/** Whether `r` serves `operation`: a request naming an unknown Mission reaches the lookup. */
async function serves(r: Running, operation: string): Promise<boolean> {
  const answer = await lifecycleRequest(r.issuer, operator, {
    mission_id: UNKNOWN_MISSION,
    operation,
    nonce: `nonce-probe-${crypto.randomUUID()}`,
  });
  if (answer.status === 404 && answer.json?.error === "not_found") return true;
  expect(answer.status, `${r.name} ${operation}: ${answer.text}`).toBe(400);
  expect(answer.json?.error).toBe("invalid_request");
  return false;
}

beforeAll(async () => {
  operator = await newLifecycleClient("class-operator");
  suspender = await newLifecycleClient("class-suspender");
  resumer = await newLifecycleClient("class-resumer");
  for (const a of ASSEMBLIES) {
    const issuer = `http://localhost:${a.port}`;
    const as = await buildAuthorizationServer({
      issuer,
      ...(a.capabilities ? { capabilities: a.capabilities } : {}),
      testClients: [operator.metadata, suspender.metadata, resumer.metadata],
      lifecycleClientGrants: {
        [operator.clientId]: [MISSION_LIFECYCLE_SCOPE],
        [suspender.clientId]: { grants: [MISSION_LIFECYCLE_SCOPE], operations: ["suspend"] },
        [resumer.clientId]: { grants: [MISSION_LIFECYCLE_SCOPE], operations: ["resume"] },
      },
    });
    const server = as.provider.listen(a.port);
    await new Promise<void>((r) => server.once("listening", () => r()));
    running.push({ name: a.name, issuer, as, server });
  }
});

afterAll(async () => {
  for (const r of running) await new Promise<void>((done) => r.server.close(() => done()));
});

describe("a Lifecycle deployment that serves suspend serves resume, without widening who may perform either (@spec status#conformance, #1724 C8)", () => {
  it("in every assembly, suspend is served only together with resume", async () => {
    const served: Record<string, [boolean, boolean]> = {};
    for (const r of running) served[r.name] = [await serves(r, "suspend"), await serves(r, "resume")];
    expect(served).toEqual({
      "revoke only": [false, false],
      "revoke with the other base operations": [true, true],
      "the full reference provider": [true, true],
    });
  });

  it("where both are served, a client authorized for suspend alone is refused resume, and one authorized for resume alone is refused suspend, as an unknown Mission is refused", async () => {
    const r = running.find((x) => x.name === "revoke with the other base operations") as Running;
    const request = (client: LifecycleTestClient, missionId: string, operation: string) =>
      lifecycleRequest(r.issuer, client, { mission_id: missionId, operation, nonce: `nonce-${operation}-${crypto.randomUUID()}` });
    const m = approve(r);
    const unknown = await request(suspender, UNKNOWN_MISSION, "resume");
    expect(unknown.status).toBe(404);

    // The suspender suspends, and may not resume what it suspended.
    expect((await request(suspender, m.id, "suspend")).status).toBe(200);
    const suspenderResume = await request(suspender, m.id, "resume");
    expect(suspenderResume.status).toBe(404);
    expect(suspenderResume.json?.error).toBe(unknown.json?.error);
    expect(r.as.kernel.get(m.id)?.state).toBe("suspended");

    // The resumer resumes, and may not suspend.
    expect((await request(resumer, m.id, "resume")).status).toBe(200);
    const resumerSuspend = await request(resumer, m.id, "suspend");
    expect(resumerSuspend.status).toBe(404);
    expect(resumerSuspend.json?.error).toBe(unknown.json?.error);
    expect(r.as.kernel.get(m.id)?.state).toBe("active");
  });
});
