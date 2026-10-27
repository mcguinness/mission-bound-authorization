/**
 * @spec status#idempotency ("A retransmit that arrives while the original is
 * still being processed never commits the operation a second time"), #1724 C1
 * (D847): a retransmit concurrent with its original.
 *
 * The original exchange is held after its transition, its observation and its
 * nonce claim have committed, while its response is being signed: the first
 * `signObservation` call waits on a gate the test releases. The retransmit
 * arrives in that window and finds the claim `committed`, not yet `final`.
 * The operation is `resume`, legal only from `suspended`, so a retransmit that
 * re-executed it would meet an `active` Mission and answer `conflict`.
 *
 * Covered: one committed transition (one version increment); every answer,
 * the original's, the concurrent retransmit's and a later replay's, is the
 * same 200 response byte for byte, reporting that one outcome.
 */
import type { Server } from "node:http";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import {
  type BuiltAs,
  buildAuthorizationServer,
  LIFECYCLE_ENDPOINT_KEY,
  MISSION_LIFECYCLE_SCOPE,
  type MissionRecord,
  validateMissionIntent,
} from "../src/index.js";
import { decodeStatusResponse, type LifecycleTestClient, lifecycleRequest, newLifecycleClient } from "./lifecycle-endpoint.helper.js";

const PORT = 15401;
const ISSUER = `http://localhost:${PORT}`;

let as: BuiltAs;
let server: Server;
let consoleClient: LifecycleTestClient;
let approvals = 0;

function approve(): MissionRecord {
  approvals += 1;
  return as.kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({ goal: "Read Acme invoices", target_resources: [CANONICAL_RESOURCE], expires_at: "2027-01-01T00:00:00Z" }),
    ),
    proposedAuthority: [{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] }],
    subject: { iss: ISSUER, sub: "alice" },
    approver: { iss: ISSUER, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-concurrent-retransmit-${approvals}`,
  });
}

/** The state of this client's retained response for `nonce` on Mission `missionId`. */
function claimState(missionId: string, nonce: string): string | undefined {
  const row = as.kernel.db
    .prepare("SELECT state FROM lifecycle_responses WHERE endpoint = ? AND principal = ? AND mission_id = ? AND nonce = ?")
    .get(LIFECYCLE_ENDPOINT_KEY, consoleClient.clientId, missionId, nonce) as { state: string } | undefined;
  return row?.state;
}

beforeAll(async () => {
  consoleClient = await newLifecycleClient("concurrent-console");
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    testClients: [consoleClient.metadata],
    lifecycleClientGrants: { [consoleClient.clientId]: [MISSION_LIFECYCLE_SCOPE] },
  });
  server = as.provider.listen(PORT);
  await new Promise<void>((r) => server.once("listening", () => r()));
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("a retransmit concurrent with its original commits once and answers with the one response (@spec status#idempotency, #1724 C1)", () => {
  it("a resume retransmitted while the original is still being signed commits one transition, and the original, the retransmit and a later replay answer the same 200 response byte for byte", async () => {
    const m = approve();
    const suspended = await lifecycleRequest(ISSUER, consoleClient, {
      mission_id: m.id,
      operation: "suspend",
      nonce: `nonce-suspend-${crypto.randomUUID()}`,
    });
    expect(suspended.status, suspended.text).toBe(200);
    const before = as.kernel.get(m.id) as MissionRecord;
    expect(before.state).toBe("suspended");

    // Hold the original exchange at its signature, after its commit.
    let release!: () => void;
    const gate = new Promise<void>((r) => {
      release = r;
    });
    let signing!: () => void;
    const held = new Promise<void>((r) => {
      signing = r;
    });
    const sign = as.kernel.signObservation.bind(as.kernel);
    let calls = 0;
    vi.spyOn(as.kernel, "signObservation").mockImplementation(async (observation) => {
      calls += 1;
      if (calls === 1) {
        signing();
        await gate;
      }
      return sign(observation);
    });

    const nonce = `nonce-resume-${crypto.randomUUID()}`;
    const members = { mission_id: m.id, operation: "resume", nonce };
    const original = lifecycleRequest(ISSUER, consoleClient, members);
    await held;
    // The window: the transition and the claim have committed, the response
    // bytes are not yet retained.
    expect(as.kernel.get(m.id)?.state).toBe("active");
    expect(claimState(m.id, nonce)).toBe("committed");

    const retransmit = await lifecycleRequest(ISSUER, consoleClient, members);
    release();
    const first = await original;
    const later = await lifecycleRequest(ISSUER, consoleClient, members);

    // One committed transition.
    const after = as.kernel.get(m.id) as MissionRecord;
    expect(after.state).toBe("active");
    expect(after.version).toBe(before.version + 1);

    // Every answer is the one committed operation's response, the same bytes.
    for (const answer of [first, retransmit, later]) {
      expect(answer.status, answer.text).toBe(200);
      expect(answer.contentType).toContain("application/mission-status-response+jwt");
    }
    expect(retransmit.text).toBe(first.text);
    expect(later.text).toBe(first.text);
    const { payload, mission } = decodeStatusResponse(first.text);
    expect(payload.nonce).toBe(nonce);
    expect(mission.state).toBe("active");
    expect(mission.version).toBe(before.version + 1);
    expect(claimState(m.id, nonce)).toBe("final");
  });
});
