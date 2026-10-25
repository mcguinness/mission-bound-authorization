/**
 * @spec status#mission-status-response (#1682, D795): a Mission Status
 * Response carries `mission.authority_hash` only to a caller the AS
 * authorizes for audit or correlation use, here a client the deployment
 * binds the `provenance` disclosure privilege to. The `mission_status` and
 * `mission_lifecycle` grants confer none, and neither does Join Disclosure
 * enrollment. The rule covers Status reads and lifecycle confirmations, and
 * a retransmitted confirmation replays the bytes first sent.
 */

import type { Server } from "node:http";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import { decodeJwt } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { STATUS_ENDPOINT_PATH } from "../src/adapters/lifecycle-endpoint.js";
import {
  type BuiltAs,
  buildAuthorizationServer,
  MISSION_LIFECYCLE_SCOPE,
  MISSION_STATUS_SCOPE,
  type MissionRecord,
  validateMissionIntent,
} from "../src/index.js";
import {
  CLIENT_ASSERTION_TYPE,
  type LifecycleAnswer,
  type LifecycleTestClient,
  lifecycleClientAssertion,
  lifecycleRequest,
  newLifecycleClient,
  readAnswer,
} from "./lifecycle-endpoint.helper.js";

const PORT = 14971;
const ISSUER = `http://localhost:${PORT}`;
const MISSION_CLIENT = "ap-agent";

let as: BuiltAs;
let server: Server;
/** Holds `mission_status` only. */
let reader: LifecycleTestClient;
/** Holds `mission_status` and `mission_lifecycle`, and no disclosure privilege. */
let operator: LifecycleTestClient;
/** Holds `mission_status`, `mission_lifecycle` and the `provenance` disclosure privilege. */
let auditor: LifecycleTestClient;
/** Holds `mission_status`, enrolled as a PDP for Join Disclosure, and no disclosure privilege. */
let enrolledPdp: LifecycleTestClient;
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
    clientId: MISSION_CLIENT,
    approvalEventId: `apev-authority-hash-disclosure-${approvals}`,
  });
}

const nonce = (): string => `nonce-ahd-${crypto.randomUUID()}`;

/** A Status read naming the canonical audience, by `client`. */
async function read(client: LifecycleTestClient, missionId: string): Promise<LifecycleAnswer> {
  const res = await fetch(`${ISSUER}${STATUS_ENDPOINT_PATH}`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      mission_id: missionId,
      audience: CANONICAL_RESOURCE,
      nonce: nonce(),
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: await lifecycleClientAssertion(ISSUER, client),
    }).toString(),
  });
  return readAnswer(res);
}

/** The signed response's `mission` object. */
function missionOf(answer: LifecycleAnswer): Record<string, unknown> {
  expect(answer.status, answer.text).toBe(200);
  return decodeJwt(answer.text).mission as Record<string, unknown>;
}

beforeAll(async () => {
  reader = await newLifecycleClient("ahd-reader");
  operator = await newLifecycleClient("ahd-operator");
  auditor = await newLifecycleClient("ahd-auditor");
  enrolledPdp = await newLifecycleClient("ahd-enrolled-pdp");
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    testClients: [reader.metadata, operator.metadata, auditor.metadata, enrolledPdp.metadata],
    lifecycleClientGrants: {
      [reader.clientId]: [MISSION_STATUS_SCOPE],
      [operator.clientId]: [MISSION_STATUS_SCOPE, MISSION_LIFECYCLE_SCOPE],
      [auditor.clientId]: { grants: [MISSION_STATUS_SCOPE, MISSION_LIFECYCLE_SCOPE], disclose: ["provenance"] },
      [enrolledPdp.clientId]: [MISSION_STATUS_SCOPE],
    },
    joinEnrollment: { [enrolledPdp.clientId]: { roles: ["pdp"], enforcementScopes: [CANONICAL_RESOURCE] } },
  });
  server = as.provider.listen(PORT);
  await new Promise<void>((r) => server.once("listening", () => r()));
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
});

describe("authority_hash disclosure on Mission Status Responses (@spec status#mission-status-response, #1682, D795)", () => {
  it("omits authority_hash from a Status read by a client holding the read grant, or the read and lifecycle grants, without the disclosure privilege", async () => {
    const m = approve();
    for (const client of [reader, operator]) {
      const mission = missionOf(await read(client, m.id));
      expect(mission.id).toBe(m.id);
      expect(Object.hasOwn(mission, "authority_hash"), client.clientId).toBe(false);
    }
  });

  it("carries authority_hash, the Mission's committed anchor, on a Status read by a client holding the provenance privilege", async () => {
    const m = approve();
    const mission = missionOf(await read(auditor, m.id));
    expect(mission.authority_hash).toBe(m.authority_hash);
  });

  it("gives a PDP enrolled for Join Disclosure its subject and client_id but not authority_hash, absent the privilege", async () => {
    const m = approve();
    const mission = missionOf(await read(enrolledPdp, m.id));
    expect(mission.subject).toEqual({ iss: ISSUER, sub: "alice" });
    expect(mission.client_id).toBe(MISSION_CLIENT);
    expect(Object.hasOwn(mission, "authority_hash")).toBe(false);
  });

  it("omits authority_hash from a lifecycle confirmation to a client without the privilege, and its retransmit replays the same bytes", async () => {
    const m = approve();
    const members = { mission_id: m.id, operation: "suspend", nonce: nonce() };
    const first = await lifecycleRequest(ISSUER, operator, members);
    const mission = missionOf(first);
    expect(mission.state).toBe("suspended");
    expect(Object.hasOwn(mission, "authority_hash")).toBe(false);
    const replay = await lifecycleRequest(ISSUER, operator, members);
    expect(replay.status).toBe(200);
    expect(replay.text).toBe(first.text);
  });

  it("carries authority_hash on a lifecycle confirmation to a client with the privilege, and its retransmit replays the same bytes", async () => {
    const m = approve();
    const members = { mission_id: m.id, operation: "suspend", nonce: nonce() };
    const first = await lifecycleRequest(ISSUER, auditor, members);
    const mission = missionOf(first);
    expect(mission.state).toBe("suspended");
    expect(mission.authority_hash).toBe(m.authority_hash);
    const replay = await lifecycleRequest(ISSUER, auditor, members);
    expect(replay.status).toBe(200);
    expect(replay.text).toBe(first.text);
  });

  it("refuses a configuration that names an unknown disclosure privilege", async () => {
    await expect(
      buildAuthorizationServer({
        issuer: "http://localhost:14972",
        lifecycleClientGrants: { "some-client": { grants: [MISSION_STATUS_SCOPE], disclose: ["audit"] } },
      }),
    ).rejects.toThrow(/unknown disclosure privilege audit/);
  });
});
