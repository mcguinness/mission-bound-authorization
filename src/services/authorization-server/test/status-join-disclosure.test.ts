/**
 * @spec draft-mcguinness-mission-authority-server (#join-disclosure),
 * draft-mcguinness-oauth-mission-status (#mission-status-response)
 *
 * Join Disclosure on the Mission Status operation (#818): a PDP enrolled for
 * the Mission's enforcement scope reads the Mission's `subject` and
 * `client_id` in the `mission` object, with every audience-scoped entry's
 * recorded `delegation`; every other caller reads neither member, and its
 * response is the one the operation served before enrollment existed.
 * Enrollment is the AS's `enrolledJoinPdps` configuration, keyed by the
 * authenticated service principal and the requested `audience`.
 */

import type { Server } from "node:http";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import { decodeJwt, decodeProtectedHeader } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  type BuiltAs,
  buildAuthorizationServer,
  MISSION_STATUS_SCOPE,
  type MissionRecord,
  validateMissionIntent,
} from "../src/index.js";

const PORT = 14826;
const ISSUER = `http://localhost:${PORT}`;
/** A fixed kernel clock, so two observations of one Mission carry the same `iat`, `exp` and `fresh_until`. */
const NOW = new Date("2026-10-19T12:00:00Z");
const OTHER_SCOPE = "https://other.example/api";

/** The joining PDP: enrolled for the payments enforcement scope only. */
const PDP_TOKEN = "join-disclosure-pdp-token";
const PDP = "svc:joining-pdp";
/** A Status reader holding the same grant, enrolled for nothing. */
const READER_TOKEN = "join-disclosure-reader-token";
const READER = "svc:status-reader";
/** A principal whose identifier is an inherited `Object.prototype` name. */
const INHERITED_TOKEN = "join-disclosure-inherited-token";

let as: BuiltAs;
let server: Server;

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    now: () => NOW,
    serviceTokenPrincipals: {
      [PDP_TOKEN]: { principal_id: PDP, scopes: [MISSION_STATUS_SCOPE] },
      [READER_TOKEN]: { principal_id: READER, scopes: [MISSION_STATUS_SCOPE] },
      [INHERITED_TOKEN]: { principal_id: "constructor", scopes: [MISSION_STATUS_SCOPE] },
    },
    enrolledJoinPdps: { [PDP]: [CANONICAL_RESOURCE] },
  });
  server = as.provider.listen(PORT);
});

afterAll(() => {
  server?.close();
});

/** A Mission for alice under ap-agent, its one entry delegable as recorded. */
function approve(): MissionRecord {
  return as.kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({ goal: "Read Acme invoices", target_resources: [CANONICAL_RESOURCE], expires_at: "2027-01-01T00:00:00Z" }),
    ),
    proposedAuthority: [
      {
        type: "mission_resource_access",
        resource: CANONICAL_RESOURCE,
        actions: ["payments:invoice.read"],
        constraints: { vendors: ["acme"] },
        delegation: { max_depth: 1, allowed_delegates: [{ sub_profile: "ai_agent" }] },
      },
    ],
    subject: { iss: ISSUER, sub: "alice" },
    approver: { iss: ISSUER, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-join-disclosure-${Math.random().toString(36).slice(2)}`,
  });
}

async function status(missionId: string, token: string, audience?: string): Promise<{ code: number; jws: string }> {
  const query = audience === undefined ? "" : `?audience=${encodeURIComponent(audience)}`;
  const res = await fetch(`${ISSUER}/missions/${missionId}/status${query}`, { headers: { "x-service-token": token } });
  return { code: res.status, jws: await res.text() };
}

const missionOf = (jws: string) => (decodeJwt(jws) as { mission: Record<string, unknown> }).mission;

describe("Join Disclosure on Mission Status (@spec authority-server#join-disclosure)", () => {
  it("discloses subject, client_id and each entry's recorded delegation to a PDP enrolled for the requested enforcement scope", async () => {
    const record = approve();
    const recorded = record.authority_set[0]?.delegation;
    expect(recorded).toBeDefined();

    const enrolled = await status(record.id, PDP_TOKEN, CANONICAL_RESOURCE);
    expect(enrolled.code).toBe(200);
    const payload = decodeJwt(enrolled.jws) as {
      mission: Record<string, unknown>;
      authorization_details: Array<Record<string, unknown>>;
    };
    expect(payload.mission.subject).toEqual({ iss: ISSUER, sub: "alice" });
    expect(payload.mission.client_id).toBe("ap-agent");
    expect(payload.authorization_details.length).toBeGreaterThan(0);
    for (const entry of payload.authorization_details) expect(entry.delegation).toEqual(recorded);

    // The two members are the whole difference from a response to any other
    // caller for the same scope at the same instant.
    const other = await status(record.id, READER_TOKEN, CANONICAL_RESOURCE);
    const { subject: _subject, client_id: _clientId, ...rest } = payload.mission;
    expect({ ...payload, mission: rest }).toEqual(decodeJwt(other.jws));
  });

  it("includes neither member for any other caller: a principal enrolled for nothing, the enrolled PDP for another scope or for no scope, an inherited-name principal", async () => {
    const record = approve();
    const cases: Array<[string, string, string | undefined]> = [
      ["not enrolled", READER_TOKEN, CANONICAL_RESOURCE],
      ["enrolled for another scope", PDP_TOKEN, OTHER_SCOPE],
      ["enrolled, no scope named", PDP_TOKEN, undefined],
      ["inherited principal name", INHERITED_TOKEN, CANONICAL_RESOURCE],
    ];
    for (const [label, token, audience] of cases) {
      const res = await status(record.id, token, audience);
      expect(res.code, label).toBe(200);
      const mission = missionOf(res.jws);
      expect(mission.id, label).toBe(record.id);
      expect("subject" in mission, label).toBe(false);
      expect("client_id" in mission, label).toBe(false);
    }
  });

  it("serves a caller not enrolled the response the kernel's default observation signs, byte for byte", async () => {
    const record = approve();
    const served = await status(record.id, READER_TOKEN, CANONICAL_RESOURCE);
    expect(served.code).toBe(200);
    // ES256 signatures differ per signing; the signing input (protected
    // header and payload) is what the response asserts.
    const unchanged = await as.kernel.signedStatus(record.id, { audience: CANONICAL_RESOURCE, requester: READER });
    expect(served.jws.split(".").slice(0, 2)).toEqual(unchanged.split(".").slice(0, 2));
    expect(decodeProtectedHeader(served.jws).typ).toBe("mission-status-response+jwt");
  });

  it("authenticates before anything else: an unauthenticated request is refused 401 with no Mission member", async () => {
    const record = approve();
    const res = await fetch(`${ISSUER}/missions/${record.id}/status?audience=${encodeURIComponent(CANONICAL_RESOURCE)}`);
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "unauthorized" });
  });
});
