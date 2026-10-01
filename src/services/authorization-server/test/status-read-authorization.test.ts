/**
 * @spec draft-mcguinness-oauth-mission-status (#mission-status-authentication,
 * #mission-status-anti-oracle, #mission-status-errors)
 *
 * The Mission Status operation's explicit READ authorization: an authenticated
 * caller must also carry the `mission_status` grant. A caller without it is
 * refused with the same not-found body an unknown Mission gets, so the refusal
 * reveals nothing about whether the Mission exists. The same check decides a
 * forwarded discharge's response shape (discharge-carryover.test.ts).
 */

import type { Server } from "node:http";
import { CANONICAL_RESOURCE, DEV_SERVICE_TOKEN } from "@mission/demo-data";
import { decodeJwt } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  type BuiltAs,
  buildAuthorizationServer,
  MISSION_DISCHARGE_SCOPE,
  MISSION_LIFECYCLE_SCOPE,
  MISSION_STATUS_SCOPE,
  type MissionRecord,
  validateMissionIntent,
} from "../src/index.js";

const PORT = 14559;
const ISSUER = `http://localhost:${PORT}`;

/** Authenticated, holding every operational grant EXCEPT the Status read. */
const NO_READ_TOKEN = "dev-no-status-read-token";
/** Authenticated, holding the Status read grant and nothing else. */
const READ_ONLY_TOKEN = "dev-status-read-only-token";

let as: BuiltAs;
let server: Server;

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: {
      [NO_READ_TOKEN]: {
        principal_id: "svc:no-status-read",
        scopes: [MISSION_LIFECYCLE_SCOPE, MISSION_DISCHARGE_SCOPE],
      },
      [READ_ONLY_TOKEN]: { principal_id: "svc:status-reader", scopes: [MISSION_STATUS_SCOPE] },
    },
  });
  server = as.provider.listen(PORT);
});

afterAll(() => {
  server?.close();
});

function approve(): MissionRecord {
  return as.kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({
        goal: "Read Acme invoices",
        target_resources: [CANONICAL_RESOURCE],
        expires_at: "2027-01-01T00:00:00Z",
      }),
    ),
    proposedAuthority: [
      {
        type: "mission_resource_access",
        resource: CANONICAL_RESOURCE,
        actions: ["payments:invoice.read"],
        constraints: { vendors: ["acme"] },
      },
    ],
    subject: { iss: ISSUER, sub: "alice" },
    approver: { iss: ISSUER, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-status-read-${Math.random().toString(36).slice(2)}`,
  });
}

const status = (missionId: string, token: string, nonce: string): Promise<Response> =>
  fetch(`${ISSUER}/missions/${missionId}/status?nonce=${nonce}`, {
    headers: { "x-service-token": token },
  });

describe("the Mission Status read authorization (@spec status#mission-status-authentication)", () => {
  it("refuses an authenticated caller without mission_status with the indistinguishable not-found body, and serves one that holds it", async () => {
    const record = approve();
    // Without the read grant: the same body an unknown Mission gets.
    const refused = await status(record.id, NO_READ_TOKEN, "n-refused");
    const unknown = await status("msn_does_not_exist_0000000000", DEV_SERVICE_TOKEN, "n-refused");
    expect(refused.status).toBe(404);
    expect(unknown.status).toBe(404);
    const refusedBody = await refused.json();
    expect(refusedBody).toEqual(await unknown.json());
    expect(refusedBody).toEqual({
      error: "not_found",
      error_description: "Mission reference is not found or not visible.",
      nonce: "n-refused",
    });
    // With it (alone, or beside other grants): the signed Status response.
    for (const token of [READ_ONLY_TOKEN, DEV_SERVICE_TOKEN]) {
      const served = await status(record.id, token, `n-served-${token.length}`);
      expect(served.status).toBe(200);
      expect(served.headers.get("content-type")).toBe("application/mission-status-response+jwt");
      const payload = decodeJwt(await served.text()) as Record<string, unknown>;
      expect((payload.mission as Record<string, unknown>).id).toBe(record.id);
    }
  });
});
