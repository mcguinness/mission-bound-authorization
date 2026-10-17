/**
 * @spec mission#approval-authentication (#826, D425) — the demo approval
 * console presents its Approver's recorded login, the `acr` and time of a
 * login that happened earlier, and never records one at an approval. So the
 * context ages: the approval-authentication floor refuses a high-risk
 * approval once the login is older than the floor allows, until the Approver
 * logs in again. The demo's direct kernel approvals check the same floor
 * against the same recorded login. The login is simulated (the demo has no
 * Approver identity provider) and is not acceptance evidence.
 */
import type { Server } from "node:http";
import { ApprovalSessionStore, buildAuthorizationServer } from "@mission/authorization-server";
import { APPROVAL_FLOOR, CANONICAL_RESOURCE } from "@mission/demo-data";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type ApprovalConsole, issueMissionToken, logInAgain, recordApproverLogin } from "../src/approval-console.js";
import type { IssueOpts } from "../src/oauth-client.js";
import { assertDemoApprovalFloor, type DemoStack } from "../src/stack.js";

const PORT = 14962;
const ISSUER = `http://localhost:${PORT}`;
const MAX_AGE = APPROVAL_FLOOR.floors[0]?.max_authentication_age_seconds as number;
const REMIT: IssueOpts = {
  missionIntent: JSON.stringify({
    intent: { goal: "Send the Acme remittance", target_resources: [CANONICAL_RESOURCE], expires_at: "2027-01-01T00:00:00Z" },
  }),
  authorizationDetails: JSON.stringify([
    {
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:invoice.read", "payments:remittance.send"],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    },
  ]),
};
const sessions = new ApprovalSessionStore();
let as: Awaited<ReturnType<typeof buildAuthorizationServer>>;
let server: Server;

beforeAll(async () => {
  as = await buildAuthorizationServer({ issuer: ISSUER, approvalSessions: sessions });
  server = as.provider.listen(PORT);
});
afterAll(() => server?.close());

const now = () => Math.floor(Date.now() / 1000);

describe("the demo approval console presents a recorded login, never one stamped at the approval (@spec mission#approval-authentication, #826, D425)", () => {
  it("a high-risk approval from a login older than the floor's age bound refuses and leaves the recorded login unchanged; after a new login it completes", async () => {
    const login = recordApproverLogin({ sub: "bob", acr: "mfa" }, now() - MAX_AGE - 5);
    const recorded = login.auth_time;
    const console_: ApprovalConsole = { sessions, login };
    await expect(issueMissionToken(ISSUER, as.agentClientJwk, REMIT, console_)).rejects.toThrow(
      /approval did not yield a code: access_denied/,
    );
    expect(login.auth_time).toBe(recorded);
    logInAgain(login);
    const issued = await issueMissionToken(ISSUER, as.agentClientJwk, REMIT, console_);
    expect(issued.accessToken).toBeTruthy();
    expect(login.auth_time).toBeGreaterThan(recorded);
  });

  it("a demo approval that goes straight to the kernel meets the floor against the stack's recorded login", () => {
    const login = recordApproverLogin({ sub: "bob", acr: "mfa" }, now() - MAX_AGE - 5);
    const stack = { approverLogin: login, kernel: as.kernel } as unknown as DemoStack;
    const remit = [{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:remittance.send"] }];
    expect(() => assertDemoApprovalFloor(stack, remit)).toThrow(/older than the high-risk-authority floor allows/);
    logInAgain(login);
    expect(() => assertDemoApprovalFloor(stack, remit)).not.toThrow();
  });
});
