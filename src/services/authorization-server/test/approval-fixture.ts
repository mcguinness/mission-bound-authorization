import { MISSION_APPROVAL_SCOPE, type ServiceTokenPrincipal } from "../src/index.js";

/** Trusted test driver credential; never part of the client fixture. */
const TOKEN = "test-only-independent-approver-759";
const principal: ServiceTokenPrincipal = {
  principal_id: "svc:test-approver",
  scopes: [MISSION_APPROVAL_SCOPE],
  approver: { sub: "bob", acr: "password", auth_time: Math.floor(Date.now() / 1000) },
};
export const TEST_APPROVAL_PRINCIPALS = { [TOKEN]: principal };

/** Establish achieved context at the trusted fixture, not in decide input. */
export function trustedApprovalHeaders(sub = "bob", context: Record<string, unknown> = {}): Record<string, string> {
  const time = context.approver_auth_time;
  principal.approver = {
    sub,
    acr: typeof context.approver_acr === "string" ? context.approver_acr : "password",
    auth_time: typeof time === "number" ? time : typeof time === "string" ? Math.floor(Date.parse(time) / 1000) : Math.floor(Date.now() / 1000),
  };
  return { "x-service-token": TOKEN };
}
