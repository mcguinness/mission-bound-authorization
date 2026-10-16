import { APPROVAL_SUBJECT_HEADER, type ApprovalSessionStore, MISSION_APPROVAL_SCOPE, type ServiceTokenPrincipal } from "../src/index.js";

/**
 * A trusted browser approval (#826): the Approver authenticated in THIS user
 * agent through the trusted login, which records the achieved context and,
 * for an approval on another principal's behalf, the selected Subject. The
 * returned headers carry the interaction cookies plus the approval session.
 */
export function browserApprovalHeaders(
  sessions: ApprovalSessionStore,
  uid: string,
  approver: { sub: string; acr?: string; auth_time?: number; subject?: string },
  interactionCookies: string,
): Record<string, string> {
  const { cookie, csrf } = sessions.establish(uid, {
    sub: approver.sub,
    acr: approver.acr ?? "password",
    auth_time: approver.auth_time ?? Math.floor(Date.now() / 1000),
    ...(approver.subject ? { subject: approver.subject } : {}),
  });
  return { cookie: interactionCookies ? `${interactionCookies}; ${cookie}` : cookie, "x-csrf-token": csrf };
}

/**
 * A high-risk approval (#826, D425): the published approval-authentication
 * floor accepts only an Approver logged in on the browser approval surface
 * with an accepted `acr` (`mfa`) inside its age bound, never a headless
 * approval service. Bob, approving for Alice unless told otherwise; `null`
 * selects no Subject, a self-approval.
 */
export function floorApprovalHeaders(
  sessions: ApprovalSessionStore,
  uid: string,
  interactionCookies: string,
  approver: { sub?: string; subject?: string | null } = {},
): Record<string, string> {
  const subject = approver.subject === undefined ? "alice" : approver.subject;
  return browserApprovalHeaders(
    sessions,
    uid,
    { sub: approver.sub ?? "bob", acr: "mfa", ...(subject !== null ? { subject } : {}) },
    interactionCookies,
  );
}

/** Trusted test driver credential; never part of the client fixture. */
const TOKEN = "test-only-independent-approver-759";
const principal: ServiceTokenPrincipal = {
  principal_id: "svc:test-approver",
  scopes: [MISSION_APPROVAL_SCOPE],
  approver: { sub: "bob", acr: "password", auth_time: Math.floor(Date.now() / 1000) },
};
export const TEST_APPROVAL_PRINCIPALS = { [TOKEN]: principal };

/**
 * Establish achieved context at the trusted fixture, not in decide input.
 * `subject` is the Subject the trusted approval service selects (#826),
 * defaulting to alice, the Subject every fixture flow approved for before
 * `login_hint` stopped selecting it; `null` selects none, a self-approval.
 */
export function trustedApprovalHeaders(
  sub = "bob",
  context: Record<string, unknown> = {},
  subject: string | null = "alice",
): Record<string, string> {
  const time = context.approver_auth_time;
  principal.approver = {
    sub,
    acr: typeof context.approver_acr === "string" ? context.approver_acr : "password",
    auth_time: typeof time === "number" ? time : typeof time === "string" ? Math.floor(Date.parse(time) / 1000) : Math.floor(Date.now() / 1000),
  };
  return { "x-service-token": TOKEN, ...(subject !== null ? { [APPROVAL_SUBJECT_HEADER]: subject } : {}) };
}
