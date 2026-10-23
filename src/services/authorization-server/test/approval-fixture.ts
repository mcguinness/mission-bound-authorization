import { APPROVAL_SUBJECT_HEADER, type ApprovalSessionStore, MISSION_APPROVAL_SCOPE, type ServiceTokenPrincipal } from "../src/index.js";
import { RENDER_REVISION_HEADER } from "../src/adapters/approval-render-revision.js";

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
 * The suite's one recorded Approver login (#826, D425): Bob logged in with
 * `mfa` when this module loaded, once per test file. Approvals consume it and
 * never reset it, so it ages like a real login; a suite runs well inside the
 * floor's 300-second bound.
 */
export const FIXTURE_LOGIN_TIME = Math.floor(Date.now() / 1000);

/** That login as an expansion approval's achieved context (the trusted integration's record). */
export const FIXTURE_BROWSER_LOGIN = { surface: "browser" as const, acr: "mfa", auth_time: FIXTURE_LOGIN_TIME };

/**
 * A high-risk approval (#826, D425): the published approval-authentication
 * floor accepts only an Approver logged in on the browser approval surface
 * with an accepted `acr` (`mfa`) inside its age bound, never a headless
 * approval service. Bob, approving for Alice unless told otherwise; `null`
 * selects no Subject, a self-approval. The context is the suite's recorded
 * login ({@link FIXTURE_LOGIN_TIME}), never a time stamped at the approval.
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
    { sub: approver.sub ?? "bob", acr: "mfa", auth_time: FIXTURE_LOGIN_TIME, ...(subject !== null ? { subject } : {}) },
    interactionCookies,
  );
}

/**
 * @spec mission#approval-context-changes (#1446, D583): render the approval
 * page to the principal `headers` authenticate (an approval session's cookie,
 * or the trusted headless service with its Subject), as an Approver reviews it
 * before deciding, and return the rendering's revision. An approval names it
 * (`render_revision`); without the latest one, no decision approves.
 */
export async function renderedRevision(issuer: string, uid: string, headers: Record<string, string>): Promise<string> {
  const { "content-type": _type, ...rendering } = headers;
  const res = await fetch(`${issuer}/interaction/${uid}`, { headers: rendering });
  const revision = res.headers.get(RENDER_REVISION_HEADER);
  if (res.status !== 200 || !revision) {
    throw new Error(`no approval rendering for ${uid}: ${res.status} ${(await res.text()).slice(0, 200)}`);
  }
  return revision;
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
