/** Trusted exhibit/console driver. Never imported by the agent OAuth helper. */
import { APPROVAL_SUBJECT_HEADER, type ApprovalSessionStore, RENDER_REVISION_HEADER } from "@mission/authorization-server";
import type { ApproverAccount } from "./approver-idp.js";
import { jarClosures, redeemMissionApproval, submitMissionApproval, type CookieJar, type IssueOpts, type SubmittedApproval } from "./oauth-client.js";

/** The console Approver's recorded login: who, the `acr` that login achieved, and when it happened. */
export interface ApproverLogin {
  sub: string;
  acr: string;
  auth_time: number;
}

/**
 * Record a login by the console's Approver, at the moment the login happens
 * (#826, D425). The shared demo composition has no Approver identity
 * provider, so this stands in for a deployment's login integration: it
 * records the `acr` the demo configures and the current time. It is called
 * at a login (stack composition, or the demo server's explicit login route),
 * never at an approval. The login is simulated, so it is not evidence that a
 * person authenticated. The as-native target logs its Approver in through an
 * upstream provider instead ({@link UpstreamApprovalConsole}, #1320).
 */
export function recordApproverLogin(approver: { sub: string; acr: string }, at = Math.floor(Date.now() / 1000)): ApproverLogin {
  return { sub: approver.sub, acr: approver.acr, auth_time: at };
}

/** A new login by the same Approver, updating the recorded login in place. No approval calls it. */
export function logInAgain(login: ApproverLogin, at = Math.floor(Date.now() / 1000)): void {
  login.auth_time = at;
}

/**
 * The console's Approver on the AS's trusted browser approval surface (#826,
 * D425). Every approval presents the recorded login unchanged, its `acr` and
 * the time it happened, bound to the one interaction through the AS's trusted
 * login store. An approval never records a login, so the context ages: the
 * approval-authentication floor refuses it once it is older than the floor
 * allows, until the Approver logs in again. A headless approval service's
 * registration is not an authentication of the Approver.
 */
export interface ApprovalConsole {
  sessions: ApprovalSessionStore;
  login: ApproverLogin;
}

/**
 * @spec mission#approval-authentication (#1320, D496): the console's
 * Approver logging in, in the Approver's own user agent, through the AS's
 * approval surface to the upstream OpenID Provider (`approver-idp.ts`), at
 * each approval: the account's password, then the one-time code its
 * enrolled device receives, or no second factor (`secondFactor: "skip"`,
 * which the provider asserts as a password-only login). The AS records the
 * `acr` and `auth_time` of the ID Token it validates; nothing here supplies
 * them.
 */
export interface UpstreamApprovalConsole {
  upstream: { account: ApproverAccount; secondFactor: "code" | "skip" };
}

/** How the console authenticates: a recorded or upstream browser login, or a headless approval service token. */
export type ApproverCredential = ApprovalConsole | UpstreamApprovalConsole | string;

/**
 * The Approver's login for approval interaction `uid` through the upstream
 * provider, selecting `subject` (`null`: a self-approval). Two user-agent
 * cookie jars, one per origin, as a browser keeps them. Returns the approval
 * session's cookie and its CSRF secret, from the AS's callback page.
 */
export async function logInUpstream(
  asUrl: string,
  uid: string,
  approver: UpstreamApprovalConsole,
  subject: string | null,
): Promise<{ cookie: string; csrf: string }> {
  const { account, secondFactor } = approver.upstream;
  const asJar: CookieJar = new Map();
  const idpJar: CookieJar = new Map();
  const at = jarClosures(asJar);
  const idp = jarClosures(idpJar);
  const query = subject !== null ? `?${new URLSearchParams({ subject })}` : "";
  let res = await fetch(`${asUrl}/interaction/${uid}/approver-login${query}`, {
    redirect: "manual",
    headers: { cookie: at.cookieHeader() },
  });
  if (res.status !== 303) throw new Error(`approver login did not start: ${res.status} ${await res.text()}`);
  at.storeCookies(res);
  const authorize = new URL(res.headers.get("location") as string);
  const origin = authorize.origin;
  // The provider's authorization endpoint sends the user agent to its login.
  res = await fetch(authorize, { redirect: "manual", headers: { cookie: idp.cookieHeader() } });
  idp.storeCookies(res);
  const loginPage = new URL(res.headers.get("location") ?? "", origin);
  const form = (step: string, body: Record<string, string>) =>
    fetch(new URL(`${loginPage.pathname}/${step}`, origin), {
      method: "POST",
      redirect: "manual",
      headers: { "content-type": "application/x-www-form-urlencoded", cookie: idp.cookieHeader() },
      body: new URLSearchParams(body).toString(),
    });
  res = await form("password", { username: account.username, password: account.password });
  if (res.status !== 200) throw new Error(`approver login refused the password: ${res.status}`);
  if (secondFactor === "code") {
    const code = account.device.latest();
    if (!code) throw new Error("the approver's device received no code");
    res = await form("code", { code });
  } else {
    res = await form("skip", {});
  }
  idp.storeCookies(res);
  let location = res.headers.get("location");
  while (location && new URL(location, origin).origin === origin) {
    res = await fetch(new URL(location, origin), { redirect: "manual", headers: { cookie: idp.cookieHeader() } });
    idp.storeCookies(res);
    location = res.headers.get("location");
  }
  if (!location || new URL(location).origin !== new URL(asUrl).origin) throw new Error("approver login did not return to the AS");
  res = await fetch(location, { redirect: "manual", headers: { cookie: at.cookieHeader() } });
  at.storeCookies(res);
  const page = await res.text();
  if (res.status !== 200) throw new Error(`approver login refused: ${res.status} ${page}`);
  const csrf = /name="mission-approval-csrf" content="([^"]+)"/.exec(page)?.[1];
  const session = asJar.get("mission_approver_session");
  if (!csrf || !session) throw new Error("approver login established no approval session");
  return { cookie: `mission_approver_session=${session}`, csrf };
}

/**
 * @spec mission#approval-context-changes (#1446, D583): the response header
 * carrying the revision of an approval page the AS rendered to an
 * authenticated principal.
 */
export const APPROVAL_RENDER_REVISION_HEADER = RENDER_REVISION_HEADER;

/**
 * Render an interaction's approval page to the principal `headers`
 * authenticate (an approval session, or the trusted approval service with
 * the Subject it names), as the Approver reviews it before deciding, and
 * return the rendering's revision, which an approval names. Undefined where
 * the AS rendered none for that principal; the decision is then refused.
 */
export async function renderApproval(asUrl: string, uid: string, headers: Record<string, string>): Promise<string | undefined> {
  const page = await fetch(`${asUrl}/interaction/${uid}`, { redirect: "manual", headers });
  await page.text();
  return page.headers.get(APPROVAL_RENDER_REVISION_HEADER) ?? undefined;
}

/**
 * The trusted console resolves an approval. `subject` is the Subject the
 * console selects for an approval on another principal's behalf (#826): the
 * demo's approver Bob approves for Alice; `null` is a self-approval. The
 * agent's PAR never names it.
 */
export async function resolveMissionApproval(asUrl: string, approver: ApproverCredential, pending: { uid: string; jar: CookieJar }, decision: "approve" | "deny", subject: string | null = "alice"): Promise<string | undefined> {
  const { cookieHeader, storeCookies } = jarClosures(pending.jar);
  let identity: Record<string, string>;
  if (typeof approver === "string") {
    identity = { cookie: cookieHeader(), "x-service-token": approver, ...(subject !== null ? { [APPROVAL_SUBJECT_HEADER]: subject } : {}) };
  } else if ("upstream" in approver) {
    const login = await logInUpstream(asUrl, pending.uid, approver, subject);
    const interaction = cookieHeader();
    identity = { cookie: interaction ? `${interaction}; ${login.cookie}` : login.cookie, "x-csrf-token": login.csrf };
  } else {
    const login = approver.sessions.establish(pending.uid, {
      sub: approver.login.sub,
      acr: approver.login.acr,
      auth_time: approver.login.auth_time,
      ...(subject !== null ? { subject } : {}),
    });
    const interaction = cookieHeader();
    identity = { cookie: interaction ? `${interaction}; ${login.cookie}` : login.cookie, "x-csrf-token": login.csrf };
  }
  // An approval names the page rendered to this same principal (#1446), so
  // the console renders it first; a denial needs no rendering.
  const render_revision = decision === "approve" ? await renderApproval(asUrl, pending.uid, identity) : undefined;
  let res = await fetch(`${asUrl}/interaction/${pending.uid}/decide`, {
    method: "POST", redirect: "manual",
    headers: { "content-type": "application/json", ...identity },
    body: JSON.stringify({ decision, ...(render_revision ? { render_revision } : {}) }),
  });
  if (res.status >= 400) throw new Error(`approval resolution refused: ${res.status}`);
  storeCookies(res);
  let location = res.headers.get("location");
  while (location && new URL(location, asUrl).origin === new URL(asUrl).origin) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookieHeader() } });
    storeCookies(res);
    location = res.headers.get("location");
  }
  if (!location || new URL(location).origin !== "http://localhost:9999") throw new Error("approval did not finish at the registered redirect");
  const result = new URL(location).searchParams;
  if (decision === "deny") {
    if (result.get("error") !== "access_denied") throw new Error("denial did not complete");
    return undefined;
  }
  const code = result.get("code");
  if (!code) throw new Error(`approval did not yield a code: ${result.get("error")}`);
  return code;
}

export async function completeMissionApproval(asUrl: string, clientKey: Record<string, unknown>, pending: { uid: string; jar: CookieJar; par?: SubmittedApproval["par"] }, approver: ApproverCredential) {
  const code = await resolveMissionApproval(asUrl, approver, pending, "approve");
  return redeemMissionApproval(asUrl, clientKey, { code: code!, ...(pending.par ? { par: pending.par } : {}) });
}

export async function denyMissionApproval(asUrl: string, pending: { uid: string; jar: CookieJar }, approver: ApproverCredential): Promise<void> {
  await resolveMissionApproval(asUrl, approver, pending, "deny");
}

/** Trusted driver orchestrates distinct client and approver roles before handing off a token. */
export async function issueMissionToken(asUrl: string, clientKey: Record<string, unknown>, opts: IssueOpts, approver: ApproverCredential) {
  const pending = await submitMissionApproval(asUrl, clientKey, opts);
  return completeMissionApproval(asUrl, clientKey, pending, approver);
}
