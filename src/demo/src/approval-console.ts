/** Trusted exhibit/console driver. Never imported by the agent OAuth helper. */
import { APPROVAL_SUBJECT_HEADER, type ApprovalSessionStore } from "@mission/authorization-server";
import { jarClosures, redeemMissionApproval, submitMissionApproval, type CookieJar, type IssueOpts, type SubmittedApproval } from "./oauth-client.js";

/**
 * The console's Approver on the AS's trusted browser approval surface (#826,
 * D425). Each approval logs the Approver in through the AS's trusted login
 * store, which records the `acr` that login achieved and the time it
 * happened, bound to the one interaction. The approval-authentication floor
 * accepts only such a login: a headless approval service's registration is
 * not an authentication of the Approver. The demo has no Approver identity
 * provider, so the console stands in for the trusted login integration and
 * records a login at the moment it approves; a deployment calls `establish`
 * from its real login. The floor's evidence here is structural (the browser
 * surface, a per-interaction context, the age bound), not a claim that the
 * demo authenticated a person.
 */
export interface ApprovalConsole {
  sessions: ApprovalSessionStore;
  approver: { sub: string; acr: string };
}

/** How the console authenticates: a browser login, or a headless approval service token. */
export type ApproverCredential = ApprovalConsole | string;

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
  } else {
    const login = approver.sessions.establish(pending.uid, {
      sub: approver.approver.sub,
      acr: approver.approver.acr,
      auth_time: Math.floor(Date.now() / 1000),
      ...(subject !== null ? { subject } : {}),
    });
    const interaction = cookieHeader();
    identity = { cookie: interaction ? `${interaction}; ${login.cookie}` : login.cookie, "x-csrf-token": login.csrf };
  }
  let res = await fetch(`${asUrl}/interaction/${pending.uid}/decide`, {
    method: "POST", redirect: "manual",
    headers: { "content-type": "application/json", ...identity },
    body: JSON.stringify({ decision }),
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
