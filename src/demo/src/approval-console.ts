/** Trusted exhibit/console driver. Never imported by the agent OAuth helper. */
import { jarClosures, redeemMissionApproval, submitMissionApproval, type CookieJar, type IssueOpts, type SubmittedApproval } from "./oauth-client.js";

export async function resolveMissionApproval(asUrl: string, approverToken: string, pending: { uid: string; jar: CookieJar }, decision: "approve" | "deny"): Promise<string | undefined> {
  const { cookieHeader, storeCookies } = jarClosures(pending.jar);
  let res = await fetch(`${asUrl}/interaction/${pending.uid}/decide`, {
    method: "POST", redirect: "manual",
    headers: { "content-type": "application/json", cookie: cookieHeader(), "x-service-token": approverToken },
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

export async function completeMissionApproval(asUrl: string, clientKey: Record<string, unknown>, pending: { uid: string; jar: CookieJar; par?: SubmittedApproval["par"] }, approverToken: string) {
  const code = await resolveMissionApproval(asUrl, approverToken, pending, "approve");
  return redeemMissionApproval(asUrl, clientKey, { code: code!, ...(pending.par ? { par: pending.par } : {}) });
}

export async function denyMissionApproval(asUrl: string, pending: { uid: string; jar: CookieJar }, approverToken: string): Promise<void> {
  await resolveMissionApproval(asUrl, approverToken, pending, "deny");
}

/** Trusted driver orchestrates distinct client and approver roles before handing off a token. */
export async function issueMissionToken(asUrl: string, clientKey: Record<string, unknown>, opts: IssueOpts, approverToken: string) {
  const pending = await submitMissionApproval(asUrl, clientKey, opts);
  return completeMissionApproval(asUrl, clientKey, pending, approverToken);
}
