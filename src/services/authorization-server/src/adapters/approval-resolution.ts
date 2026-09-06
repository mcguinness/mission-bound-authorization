import { randomBytes } from "node:crypto";

export const MISSION_APPROVAL_SCOPE = "mission_approval";
export const APPROVAL_SESSION_COOKIE = "mission_approver_session";

/** Achieved context established by the trusted login/service registration. */
export interface ApprovalPrincipal { sub: string; acr: string; auth_time: number }

export function validApprovalPrincipal(value: unknown): value is ApprovalPrincipal {
  if (!value || typeof value !== "object") return false;
  const p = value as Record<string, unknown>;
  return typeof p.sub === "string" && p.sub.length > 0 &&
    typeof p.acr === "string" && p.acr.length > 0 &&
    Number.isSafeInteger(p.auth_time) && (p.auth_time as number) >= 0;
}

/**
 * Trusted-login integration, never an HTTP login or agent-callable API.
 * The OAuth interaction cookie is NOT an approver login: it is also held by
 * the initiating client. A separate login establishes this interaction-bound
 * session, with achieved context retained server-side and a CSRF secret.
 */
export class ApprovalSessionStore {
  private readonly sessions = new Map<string, { uid: string; principal: ApprovalPrincipal; csrf: string; expires: number }>();
  constructor(private readonly now = () => Date.now()) {}

  establish(uid: string, principal: ApprovalPrincipal, lifetimeMs = 300_000): { cookie: string; csrf: string } {
    if (!uid || !validApprovalPrincipal(principal) || lifetimeMs <= 0 || !Number.isFinite(lifetimeMs)) throw new Error("invalid approval login");
    const token = randomBytes(32).toString("base64url");
    const csrf = randomBytes(32).toString("base64url");
    this.sessions.set(token, { uid, principal: { ...principal }, csrf, expires: this.now() + lifetimeMs });
    return { cookie: `${APPROVAL_SESSION_COOKIE}=${token}`, csrf };
  }

  resolve(cookie: string, csrf: string, uid: string): ApprovalPrincipal | undefined {
    const tokens = cookie.split(";").map(s => s.trim()).filter(s => s.startsWith(`${APPROVAL_SESSION_COOKIE}=`));
    if (tokens.length !== 1) return undefined;
    const token = tokens[0]!.slice(APPROVAL_SESSION_COOKIE.length + 1);
    const session = this.sessions.get(token);
    if (!session) return undefined;
    if (session.expires <= this.now()) { this.sessions.delete(token); return undefined; }
    if (!csrf || csrf !== session.csrf || uid !== session.uid) return undefined;
    return { ...session.principal };
  }
}
