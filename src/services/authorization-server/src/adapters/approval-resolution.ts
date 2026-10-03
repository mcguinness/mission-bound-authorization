import { randomBytes } from "node:crypto";

export const MISSION_APPROVAL_SCOPE = "mission_approval";
export const APPROVAL_SESSION_COOKIE = "mission_approver_session";
/**
 * @spec mission#approval-event (step 2): the header on which a trusted
 * headless approval service names the Subject it resolved for an approval on
 * another principal's behalf. Honored only on a request authenticated as such
 * a service; never a client parameter (#826).
 */
export const APPROVAL_SUBJECT_HEADER = "x-approval-subject";

/**
 * Achieved context established by the trusted login/service registration.
 * `subject` is the Subject that same authenticated surface selected for an
 * approval on another principal's behalf (an administrative selection,
 * @spec mission#approval-event step 2): absent, the approval is a
 * self-approval and the Subject is `sub`. It is never taken from the client:
 * `login_hint` concerns the Approver (#826).
 */
export interface ApprovalPrincipal { sub: string; acr: string; auth_time: number; subject?: string }

export function validApprovalPrincipal(value: unknown): value is ApprovalPrincipal {
  if (!value || typeof value !== "object") return false;
  const p = value as Record<string, unknown>;
  return typeof p.sub === "string" && p.sub.length > 0 &&
    typeof p.acr === "string" && p.acr.length > 0 &&
    Number.isSafeInteger(p.auth_time) && (p.auth_time as number) >= 0 &&
    (p.subject === undefined || (typeof p.subject === "string" && p.subject.length > 0));
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
    const session = this.sessionFor(cookie, uid);
    if (!session || !csrf || csrf !== session.csrf) return undefined;
    return { ...session.principal };
  }

  /**
   * The Subject the session for this interaction selected (its own `sub` for
   * a self-approval), for the read-only approval rendering. No CSRF: it
   * changes nothing and authorizes nothing; the decision re-resolves the
   * session with its CSRF secret.
   */
  subjectFor(cookie: string, uid: string): string | undefined {
    const session = this.sessionFor(cookie, uid);
    return session ? (session.principal.subject ?? session.principal.sub) : undefined;
  }

  private sessionFor(cookie: string, uid: string): { uid: string; principal: ApprovalPrincipal; csrf: string } | undefined {
    const tokens = cookie.split(";").map(s => s.trim()).filter(s => s.startsWith(`${APPROVAL_SESSION_COOKIE}=`));
    if (tokens.length !== 1) return undefined;
    const token = tokens[0]!.slice(APPROVAL_SESSION_COOKIE.length + 1);
    const session = this.sessions.get(token);
    if (!session) return undefined;
    if (session.expires <= this.now()) { this.sessions.delete(token); return undefined; }
    if (uid !== session.uid) return undefined;
    return session;
  }
}
