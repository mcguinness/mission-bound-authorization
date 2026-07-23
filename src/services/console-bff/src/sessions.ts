/**
 * @spec D35 (BFF topology), D40 (trusted base)
 *
 * Browser session management for the approver and operator consoles. Sessions
 * are opaque, HttpOnly-cookie-bound, and carry the persona's roles. Every
 * state-changing operation requires a matching CSRF token and a role check.
 * The BFF is the only holder of the downstream service credentials.
 */

import { randomBytes } from "node:crypto";

export type Role = "approver" | "operator";

export interface Session {
  id: string;
  sub: string;
  roles: Role[];
  csrf: string;
}

export class SessionStore {
  private readonly sessions = new Map<string, Session>();

  /** Establish a session for an authenticated persona (auth is upstream/SSO). */
  create(sub: string, roles: Role[]): Session {
    const session: Session = {
      id: `sess_${randomBytes(18).toString("base64url")}`,
      sub,
      roles,
      csrf: randomBytes(18).toString("base64url"),
    };
    this.sessions.set(session.id, session);
    return session;
  }

  get(id: string | undefined): Session | undefined {
    return id ? this.sessions.get(id) : undefined;
  }

  destroy(id: string): void {
    this.sessions.delete(id);
  }
}

export class AuthzError extends Error {
  constructor(
    readonly status: 401 | 403,
    message: string,
  ) {
    super(message);
  }
}

/** Require an authenticated session with a role; enforce CSRF on writes. */
export function requireRole(
  session: Session | undefined,
  role: Role,
  opts: { write?: boolean; csrf?: string } = {},
): Session {
  if (!session) throw new AuthzError(401, "no session");
  if (!session.roles.includes(role)) throw new AuthzError(403, `role ${role} required`);
  if (opts.write && opts.csrf !== session.csrf) throw new AuthzError(403, "CSRF token mismatch");
  return session;
}
