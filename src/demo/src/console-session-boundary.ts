import type { Hono } from "hono";
import { requireRole, type Session } from "@mission/console-bff";

/**
 * Local-demo login bootstrap. The random launch secret is shown only to the
 * operator, not returned by an agent route or /bff/session. Production uses
 * authenticated SSO; this demo still needs a real credential boundary.
 */
export function installConsoleSessionBoundary(app: Hono, session: Session, now = () => Date.now()): void {
  const expiresAt = now() + 30 * 60_000;
  app.post("/console/session", c => {
    if (now() >= expiresAt || c.req.header("authorization") !== `Bearer ${session.id}`) return c.json({ error: "unauthorized" }, 401);
    c.header("set-cookie", `mission_console=${session.id}; Path=/bff; HttpOnly; SameSite=Strict; Max-Age=1800`);
    return c.json({ authenticated: true });
  });
  app.use("/bff/*", async (c, next) => {
    const cookies = (c.req.header("cookie") ?? "").split(";").map(s => s.trim()).filter(s => s.startsWith("mission_console="));
    if (now() >= expiresAt || cookies.length !== 1 || cookies[0] !== `mission_console=${session.id}`) return c.json({ error: "unauthorized" }, 401);
    const origin = c.req.header("origin");
    if (origin && origin !== new URL(c.req.url).origin) return c.json({ error: "forbidden" }, 403);
    const role = c.req.path.startsWith("/bff/approver/") ? "approver" : "operator";
    try { requireRole(session, role, { write: c.req.method !== "GET", csrf: c.req.header("x-csrf") ?? "" }); }
    catch { return c.json({ error: "forbidden" }, 403); }
    await next();
  });
}
