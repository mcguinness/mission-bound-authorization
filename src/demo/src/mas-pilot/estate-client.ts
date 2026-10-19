/**
 * @spec authority-server#mission-join (#818)
 *
 * An estate client obtaining an ordinary access token from the pilot's estate
 * authorization server: the authorization code grant with PKCE (S256), a
 * `resource` indicator, `client_secret_basic` client authentication, and a
 * DPoP proof at the token endpoint, so the token is bound to the client's key.
 * Nothing here is Mission-aware: this is how an unchanged estate client gets
 * the credential it later presents at the gateway.
 */

import { createHash, randomBytes } from "node:crypto";
import { type DpopKeys, dpopProofFor } from "@mission/mcp-payments";

export interface EstateTokenRequest {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  /** The estate directory account that logs in (the login stand-in reads `login_hint`). */
  account: string;
  resource: string;
  scope: string;
  dpopKeys: DpopKeys;
}

export type EstateTokenResult =
  | { ok: true; accessToken: string; tokenType: string; scope?: string }
  | { ok: false; status: number; error: string; errorDescription?: string };

type CookieJar = Map<string, string>;

function remember(jar: CookieJar, res: Response): void {
  for (const line of res.headers.getSetCookie()) {
    const pair = line.split(";", 1)[0] ?? "";
    const eq = pair.indexOf("=");
    if (eq > 0) jar.set(pair.slice(0, eq).trim(), pair.slice(eq + 1));
  }
}

const cookieHeader = (jar: CookieJar): string => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");

/**
 * Run the authorization code grant against the estate AS and return the
 * access token, or the error the estate AS answered with.
 */
export async function obtainEstateToken(req: EstateTokenRequest): Promise<EstateTokenResult> {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const authorize = new URL(`${req.issuer}/auth`);
  for (const [k, v] of Object.entries({
    client_id: req.clientId,
    response_type: "code",
    redirect_uri: req.redirectUri,
    scope: req.scope,
    resource: req.resource,
    code_challenge: challenge,
    code_challenge_method: "S256",
    login_hint: req.account,
    state: randomBytes(8).toString("hex"),
  })) {
    authorize.searchParams.set(k, v);
  }

  // Follow the front channel: authorization endpoint, interaction, resume,
  // then the redirect back to the client with the code (or an error).
  const jar: CookieJar = new Map();
  let next = authorize.toString();
  let code: string | undefined;
  for (let hop = 0; hop < 10; hop++) {
    if (next.startsWith(req.redirectUri)) {
      const back = new URL(next);
      const error = back.searchParams.get("error");
      if (error) {
        const description = back.searchParams.get("error_description");
        return { ok: false, status: 302, error, ...(description ? { errorDescription: description } : {}) };
      }
      code = back.searchParams.get("code") ?? undefined;
      break;
    }
    const res = await fetch(next, { redirect: "manual", headers: { cookie: cookieHeader(jar) } });
    remember(jar, res);    const location = res.headers.get("location");
    if (!location) {
      const body = await res.text();
      return { ok: false, status: res.status, error: "no_redirect", errorDescription: body.slice(0, 200) };
    }
    next = new URL(location, next).toString();
  }
  if (!code) return { ok: false, status: 0, error: "no_code" };

  const tokenEndpoint = `${req.issuer}/token`;
  const res = await fetch(tokenEndpoint, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${Buffer.from(`${encodeURIComponent(req.clientId)}:${encodeURIComponent(req.clientSecret)}`).toString("base64")}`,
      dpop: await dpopProofFor(req.dpopKeys, tokenEndpoint, "POST"),
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: req.redirectUri,
      code_verifier: verifier,
      resource: req.resource,
    }).toString(),
  });
  const body = (await res.json()) as Record<string, unknown>;
  if (!res.ok || typeof body.access_token !== "string") {
    return {
      ok: false,
      status: res.status,
      error: typeof body.error === "string" ? body.error : "token_error",
      ...(typeof body.error_description === "string" ? { errorDescription: body.error_description } : {}),
    };
  }
  return {
    ok: true,
    accessToken: body.access_token,
    tokenType: String(body.token_type),
    ...(typeof body.scope === "string" ? { scope: body.scope } : {}),
  };
}
