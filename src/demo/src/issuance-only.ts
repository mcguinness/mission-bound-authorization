/**
 * The issuance-only reference deployment (#873): the reference Authorization
 * Server and the `plain-rs` Resource Server, in two configurations over the
 * same path: JWT validation alone, or JWT validation plus per-request RFC 7662
 * introspection. No PDP, PEP, OpenFGA or Mission runtime component runs.
 *
 * `startIssuanceOnly` boots both from the shipped config (topology,
 * scope-projection mapping, policy ceiling, introspection principals).
 * `runWalkthrough` drives the `reports.read` path over real HTTP and returns
 * each step's request and result. `src/docs/issuance-only-deployment.md` § Run
 * it publishes the commands that wrap both.
 */

import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildAuthorizationServer,
  type BuiltAs,
  MISSION_APPROVAL_SCOPE,
  type ProviderCapability,
  type ServiceTokenPrincipal,
} from "@mission/authorization-server";
import { DEV_SERVICE_TOKEN, INTROSPECTION_PRINCIPALS, TOPOLOGY } from "@mission/demo-data";
import { startPlainResourceServer } from "@mission/plain-rs";
import {
  type CryptoKey,
  decodeJwt,
  exportJWK,
  generateKeyPair,
  importJWK,
  type JWK,
  SignJWT,
} from "jose";

/**
 * Where the launcher writes the dev credentials the walkthrough reads
 * (`ISSUANCE_ONLY_CREDENTIALS` overrides). Written with mode 0600.
 */
export const CREDENTIALS_PATH =
  process.env.ISSUANCE_ONLY_CREDENTIALS ?? join(tmpdir(), "mission-issuance-only.credentials.json");

/**
 * The capabilities this deployment enables beyond the issuance profile, which
 * is always on (PAR, the authorization code with PKCE, DPoP-bound JWT access
 * tokens, refresh, scope projection, the approval interaction, introspection).
 * Only the lifecycle endpoint's `revoke` is added, because the walkthrough
 * revokes. Every other capability is off and refuses with its standard error;
 * `src/docs/issuance-only-deployment.md` § Enabled capabilities lists each.
 */
export const ISSUANCE_ONLY_CAPABILITIES: ReadonlySet<ProviderCapability> = new Set<ProviderCapability>([
  "lifecycle-revoke",
]);

/** The plain RS audience: the shipped `scope_only` mapping entry's key. */
export const PLAIN_RS_AUDIENCE = TOPOLOGY.resources.plainRs;

export interface IssuanceOnlyOptions {
  /** JWT validation plus per-request introspection (otherwise JWT only). */
  introspection: boolean;
  /** AS port; the issuer is `http://localhost:{asPort}`. Default `topology.ports.as` (4400). */
  asPort?: number;
  /** plain-rs listen port. Default: the audience URL's port (4410). */
  rsPort?: number;
}

/**
 * What a client of this deployment needs: the two URLs and the dev credentials
 * the boot generated. `agentClientJwk` is the `ap-agent` client's private key
 * (generated per boot, D25); `approverServiceToken` is the approver console's
 * credential; `lifecycleServiceToken` is the console's lifecycle credential.
 * In a real deployment these three are held by three different parties.
 */
export interface IssuanceOnlyCredentials {
  configuration: "jwt-only" | "jwt+introspection";
  asUrl: string;
  rsUrl: string;
  audience: string;
  agentClientJwk: Record<string, unknown>;
  approverServiceToken: string;
  lifecycleServiceToken: string;
}

export interface IssuanceOnlyDeployment {
  as: BuiltAs;
  credentials: IssuanceOnlyCredentials;
  close(): Promise<void>;
}

/**
 * Boot the AS and `plain-rs`. The AS is the reference assembly
 * (`buildAuthorizationServer`) restricted to {@link ISSUANCE_ONLY_CAPABILITIES},
 * with one addition: the demo's trusted approval input, a scoped service
 * principal (`svc:approver-console`, approver `bob`) behind
 * `allowHeadlessAdjudication`, the same input the demo stack uses. It is not
 * end-user consent. In the introspection configuration plain-rs authenticates
 * to `{issuer}/introspect` as the shipped `rs-plain` principal.
 */
export async function startIssuanceOnly(opts: IssuanceOnlyOptions): Promise<IssuanceOnlyDeployment> {
  const asPort = opts.asPort ?? TOPOLOGY.ports.as;
  const rsPort = opts.rsPort ?? Number(new URL(PLAIN_RS_AUDIENCE).port);
  const asUrl = `http://localhost:${asPort}`;
  const rsUrl = `http://localhost:${rsPort}`;
  const approverServiceToken = crypto.randomUUID();
  const approver: ServiceTokenPrincipal = {
    principal_id: "svc:approver-console",
    scopes: [MISSION_APPROVAL_SCOPE],
    approver: { sub: "bob", acr: "mfa", auth_time: Math.floor(Date.now() / 1000) },
  };
  const as = await buildAuthorizationServer({
    issuer: asUrl,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: { [approverServiceToken]: approver },
    capabilities: ISSUANCE_ONLY_CAPABILITIES,
  });
  const asServer = as.provider.listen(asPort);
  await new Promise<void>((r) => asServer.once("listening", () => r()));
  const principal = INTROSPECTION_PRINCIPALS.find((p) => p.principal_id === "rs-plain");
  if (opts.introspection && !principal) {
    throw new Error("config/introspection.json names no rs-plain principal");
  }
  const rsServer: Server = await startPlainResourceServer(
    {
      issuer: asUrl,
      audience: PLAIN_RS_AUDIENCE,
      jwksUri: `${asUrl}/jwks`,
      baseUrl: rsUrl,
      ...(opts.introspection && principal
        ? {
            introspection: {
              endpoint: `${asUrl}/introspect`,
              clientId: principal.principal_id,
              clientSecret: principal.secret,
            },
          }
        : {}),
    },
    rsPort,
  );
  return {
    as,
    credentials: {
      configuration: opts.introspection ? "jwt+introspection" : "jwt-only",
      asUrl,
      rsUrl,
      audience: PLAIN_RS_AUDIENCE,
      agentClientJwk: as.agentClientJwk,
      approverServiceToken,
      lifecycleServiceToken: DEV_SERVICE_TOKEN,
    },
    close: async () => {
      // Stop accepting, then drop open keep-alive connections so the close
      // does not wait out a client's idle socket.
      const stop = (server: Server) =>
        new Promise<void>((r) => {
          server.close(() => r());
          server.closeAllConnections();
        });
      await Promise.all([stop(asServer), stop(rsServer)]);
    },
  };
}

/** One walkthrough step: what was sent and what came back. */
export interface WalkthroughStep {
  step: string;
  request: string;
  status: number;
  result: Record<string, unknown>;
}

const REDIRECT_URI = "http://localhost:9999/cb";
const PKCE_VERIFIER = "issuance-only-walkthrough-verifier-0123456789-0123456789";
const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/**
 * Drive the `reports.read` path against a running deployment, over real HTTP:
 * PAR with a `mission_intent` proposing `reports:report.read` for the plain RS
 * (no `scope` parameter), approval by the approver console, code exchange with
 * PKCE and DPoP, `GET /api/reports` (200), `POST /api/reports` (403
 * `insufficient_scope`), revocation through the lifecycle endpoint, then a
 * refresh (`invalid_grant`) and the same access token at plain-rs again.
 * `onStep` receives each step as it completes.
 */
export async function runWalkthrough(
  creds: IssuanceOnlyCredentials,
  onStep: (s: WalkthroughStep) => void = () => {},
): Promise<WalkthroughStep[]> {
  const steps: WalkthroughStep[] = [];
  const record = (s: WalkthroughStep) => {
    steps.push(s);
    onStep(s);
  };
  const { asUrl, rsUrl, audience } = creds;
  const clientKey = (await importJWK(creds.agentClientJwk as JWK, "ES256")) as CryptoKey;
  const clientAssertion = () =>
    new SignJWT({})
      .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
      .setIssuer("ap-agent")
      .setSubject("ap-agent")
      .setAudience(asUrl)
      .setIssuedAt()
      .setExpirationTime("2m")
      .setJti(crypto.randomUUID())
      .sign(clientKey);
  const dpopKeys = await generateKeyPair("ES256", { extractable: true });
  const dpopJwk = await exportJWK(dpopKeys.publicKey);
  const proof = (htm: string, htu: string, extra: Record<string, unknown> = {}) =>
    new SignJWT({ htm, htu, ...extra })
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: dpopJwk })
      .setIssuedAt()
      .setJti(crypto.randomUUID())
      .sign(dpopKeys.privateKey);
  const json = async (res: Response) => {
    const text = await res.text();
    try {
      return JSON.parse(text) as Record<string, unknown>;
    } catch {
      return { body: text };
    }
  };

  // 1. PAR: the Mission Intent and the authority proposal for the plain RS.
  const challenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(PKCE_VERIFIER)),
  ).toString("base64url");
  const proposal = [{ type: "mission_resource_access", resource: audience, actions: ["reports:report.read"] }];
  const par = await fetch(`${asUrl}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      resource: audience,
      code_challenge: challenge,
      code_challenge_method: "S256",
      login_hint: "alice",
      mission_intent: JSON.stringify({
        intent: {
          goal: "Read the quarterly reports",
          target_resources: [audience],
          expires_at: new Date(Date.now() + 24 * 3600 * 1000).toISOString(),
        },
      }),
      authorization_details: JSON.stringify(proposal),
      client_assertion: await clientAssertion(),
      client_assertion_type: CLIENT_ASSERTION_TYPE,
    }).toString(),
  });
  const parBody = await json(par);
  record({
    step: "1. PAR",
    request: `POST ${asUrl}/request resource=${audience} authorization_details=${JSON.stringify(proposal)} (no scope)`,
    status: par.status,
    result: parBody,
  });
  if (par.status !== 201) return steps;

  // Front channel: /auth redirects to the approval interaction.
  const cookies = new Map<string, string>();
  const cookie = () => [...cookies].map(([k, v]) => `${k}=${v}`).join("; ");
  const keep = (res: Response) => {
    for (const line of res.headers.getSetCookie()) {
      const [pair] = line.split(";");
      const eq = (pair as string).indexOf("=");
      cookies.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
    }
  };
  let res = await fetch(
    `${asUrl}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: String(parBody.request_uri) })}`,
    { redirect: "manual" },
  );
  keep(res);
  const uid = (res.headers.get("location") ?? "").split("/interaction/")[1] ?? "";

  // 2. Approval by the approver console (the demo's trusted approval input).
  res = await fetch(`${asUrl}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: {
      "content-type": "application/json",
      cookie: cookie(),
      "x-service-token": creds.approverServiceToken,
    },
    body: JSON.stringify({ decision: "approve" }),
  });
  keep(res);
  let location = res.headers.get("location") ?? "";
  while (location.startsWith(asUrl)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookie() } });
    keep(res);
    location = res.headers.get("location") ?? "";
  }
  const callback = location ? new URL(location).searchParams : new URLSearchParams();
  const code = callback.get("code");
  record({
    step: "2. Approval",
    request: `POST ${asUrl}/interaction/${uid}/decide {"decision":"approve"} as svc:approver-console`,
    status: code ? 200 : 400,
    result: code ? { code: "(redacted)" } : Object.fromEntries(callback),
  });
  if (!code) return steps;

  // 3. Code exchange with PKCE and DPoP.
  const token = async (params: Record<string, string>) => {
    const htu = `${asUrl}/token`;
    const send = async (extra: Record<string, unknown> = {}) =>
      fetch(htu, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", dpop: await proof("POST", htu, extra) },
        body: new URLSearchParams({
          ...params,
          client_assertion: await clientAssertion(),
          client_assertion_type: CLIENT_ASSERTION_TYPE,
        }).toString(),
      });
    let r = await send();
    const nonce = r.headers.get("dpop-nonce");
    if (r.status === 400 && nonce) r = await send({ nonce });
    return { status: r.status, body: await json(r) };
  };
  const exchanged = await token({
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: PKCE_VERIFIER,
    resource: audience,
  });
  const accessToken = String(exchanged.body.access_token ?? "");
  const refreshToken = String(exchanged.body.refresh_token ?? "");
  const claims = accessToken ? decodeJwt(accessToken) : {};
  record({
    step: "3. Code exchange",
    request: `POST ${asUrl}/token grant_type=authorization_code (PKCE S256, DPoP)`,
    status: exchanged.status,
    result: {
      token_type: exchanged.body.token_type,
      scope: exchanged.body.scope,
      expires_in: exchanged.body.expires_in,
      access_token_claims: {
        aud: claims.aud,
        scope: claims.scope,
        mission: claims.mission,
        cnf: claims.cnf ? { jkt: (claims.cnf as { jkt?: string }).jkt } : undefined,
        exp: claims.exp,
      },
      refresh_token: refreshToken ? "(issued)" : undefined,
      error: exchanged.body.error,
    },
  });
  if (exchanged.status !== 200) return steps;

  const callRs = async (method: "GET" | "POST") => {
    const url = `${rsUrl}/api/reports`;
    const ath = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(accessToken))).toString(
      "base64url",
    );
    const r = await fetch(url, {
      method,
      headers: {
        authorization: `DPoP ${accessToken}`,
        dpop: await proof(method, url, { ath }),
        ...(method === "POST" ? { "content-type": "application/json" } : {}),
      },
      ...(method === "POST" ? { body: JSON.stringify({ title: "Q3" }) } : {}),
    });
    return { status: r.status, body: await json(r), challenge: r.headers.get("www-authenticate") };
  };

  // 4. The in-scope operation.
  const read = await callRs("GET");
  record({ step: "4. GET /api/reports", request: `GET ${rsUrl}/api/reports (DPoP)`, status: read.status, result: read.body });

  // 5. The operation the projected scope does not cover.
  const write = await callRs("POST");
  record({
    step: "5. POST /api/reports",
    request: `POST ${rsUrl}/api/reports (DPoP)`,
    status: write.status,
    result: { ...write.body, "www-authenticate": write.challenge },
  });

  // 6. Revoke the Mission through the lifecycle endpoint.
  const missionId = (claims.mission as { id?: string } | undefined)?.id ?? "";
  const revoke = await fetch(`${asUrl}/missions/${missionId}/lifecycle`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-service-token": creds.lifecycleServiceToken },
    body: JSON.stringify({ operation: "revoke", nonce: crypto.randomUUID() }),
  });
  const revokeText = await revoke.text();
  let revokeResult: Record<string, unknown>;
  try {
    revokeResult = JSON.parse(revokeText) as Record<string, unknown>;
  } catch {
    // A signed Mission Status response (compact JWS): show its state.
    const signed = decodeJwt(revokeText) as Record<string, unknown>;
    revokeResult = { state: signed.state ?? (signed.mission as { state?: unknown } | undefined)?.state, signed: true };
  }
  record({
    step: "6. Revoke",
    request: `POST ${asUrl}/missions/${missionId}/lifecycle {"operation":"revoke"} as svc:console`,
    status: revoke.status,
    result: revokeResult,
  });

  // 6a. Refresh after revocation.
  const refreshed = await token({ grant_type: "refresh_token", refresh_token: refreshToken });
  record({
    step: "6a. Refresh after revoke",
    request: `POST ${asUrl}/token grant_type=refresh_token`,
    status: refreshed.status,
    result: { error: refreshed.body.error, mission_error: refreshed.body.mission_error },
  });

  // 6b. The same access token at plain-rs.
  const after = await callRs("GET");
  record({
    step: "6b. GET /api/reports after revoke",
    request: `GET ${rsUrl}/api/reports (same access token, DPoP)`,
    status: after.status,
    result: after.body,
  });
  return steps;
}

/** Print one step the way the walkthrough command does. */
export function formatStep(s: WalkthroughStep): string {
  return `${s.step}\n  -> ${s.request}\n  <- ${s.status} ${JSON.stringify(s.result)}`;
}
