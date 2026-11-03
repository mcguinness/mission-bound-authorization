/**
 * #2018: a reference AS built with an explicit capability set on a free
 * port, and the issuance path through it for `ap-agent` and the plain RS
 * audience: PAR, the approval interaction (rendered to the trusted approval
 * service, then decided), and the code's redemption.
 */
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { TOPOLOGY } from "@mission/demo-data";
import { exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { buildAuthorizationServer, type BuiltAs, type ProviderCapability } from "../src/index.js";
import { TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";
import { RENDER_REVISION_HEADER } from "../src/adapters/approval-render-revision.js";

export type Json = Record<string, unknown>;

/** The plain RS audience, under the shipped `scope_only` mapping entry. */
export const AUDIENCE = TOPOLOGY.resources.plainRs;
export const READ = [{ type: "mission_resource_access", resource: AUDIENCE, actions: ["reports:report.read"] }];
const REDIRECT_URI = "http://localhost:9999/cb";
const VERIFIER = "capability-switch-verifier-0123456789-0123456789";
const ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

export interface SwitchedAs {
  as: BuiltAs;
  issuer: string;
  close: () => Promise<void>;
}

/** Build the AS with `capabilities` (and any further options) and serve it on a free port. */
export async function startAs(
  capabilities: Iterable<ProviderCapability>,
  opts: Omit<Parameters<typeof buildAuthorizationServer>[0], "issuer" | "capabilities"> = {},
): Promise<SwitchedAs> {
  const server: Server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    const as = await buildAuthorizationServer({
      issuer,
      allowHeadlessAdjudication: true,
      serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
      ...opts,
      capabilities: new Set(capabilities),
    });
    server.on("request", as.provider.callback());
    return {
      as,
      issuer,
      close: () =>
        new Promise<void>((resolve) => {
          server.closeAllConnections();
          server.close(() => resolve());
        }),
    };
  } catch (e) {
    server.close();
    throw e;
  }
}

async function readJson(res: Response): Promise<Json> {
  const text = await res.text();
  try {
    return JSON.parse(text) as Json;
  } catch {
    return { body: text };
  }
}

async function clientAssertion(h: SwitchedAs): Promise<string> {
  const key = await importJWK(h.as.agentClientJwk as never, "ES256");
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
    .setIssuer("ap-agent")
    .setSubject("ap-agent")
    .setAudience(h.issuer)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(key);
}

/** A Pushed Authorization Request carrying the reports Intent, with any extra Intent members. */
export async function par(h: SwitchedAs, intentExtra: Json = {}): Promise<{ status: number; body: Json }> {
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER))).toString("base64url");
  const expiresAt = new Date(Date.now() + 7 * 86_400_000).toISOString().replace(/\.\d{3}Z$/, "Z");
  const res = await fetch(`${h.issuer}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      resource: AUDIENCE,
      code_challenge: challenge,
      code_challenge_method: "S256",
      mission_intent: JSON.stringify({
        intent: { goal: "Read the quarterly reports", target_resources: [AUDIENCE], expires_at: expiresAt, ...intentExtra },
      }),
      authorization_details: JSON.stringify(READ),
      client_assertion: await clientAssertion(h),
      client_assertion_type: ASSERTION_TYPE,
    }).toString(),
  });
  return { status: res.status, body: await readJson(res) };
}

/**
 * Take a pushed request through the approval interaction: the trusted
 * approval service (Bob, for Alice) reads the approval page and approves.
 * Returns the page it read, the front channel's final redirect, and the
 * Missions the decision created.
 */
export async function decideApproval(
  h: SwitchedAs,
  requestUri: string,
): Promise<{ page: string; location: URL; created: string[] }> {
  const cookies = new Map<string, string>();
  const store = (res: Response) => {
    for (const line of res.headers.getSetCookie()) {
      const [pair] = line.split(";");
      const eq = (pair as string).indexOf("=");
      cookies.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
    }
  };
  const cookie = () => [...cookies.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
  let res = await fetch(`${h.issuer}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: requestUri })}`, {
    redirect: "manual",
  });
  store(res);
  const uid = (res.headers.get("location") ?? "").split("/interaction/")[1] as string;
  const headers = { ...trustedApprovalHeaders(), cookie: cookie() };
  const rendered = await fetch(`${h.issuer}/interaction/${uid}`, { headers });
  const page = await rendered.text();
  const revision = rendered.headers.get(RENDER_REVISION_HEADER);
  if (rendered.status !== 200 || !revision) throw new Error(`no approval rendering: ${rendered.status} ${page.slice(0, 200)}`);
  const before = new Set(h.as.kernel.allMissions().map((m) => m.id));
  res = await fetch(`${h.issuer}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { ...headers, "content-type": "application/json" },
    body: JSON.stringify({ decision: "approve", render_revision: revision }),
  });
  store(res);
  let location = res.headers.get("location") ?? "";
  while (location.startsWith(h.issuer)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookie() } });
    store(res);
    location = res.headers.get("location") ?? "";
  }
  const created = h.as.kernel.allMissions().filter((m) => !before.has(m.id));
  return { page, location: new URL(location), created: created.map((m) => m.id) };
}

/** {@link decideApproval}, requiring a code and exactly one created Mission. */
export async function approve(h: SwitchedAs, requestUri: string): Promise<{ page: string; code: string; missionId: string }> {
  const { page, location, created } = await decideApproval(h, requestUri);
  const code = location.searchParams.get("code");
  if (!code) throw new Error(`approval did not yield a code: ${location}`);
  if (created.length !== 1) throw new Error(`expected one Mission, found ${created.length}`);
  return { page, code, missionId: created[0] as string };
}

/** Redeem `code` at the token endpoint, DPoP-bound to a fresh key. */
export async function redeem(h: SwitchedAs, code: string): Promise<{ status: number; body: Json }> {
  const keys = await generateKeyPair("ES256", { extractable: true });
  const htu = `${h.issuer}/token`;
  const proof = async (nonce?: string) =>
    new SignJWT({ htu, htm: "POST", ...(nonce ? { nonce } : {}) })
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
      .setIssuedAt()
      .setJti(crypto.randomUUID())
      .sign(keys.privateKey);
  const send = async (nonce?: string) =>
    fetch(htu, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await proof(nonce) },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: VERIFIER,
        resource: AUDIENCE,
        client_assertion: await clientAssertion(h),
        client_assertion_type: ASSERTION_TYPE,
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send(nonce);
  return { status: res.status, body: await readJson(res) };
}

/** The AS's discovery document. */
export async function metadata(h: SwitchedAs): Promise<Json> {
  return (await (await fetch(`${h.issuer}/.well-known/openid-configuration`)).json()) as Json;
}
