/**
 * @spec #831 C2: a real resource server that follows the AS's key rotation
 * without restarting.
 *
 * One plain-rs, holding the AS's access-token keys through `IssuerKeys`,
 * serves throughout while the AS is stopped, edited, started and verified:
 * staged, activated, then retired. The resource server's trusted
 * configuration lists the next generation's `kid` before activation, and its
 * key clock is injected so the AS's declared `max-age` is crossed on
 * purpose. It accepts a token under the new generation at once, a token
 * under the old one while that generation is in overlap, refuses everything
 * while the AS is down and its set is stale, and refuses the old generation
 * once it is retired.
 */
import { mkdtempSync } from "node:fs";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  activateSigningKeyGeneration,
  APPROVAL_SUBJECT_HEADER,
  initSigningKeyRing,
  JWKS_MAX_AGE_SECONDS,
  retireSigningKeyGeneration,
  stageSigningKeyGeneration,
  verifySigningKeyRing,
} from "@mission/authorization-server";
import { IssuerKeys } from "@mission/core";
import { TOPOLOGY } from "@mission/demo-data";
import { startPlainResourceServer } from "@mission/plain-rs";
import { decodeProtectedHeader, exportJWK, generateKeyPair, importJWK, type JWK, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { renderApproval } from "../src/approval-console.js";
import { type IssuanceOnlyCredentials, PLAIN_RS_AUDIENCE, startIssuanceOnly } from "../src/issuance-only.js";

const AS_PORT = 14941;
const DEPLOYMENT_RS_PORT = 14942;
const RS_PORT = 14943;
const ISSUER = `http://localhost:${AS_PORT}`;
const RS_URL = `http://localhost:${RS_PORT}`;
const { asToken, asStatus, asTxn, asContinuation } = TOPOLOGY.keys;
const ROLES = { asToken, asStatus, asTxn, asContinuation };
const REDIRECT_URI = "http://localhost:9999/cb";
const VERIFIER = "issuer-keys-plain-rs-rotation-verifier-0123456789-0123456789";

/** A `reports:report.read` token for plain-rs, and a call to it presenting the token with its DPoP key. */
async function mint(creds: IssuanceOnlyCredentials): Promise<{ token: string; read: () => Promise<number> }> {
  const { asUrl, audience } = creds;
  const clientKey = (await importJWK(creds.agentClientJwk as JWK, "ES256")) as CryptoKey;
  const assertion = () =>
    new SignJWT({})
      .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
      .setIssuer("ap-agent")
      .setSubject("ap-agent")
      .setAudience(asUrl)
      .setIssuedAt()
      .setExpirationTime("2m")
      .setJti(crypto.randomUUID())
      .sign(clientKey);
  const dpop = await generateKeyPair("ES256", { extractable: true });
  const dpopJwk = await exportJWK(dpop.publicKey);
  const proof = (htm: string, htu: string, extra: Record<string, unknown> = {}) =>
    new SignJWT({ htm, htu, ...extra })
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: dpopJwk })
      .setIssuedAt()
      .setJti(crypto.randomUUID())
      .sign(dpop.privateKey);
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER))).toString("base64url");
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
      mission_intent: JSON.stringify({
        intent: { goal: "Read the quarterly reports", target_resources: [audience], expires_at: new Date(Date.now() + 86_400_000).toISOString() },
      }),
      authorization_details: JSON.stringify([{ type: "mission_resource_access", resource: audience, actions: ["reports:report.read"] }]),
      client_assertion: await assertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  expect(par.status).toBe(201);
  const { request_uri } = (await par.json()) as { request_uri: string };
  const cookies = new Map<string, string>();
  const cookie = () => [...cookies].map(([k, v]) => `${k}=${v}`).join("; ");
  const keep = (res: Response) => {
    for (const line of res.headers.getSetCookie()) {
      const [pair] = line.split(";");
      const eq = (pair as string).indexOf("=");
      cookies.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
    }
  };
  let res = await fetch(`${asUrl}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri })}`, { redirect: "manual" });
  keep(res);
  const uid = (res.headers.get("location") ?? "").split("/interaction/")[1] ?? "";
  const approver = { cookie: cookie(), "x-service-token": creds.approverServiceToken, [APPROVAL_SUBJECT_HEADER]: "alice" };
  const render_revision = await renderApproval(asUrl, uid, approver);
  res = await fetch(`${asUrl}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/json", ...approver },
    body: JSON.stringify({ decision: "approve", ...(render_revision ? { render_revision } : {}) }),
  });
  keep(res);
  let location = res.headers.get("location") ?? "";
  while (location.startsWith(asUrl)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookie() } });
    keep(res);
    location = res.headers.get("location") ?? "";
  }
  const code = new URL(location).searchParams.get("code") as string;
  const send = async (extra: Record<string, unknown> = {}) =>
    fetch(`${asUrl}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await proof("POST", `${asUrl}/token`, extra) },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: VERIFIER,
        resource: audience,
        client_assertion: await assertion(),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let tok = await send();
  const nonce = tok.headers.get("dpop-nonce");
  if (tok.status === 400 && nonce) tok = await send({ nonce });
  const body = (await tok.json()) as Record<string, unknown>;
  expect(tok.status, JSON.stringify(body)).toBe(200);
  const token = body.access_token as string;
  const read = async (): Promise<number> => {
    const url = `${RS_URL}/api/reports`;
    const ath = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token))).toString("base64url");
    const r = await fetch(url, { headers: { authorization: `DPoP ${token}`, dpop: await proof("GET", url, { ath }) } });
    await r.text();
    return r.status;
  };
  return { token, read };
}

describe("a resource server across the AS's key rotation (@spec #831 C2)", () => {
  it("accepts the trusted new generation at once and the old one in overlap, refuses while it cannot revalidate, and refuses the retired generation", { timeout: 180_000 }, async () => {
    const ring = join(mkdtempSync(join(tmpdir(), "plain-rs-rotation-")), "keys", "ring.json");
    const start = Date.now();
    const at = (s: number) => () => new Date(start + s * 1000);
    await initSigningKeyRing(ring, ISSUER, ROLES, at(0));
    let t = start;
    const advance = (s: number) => {
      t += s * 1000;
    };
    // The resource server's trusted configuration: the access-token role, generation 2 authorized ahead of activation.
    const keys = new IssuerKeys({
      jwksUri: `${ISSUER}/jwks`,
      roles: { accessToken: { kids: [asToken.kid, `${asToken.kid}-2`], algs: [asToken.alg] } },
      now: () => t,
    });
    const rs: Server = await startPlainResourceServer(
      { issuer: ISSUER, audience: PLAIN_RS_AUDIENCE, keys: keys.resolver("accessToken") as never, baseUrl: RS_URL },
      RS_PORT,
    );
    const boot = () =>
      startIssuanceOnly({ introspection: false, asPort: AS_PORT, rsPort: DEPLOYMENT_RS_PORT, signingKeys: { ring } });
    try {
      let deployment = await boot();
      const first = await mint(deployment.credentials);
      expect(decodeProtectedHeader(first.token).kid).toBe(asToken.kid);
      expect(await first.read()).toBe(200);
      await deployment.close();

      await stageSigningKeyGeneration(ring, ISSUER, ROLES, "asToken", at(1));
      deployment = await boot();
      await verifySigningKeyRing(ring, ISSUER, ROLES, { now: at(2) });
      await deployment.close();
      await activateSigningKeyGeneration(ring, ISSUER, ROLES, "asToken", {
        minPublishedS: JWKS_MAX_AGE_SECONDS,
        now: at(2 + JWKS_MAX_AGE_SECONDS),
      });

      // Activated: the resource server never restarted, and its cached set is still fresh.
      deployment = await boot();
      await verifySigningKeyRing(ring, ISSUER, ROLES, { now: at(3 + JWKS_MAX_AGE_SECONDS) });
      const second = await mint(deployment.credentials);
      expect(decodeProtectedHeader(second.token).kid).toBe(`${asToken.kid}-2`);
      expect(await second.read()).toBe(200);
      expect(await first.read()).toBe(200);
      await deployment.close();

      // The AS is down and the resource server's set goes stale: no current reliance.
      advance(JWKS_MAX_AGE_SECONDS);
      expect(await second.read()).toBe(401);

      await retireSigningKeyGeneration(ring, ISSUER, ROLES, "asToken", asToken.kid, {
        retention: { auditHorizonS: 3600, maxMissionLifetimeS: 3600 },
        now: at(3 + JWKS_MAX_AGE_SECONDS + 3600),
      });
      deployment = await boot();
      expect(await first.read()).toBe(401);
      expect(await second.read()).toBe(200);
      await deployment.close();
    } finally {
      await new Promise<void>((r) => {
        rs.close(() => r());
        rs.closeAllConnections();
      });
    }
  });
});
