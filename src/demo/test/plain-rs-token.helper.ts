/**
 * @spec #831 C2: a `reports:report.read` token for plain-rs from an
 * issuance-only deployment's AS (PAR, approval by the approver console, code
 * exchange with DPoP), and a call to a plain-rs at `rsUrl` presenting it with
 * its DPoP key. Shared by the tests that hold plain-rs across a key change.
 */
import { APPROVAL_SUBJECT_HEADER } from "@mission/authorization-server";
import { exportJWK, generateKeyPair, importJWK, type JWK, SignJWT } from "jose";
import { expect } from "vitest";
import { renderApproval } from "../src/approval-console.js";
import type { IssuanceOnlyCredentials } from "../src/issuance-only.js";

const REDIRECT_URI = "http://localhost:9999/cb";
const VERIFIER = "plain-rs-token-helper-verifier-0123456789-0123456789-0123456789";

export async function mintPlainRsToken(
  creds: IssuanceOnlyCredentials,
  rsUrl: string,
): Promise<{ token: string; read: () => Promise<number> }> {
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
    const url = `${rsUrl}/api/reports`;
    const ath = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token))).toString("base64url");
    const r = await fetch(url, { headers: { authorization: `DPoP ${token}`, dpop: await proof("GET", url, { ath }) } });
    await r.text();
    return r.status;
  };
  return { token, read };
}
