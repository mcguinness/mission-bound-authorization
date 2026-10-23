/**
 * @spec mission#submission-via-par (#1503, D620): the two carriages of the
 * Submission envelope through PAR. Inside a signed Request Object (RFC 9101)
 * the `mission_intent` claim's value is the Submission envelope itself, a
 * JSON object, validated as a form value is and committed by the same
 * `intent_hash`; a string or any other value is refused invalid_request. The
 * form parameter carries the envelope's JSON serialization, and a form value
 * that does not parse to a JSON object is refused invalid_request. A push
 * that carries a Request Object and a `mission_intent` outside it is refused
 * invalid_request, and an unsigned Request Object is refused.
 */

import { type Server } from "node:http";
import { intentHash } from "@mission/core";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { CompactSign, exportJWK, generateKeyPair, importJWK, SignJWT, UnsecuredJWT, type CryptoKey } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ApprovalSessionStore, buildAuthorizationServer, type BuiltAs } from "../src/index.js";
import { floorApprovalHeaders, renderedRevision, TEST_APPROVAL_PRINCIPALS } from "./approval-fixture.js";

const PORT = 14961;
const ISSUER = `http://localhost:${PORT}`;
const CLIENT = "ap-agent";
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
const SESSIONS = new ApprovalSessionStore();

const INTENT = {
  goal: "Reconcile Q3 invoices",
  target_resources: [RESOURCE],
  expires_at: new Date(Date.now() + 86_400_000).toISOString().replace(/\.\d{3}Z$/, "Z"),
};
const ENVELOPE = { intent: INTENT };

const PKCE_VERIFIER = "request-object-submission-verifier-0123456789-0123456789";
async function pkceChallenge(): Promise<string> {
  return Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(PKCE_VERIFIER)),
  ).toString("base64url");
}

let as: BuiltAs;
let server: Server;
let agentKey: CryptoKey;

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    approvalSessions: SESSIONS,
  });
  server = as.provider.listen(PORT);
  agentKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
});

afterAll(() => {
  server?.close();
});

/** The authorization request parameters, in the form or inside a Request Object. */
async function authorizationParams(): Promise<Record<string, string>> {
  return {
    response_type: "code",
    redirect_uri: REDIRECT_URI,
    resource: RESOURCE,
    code_challenge: await pkceChallenge(),
    code_challenge_method: "S256",
    login_hint: "alice",
  };
}

async function clientAssertion(): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
    .setIssuer(CLIENT)
    .setSubject(CLIENT)
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(agentKey);
}

/** The claims of a Request Object for the client, with the given extra claims. */
async function requestObjectClaims(claims: Record<string, unknown>): Promise<Record<string, unknown>> {
  return { client_id: CLIENT, ...(await authorizationParams()), ...claims };
}

/** A Request Object signed with the client's registered key. */
async function signedRequestObject(claims: Record<string, unknown>): Promise<string> {
  return new SignJWT(await requestObjectClaims(claims))
    .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
    .setIssuer(CLIENT)
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("1m")
    .setJti(crypto.randomUUID())
    .sign(agentKey);
}

/** A Request Object signed over exactly this payload text, which may repeat a member name. */
async function signedRawRequestObject(payload: string): Promise<string> {
  return new CompactSign(new TextEncoder().encode(payload))
    .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
    .sign(agentKey);
}

/** One pushed authorization request, authenticated by the client's assertion. */
async function push(form: Record<string, string>): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: CLIENT,
      ...form,
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

/** A push carrying the form parameter `mission_intent` with this exact value. */
async function pushForm(missionIntent: string): Promise<{ status: number; body: Record<string, unknown> }> {
  return push({ ...(await authorizationParams()), mission_intent: missionIntent });
}

/** A push carrying this Request Object, with any parameters outside it. */
async function pushRequestObject(
  request: string,
  outside: Record<string, string> = {},
): Promise<{ status: number; body: Record<string, unknown> }> {
  return push({ request, ...outside });
}

/**
 * Redeem the request_uri, render the approval and approve it; returns the
 * Mission Record and the authorization code the redirect carries.
 */
async function approve(requestUri: string) {
  const cookies = new Map<string, string>();
  const cookieHeader = () => [...cookies.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
  const keep = (res: Response) => {
    for (const line of res.headers.getSetCookie()) {
      const [pair] = line.split(";");
      const eq = (pair as string).indexOf("=");
      cookies.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
    }
  };
  let res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: CLIENT, request_uri: requestUri })}`, {
    redirect: "manual",
  });
  keep(res);
  let location = res.headers.get("location") ?? "";
  expect(location, await res.text()).toMatch(/\/interaction\/[^/]+$/);
  const uid = location.split("/interaction/")[1] as string;
  const page = await fetch(`${ISSUER}/interaction/${uid}`, { headers: { cookie: cookieHeader() } });
  const html = await page.text();
  expect(page.status, html.slice(0, 400)).toBe(200);
  expect(html).toContain(INTENT.goal);
  const decideHeaders = { ...floorApprovalHeaders(SESSIONS, uid, cookieHeader()), "content-type": "application/json" };
  const render_revision = await renderedRevision(ISSUER, uid, decideHeaders);
  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: decideHeaders,
    body: JSON.stringify({ decision: "approve", render_revision }),
  });
  expect(res.status, await res.clone().text()).toBe(303);
  keep(res);
  const record = as.kernel.findByApprovalEvent(`apev_${uid}`);
  expect(record).toBeDefined();
  location = res.headers.get("location") ?? "";
  while (location.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookieHeader() } });
    keep(res);
    location = res.headers.get("location") ?? "";
  }
  return { record, code: new URL(location).searchParams.get("code") };
}

/** Redeem an authorization code at the token endpoint, under a DPoP proof. */
async function redeem(code: string): Promise<{ status: number; body: Record<string, unknown> }> {
  const dpopKeys = await generateKeyPair("ES256", { extractable: true });
  const dpopPub = await exportJWK(dpopKeys.publicKey);
  const htu = `${ISSUER}/token`;
  const send = async (extra: Record<string, unknown> = {}): Promise<Response> =>
    fetch(htu, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        dpop: await new SignJWT({ htu, htm: "POST", ...extra })
          .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: dpopPub })
          .setIssuedAt()
          .setJti(crypto.randomUUID())
          .sign(dpopKeys.privateKey),
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: PKCE_VERIFIER,
        resource: RESOURCE,
        client_assertion: await clientAssertion(),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

describe("Submission envelope inside a Request Object pushed through PAR (@spec mission#submission-via-par, #1503)", () => {
  it("accepts a mission_intent claim that is the Submission envelope as a JSON object, with the intent_hash of the equivalent form submission", async () => {
    const jar = await pushRequestObject(await signedRequestObject({ mission_intent: ENVELOPE }));
    expect(jar.status, JSON.stringify(jar.body)).toBe(201);
    const form = await pushForm(JSON.stringify(ENVELOPE));
    expect(form.status, JSON.stringify(form.body)).toBe(201);
    const fromRequestObject = (await approve(jar.body.request_uri as string)).record;
    const fromForm = (await approve(form.body.request_uri as string)).record;
    expect(fromRequestObject?.id).not.toBe(fromForm?.id);
    expect(fromRequestObject?.intent_hash).toBe(fromForm?.intent_hash);
    expect(fromRequestObject?.intent_hash).toBe(intentHash(ISSUER, INTENT as never));
  });

  it("refuses a mission_intent claim whose value is a string, even the envelope's own serialization, or any other value that is not a JSON object, with invalid_request", async () => {
    for (const claim of [JSON.stringify(ENVELOPE), "", 17, true, null]) {
      const res = await pushRequestObject(await signedRequestObject({ mission_intent: claim }));
      expect(res.status, `${JSON.stringify(claim)}: ${JSON.stringify(res.body)}`).toBe(400);
      expect(res.body.error).toBe("invalid_request");
      expect(res.body.error_description).toContain("mission_intent in a Request Object must be a JSON object");
    }
    // An array value is refused by the provider as a repeated parameter.
    const array = await pushRequestObject(await signedRequestObject({ mission_intent: [JSON.stringify(ENVELOPE)] }));
    expect(array.status, JSON.stringify(array.body)).toBe(400);
    expect(array.body.error).toBe("invalid_request");
  });

  it("refuses a Request Object whose payload repeats a member name, inside the envelope or among its claims, with invalid_request", async () => {
    const claims = await requestObjectClaims({ iss: CLIENT, aud: ISSUER, exp: Math.floor(Date.now() / 1000) + 60 });
    const prefix = JSON.stringify(claims).slice(0, -1);
    const inEnvelope = `${prefix},"mission_intent":{"intent":${JSON.stringify(INTENT)},"intent":${JSON.stringify(INTENT)}}}`;
    const claimTwice = `${prefix},"mission_intent":${JSON.stringify(ENVELOPE)},"mission_intent":${JSON.stringify(ENVELOPE)}}`;
    for (const payload of [inEnvelope, claimTwice]) {
      const res = await pushRequestObject(await signedRawRequestObject(payload));
      expect(res.status, JSON.stringify(res.body)).toBe(400);
      expect(res.body.error).toBe("invalid_request");
      expect(res.body.error_description).toContain("duplicate JSON member name");
    }
  });

  it("refuses a push that carries a mission_intent outside its Request Object with invalid_request", async () => {
    // Control: the same Request Object, pushed alone, is accepted.
    const alone = await pushRequestObject(await signedRequestObject({ mission_intent: ENVELOPE }));
    expect(alone.status, JSON.stringify(alone.body)).toBe(201);
    const widened = JSON.stringify({ intent: { ...INTENT, goal: "Reconcile and pay Q3 invoices" } });
    for (const [inside, outside] of [
      [{ mission_intent: ENVELOPE }, JSON.stringify(ENVELOPE)],
      [{ mission_intent: ENVELOPE }, widened],
      [{}, JSON.stringify(ENVELOPE)],
    ] as const) {
      const res = await pushRequestObject(await signedRequestObject(inside), { mission_intent: outside });
      expect(res.status, JSON.stringify(res.body)).toBe(400);
      expect(res.body.error).toBe("invalid_request");
      expect(res.body.error_description).toContain("outside the Request Object");
    }
  });

  it("refuses an unsigned Request Object (alg none) with invalid_request_object", async () => {
    const unsigned = new UnsecuredJWT(await requestObjectClaims({ mission_intent: ENVELOPE }))
      .setIssuer(CLIENT)
      .setAudience(ISSUER)
      .setIssuedAt()
      .setExpirationTime("1m")
      .encode();
    const res = await pushRequestObject(unsigned);
    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(res.body.error).toBe("invalid_request_object");
  });

  it("advertises Request Object support, signed with ES256 only, in its metadata", async () => {
    const meta = (await (await fetch(`${ISSUER}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
    expect(meta.request_parameter_supported).toBe(true);
    expect(meta.request_object_signing_alg_values_supported).toEqual(["ES256"]);
  });
});

describe("Submission envelope as the form parameter of a push (@spec mission#submission-via-par, #1503)", () => {
  it("refuses a form mission_intent that does not parse to a JSON object, including a JSON string of the envelope, with invalid_request", async () => {
    for (const value of ["[]", '"x"', JSON.stringify(JSON.stringify(ENVELOPE)), "17", "null"]) {
      const res = await pushForm(value);
      expect(res.status, `${value}: ${JSON.stringify(res.body)}`).toBe(400);
      expect(res.body.error).toBe("invalid_request");
      expect(res.body.error_description).toContain("mission_intent must be a JSON object");
    }
    for (const value of ["x", "{"]) {
      const res = await pushForm(value);
      expect(res.status, `${value}: ${JSON.stringify(res.body)}`).toBe(400);
      expect(res.body.error).toBe("invalid_request");
      expect(res.body.error_description).toContain("mission_intent must be valid JSON");
    }
  });
});

const READ = [{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] }];
const MISSING_RESOURCE = [{ type: "mission_resource_access", actions: ["payments:invoice.read"] }];
const UNSUPPORTED_TYPE = [{ type: "urn:example:unsupported", resource: RESOURCE }];
const MALFORMED_ENVELOPES: [label: string, envelope: unknown][] = [
  ["unknown envelope member", { intent: INTENT, note: "x" }],
  ["intent not an object", { intent: 17 }],
];

/** A push whose Request Object carries this mission_intent claim and, when given, this proposal. */
async function pushCarrying(missionIntent: unknown, proposal?: unknown) {
  return pushRequestObject(
    await signedRequestObject({
      mission_intent: missionIntent,
      ...(proposal === undefined ? {} : { authorization_details: proposal }),
    }),
  );
}

/** Each case is refused with the expected error code. */
async function expectRefused(cases: [label: string, missionIntent: unknown, proposal: unknown, error: string][]) {
  for (const [label, missionIntent, proposal, error] of cases) {
    const res = await pushCarrying(missionIntent, proposal);
    expect(res.status, `${label}: ${JSON.stringify(res.body)}`).toBe(400);
    expect(res.body.error, `${label}: ${JSON.stringify(res.body)}`).toBe(error);
  }
}

describe("Submission Processing Order on the Request Object path (@spec mission#submission-processing, #1512)", () => {
  it("refuses a malformed Submission envelope alone with invalid_request", async () => {
    await expectRefused(MALFORMED_ENVELOPES.map(([label, envelope]) => [label, envelope, READ, "invalid_request"]));
  });

  it("refuses a malformed proposal alone, beside a valid envelope, with invalid_authorization_details", async () => {
    await expectRefused([
      ["proposal entry missing its resource", ENVELOPE, MISSING_RESOURCE, "invalid_authorization_details"],
      ["proposal entry of an unsupported type", ENVELOPE, UNSUPPORTED_TYPE, "invalid_authorization_details"],
    ]);
  });

  it("a malformed Submission envelope together with a malformed proposal is refused at step 1, with invalid_request", async () => {
    await expectRefused([
      ...MALFORMED_ENVELOPES.flatMap(([label, envelope]): [string, unknown, unknown, string][] => [
        [`${label} and a proposal entry missing its resource`, envelope, MISSING_RESOURCE, "invalid_request"],
        [`${label} and a proposal entry of an unsupported type`, envelope, UNSUPPORTED_TYPE, "invalid_request"],
      ]),
      ["a string claim and a proposal entry missing its resource", JSON.stringify(ENVELOPE), MISSING_RESOURCE, "invalid_request"],
    ]);
  });

  it("an intent object that fails validation together with a malformed proposal is refused at step 2, with invalid_request", async () => {
    const invalidIntent = { intent: { ...INTENT, goal: 17 } };
    await expectRefused([
      ["invalid Intent only", invalidIntent, READ, "invalid_request"],
      ["invalid Intent and a proposal entry missing its resource", invalidIntent, MISSING_RESOURCE, "invalid_request"],
      ["invalid Intent and a proposal entry of an unsupported type", invalidIntent, UNSUPPORTED_TYPE, "invalid_request"],
    ]);
  });

  it("a structurally invalid evidence entry together with a malformed proposal is refused at step 1, with invalid_request, and an unsupported evidence type waits for step 6", async () => {
    const untyped = { intent: INTENT, evidence: [{ assertion: "x" }] };
    const notAnObject = { intent: INTENT, evidence: ["x"] };
    const unknownType = { intent: INTENT, evidence: [{ type: "urn:test:intent-evidence:unregistered" }] };
    await expectRefused([
      ["an evidence entry without a type only", untyped, READ, "invalid_request"],
      ["an evidence entry that is not an object only", notAnObject, READ, "invalid_request"],
      ["an unsupported evidence type only", unknownType, READ, "invalid_mission_intent_evidence"],
      ["an evidence entry without a type and a proposal entry missing its resource", untyped, MISSING_RESOURCE, "invalid_request"],
      ["an evidence entry that is not an object and a proposal entry of an unsupported type", notAnObject, UNSUPPORTED_TYPE, "invalid_request"],
      ["an unsupported evidence type and a proposal entry missing its resource", unknownType, MISSING_RESOURCE, "invalid_authorization_details"],
    ]);
  });

  it("accepts a valid envelope with a valid proposal through PAR, approval, code redemption and token issuance", async () => {
    const par = await pushCarrying(ENVELOPE, READ);
    expect(par.status, JSON.stringify(par.body)).toBe(201);
    const { record, code } = await approve(par.body.request_uri as string);
    expect(record?.proposed_authority).toEqual(READ);
    expect(code, "the approval redirect carries a code").toBeTruthy();
    const token = await redeem(code as string);
    expect(token.status, JSON.stringify(token.body)).toBe(200);
    expect(token.body.access_token).toBeTruthy();
    expect(token.body.mission_id).toBe(record?.id);
    const granted = token.body.authorization_details as { type: string; resource: string; actions: string[] }[];
    expect(granted.length).toBeGreaterThan(0);
    for (const entry of granted) {
      expect(entry.type).toBe("mission_resource_access");
      expect(entry.resource).toBe(RESOURCE);
    }
    expect(granted.flatMap((e) => e.actions)).toContain("payments:invoice.read");
  });
});
