/**
 * @spec mission#remediation-grains, mission#subset, mission#error-mapping
 * (#1303) — a token request's `authorization_details` (Section 6 of RFC 9396)
 * narrows the issued token. A refresh or code exchange naming a subset of what
 * the grant carries, as the effective set narrows it, gets exactly that
 * subset, in the access token and in the response. One naming more (an action
 * outside the grant, a relaxed constraint, a contained entry) is refused
 * `invalid_authorization_details`.
 *
 * On refresh, every refusal of the parameter, its validation included, lands
 * before oidc-provider consumes the presented token: a rotating refresh
 * refused after rotation spends the lineage (the successor never reaches the
 * client, and a retry with the presented token is reuse, which revokes the
 * grant). Each refusal below counts the refresh tokens saved and then
 * refreshes with the same token.
 *
 * Each test drives the full assembly over HTTP: PAR, approval, code exchange,
 * then the request under test.
 */
import { TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";

import { type Server } from "node:http";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import { decodeJwt, exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { ACCESS_TOKEN_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from "../src/adapters/continuation-grant.js";
import { buildAuthorizationServer, type BuiltAs } from "../src/index.js";
import { delegationHandleParams } from "./delegation-handle.helper.js";

const PORT = 14897;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE;
const FAR_EXP = "2027-06-01T00:00:00Z";
const VERIFIER = "token-request-rar-verifier-0123456789-0123456789-0123";
const LIST = "payments:invoice.list";
const READ = "payments:invoice.read";
const EXECUTE = "payments:payment.execute";
const ACME = { vendors: ["acme"] };
const MISSION_ENTRY = { type: "mission_resource_access", resource: RESOURCE, actions: [LIST, READ], constraints: ACME };
/** A requested entry; `null` constraints omits the member. */
const entry = (actions: string[], constraints: Record<string, unknown> | null = ACME) => ({
  type: "mission_resource_access",
  resource: RESOURCE,
  actions,
  ...(constraints ? { constraints } : {}),
});

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };
type Json = Record<string, unknown>;
type Entry = { resource: string; actions: string[]; constraints?: Json };

let as: BuiltAs;
let server: Server;
let clientKey: CryptoKey;

async function newKeys(): Promise<Keys> {
  return (await generateKeyPair("ES256", { extractable: true })) as Keys;
}

async function clientAssertion(): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
    .setIssuer("ap-agent")
    .setSubject("ap-agent")
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(clientKey);
}

async function dpopProof(keys: Keys, extra: Json = {}): Promise<string> {
  return new SignJWT({ htu: `${ISSUER}/token`, htm: "POST", ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(keys.privateKey);
}

async function token(params: Record<string, string>, keys: Keys): Promise<{ status: number; body: Json }> {
  const send = async (extra: Json = {}) =>
    fetch(`${ISSUER}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(keys, extra) },
      body: new URLSearchParams({
        ...params,
        client_assertion: await clientAssertion(),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return { status: res.status, body: (await res.json()) as Json };
}

/** PAR over the Mission entry and its approval: an authorization code. */
async function approvedCode(): Promise<string> {
  const challenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER)),
  ).toString("base64url");
  const par = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      resource: RESOURCE,
      code_challenge: challenge,
      code_challenge_method: "S256",
      login_hint: "alice",
      mission_intent: JSON.stringify({
        intent: { goal: "Read Acme invoices", target_resources: [RESOURCE], expires_at: FAR_EXP },
      }),
      authorization_details: JSON.stringify([MISSION_ENTRY]),
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const pushed = (await par.json()) as Json;
  expect(par.status, JSON.stringify(pushed)).toBe(201);
  const jar = new Map<string, string>();
  const keep = (res: Response) => {
    for (const line of res.headers.getSetCookie()) {
      const [pair] = line.split(";");
      const eq = (pair as string).indexOf("=");
      jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
    }
  };
  const cookie = () => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
  let res = await fetch(
    `${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: String(pushed.request_uri) })}`,
    { redirect: "manual" },
  );
  keep(res);
  const uid = (res.headers.get("location") ?? "").split("/interaction/")[1] as string;
  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { ...trustedApprovalHeaders(), "content-type": "application/json", cookie: cookie() },
    body: JSON.stringify({ decision: "approve" }),
  });
  keep(res);
  let location = res.headers.get("location") ?? "";
  while (location.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookie() } });
    keep(res);
    location = res.headers.get("location") ?? "";
  }
  return new URL(location).searchParams.get("code") as string;
}

const exchange = (code: string, keys: Keys, extra: Record<string, string> = {}) =>
  token(
    { grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: VERIFIER, resource: RESOURCE, ...extra },
    keys,
  );

/** An active Mission over MISSION_ENTRY: its access and refresh token. */
async function issue(): Promise<{ missionId: string; accessToken: string; refreshToken: string; keys: Keys }> {
  const keys = await newKeys();
  const exchanged = await exchange(await approvedCode(), keys);
  expect(exchanged.status, JSON.stringify(exchanged.body)).toBe(200);
  const accessToken = exchanged.body.access_token as string;
  const missionId = (decodeJwt(accessToken) as { mission: { id: string } }).mission.id;
  return { missionId, accessToken, refreshToken: exchanged.body.refresh_token as string, keys };
}

const asParam = (details: unknown): Record<string, string> =>
  details === undefined ? {} : { authorization_details: typeof details === "string" ? details : JSON.stringify(details) };

const refresh = (refreshToken: string, keys: Keys, details?: unknown) =>
  token({ grant_type: "refresh_token", refresh_token: refreshToken, resource: RESOURCE, ...asParam(details) }, keys);

/** An async-delegation family over the Mission's own access token: its refresh token rotates on every refresh. */
async function family(baseAccessToken: string, keys: Keys): Promise<string> {
  const handle = await token(delegationHandleParams(baseAccessToken, "ap-agent"), keys);
  expect(handle.status, JSON.stringify(handle.body)).toBe(200);
  const res = await token(
    {
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      request_refresh_token: "true",
      subject_token: handle.body.access_token as string,
      subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      resource: RESOURCE,
      creation_request_id: crypto.randomUUID(),
    },
    keys,
  );
  expect(res.status, JSON.stringify(res.body)).toBe(200);
  return res.body.refresh_token as string;
}

/** Run `fn`, counting the refresh tokens oidc-provider saves meanwhile. */
async function countingRefreshSaves<T>(fn: () => Promise<T>): Promise<{ result: T; saved: number }> {
  let saved = 0;
  const onSaved = () => {
    saved += 1;
  };
  as.provider.on("refresh_token.saved", onSaved);
  try {
    return { result: await fn(), saved };
  } finally {
    as.provider.removeListener("refresh_token.saved", onSaved);
  }
}

/**
 * An approval grant's refresh token rotates once 70% of its lifetime has
 * passed (oidc-provider's default rule, inlined in `rotateRefreshToken`).
 * Reading the elapsed share as 80% makes every approval refresh rotate.
 */
function pastSeventyPercent(): void {
  vi.spyOn(
    as.provider.RefreshToken.prototype as unknown as { ttlPercentagePassed(): number },
    "ttlPercentagePassed",
  ).mockReturnValue(80);
}

const tokenEntries = (accessToken: unknown): Entry[] =>
  (decodeJwt(accessToken as string) as { authorization_details: Entry[] }).authorization_details;
const actionsOf = (entries: Entry[]) => entries.flatMap((e) => e.actions).sort();

/** A 200 whose token and response both carry exactly `actions`, each entry still Acme-constrained. */
function expectIssued(res: { status: number; body: Json }, actions: string[]): void {
  expect(res.status, JSON.stringify(res.body)).toBe(200);
  const carried = tokenEntries(res.body.access_token);
  expect(actionsOf(carried)).toEqual([...actions].sort());
  for (const e of carried) expect(e.constraints?.vendors).toEqual(["acme"]);
  expect(res.body.authorization_details).toEqual(carried);
}

function expectRefused(res: { status: number; body: Json }, error: string): void {
  expect(res.status, JSON.stringify(res.body)).toBe(400);
  expect(res.body.error).toBe(error);
  expect(res.body.access_token).toBeUndefined();
}

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
  });
  server = as.provider.listen(PORT);
  await new Promise<void>((r) => server.once("listening", () => r()));
  clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("a refresh request's authorization_details narrows the issued token (@spec mission#remediation-grains, #1303)", () => {
  it("a narrower request issues exactly that subset, in the token and the response, and a later refresh may ask for the whole grant again", async () => {
    const m = await issue();
    expectIssued(await refresh(m.refreshToken, m.keys), [LIST, READ]);
    const narrowed = await refresh(m.refreshToken, m.keys, [entry([READ])]);
    expectIssued(narrowed, [READ]);
    // The refresh token keeps the grant (Section 6 of RFC 9396).
    const next = (narrowed.body.refresh_token as string | undefined) ?? m.refreshToken;
    expectIssued(await refresh(next, m.keys), [LIST, READ]);
  });

  it("an empty array names nothing: the token carries the whole grant", async () => {
    const m = await issue();
    expectIssued(await refresh(m.refreshToken, m.keys, []), [LIST, READ]);
  });
});

describe("a refresh request's authorization_details beyond the grant is refused before rotation (@spec mission#subset, mission#error-mapping, #1303)", () => {
  it("an action outside the grant is refused invalid_authorization_details, saving no refresh token, and the same token still refreshes", async () => {
    const m = await issue();
    pastSeventyPercent();
    const refused = await countingRefreshSaves(() => refresh(m.refreshToken, m.keys, [entry([READ, EXECUTE])]));
    expectRefused(refused.result, "invalid_authorization_details");
    expect(refused.saved).toBe(0);
    const again = await countingRefreshSaves(() => refresh(m.refreshToken, m.keys));
    expectIssued(again.result, [LIST, READ]);
    expect(again.saved).toBe(1); // it rotated: the refusal had consumed nothing
  });

  it("relaxing a constraint (an entry without the grant's vendors) is refused, not re-narrowed", async () => {
    const m = await issue();
    pastSeventyPercent();
    const refused = await countingRefreshSaves(() => refresh(m.refreshToken, m.keys, [entry([READ], null)]));
    expectRefused(refused.result, "invalid_authorization_details");
    expect(refused.saved).toBe(0);
    expectIssued(await refresh(m.refreshToken, m.keys), [LIST, READ]);
  });

  it("an entry the effective set removed (contained) is refused; the remainder is still issued on request", async () => {
    const m = await issue();
    as.kernel.contain(m.missionId, {
      event: { type: "anomaly.detected", source: "svc:soc", observed_at: new Date().toISOString(), event_id: crypto.randomUUID() },
      remove: [{ resource: RESOURCE, actions: [LIST] }],
    });
    expectRefused(await refresh(m.refreshToken, m.keys, [entry([LIST])]), "invalid_authorization_details");
    expectIssued(await refresh(m.refreshToken, m.keys, [entry([READ])]), [READ]);
    expectIssued(await refresh(m.refreshToken, m.keys), [READ]);
  });

  it("a malformed or schema-invalid authorization_details on a rotating approval grant is refused saving no refresh token, and the same token still refreshes", async () => {
    const m = await issue();
    pastSeventyPercent();
    const cases: Array<[unknown, string]> = [
      ["not json", "invalid_request"],
      [[{ type: "mission_resource_access", actions: [READ] }], "invalid_authorization_details"], // no resource: the schema
      [[{ type: "payment_initiation", actions: [READ] }], "invalid_authorization_details"], // an unadvertised type
      [[entry([READ], { vendors: "acme" })], "invalid_authorization_details"], // a malformed constraint: the schema, before any comparison
    ];
    for (const [details, error] of cases) {
      const refused = await countingRefreshSaves(() => refresh(m.refreshToken, m.keys, details));
      expectRefused(refused.result, error);
      expect(refused.saved, JSON.stringify(details)).toBe(0);
    }
    expectIssued(await refresh(m.refreshToken, m.keys), [LIST, READ]);
  });

  // @spec mission#subset (#1399, D538): a requested entry within the grant but
  // carrying an unsupported member is refused before rotation, never issued
  // rebuilt without the member.
  it("an entry carrying an unsupported member is refused invalid_authorization_details saving no refresh token, and the same token still refreshes", async () => {
    const m = await issue();
    pastSeventyPercent();
    const refused = await countingRefreshSaves(() =>
      refresh(m.refreshToken, m.keys, [{ ...entry([READ]), invoice_ids: ["INV-7"] }]),
    );
    expectRefused(refused.result, "invalid_authorization_details");
    expect(refused.result.body.error_description).toMatch(/invoice_ids is not a supported member/);
    expect(refused.saved).toBe(0);
    expectIssued(await refresh(m.refreshToken, m.keys, [entry([READ])]), [READ]);
  });

  it("an async-delegation family, which rotates on every refresh: a schema-invalid or excess request is refused saving nothing, and the same token still refreshes", async () => {
    const m = await issue();
    const familyToken = await family(m.accessToken, m.keys);
    for (const details of [[{ type: "mission_resource_access", actions: [READ] }], [entry([READ, EXECUTE])]]) {
      const refused = await countingRefreshSaves(() => refresh(familyToken, m.keys, details));
      expectRefused(refused.result, "invalid_authorization_details");
      expect(refused.saved, JSON.stringify(details)).toBe(0);
    }
    const again = await countingRefreshSaves(() => refresh(familyToken, m.keys, [entry([READ])]));
    expectIssued(again.result, [READ]);
    expect(again.saved).toBe(1);
  });
});

describe("a code exchange's authorization_details narrows the issued token (@spec mission#subset, mission#error-mapping, #1303)", () => {
  it("a narrower request issues exactly that subset", async () => {
    const res = await exchange(await approvedCode(), await newKeys(), asParam([entry([READ])]));
    expectIssued(res, [READ]);
  });

  it("an action outside the grant is refused invalid_authorization_details", async () => {
    const res = await exchange(await approvedCode(), await newKeys(), asParam([entry([READ, EXECUTE])]));
    expectRefused(res, "invalid_authorization_details");
  });
});
