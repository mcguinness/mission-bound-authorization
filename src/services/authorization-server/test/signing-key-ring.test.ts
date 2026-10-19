/**
 * @spec mission#mission-bound-tokens (verification keys), #831 slice 1:
 * durable AS signing keys.
 *
 * A key ring file, initialized once, keeps the AS's four role keys under
 * their configured `kid` across restarts; loading never falls back to
 * generation. These tests witness the ring's file discipline, every refusal,
 * the environment selector deployments use, and, end to end, that an access
 * token signed before a restart verifies against the restarted AS's JWKS
 * while its introspection does not survive (the issuance store is in memory,
 * #250's).
 */
import { FIXTURE_BROWSER_LOGIN, floorApprovalHeaders, TEST_APPROVAL_PRINCIPALS } from "./approval-fixture.js";

import { chmodSync, mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CANONICAL_RESOURCE, TOPOLOGY } from "@mission/demo-data";
import { calculateJwkThumbprint, createLocalJWKSet, decodeJwt, exportJWK, generateKeyPair, importJWK, jwtVerify, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import {
  ApprovalSessionStore,
  AS_SIGNING_ROLES,
  buildAuthorizationServer,
  initSigningKeyRing,
  loadSigningKeyRing,
  SIGNING_KEY_RING_FORMAT,
  SigningKeyRingError,
  signingKeysFromEnv,
} from "../src/index.js";

void FIXTURE_BROWSER_LOGIN;
const FLOOR_SESSIONS = new ApprovalSessionStore();
const PORT = 14831;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const ROLES = {
  asToken: TOPOLOGY.keys.asToken,
  asStatus: TOPOLOGY.keys.asStatus,
  asTxn: TOPOLOGY.keys.asTxn,
  asContinuation: TOPOLOGY.keys.asContinuation,
};
const KIDS = AS_SIGNING_ROLES.map((r) => ROLES[r].kid).sort();
const PRIVATE_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/** A fresh private directory (mode 0700) and a ring path inside it. */
function ringPath(): string {
  return join(mkdtempSync(join(tmpdir(), "key-ring-")), "keys", "as-signing-keys.json");
}

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };

async function proof(keys: Keys, extra: Record<string, unknown> = {}): Promise<string> {
  return new SignJWT({ htu: `${ISSUER}/token`, htm: "POST", ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(keys.privateKey);
}

/** The thumbprints of the keys the AS publishes at /jwks, by kid; asserts no private member is published. */
async function publishedThumbprints(): Promise<Record<string, string>> {
  const res = await fetch(`${ISSUER}/jwks`);
  expect(res.status).toBe(200);
  const { keys } = (await res.json()) as { keys: Record<string, unknown>[] };
  expect(keys.map((k) => k.kid).sort()).toEqual(KIDS);
  const out: Record<string, string> = {};
  for (const k of keys) {
    for (const m of PRIVATE_MEMBERS) expect(k[m], `${String(k.kid)} publishes ${m}`).toBeUndefined();
    out[k.kid as string] = await calculateJwkThumbprint(k as never);
  }
  return out;
}

/** Boot an AS on PORT with `signingKeys`, run `body`, then close it. */
async function withAs<T>(
  signingKeys: { ring: string } | { ephemeral: true } | undefined,
  body: (as: Awaited<ReturnType<typeof buildAuthorizationServer>>) => Promise<T>,
): Promise<T> {
  const as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    approvalSessions: FLOOR_SESSIONS,
    ...(signingKeys ? { signingKeys } : {}),
  });
  const server: Server = as.provider.listen(PORT);
  await new Promise<void>((r) => server.once("listening", () => r()));
  try {
    return await body(as);
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
}

function storeCookies(res: Response, jar: Map<string, string>): void {
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const eq = (pair as string).indexOf("=");
    jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
  }
}
const cookieHeader = (jar: Map<string, string>) => [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");

/** PAR, approval and code exchange as ap-agent against the running AS: a Mission-bound access token. */
async function mintAccessToken(as: Awaited<ReturnType<typeof buildAuthorizationServer>>): Promise<string> {
  const clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  const assertion = () =>
    new SignJWT({})
      .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
      .setIssuer("ap-agent")
      .setSubject("ap-agent")
      .setAudience(ISSUER)
      .setIssuedAt()
      .setExpirationTime("2m")
      .setJti(crypto.randomUUID())
      .sign(clientKey);
  const dpop = await generateKeyPair("ES256", { extractable: true });
  const jar = new Map<string, string>();
  const verifier = "signing-key-ring-verifier-0123456789-0123456789-0123456789";
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString(
    "base64url",
  );
  const par = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      resource: CANONICAL_RESOURCE,
      code_challenge: challenge,
      code_challenge_method: "S256",
      login_hint: "alice",
      mission_intent: JSON.stringify({
        intent: { goal: "Read Acme invoices", target_resources: [CANONICAL_RESOURCE], expires_at: "2027-01-01T00:00:00Z" },
      }),
      authorization_details: JSON.stringify([
        { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"], constraints: { vendors: ["acme"] } },
      ]),
      client_assertion: await assertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  expect(par.status).toBe(201);
  const { request_uri } = (await par.json()) as { request_uri: string };
  let res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri })}`, {
    redirect: "manual",
  });
  storeCookies(res, jar);
  let location = res.headers.get("location") as string;
  const uid = location.split("/interaction/")[1] as string;
  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { ...floorApprovalHeaders(FLOOR_SESSIONS, uid, cookieHeader(jar)), "content-type": "application/json" },
    body: JSON.stringify({ decision: "approve" }),
  });
  storeCookies(res, jar);
  location = res.headers.get("location") as string;
  while (location?.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookieHeader(jar) } });
    storeCookies(res, jar);
    location = res.headers.get("location") as string;
  }
  const code = new URL(location).searchParams.get("code") as string;
  const send = async (extra: Record<string, unknown> = {}) =>
    fetch(`${ISSUER}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await proof(dpop, extra) },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: verifier,
        resource: CANONICAL_RESOURCE,
        client_assertion: await assertion(),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let tok = await send();
  const nonce = tok.headers.get("dpop-nonce");
  if (tok.status === 400 && nonce) tok = await send({ nonce });
  const body = (await tok.json()) as Record<string, unknown>;
  expect(tok.status, JSON.stringify(body)).toBe(200);
  return body.access_token as string;
}

async function introspect(token: string): Promise<Record<string, unknown>> {
  const res = await fetch(`${ISSUER}/introspect`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${Buffer.from("rs-payments:dev-introspection-rs-payments").toString("base64")}`,
    },
    body: new URLSearchParams({ token }).toString(),
  });
  expect(res.status).toBe(200);
  return (await res.json()) as Record<string, unknown>;
}

describe("the signing key ring file (@spec #831 slice 1)", () => {
  it("is written once, 0600 in a 0700 directory, holding the four role keys under their configured kids; a second init refuses", async () => {
    const file = ringPath();
    const published = await initSigningKeyRing(file, ISSUER, ROLES);
    expect(published.map((k) => k.kid).sort()).toEqual(KIDS);
    for (const k of published) for (const m of PRIVATE_MEMBERS) expect(k[m]).toBeUndefined();
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(statSync(join(file, "..")).mode & 0o777).toBe(0o700);
    const ring = JSON.parse(readFileSync(file, "utf8")) as { format: string; issuer: string; roles: Record<string, { kid: string }> };
    expect(ring.format).toBe(SIGNING_KEY_RING_FORMAT);
    expect(ring.issuer).toBe(ISSUER);
    expect(Object.keys(ring.roles).sort()).toEqual([...AS_SIGNING_ROLES].sort());
    const before = readFileSync(file, "utf8");
    await expect(initSigningKeyRing(file, ISSUER, ROLES)).rejects.toThrow(/already exists; a ring is initialized once/);
    expect(readFileSync(file, "utf8")).toBe(before);
  });

  it("refuses to initialize in a directory that grants group or other access", async () => {
    const dir = join(mkdtempSync(join(tmpdir(), "key-ring-")), "open");
    mkdirSync(dir, { mode: 0o755 });
    chmodSync(dir, 0o755);
    await expect(initSigningKeyRing(join(dir, "ring.json"), ISSUER, ROLES)).rejects.toThrow(/grants group or other access/);
  });

  it("loads the same keys every time, and another ring's keys differ", async () => {
    const file = ringPath();
    await initSigningKeyRing(file, ISSUER, ROLES);
    const a = await loadSigningKeyRing(file, ISSUER, ROLES);
    const b = await loadSigningKeyRing(file, ISSUER, ROLES);
    const other = ringPath();
    await initSigningKeyRing(other, ISSUER, ROLES);
    const c = await loadSigningKeyRing(other, ISSUER, ROLES);
    for (const role of AS_SIGNING_ROLES) {
      expect(a[role].publicJwk.kid).toBe(ROLES[role].kid);
      expect(await calculateJwkThumbprint(a[role].publicJwk as never)).toBe(await calculateJwkThumbprint(b[role].publicJwk as never));
      expect(await calculateJwkThumbprint(a[role].publicJwk as never)).not.toBe(
        await calculateJwkThumbprint(c[role].publicJwk as never),
      );
    }
  });

  it("refuses, never generating a replacement, a ring that is missing, open to others, malformed or mismatched", async () => {
    const valid = ringPath();
    await initSigningKeyRing(valid, ISSUER, ROLES);
    const good = JSON.parse(readFileSync(valid, "utf8")) as Record<string, unknown>;
    const roles = good.roles as Record<string, Record<string, unknown>>;
    /** Write `content` as a 0600 ring in a fresh 0700 directory. */
    const ringWith = (content: string): string => {
      const file = ringPath();
      mkdirSync(join(file, ".."), { recursive: true, mode: 0o700 });
      writeFileSync(file, content, { mode: 0o600 });
      return file;
    };
    const variant = (edit: (r: Record<string, unknown>) => void): string => {
      const r = structuredClone(good);
      edit(r);
      return ringWith(JSON.stringify(r));
    };
    const openFile = ringWith(JSON.stringify(good));
    chmodSync(openFile, 0o644);
    const cases: [string, string, RegExp][] = [
      ["missing", join(mkdtempSync(join(tmpdir(), "key-ring-")), "absent.json"), /no ring at .*pnpm keys init/],
      ["readable by others", openFile, /grants group or other access; it must be mode 0600/],
      ["not JSON", ringWith("{not json"), /is not valid JSON/],
      ["not a ring", variant((r) => { r.format = "something-else"; }), /is not a mission-as-signing-key-ring\/1 ring/],
      ["another issuer", variant((r) => { r.issuer = "https://elsewhere.example"; }), /is for issuer https:\/\/elsewhere\.example/],
      ["a missing role", variant((r) => { delete (r.roles as Record<string, unknown>).asTxn; }), /has no asTxn key/],
      ["an extra role", variant((r) => { (r.roles as Record<string, unknown>).asExtra = roles.asTxn; }), /carries unknown roles: asExtra/],
      ["a changed kid", variant((r) => { (r.roles as Record<string, Record<string, unknown>>).asStatus!.kid = "as-status-2"; }), /asStatus is recorded under kid as-status-2, not the configured as-status/],
      ["a changed alg", variant((r) => { (r.roles as Record<string, Record<string, unknown>>).asToken!.alg = "ES256"; }), /asToken is recorded with alg ES256, not the configured RS256/],
      ["no private key", variant((r) => { delete ((r.roles as Record<string, Record<string, Record<string, unknown>>>).asTxn!.private_jwk!).d; }), /asTxn holds no private key/],
      ["a key that does not import", variant((r) => { ((r.roles as Record<string, Record<string, Record<string, unknown>>>).asContinuation!.private_jwk!).d = "AAAA"; }), /asContinuation's key does not import/],
    ];
    for (const [name, file, message] of cases) {
      await expect(loadSigningKeyRing(file, ISSUER, ROLES), name).rejects.toThrow(message);
      await expect(loadSigningKeyRing(file, ISSUER, ROLES), name).rejects.toBeInstanceOf(SigningKeyRingError);
    }
    // The AS assembly refuses the same way: nothing listens, nothing is generated.
    await expect(
      buildAuthorizationServer({ issuer: ISSUER, signingKeys: { ring: cases[0]![1] } }),
    ).rejects.toThrow(/no ring at/);
  });

  it("a deployment chooses its keys from its environment: a ring path or MISSION_EPHEMERAL_KEYS=1, never neither or both", () => {
    expect(signingKeysFromEnv({ MISSION_KEY_RING: "/var/keys/ring.json" })).toEqual({ ring: "/var/keys/ring.json" });
    expect(signingKeysFromEnv({ MISSION_EPHEMERAL_KEYS: "1" })).toEqual({ ephemeral: true });
    expect(() => signingKeysFromEnv({})).toThrow(/choose the signing keys: MISSION_KEY_RING=<path>/);
    expect(() => signingKeysFromEnv({ MISSION_EPHEMERAL_KEYS: "true" })).toThrow(/choose the signing keys/);
    expect(() => signingKeysFromEnv({ MISSION_KEY_RING: "/r.json", MISSION_EPHEMERAL_KEYS: "1" })).toThrow(/not both/);
  });
});

describe("an AS signing from a key ring across restarts (@spec #831 slice 1)", () => {
  it("publishes the same four keys after a restart from one ring, and different keys from two ephemeral boots, never a private member", async () => {
    const file = ringPath();
    await initSigningKeyRing(file, ISSUER, ROLES);
    const first = await withAs({ ring: file }, async (as) => {
      expect(as.signingKeyMode).toBe("ring");
      return { jwks: await publishedThumbprints(), status: as.kernel.statusVerificationKey().export({ format: "jwk" }) };
    });
    const second = await withAs({ ring: file }, async (as) => ({
      jwks: await publishedThumbprints(),
      status: as.kernel.statusVerificationKey().export({ format: "jwk" }),
    }));
    expect(second.jwks).toEqual(first.jwks);
    // The kernel's status signer, which governed-policy consents are checked against, is the ring's.
    expect(second.status).toEqual(first.status);

    const e1 = await withAs(undefined, async (as) => {
      expect(as.signingKeyMode).toBe("ephemeral");
      return publishedThumbprints();
    });
    const e2 = await withAs({ ephemeral: true }, async () => publishedThumbprints());
    for (const kid of KIDS) expect(e2[kid]).not.toBe(e1[kid]);
  });

  it("an access token signed before a restart verifies against the restarted AS's JWKS; its introspection does not survive the restart (#250)", async () => {
    const file = ringPath();
    await initSigningKeyRing(file, ISSUER, ROLES);
    const token = await withAs({ ring: file }, async (as) => {
      const minted = await mintAccessToken(as);
      expect((await introspect(minted)).active).toBe(true);
      return minted;
    });
    await withAs({ ring: file }, async () => {
      const jwks = (await (await fetch(`${ISSUER}/jwks`)).json()) as { keys: never[] };
      const { payload, protectedHeader } = await jwtVerify(token, createLocalJWKSet(jwks), { issuer: ISSUER, typ: "at+jwt" });
      expect(protectedHeader.kid).toBe(TOPOLOGY.keys.asToken.kid);
      expect(payload.jti).toBe(decodeJwt(token).jti);
      // Signature continuity only: the token issuance index is in memory, so
      // the restarted AS holds no record of minting it and introspection
      // answers inactive. Durable issuance state is #250's.
      expect(await introspect(token)).toEqual({ active: false });
    });
  });

  it("refuses a test-injected token key with a ring", async () => {
    const file = ringPath();
    await initSigningKeyRing(file, ISSUER, ROLES);
    const { privateKey } = await generateKeyPair(TOPOLOGY.keys.asToken.alg, { extractable: true });
    await expect(
      buildAuthorizationServer({
        issuer: ISSUER,
        signingKeys: { ring: file },
        testTokenSigningJwk: (await exportJWK(privateKey)) as never,
      }),
    ).rejects.toThrow(/testTokenSigningJwk cannot be combined with a key ring/);
  });
});
