/**
 * @spec runtime-oauth#token-validation, RFC 8725 Section 3.12 (#825 PR 2a, D312)
 *
 * Each token class verifies only under the keys locally pinned to its role.
 * Every key here sits in both of the resource's key sets and is trusted for
 * SOME class, so a token signed by a trusted key of the wrong role is
 * refused exactly as an untrusted key is, before any claim is used.
 */

import { createPublicKey, randomUUID } from "node:crypto";
import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
  CANONICAL_RESOURCE,
  type DpopKeys,
  dpopProofFor,
  type KeyRoles,
  McpPaymentsServer,
  PaymentsStore,
  roleKeyResolvers,
} from "../src/index.js";

const ISSUER = "https://as.test";
const HTU = CANONICAL_RESOURCE;
const HTM = "POST";
const MISSION = { id: "msn_825_roles", issuer: ISSUER };
const ROLES: KeyRoles = {
  accessToken: ["as-token"],
  attenuationRoot: ["as-attenuation"],
  transactionToken: ["as-txn"],
};
/** jose's refusal when no key in the role's set matches: the untrusted-key path. */
const NO_KEY = /no applicable key/;

interface RoleKey {
  kid: string;
  privateKey: CryptoKey;
  jwk: Record<string, unknown>;
}
let access: RoleKey;
let root: RoleKey;
let txn: RoleKey;
let holder: DpopKeys;
let holderJkt: string;

async function roleKey(kid: string): Promise<RoleKey> {
  const kp = await generateKeyPair("ES256", { extractable: true });
  return { kid, privateKey: kp.privateKey, jwk: { ...(await exportJWK(kp.publicKey)), kid, alg: "ES256" } };
}

/** All three keys in both key sets: only the role pin tells them apart. */
function server(roles: KeyRoles = ROLES): McpPaymentsServer {
  const keys = [access.jwk, root.jwk, txn.jwk];
  return new McpPaymentsServer({
    pep: undefined as never, // signature verification refuses before any PEP use
    payments: new PaymentsStore(),
    loadView: () => undefined,
    jwks: { keys },
    txnTokenJwks: { keys },
    asIssuer: ISSUER,
    keyRoles: roles,
    issuer: ISSUER,
  });
}

function sign(
  typ: string,
  claims: Record<string, unknown>,
  key: RoleKey,
  header: Record<string, unknown> = { kid: key.kid },
): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "ES256", typ, ...header } as never)
    .sign(key.privateKey);
}

function base(): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: ISSUER,
    aud: CANONICAL_RESOURCE,
    sub: "alice",
    client_id: "ap-agent",
    jti: randomUUID(),
    iat: now,
    exp: now + 300,
    cnf: { jkt: holderJkt },
  };
}

const accessClaims = () => ({
  ...base(),
  mission: MISSION,
  authorization_details: [
    { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] },
  ],
});

beforeAll(async () => {
  access = await roleKey("as-token");
  root = await roleKey("as-attenuation");
  txn = await roleKey("as-txn");
  holder = await generateKeyPair("ES256", { extractable: true });
  holderJkt = await calculateJwkThumbprint(await exportJWK(holder.publicKey));
});

describe("each token class verifies only under its own role's keys (@spec runtime-oauth#token-validation, #825, D312)", () => {
  it("admits an access token signed by the access-token key, over HTTP and the mediated channel", async () => {
    const rs = server();
    const token = await sign("at+jwt", accessClaims(), access);
    const overHttp = await rs.validateToken(token, await dpopProofFor(holder, HTU, HTM, token), HTU, HTM);
    expect(overHttp.sub).toBe("alice");
    expect((await rs.validateMissionToken(token)).sub).toBe("alice");
  });

  it.each([
    ["the transaction-token key", () => txn],
    ["the attenuation-root key", () => root],
  ])("refuses an access token signed by %s, on both transports", async (_label, key) => {
    const rs = server();
    const token = await sign("at+jwt", accessClaims(), key());
    await expect(
      rs.validateToken(token, await dpopProofFor(holder, HTU, HTM, token), HTU, HTM),
    ).rejects.toThrow(NO_KEY);
    await expect(rs.validateMissionToken(token)).rejects.toThrow(NO_KEY);
  });

  it("refuses an attenuation root signed by the access-token key, and verifies the root key's signature", async () => {
    const rs = server();
    const claims = { ...base(), mission: { ...MISSION, authority_hash: "sha-256:roles" } };
    const wrongRole = await sign("aat+jwt", claims, access);
    await expect(
      rs.validateAttenuationChain([wrongRole], await dpopProofFor(holder, HTU, HTM, wrongRole), HTU, HTM),
    ).rejects.toThrow(NO_KEY);
    // Under its own role's key the signature verifies and the chain's own
    // checks run (here, the toolless root fails them): the key was accepted.
    const pinned = await sign("aat+jwt", claims, root);
    const outcome = await rs
      .validateAttenuationChain([pinned], await dpopProofFor(holder, HTU, HTM, pinned), HTU, HTM)
      .then(
        () => "admitted",
        (e: Error) => e.message,
      );
    expect(outcome).not.toMatch(NO_KEY);
  });

  it("refuses a transaction token signed by the access-token key, though that key is in the transaction key set", async () => {
    const rs = server();
    const claims = {
      ...base(),
      txn: "txn_roles",
      parameter_digest: "sha-256:roles",
      mission: MISSION,
    };
    const popFor = async (t: string) => ({ proof: await dpopProofFor(holder, HTU, HTM, t), htu: HTU, htm: HTM });
    const wrongRole = await sign("mission-txn-token+jwt", claims, access);
    expect(await rs.verifyTransactionCredential(wrongRole, await popFor(wrongRole))).toEqual({
      ok: false,
      refusal_reason: "txn_invalid",
    });
    // Under the transaction key the signature verifies and the next check
    // runs: no challenge was retained for this `txn`.
    const pinned = await sign("mission-txn-token+jwt", claims, txn);
    expect(await rs.verifyTransactionCredential(pinned, await popFor(pinned))).toEqual({
      ok: false,
      refusal_reason: "txn_unknown",
    });
  });

  it("refuses a token whose header names no kid, even with one key in the role", async () => {
    const rs = server();
    const token = await sign("at+jwt", accessClaims(), access, {});
    await expect(rs.validateMissionToken(token)).rejects.toThrow(/names no kid/);
  });
});

describe("the key-role pin is checked at startup (@spec runtime-oauth#token-validation, D312)", () => {
  it("refuses a kid configured for two roles", () => {
    expect(() =>
      roleKeyResolvers(
        { accessToken: ["as-token"], attenuationRoot: ["as-token"], transactionToken: [] },
        { jwks: { keys: [access.jwk] } },
      ),
    ).toThrow(/both accessToken and attenuationRoot/);
  });

  it("refuses a kid that names no key in its key set", () => {
    expect(() =>
      roleKeyResolvers(
        { accessToken: ["as-missing"], attenuationRoot: [], transactionToken: [] },
        { jwks: { keys: [access.jwk] } },
      ),
    ).toThrow(/accessToken kid as-missing names no key/);
  });

  it("refuses a transaction-token kid when no transaction key set is configured", () => {
    expect(() =>
      roleKeyResolvers(
        { accessToken: [], attenuationRoot: [], transactionToken: ["as-txn"] },
        { jwks: { keys: [txn.jwk] } },
      ),
    ).toThrow(/transactionToken kid as-txn names no key/);
  });

  it("refuses at server construction, not at the first request", () => {
    expect(() => server({ accessToken: ["as-token"], attenuationRoot: ["as-token"], transactionToken: [] })).toThrow(
      /key role pin/,
    );
  });
});

describe("one key material serves one role, whatever kids it is published under (@spec runtime-oauth#token-validation, D312, #1123 review)", () => {
  it("refuses one key published as the access-token kid and the transaction kid, across jwks and txnTokenJwks", () => {
    const asTokenAlias = { ...txn.jwk, kid: "as-token" };
    expect(() =>
      roleKeyResolvers(
        { accessToken: ["as-token"], attenuationRoot: [], transactionToken: ["as-txn"] },
        { jwks: { keys: [asTokenAlias] }, txnTokenJwks: { keys: [txn.jwk] } },
      ),
    ).toThrow(/transactionToken kid as-txn is the same key as accessToken kid as-token/);
  });

  it("refuses to construct a server whose access and transaction roles share one key under two kids", () => {
    const shared = { ...txn.jwk, kid: "as-token" };
    expect(
      () =>
        new McpPaymentsServer({
          pep: undefined as never,
          payments: new PaymentsStore(),
          loadView: () => undefined,
          jwks: { keys: [shared] },
          txnTokenJwks: { keys: [txn.jwk] },
          asIssuer: ISSUER,
          keyRoles: { accessToken: ["as-token"], attenuationRoot: [], transactionToken: ["as-txn"] },
          issuer: ISSUER,
        }),
    ).toThrow(/is the same key as/);
  });

  it("refuses one key published as the access-token kid and the attenuation-root kid in one key set", () => {
    const rootAlias = { ...access.jwk, kid: "as-attenuation" };
    expect(() =>
      roleKeyResolvers(
        { accessToken: ["as-token"], attenuationRoot: ["as-attenuation"], transactionToken: [] },
        { jwks: { keys: [access.jwk, rootAlias] } },
      ),
    ).toThrow(/attenuationRoot kid as-attenuation is the same key as accessToken kid as-token/);
  });

  it("allows one key under two kids within one role (a rotation alias)", () => {
    const rotationAlias = { ...access.jwk, kid: "as-token-2" };
    expect(() =>
      roleKeyResolvers(
        { accessToken: ["as-token", "as-token-2"], attenuationRoot: [], transactionToken: [] },
        { jwks: { keys: [access.jwk, rotationAlias] } },
      ),
    ).not.toThrow();
  });

  // The verifier accepts equivalent encodings of one public key, so the
  // cross-role comparison must see through them: each alias below imports as
  // exactly the same key as its canonical form, yet hashes differently as
  // written.
  const sameKey = (a: Record<string, unknown>, b: Record<string, unknown>) =>
    expect(createPublicKey({ key: a as JsonWebKey, format: "jwk" }).export({ format: "jwk" })).toEqual(
      createPublicKey({ key: b as JsonWebKey, format: "jwk" }).export({ format: "jwk" }),
    );

  it("refuses an EC key whose access-role alias pads x with '=' (#1123 re-review)", () => {
    const padded = { ...txn.jwk, kid: "as-token", x: `${txn.jwk.x as string}=` };
    sameKey(padded, txn.jwk);
    expect(() =>
      roleKeyResolvers(
        { accessToken: ["as-token"], attenuationRoot: [], transactionToken: ["as-txn"] },
        { jwks: { keys: [padded] }, txnTokenJwks: { keys: [txn.jwk] } },
      ),
    ).toThrow(/transactionToken kid as-txn is the same key as accessToken kid as-token/);
  });

  it("refuses an RSA key whose access-role alias prepends a zero byte to the modulus (#1123 re-review)", async () => {
    const kp = await generateKeyPair("RS256", { extractable: true });
    const rsa = { ...(await exportJWK(kp.publicKey)), kid: "as-txn", alg: "RS256" };
    const n = Buffer.concat([Buffer.from([0]), Buffer.from(rsa.n as string, "base64url")]).toString("base64url");
    const zeroLed = { ...rsa, kid: "as-token", n };
    sameKey(zeroLed, rsa);
    expect(() =>
      roleKeyResolvers(
        { accessToken: ["as-token"], attenuationRoot: [], transactionToken: ["as-txn"] },
        { jwks: { keys: [zeroLed] }, txnTokenJwks: { keys: [rsa] } },
      ),
    ).toThrow(/transactionToken kid as-txn is the same key as accessToken kid as-token/);
  });

  it("refuses an RSA key whose access-role alias zero-pads the exponent", async () => {
    const kp = await generateKeyPair("RS256", { extractable: true });
    const rsa = { ...(await exportJWK(kp.publicKey)), kid: "as-txn", alg: "RS256" };
    const e = Buffer.concat([Buffer.from([0]), Buffer.from(rsa.e as string, "base64url")]).toString("base64url");
    const zeroLed = { ...rsa, kid: "as-token", e };
    sameKey(zeroLed, rsa);
    expect(() =>
      roleKeyResolvers(
        { accessToken: ["as-token"], attenuationRoot: [], transactionToken: ["as-txn"] },
        { jwks: { keys: [zeroLed] }, txnTokenJwks: { keys: [rsa] } },
      ),
    ).toThrow(/is the same key as/);
  });

  it("refuses a pinned key that is not a public EC, OKP or RSA key", () => {
    expect(() =>
      roleKeyResolvers(
        { accessToken: ["as-hmac"], attenuationRoot: [], transactionToken: [] },
        { jwks: { keys: [{ kty: "oct", k: "c2VjcmV0", kid: "as-hmac", alg: "HS256" }] } },
      ),
    ).toThrow(/is not a public EC, OKP or RSA key/);
  });
});
