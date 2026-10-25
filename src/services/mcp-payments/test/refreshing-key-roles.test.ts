/**
 * @spec #831 C2, runtime-oauth#token-validation (#825, D312): the payments
 * resource's per-role key pins over the issuer's published set rather than a
 * snapshot. Each role resolves only its pinned `kid`s, held through
 * `IssuerKeys` (`@mission/core`); a server takes a fixed set or a
 * `jwks_uri`, never both.
 */
import { exportJWK, generateKeyPair, jwtVerify, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { type KeyRoles, McpPaymentsServer, refreshingRoleKeyResolvers } from "../src/index.js";

const ISSUER = "https://as.test";
const ROLES: KeyRoles = { accessToken: ["as-token"], attenuationRoot: [], transactionToken: ["as-txn"] };

async function signer(kid: string) {
  const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
  const jwk = { ...(await exportJWK(publicKey)), kid, alg: "ES256", use: "sig" };
  const sign = (typ: string) => new SignJWT({ iss: ISSUER }).setProtectedHeader({ alg: "ES256", kid, typ }).setIssuedAt().sign(privateKey);
  return { jwk, sign };
}

/** A fetch answering each URI with its key set, fresh for five minutes, counting requests per URI. */
function issuer(sets: Record<string, Record<string, unknown>[]>) {
  const requests: string[] = [];
  const fetch = async (url: string) => {
    requests.push(url);
    return new Response(JSON.stringify({ keys: sets[url] ?? [] }), { headers: { "cache-control": "max-age=300" } });
  };
  return { fetch, requests };
}

describe("the payments resource's key pins over a jwks_uri (@spec #831 C2)", () => {
  it("resolves each role's pinned kids only, from one set or from separate sets", async () => {
    const token = await signer("as-token");
    const txn = await signer("as-txn");
    const one = issuer({ "https://as.test/jwks": [token.jwk, txn.jwk] });
    const shared = refreshingRoleKeyResolvers(ROLES, { jwksUri: "https://as.test/jwks" }, { fetch: one.fetch });
    await jwtVerify(await token.sign("at+jwt"), shared.accessToken);
    await jwtVerify(await txn.sign("txn+jwt"), shared.transactionToken);
    // Another role's key, published in the same set, is not this role's.
    await expect(jwtVerify(await txn.sign("at+jwt"), shared.accessToken)).rejects.toMatchObject({ code: "untrusted_kid" });
    await expect(jwtVerify(await token.sign("at+jwt"), shared.attenuationRoot)).rejects.toMatchObject({ code: "untrusted_kid" });
    expect(one.requests).toEqual(["https://as.test/jwks"]);

    const two = issuer({ "https://as.test/jwks": [token.jwk], "https://tas.test/jwks": [txn.jwk] });
    const split = refreshingRoleKeyResolvers(
      ROLES,
      { jwksUri: "https://as.test/jwks", txnTokenJwksUri: "https://tas.test/jwks" },
      { fetch: two.fetch },
    );
    await jwtVerify(await token.sign("at+jwt"), split.accessToken);
    await jwtVerify(await txn.sign("txn+jwt"), split.transactionToken);
    expect(two.requests.sort()).toEqual(["https://as.test/jwks", "https://tas.test/jwks"]);
  });

  it("refuses at startup a kid pinned to two roles", () => {
    expect(() =>
      refreshingRoleKeyResolvers({ accessToken: ["k"], attenuationRoot: [], transactionToken: ["k"] }, { jwksUri: "https://as.test/jwks" }),
    ).toThrow(/kid k is configured for both accessToken and transactionToken/);
  });

  it("a server takes exactly one key source per class: a fixed set or a jwks_uri", () => {
    const jwks = { keys: [] };
    const build = (deps: Record<string, unknown>) => () => new McpPaymentsServer({ keyRoles: ROLES, ...deps } as never);
    expect(build({ jwks, jwksUri: "https://as.test/jwks" })).toThrow(/give exactly one of jwks and jwksUri/);
    expect(build({})).toThrow(/give exactly one of jwks and jwksUri/);
    expect(build({ jwks, txnTokenJwks: jwks, txnTokenJwksUri: "https://as.test/jwks" })).toThrow(/txnTokenJwks or txnTokenJwksUri, not both/);
    expect(build({ jwksUri: "https://as.test/jwks", txnTokenJwks: jwks })).toThrow(/a jwksUri server takes txnTokenJwksUri, not txnTokenJwks/);
  });
});
