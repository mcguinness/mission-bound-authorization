/**
 * @spec #831 C2, runtime-oauth#token-validation (#825, D312): the payments
 * resource's per-role key pins over the issuer's published set rather than a
 * snapshot. Each role resolves only its pinned `kid`s, held through
 * `IssuerKeys` (`@mission/core`); a server takes a fixed set or a
 * `jwks_uri`, never both.
 */
import { exportJWK, generateKeyPair, jwtVerify, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import {
  type KeyRoles,
  McpPaymentsServer,
  openEphemeralWriteReservationStore,
  PaymentsStore,
  refreshingRoleKeyResolvers,
  roleKeyResolvers,
} from "../src/index.js";

const ISSUER = "https://as.test";
const ROLES: KeyRoles = { accessToken: ["as-token"], attenuationRoot: [], transactionToken: ["as-txn"] };
/** Access tokens only: a fixed set must name every pinned kid. */
const ACCESS_ONLY: KeyRoles = { accessToken: ["as-token"], attenuationRoot: [], transactionToken: [] };

async function signer(kid: string, alg = "ES256") {
  const { privateKey, publicKey } = await generateKeyPair(alg, { extractable: true });
  const jwk = { ...(await exportJWK(publicKey)), kid, alg, use: "sig" };
  const sign = (typ: string) => new SignJWT({ iss: ISSUER }).setProtectedHeader({ alg, kid, typ }).setIssuedAt().sign(privateKey);
  /** The same key published under another kid. */
  const as = (other: string) => ({ ...jwk, kid: other });
  const signAs = (other: string, typ: string) =>
    new SignJWT({ iss: ISSUER }).setProtectedHeader({ alg, kid: other, typ }).setIssuedAt().sign(privateKey);
  return { jwk, sign, as, signAs };
}

/** A fetch answering each URI with its key set (an Error refuses), fresh for five minutes, counting requests per URI. */
function issuer(sets: Record<string, Record<string, unknown>[] | Error>) {
  const requests: string[] = [];
  const fetch = async (url: string) => {
    requests.push(url);
    const set = sets[url] ?? [];
    if (set instanceof Error) throw set;
    return new Response(JSON.stringify({ keys: set }), { headers: { "cache-control": "max-age=300" } });
  };
  return { fetch, requests, sets };
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

describe("one key, one role, across two key sources (@spec #831 C2, D825)", () => {
  it("refuses a key one source trusts for access tokens and the other for transaction tokens, both ways, until the other source no longer holds it", async () => {
    const shared = await signer("as-token");
    const txnOwn = await signer("as-txn");
    let t = 0;
    const two = issuer({ "https://as.test/jwks": [shared.jwk], "https://tas.test/jwks": [shared.as("as-txn")] });
    const split = refreshingRoleKeyResolvers(
      ROLES,
      { jwksUri: "https://as.test/jwks", txnTokenJwksUri: "https://tas.test/jwks" },
      { fetch: two.fetch, now: () => t },
    );
    await expect(jwtVerify(await shared.sign("at+jwt"), split.accessToken)).rejects.toThrow(/same key as the other source's transactionToken key/);
    await expect(jwtVerify(await shared.signAs("as-txn", "txn+jwt"), split.transactionToken)).rejects.toThrow(/same key as the other source's accessToken key/);
    // The transaction-token issuer replaces its key: once its set refreshes, both verify.
    two.sets["https://tas.test/jwks"] = [txnOwn.jwk];
    t += 300_000;
    await jwtVerify(await shared.sign("at+jwt"), split.accessToken);
    await jwtVerify(await txnOwn.sign("txn+jwt"), split.transactionToken);
  });

  it("refuses when the other source cannot be revalidated", async () => {
    const token = await signer("as-token");
    const down = issuer({ "https://as.test/jwks": [token.jwk], "https://tas.test/jwks": new Error("unreachable") });
    const split = refreshingRoleKeyResolvers(
      ROLES,
      { jwksUri: "https://as.test/jwks", txnTokenJwksUri: "https://tas.test/jwks" },
      { fetch: down.fetch },
    );
    await expect(jwtVerify(await token.sign("at+jwt"), split.accessToken)).rejects.toMatchObject({ code: "unavailable" });
  });

  it("reloads the pins at once across both sources, or not at all", async () => {
    const token = await signer("as-token");
    const token2 = await signer("as-token-2");
    const txn = await signer("as-txn");
    const two = issuer({ "https://as.test/jwks": [token.jwk, token2.jwk], "https://tas.test/jwks": [txn.jwk, token2.as("as-txn-2")] });
    const split = refreshingRoleKeyResolvers(
      ROLES,
      { jwksUri: "https://as.test/jwks", txnTokenJwksUri: "https://tas.test/jwks" },
      { fetch: two.fetch },
    );
    await expect(jwtVerify(await token2.sign("at+jwt"), split.accessToken)).rejects.toMatchObject({ code: "untrusted_kid" });
    split.setRoles({ accessToken: ["as-token", "as-token-2"], attenuationRoot: [], transactionToken: ["as-txn"] });
    await jwtVerify(await token2.sign("at+jwt"), split.accessToken);
    // Pinning as-txn-2 too would give one source's key to the other's role: refused, the pins in force kept.
    await jwtVerify(await txn.sign("txn+jwt"), split.transactionToken);
    expect(() => split.setRoles({ accessToken: ["k"], attenuationRoot: [], transactionToken: ["k"] })).toThrow(/configured for both/);
    await jwtVerify(await token2.sign("at+jwt"), split.accessToken);
    // The access source takes a change the transaction source then refuses: the access source's change is undone.
    expect(() =>
      split.setRoles({ accessToken: ["as-token"], attenuationRoot: [], transactionToken: ["as-txn"] }, { transactionToken: [] }),
    ).toThrow(/accepts no algorithm/);
    await jwtVerify(await token2.sign("at+jwt"), split.accessToken);
  });
});

describe("the deployment's algorithm policy, the same under either key source (@spec #831 C2, D825)", () => {
  it("accepts a pinned ES512 key through a fixed set and through a jwks_uri, and refuses it under both when the policy lists only ES256", async () => {
    const es512 = await signer("as-token", "ES512");
    const set = { keys: [es512.jwk] };
    const one = issuer({ "https://as.test/jwks": [es512.jwk] });
    const snapshot = roleKeyResolvers(ACCESS_ONLY, { jwks: set });
    const refreshing = refreshingRoleKeyResolvers(ACCESS_ONLY, { jwksUri: "https://as.test/jwks" }, { fetch: one.fetch });
    await jwtVerify(await es512.sign("at+jwt"), snapshot.accessToken);
    await jwtVerify(await es512.sign("at+jwt"), refreshing.accessToken);
    const policy = { accessToken: ["ES256"] };
    const narrowSnapshot = roleKeyResolvers(ACCESS_ONLY, { jwks: set }, policy);
    const narrowRefreshing = refreshingRoleKeyResolvers(ACCESS_ONLY, { jwksUri: "https://as.test/jwks" }, { fetch: one.fetch, algorithms: policy });
    await expect(jwtVerify(await es512.sign("at+jwt"), narrowSnapshot.accessToken)).rejects.toThrow(/alg ES512 is not accepted for accessToken/);
    await expect(jwtVerify(await es512.sign("at+jwt"), narrowRefreshing.accessToken)).rejects.toMatchObject({ code: "algorithm" });
  });
});

describe("a payments server reloads its pins while serving (@spec #831 C2, D825)", () => {
  type Pins = { resolveAccessKey: Parameters<typeof jwtVerify>[1] };
  it("adds and removes an access-token kid, under a fixed set and under a jwks_uri", async () => {
    const token = await signer("as-token");
    const token2 = await signer("as-token-2");
    const one = issuer({ "https://as.test/jwks": [token.jwk, token2.jwk] });
    for (const source of [{ jwks: { keys: [token.jwk, token2.jwk] } }, { jwksUri: "https://as.test/jwks", issuerKeysOptions: { fetch: one.fetch } }]) {
      const server = new McpPaymentsServer({
        writeReservations: openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" }),
        pep: undefined as never,
        payments: new PaymentsStore(),
        loadView: () => undefined,
        keyRoles: ACCESS_ONLY,
        issuer: ISSUER,
        ...source,
      } as never);
      const pins = () => (server as unknown as Pins).resolveAccessKey;
      await expect(jwtVerify(await token2.sign("at+jwt"), pins())).rejects.toThrow();
      server.reloadKeyRoles({ accessToken: ["as-token", "as-token-2"], attenuationRoot: [], transactionToken: [] });
      await jwtVerify(await token2.sign("at+jwt"), pins());
      server.reloadKeyRoles({ accessToken: ["as-token-2"], attenuationRoot: [], transactionToken: [] });
      await expect(jwtVerify(await token.sign("at+jwt"), pins())).rejects.toThrow();
      // A reload that pins one kid to two roles is refused, and the pins in force stay.
      expect(() => server.reloadKeyRoles({ accessToken: ["k"], attenuationRoot: [], transactionToken: ["k"] })).toThrow(/configured for both/);
      await jwtVerify(await token2.sign("at+jwt"), pins());
    }
  });
});
