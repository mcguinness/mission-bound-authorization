/**
 * @spec status#historical-key-set, status#as-metadata, status#signing-key-retention (#831 B3)
 *
 * The AS's historical key set: the Status role's generations withdrawn as
 * compromised, each with OpenID Federation's `revoked` member, signed as a
 * `jwk-set+jwt` under the active Mission Status signing key and advertised as
 * `mission_historical_jwks_uri` while it lists a key.
 */

import { mkdtempSync } from "node:fs";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TOPOLOGY } from "@mission/demo-data";
import { compactVerify, createLocalJWKSet, decodeJwt, decodeProtectedHeader, exportJWK, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";
import {
  buildAuthorizationServer,
  compromiseSigningKeyGeneration,
  historicalKeys,
  initSigningKeyRing,
  signHistoricalKeySet,
} from "../src/index.js";

const PORT = 14938;
const ISSUER = `http://localhost:${PORT}`;
const { asToken, asStatus, asTxn, asContinuation } = TOPOLOGY.keys;
const ROLES = { asToken, asStatus, asTxn, asContinuation };

type As = Awaited<ReturnType<typeof buildAuthorizationServer>>;

async function withAs<T>(ring: string, body: (as: As) => Promise<T>): Promise<T> {
  const as = await buildAuthorizationServer({ issuer: ISSUER, signingKeys: { ring } });
  const server: Server = as.provider.listen(PORT);
  await new Promise<void>((r) => server.once("listening", () => r()));
  try {
    return await body(as);
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
}

const discovery = async () =>
  (await (await fetch(`${ISSUER}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
const publishedKeys = async () => ((await (await fetch(`${ISSUER}/jwks`)).json()) as { keys: Record<string, unknown>[] }).keys;

async function publicKey(kid: string) {
  const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
  return { privateKey, publicJwk: { ...(await exportJWK(publicKey)), kid, alg: "ES256", use: "sig" } };
}

describe("the historical key set's listing and signer (@spec status#historical-key-set, #831 B3)", () => {
  it("lists each withdrawn key under its kid, with revoked: reason compromised, revoked_at and, only when established, compromised_at, as NumericDates", async () => {
    const a = await publicKey("as-status");
    const b = await publicKey("as-status-2");
    const keys = historicalKeys([
      { publicJwk: a.publicJwk, revoked_at: "2026-10-26T10:00:00.900Z", compromised_at: "2026-10-26T09:30:00.000Z" },
      { publicJwk: b.publicJwk, revoked_at: "2026-10-26T11:00:00.000Z" },
    ]);
    expect(keys).toEqual([
      { ...a.publicJwk, revoked: { reason: "compromised", revoked_at: 1793008800, compromised_at: 1793007000 } },
      { ...b.publicJwk, revoked: { reason: "compromised", revoked_at: 1793012400 } },
    ]);
  });

  it("signs nothing when no key is withdrawn, and never under a key the set lists, by kid or by key material", async () => {
    const listed = await publicKey("as-status");
    const signer = await publicKey("as-status-2");
    const withdrawn = [{ publicJwk: listed.publicJwk, revoked_at: "2026-10-26T10:00:00Z" }];
    const now = new Date("2026-10-26T12:00:00Z");
    expect(
      await signHistoricalKeySet({
        issuer: ISSUER,
        withdrawn: [],
        signer: { key: signer.privateKey, kid: "as-status-2", publicJwk: signer.publicJwk },
        now,
      }),
    ).toBeUndefined();
    const jws = await signHistoricalKeySet({
      issuer: ISSUER,
      withdrawn,
      signer: { key: signer.privateKey, kid: "as-status-2", publicJwk: signer.publicJwk },
      now,
    });
    expect(decodeProtectedHeader(jws as string)).toEqual({ alg: "ES256", kid: "as-status-2", typ: "jwk-set+jwt" });
    // Under the listed key's kid: refused.
    await expect(
      signHistoricalKeySet({
        issuer: ISSUER,
        withdrawn,
        signer: { key: listed.privateKey, kid: "as-status", publicJwk: listed.publicJwk },
        now,
      }),
    ).rejects.toThrow(/never signed under a key it lists/);
    // The listed key's material under another kid: refused too.
    await expect(
      signHistoricalKeySet({
        issuer: ISSUER,
        withdrawn,
        signer: { key: listed.privateKey, kid: "renamed", publicJwk: { ...listed.publicJwk, kid: "renamed" } },
        now,
      }),
    ).rejects.toThrow(/never signed under a key it lists/);
  });
});

describe("an AS across a Status key compromise (@spec status#historical-key-set, status#as-metadata, #831 B3)", () => {
  it("publishes no set before the compromise; after it, advertises mission_historical_jwks_uri and serves the withdrawn key, revoked, signed under the replacement", { timeout: 120_000 }, async () => {
    const ring = join(mkdtempSync(join(tmpdir(), "historical-key-set-")), "keys", "ring.json");
    const start = Date.now();
    const at = (s: number) => () => new Date(start + s * 1000);
    await initSigningKeyRing(ring, ISSUER, ROLES, at(0));

    const original = await withAs(ring, async () => {
      expect("mission_historical_jwks_uri" in (await discovery())).toBe(false);
      expect((await fetch(`${ISSUER}/historical-jwks`)).status).toBe(404);
      return (await publishedKeys()).find((k) => k.kid === asStatus.kid) as Record<string, unknown>;
    });
    expect(original).toBeDefined();

    const compromisedAt = new Date(start - 60_000);
    const { replacement } = await compromiseSigningKeyGeneration(ring, ISSUER, ROLES, "asStatus", asStatus.kid, {
      compromisedAt,
      now: at(1),
    });
    expect(replacement).toBe(`${asStatus.kid}-2`);

    await withAs(ring, async (as) => {
      const meta = await discovery();
      expect(meta.mission_historical_jwks_uri).toBe(`${ISSUER}/historical-jwks`);
      const res = await fetch(meta.mission_historical_jwks_uri as string);
      expect(res.status).toBe(200);
      // Literals, not the server's own constants, so a wrong value the server
      // serves cannot pass (#1813 review): the registered media type, and an
      // explicit freshness lifetime of the AS's choosing.
      expect(res.headers.get("content-type")).toBe("application/jwk-set+jwt");
      expect(res.headers.get("cache-control")).toMatch(/^max-age=[1-9][0-9]*$/);
      const jwksRes = await fetch(`${ISSUER}/jwks`);
      expect(res.headers.get("etag")).toBe(jwksRes.headers.get("etag"));
      const jws = await res.text();

      // Signed under the active Status key, the replacement, which the AS now signs Status responses under.
      expect(decodeProtectedHeader(jws)).toEqual({ alg: "ES256", kid: replacement, typ: "jwk-set+jwt" });
      expect(as.kernel.statusSigner().kid).toBe(replacement);
      const live = (await jwksRes.json()) as { keys: Record<string, unknown>[] };
      const statusOnly = createLocalJWKSet({ keys: live.keys.filter((k) => k.kid === replacement) as never });
      await compactVerify(jws, statusOnly);

      // It lists the withdrawn key, its original material under its original kid, revoked.
      const payload = decodeJwt(jws) as { iss: string; iat: number; keys: Record<string, unknown>[] };
      expect(payload.iss).toBe(ISSUER);
      expect(typeof payload.iat).toBe("number");
      expect(payload.keys).toHaveLength(1);
      const listed = payload.keys[0] as Record<string, unknown>;
      expect({ kid: listed.kid, kty: listed.kty, crv: listed.crv, x: listed.x, y: listed.y }).toEqual({
        kid: original.kid,
        kty: original.kty,
        crv: original.crv,
        x: original.x,
        y: original.y,
      });
      expect(listed.revoked).toEqual({
        reason: "compromised",
        revoked_at: Math.floor(at(1)().getTime() / 1000),
        compromised_at: Math.floor(compromisedAt.getTime() / 1000),
      });
      // Withdrawn from the jwks_uri: the live set no longer carries it.
      expect(live.keys.some((k) => k.kid === asStatus.kid)).toBe(false);
    });
  });
});
