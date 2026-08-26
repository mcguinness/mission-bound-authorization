/**
 * @spec cross-domain#origin-principal-mapping, #origin-principal-continuity,
 * #dual-axis (#539)
 *
 * Dedicated RAS unit coverage for the dual-axis origin-principal mapping and
 * entitlement check at ID-JAG redemption: co-resolution of the grant's own
 * `(iss, sub)` against its carried `mission.subject`, mapping-table ambiguity/
 * disablement/staleness, current entitlement of the resolved local principal,
 * and the continuation-profile carve-out (its own already-resolved,
 * per-audience `sub`, mapping/co-resolution skipped, entitlement still run).
 * Mints raw ID-JAG JWTs directly (not via `issueCrossDomainGrant`) so each
 * scenario can construct exactly the grant shape under test.
 */

import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { type LocalMappingPolicy, type LocalPrincipalMapping } from "@mission/core";
import { ID_JAG_TYP, ResourceAuthorizationServer, type RasConfig } from "../src/index.js";

const AS_ISS = "https://as.example.test";
const RAS_ISS = "https://ras.example.test";
const IDP_ISS = "https://idp.example.test"; // mission.subject's own issuer, distinct from AS_ISS
const AUDIENCE = "https://saas.example.test/mcp";
const GRANT_SUB = "svc-acct-42"; // the grant's own top-level `sub`
const IDP_SUB = "alice"; // mission.subject.sub
const LOCAL_SUB = "local-alice";
const REGISTERED_CLIENT_ID = "ledgercloud-redeemer";

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };

let asKeys: Keys;
let rasKeys: Keys;
let clientKeys: Keys;
let clientJkt: string;

const FAR_PAST = "2020-01-01T00:00:00Z";
const FAR_FUTURE = "2099-01-01T00:00:00Z";

function mappingEntry(overrides: Partial<LocalPrincipalMapping> & { origin: LocalPrincipalMapping["origin"] }): LocalPrincipalMapping {
  return {
    local_sub: LOCAL_SUB,
    observed_at: FAR_PAST,
    valid_until: FAR_FUTURE,
    ...overrides,
  };
}

/** The base co-resolving mapping table: both origin identities -> LOCAL_SUB. */
function basePolicy(entries?: LocalPrincipalMapping[]): LocalMappingPolicy {
  return {
    id: "test-map",
    version: "v1",
    entries: entries ?? [
      mappingEntry({ origin: { iss: AS_ISS, sub: GRANT_SUB } }),
      mappingEntry({ origin: { iss: IDP_ISS, sub: IDP_SUB } }),
    ],
  };
}

interface GrantOverrides {
  iss?: string | null; // null = omit entirely, "" = present but empty (malformed)
  sub?: string | null; // null = omit entirely, "" = present but empty (malformed)
  missionSubject?: { iss: string; sub: string } | null; // null = omit entirely
  missionId?: string | null; // null = omit entirely, "" = present but empty (malformed)
  missionAuthorityHash?: string | null; // null = omit entirely, "" = present but empty (malformed)
  identityContinuationHandle?: string;
  exp?: number; // absolute epoch seconds
}

async function mintGrant(overrides: GrantOverrides = {}): Promise<string> {
  const nowS = Math.floor(Date.now() / 1000);
  const mission: Record<string, unknown> = { issuer: AS_ISS };
  if (overrides.missionId !== null) mission.id = overrides.missionId ?? "mission-1";
  if (overrides.missionAuthorityHash !== null) mission.authority_hash = overrides.missionAuthorityHash ?? "sha-256:test";
  if (overrides.missionSubject !== null) {
    mission.subject = overrides.missionSubject ?? { iss: IDP_ISS, sub: IDP_SUB };
  }
  const payload: Record<string, unknown> = {
    mission,
    authorization_details: [],
    cnf: { jkt: clientJkt },
    ...(overrides.sub !== null ? { sub: overrides.sub ?? GRANT_SUB } : {}),
    client_id: "ap-agent",
    ...(overrides.identityContinuationHandle !== undefined
      ? { identity_continuation_handle: overrides.identityContinuationHandle }
      : {}),
  };
  let signer = new SignJWT(payload).setProtectedHeader({ alg: "ES256", kid: "as-token", typ: ID_JAG_TYP });
  if (overrides.iss !== null) signer = signer.setIssuer(overrides.iss ?? AS_ISS);
  return signer
    .setAudience(RAS_ISS)
    .setIssuedAt(nowS)
    .setExpirationTime(overrides.exp ?? nowS + 300)
    .setJti(`jag_${Math.random().toString(36).slice(2)}`)
    .sign(asKeys.privateKey);
}

beforeAll(async () => {
  asKeys = await generateKeyPair("ES256", { extractable: true });
  rasKeys = await generateKeyPair("ES256", { extractable: true });
  clientKeys = await generateKeyPair("ES256", { extractable: true });
  clientJkt = await calculateJwkThumbprint(await exportJWK(clientKeys.publicKey));
});

async function ras(config: Partial<RasConfig> = {}): Promise<ResourceAuthorizationServer> {
  const asPub = { ...(await exportJWK(asKeys.publicKey)), kid: "as-token", alg: "ES256" };
  return new ResourceAuthorizationServer({
    issuer: RAS_ISS,
    trustedIssuers: { [AS_ISS]: { keys: [asPub as never] } },
    signKey: rasKeys.privateKey,
    signKid: "ras-token",
    localTokenAudience: AUDIENCE,
    registeredClients: { [clientJkt]: REGISTERED_CLIENT_ID },
    mapping: basePolicy(),
    entitlement: { resolve: async () => ({ entitled: true, observed_at: new Date().toISOString() }) },
    entitlementStalenessBoundSeconds: 300,
    ...config,
  });
}

describe("RAS co-resolution: base grant (@spec cross-domain#origin-principal-mapping)", () => {
  it("co-resolves the grant's own (iss, sub) and mission.subject to one local principal, mints it as sub, and preserves mission.subject unchanged", async () => {
    const server = await ras();
    const grant = await mintGrant();
    const { access_token } = await server.redeem(grant, clientJkt);
    const claims = JSON.parse(Buffer.from(access_token.split(".")[1] as string, "base64url").toString());
    expect(claims.sub).toBe(LOCAL_SUB);
    expect(claims.sub).not.toBe(GRANT_SUB); // never a blind copy of the grant's own sub
    expect(claims.mission.subject).toEqual({ iss: IDP_ISS, sub: IDP_SUB });
  });

  it("denies invalid_grant when the grant's own identity and mission.subject resolve to DIFFERENT local principals", async () => {
    const server = await ras({
      mapping: basePolicy([
        mappingEntry({ origin: { iss: AS_ISS, sub: GRANT_SUB }, local_sub: "local-one" }),
        mappingEntry({ origin: { iss: IDP_ISS, sub: IDP_SUB }, local_sub: "local-two" }),
      ]),
    });
    const grant = await mintGrant();
    await expect(server.redeem(grant, clientJkt)).rejects.toMatchObject({ code: "invalid_grant" });
  });

  it("denies invalid_grant when mission.subject is missing", async () => {
    const server = await ras();
    const grant = await mintGrant({ missionSubject: null });
    await expect(server.redeem(grant, clientJkt)).rejects.toMatchObject({ code: "invalid_grant" });
  });

  it("denies invalid_grant when mission.subject is malformed (missing sub)", async () => {
    const server = await ras();
    const grant = await mintGrant({ missionSubject: { iss: IDP_ISS, sub: "" } });
    await expect(server.redeem(grant, clientJkt)).rejects.toMatchObject({ code: "invalid_grant" });
  });

  it("denies invalid_grant when the grant's own top-level iss is missing, before any trust-anchor lookup or jwtVerify call", async () => {
    const server = await ras();
    const grant = await mintGrant({ iss: null });
    await expect(server.redeem(grant, clientJkt)).rejects.toMatchObject({
      code: "invalid_grant",
      message: "grant missing or malformed iss",
    });
  });

  it("denies invalid_grant when the grant's own top-level iss is present but empty", async () => {
    const server = await ras();
    const grant = await mintGrant({ iss: "" });
    await expect(server.redeem(grant, clientJkt)).rejects.toMatchObject({
      code: "invalid_grant",
      message: "grant missing or malformed iss",
    });
  });

  it("denies invalid_grant when the grant's own sub is missing (never coerced to the literal string \"undefined\")", async () => {
    const server = await ras();
    const grant = await mintGrant({ sub: null });
    await expect(server.redeem(grant, clientJkt)).rejects.toMatchObject({ code: "invalid_grant" });
  });

  it("denies invalid_grant when the grant's own sub is present but empty", async () => {
    const server = await ras();
    const grant = await mintGrant({ sub: "" });
    await expect(server.redeem(grant, clientJkt)).rejects.toMatchObject({ code: "invalid_grant" });
  });

  it("denies invalid_grant when mission.id is missing", async () => {
    const server = await ras();
    const grant = await mintGrant({ missionId: null });
    await expect(server.redeem(grant, clientJkt)).rejects.toMatchObject({ code: "invalid_grant" });
  });

  it("denies invalid_grant when mission.id is present but empty", async () => {
    const server = await ras();
    const grant = await mintGrant({ missionId: "" });
    await expect(server.redeem(grant, clientJkt)).rejects.toMatchObject({ code: "invalid_grant" });
  });

  it("denies invalid_grant when mission.authority_hash is missing", async () => {
    const server = await ras();
    const grant = await mintGrant({ missionAuthorityHash: null });
    await expect(server.redeem(grant, clientJkt)).rejects.toMatchObject({ code: "invalid_grant" });
  });

  it("denies invalid_grant when mission.authority_hash is present but empty", async () => {
    const server = await ras();
    const grant = await mintGrant({ missionAuthorityHash: "" });
    await expect(server.redeem(grant, clientJkt)).rejects.toMatchObject({ code: "invalid_grant" });
  });

  it("denies invalid_grant on an ambiguous (duplicate) mapping entry for the same origin", async () => {
    const server = await ras({
      mapping: basePolicy([
        mappingEntry({ origin: { iss: AS_ISS, sub: GRANT_SUB }, local_sub: "dup-a" }),
        mappingEntry({ origin: { iss: AS_ISS, sub: GRANT_SUB }, local_sub: "dup-b" }),
        mappingEntry({ origin: { iss: IDP_ISS, sub: IDP_SUB } }),
      ]),
    });
    const grant = await mintGrant();
    await expect(server.redeem(grant, clientJkt)).rejects.toMatchObject({ code: "invalid_grant" });
  });

  it("denies invalid_grant on a disabled mapping entry", async () => {
    const server = await ras({
      mapping: basePolicy([
        mappingEntry({ origin: { iss: AS_ISS, sub: GRANT_SUB }, disabled: true }),
        mappingEntry({ origin: { iss: IDP_ISS, sub: IDP_SUB } }),
      ]),
    });
    const grant = await mintGrant();
    await expect(server.redeem(grant, clientJkt)).rejects.toMatchObject({ code: "invalid_grant" });
  });

  it("denies invalid_grant on a mapping stale beyond its own valid_until", async () => {
    const server = await ras({
      mapping: basePolicy([
        mappingEntry({ origin: { iss: AS_ISS, sub: GRANT_SUB }, valid_until: "2021-01-01T00:00:00Z" }),
        mappingEntry({ origin: { iss: IDP_ISS, sub: IDP_SUB } }),
      ]),
    });
    const grant = await mintGrant();
    await expect(server.redeem(grant, clientJkt)).rejects.toMatchObject({ code: "invalid_grant" });
  });

  it("denies invalid_grant on a future-dated mapping observed_at", async () => {
    const server = await ras({
      mapping: basePolicy([
        mappingEntry({ origin: { iss: AS_ISS, sub: GRANT_SUB }, observed_at: "2099-06-01T00:00:00Z" }),
        mappingEntry({ origin: { iss: IDP_ISS, sub: IDP_SUB } }),
      ]),
    });
    const grant = await mintGrant();
    await expect(server.redeem(grant, clientJkt)).rejects.toMatchObject({ code: "invalid_grant" });
  });

  it("denies invalid_grant on a missing (zero-match) mapping", async () => {
    const server = await ras({ mapping: basePolicy([]) });
    const grant = await mintGrant();
    await expect(server.redeem(grant, clientJkt)).rejects.toMatchObject({ code: "invalid_grant" });
  });
});

describe("RAS entitlement (@spec cross-domain#dual-axis)", () => {
  it("denies invalid_grant when the entitlement resolver returns undefined", async () => {
    const server = await ras({ entitlement: { resolve: async () => undefined } });
    const grant = await mintGrant();
    await expect(server.redeem(grant, clientJkt)).rejects.toMatchObject({ code: "invalid_grant" });
  });

  it("denies invalid_grant when entitled is false", async () => {
    const server = await ras({
      entitlement: { resolve: async () => ({ entitled: false, observed_at: new Date().toISOString() }) },
    });
    const grant = await mintGrant();
    await expect(server.redeem(grant, clientJkt)).rejects.toMatchObject({ code: "invalid_grant" });
  });

  it("denies invalid_grant when the entitlement observation is stale beyond entitlementStalenessBoundSeconds", async () => {
    const server = await ras({
      entitlement: {
        resolve: async () => ({ entitled: true, observed_at: new Date(Date.now() - 3_600_000).toISOString() }),
      },
      entitlementStalenessBoundSeconds: 60,
    });
    const grant = await mintGrant();
    await expect(server.redeem(grant, clientJkt)).rejects.toMatchObject({ code: "invalid_grant" });
  });

  it("denies invalid_grant when the entitlement resolver throws", async () => {
    const server = await ras({
      entitlement: {
        resolve: async () => {
          throw new Error("resolver unavailable");
        },
      },
    });
    const grant = await mintGrant();
    await expect(server.redeem(grant, clientJkt)).rejects.toMatchObject({ code: "invalid_grant" });
  });
});

describe("RAS expiry clamping (@spec cross-domain#dual-axis)", () => {
  it("clamps the minted token's exp to the mapping's own valid_until when tighter than the grant lease", async () => {
    const nowS = Math.floor(Date.now() / 1000);
    const tightValidUntil = new Date((nowS + 30) * 1000).toISOString();
    const server = await ras({
      mapping: basePolicy([
        mappingEntry({ origin: { iss: AS_ISS, sub: GRANT_SUB }, valid_until: tightValidUntil }),
        mappingEntry({ origin: { iss: IDP_ISS, sub: IDP_SUB }, valid_until: tightValidUntil }),
      ]),
      localTokenTtlSeconds: 120,
    });
    const grant = await mintGrant({ exp: nowS + 300 });
    const { access_token, expires_in } = await server.redeem(grant, clientJkt);
    const claims = JSON.parse(Buffer.from(access_token.split(".")[1] as string, "base64url").toString());
    expect(expires_in).toBeLessThanOrEqual(31);
    expect(claims.exp).toBeLessThanOrEqual(Math.floor(Date.parse(tightValidUntil) / 1000));
  });

  it("clamps the minted token's exp to the entitlement observation's freshness horizon when tighter", async () => {
    const nowS = Math.floor(Date.now() / 1000);
    const observedAt = new Date().toISOString();
    const server = await ras({
      entitlement: { resolve: async () => ({ entitled: true, observed_at: observedAt }) },
      entitlementStalenessBoundSeconds: 20,
      localTokenTtlSeconds: 120,
    });
    const grant = await mintGrant({ exp: nowS + 300 });
    const { access_token } = await server.redeem(grant, clientJkt);
    const claims = JSON.parse(Buffer.from(access_token.split(".")[1] as string, "base64url").toString());
    expect(claims.exp).toBeLessThanOrEqual(Math.floor(Date.parse(observedAt) / 1000) + 20);
  });
});

describe("RAS continuation carve-out (@spec id-continuation-assertion)", () => {
  it("skips mapping/co-resolution for a continuation grant and mints its own already-resolved sub, but still enforces entitlement", async () => {
    const continuationSub = "acct_deterministic123";
    const server = await ras({ mapping: basePolicy([]) }); // empty: would deny any base-grant lookup
    const grant = await mintGrant({ sub: continuationSub, identityContinuationHandle: "handle-1" });
    const { access_token } = await server.redeem(grant, clientJkt);
    const claims = JSON.parse(Buffer.from(access_token.split(".")[1] as string, "base64url").toString());
    expect(claims.sub).toBe(continuationSub);
  });

  it("still denies invalid_grant for a continuation grant when entitlement fails", async () => {
    const server = await ras({
      mapping: basePolicy([]),
      entitlement: { resolve: async () => ({ entitled: false, observed_at: new Date().toISOString() }) },
    });
    const grant = await mintGrant({ sub: "acct_deterministic456", identityContinuationHandle: "handle-2" });
    await expect(server.redeem(grant, clientJkt)).rejects.toMatchObject({ code: "invalid_grant" });
  });

  it("denies invalid_grant for a continuation grant when sub is missing (never coerced to the literal string \"undefined\")", async () => {
    const server = await ras({ mapping: basePolicy([]) });
    const grant = await mintGrant({ sub: null, identityContinuationHandle: "handle-3" });
    await expect(server.redeem(grant, clientJkt)).rejects.toMatchObject({ code: "invalid_grant" });
  });

  it("denies invalid_grant for a continuation grant when sub is present but empty", async () => {
    const server = await ras({ mapping: basePolicy([]) });
    const grant = await mintGrant({ sub: "", identityContinuationHandle: "handle-4" });
    await expect(server.redeem(grant, clientJkt)).rejects.toMatchObject({ code: "invalid_grant" });
  });
});

describe("RAS expiry clamp rejected before jti consumption (@spec cross-domain#dual-axis)", () => {
  it("refuses a grant whose clamped expiry has already elapsed, without consuming its one-time jti", async () => {
    const fixedNowS = Math.floor(Date.now() / 1000);
    const fixedNow = new Date(fixedNowS * 1000);
    const staleness = 300;
    let entitlementCalls = 0;
    const server = await ras({
      now: () => fixedNow,
      entitlementStalenessBoundSeconds: staleness,
      entitlement: {
        resolve: async () => {
          entitlementCalls += 1;
          if (entitlementCalls === 1) {
            // Exactly at the staleness boundary: the entitlement observation
            // is still "current" (age == the declared bound), but it clamps
            // the entitlement freshness horizon down to fixedNowS itself --
            // an expiry that has already elapsed, not merely tight.
            return { entitled: true, observed_at: new Date((fixedNowS - staleness) * 1000).toISOString() };
          }
          // Second call: comfortably fresh, so the clamp no longer elapses.
          return { entitled: true, observed_at: fixedNow.toISOString() };
        },
      },
    });
    const grant = await mintGrant({ exp: fixedNowS + 600 });
    await expect(server.redeem(grant, clientJkt)).rejects.toMatchObject({ code: "invalid_grant" });
    // The one-time jti was NOT consumed by the rejected attempt: redeeming
    // the SAME grant again (now with a fresh entitlement observation)
    // succeeds rather than failing on replay.
    const { access_token } = await server.redeem(grant, clientJkt);
    expect(access_token).toBeTruthy();
  });
});
