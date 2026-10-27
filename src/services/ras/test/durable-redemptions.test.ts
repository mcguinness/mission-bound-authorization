/**
 * @spec cross-domain#validation-at-resource-as (one-time use), #1767 (D887)
 *
 * The RAS's single-use claims across a restart. A RAS given a durable
 * redemption store refuses, after it restarts, a base or a continuation
 * ID-JAG it redeemed before, including when the issuer's clock runs ahead of
 * its own; still redeems, once, a grant issued before the restart and never
 * redeemed; releases one token for concurrent redemptions of one grant; and
 * refuses to boot on a store that is missing or that `init` did not create,
 * so lost history is never read as an empty one.
 */

import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { DurableStoreError } from "@mission/store";
import {
  claimRedemption,
  ID_JAG_TYP,
  initRasRedemptionStore,
  openInMemoryRedemptionStore,
  type RasConfig,
  RasRedemptionStoreError,
  REDEMPTION_RETENTION_MARGIN_S,
  ResourceAuthorizationServer,
} from "../src/index.js";

const AS_ISS = "https://as.example.test";
const RAS_ISS = "https://ras.example.test";
const IDP_ISS = "https://idp.example.test";
const AUDIENCE = "https://saas.example.test/mcp";
const CLIENT_ID = "ledgercloud-redeemer";
const ENTRY = { type: "mission_resource_access", resource: AUDIENCE, actions: ["invoices.read"] };

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };
let asKeys: Keys;
let rasKeys: Keys;
let clientJkt: string;

beforeAll(async () => {
  asKeys = await generateKeyPair("ES256", { extractable: true });
  rasKeys = await generateKeyPair("ES256", { extractable: true });
  const clientKeys = await generateKeyPair("ES256", { extractable: true });
  clientJkt = await calculateJwkThumbprint(await exportJWK(clientKeys.publicKey));
});

const wallS = () => Math.floor(Date.now() / 1000);

/** A base ID-JAG, or a continuation one with its own already-resolved `sub`. */
async function mintGrant(opts: { continuation?: boolean; iat?: number; noExp?: boolean } = {}): Promise<string> {
  const iat = opts.iat ?? wallS();
  const jwt = new SignJWT({
    mission: {
      issuer: AS_ISS,
      id: "mission-1",
      authority_hash: "sha-256:test",
      subject: { iss: IDP_ISS, sub: "alice" },
      expires_at: new Date(Date.now() + 86_400_000).toISOString(),
    },
    authorization_details: [ENTRY],
    cnf: { jkt: clientJkt },
    client_id: CLIENT_ID,
    ...(opts.continuation
      ? { sub: "acct_continued", identity_continuation_handle: "handle-1767" }
      : { sub: "svc-acct-42" }),
  })
    .setProtectedHeader({ alg: "ES256", kid: "as-token", typ: ID_JAG_TYP })
    .setIssuer(AS_ISS)
    .setAudience(RAS_ISS)
    .setIssuedAt(iat)
    .setJti(`jag_${Math.random().toString(36).slice(2)}`);
  return (opts.noExp ? jwt : jwt.setExpirationTime(wallS() + 300)).sign(asKeys.privateKey);
}

async function rasConfig(config: Partial<RasConfig> = {}): Promise<RasConfig> {
  const asPub = { ...(await exportJWK(asKeys.publicKey)), kid: "as-token", alg: "ES256" };
  const mapped = (iss: string, sub: string) => ({
    origin: { iss, sub },
    local_sub: "local-alice",
    observed_at: "2020-01-01T00:00:00Z",
    valid_until: "2099-01-01T00:00:00Z",
  });
  return {
    localCeiling: [ENTRY as never],
    localPolicyVersion: "test-local-policy-1",
    issuer: RAS_ISS,
    trustedIssuers: { [AS_ISS]: { keys: [asPub as never] } },
    signKey: rasKeys.privateKey,
    signKid: "ras-token",
    localTokenAudience: AUDIENCE,
    registeredClients: { [clientJkt]: CLIENT_ID },
    mapping: { id: "test-map", version: "v1", entries: [mapped(AS_ISS, "svc-acct-42"), mapped(IDP_ISS, "alice")] },
    entitlement: { resolve: async () => ({ entitled: true, observed_at: new Date().toISOString() }) },
    entitlementStalenessBoundSeconds: 300,
    resourceConstraintsSupported: { [AUDIENCE]: [] },
    ...config,
  };
}

const REPLAY = { code: "invalid_grant", message: "grant replay or missing jti" };

let dir: string;
const open: ResourceAuthorizationServer[] = [];

/** A RAS on the durable store at `file`; the test's cleanup closes it. */
async function rasOn(file: string, config: Partial<RasConfig> = {}): Promise<ResourceAuthorizationServer> {
  const server = new ResourceAuthorizationServer(await rasConfig({ redemptions: { file }, ...config }));
  open.push(server);
  return server;
}

/** A created store in a fresh directory. */
function createdStore(): string {
  dir = mkdtempSync(join(tmpdir(), "ras-redemptions-"));
  const file = join(dir, "redemptions.sqlite");
  initRasRedemptionStore(file);
  return file;
}

afterEach(() => {
  for (const server of open.splice(0)) server.close();
  if (dir) rmSync(dir, { recursive: true, force: true });
});

describe("RAS durable redemption records across a restart (@spec cross-domain#validation-at-resource-as, #1767, D887)", () => {
  for (const kind of ["base", "continuation"] as const) {
    it(`refuses, after a restart on the same store, a ${kind} ID-JAG redeemed before it`, async () => {
      const file = createdStore();
      const grant = await mintGrant({ continuation: kind === "continuation" });
      const before = await rasOn(file);
      await before.redeem(grant, clientJkt);
      before.close();
      const after = await rasOn(file);
      await expect(after.redeem(grant, clientJkt)).rejects.toMatchObject(REPLAY);
    });
  }

  it("refuses the replay after a restart when the issuer's clock runs ahead of the RAS's: the grant's iat is after the RAS started, both times", async () => {
    const file = createdStore();
    const iat = wallS() + 30;
    const grant = await mintGrant({ iat });
    // Redeemed at a RAS whose clock reads iat - 10 s, then replayed after a
    // restart at iat - 9 s: a floor at the RAS's start time passes it twice.
    const before = await rasOn(file, { now: () => new Date((iat - 10) * 1000) });
    await before.redeem(grant, clientJkt);
    before.close();
    const after = await rasOn(file, { now: () => new Date((iat - 9) * 1000) });
    await expect(after.redeem(grant, clientJkt)).rejects.toMatchObject(REPLAY);
  });

  it("redeems once, after a restart, a grant issued before it and never redeemed", async () => {
    const file = createdStore();
    const grant = await mintGrant({ iat: wallS() - 5 });
    const before = await rasOn(file);
    await before.redeem(await mintGrant(), clientJkt);
    before.close();
    const after = await rasOn(file);
    await expect(after.redeem(grant, clientJkt)).resolves.toMatchObject({ access_token: expect.any(String) });
    await expect(after.redeem(grant, clientJkt)).rejects.toMatchObject(REPLAY);
  });

  it("refuses a grant without exp, which has no acceptance period to keep its claim through", async () => {
    const server = await rasOn(createdStore());
    await expect(server.redeem(await mintGrant({ noExp: true }), clientJkt)).rejects.toMatchObject({
      code: "invalid_grant",
      message: "grant has no exp",
    });
  });

  it("releases one token for concurrent redemptions of one grant", async () => {
    const server = await rasOn(createdStore());
    const grant = await mintGrant();
    const results = await Promise.allSettled(Array.from({ length: 5 }, () => server.redeem(grant, clientJkt)));
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    for (const r of results.filter((r) => r.status === "rejected")) {
      expect((r as PromiseRejectedResult).reason).toMatchObject(REPLAY);
    }
  });
});

describe("RAS redemption store: missing or lost history refuses (@spec cross-domain#validation-at-resource-as, #1767, D887)", () => {
  it("refuses to boot on a missing store, names the command that creates it, and never creates one", async () => {
    dir = mkdtempSync(join(tmpdir(), "ras-redemptions-"));
    const file = join(dir, "redemptions.sqlite");
    await expect(rasOn(file)).rejects.toThrow(RasRedemptionStoreError);
    await expect(rasOn(file)).rejects.toThrow(/pnpm ras-redemptions init --file/);
    expect(existsSync(file)).toBe(false);
  });

  it("refuses to boot on a store file init did not create: an empty file is lost history, not an empty one", async () => {
    dir = mkdtempSync(join(tmpdir(), "ras-redemptions-"));
    const file = join(dir, "redemptions.sqlite");
    writeFileSync(file, "");
    await expect(rasOn(file)).rejects.toThrow(/is not a redemption store .* created: its history is lost/);
    // Refused again at the next boot: the failed open left no mark that passes.
    await expect(rasOn(file)).rejects.toThrow(RasRedemptionStoreError);
  });

  it("refuses a second RAS on a store another holds, and a second init of an existing store", async () => {
    const file = createdStore();
    await rasOn(file);
    await expect(rasOn(file)).rejects.toThrow(DurableStoreError);
    expect(() => initRasRedemptionStore(file)).toThrow(/already exists/);
  });
});

describe("RAS redemption claims (@spec cross-domain#validation-at-resource-as, #1767, D887)", () => {
  it("scopes a claim to its issuer: one jti from two issuers is two claims, and each is claimed once", () => {
    const db = openInMemoryRedemptionStore();
    expect(claimRedemption(db, AS_ISS, "jti-1", 1000, 900)).toBe(true);
    expect(claimRedemption(db, "https://other-as.example.test", "jti-1", 1000, 900)).toBe(true);
    expect(claimRedemption(db, AS_ISS, "jti-1", 1000, 901)).toBe(false);
    db.close();
  });

  it("keeps a claim through its grant's exp and the margin past it, and prunes it only after", () => {
    const db = openInMemoryRedemptionStore();
    const exp = 1000;
    expect(claimRedemption(db, AS_ISS, "jti-1", exp, 900)).toBe(true);
    expect(claimRedemption(db, AS_ISS, "jti-1", exp, exp + REDEMPTION_RETENTION_MARGIN_S)).toBe(false);
    expect(claimRedemption(db, AS_ISS, "jti-2", 5000, exp + REDEMPTION_RETENTION_MARGIN_S + 1)).toBe(true);
    const held = db.prepare("SELECT jti FROM grant_redemptions ORDER BY jti").all();
    expect(held).toEqual([{ jti: "jti-2" }]);
    db.close();
  });
});
