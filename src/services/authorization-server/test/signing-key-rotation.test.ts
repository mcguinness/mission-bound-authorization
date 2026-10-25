/**
 * @spec mission#mission-bound-tokens (verification keys), #831 B2: the key
 * ring's generations, and their rotation, retirement and compromise.
 *
 * A `/2` ring keeps each role's generations. These tests witness the ring's
 * invariants (every refusal), the explicit migration of a slice 1 ring, each
 * operation on the file with an injected clock, and, end to end across AS
 * restarts, what the AS publishes at `/jwks`, the `kid` it signs under, and
 * which generations its own subject verification accepts: a token signed
 * under an `overlap` generation passes the signature check, and one under a
 * retired or compromised generation fails it.
 */
import { FIXTURE_BROWSER_LOGIN, floorApprovalHeaders, renderedRevision, TEST_APPROVAL_PRINCIPALS } from "./approval-fixture.js";

import { mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CANONICAL_RESOURCE, TOPOLOGY } from "@mission/demo-data";
import { calculateJwkThumbprint, decodeProtectedHeader, exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { delegationHandleParams } from "./delegation-handle.helper.js";
import {
  activateSigningKeyGeneration,
  ApprovalSessionStore,
  AS_SIGNING_ROLES,
  buildAuthorizationServer,
  compromiseSigningKeyGeneration,
  initSigningKeyRing,
  JWKS_MAX_AGE_SECONDS,
  loadSigningKeyRing,
  loadSigningKeyRingState,
  migrateSigningKeyRing,
  retireSigningKeyGeneration,
  SIGNING_KEY_RING_FORMAT,
  SIGNING_KEY_RING_FORMAT_V1,
  SigningKeyRingError,
  stageSigningKeyGeneration,
  verifySigningKeyRing,
} from "../src/index.js";
import { confirmRing } from "./ring-confirm.helper.js";

void FIXTURE_BROWSER_LOGIN;
const FLOOR_SESSIONS = new ApprovalSessionStore();
const PORT = 14931;
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
/** The audit horizon a test retires against, and the instants the operations run at. */
const HORIZON_S = 3600;
const T0 = new Date("2026-10-25T12:00:00Z");
const at = (seconds: number) => () => new Date(T0.getTime() + seconds * 1000);
const WRONG_KEY = "subject_token is not signed by this AS's access-token key";
/** The check after the signature: the exchange proves a fresh DPoP key, not the token's. */
const SIGNATURE_ACCEPTED = "possession proof does not match the subject_token confirmation key";

type StoredGeneration = Record<string, unknown> & { kid: string; state: string };
type StoredRing = Record<string, unknown> & { roles: Record<string, { alg: string; generations: StoredGeneration[] }> };

/** A fresh private directory (mode 0700) and a ring path inside it. */
function ringPath(): string {
  return join(mkdtempSync(join(tmpdir(), "key-rotation-")), "keys", "as-signing-keys.json");
}
const readRing = (file: string): StoredRing => JSON.parse(readFileSync(file, "utf8")) as StoredRing;
const generationsOf = (file: string, role: string): StoredGeneration[] => readRing(file).roles[role]!.generations;

/** Write `ring` as a 0600 file in a fresh 0700 directory. */
function ringWith(ring: unknown): string {
  const file = ringPath();
  mkdirSync(join(file, ".."), { recursive: true, mode: 0o700 });
  writeFileSync(file, JSON.stringify(ring), { mode: 0o600 });
  return file;
}

/** A slice 1 (`/1`) ring with fresh keys: one key per role under its configured `kid`. */
async function v1Ring(): Promise<string> {
  const roles: Record<string, unknown> = {};
  for (const r of AS_SIGNING_ROLES) {
    const { privateKey } = await generateKeyPair(ROLES[r].alg, { extractable: true });
    roles[r] = { kid: ROLES[r].kid, alg: ROLES[r].alg, created_at: T0.toISOString(), private_jwk: await exportJWK(privateKey) };
  }
  return ringWith({ format: SIGNING_KEY_RING_FORMAT_V1, issuer: ISSUER, created_at: T0.toISOString(), roles });
}

/** Asserts no generation that has stopped signing still holds a private key in the file. */
function noRetainedPrivateKeys(file: string): void {
  for (const role of AS_SIGNING_ROLES) {
    for (const g of generationsOf(file, role)) {
      const signs = g.state === "pending" || g.state === "active";
      expect(g.private_jwk === undefined, `${g.kid} (${g.state})`).toBe(!signs);
    }
  }
}

const kidsOf = (keys: Record<string, unknown>[]) => keys.map((k) => k.kid as string).sort();

describe("a /2 ring's generations (@spec #831 B2)", () => {
  it("a new ring is /2, with generation 1 of each role active under its configured kid", async () => {
    const file = ringPath();
    await initSigningKeyRing(file, ISSUER, ROLES, at(0));
    const ring = readRing(file);
    expect(ring.format).toBe(SIGNING_KEY_RING_FORMAT);
    for (const role of AS_SIGNING_ROLES) {
      expect(ring.roles[role]!.alg).toBe(ROLES[role].alg);
      expect(generationsOf(file, role).map((g) => [g.generation, g.kid, g.state])).toEqual([[1, ROLES[role].kid, "active"]]);
    }
    const keys = await loadSigningKeyRing(file, ISSUER, ROLES);
    for (const role of AS_SIGNING_ROLES) {
      expect(keys[role].kid).toBe(ROLES[role].kid);
      expect(kidsOf(keys[role].published)).toEqual([ROLES[role].kid]);
      expect(kidsOf(keys[role].verification)).toEqual([ROLES[role].kid]);
      expect(keys[role].withdrawn).toEqual([]);
    }
  });

  it("refuses, never generating a replacement, a /2 ring whose generations break an invariant", async () => {
    const valid = ringPath();
    await initSigningKeyRing(valid, ISSUER, ROLES, at(0));
    await stageSigningKeyGeneration(valid, ISSUER, ROLES, "asStatus", at(0));
    const good = readRing(valid);
    const other = await exportJWK((await generateKeyPair("ES256", { extractable: true })).publicKey);
    const variant = (edit: (status: StoredGeneration[], r: StoredRing) => void): string => {
      const r = structuredClone(good);
      edit(r.roles.asStatus!.generations, r);
      return ringWith(r);
    };
    const cases: [string, string, RegExp][] = [
      ["no revision", variant((_, r) => { delete r.revision; }), /has no revision/],
      ["a changed alg", variant((_, r) => { r.roles.asToken!.alg = "ES256"; }), /asToken is recorded with alg ES256, not the configured RS256/],
      ["no generations", variant((g) => { g.length = 0; }), /asStatus has no generations/],
      ["a generation recorded twice", variant((g) => { g[1]!.generation = 1; g[1]!.kid = "as-status"; }), /asStatus records generation 1 twice/],
      ["a kid its number does not give", variant((g) => { g[1]!.kid = "as-status-9"; }), /asStatus generation 2 is recorded under kid as-status-9, not as-status-2 from the configured as-status/],
      ["a ring for another configured kid", variant((g) => { g[0]!.kid = "as-other"; }), /asStatus generation 1 is recorded under kid as-other, not as-status/],
      ["no generation 1", variant((g) => { g[0]!.generation = 3; g[0]!.kid = "as-status-3"; }), /asStatus has no generation 1/],
      ["an unknown state", variant((g) => { g[1]!.state = "standby"; }), /as-status-2 has an unknown state standby/],
      ["no active generation", variant((g) => { g[0]!.state = "overlap"; g[0]!.stopped_at = T0.toISOString(); delete g[0]!.private_jwk; }), /asStatus has no active generation/],
      ["two active generations", variant((g) => { g[1]!.state = "active"; g[1]!.activated_at = T0.toISOString(); }), /asStatus has more than one active generation/],
      ["two pending generations", variant((g) => { g.push({ ...structuredClone(g[1]!), generation: 3, kid: "as-status-3" }); }), /asStatus has more than one pending generation/],
      ["an active generation without its activation time", variant((g) => { delete g[0]!.activated_at; }), /as-status is active without activated_at/],
      ["a time its state does not carry", variant((g) => { g[1]!.revoked_at = T0.toISOString(); }), /as-status-2 is pending but records revoked_at/],
      ["a time that is not a time", variant((g) => { g[0]!.activated_at = "yesterday"; }), /as-status is active without activated_at/],
      ["an overlap generation that keeps its private key", variant((g) => { g[1]!.state = "overlap"; g[1]!.activated_at = T0.toISOString(); g[1]!.stopped_at = T0.toISOString(); }), /as-status-2 is overlap but still holds a private key/],
      ["a signing generation without a private key", variant((g) => { delete g[0]!.private_jwk; }), /as-status holds no private key/],
      ["a private key that does not match the public key", variant((g) => { g[0]!.public_jwk = other; }), /as-status's private key does not match its public key/],
      ["a public key with private members", variant((g) => { g[0]!.public_jwk = { ...(g[0]!.private_jwk as object) }; }), /as-status holds no public key, or a public key with private members/],
    ];
    for (const [name, file, message] of cases) {
      await expect(loadSigningKeyRing(file, ISSUER, ROLES), name).rejects.toThrow(message);
      await expect(loadSigningKeyRing(file, ISSUER, ROLES), name).rejects.toBeInstanceOf(SigningKeyRingError);
    }
  });

  it("a slice 1 (/1) ring loads as one active generation per role, and converts to /2 only explicitly, with the same keys and kids", async () => {
    const file = await v1Ring();
    const before = await loadSigningKeyRing(file, ISSUER, ROLES);
    for (const role of AS_SIGNING_ROLES) {
      expect(before[role].kid).toBe(ROLES[role].kid);
      expect(kidsOf(before[role].published)).toEqual([ROLES[role].kid]);
    }
    // No operation runs on a /1 ring; each names the migration step instead.
    const raw = readFileSync(file, "utf8");
    await expect(stageSigningKeyGeneration(file, ISSUER, ROLES, "asToken", at(0))).rejects.toThrow(
      /is a mission-as-signing-key-ring\/1 ring; convert it first with `pnpm keys migrate/,
    );
    expect(readFileSync(file, "utf8")).toBe(raw);

    const published = await migrateSigningKeyRing(file, ISSUER, ROLES, at(10));
    expect(readRing(file).format).toBe(SIGNING_KEY_RING_FORMAT);
    expect(statSync(file).mode & 0o777).toBe(0o600);
    const after = await loadSigningKeyRing(file, ISSUER, ROLES);
    for (const role of AS_SIGNING_ROLES) {
      expect(after[role].kid).toBe(ROLES[role].kid);
      expect(await calculateJwkThumbprint(after[role].publicJwk as never)).toBe(
        await calculateJwkThumbprint(before[role].publicJwk as never),
      );
      expect(generationsOf(file, role).map((g) => [g.kid, g.state, g.activated_at])).toEqual([
        [ROLES[role].kid, "active", T0.toISOString()],
      ]);
    }
    expect(published.map((k) => k.kid).sort()).toEqual(KIDS);
    await expect(migrateSigningKeyRing(file, ISSUER, ROLES)).rejects.toThrow(/is already a mission-as-signing-key-ring\/2 ring/);
  });

  it("a /1 ring that would not load is not migrated, and is left as it was", async () => {
    const good = readRing(await v1Ring()) as unknown as { roles: Record<string, Record<string, unknown>> };
    good.roles.asStatus!.kid = "as-status-2";
    const file = ringWith(good);
    const raw = readFileSync(file, "utf8");
    await expect(migrateSigningKeyRing(file, ISSUER, ROLES)).rejects.toThrow(/asStatus is recorded under kid as-status-2, not the configured as-status/);
    expect(readFileSync(file, "utf8")).toBe(raw);
  });
});

describe("rotating, retiring and compromising a role's generations (@spec #831 B2)", () => {
  it("rotation stages a pending generation, published but not signing, and changes no other role", async () => {
    const file = ringPath();
    await initSigningKeyRing(file, ISSUER, ROLES, at(0));
    const untouched = (r: StoredRing) => JSON.stringify(AS_SIGNING_ROLES.filter((x) => x !== "asToken").map((x) => r.roles[x]));
    const before = untouched(readRing(file));
    expect(await stageSigningKeyGeneration(file, ISSUER, ROLES, "asToken", at(0))).toEqual({ kid: "as-token-2" });
    expect(untouched(readRing(file))).toBe(before);
    const keys = await loadSigningKeyRing(file, ISSUER, ROLES);
    expect(keys.asToken.kid).toBe("as-token");
    expect(kidsOf(keys.asToken.published)).toEqual(["as-token", "as-token-2"]);
    expect(kidsOf(keys.asToken.verification)).toEqual(["as-token"]);
    expect(statSync(file).mode & 0o777).toBe(0o600);
    await expect(stageSigningKeyGeneration(file, ISSUER, ROLES, "asToken", at(1))).rejects.toThrow(
      /asToken already has a pending generation, as-token-2; activate or retire it first/,
    );
    await expect(stageSigningKeyGeneration(file, ISSUER, ROLES, "asOther", at(1))).rejects.toThrow(/unknown role asOther/);
  });

  it("verification confirms only a running AS that serves this ring's revision and exactly its live set, recording without advancing the revision", async () => {
    const file = ringPath();
    await initSigningKeyRing(file, ISSUER, ROLES, at(0));
    expect(readRing(file).revision).toBe(1);
    await stageSigningKeyGeneration(file, ISSUER, ROLES, "asToken", at(0));
    expect(readRing(file).revision).toBe(2);
    const { keys } = await loadSigningKeyRingState(file, ISSUER, ROLES);
    const live = Object.values(keys).flatMap((r) => r.published);
    const serving = (etag: string | null, served: Record<string, unknown>[]) => async (url: string) =>
      url.endsWith("/.well-known/openid-configuration")
        ? Response.json({ issuer: ISSUER, jwks_uri: `${ISSUER}/jwks` })
        : new Response(JSON.stringify({ keys: served }), { headers: etag ? { etag } : {} });
    const verify = (etag: string | null, served: Record<string, unknown>[], s: number) =>
      verifySigningKeyRing(file, ISSUER, ROLES, { fetch: serving(etag, served), now: at(s) });
    const raw = readFileSync(file, "utf8");
    // An AS still running the previous revision, or a key set with none.
    await expect(verify('"1"', live, 5)).rejects.toThrow(
      /the running AS serves revision "1", not this ring's "2": restart it with this ring, then verify again/,
    );
    await expect(verify(null, live, 5)).rejects.toThrow(/the running AS serves revision \(none\)/);
    // This revision, but not this ring's live set.
    await expect(verify('"2"', live.filter((k) => k.kid !== "as-token-2"), 5)).rejects.toThrow(/not this ring's live set/);
    expect(readFileSync(file, "utf8")).toBe(raw);
    expect(await verify('"2"', live, 5)).toEqual({
      revision: 2,
      published: ["as-token", "as-token-2", "as-status", "as-txn", "as-continuation"],
      stopped: [],
      withdrawn: [],
    });
    expect(readRing(file).revision).toBe(2);
    expect(generationsOf(file, "asToken").map((g) => g.published_at)).toEqual([at(5)().toISOString(), at(5)().toISOString()]);
    // A later verification records nothing it already recorded.
    expect(await verify('"2"', live, 9)).toEqual({ revision: 2, published: [], stopped: [], withdrawn: [] });
  });

  it("activation waits out the /jwks freshness lifetime from the publication the running AS was confirmed serving, then signs under the new generation", async () => {
    const file = ringPath();
    await initSigningKeyRing(file, ISSUER, ROLES, at(0));
    const minPublishedS = JWKS_MAX_AGE_SECONDS;
    const activate = (s: number) => activateSigningKeyGeneration(file, ISSUER, ROLES, "asToken", { minPublishedS, now: at(s) });
    await expect(activate(1)).rejects.toThrow(/asToken has no pending generation; stage one with `pnpm keys rotate --role asToken`/);
    await stageSigningKeyGeneration(file, ISSUER, ROLES, "asToken", at(0));
    // Staging publishes nothing: with no confirmed publication, no wait suffices.
    await expect(activate(10 * minPublishedS)).rejects.toThrow(
      /as-token-2 is not confirmed published: start the AS with this ring, then run `pnpm keys verify`/,
    );
    await confirmRing(file, ISSUER, ROLES, at(1000));
    await expect(activate(1000 + minPublishedS - 1)).rejects.toThrow(
      new RegExp(`as-token-2 has been confirmed published for ${minPublishedS - 1}s; activation needs ${minPublishedS}s, 1s more`),
    );
    expect(await activate(1000 + minPublishedS)).toEqual({ kid: "as-token-2", previous: "as-token" });
    const keys = await loadSigningKeyRing(file, ISSUER, ROLES);
    expect(keys.asToken.kid).toBe("as-token-2");
    expect(keys.asToken.privateJwk.kid).toBe("as-token-2");
    expect(kidsOf(keys.asToken.published)).toEqual(["as-token", "as-token-2"]);
    expect(kidsOf(keys.asToken.verification)).toEqual(["as-token", "as-token-2"]);
    const [old] = generationsOf(file, "asToken");
    // The edit's time is recorded, but only a verification confirms the stop.
    expect([old!.state, old!.stopped_at, old!.stop_confirmed_at]).toEqual(["overlap", at(1000 + minPublishedS)().toISOString(), undefined]);
    noRetainedPrivateKeys(file);
  });

  it("retirement waits for the retention deadline from the confirmed stop, refuses when none can be established, and refuses a Status generation a standing consent depends on", async () => {
    const file = ringPath();
    await initSigningKeyRing(file, ISSUER, ROLES, at(0));
    for (const role of ["asToken", "asStatus"]) await stageSigningKeyGeneration(file, ISSUER, ROLES, role, at(0));
    await confirmRing(file, ISSUER, ROLES, at(10));
    for (const role of ["asToken", "asStatus"]) {
      await activateSigningKeyGeneration(file, ISSUER, ROLES, role, { minPublishedS: 0, now: at(100) });
    }
    const retention = { auditHorizonS: HORIZON_S, maxMissionLifetimeS: HORIZON_S / 2 };
    const retire = (role: string, kid: string, s: number, extra: Record<string, unknown> = {}) =>
      retireSigningKeyGeneration(file, ISSUER, ROLES, role, kid, { retention: { ...retention, ...extra }, now: at(s) });
    await expect(retire("asToken", "as-token-2", 200)).rejects.toThrow(
      /as-token-2 is asToken's active generation; activate a successor before retiring it/,
    );
    // The activation's edit is not a confirmed stop: the running AS may still sign under generation 1.
    await expect(retire("asToken", "as-token", 100 + 10 * HORIZON_S)).rejects.toThrow(
      /as-token is not confirmed to have stopped signing: start the AS with this ring, then run `pnpm keys verify`/,
    );
    await confirmRing(file, ISSUER, ROLES, at(500));
    await expect(retire("asToken", "as-token", 500 + 10 * HORIZON_S, { maxMissionLifetimeS: null })).rejects.toThrow(
      /no retention deadline can be established for as-token: the Mission lifetime is unbounded/,
    );
    // The deadline: the confirmed stop, plus the longer of the audit horizon and the longest Mission lifetime.
    await expect(retire("asToken", "as-token", 500 + HORIZON_S - 5)).rejects.toThrow(
      new RegExp(`as-token was confirmed to have stopped signing at ${at(500)().toISOString()}; it stays published for ${HORIZON_S}s .*, 5s more`),
    );
    await expect(retire("asToken", "as-token", 500 + 2 * HORIZON_S - 5, { maxMissionLifetimeS: 2 * HORIZON_S })).rejects.toThrow(
      new RegExp(`it stays published for ${2 * HORIZON_S}s .*, 5s more`),
    );
    await retire("asToken", "as-token", 500 + HORIZON_S);
    expect(kidsOf((await loadSigningKeyRing(file, ISSUER, ROLES)).asToken.published)).toEqual(["as-token-2"]);
    await expect(retire("asToken", "as-token", 500 + HORIZON_S)).rejects.toThrow(/as-token is already retired/);
    // A Status generation: the standing governed-policy consents attested under it decide.
    await expect(retire("asStatus", "as-status", 500 + HORIZON_S)).rejects.toThrow(
      /the standing governed-policy consents attested under as-status are unknown; name the kernel store/,
    );
    await expect(retire("asStatus", "as-status", 500 + HORIZON_S, { standingConsents: 2 })).rejects.toThrow(
      /2 standing governed-policy consent\(s\) are attested under as-status; retirement does not expire a consent/,
    );
    await retire("asStatus", "as-status", 500 + HORIZON_S, { standingConsents: 0 });
    // An abandoned rotation: a pending generation never signed, so it retires with no deadline.
    await stageSigningKeyGeneration(file, ISSUER, ROLES, "asToken", at(600 + HORIZON_S));
    await retire("asToken", "as-token-3", 600 + HORIZON_S, { maxMissionLifetimeS: null });
    expect(kidsOf((await loadSigningKeyRing(file, ISSUER, ROLES)).asToken.published)).toEqual(["as-token-2"]);
    await expect(retire("asToken", "as-token-9", 0)).rejects.toThrow(/asToken has no generation as-token-9/);
    noRetainedPrivateKeys(file);
  });

  it("compromising the active generation withdraws it at once and activates a fresh replacement in the same write", async () => {
    const file = ringPath();
    await initSigningKeyRing(file, ISSUER, ROLES, at(0));
    await stageSigningKeyGeneration(file, ISSUER, ROLES, "asStatus", at(0));
    expect(await compromiseSigningKeyGeneration(file, ISSUER, ROLES, "asStatus", "as-status", { now: at(50) })).toEqual({
      kid: "as-status",
      replacement: "as-status-3",
    });
    const keys = await loadSigningKeyRing(file, ISSUER, ROLES);
    // The replacement signs; the pending generation, which may share the exposure, is not promoted.
    expect(keys.asStatus.kid).toBe("as-status-3");
    expect(kidsOf(keys.asStatus.published)).toEqual(["as-status-2", "as-status-3"]);
    expect(kidsOf(keys.asStatus.verification)).toEqual(["as-status-3"]);
    expect(keys.asStatus.withdrawn.map((w) => [w.publicJwk.kid, w.revoked_at, w.compromised_at])).toEqual([
      ["as-status", at(50)().toISOString(), undefined],
    ]);
    const [compromised] = generationsOf(file, "asStatus");
    expect(compromised!.state).toBe("compromised");
    expect("compromised_at" in compromised!).toBe(false);
    noRetainedPrivateKeys(file);
    await expect(compromiseSigningKeyGeneration(file, ISSUER, ROLES, "asStatus", "as-status", { now: at(60) })).rejects.toThrow(
      /as-status is already compromised/,
    );
  });

  it("compromising a generation that no longer signs withdraws it with no replacement, recording an established compromise time, never a future one", async () => {
    const file = ringPath();
    await initSigningKeyRing(file, ISSUER, ROLES, at(0));
    await stageSigningKeyGeneration(file, ISSUER, ROLES, "asTxn", at(0));
    await confirmRing(file, ISSUER, ROLES, at(10));
    await activateSigningKeyGeneration(file, ISSUER, ROLES, "asTxn", { minPublishedS: 0, now: at(100) });
    await expect(
      compromiseSigningKeyGeneration(file, ISSUER, ROLES, "asTxn", "as-txn", { compromisedAt: at(500)(), now: at(200) }),
    ).rejects.toThrow(/the compromise time 2026-10-25T12:08:20.000Z is in the future/);
    expect(
      await compromiseSigningKeyGeneration(file, ISSUER, ROLES, "asTxn", "as-txn", { compromisedAt: at(40)(), now: at(200) }),
    ).toEqual({ kid: "as-txn" });
    const keys = await loadSigningKeyRing(file, ISSUER, ROLES);
    expect(keys.asTxn.kid).toBe("as-txn-2");
    expect(kidsOf(keys.asTxn.published)).toEqual(["as-txn-2"]);
    expect(kidsOf(keys.asTxn.verification)).toEqual(["as-txn-2"]);
    expect(keys.asTxn.withdrawn.map((w) => [w.publicJwk.kid, w.revoked_at, w.compromised_at])).toEqual([
      ["as-txn", at(200)().toISOString(), at(40)().toISOString()],
    ]);
    noRetainedPrivateKeys(file);
  });
});

// ---------------------------------------------------------------------------
// End to end: the AS across restarts, one operation between each.
// ---------------------------------------------------------------------------

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };

async function proof(keys: Keys, extra: Record<string, unknown> = {}): Promise<string> {
  return new SignJWT({ htu: `${ISSUER}/token`, htm: "POST", ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(keys.privateKey);
}

/** The kids the AS publishes at /jwks, with its declared freshness; asserts no private member is published. */
async function publishedKids(): Promise<string[]> {
  const res = await fetch(`${ISSUER}/jwks`);
  expect(res.status).toBe(200);
  expect(res.headers.get("cache-control")).toBe(`max-age=${JWKS_MAX_AGE_SECONDS}`);
  const { keys } = (await res.json()) as { keys: Record<string, unknown>[] };
  for (const k of keys) for (const m of PRIVATE_MEMBERS) expect(k[m], `${String(k.kid)} publishes ${m}`).toBeUndefined();
  return kidsOf(keys);
}

type As = Awaited<ReturnType<typeof buildAuthorizationServer>>;

/** Boot an AS on PORT from `ring`, run `body`, then close it. */
async function withAs<T>(ring: string, body: (as: As) => Promise<T>): Promise<T> {
  const as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    approvalSessions: FLOOR_SESSIONS,
    signingKeys: { ring },
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

const clientAssertion = async (as: As): Promise<string> =>
  new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
    .setIssuer("ap-agent")
    .setSubject("ap-agent")
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign((await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey);

/** POST /token as ap-agent with a DPoP proof, retrying once with the AS's nonce. */
async function tokenRequest(as: As, params: Record<string, string>): Promise<{ status: number; body: Record<string, unknown> }> {
  const dpop = await generateKeyPair("ES256", { extractable: true });
  const send = async (extra: Record<string, unknown> = {}) =>
    fetch(`${ISSUER}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await proof(dpop, extra) },
      body: new URLSearchParams({
        ...params,
        client_assertion: await clientAssertion(as),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

/**
 * PAR, approval and code exchange as ap-agent against the running AS: a
 * Mission-bound access token, and with `openid` an ID Token too (Alice
 * approves for herself, since openid needs the Subject).
 */
async function signIn(as: As, openid = false): Promise<{ accessToken: string; idToken?: string }> {
  const jar = new Map<string, string>();
  const verifier = "signing-key-rotation-verifier-0123456789-0123456789-0123456789";
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url");
  const par = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      ...(openid ? { scope: "openid" } : {}),
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
      client_assertion: await clientAssertion(as),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  expect(par.status).toBe(201);
  const { request_uri } = (await par.json()) as { request_uri: string };
  let res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri })}`, { redirect: "manual" });
  storeCookies(res, jar);
  let location = res.headers.get("location") as string;
  const uid = location.split("/interaction/")[1] as string;
  const approver = openid ? { sub: "alice", subject: null } : undefined;
  const decideHeaders = { ...floorApprovalHeaders(FLOOR_SESSIONS, uid, cookieHeader(jar), approver), "content-type": "application/json" };
  const render_revision = await renderedRevision(ISSUER, uid, decideHeaders);
  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: decideHeaders,
    body: JSON.stringify({ decision: "approve", render_revision }),
  });
  storeCookies(res, jar);
  location = res.headers.get("location") as string;
  while (location?.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookieHeader(jar) } });
    storeCookies(res, jar);
    location = res.headers.get("location") as string;
  }
  const code = new URL(location).searchParams.get("code") as string;
  const tok = await tokenRequest(as, {
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier,
    resource: CANONICAL_RESOURCE,
  });
  expect(tok.status, JSON.stringify(tok.body)).toBe(200);
  return {
    accessToken: tok.body.access_token as string,
    ...(typeof tok.body.id_token === "string" ? { idToken: tok.body.id_token } : {}),
  };
}

const mintAccessToken = async (as: As): Promise<string> => (await signIn(as)).accessToken;

/** The provider's own check of an ID Token presented as `id_token_hint`, against its keystore. */
async function validatesAsHint(as: As, idToken: string): Promise<boolean> {
  const provider = as.provider as unknown as {
    IdToken: { validate(jwt: string, client: unknown): Promise<unknown> };
    Client: { find(id: string): Promise<unknown> };
  };
  try {
    await provider.IdToken.validate(idToken, await provider.Client.find("ap-agent"));
    return true;
  } catch {
    return false;
  }
}

/**
 * The refusal a delegation-handle exchange presenting `subjectToken` gets.
 * Its first check after the token type is the subject's signature under the
 * AS's accepted access-token generations (#831): a token under any other key
 * fails it ({@link WRONG_KEY}), and one under an accepted generation reaches
 * the next check, possession, which a fresh DPoP key fails
 * ({@link SIGNATURE_ACCEPTED}).
 */
async function exchangeRefusal(as: As, subjectToken: string): Promise<string> {
  const answer = await tokenRequest(as, delegationHandleParams(subjectToken, "ap-agent"));
  expect(answer.status, JSON.stringify(answer.body)).toBe(400);
  return answer.body.error_description as string;
}

const kidOf = (jwt: string) => decodeProtectedHeader(jwt).kid;

describe("an AS across a rotation, a retirement and a compromise (@spec #831 B2)", () => {
  it("follows stop, edit, start, verify: publishes each generation while it is live, signs under the active one, and accepts a credential only under an active or overlap generation", { timeout: 180_000 }, async () => {
    const file = ringPath();
    const start = new Date();
    const later = (s: number) => () => new Date(start.getTime() + s * 1000);
    const verify = (s: number) => verifySigningKeyRing(file, ISSUER, ROLES, { now: later(s) });
    await initSigningKeyRing(file, ISSUER, ROLES, later(0));

    const { accessToken: first, idToken: firstId } = await withAs(file, async (as) => {
      expect(await publishedKids()).toEqual(KIDS);
      expect((await verify(0)).published.sort()).toEqual(KIDS);
      const signed = await signIn(as, true);
      expect(await validatesAsHint(as, signed.idToken as string)).toBe(true);
      // Staged while this AS runs: an edit, not yet in effect, so verification refuses until a restart.
      await stageSigningKeyGeneration(file, ISSUER, ROLES, "asToken", later(1));
      await stageSigningKeyGeneration(file, ISSUER, ROLES, "asStatus", later(1));
      await expect(verify(1)).rejects.toThrow(/the running AS serves revision "1", not this ring's "3"/);
      return signed;
    });
    expect(kidOf(first)).toBe("as-token");
    expect(kidOf(firstId as string)).toBe("as-token");

    // Started on the staged ring: generation 2 published, not signing.
    await withAs(file, async (as) => {
      expect(await publishedKids()).toEqual([...KIDS, "as-token-2", "as-status-2"].sort());
      expect((await verify(2)).published).toEqual(["as-token-2", "as-status-2"]);
      expect(kidOf(await mintAccessToken(as))).toBe("as-token");
      expect(as.kernel.statusSigner().kid).toBe("as-status");
    });

    // Activated once confirmed published for the freshness lifetime; generation 1 moves to overlap.
    for (const role of ["asToken", "asStatus"]) {
      await activateSigningKeyGeneration(file, ISSUER, ROLES, role, {
        minPublishedS: JWKS_MAX_AGE_SECONDS,
        now: later(2 + JWKS_MAX_AGE_SECONDS),
      });
    }
    const second = await withAs(file, async (as) => {
      expect(await publishedKids()).toEqual([...KIDS, "as-token-2", "as-status-2"].sort());
      expect((await verify(3 + JWKS_MAX_AGE_SECONDS)).stopped).toEqual(["as-token", "as-status"]);
      expect(await exchangeRefusal(as, first)).toBe(SIGNATURE_ACCEPTED);
      // The provider still verifies its own ID Token from generation 1, and signs a new one only under generation 2.
      expect(await validatesAsHint(as, firstId as string)).toBe(true);
      expect(kidOf((await signIn(as, true)).idToken as string)).toBe("as-token-2");
      expect(as.kernel.statusSigner().kid).toBe("as-status-2");
      expect(as.kernel.statusVerificationKeyFor("as-status")).toBeDefined();
      return mintAccessToken(as);
    });
    expect(kidOf(second)).toBe("as-token-2");

    // Retired at the deadline from the confirmed stop (this AS's kernel is in memory: no consent outlives it).
    const retention = { auditHorizonS: HORIZON_S, maxMissionLifetimeS: HORIZON_S, standingConsents: 0 };
    for (const [role, kid] of [["asToken", "as-token"], ["asStatus", "as-status"]] as const) {
      await retireSigningKeyGeneration(file, ISSUER, ROLES, role, kid, { retention, now: later(3 + JWKS_MAX_AGE_SECONDS + HORIZON_S) });
    }
    const live = (...extra: string[]) => [...KIDS.filter((k) => k !== "as-token" && k !== "as-status"), ...extra].sort();
    await withAs(file, async (as) => {
      expect(await publishedKids()).toEqual(live("as-token-2", "as-status-2"));
      expect((await verify(4 + JWKS_MAX_AGE_SECONDS + HORIZON_S)).withdrawn).toEqual(["as-token", "as-status"]);
      expect(await exchangeRefusal(as, first)).toBe(WRONG_KEY);
      expect(await validatesAsHint(as, firstId as string)).toBe(false);
      expect(await exchangeRefusal(as, second)).toBe(SIGNATURE_ACCEPTED);
      expect(as.kernel.statusVerificationKeyFor("as-status")).toBeUndefined();
    });

    // Compromised while active: withdrawn, and a replacement signs, once the AS restarts.
    await compromiseSigningKeyGeneration(file, ISSUER, ROLES, "asToken", "as-token-2", {
      now: later(5 + JWKS_MAX_AGE_SECONDS + HORIZON_S),
    });
    await withAs(file, async (as) => {
      expect(await publishedKids()).toEqual(live("as-token-3", "as-status-2"));
      const confirmed = await verify(6 + JWKS_MAX_AGE_SECONDS + HORIZON_S);
      expect([confirmed.stopped, confirmed.withdrawn]).toEqual([["as-token-2"], ["as-token-2"]]);
      expect(await exchangeRefusal(as, second)).toBe(WRONG_KEY);
      expect(kidOf(await mintAccessToken(as))).toBe("as-token-3");
    });
  });
});
