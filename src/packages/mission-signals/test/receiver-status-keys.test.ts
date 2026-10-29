/**
 * @spec status#signing-key-retention, status#historical-key-set (#1810): the
 * Signals receiver's resynchronization verifies a Mission Status response
 * under the issuer's Status keys held as the PDP's Status consumer holds
 * them, `missionStatusIssuer(...).keys`: a key the issuer's historical key set
 * lists is refused for the release a resynchronization decides, though the
 * configured `kid`s and the cached `jwks_uri` still carry it, and a rotation
 * reaches the receiver within the freshness the `jwks_uri` declares.
 *
 * The receiver's SET keys (`jwks`) carry `as-status` and not `as-status-2`,
 * as a configuration pinned before the rotation would.
 */

import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { LifecycleCommit } from "@mission/authorization-server";
import { missionStatusIssuer } from "@mission/pdp";
import {
  type CryptoKey,
  exportJWK,
  generateKeyPair,
  type JWK,
  type JWTVerifyGetKey,
  SignJWT,
} from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { MissionSignalReceiver, signLifecycleEvent } from "../src/index.js";

const ISS = "https://as.status-keys.test";
const AUD = "https://consumer.status-keys.test";
const CLIENT = "consumer-client";
const JWKS = `${ISS}/jwks`;
const HISTORICAL = `${ISS}/historical-jwks`;
const KIDS = ["as-status", "as-status-2"];
const EXPIRES_AT = "2027-01-01T00:00:00Z";

interface StatusKey {
  kid: string;
  jwk: JWK;
  key: CryptoKey;
}

let setKey: CryptoKey;
let jwks: { keys: JWK[] };
/** `as-status`: the generation the AS withdraws, as compromised or by rotation. */
let first: StatusKey;
/** `as-status-2`: the generation that replaces it. */
let second: StatusKey;
const dirs: string[] = [];

async function statusKey(kid: string): Promise<StatusKey> {
  const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
  return {
    kid,
    jwk: { ...(await exportJWK(publicKey)), kid, alg: "ES256", use: "sig" },
    key: privateKey,
  };
}

beforeAll(async () => {
  const sets = await generateKeyPair("ES256", { extractable: true });
  setKey = sets.privateKey;
  first = await statusKey("as-status");
  second = await statusKey("as-status-2");
  jwks = {
    keys: [
      { ...(await exportJWK(sets.publicKey)), kid: "as-signals", alg: "ES256", use: "sig" },
      first.jwk,
    ],
  };
});

afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

/** The one clock the issuer's key sets, the responses and the receiver read, in milliseconds. */
let t = Date.now();

const metadata = (extra: Record<string, unknown> = {}) => ({
  issuer: ISS,
  jwks_uri: JWKS,
  mission_status_endpoint: `${ISS}/status`,
  ...extra,
});

const revoked = (jwk: JWK) => ({
  ...jwk,
  revoked: { reason: "compromised", revoked_at: Math.floor(t / 1000) },
});

/** The issuer's historical key set, signed under `signer`. */
const historicalSet = (signer: StatusKey, listed: Record<string, unknown>[]) =>
  new SignJWT({ keys: listed })
    .setProtectedHeader({ alg: "ES256", kid: signer.kid, typ: "jwk-set+jwt" })
    .setIssuer(ISS)
    .setIssuedAt(Math.floor(t / 1000))
    .sign(signer.key);

/** What the issuer serves; `requests` records every URL fetched. */
interface IssuerState {
  published: JWK[];
  historical?: string;
  requests: string[];
}

const fetched = (state: IssuerState, url: string) => state.requests.filter((u) => u === url).length;

/** The issuer's jwks_uri and historical key set, each fresh for five minutes. */
function issuer(state: IssuerState) {
  return async (url: string) => {
    state.requests.push(url);
    if (url === JWKS) {
      return new Response(JSON.stringify({ keys: state.published }), {
        headers: { "cache-control": "max-age=300" },
      });
    }
    if (url === HISTORICAL && state.historical !== undefined) {
      return new Response(state.historical, {
        headers: { "content-type": "application/jwk-set+jwt", "cache-control": "max-age=300" },
      });
    }
    return new Response("", { status: 404 });
  };
}

/** The issuer as the consumer configures it, from its metadata, on the shared clock. */
const configure = (state: IssuerState, advertised: Record<string, unknown> = {}) =>
  missionStatusIssuer(ISS, {
    read: async () => metadata(advertised),
    kids: KIDS,
    algs: ["ES256"],
    fetch: issuer(state),
    now: () => t,
  });

let events = 0;
function set(missionId: string, version: number): Promise<string> {
  events += 1;
  const commit = {
    id: missionId,
    issuer: ISS,
    state: "active",
    version,
    committed_at: new Date(Date.UTC(2026, 9, 1, 0, 0, version)).toISOString(),
    expires_at: EXPIRES_AT,
    event_id: `set_status_keys_${events}`,
  } as LifecycleCommit;
  return signLifecycleEvent(commit, { audience: AUD, key: setKey, kid: "as-signals" });
}

/**
 * A witnessed receiver whose store was replaced by an empty one, so every
 * Mission is held until a Mission Status read resynchronizes it.
 */
async function held(keys: JWTVerifyGetKey): Promise<MissionSignalReceiver> {
  const root = mkdtempSync(join(tmpdir(), "signal-status-keys-"));
  dirs.push(root);
  for (const d of ["state", "witness"]) mkdirSync(join(root, d));
  const options = {
    jwks,
    issuer: ISS,
    audience: AUD,
    store: { file: join(root, "state", "receiver.db") },
    witness: { file: join(root, "witness", "receiver.witness") },
    status: { clientId: CLIENT, keys },
  };
  const before = new MissionSignalReceiver(options);
  expect((await before.verifyAndApply(await set("msn_seen", 1))).status).toBe("applied");
  before.close();
  for (const suffix of ["", "-wal", "-shm"])
    rmSync(`${options.store.file}${suffix}`, { force: true });
  const r = new MissionSignalReceiver(options);
  expect(r.recovering("msn_seen")).toBe(true);
  return r;
}

/** Resynchronize a held Mission from a state-only Status response signed under `signer` at the shared clock. */
async function resync(r: MissionSignalReceiver, signer: StatusKey, missionId: string) {
  const nonce = r.recoveryNonce(missionId) as string;
  expect(nonce).toBeDefined();
  const iat = Math.floor(t / 1000);
  const response = await new SignJWT({
    sub: CLIENT,
    nonce,
    mission: {
      id: missionId,
      issuer: ISS,
      state: "active",
      version: 1,
      expires_at: EXPIRES_AT,
      fresh_until: new Date((iat + 60) * 1000).toISOString(),
    },
  })
    .setProtectedHeader({ alg: "ES256", kid: signer.kid, typ: "mission-status-response+jwt" })
    .setIssuer(ISS)
    .setAudience(CLIENT)
    .setIssuedAt(iat)
    .setExpirationTime(iat + 60)
    .sign(signer.key);
  return r.resynchronize(missionId, response, new Date(t));
}

describe("the Signals receiver's Status keys (@spec status#signing-key-retention, status#historical-key-set, #1810)", () => {
  it("refuses a resynchronization response signed under a key the issuer's historical key set lists, though its configured kids and its cached jwks_uri still carry it; the set is what refuses it", async () => {
    t = Date.now();
    const compromised = first;
    const current = second;
    // The AS has withdrawn as-status as compromised; this consumer's jwks_uri response still carries it.
    const state: IssuerState = {
      published: [current.jwk, compromised.jwk],
      historical: await historicalSet(current, [revoked(compromised.jwk)]),
      requests: [],
    };
    const configured = await configure(state, { mission_historical_jwks_uri: HISTORICAL });
    const r = await held(configured.keys);
    try {
      // The restored receiver's first verification is under the listed key: refused, and the Mission stays held.
      expect(await resync(r, compromised, "msn_a")).toEqual({
        status: "refused",
        reason: "unverified",
      });
      expect(r.recovering("msn_a")).toBe(true);
      // That first verification read both the jwks_uri, which carries the key, and the historical set.
      expect(fetched(state, JWKS)).toBeGreaterThan(0);
      expect(fetched(state, HISTORICAL)).toBeGreaterThan(0);
      // The current key releases it.
      expect(await resync(r, current, "msn_a")).toMatchObject({
        status: "resynchronized",
        state: "active",
        version: 1,
      });
      expect(r.recovering("msn_a")).toBe(false);
      // After a verification under the current key, the listed key is still refused.
      expect(await resync(r, compromised, "msn_b")).toEqual({
        status: "refused",
        reason: "unverified",
      });
      expect(r.recovering("msn_b")).toBe(true);
    } finally {
      r.close();
    }
    // The same issuer advertising no historical key set: the cached jwks_uri's key resynchronizes.
    const unadvertised = await configure(state);
    const control = await held(unadvertised.keys);
    try {
      expect(await resync(control, compromised, "msn_a")).toMatchObject({
        status: "resynchronized",
      });
    } finally {
      control.close();
    }
  });

  it("follows a Status key rotation within the jwks_uri's declared freshness: a newly published trusted key resynchronizes before the cached set's lifetime ends, and a withdrawn one stops once it ends, when the set is fetched again", async () => {
    t = Date.now();
    const old = first;
    const next = second;
    const state: IssuerState = { published: [old.jwk], requests: [] };
    const configured = await configure(state);
    const r = await held(configured.keys);
    try {
      expect(await resync(r, old, "msn_a")).toMatchObject({ status: "resynchronized" });
      // The AS publishes the next generation, which the configuration already trusts. Its unknown kid
      // refetches the set (at most once per the resolver's 30 s refresh interval), so it verifies
      // before the cached set's lifetime ends.
      state.published = [old.jwk, next.jwk];
      t += 1_000;
      const beforeRotation = fetched(state, JWKS);
      expect(await resync(r, next, "msn_b")).toMatchObject({ status: "resynchronized" });
      expect(fetched(state, JWKS)).toBe(beforeRotation + 1);
      // The AS withdraws the old generation. Within the cached set's lifetime the old key still verifies...
      state.published = [next.jwk];
      t += 1_000;
      expect(await resync(r, old, "msn_c")).toMatchObject({ status: "resynchronized" });
      expect(fetched(state, JWKS)).toBe(beforeRotation + 1);
      // ...without a fetch, and once that lifetime (300 s) ends, the set is fetched again and the old key no
      // longer verifies.
      const withinLifetime = fetched(state, JWKS);
      t += 300_000;
      expect(await resync(r, old, "msn_d")).toEqual({ status: "refused", reason: "unverified" });
      expect(fetched(state, JWKS)).toBeGreaterThan(withinLifetime);
      expect(r.recovering("msn_d")).toBe(true);
      expect(await resync(r, next, "msn_d")).toMatchObject({ status: "resynchronized" });
    } finally {
      r.close();
    }
  });
});
