/**
 * @spec draft-mcguinness-oauth-id-continuation-assertion-02 (RFC 8693 token
 * exchange -> continuation ID-JAG)
 *
 * The end-to-end intra-domain continuation hop on the real /token endpoint: an
 * ICA subject token in, a Mission-rooted continuation ID-JAG out, with the
 * current-actor check and the RFC 8693 error taxonomy.
 *
 * The ICA `act` (minted by the Continuation Assertion Issuer against (AS, client_id)) MUST
 * equal the private_key_jwt presenter's canonical actor identity (raw ===,
 * case-sensitive), and the DPoP proof key MUST be the ICA's cnf.jkt. The
 * request carries no actor_token or actor_token_type (ICA -02 5.5.1).
 *
 * The ID-JAG is signed with the dedicated ES256 as-continuation key (published on
 * jwks_uri and trusted by the RAS) because issueCrossDomainGrant hardcodes an
 * ES256 header and the AS token key is RS256; the test verifies it against the AS
 * jwks_uri (asserting the as-continuation kid) AND redeems it end-to-end at a RAS.
 * gateDerivation runs exactly once (inside issueCrossDomainGrant, via a direct
 * SignJWT — never provider.AccessToken).
 *
 * Setup drives the store directly (rootGrantAnchor + mint) and mints ICAs with a
 * dedicated Continuation Assertion Issuer key injected via continuationAssertionIssuers.
 */

import { type Server } from "node:http";
import { CANONICAL_RESOURCE, DERIVATION_POLICY, TOPOLOGY } from "@mission/demo-data";
import { ResourceAuthorizationServer } from "@mission/ras";
import {
  calculateJwkThumbprint,
  createRemoteJWKSet,
  decodeJwt,
  exportJWK,
  generateKeyPair,
  importJWK,
  jwtVerify,
  SignJWT,
} from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TOKEN_EXCHANGE_GRANT_TYPE } from "../src/adapters/continuation-grant.js";
import {
  AuthorityNarrowedToEmptyError,
  buildAuthorizationServer,
  type BuiltAs,
  ID_JAG_TOKEN_TYPE,
  IDENTITY_CONTINUATION_JWT_TYP,
  IDENTITY_CONTINUATION_TOKEN_TYPE,
  issueCrossDomainGrant,
  validateMissionIntent,
} from "../src/index.js";

const PORT = 14475;
const ISSUER = `http://localhost:${PORT}`;
const CAI = "https://cai.example"; // the injected Continuation Assertion Issuer
const CAI_OTHER = "https://cai-other.example"; // trusted only for OTHER_RAS's hops
const OTHER_RAS = "https://ras.other.test";
const RESOURCE = CANONICAL_RESOURCE; // in DERIVATION_POLICY's ceiling
const RAS_AUD = "https://ras.ledgercloud.test"; // the target Resource AS (audience)
const RESOURCE_B = "https://api.ledgercloud.test/v1"; // a second resource the same RAS serves, never approved
const RESOURCE_C = TOPOLOGY.resources.saas; // a third resource the same RAS serves, in the ceiling
const READ_C = { type: "mission_resource_access", resource: RESOURCE_C, actions: ["ledger:vendor.read"] };
const MISSION_EXP = "2027-01-01T00:00:00Z";
const JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";
const RESOURCE_TO_AS = (r: string) => (r === RESOURCE || r === RESOURCE_B || r === RESOURCE_C ? RAS_AUD : ISSUER);

// @spec cross-domain#origin-principal-mapping, #dual-axis (#539): every RAS
// redemption in this file is a CONTINUATION ID-JAG (identity_continuation_handle
// present), which carries its own already-resolved, per-audience deterministic
// `sub` -- mapping/co-resolution never runs for it (see ras/src/index.ts). The
// mapping table is still a required RasConfig field, so it stays empty
// (unconsulted); entitlement DOES run on every redemption regardless of
// continuation status, so this always-true/always-fresh resolver keeps that
// check from blocking a test that isn't exercising it.
const NO_MAPPING = { id: "unused", version: "v1", entries: [] };
const ALWAYS_ENTITLED = { resolve: async () => ({ entitled: true, observed_at: new Date().toISOString() }) };
const ENTITLEMENT_BOUND_S = 86_400;

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };

let as: BuiltAs;
let asServer: Server;
let clientKey: CryptoKey; // ap-agent private_key_jwt key (kid ap-agent-auth)
let caiKeys: Keys; // the Continuation Assertion Issuer's ICA signing key
let otherCaiKeys: Keys; // CAI_OTHER's ICA signing key
let rasCaiKeys: Keys; // RAS_AUD's own ICA signing key (the accepting RAS as its own issuer)
let agentKeys: Keys; // the agent's DPoP key
let agentJkt: string;
let svcKeys: Keys; // a second client, svc-b: its private_key_jwt key
let svcDpopKeys: Keys; // svc-b's DPoP key
let svcJkt: string;
let svcXKeys: Keys; // a third client, svc-x, whose asserted profile no delegation policy names
let svcXDpopKeys: Keys;
let svcXJkt: string;
let svcCKeys: Keys; // a fourth client, svc-c, a second ai_agent delegate
let svcCDpopKeys: Keys;
let svcCJkt: string;
let remoteJwks: ReturnType<typeof createRemoteJWKSet>;

/** A continuation lineage: an active Mission + a grant anchor + an initial handle. */
function newLineage(
  eventId: string,
  envelope: { authTime?: number; acr?: string; amr?: string[] } = {},
  expiresAt: string = MISSION_EXP,
  intentExtra: Record<string, unknown> = {},
  /** Further approved entries, beyond the payments read every lineage holds. */
  extraAuthority: Record<string, unknown>[] = [],
  /** A delegation policy proposed for the payments read (narrowed by the ceiling's). */
  baseDelegation?: Record<string, unknown>,
): {
  missionId: string;
  handle: string;
} {
  const intent = validateMissionIntent(
    JSON.stringify({
      goal: "Continue a Mission across an intra-domain hop",
      target_resources: [RESOURCE, ...extraAuthority.map((e) => e.resource as string)],
      expires_at: expiresAt,
      ...intentExtra,
    }),
  );
  const mission = as.kernel.approve({
    intent,
    proposedAuthority: [
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: ["payments:invoice.read"],
        constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
        ...(baseDelegation ? { delegation: baseDelegation } : {}),
      },
      ...(extraAuthority as never[]),
    ],
    subject: { iss: ISSUER, sub: "alice" }, // the GLOBAL subject
    approver: { iss: ISSUER, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: eventId,
    // The assembled AS owns its catalog resolver; this fixture must use that
    // production path rather than supplying competing caller-resolved facts.
  });
  const anchorId = as.continuationStore.rootGrantAnchor({ missionId: mission.id, authEnvelope: envelope });
  const handle = as.continuationStore.mint({
    anchorId,
    missionId: mission.id,
    actor: { iss: ISSUER, sub: "ap-agent" },
    cnfJkt: agentJkt,
    audience: ISSUER, // as approval-time rooting records it
  });
  return { missionId: mission.id, handle };
}

/**
 * Approve a Mission WITHOUT manually rooting a continuation: the AS assembly roots
 * the durable grant anchor + INITIAL handle at approval (see index.ts
 * rootMissionContinuation). Returns the mission id and that AUTO-rooted handle, so
 * the lifecycle tests prove approval-time rooting rather than test-only rooting.
 */
function approveLineage(
  eventId: string,
  built: BuiltAs = as,
): {
  missionId: string;
  handle: string;
} {
  const intent = validateMissionIntent(
    JSON.stringify({
      goal: "Continue a Mission across an intra-domain hop",
      target_resources: [RESOURCE],
      expires_at: MISSION_EXP,
    }),
  );
  const mission = built.kernel.approve({
    intent,
    proposedAuthority: [
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: ["payments:invoice.read"],
        constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
      },
    ],
    subject: { iss: built.issuer, sub: "alice" },
    approver: { iss: built.issuer, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: eventId,
  });
  const handles = built.continuationStore.handlesForMission(mission.id);
  return { missionId: mission.id, handle: handles[0] as string };
}

/** The issuer that signs an ICA: its `iss`, header `kid` and private key. */
interface Signer {
  iss: string;
  kid: string;
  key: CryptoKey;
  alg?: string;
}

interface IcaOpts {
  handle?: string;
  signer?: Signer;
  cnfJkt?: string;
  act?: { iss: string; sub: string };
  iatSec?: number;
  expSec?: number;
  aud?: string | string[];
  over?: Record<string, unknown>;
}

/** Mint an ICA signed by the Continuation Assertion Issuer key (iss=CAI, aud=AS issuer). */
async function mintICA(handle: string, opts: IcaOpts = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const base: Record<string, unknown> = {
    identity_continuation_handle: opts.handle ?? handle,
    cnf: { jkt: opts.cnfJkt ?? agentJkt },
    act: opts.act ?? { iss: ISSUER, sub: "ap-agent" },
    ...opts.over,
  };
  const signer = opts.signer ?? { iss: CAI, kid: "cai-key", key: caiKeys.privateKey };
  return new SignJWT(base)
    .setProtectedHeader({ alg: signer.alg ?? "ES256", kid: signer.kid, typ: IDENTITY_CONTINUATION_JWT_TYP })
    .setIssuer(signer.iss)
    .setAudience(opts.aud ?? ISSUER)
    .setIssuedAt(opts.iatSec ?? now)
    .setExpirationTime(opts.expSec ?? now + 120)
    .setJti(crypto.randomUUID())
    .sign(signer.key);
}

/** An actor_token as a pre--02 client sent it: signed by the DPoP key, cnf.jkt = the presenter jkt. */
async function mintActorToken(over: Record<string, unknown> = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ iss: ISSUER, sub: "ap-agent", cnf: { jkt: agentJkt }, ...over })
    .setProtectedHeader({ alg: "ES256" })
    .setIssuedAt(now)
    .setExpirationTime(now + 120)
    .setJti(crypto.randomUUID())
    .sign(agentKeys.privateKey);
}

/**
 * The AS a request goes to: its issuer and the client key it registered (by
 * default ap-agent's), and the presenter's DPoP key (by default the agent's).
 */
interface Target {
  issuer: string;
  clientKey: CryptoKey;
  clientId?: string;
  dpopKeys?: Keys;
}

async function clientAssertion(t: Target): Promise<string> {
  const clientId = t.clientId ?? "ap-agent";
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: `${clientId}-auth` })
    .setIssuer(clientId)
    .setSubject(clientId)
    .setAudience(t.issuer)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(t.clientKey);
}

async function dpopProof(
  htu: string,
  htm: string,
  extra: Record<string, unknown> = {},
  keys: Keys = agentKeys,
): Promise<string> {
  return new SignJWT({ htu, htm, ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(keys.privateKey);
}

interface ExchangeFields {
  subjectToken: string;
  actorToken?: string;
  actorTokenType?: string;
  audience?: string;
  /** One value, several (each sent as its own `resource`), or null to omit it. */
  resource?: string | string[] | null;
  requestedTokenType?: string;
  subjectTokenType?: string;
  extra?: Record<string, string>;
  /** Parameters appended as-is, so one name can repeat. */
  repeated?: Array<[string, string]>;
  /** Send no DPoP header. */
  noDpop?: boolean;
}

/** POST /token with the token-exchange grant + private_key_jwt + DPoP (nonce retry). */
async function tokenExchange(f: ExchangeFields, t: Target = { issuer: ISSUER, clientKey }): Promise<Response> {
  const htu = `${t.issuer}/token`;
  const params: Record<string, string> = {
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    requested_token_type: f.requestedTokenType ?? ID_JAG_TOKEN_TYPE,
    subject_token: f.subjectToken,
    subject_token_type: f.subjectTokenType ?? IDENTITY_CONTINUATION_TOKEN_TYPE,
    audience: f.audience ?? RAS_AUD,
    ...f.extra,
  };
  if (f.actorToken !== undefined) params.actor_token = f.actorToken;
  if (f.actorTokenType !== undefined) params.actor_token_type = f.actorTokenType;
  const resources = f.resource === null ? [] : [f.resource ?? RESOURCE].flat();
  const send = async (extra: Record<string, unknown> = {}): Promise<Response> => {
    const body = new URLSearchParams({
      ...params,
      client_assertion: await clientAssertion(t),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    });
    for (const r of resources) body.append("resource", r);
    for (const [name, value] of f.repeated ?? []) body.append(name, value);
    return fetch(htu, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        ...(f.noDpop ? {} : { dpop: await dpopProof(htu, "POST", extra, t.dpopKeys) }),
      },
      body: body.toString(),
    });
  };
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return res;
}

beforeAll(async () => {
  caiKeys = await generateKeyPair("ES256", { extractable: true });
  const caiPub = { ...(await exportJWK(caiKeys.publicKey)), kid: "cai-key", alg: "ES256", use: "sig" };
  otherCaiKeys = await generateKeyPair("ES256", { extractable: true });
  const otherCaiPub = { ...(await exportJWK(otherCaiKeys.publicKey)), kid: "other-cai-key", alg: "ES256" };
  rasCaiKeys = await generateKeyPair("ES256", { extractable: true });
  const rasCaiPub = { ...(await exportJWK(rasCaiKeys.publicKey)), kid: "ras-cai-key", alg: "ES256" };
  agentKeys = await generateKeyPair("ES256", { extractable: true });
  agentJkt = await calculateJwkThumbprint(await exportJWK(agentKeys.publicKey));
  svcKeys = await generateKeyPair("ES256", { extractable: true });
  svcDpopKeys = await generateKeyPair("ES256", { extractable: true });
  svcJkt = await calculateJwkThumbprint(await exportJWK(svcDpopKeys.publicKey));
  svcXKeys = await generateKeyPair("ES256", { extractable: true });
  svcXDpopKeys = await generateKeyPair("ES256", { extractable: true });
  svcXJkt = await calculateJwkThumbprint(await exportJWK(svcXDpopKeys.publicKey));
  svcCKeys = await generateKeyPair("ES256", { extractable: true });
  svcCDpopKeys = await generateKeyPair("ES256", { extractable: true });
  svcCJkt = await calculateJwkThumbprint(await exportJWK(svcCDpopKeys.publicKey));
  const exchangeClient = async (clientId: string, keys: Keys) => ({
    client_id: clientId,
    grant_types: [TOKEN_EXCHANGE_GRANT_TYPE],
    response_types: [],
    redirect_uris: [],
    token_endpoint_auth_method: "private_key_jwt",
    token_endpoint_auth_signing_alg: "ES256",
    jwks: { keys: [{ ...(await exportJWK(keys.publicKey)), kid: `${clientId}-auth`, alg: "ES256" }] },
  });

  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    // Further token-exchange clients, so a hop can be continued by an actor
    // other than the one that obtained it.
    testClients: [
      await exchangeClient("svc-b", svcKeys),
      await exchangeClient("svc-x", svcXKeys),
      await exchangeClient("svc-c", svcCKeys),
    ],
    // The AS-asserted actor profiles the delegation policies match: the
    // ceiling's payments entries are delegable to ai_agent actors through
    // depth 2 (config/policy.json), and svc-x is a class none names.
    actorProfiles: { "ap-agent": "ai_agent", "svc-b": "ai_agent", "svc-x": "service", "svc-c": "ai_agent" },
    continuationAssertionIssuers: [
      // Trusted for the root hops (this AS) and the child hops (RAS_AUD).
      { iss: CAI, jwks: { keys: [caiPub] }, attestsFor: [ISSUER, RAS_AUD] },
      { iss: CAI_OTHER, jwks: { keys: [otherCaiPub] }, attestsFor: [OTHER_RAS] },
      // The accepting RAS itself, trusted for its own hops only.
      { iss: RAS_AUD, jwks: { keys: [rasCaiPub] }, attestsFor: [] },
    ],
    resourceToAs: RESOURCE_TO_AS,
    // Deterministic subjectResolver is the default (a stable digest over ISSUER).
  });
  asServer = as.provider.listen(PORT);
  clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  remoteJwks = createRemoteJWKSet(new URL(`${ISSUER}/jwks`));
});

afterAll(() => {
  asServer?.close();
});

describe("RFC 8693 token exchange: ICA subject token -> continuation ID-JAG (@spec id-continuation-assertion)", () => {
  it("a Mission ending inside the grant lifetime gets a continuation ID-JAG that expires no later than it (@spec mission#mission-bound-tokens)", async () => {
    const { missionId, handle } = newLineage("apev-exp-clamp", {}, new Date(Date.now() + 60_000).toISOString());
    const res = await tokenExchange({ subjectToken: await mintICA(handle) });
    const body = (await res.json()) as { access_token?: string };
    expect(res.status, JSON.stringify(body)).toBe(200);
    const missionExp = Math.floor(Date.parse(as.kernel.get(missionId)?.expires_at as string) / 1000);
    const grant = decodeJwt(body.access_token as string) as { iat: number; exp: number };
    expect(grant.exp).toBeLessThanOrEqual(missionExp);
    expect(grant.exp - grant.iat).toBeLessThan(300);
  });

  it("happy path: mints a Mission-rooted ID-JAG with a fresh handle, deterministic sub, collapsed act, and carried envelope", async () => {
    const { missionId, handle } = newLineage("apev-happy", {
      authTime: 1_700_000_000,
      acr: "urn:mace:acr:mfa",
      amr: ["pwd", "otp"],
    });

    const res = await tokenExchange({ subjectToken: await mintICA(handle) });
    const body = (await res.json()) as {
      access_token?: string;
      issued_token_type?: string;
      token_type?: string;
      expires_in?: number;
      error?: string;
    };
    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(body.issued_token_type).toBe(ID_JAG_TOKEN_TYPE);
    expect(body.token_type).toBe("N_A");
    expect(body.expires_in).toBeGreaterThan(0);
    expect(res.headers.get("cache-control")).toContain("no-store");

    // The ID-JAG verifies on the AS jwks_uri, signed with the DEDICATED ES256
    // as-continuation key (remoteJwks resolves by kid, so the kid assertion is
    // what proves the rewire off the as-txn placeholder actually happened).
    const { payload, protectedHeader } = await jwtVerify(body.access_token as string, remoteJwks, {
      issuer: ISSUER,
      audience: RAS_AUD,
    });
    expect(protectedHeader.kid).toBe("as-continuation");
    expect(payload.aud).toBe(RAS_AUD);
    expect((payload.cnf as { jkt?: string }).jkt).toBe(agentJkt); // sender-constrained to the DPoP key
    expect((payload.mission as { id?: string }).id).toBe(missionId);
    expect(Array.isArray(payload.authorization_details)).toBe(true);

    // Audience-local, deterministic sub: NOT the global mission subject.
    const localSub = payload.sub as string;
    expect(localSub).not.toBe("alice");
    expect(localSub.startsWith("acct_")).toBe(true);

    // Fresh new-hop handle: distinct from the presented one, resolvable to the
    // SAME Mission (a hop persists; it is not consumed).
    const freshHandle = payload.identity_continuation_handle as string;
    expect(freshHandle).not.toBe(handle);
    expect(as.continuationStore.resolve(freshHandle)?.missionId).toBe(missionId);
    // The child hop records the RAS audience its ID-JAG names (ICA -02 5.1.2).
    expect(as.continuationStore.resolve(freshHandle)?.audience).toBe(RAS_AUD);

    // Collapsed act: the root hop's actor is this same client, so the lineage
    // merges to a single entry (no nested `act`). A second actor nests; see
    // "continuation onward act lineage".
    expect(payload.act).toEqual({ iss: ISSUER, sub: "ap-agent" });
    expect(payload.act).not.toHaveProperty("act");

    // Root auth envelope carried unchanged.
    expect(payload.auth_time).toBe(1_700_000_000);
    expect(payload.acr).toBe("urn:mace:acr:mfa");
    expect(payload.amr).toEqual(["pwd", "otp"]);

    // A second, DIFFERENT ICA (fresh jti) over the same lineage yields the SAME
    // deterministic sub for the same (audience, subject).
    const res2 = await tokenExchange({ subjectToken: await mintICA(handle) });
    const body2 = (await res2.json()) as { access_token?: string; error?: string };
    expect(res2.status, JSON.stringify(body2)).toBe(200);
    const { payload: p2 } = await jwtVerify(body2.access_token as string, remoteJwks, {
      issuer: ISSUER,
      audience: RAS_AUD,
    });
    expect(p2.sub).toBe(localSub);
  });

  it("end-to-end: the continuation ID-JAG redeems at the RAS (trusted as-continuation key) into a local token", async () => {
    const { missionId, handle } = newLineage("apev-ras");
    const res = await tokenExchange({ subjectToken: await mintICA(handle) });
    const body = (await res.json()) as { access_token?: string; error?: string };
    expect(res.status, JSON.stringify(body)).toBe(200);
    const idJag = body.access_token as string;
    const localSub = (await jwtVerify(idJag, remoteJwks, { issuer: ISSUER, audience: RAS_AUD })).payload.sub as string;

    // The RAS trusts the AS issuer's PUBLIC as-continuation key (from the
    // jwks_uri) — the same wiring the demo stack performs. aud = the RAS issuer,
    // which is the ID-JAG audience (RAS_AUD).
    const serverJwks = (await (await fetch(`${ISSUER}/jwks`)).json()) as { keys: Record<string, unknown>[] };
    const asContinuationPub = serverJwks.keys.find((k) => k.kid === "as-continuation");
    expect(asContinuationPub, "as-continuation key must be published on jwks_uri").toBeDefined();

    const rasKeys = await generateKeyPair("ES256", { extractable: true });
    const ras = new ResourceAuthorizationServer({
      localCeiling: DERIVATION_POLICY.ceiling,
      localPolicyVersion: DERIVATION_POLICY.policy_version,
      issuer: RAS_AUD,
      trustedIssuers: { [ISSUER]: { keys: [asContinuationPub as never] } },
      signKey: rasKeys.privateKey,
      signKid: "ras-token",
      registeredClients: { [agentJkt]: TOPOLOGY.rasLocalClientId },
      mapping: NO_MAPPING,
      entitlement: ALWAYS_ENTITLED,
      entitlementStalenessBoundSeconds: ENTITLEMENT_BOUND_S,
    });

    // Redeem the continuation ID-JAG (JWT-bearer grant), sender-constrained to
    // the SAME DPoP presenter key the ID-JAG's cnf.jkt names.
    const { access_token, expires_in } = await ras.redeem(idJag, agentJkt);
    expect(expires_in).toBeGreaterThan(0);

    // The local token surfaces the continuation identity: audience-local sub,
    // authorization_details, cnf, and the preserved mission anchors.
    const local = JSON.parse(Buffer.from(access_token.split(".")[1] as string, "base64url").toString());
    expect(local.iss).toBe(RAS_AUD); // minted by the RAS
    expect(local.sub).toBe(localSub); // the audience-local sub, unchanged
    expect(local.sub).not.toBe("alice"); // never the global subject
    expect(local.cnf.jkt).toBe(agentJkt); // sender-constraint preserved
    expect(Array.isArray(local.authorization_details)).toBe(true);
    expect(local.mission.id).toBe(missionId); // mission anchors preserved
    expect(local.mission.issuer).toBe(ISSUER); // originating AS unchanged

    // @spec cross-domain#validation-at-resource-as (S-12): client_id identifies
    // the redeeming destination client (this RAS's own registration), never the
    // grant's own client_id (the originating actor, "ap-agent") or the
    // presenter key.
    expect(local.client_id).toBe(TOPOLOGY.rasLocalClientId);
    expect(local.client_id).not.toBe("ap-agent");
    expect(local.client_id).not.toBe(agentJkt);

    // A replay of the same ID-JAG is refused at the RAS (one-time jti).
    await expect(ras.redeem(idJag, agentJkt)).rejects.toMatchObject({ code: "invalid_grant" });
  });

  it("advertises the feature: AS discovery flag + RAS grant-profile metadata", async () => {
    // (4) AS .well-known advertises identity_continuation_supported.
    const meta = (await (await fetch(`${ISSUER}/.well-known/openid-configuration`)).json()) as Record<
      string,
      unknown
    >;
    expect(meta.identity_continuation_supported).toBe(true);
    // ICA -02 7.1: an IdP that sets the flag also lists the id-jag type.
    expect(meta.identity_chaining_requested_token_types_supported).toEqual([ID_JAG_TOKEN_TYPE]);

    // @spec txn-authorization#challenge-redemption — this AS is built WITHOUT
    // transaction authorization, so it does not advertise an endpoint that
    // would answer 501.
    expect(meta.transaction_authorization_endpoint).toBeUndefined();

    // (5) RAS metadata advertises the base id-jag grant profile only: it binds
    // no continuation handle, so it does not claim id-jag-continuation, which
    // would also oblige it to advertise jwt-dpop (ICA -02 7.2).
    const rasKeys = await generateKeyPair("ES256", { extractable: true });
    const ras = new ResourceAuthorizationServer({
      localCeiling: DERIVATION_POLICY.ceiling,
      localPolicyVersion: DERIVATION_POLICY.policy_version,
      issuer: RAS_AUD,
      trustedIssuers: {},
      signKey: rasKeys.privateKey,
      signKid: "ras-token",
      registeredClients: { [agentJkt]: TOPOLOGY.rasLocalClientId },
      mapping: NO_MAPPING,
      entitlement: ALWAYS_ENTITLED,
      entitlementStalenessBoundSeconds: ENTITLEMENT_BOUND_S,
    });
    const profiles = ras.metadata().authorization_grant_profiles_supported as string[];
    expect(profiles).toEqual(["urn:ietf:params:oauth:grant-profile:id-jag"]);
    expect(profiles).not.toContain("urn:ietf:params:oauth:grant-profile:id-jag-continuation");
  });

  it("(a) ICA lifetime exp-iat > 300s -> invalid_request", async () => {
    const { handle } = newLineage("apev-a");
    const now = Math.floor(Date.now() / 1000);
    const res = await tokenExchange({
      subjectToken: await mintICA(handle, { iatSec: now, expSec: now + 301 }),
    });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toMatch(/lifetime/);
  });

  it("(a1) an ICA whose aud is an array -> invalid_request, even when it holds only the AS issuer (ICA -02 3.2)", async () => {
    const { handle } = newLineage("apev-a1");
    const res = await tokenExchange({ subjectToken: await mintICA(handle, { aud: [ISSUER] }) });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toMatch(/aud MUST be a single string/);
  });

  it("(a2) an ICA whose iat is beyond the clock skew in the future -> invalid_request (ICA -02 5.5.3 rule 6)", async () => {
    const { handle } = newLineage("apev-a2");
    const now = Math.floor(Date.now() / 1000);
    const res = await tokenExchange({ subjectToken: await mintICA(handle, { iatSec: now + 120, expSec: now + 240 }) });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toMatch(/iat is in the future/);
  });

  it("(b0) consumption is atomic with issuance (#617 review 1): a redemption refused at the Mission gate leaves the ICA UNCONSUMED; the SAME assertion redeems once the gate reopens", async () => {
    const { missionId, handle } = newLineage("apev-b0");
    const ica = await mintICA(handle);

    // Suspend: reversible, and NOT terminal, so the handle lineage stays
    // resolvable (chain state passes) and the refusal comes from the Mission
    // gate at the authorization rule, i.e. AFTER validation.
    as.kernel.transition(missionId, "suspend");
    const refused = await tokenExchange({ subjectToken: ica });
    const refusedBody = (await refused.json()) as { error?: string; error_description?: string };
    expect(refused.status, JSON.stringify(refusedBody)).toBe(400);
    // A suspended Mission is reversible, so the chain has not ended: never
    // invalid_continuation (ICA -02 5.5.6; owner ruling 2026-10-01).
    expect(refusedBody.error).toBe("unauthorized_client");
    expect(refusedBody.error_description).toMatch(/gate refused issuance/);
    expect(refusedBody).not.toHaveProperty("mission_error");

    // Nothing was issued, so nothing was consumed: the assertion is still
    // single-use-unspent. (Recording at validation, the prior behavior, burned
    // it here and made this retry fail /replay/ forever.)
    as.kernel.transition(missionId, "resume");
    const ok = await tokenExchange({ subjectToken: ica });
    const okBody = (await ok.json()) as { access_token?: string; error?: string };
    expect(ok.status, JSON.stringify(okBody)).toBe(200);
    expect(typeof okBody.access_token).toBe("string");

    // And it is consumed exactly once: the successful issuance recorded it.
    const replayed = await tokenExchange({ subjectToken: ica });
    const replayedBody = (await replayed.json()) as { error?: string; error_description?: string };
    expect(replayed.status, JSON.stringify(replayedBody)).toBe(400);
    expect(replayedBody.error_description).toMatch(/replay/);
  });

  it("(b1) a Mission past its expiry at the gate -> invalid_continuation with mission_error (ICA -02 5.5.6)", async () => {
    const { missionId, handle } = newLineage("apev-b1");
    // The expiry clock has run out but the gate has not yet materialized it, so
    // the handle still resolves and the refusal comes from the Mission gate.
    as.kernel.db.prepare("UPDATE missions SET expires_at = ? WHERE id = ?").run("2020-01-01T00:00:00Z", missionId);
    const res = await tokenExchange({ subjectToken: await mintICA(handle) });
    const body = (await res.json()) as { error?: string; error_description?: string; mission_error?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_continuation");
    expect(body.error_description).toMatch(/gate refused issuance/);
    expect(body.mission_error).toBe("mission_expired");
  });

  it("(b2) a Mission whose authority is fully contained -> invalid_target (ICA -02 5.5.6)", async () => {
    const { missionId, handle } = newLineage("apev-b2");
    as.kernel.contain(missionId, {
      event: {
        type: "tainted_read",
        source: "https://siem.example/detections",
        observed_at: new Date().toISOString(),
        event_id: "evt-apev-b2",
      },
      remove: [{ resource: RESOURCE, actions: ["payments:invoice.read"] }],
    });
    const res = await tokenExchange({ subjectToken: await mintICA(handle) });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_target");
    expect(body.error_description).toMatch(/authority_contained/);
  });

  it("(b3) an exhausted derivation cap -> invalid_grant with mission_error (a limit, ICA -02 5.5.6)", async () => {
    const { handle } = newLineage("apev-b3", {}, MISSION_EXP, { requested_derivation_limit: 1 });
    const first = await tokenExchange({ subjectToken: await mintICA(handle) });
    expect(first.status, await first.clone().text()).toBe(200);
    const res = await tokenExchange({ subjectToken: await mintICA(handle) });
    const body = (await res.json()) as { error?: string; error_description?: string; mission_error?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_grant");
    expect(body.error_description).toMatch(/derivation_cap_exhausted/);
    expect(body.mission_error).toBe("derivations_exhausted");
  });

  it("(b4) a revoked Mission whose hop the store has not yet ended -> invalid_continuation at the gate, not unauthorized_client", async () => {
    const { missionId, handle } = newLineage("apev-b4");
    as.kernel.transition(missionId, "revoke");
    // Undo the store fan-out so the hop still resolves and the gate, reading
    // the terminal Mission, is what refuses (a store that lags the lifecycle).
    as.continuationStore.db.prepare("UPDATE continuation_anchors SET state = 'active' WHERE mission_id = ?").run(missionId);
    as.continuationStore.db.prepare("UPDATE continuation_handles SET state = 'active' WHERE mission_id = ?").run(missionId);
    const res = await tokenExchange({ subjectToken: await mintICA(handle) });
    const body = (await res.json()) as { error?: string; error_description?: string; mission_error?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_continuation");
    expect(body.error_description).toMatch(/gate refused issuance/);
    expect(body.mission_error).toBe("mission_revoked");
  });

  it("(b5) a refusal at the Mission gate records no child hop (the hop is recorded only once the gate admits)", async () => {
    const { missionId, handle } = newLineage("apev-b5");
    as.kernel.transition(missionId, "suspend");
    const before = as.continuationStore.handlesForMission(missionId).length;
    const res = await tokenExchange({ subjectToken: await mintICA(handle) });
    const body = (await res.json()) as { error?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("unauthorized_client");
    expect(as.continuationStore.handlesForMission(missionId)).toHaveLength(before);
  });

  it("(b) a replayed ICA jti -> rejected (single-use, consumed at issuance commit)", async () => {
    const { handle } = newLineage("apev-b");
    const ica = await mintICA(handle);
    const first = await tokenExchange({ subjectToken: ica });
    expect(first.status, await first.clone().text()).toBe(200);

    const second = await tokenExchange({ subjectToken: ica });
    const body = (await second.json()) as { error?: string; error_description?: string };
    expect(second.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toMatch(/replay/);
  });

  it("(b6) concurrent presentations of one ICA: exactly one is issued, every other is invalid_request, and only one derivation and one hop are spent (ICA -02 5.5.7)", async () => {
    const { missionId, handle } = newLineage("apev-b6");
    const ica = await mintICA(handle);
    const hopsBefore = as.continuationStore.handlesForMission(missionId).length;
    const results = await Promise.all(
      Array.from({ length: 5 }, async () => {
        const res = await tokenExchange({ subjectToken: ica });
        return { status: res.status, body: (await res.json()) as { error?: string } };
      }),
    );
    expect(results.filter((r) => r.status === 200), JSON.stringify(results)).toHaveLength(1);
    for (const r of results.filter((r) => r.status !== 200)) {
      expect(r.status, JSON.stringify(r.body)).toBe(400);
      expect(r.body.error).toBe("invalid_request");
    }
    expect(as.kernel.get(missionId)?.derivation_count).toBe(1);
    expect(as.continuationStore.handlesForMission(missionId)).toHaveLength(hopsBefore + 1);
  });

  it("(c) a request carrying actor_token -> invalid_request (ICA -02 5.5.1: the actor is the authenticated client)", async () => {
    const { missionId, handle } = newLineage("apev-c");
    const res = await tokenExchange({
      subjectToken: await mintICA(handle),
      actorToken: await mintActorToken(),
      actorTokenType: JWT_TOKEN_TYPE,
    });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toMatch(/actor_token/);
    // Refused before any side effect: no hop recorded for the Mission.
    expect(as.continuationStore.handlesForMission(missionId)).toHaveLength(2);
  });

  it("(c1) actor_token_type alone -> invalid_request", async () => {
    const { handle } = newLineage("apev-c1");
    const res = await tokenExchange({ subjectToken: await mintICA(handle), actorTokenType: JWT_TOKEN_TYPE });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toMatch(/actor_token_type/);
  });

  it("(c2) actor_token alone -> invalid_request", async () => {
    const { handle } = newLineage("apev-c2");
    const res = await tokenExchange({ subjectToken: await mintICA(handle), actorToken: await mintActorToken() });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toMatch(/actor_token/);
  });

  it("(c3) an ICA act that is not the authenticated client's canonical actor -> invalid_request (ICA -02 5.5.6)", async () => {
    const { missionId, handle } = newLineage("apev-c3");
    for (const act of [
      { iss: ISSUER, sub: "ap-agent-imposter" }, // another sub at the same issuer
      { iss: CAI, sub: "ap-agent" }, // the same sub at another actor identity authority
    ]) {
      const res = await tokenExchange({ subjectToken: await mintICA(handle, { act }) });
      const body = (await res.json()) as { error?: string; error_description?: string };
      expect(res.status, JSON.stringify(body)).toBe(400);
      expect(body.error).toBe("invalid_request");
      expect(body.error_description).toMatch(/actor does not match the authenticated client/);
    }
    expect(as.continuationStore.handlesForMission(missionId)).toHaveLength(2);
  });

  it("(d) DPoP jkt != ICA cnf.jkt -> invalid_request (presenter-key mismatch)", async () => {
    const { handle } = newLineage("apev-d");
    const res = await tokenExchange({
      subjectToken: await mintICA(handle, { cnfJkt: "some-other-jkt-thumbprint-value" }),
    });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toMatch(/presenter key/);
  });

  it("(e) an unknown continuation handle -> invalid_request, never invalid_continuation (ICA -02 5.5.6)", async () => {
    const { handle } = newLineage("apev-e");
    const res = await tokenExchange({
      subjectToken: await mintICA(handle, { handle: "ich_unknownhandle0123456789ABCDEFGH" }),
    });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toMatch(/unknown continuation handle/);
  });

  it("(e1) a terminal handle on a live Mission (its session ended) -> invalid_continuation", async () => {
    const { missionId } = newLineage("apev-e1");
    const anchorId = as.continuationStore.rootSessionAnchor({ missionId, sessionId: "sess-e1", authEnvelope: {} });
    const handle = as.continuationStore.mint({ anchorId, missionId, actor: { iss: ISSUER, sub: "ap-agent" }, audience: ISSUER });
    as.continuationStore.terminateSession("sess-e1");
    const res = await tokenExchange({ subjectToken: await mintICA(handle) });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_continuation");
    expect(body.error_description).toMatch(/terminal continuation handle/);
  });

  it("(f) resourceToAs(resource) != audience -> invalid_target", async () => {
    const { handle } = newLineage("apev-f");
    const res = await tokenExchange({
      subjectToken: await mintICA(handle),
      audience: "https://wrong-audience.test",
    });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_target");
  });

  it("(f1) no resource -> issued (zero or more resource, ICA -02 5.5.3 rule 1)", async () => {
    const { handle } = newLineage("apev-f1");
    const res = await tokenExchange({ subjectToken: await mintICA(handle), resource: null });
    expect(res.status, await res.clone().text()).toBe(200);
  });

  it("(f2) several resources, each approved and served by the audience -> issued", async () => {
    const { handle } = newLineage("apev-f2", {}, MISSION_EXP, {}, [READ_C]);
    const res = await tokenExchange({ subjectToken: await mintICA(handle), resource: [RESOURCE, RESOURCE_C] });
    expect(res.status, await res.clone().text()).toBe(200);
  });

  it("(f5) a resource the audience serves but the Mission does not authorize -> invalid_target, with no hop and no derivation (ICA -02 5.5.6)", async () => {
    const { missionId, handle } = newLineage("apev-f5");
    const hops = as.continuationStore.handlesForMission(missionId).length;
    for (const resource of [RESOURCE_B, [RESOURCE, RESOURCE_B]]) {
      const res = await tokenExchange({ subjectToken: await mintICA(handle), resource });
      const body = (await res.json()) as { error?: string; error_description?: string };
      expect(res.status, JSON.stringify(body)).toBe(400);
      expect(body.error).toBe("invalid_target");
      expect(body.error_description).toMatch(/not authorized by the Mission/);
    }
    expect(as.continuationStore.handlesForMission(missionId)).toHaveLength(hops);
    expect(as.kernel.get(missionId)?.derivation_count).toBe(0);
  });

  it("(f3) one resource the audience does not serve -> invalid_target, in either order (an order-independent set)", async () => {
    const { handle } = newLineage("apev-f3");
    for (const resource of [
      [RESOURCE, "https://elsewhere.test/api"],
      ["https://elsewhere.test/api", RESOURCE],
    ]) {
      const res = await tokenExchange({ subjectToken: await mintICA(handle), resource });
      const body = (await res.json()) as { error?: string };
      expect(res.status, JSON.stringify(body)).toBe(400);
      expect(body.error).toBe("invalid_target");
    }
  });

  it("(f4) every other token exchange still refuses a repeated resource", async () => {
    const { handle } = newLineage("apev-f4");
    for (const extra of [
      { request_refresh_token: "true" },
      { subject_token_type: "urn:ietf:params:oauth:token-type:mission-delegation-chain" },
    ]) {
      const res = await tokenExchange({ subjectToken: await mintICA(handle), resource: [RESOURCE, RESOURCE_B], extra });
      const body = (await res.json()) as { error?: string; error_description?: string };
      expect(res.status, JSON.stringify(body)).toBe(400);
      expect(body.error).toBe("invalid_request");
      expect(body.error_description).toBe("'resource' parameter must not be provided twice");
    }
    for (const requestedTokenType of [JWT_TOKEN_TYPE, "urn:ietf:params:oauth:token-type:access_token"]) {
      const res = await tokenExchange({
        subjectToken: await mintICA(handle),
        resource: [RESOURCE, RESOURCE_B],
        requestedTokenType,
      });
      const body = (await res.json()) as { error?: string; error_description?: string };
      expect(res.status, JSON.stringify(body)).toBe(400);
      expect(body.error_description).toBe("'resource' parameter must not be provided twice");
    }
  });

  it("(h) a requested authorization_details within the Mission's authority for the audience is issued as requested (ICA -02 5.5.3 rule 7)", async () => {
    const { handle } = newLineage("apev-h");
    const requested = [
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: ["payments:invoice.read"],
        constraints: { max_amount: { amount: "100.00", currency: "USD" }, vendors: ["acme"] },
      },
    ];
    const res = await tokenExchange({
      subjectToken: await mintICA(handle),
      extra: { authorization_details: JSON.stringify(requested) },
    });
    const body = (await res.json()) as { access_token?: string };
    expect(res.status, JSON.stringify(body)).toBe(200);
    const details = decodeJwt(body.access_token as string).authorization_details as Array<Record<string, unknown>>;
    expect(details).toHaveLength(1);
    expect(details[0]?.constraints).toEqual(requested[0]?.constraints);
  });

  it("(h1) without authorization_details, or with an empty array, the grant carries the whole audience-scoped set", async () => {
    const { handle } = newLineage("apev-h1");
    for (const extra of [{}, { authorization_details: "[]" }]) {
      const res = await tokenExchange({ subjectToken: await mintICA(handle), extra });
      const body = (await res.json()) as { access_token?: string };
      expect(res.status, JSON.stringify(body)).toBe(200);
      const details = decodeJwt(body.access_token as string).authorization_details as Array<Record<string, unknown>>;
      expect(details).toHaveLength(1);
      expect((details[0]?.constraints as { max_amount: { amount: string } }).max_amount.amount).toBe("500.00");
    }
  });

  it("(h2) authorization_details beyond the Mission's authority, or of an unimplemented type -> invalid_authorization_details, with no hop and no derivation", async () => {
    const { missionId, handle } = newLineage("apev-h2");
    const hops = as.continuationStore.handlesForMission(missionId).length;
    for (const [requested, reason] of [
      [[{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.pay"] }], /exceed/],
      [
        [
          {
            type: "mission_resource_access",
            resource: RESOURCE,
            actions: ["payments:invoice.read"],
            constraints: { max_amount: { amount: "900.00", currency: "USD" }, vendors: ["acme"] },
          },
        ],
        /exceed/,
      ],
      [[{ type: "payment_initiation", instructedAmount: { amount: "1.00", currency: "EUR" } }], /not implemented/],
      [[{ type: "mission_resource_access", resource: RESOURCE }], /actions/],
    ] as const) {
      const res = await tokenExchange({
        subjectToken: await mintICA(handle),
        extra: { authorization_details: JSON.stringify(requested) },
      });
      const body = (await res.json()) as { error?: string; error_description?: string };
      expect(res.status, JSON.stringify(body)).toBe(400);
      expect(body.error).toBe("invalid_authorization_details");
      expect(body.error_description).toMatch(reason);
    }
    expect(as.continuationStore.handlesForMission(missionId)).toHaveLength(hops);
    expect(as.kernel.get(missionId)?.derivation_count).toBe(0);
  });

  it("(h3) malformed or repeated authorization_details -> invalid_request (ICA -02 5.5.3 rule 1)", async () => {
    const { handle } = newLineage("apev-h3");
    for (const value of ["not json", '{"type":"mission_resource_access"}', '["read"]']) {
      const res = await tokenExchange({ subjectToken: await mintICA(handle), extra: { authorization_details: value } });
      const body = (await res.json()) as { error?: string };
      expect(res.status, JSON.stringify(body)).toBe(400);
      expect(body.error).toBe("invalid_request");
    }
    const res = await tokenExchange({
      subjectToken: await mintICA(handle),
      repeated: [
        ["authorization_details", "[]"],
        ["authorization_details", "[]"],
      ],
    });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toMatch(/authorization_details/);
  });

  it("(g) revoking the Mission terminates its handles (onLifecycleCommit fan-out) -> invalid_continuation", async () => {
    const { missionId, handle } = newLineage("apev-g");
    const ica = await mintICA(handle);
    // Revoke BEFORE presentation: the fan-out marks the anchor + handle terminal.
    as.kernel.transition(missionId, "revoke");
    const res = await tokenExchange({ subjectToken: ica });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_continuation");
    // The STORE path (proves the fan-out wiring), distinct from the gate path.
    expect(body.error_description).toMatch(/terminal continuation handle/);
  });
});

type Who = "A" | "B" | "X" | "C";

/** Present a continuation of `handle` as A (ap-agent), B (svc-b), X (svc-x) or C (svc-c). */
async function exchangeAs(handle: string, who: Who, f: Omit<ExchangeFields, "subjectToken"> = {}): Promise<Response> {
  if (who === "A") return tokenExchange({ ...f, subjectToken: await mintICA(handle) });
  const delegates = {
    B: ["svc-b", svcKeys, svcDpopKeys, svcJkt],
    X: ["svc-x", svcXKeys, svcXDpopKeys, svcXJkt],
    C: ["svc-c", svcCKeys, svcCDpopKeys, svcCJkt],
  } as const;
  const [clientId, keys, dpopKeys, jkt] = delegates[who];
  const ica = await mintICA(handle, { act: { iss: ISSUER, sub: clientId }, cnfJkt: jkt });
  return tokenExchange({ ...f, subjectToken: ica }, { issuer: ISSUER, clientKey: keys.privateKey, clientId, dpopKeys });
}

/**
 * @spec id-continuation-assertion — the onward act lineage (ICA -02 5.5.5):
 * derived from the presented hop's ancestry, never from the assertion.
 */
describe("continuation onward act lineage (@spec id-continuation-assertion)", () => {
  const A = { iss: ISSUER, sub: "ap-agent" };
  const B = { iss: ISSUER, sub: "svc-b" };

  /** Continue `handle` as A (ap-agent) or B (svc-b); returns the onward act and the new hop. */
  async function continueAs(handle: string, who: "A" | "B"): Promise<{ act: unknown; hop: string }> {
    const res = await exchangeAs(handle, who);
    const body = (await res.json()) as { access_token?: string };
    expect(res.status, JSON.stringify(body)).toBe(200);
    const claims = decodeJwt(body.access_token as string);
    return { act: claims.act, hop: claims.identity_continuation_handle as string };
  }

  it("places the current actor atop the hop's recorded lineage from the Mission's client, merging consecutive equal actors", async () => {
    const { handle: root } = newLineage("apev-l1");
    const h1 = await continueAs(root, "A");
    expect(h1.act).toEqual(A); // the root's actor is A: one entry
    const h2 = await continueAs(h1.hop, "B");
    expect(h2.act).toEqual({ ...B, act: A });
    const h3 = await continueAs(h2.hop, "B");
    expect(h3.act).toEqual({ ...B, act: A }); // B atop B merges
    const h4 = await continueAs(h3.hop, "A");
    expect(h4.act).toEqual({ ...A, act: { ...B, act: A } });
  });

  it("siblings do not contribute: after B continues the root, A's next continuation from the root is still A alone", async () => {
    const { handle: root } = newLineage("apev-l2");
    expect((await continueAs(root, "B")).act).toEqual({ ...B, act: A });
    expect((await continueAs(root, "A")).act).toEqual(A);
  });
});

/**
 * @spec id-continuation-assertion — the requested resources narrow the grant
 * (ICA -02 5.5.3 rule 7): with one or more `resource`, the grant carries only
 * the entries of those resources; with none, every entry for the audience.
 */
describe("continuation resource narrowing (@spec id-continuation-assertion)", () => {
  const resourcesOf = async (res: Response): Promise<string[]> => {
    const body = (await res.json()) as { access_token?: string };
    expect(res.status, JSON.stringify(body)).toBe(200);
    const details = decodeJwt(body.access_token as string).authorization_details as Array<{ resource: string }>;
    return details.map((d) => d.resource).sort();
  };

  it("on a Mission holding A and C at one Resource AS: resource=A gets only A's entry, A and C get both, and no resource gets both", async () => {
    const { handle } = newLineage("apev-n1", {}, MISSION_EXP, {}, [READ_C]);
    expect(await resourcesOf(await exchangeAs(handle, "A", { resource: RESOURCE }))).toEqual([RESOURCE]);
    expect(await resourcesOf(await exchangeAs(handle, "A", { resource: [RESOURCE, RESOURCE_C] }))).toEqual(
      [RESOURCE, RESOURCE_C].sort(),
    );
    expect(await resourcesOf(await exchangeAs(handle, "A", { resource: null }))).toEqual([RESOURCE, RESOURCE_C].sort());
  });

  it("resource=A with authorization_details naming C -> invalid_authorization_details, with no hop and no derivation", async () => {
    const { missionId, handle } = newLineage("apev-n2", {}, MISSION_EXP, {}, [READ_C]);
    const requestC = JSON.stringify([{ ...READ_C, constraints: { vendors: ["acme"] } }]);
    const hops = as.continuationStore.handlesForMission(missionId).length;
    const res = await exchangeAs(handle, "A", { resource: RESOURCE, extra: { authorization_details: requestC } });
    const body = (await res.json()) as { error?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_authorization_details");
    expect(as.continuationStore.handlesForMission(missionId)).toHaveLength(hops);
    expect(as.kernel.get(missionId)?.derivation_count).toBe(0);
    // Naming C as a resource too, the same detail is issued.
    const both = await exchangeAs(handle, "A", {
      resource: [RESOURCE, RESOURCE_C],
      extra: { authorization_details: requestC },
    });
    expect(await resourcesOf(both)).toEqual([RESOURCE_C]);
  });

  it("composes with delegation: at Mission delegation depth 1, resource naming the surviving entry issues only that entry", async () => {
    const { handle } = newLineage("apev-n3", {}, MISSION_EXP, {}, [READ_C]);
    expect(await resourcesOf(await exchangeAs(handle, "B", { resource: RESOURCE }))).toEqual([RESOURCE]);
  });
});

/**
 * @spec mission#delegation-constraints — per-entry delegation constraints on
 * a continuation to another actor. The Mission delegation depth counts from
 * the approved agent (ap-agent, the root actor): the merged lineage length
 * minus one. Distinct from the ICA actor-lineage depth bound (ICA -02 6.3),
 * which this deployment leaves unset.
 */
describe("continuation delegation constraints (@spec mission#delegation-constraints)", () => {
  type Detail = { resource: string; delegation?: { max_depth: number } };
  const granted = async (res: Response): Promise<{ details: Detail[]; hop: string }> => {
    const body = (await res.json()) as { access_token?: string };
    expect(res.status, JSON.stringify(body)).toBe(200);
    const claims = decodeJwt(body.access_token as string);
    return {
      details: claims.authorization_details as Detail[],
      hop: claims.identity_continuation_handle as string,
    };
  };
  const refused = async (res: Response, error: string): Promise<string | undefined> => {
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe(error);
    return body.error_description;
  };
  const sideEffects = (missionId: string) => ({
    hops: as.continuationStore.handlesForMission(missionId).length,
    derivations: as.kernel.get(missionId)?.derivation_count,
  });

  it("max_depth 1: B continuing its own hop (A->B->B) stays at Mission delegation depth 1 and issues, carrying the entry", async () => {
    const { missionId, handle: root } = newLineage("apev-d6", {}, MISSION_EXP, {}, [], { max_depth: 1 });
    expect(as.kernel.get(missionId)?.authority_set[0]?.delegation?.max_depth).toBe(1);
    const hB = await granted(await exchangeAs(root, "B")); // {B, act: A}: depth 1
    const hBB = await granted(await exchangeAs(hB.hop, "B")); // B atop B merges: still depth 1
    for (const { details } of [hB, hBB]) {
      expect(details.map((d) => d.resource)).toEqual([RESOURCE]);
      expect(details[0]?.delegation?.max_depth).toBe(1);
    }
    // The limit binds: A returning atop B (A->B->A) is depth 2.
    const reason = await refused(await exchangeAs(hB.hop, "A"), "invalid_target");
    expect(reason).toMatch(/Mission delegation depth 2/);
  });

  it("max_depth 1: siblings do not add depth: B and then C each continuing the root (A->B, A->C) issue at Mission delegation depth 1, carrying the entry", async () => {
    const { handle: root } = newLineage("apev-d7", {}, MISSION_EXP, {}, [], { max_depth: 1 });
    const hB = await granted(await exchangeAs(root, "B"));
    const hC = await granted(await exchangeAs(root, "C")); // a sibling of hB: depth 1, not 2
    for (const { details } of [hB, hC]) {
      expect(details.map((d) => d.resource)).toEqual([RESOURCE]);
      expect(details[0]?.delegation?.max_depth).toBe(1);
    }
    // Through hB instead (A->B->C), C is at depth 2 and refused.
    const reason = await refused(await exchangeAs(hB.hop, "C"), "invalid_target");
    expect(reason).toMatch(/Mission delegation depth 2/);
  });

  it("a hop whose recorded parent is gone issues no token: 500 server_error, with no hop and no derivation", async () => {
    const { missionId, handle: root } = newLineage("apev-d8");
    const hB = await granted(await exchangeAs(root, "B"));
    // Break hB's ancestry: its parent, the root hop, is no longer recorded.
    as.continuationStore.db.prepare("DELETE FROM continuation_handles WHERE handle = ?").run(root);
    const before = sideEffects(missionId);
    const res = await exchangeAs(hB.hop, "B");
    const body = (await res.json()) as { access_token?: string; error?: string };
    expect(res.status, JSON.stringify(body)).toBe(500);
    expect(body.error).toBe("server_error");
    expect(body).not.toHaveProperty("access_token");
    expect(sideEffects(missionId)).toEqual(before);
  });

  it("max_depth 2: A->B and A->B->A issue; A->B->A->B (Mission delegation depth 3) is invalid_target, with no hop and no derivation", async () => {
    const { missionId, handle: root } = newLineage("apev-d1");
    // The approved entry inherits the ceiling's delegation policy.
    expect(as.kernel.get(missionId)?.authority_set[0]?.delegation?.max_depth).toBe(2);
    const h1 = await granted(await exchangeAs(root, "A")); // {A}: depth 0
    const h2 = await granted(await exchangeAs(h1.hop, "B")); // {B, act: A}: depth 1
    const h3 = await granted(await exchangeAs(h2.hop, "A")); // {A, act: {B, act: A}}: depth 2
    expect(h3.details.map((d) => d.resource)).toEqual([RESOURCE]);
    const before = sideEffects(missionId);
    const reason = await refused(await exchangeAs(h3.hop, "B"), "invalid_target");
    expect(reason).toMatch(/Mission delegation depth 3/);
    expect(sideEffects(missionId)).toEqual(before);
  });

  it("A->B narrows out a non-delegable entry and keeps the delegable one, its delegation policy intact", async () => {
    const { handle: root } = newLineage("apev-d2", {}, MISSION_EXP, {}, [READ_C]);
    // No `resource`, so only the delegation gate narrows.
    const { details } = await granted(await exchangeAs(root, "B", { resource: null }));
    expect(details.map((d) => d.resource)).toEqual([RESOURCE]);
    expect(details[0]?.delegation?.max_depth).toBe(2);
  });

  it("a same-actor continuation (Mission delegation depth 0) is not narrowed", async () => {
    const { handle: root } = newLineage("apev-d3", {}, MISSION_EXP, {}, [READ_C]);
    // No `resource`, so nothing narrows the grant.
    const h1 = await granted(await exchangeAs(root, "A", { resource: null }));
    const h2 = await granted(await exchangeAs(h1.hop, "A", { resource: null }));
    for (const { details } of [h1, h2]) {
      expect(details.map((d) => d.resource).sort()).toEqual([RESOURCE, RESOURCE_C].sort());
    }
  });

  it("a delegate allowed_delegates does not name narrows the entry out: invalid_target, with no hop and no derivation", async () => {
    const { missionId, handle: root } = newLineage("apev-d4");
    const before = sideEffects(missionId);
    const reason = await refused(await exchangeAs(root, "X"), "invalid_target");
    expect(reason).toMatch(/Mission delegation depth 1/);
    expect(sideEffects(missionId)).toEqual(before);
  });

  it("a narrowed-out entry cannot be requested: by authorization_details (invalid_authorization_details) or by resource (invalid_target), with no hop and no derivation", async () => {
    const { missionId, handle: root } = newLineage("apev-d5", {}, MISSION_EXP, {}, [READ_C]);
    // The approved entry, as derived (it takes the ceiling's vendors constraint).
    const requestC = JSON.stringify([{ ...READ_C, constraints: { vendors: ["acme"] } }]);
    const before = sideEffects(missionId);
    await refused(
      await exchangeAs(root, "B", { resource: null, extra: { authorization_details: requestC } }),
      "invalid_authorization_details",
    );
    await refused(await exchangeAs(root, "B", { resource: RESOURCE_C }), "invalid_target");
    expect(sideEffects(missionId)).toEqual(before);
    // The same requests at depth 0 issue.
    await granted(await exchangeAs(root, "A", { resource: null, extra: { authorization_details: requestC } }));
    await granted(await exchangeAs(root, "A", { resource: RESOURCE_C }));
  });
});

/**
 * @spec id-continuation-assertion — issuer trust is scoped per RAS (ICA -02
 * 5.5.3 rule 3, 7.3): an assertion's issuer must be the referenced hop's
 * accepting RAS, or an issuer trusted to attest that RAS's hops, read against
 * the audience recorded for the hop.
 */
describe("continuation issuer trust per RAS (@spec id-continuation-assertion)", () => {
  const otherCai = (): Signer => ({ iss: CAI_OTHER, kid: "other-cai-key", key: otherCaiKeys.privateKey });
  const rasCai = (): Signer => ({ iss: RAS_AUD, kid: "ras-cai-key", key: rasCaiKeys.privateKey });

  it("an issuer trusted only for another RAS cannot attest this hop: invalid_request, with no hop recorded and no derivation counted", async () => {
    const { missionId, handle } = newLineage("apev-i1");
    const hops = as.continuationStore.handlesForMission(missionId).length;
    const res = await tokenExchange({ subjectToken: await mintICA(handle, { signer: otherCai() }) });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toMatch(/not trusted for this hop's RAS/);
    expect(as.continuationStore.handlesForMission(missionId)).toHaveLength(hops);
    expect(as.kernel.get(missionId)?.derivation_count).toBe(0);
  });

  it("the same issuer attests a hop whose recorded RAS it is trusted for", async () => {
    const { missionId, handle } = newLineage("apev-i2");
    const anchorId = as.continuationStore.resolve(handle)?.anchor.anchorId as string;
    const otherHop = as.continuationStore.mint({
      anchorId,
      missionId,
      actor: { iss: ISSUER, sub: "ap-agent" },
      priorHandle: handle,
      audience: OTHER_RAS,
    });
    const res = await tokenExchange({ subjectToken: await mintICA(otherHop, { signer: otherCai() }) });
    expect(res.status, await res.clone().text()).toBe(200);
  });

  it("the accepting RAS attests its own hop without being listed, and no other RAS's hop", async () => {
    const { handle } = newLineage("apev-i3");
    // A first continuation to RAS_AUD records a child hop whose audience is RAS_AUD.
    const first = await tokenExchange({ subjectToken: await mintICA(handle) });
    const firstBody = (await first.json()) as { access_token?: string };
    expect(first.status, JSON.stringify(firstBody)).toBe(200);
    const childHop = decodeJwt(firstBody.access_token as string).identity_continuation_handle as string;
    const own = await tokenExchange({ subjectToken: await mintICA(childHop, { signer: rasCai() }) });
    expect(own.status, await own.clone().text()).toBe(200);
    // The root hop's RAS is this AS, so RAS_AUD cannot attest it.
    const root = await tokenExchange({ subjectToken: await mintICA(handle, { signer: rasCai() }) });
    const rootBody = (await root.json()) as { error?: string; error_description?: string };
    expect(root.status, JSON.stringify(rootBody)).toBe(400);
    expect(rootBody.error).toBe("invalid_request");
    expect(rootBody.error_description).toMatch(/not trusted for this hop's RAS/);
  });
});

/**
 * @spec id-continuation-assertion — the default trust configuration: with no
 * issuers injected, the AS trusts itself only under its continuation-purpose
 * as-continuation key, not every key on its jwks_uri (ICA -02 7.3).
 */
describe("continuation default issuer trust (@spec id-continuation-assertion)", () => {
  const PORT3 = 14478;
  const ISSUER3 = `http://localhost:${PORT3}`;
  let as3: BuiltAs;
  let server3: Server;
  let target3: Target;
  let tokenKey: CryptoKey;

  beforeAll(async () => {
    const { alg } = TOPOLOGY.keys.asToken;
    const tokenKeys = await generateKeyPair(alg, { extractable: true });
    tokenKey = tokenKeys.privateKey;
    as3 = await buildAuthorizationServer({
      issuer: ISSUER3,
      allowHeadlessAdjudication: true,
      // A test-held AS token key, so the test can sign with a key on jwks_uri.
      testTokenSigningJwk: await exportJWK(tokenKeys.privateKey),
      resourceToAs: (r: string) => (r === RESOURCE ? RAS_AUD : ISSUER3),
    });
    server3 = as3.provider.listen(PORT3);
    target3 = { issuer: ISSUER3, clientKey: (await importJWK(as3.agentClientJwk as never, "ES256")) as CryptoKey };
  });

  afterAll(() => {
    server3?.close();
  });

  it("an ICA signed by the AS token key is refused: the default trusts only the as-continuation key", async () => {
    const { handle } = approveLineage("apev-default-trust", as3);
    const signer: Signer = { iss: ISSUER3, kid: TOPOLOGY.keys.asToken.kid, key: tokenKey, alg: TOPOLOGY.keys.asToken.alg };
    const res = await tokenExchange(
      { subjectToken: await mintICA(handle, { signer, aud: ISSUER3, act: { iss: ISSUER3, sub: "ap-agent" } }) },
      target3,
    );
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toMatch(/verification failed/);
  });
});

/**
 * @spec id-continuation-assertion — error precedence (ICA -02 5.5.6): when
 * several rules fail, the code of the earliest. Each case pairs two failures
 * whose codes differ, so the response shows which rule ran first.
 */
describe("continuation error precedence (@spec id-continuation-assertion)", () => {
  /** Undo the store's terminal fan-out, so only the (terminal) Mission ends the chain. */
  const reopenStore = (missionId: string): void => {
    as.continuationStore.db.prepare("UPDATE continuation_anchors SET state = 'active' WHERE mission_id = ?").run(missionId);
    as.continuationStore.db.prepare("UPDATE continuation_handles SET state = 'active' WHERE mission_id = ?").run(missionId);
  };
  const errorOf = async (res: Response): Promise<string | undefined> => {
    const body = (await res.json()) as { error?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    return body.error;
  };

  it("issuer trust for the hop's RAS precedes key proof and chain state: an issuer not trusted for a terminal hop's RAS is invalid_request", async () => {
    const { missionId, handle } = newLineage("apev-p0");
    as.kernel.transition(missionId, "revoke");
    const foreign = await mintICA(handle, { signer: { iss: CAI_OTHER, kid: "other-cai-key", key: otherCaiKeys.privateKey } });
    expect(await errorOf(await tokenExchange({ subjectToken: foreign }))).toBe("invalid_request");
    expect(await errorOf(await tokenExchange({ subjectToken: foreign, noDpop: true }))).toBe("invalid_request");
    // The trusted issuer reaches the chain-state code.
    expect(await errorOf(await tokenExchange({ subjectToken: await mintICA(handle) }))).toBe("invalid_continuation");
  });

  it("a malformed assertion precedes a missing DPoP proof and a requested scope: invalid_request", async () => {
    const { handle } = newLineage("apev-p1");
    const malformed = await mintICA(handle, { over: { sub: "alice" } }); // a forbidden claim
    expect(await errorOf(await tokenExchange({ subjectToken: malformed, noDpop: true }))).toBe("invalid_request");
    expect(await errorOf(await tokenExchange({ subjectToken: malformed, extra: { scope: "payments.read" } }))).toBe(
      "invalid_request",
    );
  });

  it("no chain-state code before the key proof and the actor match: a terminal hop with no DPoP proof is invalid_dpop_proof, with a foreign act invalid_request", async () => {
    const { missionId, handle } = newLineage("apev-p2");
    as.kernel.transition(missionId, "revoke");
    expect(await errorOf(await tokenExchange({ subjectToken: await mintICA(handle), noDpop: true }))).toBe(
      "invalid_dpop_proof",
    );
    const foreign = await mintICA(handle, { act: { iss: ISSUER, sub: "ap-agent-imposter" } });
    expect(await errorOf(await tokenExchange({ subjectToken: foreign }))).toBe("invalid_request");
    // Both failures cleared: the chain-state code itself.
    expect(await errorOf(await tokenExchange({ subjectToken: await mintICA(handle) }))).toBe("invalid_continuation");
  });

  it("a permanently unusable hop precedes a limit: a terminal Mission with its derivation cap spent is invalid_continuation", async () => {
    const { missionId, handle } = newLineage("apev-p3", {}, MISSION_EXP, { requested_derivation_limit: 1 });
    const first = await tokenExchange({ subjectToken: await mintICA(handle) });
    expect(first.status, await first.clone().text()).toBe(200);
    as.kernel.transition(missionId, "revoke");
    reopenStore(missionId);
    expect(await errorOf(await tokenExchange({ subjectToken: await mintICA(handle) }))).toBe("invalid_continuation");
  });

  it("chain state precedes replay: a consumed assertion over a terminal hop is invalid_continuation", async () => {
    const { missionId, handle } = newLineage("apev-p4");
    const ica = await mintICA(handle);
    const first = await tokenExchange({ subjectToken: ica });
    expect(first.status, await first.clone().text()).toBe(200);
    as.kernel.transition(missionId, "revoke");
    expect(await errorOf(await tokenExchange({ subjectToken: ica }))).toBe("invalid_continuation");
  });

  it("a limit precedes target and scope: a spent derivation cap is invalid_grant over an unserved resource or a requested scope", async () => {
    const { handle } = newLineage("apev-p5", {}, MISSION_EXP, { requested_derivation_limit: 1 });
    const first = await tokenExchange({ subjectToken: await mintICA(handle) });
    expect(first.status, await first.clone().text()).toBe(200);
    const unserved = await tokenExchange({ subjectToken: await mintICA(handle), resource: "https://elsewhere.test/api" });
    expect(await errorOf(unserved)).toBe("invalid_grant");
    const scoped = await tokenExchange({ subjectToken: await mintICA(handle), extra: { scope: "payments.read" } });
    expect(await errorOf(scoped)).toBe("invalid_grant");
  });

  it("chain state precedes freshness: an expired assertion over a terminal hop is invalid_continuation", async () => {
    const { missionId, handle } = newLineage("apev-p8");
    const now = Math.floor(Date.now() / 1000);
    const expired = await mintICA(handle, { iatSec: now - 200, expSec: now - 100 });
    // On a live chain the same assertion fails freshness.
    expect(await errorOf(await tokenExchange({ subjectToken: expired }))).toBe("invalid_request");
    as.kernel.transition(missionId, "revoke");
    expect(await errorOf(await tokenExchange({ subjectToken: expired }))).toBe("invalid_continuation");
  });

  it("a limit precedes freshness: an assertion past the lifetime cap over a spent derivation cap is invalid_grant", async () => {
    const { handle } = newLineage("apev-p9", {}, MISSION_EXP, { requested_derivation_limit: 1 });
    const first = await tokenExchange({ subjectToken: await mintICA(handle) });
    expect(first.status, await first.clone().text()).toBe(200);
    const now = Math.floor(Date.now() / 1000);
    const tooLong = await mintICA(handle, { iatSec: now, expSec: now + 301 });
    expect(await errorOf(await tokenExchange({ subjectToken: tooLong }))).toBe("invalid_grant");
  });

  it("freshness precedes authorization: an expired assertion over a suspended Mission is invalid_request", async () => {
    const { missionId, handle } = newLineage("apev-p10");
    as.kernel.transition(missionId, "suspend");
    const now = Math.floor(Date.now() / 1000);
    const expired = await mintICA(handle, { iatSec: now - 200, expSec: now - 100 });
    expect(await errorOf(await tokenExchange({ subjectToken: expired }))).toBe("invalid_request");
  });

  it("a limit precedes authorization_details: an excess authorization detail over a spent derivation cap is invalid_grant", async () => {
    const { handle } = newLineage("apev-p11", {}, MISSION_EXP, { requested_derivation_limit: 1 });
    const first = await tokenExchange({ subjectToken: await mintICA(handle) });
    expect(first.status, await first.clone().text()).toBe(200);
    const excess = JSON.stringify([{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.pay"] }]);
    const res = await tokenExchange({ subjectToken: await mintICA(handle), extra: { authorization_details: excess } });
    expect(await errorOf(res)).toBe("invalid_grant");
  });

  it("replay precedes authorization: a consumed assertion over a suspended Mission is invalid_request", async () => {
    const { missionId, handle } = newLineage("apev-p6");
    const ica = await mintICA(handle);
    const first = await tokenExchange({ subjectToken: ica });
    expect(first.status, await first.clone().text()).toBe(200);
    as.kernel.transition(missionId, "suspend");
    expect(await errorOf(await tokenExchange({ subjectToken: ica }))).toBe("invalid_request");
    // A fresh assertion reaches the authorization rule.
    expect(await errorOf(await tokenExchange({ subjectToken: await mintICA(handle) }))).toBe("unauthorized_client");
  });

  it("an audience the Mission holds no authority for is invalid_target before the gate counts a derivation", async () => {
    const { missionId, handle } = newLineage("apev-p7");
    // The AS itself serves this resource, but every Mission entry maps to RAS_AUD.
    const res = await tokenExchange({
      subjectToken: await mintICA(handle),
      audience: ISSUER,
      resource: "https://elsewhere.test/api",
    });
    expect(await errorOf(res)).toBe("invalid_target");
    expect(as.kernel.get(missionId)?.derivation_count).toBe(0);
  });
});

/**
 * @spec id-continuation-assertion — end-to-end LIFECYCLE invariants over the
 * approval-time-rooted continuation root. These prove the durable grant-anchored
 * root is real (rooted when a Mission is approved, not test-only), that revocation
 * blocks NEW continuations without shortening ALREADY-ISSUED tokens, and that a
 * session-anchored root terminates on session end while a grant anchor survives.
 */
describe("continuation lifecycle invariants (@spec id-continuation-assertion)", () => {
  it("approval-time rooting: an approved Mission's AUTO-rooted initial handle mints a continuation ID-JAG, carrying auth_time but no acr (@spec mission#approval-authentication)", async () => {
    // @spec mission#approval-authentication — achieved approval authentication
    // context (acr/amr) is approval-time PROVENANCE, never a Mission Intent
    // member and never synthesized onto a derived credential; only auth_time
    // (the approval instant itself, not a claim about authentication
    // strength) is auto-rooted here. This replaces the pre-#636 assertion
    // that `intent.controls.acr` flowed through to this envelope: that
    // Intent member is retired with no replacement, and rootMissionContinuation
    // (src/services/authorization-server/src/index.ts) sources no acr/amr.
    const approxNow = Math.floor(Date.now() / 1000);
    const { missionId, handle } = approveLineage("apev-life-root");

    // The assembly rooted exactly one grant anchor + initial handle at approval;
    // no manual rootGrantAnchor/mint ran. The envelope is the approval event.
    expect(as.continuationStore.handlesForMission(missionId)).toHaveLength(1);
    const resolved = as.continuationStore.resolve(handle);
    expect(resolved?.missionId).toBe(missionId);
    expect(resolved?.anchor.anchorType).toBe("grant");
    // No root ID-JAG carries this hop: its recorded RAS audience is the AS.
    expect(resolved?.audience).toBe(ISSUER);
    expect(resolved?.authEnvelope.acr).toBeUndefined();
    expect(resolved?.authEnvelope.authTime).toBeGreaterThanOrEqual(approxNow - 5);
    expect(resolved?.authEnvelope.authTime).toBeLessThanOrEqual(approxNow + 5);

    // The auto-rooted handle drives a full /token continuation hop end to end.
    const res = await tokenExchange({ subjectToken: await mintICA(handle) });
    const body = (await res.json()) as { access_token?: string; error?: string };
    expect(res.status, JSON.stringify(body)).toBe(200);
    const { payload } = await jwtVerify(body.access_token as string, remoteJwks, {
      issuer: ISSUER,
      audience: RAS_AUD,
    });
    expect((payload.mission as { id?: string }).id).toBe(missionId);
    // The approval-time envelope reaches the issued ID-JAG: auth_time yes, acr no.
    expect(payload.acr).toBeUndefined();
    expect(payload.auth_time as number).toBeGreaterThanOrEqual(approxNow - 5);
  });

  it("revocation blocks NEW continuations: revoke the Mission -> the auto-rooted handle at /token -> invalid_continuation", async () => {
    const { missionId, handle } = approveLineage("apev-life-revoke");
    const ica = await mintICA(handle);
    // The lifecycle transition; the onLifecycleCommit fan-out marks the anchor +
    // handle terminal (the same wiring PR-C tested at the store level).
    as.kernel.transition(missionId, "revoke");
    const res = await tokenExchange({ subjectToken: ica });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_continuation");
    expect(body.error_description).toMatch(/terminal continuation handle/);
  });

  it("already-issued keeps its exp: an ID-JAG minted BEFORE revoke still verifies + redeems with its ORIGINAL exp; only NEW continuations are refused after", async () => {
    const { missionId, handle } = approveLineage("apev-life-keepexp");

    // Issue a continuation ID-JAG while the Mission is active.
    const res1 = await tokenExchange({ subjectToken: await mintICA(handle) });
    const body1 = (await res1.json()) as { access_token?: string; error?: string };
    expect(res1.status, JSON.stringify(body1)).toBe(200);
    const idJag = body1.access_token as string;
    const issuedExp = decodeJwt(idJag).exp as number;
    expect(issuedExp).toBeGreaterThan(Math.floor(Date.now() / 1000));

    // Revoke the Mission.
    as.kernel.transition(missionId, "revoke");

    // (1) The already-issued ID-JAG STILL verifies against the AS jwks and carries
    //     its ORIGINAL exp — revocation did not retroactively shorten it.
    const { payload } = await jwtVerify(idJag, remoteJwks, { issuer: ISSUER, audience: RAS_AUD });
    expect(payload.exp).toBe(issuedExp);

    // (1b) It still REDEEMS at a RAS (which consults the AS signing key, not the
    //      continuation store) — the strongest form of "the issued token is
    //      untouched by revocation". This ID-JAG has never been redeemed, so the
    //      RAS one-time-jti check is satisfied.
    const serverJwks = (await (await fetch(`${ISSUER}/jwks`)).json()) as { keys: Record<string, unknown>[] };
    const asContinuationPub = serverJwks.keys.find((k) => k.kid === "as-continuation");
    const rasKeys = await generateKeyPair("ES256", { extractable: true });
    const ras = new ResourceAuthorizationServer({
      localCeiling: DERIVATION_POLICY.ceiling,
      localPolicyVersion: DERIVATION_POLICY.policy_version,
      issuer: RAS_AUD,
      trustedIssuers: { [ISSUER]: { keys: [asContinuationPub as never] } },
      signKey: rasKeys.privateKey,
      signKid: "ras-token",
      registeredClients: { [agentJkt]: TOPOLOGY.rasLocalClientId },
      mapping: NO_MAPPING,
      entitlement: ALWAYS_ENTITLED,
      entitlementStalenessBoundSeconds: ENTITLEMENT_BOUND_S,
    });
    const { expires_in } = await ras.redeem(idJag, agentJkt);
    expect(expires_in).toBeGreaterThan(0);

    // (2) A NEW continuation over the same lineage IS refused after revoke —
    //     revocation is live; it only blocks fresh issuance.
    const res2 = await tokenExchange({ subjectToken: await mintICA(handle) });
    const body2 = (await res2.json()) as { error?: string; error_description?: string };
    expect(res2.status, JSON.stringify(body2)).toBe(400);
    expect(body2.error).toBe("invalid_continuation");
  });

  it("session anchoring: terminateSession stops a session-anchored handle; the Mission's grant anchor is unaffected", () => {
    const { missionId } = approveLineage("apev-life-session");

    // The auto-rooted GRANT handle, captured BEFORE minting the session handle (a
    // bare SELECT does not guarantee ordering once a second handle exists).
    const grantHandle = as.continuationStore.handlesForMission(missionId)[0] as string;
    expect(as.continuationStore.resolve(grantHandle)?.anchor.anchorType).toBe("grant");

    // A session-anchored root + handle for the SAME Mission (the repo has no real
    // OIDC session, so this represents one: a terminable anchor).
    const sessionId = "sess-life-1";
    const sessionAnchor = as.continuationStore.rootSessionAnchor({
      missionId,
      sessionId,
      authEnvelope: {},
    });
    const sessionHandle = as.continuationStore.mint({
      anchorId: sessionAnchor,
      missionId,
      actor: { iss: ISSUER, sub: "ap-agent" },
      cnfJkt: agentJkt,
      audience: ISSUER,
    });
    expect(as.continuationStore.resolve(sessionHandle)?.anchor.anchorType).toBe("session");

    // Ending the session terminates the session-anchored handle; the grant handle
    // (durable root) keeps resolving.
    as.continuationStore.terminateSession(sessionId);
    expect(as.continuationStore.resolve(sessionHandle)).toBeUndefined();
    expect(as.continuationStore.resolve(grantHandle)?.missionId).toBe(missionId);
  });

  it("idempotent approval does not double-root: the same approval_event_id yields exactly one anchor/handle", () => {
    const first = approveLineage("apev-life-idem");
    // Re-approving with the SAME event id is idempotent in the kernel (a duplicate
    // approval_event_id throws before emitCommit), so no second commit fires and
    // no second anchor/handle is rooted. The guard in rootMissionContinuation is
    // belt-and-suspenders for this.
    const second = approveLineage("apev-life-idem");
    expect(second.missionId).toBe(first.missionId);
    expect(as.continuationStore.handlesForMission(first.missionId)).toHaveLength(1);
  });
});

describe("a continuation ID-JAG that fails after admission (@spec mission#issuance-gating, #914 ruling 1)", () => {
  it("residual: a continuation grant that fails after admission leaves the derivation counted under an unreleased reservation, until an authoritative non-acceptance returns it", async () => {
    // At the token endpoint the deterministic refusals run before admission:
    // the audience-scoped authority check counts nothing ((b2), (f5)). A grant
    // still fails after the gate admits when a state change since that check
    // narrows its authority to nothing, so drive that failure directly with a
    // filter that empties the admitted set.
    const { missionId } = newLineage("apev-after-admission");
    const count = () => as.kernel.get(missionId)?.derivation_count;
    const before = count();
    const { privateKey } = await generateKeyPair("ES256");

    await expect(
      issueCrossDomainGrant(as.kernel, privateKey, "test-kid", {
        missionId,
        targetAs: RAS_AUD,
        clientId: "ap-agent",
        cnfJkt: agentJkt,
        resourceToAs: (r: string) => (r === RESOURCE ? RAS_AUD : ISSUER),
        authorityFilter: () => [],
      }),
    ).rejects.toBeInstanceOf(AuthorityNarrowedToEmptyError);

    // The failed derivation IS counted: its reservation is reserved and never
    // released, keyed by a grant identity nobody will retry.
    expect(count()).toBe((before ?? 0) + 1);
    const rows = as.kernel.db
      .prepare("SELECT reservation_id, state FROM derivation_reservations WHERE mission_id = ?")
      .all(missionId) as Array<{ reservation_id: string; state: string }>;
    expect(rows).toHaveLength(1);
    expect(rows[0]?.state).toBe("reserved");

    // Only an authoritative observation that no artifact was accepted returns it.
    expect(
      as.kernel.reconcileDerivation(rows[0]?.reservation_id as string, {
        accepted: false,
        authority: "svc:test-issuance-log",
      }),
    ).toBe(true);
    expect(count()).toBe(before);
  });
});

/**
 * @spec id-continuation-assertion — the finite per-chain hop-count limit (ICA
 * -02 6.3), on a second AS built with a limit of 2: the auto-rooted hop plus
 * one continuation fill the chain.
 */
describe("continuation hop-count limit (@spec id-continuation-assertion)", () => {
  const PORT2 = 14476;
  const ISSUER2 = `http://localhost:${PORT2}`;
  const ACT2 = { iss: ISSUER2, sub: "ap-agent" };
  let as2: BuiltAs;
  let server2: Server;
  let target2: Target;

  beforeAll(async () => {
    const caiPub = { ...(await exportJWK(caiKeys.publicKey)), kid: "cai-key", alg: "ES256", use: "sig" };
    as2 = await buildAuthorizationServer({
      issuer: ISSUER2,
      allowHeadlessAdjudication: true,
      continuationAssertionIssuers: [{ iss: CAI, jwks: { keys: [caiPub] }, attestsFor: [ISSUER2, RAS_AUD] }],
      resourceToAs: (r: string) => (r === RESOURCE ? RAS_AUD : ISSUER2),
      continuationHopLimit: 2,
    });
    server2 = as2.provider.listen(PORT2);
    target2 = { issuer: ISSUER2, clientKey: (await importJWK(as2.agentClientJwk as never, "ES256")) as CryptoKey };
  });

  afterAll(() => {
    server2?.close();
  });

  it("refuses a continuation past the chain's limit with invalid_grant, recording no hop and counting no derivation; another chain of the same Mission is unaffected", async () => {
    const { missionId, handle } = approveLineage("apev-hop-limit", as2);
    const first = await tokenExchange({ subjectToken: await mintICA(handle, { aud: ISSUER2, act: ACT2 }) }, target2);
    expect(first.status, await first.clone().text()).toBe(200);

    const handlesBefore = as2.continuationStore.handlesForMission(missionId).length;
    const countBefore = as2.kernel.get(missionId)?.derivation_count;
    const refused = await tokenExchange({ subjectToken: await mintICA(handle, { aud: ISSUER2, act: ACT2 }) }, target2);
    const body = (await refused.json()) as { error?: string; error_description?: string };
    expect(refused.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_grant");
    expect(body.error_description).toMatch(/hop-count limit/);
    expect(as2.continuationStore.handlesForMission(missionId)).toHaveLength(handlesBefore);
    expect(as2.kernel.get(missionId)?.derivation_count).toBe(countBefore);

    // The limit is per chain: a second anchor of the same Mission continues.
    const anchorId = as2.continuationStore.rootGrantAnchor({ missionId, authEnvelope: {} });
    const other = as2.continuationStore.mint({ anchorId, missionId, actor: ACT2, audience: ISSUER2 });
    const ok = await tokenExchange({ subjectToken: await mintICA(other, { aud: ISSUER2, act: ACT2 }) }, target2);
    expect(ok.status, await ok.clone().text()).toBe(200);
  });

  it("the build refuses an unbounded or non-positive hop-count limit", async () => {
    for (const continuationHopLimit of [Number.POSITIVE_INFINITY, 0, 1.5]) {
      await expect(
        buildAuthorizationServer({ issuer: "http://localhost:14479", continuationHopLimit }),
      ).rejects.toThrow(/continuationHopLimit/);
    }
  });
});
