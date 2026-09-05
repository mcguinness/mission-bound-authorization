/**
 * @spec draft-mcguinness-oauth-id-continuation-assertion-00 (RFC 8693 token
 * exchange -> continuation ID-JAG)
 *
 * The end-to-end intra-domain continuation hop on the real /token endpoint: an
 * ICA subject token in, a Mission-rooted continuation ID-JAG out, with the full
 * FOUR-SIGNAL actor agreement and the RFC 8693 error taxonomy.
 *
 * Signals, all of which MUST name the SAME actor (raw ===, case-sensitive) and
 * be bound to the SAME confirmed DPoP key:
 *   1. client auth  — the private_key_jwt presenter (iss = AS, sub = client_id).
 *   2. actor_token  — signed by the DPoP key, cnf.jkt = the presenter jkt.
 *   3. ICA `act`    — minted by the Chain Authority against (AS, client_id).
 *   4. DPoP proof   — the presenter key.
 *
 * The ID-JAG is signed with the dedicated ES256 as-continuation key (published on
 * jwks_uri and trusted by the RAS) because issueCrossDomainGrant hardcodes an
 * ES256 header and the AS token key is RS256; the test verifies it against the AS
 * jwks_uri (asserting the as-continuation kid) AND redeems it end-to-end at a RAS.
 * gateDerivation runs exactly once (inside issueCrossDomainGrant, via a direct
 * SignJWT — never provider.AccessToken).
 *
 * Setup drives the store directly (rootGrantAnchor + mint) and mints ICAs with a
 * dedicated Chain Authority key injected via chainAuthorityIssuers.
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
  buildAuthorizationServer,
  type BuiltAs,
  ID_JAG_TOKEN_TYPE,
  IDENTITY_CONTINUATION_JWT_TYP,
  IDENTITY_CONTINUATION_TOKEN_TYPE,
  validateMissionIntent,
} from "../src/index.js";

const PORT = 14475;
const ISSUER = `http://localhost:${PORT}`;
const CA = "https://chain-authority.example"; // the injected Chain Authority
const RESOURCE = CANONICAL_RESOURCE; // in DERIVATION_POLICY's ceiling
const RAS_AUD = "https://ras.ledgercloud.test"; // the target Resource AS (audience)
const MISSION_EXP = "2027-01-01T00:00:00Z";
const ACTOR_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";
const RESOURCE_TO_AS = (r: string) => (r === RESOURCE ? RAS_AUD : ISSUER);

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
let caKeys: Keys; // Chain Authority ICA signing key
let agentKeys: Keys; // the agent's DPoP + actor-token key
let agentJkt: string;
let remoteJwks: ReturnType<typeof createRemoteJWKSet>;

/** A continuation lineage: an active Mission + a grant anchor + an initial handle. */
function newLineage(eventId: string, envelope: { authTime?: number; acr?: string; amr?: string[] } = {}): {
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
  const mission = as.kernel.approve({
    intent,
    proposedAuthority: [
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: ["payments:invoice.read"],
        constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
      },
    ],
    subject: { iss: ISSUER, sub: "alice" }, // the GLOBAL subject
    approver: { iss: ISSUER, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: eventId,
    capabilityResolution: [{ resource: RESOURCE, action: "payments:invoice.read", binding: {
      action: "payments:invoice.read", tool_id: "mcp://payments.test/tools/get_invoice",
      source_uri: "https://payments.test/.well-known/mcp", operation_ref: "get_invoice",
      source_digest: "sha-256:" + Buffer.alloc(32).toString("base64url"),
    } }],
  });
  const anchorId = as.continuationStore.rootGrantAnchor({ missionId: mission.id, authEnvelope: envelope });
  const handle = as.continuationStore.mint({
    anchorId,
    missionId: mission.id,
    actor: { iss: ISSUER, sub: "ap-agent" },
    cnfJkt: agentJkt,
  });
  return { missionId: mission.id, handle };
}

/**
 * Approve a Mission WITHOUT manually rooting a continuation: the AS assembly roots
 * the durable grant anchor + INITIAL handle at approval (see index.ts
 * rootMissionContinuation). Returns the mission id and that AUTO-rooted handle, so
 * the lifecycle tests prove approval-time rooting rather than test-only rooting.
 */
function approveLineage(eventId: string): {
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
  const mission = as.kernel.approve({
    intent,
    proposedAuthority: [
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: ["payments:invoice.read"],
        constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
      },
    ],
    subject: { iss: ISSUER, sub: "alice" },
    approver: { iss: ISSUER, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: eventId,
  });
  const handles = as.continuationStore.handlesForMission(mission.id);
  return { missionId: mission.id, handle: handles[0] as string };
}

interface IcaOpts {
  handle?: string;
  cnfJkt?: string;
  act?: { iss: string; sub: string };
  iatSec?: number;
  expSec?: number;
  over?: Record<string, unknown>;
}

/** Mint an ICA signed by the Chain Authority key (iss=CA, aud=AS issuer). */
async function mintICA(handle: string, opts: IcaOpts = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const base: Record<string, unknown> = {
    identity_continuation_handle: opts.handle ?? handle,
    cnf: { jkt: opts.cnfJkt ?? agentJkt },
    act: opts.act ?? { iss: ISSUER, sub: "ap-agent" },
    ...opts.over,
  };
  return new SignJWT(base)
    .setProtectedHeader({ alg: "ES256", kid: "ca-key", typ: IDENTITY_CONTINUATION_JWT_TYP })
    .setIssuer(CA)
    .setAudience(ISSUER)
    .setIssuedAt(opts.iatSec ?? now)
    .setExpirationTime(opts.expSec ?? now + 120)
    .setJti(crypto.randomUUID())
    .sign(caKeys.privateKey);
}

/** actor_token (Signal #2): signed by the DPoP key, cnf.jkt = the presenter jkt. */
async function mintActorToken(over: Record<string, unknown> = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ iss: ISSUER, sub: "ap-agent", cnf: { jkt: agentJkt }, ...over })
    .setProtectedHeader({ alg: "ES256" })
    .setIssuedAt(now)
    .setExpirationTime(now + 120)
    .setJti(crypto.randomUUID())
    .sign(agentKeys.privateKey);
}

async function clientAssertion(): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
    .setIssuer("ap-agent")
    .setSubject("ap-agent")
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(clientKey);
}

async function dpopProof(htu: string, htm: string, extra: Record<string, unknown> = {}): Promise<string> {
  return new SignJWT({ htu, htm, ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(agentKeys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(agentKeys.privateKey);
}

interface ExchangeFields {
  subjectToken: string;
  actorToken?: string;
  audience?: string;
  resource?: string;
  requestedTokenType?: string;
  subjectTokenType?: string;
}

/** POST /token with the token-exchange grant + private_key_jwt + DPoP (nonce retry). */
async function tokenExchange(f: ExchangeFields): Promise<Response> {
  const htu = `${ISSUER}/token`;
  const params: Record<string, string> = {
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    requested_token_type: f.requestedTokenType ?? ID_JAG_TOKEN_TYPE,
    subject_token: f.subjectToken,
    subject_token_type: f.subjectTokenType ?? IDENTITY_CONTINUATION_TOKEN_TYPE,
    audience: f.audience ?? RAS_AUD,
    resource: f.resource ?? RESOURCE,
    actor_token_type: ACTOR_TOKEN_TYPE,
  };
  if (f.actorToken !== undefined) params.actor_token = f.actorToken;
  const send = async (extra: Record<string, unknown> = {}): Promise<Response> =>
    fetch(htu, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(htu, "POST", extra) },
      body: new URLSearchParams({
        ...params,
        client_assertion: await clientAssertion(),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return res;
}

beforeAll(async () => {
  caKeys = await generateKeyPair("ES256", { extractable: true });
  const caPub = { ...(await exportJWK(caKeys.publicKey)), kid: "ca-key", alg: "ES256", use: "sig" };
  agentKeys = await generateKeyPair("ES256", { extractable: true });
  agentJkt = await calculateJwkThumbprint(await exportJWK(agentKeys.publicKey));

  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    chainAuthorityIssuers: [{ iss: CA, jwks: { keys: [caPub] } }],
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
  it("happy path: mints a Mission-rooted ID-JAG with a fresh handle, deterministic sub, collapsed act, and carried envelope", async () => {
    const { missionId, handle } = newLineage("apev-happy", {
      authTime: 1_700_000_000,
      acr: "urn:mace:acr:mfa",
      amr: ["pwd", "otp"],
    });

    const res = await tokenExchange({ subjectToken: await mintICA(handle), actorToken: await mintActorToken() });
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

    // Collapsed act: a single actor's continuation keeps a depth-1 lineage (no
    // nested `act`). NB: on this path the four-signal check forces the ICA actor
    // to equal the current actor, so this ALWAYS collapses (never extends).
    expect(payload.act).toEqual({ iss: ISSUER, sub: "ap-agent" });
    expect(payload.act).not.toHaveProperty("act");

    // Root auth envelope carried unchanged.
    expect(payload.auth_time).toBe(1_700_000_000);
    expect(payload.acr).toBe("urn:mace:acr:mfa");
    expect(payload.amr).toEqual(["pwd", "otp"]);

    // A second, DIFFERENT ICA (fresh jti) over the same lineage yields the SAME
    // deterministic sub for the same (audience, subject).
    const res2 = await tokenExchange({ subjectToken: await mintICA(handle), actorToken: await mintActorToken() });
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
    const res = await tokenExchange({ subjectToken: await mintICA(handle), actorToken: await mintActorToken() });
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

    // @spec txn-authorization#challenge-redemption — this AS is built WITHOUT
    // transaction authorization, so it does not advertise an endpoint that
    // would answer 501.
    expect(meta.transaction_authorization_endpoint).toBeUndefined();

    // (5) RAS metadata advertises both id-jag grant profiles.
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
    expect(profiles).toContain("urn:ietf:params:oauth:grant-profile:id-jag");
    expect(profiles).toContain("urn:ietf:params:oauth:grant-profile:id-jag-continuation");
  });

  it("(a) ICA lifetime exp-iat > 300s -> invalid_request", async () => {
    const { handle } = newLineage("apev-a");
    const now = Math.floor(Date.now() / 1000);
    const res = await tokenExchange({
      subjectToken: await mintICA(handle, { iatSec: now, expSec: now + 301 }),
      actorToken: await mintActorToken(),
    });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toMatch(/lifetime/);
  });

  it("(b0) consumption is atomic with issuance (#617 review 1): a redemption refused at the Mission gate leaves the ICA UNCONSUMED; the SAME assertion redeems once the gate reopens", async () => {
    const { missionId, handle } = newLineage("apev-b0");
    const ica = await mintICA(handle);

    // Suspend: reversible, and NOT terminal, so the handle lineage stays
    // resolvable (step 5 passes) and the refusal comes from the Mission gate
    // inside issueCrossDomainGrant (step 9), i.e. AFTER validation.
    as.kernel.transition(missionId, "suspend");
    const refused = await tokenExchange({ subjectToken: ica, actorToken: await mintActorToken() });
    const refusedBody = (await refused.json()) as { error?: string; error_description?: string };
    expect(refused.status, JSON.stringify(refusedBody)).toBe(400);
    expect(refusedBody.error).toBe("invalid_continuation");
    expect(refusedBody.error_description).toMatch(/gate refused issuance/);

    // Nothing was issued, so nothing was consumed: the assertion is still
    // single-use-unspent. (Recording at validation, the prior behavior, burned
    // it here and made this retry fail /replay/ forever.)
    as.kernel.transition(missionId, "resume");
    const ok = await tokenExchange({ subjectToken: ica, actorToken: await mintActorToken() });
    const okBody = (await ok.json()) as { access_token?: string; error?: string };
    expect(ok.status, JSON.stringify(okBody)).toBe(200);
    expect(typeof okBody.access_token).toBe("string");

    // And it is consumed exactly once: the successful issuance recorded it.
    const replayed = await tokenExchange({ subjectToken: ica, actorToken: await mintActorToken() });
    const replayedBody = (await replayed.json()) as { error?: string; error_description?: string };
    expect(replayed.status, JSON.stringify(replayedBody)).toBe(400);
    expect(replayedBody.error_description).toMatch(/replay/);
  });

  it("(b) a replayed ICA jti -> rejected (single-use, consumed at issuance commit)", async () => {
    const { handle } = newLineage("apev-b");
    const ica = await mintICA(handle);
    const first = await tokenExchange({ subjectToken: ica, actorToken: await mintActorToken() });
    expect(first.status, await first.clone().text()).toBe(200);

    const second = await tokenExchange({ subjectToken: ica, actorToken: await mintActorToken() });
    const body = (await second.json()) as { error?: string; error_description?: string };
    expect(second.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toMatch(/replay/);
  });

  it("(c) actor disagreement (actor_token actor != the ICA/authenticated actor) -> invalid_grant", async () => {
    const { handle } = newLineage("apev-c");
    const res = await tokenExchange({
      subjectToken: await mintICA(handle), // act.sub = "ap-agent"
      actorToken: await mintActorToken({ sub: "ap-agent-imposter" }),
    });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_grant");
    expect(body.error_description).toMatch(/actor_token actor does not match/);
  });

  it("(d) DPoP jkt != ICA cnf.jkt -> invalid_request (presenter-key mismatch)", async () => {
    const { handle } = newLineage("apev-d");
    const res = await tokenExchange({
      subjectToken: await mintICA(handle, { cnfJkt: "some-other-jkt-thumbprint-value" }),
      actorToken: await mintActorToken(),
    });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toMatch(/presenter key/);
  });

  it("(e) an unknown continuation handle -> invalid_continuation", async () => {
    const { handle } = newLineage("apev-e");
    const res = await tokenExchange({
      subjectToken: await mintICA(handle, { handle: "ich_unknownhandle0123456789ABCDEFGH" }),
      actorToken: await mintActorToken(),
    });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_continuation");
    expect(body.error_description).toMatch(/unknown or terminal/);
  });

  it("(f) resourceToAs(resource) != audience -> invalid_target", async () => {
    const { handle } = newLineage("apev-f");
    const res = await tokenExchange({
      subjectToken: await mintICA(handle),
      actorToken: await mintActorToken(),
      audience: "https://wrong-audience.test",
    });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_target");
  });

  it("(g) revoking the Mission terminates its handles (onLifecycleCommit fan-out) -> invalid_continuation", async () => {
    const { missionId, handle } = newLineage("apev-g");
    const ica = await mintICA(handle);
    // Revoke BEFORE presentation: the fan-out marks the anchor + handle terminal.
    as.kernel.transition(missionId, "revoke");
    const res = await tokenExchange({ subjectToken: ica, actorToken: await mintActorToken() });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_continuation");
    // The STORE path (proves the fan-out wiring), distinct from the gate path.
    expect(body.error_description).toMatch(/unknown or terminal/);
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
    expect(resolved?.authEnvelope.acr).toBeUndefined();
    expect(resolved?.authEnvelope.authTime).toBeGreaterThanOrEqual(approxNow - 5);
    expect(resolved?.authEnvelope.authTime).toBeLessThanOrEqual(approxNow + 5);

    // The auto-rooted handle drives a full /token continuation hop end to end.
    const res = await tokenExchange({ subjectToken: await mintICA(handle), actorToken: await mintActorToken() });
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
    const res = await tokenExchange({ subjectToken: ica, actorToken: await mintActorToken() });
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_continuation");
    expect(body.error_description).toMatch(/unknown or terminal/);
  });

  it("already-issued keeps its exp: an ID-JAG minted BEFORE revoke still verifies + redeems with its ORIGINAL exp; only NEW continuations are refused after", async () => {
    const { missionId, handle } = approveLineage("apev-life-keepexp");

    // Issue a continuation ID-JAG while the Mission is active.
    const res1 = await tokenExchange({ subjectToken: await mintICA(handle), actorToken: await mintActorToken() });
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
    const res2 = await tokenExchange({ subjectToken: await mintICA(handle), actorToken: await mintActorToken() });
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
