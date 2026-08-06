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
 * The ID-JAG is signed with the ES256 as-txn key (published on jwks_uri) because
 * issueCrossDomainGrant hardcodes an ES256 header and the AS token key is RS256;
 * the test verifies it against the AS jwks_uri. gateDerivation runs exactly once
 * (inside issueCrossDomainGrant, via a direct SignJWT — never provider.AccessToken).
 *
 * Setup drives the store directly (rootGrantAnchor + mint) and mints ICAs with a
 * dedicated Chain Authority key injected via chainAuthorityIssuers.
 */

import { type Server } from "node:http";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import {
  calculateJwkThumbprint,
  createRemoteJWKSet,
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
      resources: [RESOURCE],
      expires_at: MISSION_EXP,
      proposed_authority: [
        {
          type: "mission_resource_access",
          resource: RESOURCE,
          actions: ["payments:invoice.read"],
          constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
        },
      ],
    }),
  );
  const mission = as.kernel.approve({
    intent,
    subject: { iss: ISSUER, sub: "alice" }, // the GLOBAL subject
    approver: { iss: ISSUER, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: eventId,
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

    // The ID-JAG verifies on the AS jwks_uri (signed with the ES256 as-txn key).
    const { payload } = await jwtVerify(body.access_token as string, remoteJwks, {
      issuer: ISSUER,
      audience: RAS_AUD,
    });
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

  it("(b) a replayed ICA jti -> rejected (single-use; validator records the jti)", async () => {
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
