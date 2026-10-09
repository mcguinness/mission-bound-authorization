/**
 * @spec draft-mcguinness-oauth-mission-template#dispatch-handoff (#1158; D357,
 * D358, D361)
 *
 * The Dispatch Handoff over real HTTP. The Dispatcher (ap-agent) holds a
 * dispatched instance's token, bound to its own key; the instance's selected
 * Agent (subagent-invoice-extractor, its recorded client_id) is the approved
 * agent. The Dispatcher exchanges the token (`mission_dispatch_handoff=true`)
 * for a single-use grant naming the Agent; the Agent redeems it under RFC 7523
 * with its own key, then continues on the async delegation transport. Covered:
 *   - D357's acceptance bar: possession of the instance token's key, the
 *     recipient from the record and authenticated with its own key, authority
 *     within the presented token's and the current effective set, the
 *     continuation that follows, and refusals of the wrong recipient, wrong
 *     key, wrong audience and broader authority, recovery included;
 *   - D361: the explicit selector, malformed and conflicting selectors refused
 *     without falling through, the grant's `aud` and `client_id`, single use,
 *     and the grant's own validation (typ, aud, exp) apart from #1157's
 *     delegation-handle audience check.
 */

import { type Server } from "node:http";
import { CANONICAL_RESOURCE, demoReconciliationTemplate, DEV_SERVICE_TOKEN, TOPOLOGY } from "@mission/demo-data";
import {
  calculateJwkThumbprint,
  decodeJwt,
  decodeProtectedHeader,
  exportJWK,
  generateKeyPair,
  importJWK,
  type JWK,
  SignJWT,
} from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { CHILD_GRANT_TYP, CHILD_JWT_BEARER_GRANT_TYPE } from "../src/adapters/child-grant.js";
import {
  ACCESS_TOKEN_TOKEN_TYPE,
  JWT_TOKEN_TYPE,
  TOKEN_EXCHANGE_GRANT_TYPE,
} from "../src/adapters/continuation-grant.js";
import {
  DISPATCH_HANDOFF_CONFLICTS,
  DISPATCH_HANDOFF_TYP,
  MAX_DISPATCH_HANDOFF_LIFETIME_S,
  verifyDispatchHandoffGrant,
} from "../src/adapters/dispatch-handoff.js";
import { MISSION_DISPATCH_GRANT_TYPE } from "../src/adapters/provider.js";
import { DISPATCH_HANDOFF_SKEW_MS, DispatchHandoffStore } from "../src/kernel/dispatch-handoff-store.js";
import { GateError } from "../src/kernel/kernel.js";
import type { AuthorityEntry } from "../src/kernel/types.js";
import {
  ALL_PROVIDER_CAPABILITIES,
  buildAuthorizationServer,
  type BuiltAs,
  type ProviderCapability,
  SourceUnavailableError,
} from "../src/index.js";
import { delegationHandleParams } from "./delegation-handle.helper.js";

const PORT = 14583;
const ISSUER = `http://localhost:${PORT}`;
const TOKEN_ENDPOINT = `${ISSUER}/token`;
const RESOURCE = CANONICAL_RESOURCE;
const FAR_FUTURE = "2099-01-01T00:00:00Z";
const AGENT_ID = "subagent-invoice-extractor";
/** A test-only client registered for both grants, never the instance's Agent. */
const INTRUDER_ID = "test-handoff-intruder";

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };
type Party = "dispatcher" | "agent" | "intruder";

let as: BuiltAs;
let asServer: Server;
let tokenKey: CryptoKey; // the test-held AS token key (testTokenSigningJwk)
const clientKeys: Partial<Record<Party, CryptoKey>> = {};
const clientKids: Record<Party, string> = {
  dispatcher: "ap-agent-auth",
  agent: `${AGENT_ID}-auth`,
  intruder: `${INTRUDER_ID}-auth`,
};
const clientIds: Record<Party, string> = { dispatcher: "ap-agent", agent: AGENT_ID, intruder: INTRUDER_ID };
let dispatcherDpop: Keys;
let agentDpop: Keys;
let otherDpop: Keys;
let dispatcherJkt: string;
let agentJkt: string;
let seq = 0;
/** The injected authority source's outage switch: set, every resolution raises the transient class. */
let sourceOutage: string | undefined;

async function clientAssertion(party: Party): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: clientKids[party] })
    .setIssuer(clientIds[party])
    .setSubject(clientIds[party])
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(clientKeys[party] as CryptoKey);
}

async function dpopProof(keys: Keys, extra: Record<string, unknown> = {}): Promise<string> {
  return new SignJWT({ htu: TOKEN_ENDPOINT, htm: "POST", ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(keys.privateKey);
}

/**
 * A DPoP proof carrying exactly `claims` over the defaults (no automatic
 * `iat`), under `keys`; `jwk` replaces the header key.
 */
async function rawProof(keys: Keys, claims: Record<string, unknown>, jwk?: JWK): Promise<string> {
  return new SignJWT({ htu: TOKEN_ENDPOINT, htm: "POST", jti: crypto.randomUUID(), ...claims })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: jwk ?? (await exportJWK(keys.publicKey)) })
    .sign(keys.privateKey);
}

const nowS = (): number => Math.floor(Date.now() / 1000);

/** POST /token as `party` with a DPoP proof under `keys`, with the dpop-nonce retry. */
async function tokenRequest(
  party: Party,
  keys: Keys,
  params: Record<string, string>,
  proof: (extra: Record<string, unknown>) => Promise<string> = (extra) => dpopProof(keys, extra),
): Promise<Response> {
  const send = async (extra: Record<string, unknown> = {}): Promise<Response> =>
    fetch(TOKEN_ENDPOINT, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await proof(extra) },
      body: new URLSearchParams({
        ...params,
        client_assertion: await clientAssertion(party),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return res;
}

interface Instance {
  missionId: string;
  token: string;
  authority: AuthorityEntry[];
}

/** A fresh template (its own max_active and rate) and one dispatched instance. */
async function dispatchInstance(): Promise<Instance> {
  const created = await fetch(`${ISSUER}/templates`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
    body: JSON.stringify({ ...demoReconciliationTemplate(ISSUER), approval_event_id: `handoff-tmpl-${seq++}` }),
  });
  const { template_id } = (await created.json()) as { template_id: string };
  const res = await tokenRequest("dispatcher", dispatcherDpop, {
    grant_type: MISSION_DISPATCH_GRANT_TYPE,
    template_id,
    mission_intent: JSON.stringify({
      intent: { goal: "reconcile Acme invoices", target_resources: [RESOURCE], expires_at: FAR_FUTURE },
    }),
    dispatch_event_id: `handoff-evt-${seq++}`,
  });
  const body = (await res.json()) as { access_token: string; mission_id: string; authorization_details: AuthorityEntry[] };
  expect(res.status, JSON.stringify(body)).toBe(200);
  return { missionId: body.mission_id, token: body.access_token, authority: body.authorization_details };
}

/** The Dispatch Handoff exchange. */
async function handoff(
  subjectToken: string,
  extra: Record<string, string> = {},
  party: Party = "dispatcher",
  keys: Keys = dispatcherDpop,
): Promise<Response> {
  return tokenRequest(party, keys, {
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    subject_token: subjectToken,
    subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    requested_token_type: JWT_TOKEN_TYPE,
    mission_dispatch_handoff: "true",
    ...extra,
  });
}

/** The RFC 7523 redemption of a handoff grant. */
async function redeem(grant: string, party: Party = "agent", keys: Keys = agentDpop): Promise<Response> {
  return tokenRequest(party, keys, { grant_type: CHILD_JWT_BEARER_GRANT_TYPE, assertion: grant });
}

/** The async delegation exchange (request_refresh_token) as `party`. */
async function asyncDelegate(
  token: string,
  creationRequestId: string = crypto.randomUUID(),
  party: Party = "agent",
  keys: Keys = agentDpop,
): Promise<Response> {
  return tokenRequest(party, keys, {
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    request_refresh_token: "true",
    subject_token: token,
    subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    resource: RESOURCE,
    creation_request_id: creationRequestId,
  });
}

/** Handoff then redemption: the Agent's own token for the instance. */
async function handedOff(instance: Instance, extra: Record<string, string> = {}): Promise<string> {
  const h = await handoff(instance.token, extra);
  const hb = (await h.json()) as { access_token: string };
  expect(h.status, JSON.stringify(hb)).toBe(200);
  const r = await redeem(hb.access_token);
  const rb = (await r.json()) as { access_token: string };
  expect(r.status, JSON.stringify(rb)).toBe(200);
  return rb.access_token;
}

/** Sign `claims` with the AS token key (a grant or token this AS never minted). */
async function forge(claims: Record<string, unknown>, typ: string, exp?: number): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT(claims)
    .setProtectedHeader({ alg: TOPOLOGY.keys.asToken.alg, kid: TOPOLOGY.keys.asToken.kid, typ })
    .setIssuedAt(now)
    .setExpirationTime(exp ?? now + 120)
    .setJti(crypto.randomUUID())
    .sign(tokenKey);
}

/** A forged handoff grant for `missionId`, naming `clientId`. */
async function forgeGrant(
  missionId: string,
  clientId: string,
  authority: AuthorityEntry[],
  over: { aud?: string; typ?: string; exp?: number; iss?: string } = {},
): Promise<string> {
  return forge(
    {
      iss: over.iss ?? ISSUER,
      aud: over.aud ?? TOKEN_ENDPOINT,
      client_id: clientId,
      sub: "bob",
      mission: { id: missionId, issuer: ISSUER },
      authorization_details: authority,
    },
    over.typ ?? DISPATCH_HANDOFF_TYP,
    over.exp,
  );
}

const err = async (res: Response): Promise<{ status: number; error?: string; error_description?: string; mission_error?: string }> => ({
  status: res.status,
  ...((await res.json()) as { error?: string; error_description?: string; mission_error?: string }),
});
const actionsOf = (details: unknown): string[] =>
  ((details ?? []) as Array<{ actions: string[] }>).flatMap((e) => e.actions);
/** A strict subset of `authority`: its first action only. */
const narrowOf = (authority: AuthorityEntry[]): AuthorityEntry[] => {
  const first = authority[0] as AuthorityEntry;
  return [{ ...first, actions: [first.actions[0] as string] }];
};
const contain = (missionId: string, remove: Array<{ resource: string; actions?: string[] }>) =>
  as.kernel.contain(missionId, {
    event: {
      type: "tainted_read",
      source: "https://siem.example/detections",
      observed_at: new Date().toISOString(),
      event_id: `handoff-contain-${seq++}`,
    },
    remove,
  });

beforeAll(async () => {
  const { alg } = TOPOLOGY.keys.asToken;
  const tokenKeys = await generateKeyPair(alg, { extractable: true });
  tokenKey = tokenKeys.privateKey;
  const intruderKeys = await generateKeyPair("ES256", { extractable: true });
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    testTokenSigningJwk: (await exportJWK(tokenKeys.privateKey)) as JWK,
    authoritySource: {
      effectiveAuthoritySet: (record) => {
        if (sourceOutage !== undefined) throw new SourceUnavailableError(sourceOutage);
        return as.kernel.effectiveAuthoritySet(record);
      },
    },
    testClients: [
      {
        client_id: INTRUDER_ID,
        client_name: "Handoff intruder (registered for both grants)",
        grant_types: [CHILD_JWT_BEARER_GRANT_TYPE, TOKEN_EXCHANGE_GRANT_TYPE],
        response_types: [],
        redirect_uris: [],
        token_endpoint_auth_method: "private_key_jwt",
        token_endpoint_auth_signing_alg: "ES256",
        jwks: { keys: [{ ...(await exportJWK(intruderKeys.publicKey)), kid: clientKids.intruder, alg: "ES256" }] },
        authorization_details_types: ["mission_resource_access"],
      },
    ],
  });
  asServer = as.provider.listen(PORT);
  clientKeys.dispatcher = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  clientKeys.agent = (await importJWK(as.childClientJwk as never, "ES256")) as CryptoKey;
  clientKeys.intruder = intruderKeys.privateKey;
  dispatcherDpop = await generateKeyPair("ES256", { extractable: true });
  agentDpop = await generateKeyPair("ES256", { extractable: true });
  otherDpop = await generateKeyPair("ES256", { extractable: true });
  dispatcherJkt = await calculateJwkThumbprint(await exportJWK(dispatcherDpop.publicKey));
  agentJkt = await calculateJwkThumbprint(await exportJWK(agentDpop.publicKey));
});

afterAll(() => {
  asServer?.close();
});

describe("Dispatch Handoff: the handoff to the selected Agent and its continuation (@spec mission-template#dispatch-handoff)", () => {
  it("the Dispatcher's handoff grant names the Agent; the Agent redeems it with its own key, then opens and refreshes a family", async () => {
    const instance = await dispatchInstance();
    const before = as.kernel.get(instance.missionId);
    expect(before?.client_id).toBe(AGENT_ID);
    expect(before?.template).toBeDefined();

    const h = await handoff(instance.token);
    const hb = (await h.json()) as { access_token: string; issued_token_type?: string; token_type?: string; expires_in?: number };
    expect(h.status, JSON.stringify(hb)).toBe(200);
    expect(hb.issued_token_type).toBe(JWT_TOKEN_TYPE);
    expect(hb.token_type).toBe("N_A");
    expect(h.headers.get("cache-control")).toContain("no-store");

    // The grant: its own typ, aud = this AS's token endpoint, client_id = the
    // Agent (the recorded client_id), the instance's mission claim, short-lived.
    expect(decodeProtectedHeader(hb.access_token).typ).toBe(DISPATCH_HANDOFF_TYP);
    const grant = decodeJwt(hb.access_token);
    expect(grant.iss).toBe(ISSUER);
    expect(grant.aud).toBe(TOKEN_ENDPOINT);
    expect(grant.client_id).toBe(AGENT_ID);
    expect(grant.sub).toBe(before?.subject.sub);
    expect((grant.mission as { id?: string }).id).toBe(instance.missionId);
    expect(grant.authorization_details).toEqual(instance.authority);
    expect((grant.exp as number) - (grant.iat as number)).toBeLessThanOrEqual(MAX_DISPATCH_HANDOFF_LIFETIME_S);
    expect((grant.exp as number) * 1000).toBeLessThanOrEqual(Date.parse(before?.expires_at as string));
    // The exchange counts nothing: the redemption is the derivation.
    expect(as.kernel.get(instance.missionId)?.derivation_count).toBe(before?.derivation_count);

    const r = await redeem(hb.access_token);
    const rb = (await r.json()) as { access_token: string; token_type?: string; authorization_details?: unknown };
    expect(r.status, JSON.stringify(rb)).toBe(200);
    expect(rb.token_type).toBe("DPoP");
    const agentToken = decodeJwt(rb.access_token);
    expect(agentToken.client_id).toBe(AGENT_ID);
    // #1157 (D358): the redeemed token is the Agent's delegation handle,
    // audienced to the Agent itself, not to a resource.
    expect(agentToken.aud).toBe(AGENT_ID);
    expect((agentToken.cnf as { jkt?: string }).jkt).toBe(agentJkt);
    expect((agentToken.cnf as { jkt?: string }).jkt).not.toBe(dispatcherJkt);
    expect((agentToken.mission as { id?: string }).id).toBe(instance.missionId);
    expect(rb.authorization_details).toEqual(instance.authority);
    // One counted derivation, and the Dispatcher's grant stays the instance's.
    const after = as.kernel.get(instance.missionId);
    expect(after?.derivation_count).toBe((before?.derivation_count ?? 0) + 1);
    expect(after?.grant_id).toBe(before?.grant_id);

    // The Agent continues as the approved agent: a family, then a refresh.
    const fam = await asyncDelegate(rb.access_token);
    const fb = (await fam.json()) as { access_token?: string; refresh_token?: string };
    expect(fam.status, JSON.stringify(fb)).toBe(200);
    expect(typeof fb.refresh_token).toBe("string");
    const refreshed = await tokenRequest("agent", agentDpop, {
      grant_type: "refresh_token",
      refresh_token: fb.refresh_token as string,
    });
    const rfb = (await refreshed.json()) as { access_token?: string; refresh_token?: string };
    expect(refreshed.status, JSON.stringify(rfb)).toBe(200);
    expect((decodeJwt(rfb.access_token as string).mission as { id?: string }).id).toBe(instance.missionId);
    expect(rfb.refresh_token).not.toBe(fb.refresh_token);
  });

  it("the Dispatcher still cannot continue the instance itself: the async exchange stays open only to the approved agent", async () => {
    const instance = await dispatchInstance();
    // The instance token is not a delegation handle, so the async exchange
    // refuses it (#1157)...
    const res = await err(await asyncDelegate(instance.token, crypto.randomUUID(), "dispatcher", dispatcherDpop));
    expect(res.status).toBe(400);
    expect(res.error).toBe("invalid_grant");
    expect(res.error_description).toContain("not a delegation handle");
    // ...and the Dispatcher cannot obtain one: rule 1 holds at the handle request.
    const handle = await err(
      await tokenRequest("dispatcher", dispatcherDpop, delegationHandleParams(instance.token, clientIds.dispatcher)),
    );
    expect(handle.status).toBe(400);
    expect(handle.error).toBe("invalid_request");
    expect(handle.error_description).toContain("open only to the Mission's approved agent");
  });

  it("the recipient comes from the record, never the request: an `audience` naming another client changes nothing", async () => {
    const instance = await dispatchInstance();
    const h = await handoff(instance.token, { audience: INTRUDER_ID });
    const hb = (await h.json()) as { access_token: string };
    expect(h.status, JSON.stringify(hb)).toBe(200);
    expect(decodeJwt(hb.access_token).client_id).toBe(AGENT_ID);
    expect(decodeJwt(hb.access_token).aud).toBe(TOKEN_ENDPOINT);
  });
});

describe("Dispatch Handoff: the explicit selector (@spec mission-template#dispatch-handoff, D361)", () => {
  it("a malformed selector value is refused invalid_request", async () => {
    // An empty value is not a selector: RFC 6749 Section 3.1 treats a
    // parameter sent without a value as omitted (oidc-provider drops it).
    const instance = await dispatchInstance();
    for (const value of ["false", "1", "TRUE", "yes"]) {
      const res = await err(await handoff(instance.token, { mission_dispatch_handoff: value }));
      expect(res.status, value).toBe(400);
      expect(res.error, value).toBe("invalid_request");
      expect(res.error_description, value).toContain("mission_dispatch_handoff must be true");
    }
  });

  it("every conflicting selector is refused invalid_request and never falls through to its own exchange", async () => {
    const instance = await dispatchInstance();
    const values: Record<(typeof DISPATCH_HANDOFF_CONFLICTS)[number], string> = {
      request_refresh_token: "true",
      mission_intent: JSON.stringify({ intent: { goal: "child", target_resources: [RESOURCE], expires_at: FAR_FUTURE } }),
      child_actor: JSON.stringify({ sub: AGENT_ID, sub_profile: "ai_agent" }),
      parent: instance.missionId,
      creation_request_id: crypto.randomUUID(),
      carryover_replacement: "mis_none",
      actor_token: "x.y.z",
    };
    const before = as.kernel.get(instance.missionId);
    for (const name of DISPATCH_HANDOFF_CONFLICTS) {
      const res = await err(await handoff(instance.token, { [name]: values[name] }));
      expect(res.status, name).toBe(400);
      expect(res.error, name).toBe("invalid_request");
      expect(res.error_description, name).toContain(`cannot be combined with ${name}`);
    }
    // A full child-creation request plus the selector creates no child.
    const full = await err(
      await handoff(instance.token, {
        mission_intent: values.mission_intent,
        child_actor: values.child_actor,
        creation_request_id: crypto.randomUUID(),
        authorization_details: JSON.stringify(narrowOf(instance.authority)),
      }),
    );
    expect(full.error).toBe("invalid_request");
    expect(as.kernel.findChildren(instance.missionId)).toHaveLength(0);
    // Nothing was counted: no family, no child, no handoff redemption.
    expect(as.kernel.get(instance.missionId)?.derivation_count).toBe(before?.derivation_count);
  });

  it("a selector sent without a value is treated as omitted (RFC 6749 Section 3.2), never as a malformed value", async () => {
    // The other parameters select child creation, which refuses for its own
    // missing parameters; nothing is created and nothing is counted.
    const instance = await dispatchInstance();
    const before = as.kernel.get(instance.missionId)?.derivation_count;
    const res = await err(await handoff(instance.token, { mission_dispatch_handoff: "" }));
    expect(res.status).toBe(400);
    expect(res.error).toBe("invalid_request");
    expect(res.error_description).not.toContain("mission_dispatch_handoff");
    expect(res.error_description).toContain("creation_request_id");
    expect(as.kernel.findChildren(instance.missionId)).toHaveLength(0);
    expect(as.kernel.get(instance.missionId)?.derivation_count).toBe(before);
  });

  it("the selector requires the jwt requested_token_type", async () => {
    const instance = await dispatchInstance();
    const access = await err(await handoff(instance.token, { requested_token_type: ACCESS_TOKEN_TOKEN_TYPE }));
    expect(access.error).toBe("invalid_request");
    expect(access.error_description).toContain("requires the jwt requested_token_type");
  });

  it("a requested scope is refused: the grant carries authority, not scope", async () => {
    const instance = await dispatchInstance();
    const res = await err(await handoff(instance.token, { scope: "openid" }));
    expect(res.status).toBe(400);
    expect(res.error).toBe("invalid_scope");
  });
});

describe("Dispatch Handoff: exchange refusals (@spec mission-template#dispatch-handoff steps 1-5)", () => {
  it("wrong key: a DPoP proof under any key but the instance token's is refused invalid_grant", async () => {
    const instance = await dispatchInstance();
    const res = await err(await handoff(instance.token, {}, "dispatcher", otherDpop));
    expect(res.error).toBe("invalid_grant");
    expect(res.error_description).toContain("does not match the subject_token confirmation key");
  });

  it("wrong client: a client other than the one the token was issued to is refused invalid_grant, even with the key", async () => {
    const instance = await dispatchInstance();
    const res = await err(await handoff(instance.token, {}, "agent", dispatcherDpop));
    expect(res.error).toBe("invalid_grant");
    expect(res.error_description).toContain("not issued to the authenticated client");
  });

  it("a Mission without template lineage is refused invalid_grant", async () => {
    const plain = as.kernel.approve({
      intent: { goal: "plain", target_resources: [RESOURCE], expires_at: FAR_FUTURE } as never,
      subject: { iss: ISSUER, sub: "alice" },
      approver: { iss: ISSUER, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: `handoff-plain-${seq++}`,
    });
    const token = await forge(
      {
        iss: ISSUER,
        aud: RESOURCE,
        client_id: "ap-agent",
        sub: "alice",
        mission: { id: plain.id, issuer: ISSUER },
        cnf: { jkt: dispatcherJkt },
        authorization_details: plain.authority_set,
      },
      "at+jwt",
    );
    const res = await err(await handoff(token));
    expect(res.error).toBe("invalid_grant");
    expect(res.error_description).toContain("not a dispatched instance");
  });

  it("an instance no longer active is refused invalid_grant", async () => {
    const instance = await dispatchInstance();
    as.kernel.transition(instance.missionId, "revoke");
    const res = await err(await handoff(instance.token));
    expect(res.error).toBe("invalid_grant");
    expect(res.error_description).toContain("dispatched instance is revoked");
  });

  it("a subject token without readable authority is refused invalid_grant", async () => {
    const instance = await dispatchInstance();
    const token = await forge(
      {
        iss: ISSUER,
        aud: RESOURCE,
        client_id: "ap-agent",
        sub: "bob",
        mission: { id: instance.missionId, issuer: ISSUER },
        cnf: { jkt: dispatcherJkt },
      },
      "at+jwt",
    );
    const res = await err(await handoff(token));
    expect(res.error).toBe("invalid_grant");
    expect(res.error_description).toContain("no readable authorization_details");
  });

  it("broader authority: a request beyond the presented token is refused invalid_authorization_details", async () => {
    const instance = await dispatchInstance();
    // A down-scoped token for the instance: the request asks for all of the
    // instance, which exceeds what this token carries.
    const narrowToken = await forge(
      {
        iss: ISSUER,
        aud: RESOURCE,
        client_id: "ap-agent",
        sub: "bob",
        mission: { id: instance.missionId, issuer: ISSUER },
        cnf: { jkt: dispatcherJkt },
        authorization_details: narrowOf(instance.authority),
      },
      "at+jwt",
    );
    const res = await err(await handoff(narrowToken, { authorization_details: JSON.stringify(instance.authority) }));
    expect(res.error).toBe("invalid_authorization_details");
    expect(res.error_description).toContain("exceed the presented token's authority");
    // Absent a request, the grant carries the presented token's authority.
    const ok = await handoff(narrowToken);
    const okb = (await ok.json()) as { access_token: string };
    expect(ok.status, JSON.stringify(okb)).toBe(200);
    expect(actionsOf(decodeJwt(okb.access_token).authorization_details)).toEqual(actionsOf(narrowOf(instance.authority)));
  });

  it("broader authority: a request beyond the current effective set is refused; absent, the grant is narrowed by it", async () => {
    const instance = await dispatchInstance();
    const all = actionsOf(instance.authority);
    expect(all.length, "the demo instance needs two actions").toBeGreaterThanOrEqual(2);
    const removed = all[all.length - 1] as string;
    contain(instance.missionId, [{ resource: RESOURCE, actions: [removed] }]);
    const res = await err(await handoff(instance.token, { authorization_details: JSON.stringify(instance.authority) }));
    expect(res.error).toBe("invalid_authorization_details");
    expect(res.error_description).toContain("exceed the Mission authority");
    const ok = await handoff(instance.token);
    const okb = (await ok.json()) as { access_token: string };
    expect(ok.status, JSON.stringify(okb)).toBe(200);
    expect(actionsOf(decodeJwt(okb.access_token).authorization_details)).not.toContain(removed);
  });

  it("a narrower request is honored", async () => {
    const instance = await dispatchInstance();
    const narrow = narrowOf(instance.authority);
    const h = await handoff(instance.token, { authorization_details: JSON.stringify(narrow) });
    const hb = (await h.json()) as { access_token: string };
    expect(h.status, JSON.stringify(hb)).toBe(200);
    expect(actionsOf(decodeJwt(hb.access_token).authorization_details)).toEqual(actionsOf(narrow));
  });
});

describe("Dispatch Handoff: redemption refusals (@spec mission-template#dispatch-handoff redemption)", () => {
  async function grantFor(instance: Instance, extra: Record<string, string> = {}): Promise<string> {
    const h = await handoff(instance.token, extra);
    const hb = (await h.json()) as { access_token: string };
    expect(h.status, JSON.stringify(hb)).toBe(200);
    return hb.access_token;
  }

  it("wrong recipient: a client the grant does not name is refused, and the grant stays redeemable by the Agent", async () => {
    const instance = await dispatchInstance();
    const grant = await grantFor(instance);
    const res = await err(await redeem(grant, "intruder", otherDpop));
    expect(res.error).toBe("invalid_grant");
    expect(res.error_description).toContain("redeemer does not match the authenticated client");
    const ok = await redeem(grant);
    expect(ok.status).toBe(200);
  });

  it("the Dispatcher cannot redeem: it is not registered for the jwt-bearer grant", async () => {
    const instance = await dispatchInstance();
    const res = await err(await redeem(await grantFor(instance), "dispatcher", dispatcherDpop));
    expect(res.error).toBe("invalid_request");
    expect(res.error_description).toContain("not allowed for this client");
  });

  it("single use: a second redemption is refused invalid_grant and counts nothing", async () => {
    const instance = await dispatchInstance();
    const grant = await grantFor(instance);
    expect((await redeem(grant)).status).toBe(200);
    const counted = as.kernel.get(instance.missionId)?.derivation_count;
    const again = await err(await redeem(grant));
    expect(again.error).toBe("invalid_grant");
    expect(again.error_description).toContain("already redeemed");
    // Even under a fresh key of the Agent's.
    const third = await err(await redeem(grant, "agent", otherDpop));
    expect(third.error_description).toContain("already redeemed");
    expect(as.kernel.get(instance.missionId)?.derivation_count).toBe(counted);
  });

  it("single use under concurrency: of two simultaneous redemptions exactly one succeeds, counted once", async () => {
    const instance = await dispatchInstance();
    const grant = await grantFor(instance);
    const before = as.kernel.get(instance.missionId)?.derivation_count ?? 0;
    const results = await Promise.all([redeem(grant), redeem(grant, "agent", otherDpop)]);
    const statuses = results.map((r) => r.status).sort();
    expect(statuses).toEqual([200, 400]);
    // The loser met the winner's reservation (retryable) or its consumption.
    const loser = results.find((r) => r.status === 400) as Response;
    expect(((await loser.json()) as { error_description?: string }).error_description).toMatch(
      /in progress; retry|already redeemed/,
    );
    // Once the winner has its token, a retry is a replay.
    const after = await err(await redeem(grant));
    expect(after.error).toBe("invalid_grant");
    expect(after.error_description).toContain("already redeemed");
    expect(as.kernel.get(instance.missionId)?.derivation_count).toBe(before + 1);
  });

  it("wrong audience: a grant whose aud is not this token endpoint is refused (apart from #1157's handle audience)", async () => {
    const instance = await dispatchInstance();
    const grant = await forgeGrant(instance.missionId, AGENT_ID, instance.authority, { aud: RESOURCE });
    const res = await err(await redeem(grant));
    expect(res.error).toBe("invalid_grant");
    expect(res.error_description).toBe("invalid dispatch handoff grant");
    // The same grant with the right aud redeems: aud alone was the refusal.
    expect((await redeem(await forgeGrant(instance.missionId, AGENT_ID, instance.authority))).status).toBe(200);
  });

  it("an expired grant, or one from another issuer, is refused", async () => {
    const instance = await dispatchInstance();
    const expired = await forgeGrant(instance.missionId, AGENT_ID, instance.authority, {
      exp: Math.floor(Date.now() / 1000) - 10,
    });
    expect((await err(await redeem(expired))).error_description).toBe("invalid dispatch handoff grant");
    const foreign = await forgeGrant(instance.missionId, AGENT_ID, instance.authority, { iss: "https://other.example" });
    expect((await err(await redeem(foreign))).error_description).toBe("invalid dispatch handoff grant");
  });

  it("defence in depth: a grant naming a client that is not the instance's Agent, or a non-instance Mission, is refused", async () => {
    const instance = await dispatchInstance();
    const misnamed = await forgeGrant(instance.missionId, INTRUDER_ID, instance.authority);
    const res = await err(await redeem(misnamed, "intruder", otherDpop));
    expect(res.error).toBe("invalid_grant");
    expect(res.error_description).toContain("does not match a dispatched instance's selected Agent");

    const plain = as.kernel.approve({
      intent: { goal: "plain", target_resources: [RESOURCE], expires_at: FAR_FUTURE } as never,
      subject: { iss: ISSUER, sub: "alice" },
      approver: { iss: ISSUER, sub: "bob" },
      clientId: AGENT_ID,
      approvalEventId: `handoff-plain-${seq++}`,
    });
    const noLineage = await forgeGrant(plain.id, AGENT_ID, plain.authority_set);
    expect((await err(await redeem(noLineage))).error_description).toContain(
      "does not match a dispatched instance's selected Agent",
    );
  });

  it("a suspended instance refuses redemption without consuming the grant; after resume it redeems", async () => {
    const instance = await dispatchInstance();
    const grant = await grantFor(instance);
    as.kernel.transition(instance.missionId, "suspend");
    const res = await err(await redeem(grant));
    expect(res.error).toBe("invalid_grant");
    expect(res.mission_error).toBe("mission_suspended");
    as.kernel.transition(instance.missionId, "resume");
    expect((await redeem(grant)).status).toBe(200);
  });

  it("the redeemed authority is narrowed by the effective set at redemption; fully contained, it is refused", async () => {
    const instance = await dispatchInstance();
    const all = actionsOf(instance.authority);
    const removed = all[all.length - 1] as string;
    const partial = await grantFor(instance);
    contain(instance.missionId, [{ resource: RESOURCE, actions: [removed] }]);
    const r = await redeem(partial);
    const rb = (await r.json()) as { authorization_details?: unknown };
    expect(r.status, JSON.stringify(rb)).toBe(200);
    expect(actionsOf(rb.authorization_details)).not.toContain(removed);
    expect(actionsOf(decodeJwt((rb as { access_token: string }).access_token).authorization_details)).not.toContain(removed);

    // The grant's own actions contained, the instance's others live: refused.
    const other = await dispatchInstance();
    const narrow = narrowOf(other.authority);
    const grant = await grantFor(other, { authorization_details: JSON.stringify(narrow) });
    contain(other.missionId, [{ resource: RESOURCE, actions: actionsOf(narrow) }]);
    const refused = await err(await redeem(grant));
    expect(refused.error).toBe("invalid_grant");
    expect(refused.error_description).toContain("no longer within the instance's effective authority");

    // The whole instance contained: the kernel's gate refuses first.
    const third = await dispatchInstance();
    const whole = await grantFor(third);
    contain(third.missionId, [{ resource: RESOURCE }]);
    expect((await err(await redeem(whole))).error).toBe("invalid_grant");
  });

  it("a redemption without a DPoP proof is refused", async () => {
    const instance = await dispatchInstance();
    const grant = await grantFor(instance);
    const res = await fetch(TOKEN_ENDPOINT, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: CHILD_JWT_BEARER_GRANT_TYPE,
        assertion: grant,
        client_assertion: await clientAssertion("agent"),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toBe("DPoP proof JWT required");
  });
});

describe("Dispatch Handoff: recovery stays within the handed-off token (#1153 rule 2, D353)", () => {
  it("a retried family creation recovers with an equivalent token and is refused with a narrower one", async () => {
    const instance = await dispatchInstance();
    const full = await handedOff(instance);
    const crid = crypto.randomUUID();
    const first = await asyncDelegate(full, crid);
    const firstBody = (await first.json()) as { refresh_token?: string };
    expect(first.status, JSON.stringify(firstBody)).toBe(200);

    const narrower = await handedOff(instance, { authorization_details: JSON.stringify(narrowOf(instance.authority)) });
    const refused = await err(await asyncDelegate(narrower, crid));
    expect(refused.error).toBe("invalid_authorization_details");
    expect(refused.error_description).toContain("exceeds the presented token's authority");

    const equivalent = await handedOff(instance);
    // The completed operation's stored response: the same, still unconsumed family.
    const recovered = await asyncDelegate(equivalent, crid);
    const recoveredBody = (await recovered.json()) as { refresh_token?: string };
    expect(recovered.status, JSON.stringify(recoveredBody)).toBe(200);
    expect(recoveredBody.refresh_token).toBe(firstBody.refresh_token);
  });
});

describe("Dispatch Handoff: complete, fresh DPoP proofs on both legs (@spec RFC 9449 Section 4.3, #1163 review)", () => {
  /** The refused proofs: no iat, a day old, past the 240 s past bound, and an hour ahead. */
  const stale = () => [
    { label: "no iat", claims: {}, description: "DPoP proof has no iat" },
    { label: "a day old", claims: { iat: nowS() - 86_400 }, description: "outside the acceptance window" },
    { label: "past the window", claims: { iat: nowS() - 260 }, description: "outside the acceptance window" },
    { label: "an hour ahead", claims: { iat: nowS() + 3_600 }, description: "outside the acceptance window" },
  ];

  it("the exchange refuses an incomplete, stale or future-dated proof; a proof within the window succeeds", async () => {
    const instance = await dispatchInstance();
    const params = {
      grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
      subject_token: instance.token,
      subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
      requested_token_type: JWT_TOKEN_TYPE,
      mission_dispatch_handoff: "true",
    };
    for (const { label, claims, description } of stale()) {
      const res = await err(
        await tokenRequest("dispatcher", dispatcherDpop, params, (extra) => rawProof(dispatcherDpop, { ...claims, ...extra })),
      );
      expect(res.status, label).toBe(400);
      expect(res.error, label).toBe("invalid_dpop_proof");
      expect(res.error_description, label).toContain(description);
    }
    const ok = await tokenRequest("dispatcher", dispatcherDpop, params, (extra) =>
      rawProof(dispatcherDpop, { iat: nowS() - 200, ...extra }),
    );
    expect(ok.status, JSON.stringify(await ok.clone().json())).toBe(200);
  });

  it("the redemption refuses an incomplete, stale or future-dated proof, or a private or symmetric proof key, taking nothing; the grant then redeems", async () => {
    const instance = await dispatchInstance();
    const h = await handoff(instance.token);
    const grant = ((await h.json()) as { access_token: string }).access_token;
    const before = as.kernel.get(instance.missionId)?.derivation_count;
    const params = { grant_type: CHILD_JWT_BEARER_GRANT_TYPE, assertion: grant };
    for (const { label, claims, description } of stale()) {
      const res = await err(
        await tokenRequest("agent", agentDpop, params, (extra) => rawProof(agentDpop, { ...claims, ...extra })),
      );
      expect(res.status, label).toBe(400);
      expect(res.error, label).toBe("invalid_dpop_proof");
      expect(res.error_description, label).toContain(description);
    }
    const privateJwk = (await exportJWK(agentDpop.privateKey)) as JWK;
    const leaked = await err(
      await tokenRequest("agent", agentDpop, params, (extra) =>
        rawProof(agentDpop, { iat: nowS(), ...extra }, privateJwk),
      ),
    );
    expect(leaked.error).toBe("invalid_dpop_proof");
    expect(leaked.error_description).toBe("invalid DPoP proof");
    // A symmetric proof key: an HS256 proof under the `oct` key in its own header.
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const octJwk = { kty: "oct", k: Buffer.from(secret).toString("base64url") };
    const symmetric = await err(
      await tokenRequest("agent", agentDpop, params, (extra) =>
        new SignJWT({ htu: TOKEN_ENDPOINT, htm: "POST", jti: crypto.randomUUID(), iat: nowS(), ...extra })
          .setProtectedHeader({ alg: "HS256", typ: "dpop+jwt", jwk: octJwk })
          .sign(secret),
      ),
    );
    expect(symmetric.error).toBe("invalid_dpop_proof");
    expect(symmetric.error_description).toBe("invalid DPoP proof");
    expect(as.kernel.get(instance.missionId)?.derivation_count).toBe(before);
    expect((await redeem(grant)).status).toBe(200);
  });
});

describe("Dispatch Handoff: a redemption that issues no token leaves the grant redeemable (#1163 review)", () => {
  async function grantOf(instance: Instance): Promise<string> {
    const h = await handoff(instance.token);
    const hb = (await h.json()) as { access_token: string };
    expect(h.status, JSON.stringify(hb)).toBe(200);
    return hb.access_token;
  }

  it("an authority-source outage before the grant is taken refuses 503; restored, the same grant redeems", async () => {
    const instance = await dispatchInstance();
    const grant = await grantOf(instance);
    const before = as.kernel.get(instance.missionId)?.derivation_count ?? 0;
    sourceOutage = "authority source unavailable";
    let res: Awaited<ReturnType<typeof err>>;
    try {
      res = await err(await redeem(grant));
    } finally {
      sourceOutage = undefined;
    }
    expect(res.status).toBe(503);
    expect(res.error).toBe("temporarily_unavailable");
    expect(as.kernel.get(instance.missionId)?.derivation_count).toBe(before);
    const ok = await redeem(grant);
    expect(ok.status, JSON.stringify(await ok.clone().json())).toBe(200);
    expect(as.kernel.get(instance.missionId)?.derivation_count).toBe(before + 1);
  });

  /** The consumed-grant row for `grant`'s jti, if any. */
  const takenRow = (grant: string) =>
    as.kernel.dispatchHandoffs.db
      .prepare("SELECT state FROM dispatch_handoff_consumed WHERE jti = ?")
      .get(decodeJwt(grant).jti as string) as { state: string } | undefined;

  it("a derivation refused after the grant is taken releases it; once derivable again, the same grant redeems", async () => {
    const instance = await dispatchInstance();
    const grant = await grantOf(instance);
    as.kernel.db.prepare("UPDATE missions SET derivation_limit = derivation_count WHERE id = ?").run(instance.missionId);
    const refused = await err(await redeem(grant));
    expect(refused.error).toBe("invalid_grant");
    expect(refused.mission_error).toBe("derivations_exhausted");
    expect(takenRow(grant), "the reservation was released").toBeUndefined();
    as.kernel.db.prepare("UPDATE missions SET derivation_limit = NULL WHERE id = ?").run(instance.missionId);
    expect((await redeem(grant)).status).toBe(200);
    expect(takenRow(grant)?.state).toBe("consumed");
  });

  it("an issuance failure after the derivation is reserved releases the grant; the retry redeems and counts it once", async () => {
    const instance = await dispatchInstance();
    const grant = await grantOf(instance);
    const before = as.kernel.get(instance.missionId)?.derivation_count ?? 0;
    // The token save re-gates the instance; fail the first such gate after
    // the derivation was reserved (the count has moved), once.
    const real = as.kernel.gateActive.bind(as.kernel);
    let injected = false;
    const spy = vi.spyOn(as.kernel, "gateActive").mockImplementation((id: string) => {
      if (!injected && (as.kernel.get(id)?.derivation_count ?? 0) > before) {
        injected = true;
        throw new GateError("mission_not_active", "injected issuance failure");
      }
      return real(id);
    });
    let refused: Awaited<ReturnType<typeof err>>;
    try {
      refused = await err(await redeem(grant));
    } finally {
      spy.mockRestore();
    }
    expect(injected, "the issuance-time gate ran after the derivation was reserved").toBe(true);
    expect(refused.status).toBe(400);
    expect(refused.error).toBe("invalid_grant");
    expect(takenRow(grant), "the reservation was released").toBeUndefined();
    // The failed attempt reserved its derivation; the retry replays it.
    expect(as.kernel.get(instance.missionId)?.derivation_count).toBe(before + 1);
    const ok = await redeem(grant);
    expect(ok.status, JSON.stringify(await ok.clone().json())).toBe(200);
    expect(as.kernel.get(instance.missionId)?.derivation_count).toBe(before + 1);
    expect((await err(await redeem(grant))).error_description).toContain("already redeemed");
  });
});

describe("Dispatch Handoff behind the templates capability (adapters/capabilities.ts)", () => {
  const without = (...off: ProviderCapability[]) => new Set(ALL_PROVIDER_CAPABILITIES.filter((c) => !off.includes(c)));
  /** POST /token on another deployment, as `party` (its own client keys), with a DPoP proof under `keys`. */
  async function tokenAt(
    built: BuiltAs,
    issuer: string,
    party: "dispatcher" | "agent",
    keys: Keys,
    params: Record<string, string>,
  ): Promise<Response> {
    const jwk = party === "dispatcher" ? built.agentClientJwk : built.childClientJwk;
    const clientKey = (await importJWK(jwk as never, "ES256")) as CryptoKey;
    const assertion = await new SignJWT({})
      .setProtectedHeader({ alg: "ES256", kid: clientKids[party] })
      .setIssuer(clientIds[party])
      .setSubject(clientIds[party])
      .setAudience(issuer)
      .setIssuedAt()
      .setExpirationTime("2m")
      .setJti(crypto.randomUUID())
      .sign(clientKey);
    const send = async (extra: Record<string, unknown> = {}): Promise<Response> => {
      const proof = await new SignJWT({ htu: `${issuer}/token`, htm: "POST", ...extra })
        .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
        .setIssuedAt()
        .setJti(crypto.randomUUID())
        .sign(keys.privateKey);
      return fetch(`${issuer}/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", dpop: proof },
        body: new URLSearchParams({
          ...params,
          client_assertion: assertion,
          client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        }).toString(),
      });
    };
    let res = await send();
    const nonce = res.headers.get("dpop-nonce");
    if (res.status === 400 && nonce) res = await send({ nonce });
    return res;
  }

  it("templates off: the handoff exchange is refused before any token is read, and a handoff grant is not redeemed", async () => {
    const issuer = `http://localhost:${PORT + 1}`;
    const built = await buildAuthorizationServer({ issuer, allowHeadlessAdjudication: true, capabilities: without("templates") });
    const listening = built.provider.listen(PORT + 1);
    try {
      const exchange = await err(
        await tokenAt(built, issuer, "dispatcher", dispatcherDpop, {
          grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
          subject_token: "not-a-token",
          subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
          requested_token_type: JWT_TOKEN_TYPE,
          mission_dispatch_handoff: "true",
        }),
      );
      expect(exchange.error).toBe("invalid_request");
      expect(exchange.error_description).toContain("(templates) is not enabled");
      // A handoff-typ assertion meets the capability gate, not the handoff
      // handler (whose own refusal names the grant).
      const keys = await generateKeyPair("ES256");
      const grant = await new SignJWT({ client_id: AGENT_ID })
        .setProtectedHeader({ alg: "ES256", typ: DISPATCH_HANDOFF_TYP })
        .sign(keys.privateKey);
      const redeemed = await err(
        await tokenAt(built, issuer, "agent", agentDpop, { grant_type: CHILD_JWT_BEARER_GRANT_TYPE, assertion: grant }),
      );
      expect(redeemed.error).toBe("invalid_grant");
      expect(redeemed.error_description).not.toBe("invalid dispatch handoff grant");
    } finally {
      listening.close();
    }
  });

  it("async delegation off: the delegation-handle request is refused before any token is read (#1157)", async () => {
    const issuer = `http://localhost:${PORT + 4}`;
    const built = await buildAuthorizationServer({
      issuer,
      allowHeadlessAdjudication: true,
      capabilities: without("async-delegation"),
    });
    const listening = built.provider.listen(PORT + 4);
    try {
      const res = await err(
        await tokenAt(built, issuer, "dispatcher", dispatcherDpop, delegationHandleParams("not-a-token", clientIds.dispatcher)),
      );
      expect(res.error).toBe("invalid_request");
      expect(res.error_description).toContain("(async-delegation) is not enabled");
    } finally {
      listening.close();
    }
  });

  it("child delegation off, templates on: jwt-bearer redeems handoff grants only, never a child grant", async () => {
    const issuer = `http://localhost:${PORT + 2}`;
    const { alg, kid } = TOPOLOGY.keys.asToken;
    const keys = await generateKeyPair(alg, { extractable: true });
    const built = await buildAuthorizationServer({
      issuer,
      allowHeadlessAdjudication: true,
      capabilities: without("child-delegation"),
      testTokenSigningJwk: (await exportJWK(keys.privateKey)) as JWK,
    });
    const listening = built.provider.listen(PORT + 2);
    try {
      // A validly signed child grant for a Mission the Agent is the client of.
      const plain = built.kernel.approve({
        intent: { goal: "plain", target_resources: [RESOURCE], expires_at: FAR_FUTURE } as never,
        subject: { iss: issuer, sub: "alice" },
        approver: { iss: issuer, sub: "bob" },
        clientId: AGENT_ID,
        approvalEventId: `handoff-cap-${seq++}`,
      });
      const childGrant = await new SignJWT({ client_id: AGENT_ID, mission: { id: plain.id, issuer } })
        .setProtectedHeader({ alg, kid, typ: CHILD_GRANT_TYP })
        .setIssuer(issuer)
        .setAudience(`${issuer}/token`)
        .setIssuedAt()
        .setExpirationTime("2m")
        .setJti(crypto.randomUUID())
        .sign(keys.privateKey);
      const res = await err(
        await tokenAt(built, issuer, "agent", agentDpop, { grant_type: CHILD_JWT_BEARER_GRANT_TYPE, assertion: childGrant }),
      );
      expect(res.status, JSON.stringify(res)).toBe(400);
      expect(res.error).toBe("invalid_grant");
    } finally {
      listening.close();
    }
  });
});

describe("the handoff grant's own validation (unit)", () => {
  async function signer() {
    const keys = await generateKeyPair("ES256", { extractable: true });
    const jwks = { keys: [{ ...(await exportJWK(keys.publicKey)), kid: "k1", alg: "ES256" }] };
    const sign = (claims: Record<string, unknown>, typ = DISPATCH_HANDOFF_TYP, expIn = 60) =>
      new SignJWT(claims)
        .setProtectedHeader({ alg: "ES256", kid: "k1", typ })
        .setIssuedAt()
        .setExpirationTime(Math.floor(Date.now() / 1000) + expIn)
        .setJti(crypto.randomUUID())
        .sign(keys.privateKey);
    return { jwks, sign };
  }
  const base = {
    iss: ISSUER,
    aud: TOKEN_ENDPOINT,
    client_id: AGENT_ID,
    mission: { id: "mis_1", issuer: ISSUER },
    authorization_details: [{ type: "mission_resource_access", resource: RESOURCE, actions: ["a"] }],
  };

  it("accepts a well-formed grant and reads its members", async () => {
    const { jwks, sign } = await signer();
    const v = await verifyDispatchHandoffGrant(await sign(base), jwks as never, ISSUER);
    expect(v?.clientId).toBe(AGENT_ID);
    expect(v?.missionId).toBe("mis_1");
    expect(v?.missionIssuer).toBe(ISSUER);
    expect(v?.authority).toEqual(base.authorization_details);
  });

  it("refuses a foreign signature, the wrong typ (a child grant included), aud, iss, an expired grant, and missing members", async () => {
    const { jwks, sign } = await signer();
    const check = async (jws: string) => verifyDispatchHandoffGrant(jws, jwks as never, ISSUER);
    const foreign = await signer();
    expect(await check(await foreign.sign(base))).toBeUndefined();
    expect(await check(await sign(base, "mission-child-grant+jwt"))).toBeUndefined();
    expect(await check(await sign(base, "JWT"))).toBeUndefined();
    expect(await check(await sign({ ...base, aud: RESOURCE }))).toBeUndefined();
    expect(await check(await sign({ ...base, aud: ISSUER }))).toBeUndefined();
    expect(await check(await sign({ ...base, iss: "https://other.example" }))).toBeUndefined();
    expect(await check(await sign(base, DISPATCH_HANDOFF_TYP, -10))).toBeUndefined();
    expect(await check(await sign({ ...base, client_id: undefined }))).toBeUndefined();
    expect(await check(await sign({ ...base, mission: { issuer: ISSUER } }))).toBeUndefined();
    expect(await check(await sign({ ...base, authorization_details: [] }))).toBeUndefined();
    expect(await check(await sign({ ...base, authorization_details: undefined }))).toBeUndefined();
  });
});

describe("the consumed-grant store (unit, @spec mission-template#dispatch-handoff single use)", () => {
  it("reserves atomically, releases only an unconfirmed reservation, and remembers a consumed jti through exp plus skew", () => {
    let now = Date.parse("2026-10-08T00:00:00Z");
    const store = new DispatchHandoffStore(() => new Date(now));
    const expMs = now + 300_000;
    const j1 = { jti: "j1", missionId: "m", expMs };
    expect(store.reserve(j1)).toBe("reserved");
    expect(store.reserve(j1)).toBe("in-progress");
    // A reservation that issued nothing is released: the grant is redeemable again.
    store.release("j1");
    expect(store.reserve(j1)).toBe("reserved");
    store.confirm("j1");
    expect(store.reserve(j1)).toBe("consumed");
    // A consumed grant is never released.
    store.release("j1");
    expect(store.reserve(j1)).toBe("consumed");
    // Past exp, within the skew allowance: still remembered.
    now = expMs + DISPATCH_HANDOFF_SKEW_MS - 1;
    expect(store.reserve(j1)).toBe("consumed");
    // Another jti meanwhile is independent.
    expect(store.reserve({ jti: "j2", missionId: "m", expMs: now + 1000 })).toBe("reserved");
    // Past the horizon: pruned (the grant itself no longer verifies by then).
    now = expMs + DISPATCH_HANDOFF_SKEW_MS + 1;
    store.reserve({ jti: "j3", missionId: "m", expMs: now + 1000 });
    const rows = store.db.prepare("SELECT jti FROM dispatch_handoff_consumed ORDER BY jti").all() as Array<{ jti: string }>;
    expect(rows.map((r) => r.jti)).toEqual(["j2", "j3"]);
  });
});
