/**
 * @spec resource-access#delegate-eligibility (inherited eligibility, #1275, D457)
 * @spec resource-access#subset (the `allowed_delegates` bullet)
 *
 * Delegate eligibility with retained provenance at the token endpoint. The
 * deployment's ceiling grants `delegation` without `allowed_delegates` on one
 * resource, so an approved entry derived from it inherits the authorization
 * server's delegation-authorization policy decision, and any list it carries
 * (one the proposal added, one a later exchange requested, one a Child
 * Mission's proposal added) only restricts that decision.
 *
 * The delegation issuance on this path is the ICA continuation exchange at
 * Mission delegation depth 1 and above. Two independently controlled clients,
 * svc-b and svc-c, are the delegates; each authenticates with its own key and
 * proves its own DPoP key. The policy hook is installed by this test and
 * permits exactly the clients in `permitted`; the reference default denies
 * every delegate.
 */

import { type Server } from "node:http";
import { AUTHORITY_SOURCES } from "@mission/demo-data";
import { calculateJwkThumbprint, decodeJwt, exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { TOKEN_EXCHANGE_GRANT_TYPE } from "../src/adapters/continuation-grant.js";
import {
  type AuthorityEntry,
  buildAuthorizationServer,
  type BuiltAs,
  createChildMission,
  type DelegationPolicyRequest,
  ID_JAG_TOKEN_TYPE,
  IDENTITY_CONTINUATION_JWT_TYP,
  IDENTITY_CONTINUATION_TOKEN_TYPE,
  validateMissionIntent,
} from "../src/index.js";

const PORT = 14738;
const ISSUER = `http://localhost:${PORT}`;
const CAI = "https://cai.example";
const RAS_AUD = "https://ras.ledgercloud.test";
const MISSION_EXP = "2099-01-01T00:00:00Z";

/** The ceiling entry here grants delegation and defers eligibility to policy: no `allowed_delegates`. */
const INHERIT = "https://api.ledgercloud.test/inherit";
/** Two overlapping ceiling entries: one defers to policy, the other names svc-b. */
const OVERLAP = "https://api.ledgercloud.test/overlap";
const READ = "ledger:report.read";
const LIST = "ledger:report.list";

const CEILING: AuthorityEntry[] = [
  {
    type: "mission_resource_access",
    resource: INHERIT,
    actions: [READ, LIST],
    delegation: {
      max_depth: 2,
      children: { max_children: 5, max_child_depth: 2, allowed_child_actors: [{ sub: "child-agent" }] },
    },
  },
  {
    type: "mission_resource_access",
    resource: OVERLAP,
    actions: [READ, LIST],
    delegation: { max_depth: 2 },
  },
  {
    type: "mission_resource_access",
    resource: OVERLAP,
    actions: [READ],
    delegation: { max_depth: 2, allowed_delegates: [{ sub: "svc-b" }] },
  },
];

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };
type Delegate = "svc-b" | "svc-c";

let as: BuiltAs;
let asServer: Server;
let caiKeys: Keys;
let agentKey: CryptoKey; // ap-agent's private_key_jwt key
let agentDpop: Keys;
const clients = {} as Record<Delegate, { auth: Keys; dpop: Keys; jkt: string }>;

/** The clients the delegation-authorization policy permits: set per test. */
const permitted = new Set<string>();
/** Every policy request, in order. */
const asked: DelegationPolicyRequest[] = [];
/** When set, replaces the permitted-set decision (the in-mint re-evaluation case). */
let override: ((request: DelegationPolicyRequest) => boolean) | undefined;

beforeEach(() => {
  permitted.clear();
  asked.length = 0;
  override = undefined;
});

let events = 0;

/** Approve a Mission for ap-agent, returning it and its approval-time root continuation handle. */
function approve(proposal: AuthorityEntry[]): { missionId: string; root: string } {
  const mission = as.kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({
        goal: "Delegate a report read under inherited eligibility",
        target_resources: [...new Set(proposal.map((e) => e.resource))],
        expires_at: MISSION_EXP,
      }),
    ),
    proposedAuthority: proposal,
    subject: { iss: ISSUER, sub: "alice" },
    approver: { iss: ISSUER, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-elig-${events++}`,
  });
  return { missionId: mission.id, root: as.continuationStore.handlesForMission(mission.id)[0] as string };
}

const entry = (resource: string, actions: string[], delegation?: AuthorityEntry["delegation"]): AuthorityEntry => ({
  type: "mission_resource_access",
  resource,
  actions,
  ...(delegation ? { delegation } : {}),
});

async function mintICA(handle: string, actor: string, cnfJkt: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ identity_continuation_handle: handle, cnf: { jkt: cnfJkt }, act: { iss: ISSUER, sub: actor } })
    .setProtectedHeader({ alg: "ES256", kid: "cai-key", typ: IDENTITY_CONTINUATION_JWT_TYP })
    .setIssuer(CAI)
    .setAudience(ISSUER)
    .setIssuedAt(now)
    .setExpirationTime(now + 120)
    .setJti(crypto.randomUUID())
    .sign(caiKeys.privateKey);
}

async function clientAssertion(clientId: string, key: CryptoKey): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: `${clientId}-auth` })
    .setIssuer(clientId)
    .setSubject(clientId)
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(key);
}

async function dpopProof(keys: Keys, extra: Record<string, unknown> = {}): Promise<string> {
  return new SignJWT({ htu: `${ISSUER}/token`, htm: "POST", ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(keys.privateKey);
}

/**
 * Continue `handle` at the ICA continuation exchange as `who`: ap-agent (the
 * Mission's approved agent) or a delegate client, each authenticating with its
 * own key and proving its own DPoP key.
 */
async function continueAs(
  handle: string,
  who: "ap-agent" | Delegate,
  extra: Record<string, string> = {},
): Promise<Response> {
  const [authKey, dpop] = who === "ap-agent" ? [agentKey, agentDpop] : [clients[who].auth.privateKey, clients[who].dpop];
  const jkt = await calculateJwkThumbprint(await exportJWK(dpop.publicKey));
  const subjectToken = await mintICA(handle, who, jkt);
  const send = async (proofExtra: Record<string, unknown> = {}) =>
    fetch(`${ISSUER}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(dpop, proofExtra) },
      body: new URLSearchParams({
        grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
        requested_token_type: ID_JAG_TOKEN_TYPE,
        subject_token: subjectToken,
        subject_token_type: IDENTITY_CONTINUATION_TOKEN_TYPE,
        audience: RAS_AUD,
        client_assertion: await clientAssertion(who, authKey),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ...extra,
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return res;
}

type Detail = { resource: string; actions: string[]; delegation?: { max_depth: number; allowed_delegates?: unknown } };

async function granted(res: Response): Promise<{ details: Detail[]; hop: string }> {
  const body = (await res.json()) as { access_token?: string };
  expect(res.status, JSON.stringify(body)).toBe(200);
  const claims = decodeJwt(body.access_token as string);
  return { details: claims.authorization_details as Detail[], hop: claims.identity_continuation_handle as string };
}

async function refused(res: Response): Promise<string | undefined> {
  const body = (await res.json()) as { error?: string; error_description?: string; access_token?: string };
  expect(res.status, JSON.stringify(body)).toBe(400);
  expect(body.error).toBe("invalid_target");
  expect(body).not.toHaveProperty("access_token");
  return body.error_description;
}

const sideEffects = (missionId: string) => ({
  hops: as.continuationStore.handlesForMission(missionId).length,
  derivations: as.kernel.get(missionId)?.derivation_count,
});

beforeAll(async () => {
  caiKeys = await generateKeyPair("ES256", { extractable: true });
  agentDpop = await generateKeyPair("ES256", { extractable: true });
  const registrations: Record<string, unknown>[] = [];
  for (const id of ["svc-b", "svc-c"] as const) {
    const auth = await generateKeyPair("ES256", { extractable: true });
    const dpop = await generateKeyPair("ES256", { extractable: true });
    clients[id] = { auth, dpop, jkt: await calculateJwkThumbprint(await exportJWK(dpop.publicKey)) };
    registrations.push({
      client_id: id,
      grant_types: [TOKEN_EXCHANGE_GRANT_TYPE],
      response_types: [],
      redirect_uris: [],
      token_endpoint_auth_method: "private_key_jwt",
      token_endpoint_auth_signing_alg: "ES256",
      jwks: { keys: [{ ...(await exportJWK(auth.publicKey)), kid: `${id}-auth`, alg: "ES256" }] },
    });
  }
  const caiPub = { ...(await exportJWK(caiKeys.publicKey)), kid: "cai-key", alg: "ES256", use: "sig" };
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    testClients: registrations,
    // This deployment's ceiling, and the user-delegated source ceiling that
    // matches it, in place of the shipped ones (none of which defers to policy).
    derivationPolicy: { policy_version: "eligibility-endpoint-1", ceiling: CEILING },
    authoritySources: {
      ...AUTHORITY_SOURCES,
      entries: AUTHORITY_SOURCES.entries.map((e) => (e.id === "acme-people" ? { ...e, ceiling: CEILING as never } : e)),
    },
    delegationPolicy: (request) => {
      asked.push(request);
      return override ? override(request) : permitted.has(request.delegate.sub);
    },
    continuationAssertionIssuers: [{ iss: CAI, jwks: { keys: [caiPub] }, attestsFor: [ISSUER, RAS_AUD] }],
    resourceToAs: (r) => (r === INHERIT || r === OVERLAP ? RAS_AUD : ISSUER),
  });
  asServer = as.provider.listen(PORT);
  agentKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
});

afterAll(() => {
  asServer?.close();
});

describe("delegate eligibility with retained provenance at the ICA continuation exchange (@spec resource-access#delegate-eligibility, #1275)", () => {
  describe("an approved entry whose ceiling entry defers to policy, with a list the proposal added", () => {
    const proposal = () => [entry(INHERIT, [READ], { max_depth: 2, allowed_delegates: [{ sub: "svc-c" }] })];

    it("derivation keeps the proposal's list as a restriction and retains the entry's policy origin with the Mission", () => {
      const { missionId } = approve(proposal());
      const record = as.kernel.get(missionId);
      expect(record?.authority_set[0]?.delegation?.allowed_delegates).toEqual([{ sub: "svc-c" }]);
      expect(record?.eligibility_provenance).toEqual(["policy"]);
    });

    it("policy denies, list permits: the delegate the list names is refused invalid_target, with no hop and no derivation", async () => {
      const { missionId, root } = approve(proposal());
      permitted.add("svc-b");
      const before = sideEffects(missionId);
      await refused(await continueAs(root, "svc-c"));
      expect(sideEffects(missionId)).toEqual(before);
      // The policy was asked about this delegate at the accounted depth.
      expect(asked.at(-1)).toMatchObject({ delegate: { sub: "svc-c" }, depth: 1, mission: { id: missionId } });
    });

    it("policy permits, list omits: a delegate the policy permits is refused invalid_target", async () => {
      const { missionId, root } = approve(proposal());
      permitted.add("svc-b");
      const before = sideEffects(missionId);
      await refused(await continueAs(root, "svc-b"));
      expect(sideEffects(missionId)).toEqual(before);
    });

    it("policy and list both permit: the delegate is issued the entry, its approved list intact", async () => {
      const { root } = approve(proposal());
      permitted.add("svc-c");
      const { details } = await granted(await continueAs(root, "svc-c"));
      expect(details.map((d) => d.resource)).toEqual([INHERIT]);
      expect(details[0]?.delegation).toMatchObject({ max_depth: 2, allowed_delegates: [{ sub: "svc-c" }] });
    });

    it("both permit only within the accounted depth bound: depth 2 above max_depth 1 is refused", async () => {
      const { root } = approve([
        entry(INHERIT, [READ], { max_depth: 1, allowed_delegates: [{ sub: "svc-b" }, { sub: "svc-c" }] }),
      ]);
      permitted.add("svc-b").add("svc-c");
      const hB = await granted(await continueAs(root, "svc-b")); // {svc-b, act: ap-agent}: depth 1
      expect(hB.details.map((d) => d.resource)).toEqual([INHERIT]);
      const reason = await refused(await continueAs(hB.hop, "svc-c")); // depth 2 > max_depth 1
      expect(reason).toMatch(/Mission delegation depth 2/);
    });
  });

  it("an entry with no list that defers to policy is not delegable while the policy permits nobody: absence is never a grant", async () => {
    // No proposal list: the approved entry inherits the ceiling's delegation, no list.
    const { root } = approve([entry(INHERIT, [READ])]);
    const reason = await refused(await continueAs(root, "svc-b"));
    expect(reason).toMatch(/Mission delegation depth 1/);
  });

  it("a list requested at a later exchange restricts the issued grant but admits nobody the policy denies at the next", async () => {
    const { root } = approve([entry(INHERIT, [READ])]);
    permitted.add("svc-b");
    // svc-b requests the entry narrowed by a list naming svc-c.
    const narrowed = JSON.stringify([entry(INHERIT, [READ], { max_depth: 2, allowed_delegates: [{ sub: "svc-c" }] })]);
    const hB = await granted(await continueAs(root, "svc-b", { authorization_details: narrowed }));
    expect(hB.details[0]?.delegation).toEqual({ max_depth: 2, allowed_delegates: [{ sub: "svc-c" }] });
    // svc-c continuing svc-b's hop (depth 2): the policy denies svc-c, whatever
    // the grant svc-b received lists.
    await refused(await continueAs(hB.hop, "svc-c"));
    permitted.add("svc-c");
    await granted(await continueAs(hB.hop, "svc-c"));
  });

  it("missing provenance: an entry whose retained provenance is gone narrows out although its list and the policy permit", async () => {
    const { missionId, root } = approve([entry(INHERIT, [READ], { max_depth: 2, allowed_delegates: [{ sub: "svc-c" }] })]);
    as.kernel.db.prepare("UPDATE missions SET eligibility_provenance_json = NULL WHERE id = ?").run(missionId);
    expect(as.kernel.get(missionId)?.eligibility_provenance).toBeUndefined();
    permitted.add("svc-c");
    const before = sideEffects(missionId);
    await refused(await continueAs(root, "svc-c"));
    expect(sideEffects(missionId)).toEqual(before);
    // The policy is never consulted for an entry that cannot be resolved.
    expect(asked).toHaveLength(0);
  });

  it("overlapping origins: each approved entry keeps its own origin, so a list-origin overlap never lends a policy-origin entry its eligibility", async () => {
    // One proposal entry derives under both overlapping ceiling entries.
    const { missionId, root } = approve([
      entry(OVERLAP, [READ, LIST], { max_depth: 2, allowed_delegates: [{ sub: "svc-b" }] }),
    ]);
    const record = as.kernel.get(missionId);
    expect(record?.authority_set.map((e) => e.actions)).toEqual([[READ, LIST], [READ]]);
    expect(record?.eligibility_provenance).toEqual(["policy", "list"]);
    // The policy denies svc-b: only the entry derived from the ceiling entry
    // naming svc-b is carried, never the overlapping read+list entry.
    const denied = await granted(await continueAs(root, "svc-b", { resource: OVERLAP }));
    expect(denied.details.map((d) => d.actions)).toEqual([[READ]]);
    // The policy permits svc-b: both entries are carried.
    permitted.add("svc-b");
    const both = await granted(await continueAs(root, "svc-b", { resource: OVERLAP }));
    expect(both.details.map((d) => d.actions)).toEqual([[READ, LIST], [READ]]);
  });

  it("policy change between issuance steps: a permit at one exchange is never reused at the next", async () => {
    const { root } = approve([entry(INHERIT, [READ], { max_depth: 2, allowed_delegates: [{ sub: "svc-b" }] })]);
    permitted.add("svc-b");
    const hB = await granted(await continueAs(root, "svc-b"));
    // The policy now denies svc-b: its next exchange, still at depth 1, is refused.
    permitted.delete("svc-b");
    await refused(await continueAs(hB.hop, "svc-b"));
    permitted.add("svc-b");
    await granted(await continueAs(hB.hop, "svc-b"));
  });

  it("the policy is asked again at the mint: a decision that changes after the pre-check refuses, with no hop", async () => {
    const { missionId, root } = approve([entry(INHERIT, [READ], { max_depth: 2, allowed_delegates: [{ sub: "svc-b" }] })]);
    // Permit the first question (the pre-check) and deny every later one.
    let calls = 0;
    override = () => ++calls === 1;
    const hops = as.continuationStore.handlesForMission(missionId).length;
    await refused(await continueAs(root, "svc-b"));
    expect(calls).toBe(2);
    expect(as.continuationStore.handlesForMission(missionId)).toHaveLength(hops);
  });

  it("a Child Mission's proposal list over a policy-deferring parent entry only restricts: the policy still decides at the child's exchange", async () => {
    const { missionId: parentId } = approve([entry(INHERIT, [READ])]);
    const { child } = createChildMission(as.kernel, {
      parentId,
      intent: validateMissionIntent(
        JSON.stringify({ goal: "Read the report as a child", target_resources: [INHERIT], expires_at: MISSION_EXP }),
      ),
      proposedAuthority: [entry(INHERIT, [READ], { max_depth: 2, allowed_delegates: [{ sub: "svc-c" }] })],
      childActor: { sub: "child-agent" },
    });
    expect(child.authority_set[0]?.delegation?.allowed_delegates).toEqual([{ sub: "svc-c" }]);
    expect(child.eligibility_provenance).toEqual(["policy"]);
    const childRoot = as.continuationStore.handlesForMission(child.id)[0] as string;
    // The child's list names svc-c, the policy denies it: refused.
    await refused(await continueAs(childRoot, "svc-c"));
    permitted.add("svc-c");
    await granted(await continueAs(childRoot, "svc-c"));
  });
});
