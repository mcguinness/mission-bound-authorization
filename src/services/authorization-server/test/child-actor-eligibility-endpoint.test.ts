/**
 * @spec child-delegation#fanout (inherited child-actor eligibility, #1304, D486)
 * @spec child-delegation#attenuation, child-delegation#creation-idempotency,
 * child-delegation#carryover-generations, child-delegation#request-processing
 *
 * Child-actor eligibility with retained provenance at the token endpoint. The
 * deployment's ceiling grants `children` without `allowed_child_actors` on the
 * payments read entry, so an approved entry derived from it defers the child
 * actor to the authorization server's child-creation policy, and any list it
 * carries (one the parent's proposal added, one a Child Mission's proposal
 * added, one the presented token carries) only restricts that decision. The
 * payments write entry names its child actors, so its list decides and the
 * policy is never asked. Two overlapping reports entries, one of each origin,
 * cover multiple retained origins.
 *
 * Covered through the child-creation token exchange (and its recovery) and
 * through Child Mission Carryover, which the expansion exchange renders and
 * its deferred completion commits. Every case keeps authority, depth and
 * fan-out valid, so the child-actor gate is the only refusal in play. The
 * policy hook is installed by this test on one authorization server; a
 * second one installs none and so runs the reference default, which denies
 * every child actor.
 */

import { type Server } from "node:http";
import { AUTHORITY_SOURCES, CANONICAL_RESOURCE, DERIVATION_POLICY, TOPOLOGY } from "@mission/demo-data";
import {
  calculateJwkThumbprint,
  type CryptoKey,
  exportJWK,
  generateKeyPair,
  importJWK,
  type JWK,
  SignJWT,
} from "jose";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { ACCESS_TOKEN_TOKEN_TYPE, JWT_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from "../src/adapters/continuation-grant.js";
import {
  ApprovalSessionStore,
  type AuthorityEntry,
  buildAuthorizationServer,
  type BuiltAs,
  type CarryoverManifest,
  type ChildCreationPolicyRequest,
  createChildMission,
  type MissionRecord,
  validateMissionIntent,
} from "../src/index.js";
import { FIXTURE_BROWSER_LOGIN, TEST_APPROVAL_PRINCIPALS } from "./approval-fixture.js";
import { asTokenSigningKeyPair } from "./subject-possession.helper.js";

const PORT = 14741;
const BARE_PORT = 14742;
const EXP = "2099-01-01T00:00:00Z";

const RESOURCE = CANONICAL_RESOURCE;
const resourceOf = (action: string): string => {
  const found = DERIVATION_POLICY.ceiling.find((e) => e.actions.includes(action));
  if (!found) throw new Error(`no shipped ceiling entry carries ${action}`);
  return found.resource;
};
const LEDGER = resourceOf("ledger:vendor.read");
const REPORTS = resourceOf("reports:report.read");
const READS = ["payments:invoice.list", "payments:invoice.read", "payments:vendor.read"];
const MRA = "mission_resource_access" as const;

/**
 * This deployment's ceiling. P defers the child actor to policy (its
 * `children` names no actors) while its delegate list keeps the delegate
 * origin a list; L names its child actors; O_POLICY and O_LIST overlap on the
 * reports read, policy first.
 */
const CEILING: AuthorityEntry[] = [
  {
    type: MRA,
    resource: RESOURCE,
    actions: READS,
    constraints: { vendors: ["acme"] },
    delegation: {
      max_depth: 2,
      allowed_delegates: [{ sub_profile: "ai_agent" }],
      children: { max_children: 1, max_child_depth: 2 },
    },
  },
  {
    type: MRA,
    resource: RESOURCE,
    actions: ["payments:payment.schedule"],
    constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    delegation: {
      max_depth: 2,
      allowed_delegates: [{ sub_profile: "ai_agent" }],
      children: { max_children: 5, max_child_depth: 2, allowed_child_actors: [{ sub: "child-l" }] },
    },
  },
  {
    type: MRA,
    resource: REPORTS,
    actions: ["reports:report.read", "reports:report.write"],
    delegation: { max_depth: 2, children: { max_children: 5, max_child_depth: 2 } },
  },
  {
    type: MRA,
    resource: REPORTS,
    actions: ["reports:report.read"],
    delegation: { max_depth: 2, children: { max_children: 5, max_child_depth: 2, allowed_child_actors: [{ sub: "child-a" }] } },
  },
  { type: MRA, resource: LEDGER, actions: ["ledger:vendor.read"], constraints: { vendors: ["acme"] } },
];

type Children = Record<string, unknown>;

/** A parent proposal for the payments read entry; `children` narrows the ceiling's grant (a list added here only restricts). */
const pEntry = (children?: Children): AuthorityEntry => ({
  type: MRA,
  resource: RESOURCE,
  actions: READS,
  constraints: { vendors: ["acme"] },
  ...(children ? { delegation: { max_depth: 2, children } as AuthorityEntry["delegation"] } : {}),
});

/** A parent proposal for the payments write entry, whose ceiling entry names child-l. */
const lEntry = (): AuthorityEntry => ({
  type: MRA,
  resource: RESOURCE,
  actions: ["payments:payment.schedule"],
  constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
});

const ledgerEntry = (): AuthorityEntry => ({
  type: MRA,
  resource: LEDGER,
  actions: ["ledger:vendor.read"],
  constraints: { vendors: ["acme"] },
});

/** A child entry within a payments read parent entry; by default it may create no child of its own. */
const childEntry = (children: Children = { max_children: 1, max_child_depth: 1, allowed_child_actors: [] }): AuthorityEntry => ({
  type: MRA,
  resource: RESOURCE,
  actions: ["payments:invoice.read"],
  constraints: { vendors: ["acme"] },
  delegation: { max_depth: 1, children } as AuthorityEntry["delegation"],
});

/** A child entry within the payments write parent entry. */
const lChildEntry = (): AuthorityEntry => ({
  type: MRA,
  resource: RESOURCE,
  actions: ["payments:payment.schedule"],
  constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  delegation: { max_depth: 1, children: { max_children: 1, max_child_depth: 1, allowed_child_actors: [] } } as AuthorityEntry["delegation"],
});

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };
type Client = { id: string; key: CryptoKey; dpop: Keys; jkt: string };
type Target = { as: BuiltAs; issuer: string; agent: Client };

let hooked: Target;
let bare: Target;
let servers: Server[] = [];
let tokenKey: CryptoKey;
/** child-a, a registered client: a Child Mission's agent that creates its own child. */
let childClient: Client;

/** The child actors the child-creation policy permits, per operation: set per test. */
const permits = { creation: new Set<string>(), carryover: new Set<string>() };
/** Every policy request, in order. */
const asked: ChildCreationPolicyRequest[] = [];
/** When set, replaces the per-operation decision. */
let override: ((request: ChildCreationPolicyRequest) => boolean) | undefined;

beforeEach(() => {
  permits.creation.clear();
  permits.carryover.clear();
  asked.length = 0;
  override = undefined;
});

let events = 0;

function approve(target: Target, proposal: AuthorityEntry[], resources: string[] = [RESOURCE]): MissionRecord {
  return target.as.kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({ goal: "Work under inherited child-actor eligibility", target_resources: resources, expires_at: EXP }),
    ),
    proposedAuthority: proposal,
    subject: { iss: target.issuer, sub: "alice" },
    approver: { iss: target.issuer, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-cae-${events++}`,
  });
}

/** A child created at the kernel (setup only), under the policy as this test sets it. */
function kernelChild(target: Target, parentId: string, actor: string, proposal: AuthorityEntry[]): MissionRecord {
  return createChildMission(target.as.kernel, {
    parentId,
    intent: validateMissionIntent(
      JSON.stringify({ goal: "Child work", target_resources: [...new Set(proposal.map((e) => e.resource))], expires_at: EXP }),
    ),
    proposedAuthority: proposal,
    childActor: { sub: actor },
  }).child;
}

const AS_TOKEN_HEADER = { alg: TOPOLOGY.keys.asToken.alg, kid: TOPOLOGY.keys.asToken.kid, typ: "at+jwt" };

/**
 * A Mission-bound access token for `mission`, sender-constrained to
 * `holder`'s DPoP key, as the authorization server issues one under its
 * injected signing key. `details` is the authority it carries: the Mission's
 * approved set unless a case narrows it.
 */
async function accessToken(
  target: Target,
  mission: MissionRecord,
  holder: Client,
  details: AuthorityEntry[] = mission.authority_set,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    client_id: mission.client_id,
    cnf: { jkt: holder.jkt },
    authorization_details: details,
    mission: { id: mission.id, issuer: target.issuer },
  })
    .setProtectedHeader(AS_TOKEN_HEADER)
    .setIssuer(target.issuer)
    .setSubject(mission.subject.sub)
    .setAudience(RESOURCE)
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .setJti(crypto.randomUUID())
    .sign(tokenKey);
}

/** POST /token as `client`, with its own client assertion and DPoP proof, and the dpop-nonce retry. */
async function tokenRequest(target: Target, client: Client, params: Record<string, string>): Promise<Response> {
  const htu = `${target.issuer}/token`;
  const proof = async (extra: Record<string, unknown>) =>
    new SignJWT({ htu, htm: "POST", ...extra })
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(client.dpop.publicKey) })
      .setIssuedAt()
      .setJti(crypto.randomUUID())
      .sign(client.dpop.privateKey);
  const assertion = () =>
    new SignJWT({})
      .setProtectedHeader({ alg: "ES256", kid: `${client.id}-auth` })
      .setIssuer(client.id)
      .setSubject(client.id)
      .setAudience(target.issuer)
      .setIssuedAt()
      .setExpirationTime("2m")
      .setJti(crypto.randomUUID())
      .sign(client.key);
  const send = async (extra: Record<string, unknown> = {}) =>
    fetch(htu, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await proof(extra) },
      body: new URLSearchParams({
        ...params,
        client_assertion: await assertion(),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return res;
}

/** The child-creation exchange: `client` presents `token` (the parent's own access token by default) and names `actor`. */
async function createChild(
  target: Target,
  parent: MissionRecord,
  actor: string,
  opts: { client?: Client; token?: string; proposal?: AuthorityEntry[]; creationRequestId?: string } = {},
): Promise<Response> {
  const client = opts.client ?? target.agent;
  const proposal = opts.proposal ?? [childEntry()];
  return tokenRequest(target, client, {
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    subject_token: opts.token ?? (await accessToken(target, parent, client)),
    subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    requested_token_type: JWT_TOKEN_TYPE,
    creation_request_id: opts.creationRequestId ?? crypto.randomUUID(),
    mission_intent: JSON.stringify({
      intent: { goal: "Child work", target_resources: [...new Set(proposal.map((e) => e.resource))], expires_at: EXP },
    }),
    authorization_details: JSON.stringify(proposal),
    child_actor: JSON.stringify({ sub: actor }),
  });
}

async function created(target: Target, res: Response): Promise<MissionRecord> {
  const body = (await res.json()) as { mission_id?: string; access_token?: string };
  expect(res.status, JSON.stringify(body)).toBe(200);
  expect(body.access_token).toBeDefined();
  const child = target.as.kernel.get(body.mission_id as string);
  expect(child?.state).toBe("active");
  return child as MissionRecord;
}

async function refused(res: Response, reason = "child_actor_not_allowed"): Promise<string | undefined> {
  const body = (await res.json()) as { error?: string; mission_denial_reason?: string; error_description?: string };
  expect(res.status, JSON.stringify(body)).toBe(400);
  expect(body.error).toBe("invalid_request");
  expect(body.mission_denial_reason).toBe(reason);
  expect(body).not.toHaveProperty("access_token");
  return body.error_description;
}

/** No child, no fan-out slot, no derivation: what a refusal must leave. */
const sideEffects = (target: Target, parentId: string) => ({
  children: target.as.kernel.findChildren(parentId).length,
  derivations: target.as.kernel.get(parentId)?.derivation_count,
});

const creationAsks = () => asked.filter((r) => r.operation === "creation");
const carryoverAsks = () => asked.filter((r) => r.operation === "carryover");

// ---------------------------------------------------------------------------
// Expansion with carryover.
// ---------------------------------------------------------------------------

/** Open a widening expansion of `predecessor` (adds the ledger); returns the deferral code. */
async function openExpansion(target: Target, predecessor: MissionRecord, readEntry: AuthorityEntry): Promise<string> {
  const proposal = [readEntry, ledgerEntry()];
  const res = await tokenRequest(target, target.agent, {
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    subject_token: await accessToken(target, predecessor, target.agent),
    subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    login_hint: "alice",
    mission_intent: JSON.stringify({
      intent: { goal: "Widen to read the ledger", target_resources: [RESOURCE, LEDGER], expires_at: EXP },
    }),
    authorization_details: JSON.stringify(proposal),
    creation_request_id: crypto.randomUUID(),
  });
  const body = (await res.json()) as { error?: string; deferral_code?: string };
  expect(res.status, JSON.stringify(body)).toBe(400);
  expect(body.error).toBe("authorization_pending");
  target.as.expansionDeferrals.approve(body.deferral_code as string, {
    approver: { iss: target.issuer, sub: "bob" },
    authentication: FIXTURE_BROWSER_LOGIN,
    approvalEventId: `apev-cae-exp-${events++}`,
    approvedUntil: EXP,
  });
  return body.deferral_code as string;
}

/** The committed manifest of an approved deferral. */
function manifestOf(target: Target, code: string): CarryoverManifest {
  const row = target.as.expansionDeferrals.db
    .prepare("SELECT carryover_manifest_json FROM expansion_deferrals WHERE deferral_code = ?")
    .get(code) as { carryover_manifest_json: string };
  return JSON.parse(row.carryover_manifest_json) as CarryoverManifest;
}

const rowOf = (manifest: CarryoverManifest, childId: string) => manifest.entries.find((e) => e.child_id === childId);

/** Complete the deferred expansion (deferral code and DPoP only). */
function poll(target: Target, code: string): Promise<Response> {
  return tokenRequest(target, target.agent, {
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    deferral_code: code,
  });
}

async function completed(res: Response): Promise<{ mission_id: string }> {
  const body = (await res.json()) as { mission_id?: string; error?: string };
  expect(res.status, JSON.stringify(body)).toBe(200);
  return body as { mission_id: string };
}

/** The old child was carried: terminated with `carried_to`, its replacement a child of the successor. */
function carried(target: Target, oldChildId: string, successorId: string): MissionRecord {
  const old = target.as.kernel.get(oldChildId);
  expect(old?.termination?.reason).toBe("parent_terminated");
  const replacement = target.as.kernel.get(old?.termination?.carried_to as string);
  expect(replacement?.parent?.id).toBe(successorId);
  expect(replacement?.related_to).toBe(oldChildId);
  return replacement as MissionRecord;
}

/** The old child was not carried: cascaded with no replacement, and none names it. */
function notCarried(target: Target, oldChildId: string): void {
  const old = target.as.kernel.get(oldChildId);
  expect(old?.termination?.reason).toBe("parent_terminated");
  expect(old?.termination?.carried_to).toBeUndefined();
  expect(target.as.kernel.allMissions().some((m) => m.related_to === oldChildId)).toBe(false);
}

async function clientFor(id: string, key: CryptoKey): Promise<Client> {
  const dpop = await generateKeyPair("ES256", { extractable: true });
  return { id, key, dpop, jkt: await calculateJwkThumbprint(await exportJWK(dpop.publicKey)) };
}

beforeAll(async () => {
  const signing = await asTokenSigningKeyPair();
  tokenKey = signing.privateKey;
  const childAuth = await generateKeyPair("ES256", { extractable: true });
  const sources = {
    ...AUTHORITY_SOURCES,
    entries: AUTHORITY_SOURCES.entries.map((e) => (e.id === "acme-people" ? { ...e, ceiling: CEILING as never } : e)),
  };
  const build = async (port: number, withPolicy: boolean): Promise<Target> => {
    const issuer = `http://localhost:${port}`;
    const as = await buildAuthorizationServer({
      issuer,
      allowHeadlessAdjudication: true,
      serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
      approvalSessions: new ApprovalSessionStore(),
      testTokenSigningJwk: (await exportJWK(signing.privateKey)) as JWK,
      testClients: [
        {
          client_id: "child-a",
          grant_types: [TOKEN_EXCHANGE_GRANT_TYPE],
          response_types: [],
          redirect_uris: [],
          token_endpoint_auth_method: "private_key_jwt",
          token_endpoint_auth_signing_alg: "ES256",
          jwks: { keys: [{ ...(await exportJWK(childAuth.publicKey)), kid: "child-a-auth", alg: "ES256" }] },
          authorization_details_types: [MRA],
        },
      ],
      // This deployment's ceiling, and the user-delegated source ceiling that
      // matches it, in place of the shipped ones (none of which defers a child
      // actor to policy).
      derivationPolicy: { ...DERIVATION_POLICY, policy_version: "child-actor-endpoint-1", ceiling: CEILING },
      authoritySources: sources,
      ...(withPolicy
        ? {
            childCreationPolicy: (request: ChildCreationPolicyRequest) => {
              asked.push(request);
              return override ? override(request) : permits[request.operation].has(request.child_actor.sub);
            },
          }
        : {}),
    });
    servers.push(as.provider.listen(port));
    const agentKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
    return { as, issuer, agent: await clientFor("ap-agent", agentKey) };
  };
  hooked = await build(PORT, true);
  bare = await build(BARE_PORT, false);
  childClient = await clientFor("child-a", childAuth.privateKey);
});

afterAll(() => {
  for (const s of servers) s.close();
  servers = [];
});

describe("child-actor eligibility with retained provenance at the child-creation exchange (@spec child-delegation#fanout, #1304)", () => {
  describe("a parent entry whose ceiling entry defers the child actor to policy, with a list the parent's proposal added", () => {
    const proposal = () => [pEntry({ allowed_child_actors: [{ sub: "child-a" }] })];

    it("derivation keeps the proposal's list as a restriction and retains a policy child-actor origin, apart from the delegate origin", () => {
      const parent = approve(hooked, proposal());
      const children = parent.authority_set[0]?.delegation?.children as Children;
      expect(children.allowed_child_actors).toEqual([{ sub: "child-a" }]);
      expect(parent.child_actor_provenance).toEqual(["policy"]);
      // The same entry's delegate list came from the ceiling: its delegate
      // origin is the list, and neither origin establishes the other.
      expect(parent.eligibility_provenance).toEqual(["list"]);
      expect(hooked.as.kernel.get(parent.id)?.child_actor_provenance).toEqual(["policy"]);
    });

    it("policy denies, list permits: the actor the list names is refused, with no child, no fan-out slot and no derivation", async () => {
      const parent = approve(hooked, proposal());
      permits.creation.add("child-b");
      const before = sideEffects(hooked, parent.id);
      await refused(await createChild(hooked, parent, "child-a"));
      expect(sideEffects(hooked, parent.id)).toEqual(before);
      expect(creationAsks().at(-1)).toMatchObject({
        operation: "creation",
        parent: { id: parent.id },
        child_actor: { sub: "child-a" },
        depth: 1,
      });
      // The refusal consumed no creation budget: with max_children 1, a
      // permitted creation still has its slot.
      permits.creation.add("child-a");
      await created(hooked, await createChild(hooked, parent, "child-a"));
    });

    it("policy permits, list omits: an actor the policy permits is refused, and the policy is not asked", async () => {
      const parent = approve(hooked, proposal());
      permits.creation.add("child-b");
      const before = sideEffects(hooked, parent.id);
      await refused(await createChild(hooked, parent, "child-b"));
      // The parent entry's retained list refuses on its own: a presented token
      // whose entry carries no list does not lift it.
      const listless = await accessToken(
        hooked,
        parent,
        hooked.agent,
        parent.authority_set.map((e) => ({
          ...e,
          delegation: { ...e.delegation, children: { max_children: 1, max_child_depth: 2 } } as AuthorityEntry["delegation"],
        })),
      );
      await refused(await createChild(hooked, parent, "child-b", { token: listless }));
      expect(sideEffects(hooked, parent.id)).toEqual(before);
      expect(creationAsks()).toHaveLength(0);
    });

    it("policy and list both permit: the child is created, asked at creation and again at the commit", async () => {
      const parent = approve(hooked, proposal());
      permits.creation.add("child-a");
      const child = await created(hooked, await createChild(hooked, parent, "child-a"));
      expect(child.parent?.id).toBe(parent.id);
      expect(child.client_id).toBe("child-a");
      expect(creationAsks()).toHaveLength(2);
      // The child keeps the policy origin it inherits, apart from its delegate origin.
      expect(child.child_actor_provenance).toEqual(["policy"]);
    });
  });

  it("the policy is asked again at the creation commit: a decision that changes after the first check refuses, creating nothing", async () => {
    const parent = approve(hooked, [pEntry({ allowed_child_actors: [{ sub: "child-a" }] })]);
    // Permit the first question and deny every later one.
    let calls = 0;
    override = () => ++calls === 1;
    const before = sideEffects(hooked, parent.id);
    await refused(await createChild(hooked, parent, "child-a"));
    expect(calls).toBe(2);
    expect(sideEffects(hooked, parent.id)).toEqual(before);
  });

  it("an absent list defers to the policy and is never a grant: refused while the policy permits nobody, created once it permits the actor", async () => {
    const parent = approve(hooked, [pEntry()]);
    expect((parent.authority_set[0]?.delegation?.children as Children).allowed_child_actors).toBeUndefined();
    expect(parent.child_actor_provenance).toEqual(["policy"]);
    await refused(await createChild(hooked, parent, "child-a"));
    permits.creation.add("child-a");
    await created(hooked, await createChild(hooked, parent, "child-a"));
  });

  it("the reference default denies: with no policy installed, an absent list admits no child actor", async () => {
    const parent = approve(bare, [pEntry()]);
    const before = sideEffects(bare, parent.id);
    await refused(await createChild(bare, parent, "child-a"));
    // A list the proposal added only restricts the default decision.
    const listed = approve(bare, [pEntry({ allowed_child_actors: [{ sub: "child-a" }] })]);
    await refused(await createChild(bare, listed, "child-a"));
    expect(sideEffects(bare, parent.id)).toEqual(before);
  });

  it("an explicit list keeps deciding: a list-origin entry admits the actor it names and refuses another, without asking the policy", async () => {
    const parent = approve(hooked, [lEntry()]);
    expect(parent.child_actor_provenance).toEqual(["list"]);
    await refused(await createChild(hooked, parent, "child-b", { proposal: [lChildEntry()] }));
    await created(hooked, await createChild(hooked, parent, "child-l", { proposal: [lChildEntry()] }));
    expect(asked).toHaveLength(0);
  });

  it("an explicit list keeps deciding under the reference default: no default-deny is imposed on a list-origin entry", async () => {
    const parent = approve(bare, [lEntry()]);
    await created(bare, await createChild(bare, parent, "child-l", { proposal: [lChildEntry()] }));
  });

  it("an explicit empty list admits nobody, whether the entry defers to policy or its list decides", async () => {
    const deferring = approve(hooked, [pEntry({ allowed_child_actors: [] })]);
    expect(deferring.child_actor_provenance).toEqual(["policy"]);
    permits.creation.add("child-a");
    await refused(await createChild(hooked, deferring, "child-a"));
    const listed = approve(hooked, [
      { ...lEntry(), delegation: { max_depth: 2, children: { allowed_child_actors: [] } } as AuthorityEntry["delegation"] },
    ]);
    expect((listed.authority_set[0]?.delegation?.children as Children).allowed_child_actors).toEqual([]);
    await refused(await createChild(hooked, listed, "child-l", { proposal: [lChildEntry()] }));
    expect(sideEffects(hooked, deferring.id).children + sideEffects(hooked, listed.id).children).toBe(0);
  });

  describe("unresolved provenance fails closed (no fallback to the list, nor to the delegate origin)", () => {
    for (const [label, stored] of [
      ["missing", null],
      ["unreadable", "{not json"],
      ["an unknown value", JSON.stringify(["maybe"])],
      ["misaligned with the Authority Set", JSON.stringify(["policy", "policy"])],
    ] as const) {
      it(`${label}: refused although the list and the policy permit, and the policy is not asked`, async () => {
        const parent = approve(hooked, [pEntry({ allowed_child_actors: [{ sub: "child-a" }] })]);
        hooked.as.kernel.db
          .prepare("UPDATE missions SET child_actor_provenance_json = ? WHERE id = ?")
          .run(stored, parent.id);
        // The delegate origin is intact and says nothing about child actors.
        expect(hooked.as.kernel.get(parent.id)?.eligibility_provenance).toEqual(["list"]);
        permits.creation.add("child-a");
        const before = sideEffects(hooked, parent.id);
        // The list and the policy both permit child-a, and the policy is never
        // asked: only the unresolved origin refuses.
        await refused(await createChild(hooked, parent, "child-a"));
        expect(sideEffects(hooked, parent.id)).toEqual(before);
        expect(asked).toHaveLength(0);
      });
    }
  });

  it("multiple retained origins: the first-in-order justifying entry's policy origin governs, and a list-origin overlap never lends it eligibility", async () => {
    const parent = approve(
      hooked,
      [
        {
          type: MRA,
          resource: REPORTS,
          actions: ["reports:report.read", "reports:report.write"],
          delegation: { max_depth: 2, children: { allowed_child_actors: [{ sub: "child-a" }] } } as AuthorityEntry["delegation"],
        },
      ],
      [REPORTS],
    );
    expect(parent.authority_set.map((e) => e.actions)).toEqual([
      ["reports:report.read", "reports:report.write"],
      ["reports:report.read"],
    ]);
    expect(parent.child_actor_provenance).toEqual(["policy", "list"]);
    const reportsChild: AuthorityEntry[] = [
      {
        type: MRA,
        resource: REPORTS,
        actions: ["reports:report.read"],
        delegation: { max_depth: 1, children: { max_children: 1, max_child_depth: 1, allowed_child_actors: [] } } as AuthorityEntry["delegation"],
      },
    ];
    // The list-origin overlap names child-a, but the child entry is attributed
    // to the first entry, whose origin is policy: the policy must permit too.
    await refused(await createChild(hooked, parent, "child-a", { proposal: reportsChild }));
    expect(creationAsks().at(-1)?.approved.actions).toEqual(["reports:report.read", "reports:report.write"]);
    permits.creation.add("child-a");
    const child = await created(hooked, await createChild(hooked, parent, "child-a", { proposal: reportsChild }));
    // Each child entry keeps every origin it falls within: policy and list combine to policy.
    expect(child.child_actor_provenance).toEqual(["policy", "policy"]);
  });

  describe("a later generation's list only restricts the origin it inherits", () => {
    it("a Child Mission whose proposal added a list over a policy-deferring parent entry creates a grandchild only where the policy and that list both permit", async () => {
      const root = approve(hooked, [pEntry()]);
      permits.creation.add("child-a");
      const child = kernelChild(hooked, root.id, "child-a", [
        childEntry({ max_children: 1, max_child_depth: 2, allowed_child_actors: [{ sub: "gc-a" }] }),
      ]);
      expect((child.authority_set[0]?.delegation?.children as Children).allowed_child_actors).toEqual([{ sub: "gc-a" }]);
      expect(child.child_actor_provenance).toEqual(["policy"]);
      const token = () => accessToken(hooked, child, childClient);
      const before = sideEffects(hooked, child.id);
      // The child's list names gc-a, the policy denies it.
      await refused(await createChild(hooked, child, "gc-a", { client: childClient, token: await token() }));
      expect(creationAsks().at(-1)).toMatchObject({ parent: { id: child.id }, child_actor: { sub: "gc-a" }, depth: 2 });
      // The policy permits gc-b, the child's list omits it.
      permits.creation.add("gc-b");
      await refused(await createChild(hooked, child, "gc-b", { client: childClient, token: await token() }));
      expect(sideEffects(hooked, child.id)).toEqual(before);
      permits.creation.add("gc-a");
      const grandchild = await created(
        hooked,
        await createChild(hooked, child, "gc-a", { client: childClient, token: await token() }),
      );
      expect(grandchild.parent).toMatchObject({ id: child.id, depth: 2 });
    });
  });

  describe("the presented token's restrictions", () => {
    it("a list the presented token carries restricts the policy decision: refused where it omits the actor, created where it names it", async () => {
      const parent = approve(hooked, [pEntry()]);
      permits.creation.add("child-a");
      const withList = (actors: unknown[]) =>
        accessToken(hooked, parent, hooked.agent, [
          pEntry({ max_children: 1, max_child_depth: 2, allowed_child_actors: actors }),
        ].map((e) => ({ ...e, delegation: { ...e.delegation, allowed_delegates: [{ sub_profile: "ai_agent" }] } as AuthorityEntry["delegation"] })));
      const before = sideEffects(hooked, parent.id);
      await refused(await createChild(hooked, parent, "child-a", { token: await withList([{ sub: "child-b" }]) }));
      await refused(await createChild(hooked, parent, "child-a", { token: await withList([]) }));
      expect(sideEffects(hooked, parent.id)).toEqual(before);
      await created(hooked, await createChild(hooked, parent, "child-a", { token: await withList([{ sub: "child-a" }]) }));
    });

    it("a presented token without a list defers to the policy only under a policy-origin parent entry", async () => {
      // Under the policy origin the parent's own token (no list) creates once the policy permits.
      const deferring = approve(hooked, [pEntry()]);
      await refused(await createChild(hooked, deferring, "child-a"));
      permits.creation.add("child-a");
      await created(hooked, await createChild(hooked, deferring, "child-a"));
      // Under the list origin a token entry without a list still denies, though the parent's list names the actor.
      const listed = approve(hooked, [lEntry()]);
      const bareToken = await accessToken(
        hooked,
        listed,
        hooked.agent,
        listed.authority_set.map((e) => ({
          ...e,
          delegation: { ...e.delegation, children: { max_children: 5, max_child_depth: 2 } } as AuthorityEntry["delegation"],
        })),
      );
      await refused(await createChild(hooked, listed, "child-l", { proposal: [lChildEntry()], token: bareToken }));
    });
  });

  it("recovery re-establishes the rule: a completed creation is redelivered only while the policy still permits the actor", async () => {
    const parent = approve(hooked, [pEntry({ allowed_child_actors: [{ sub: "child-a" }] })]);
    permits.creation.add("child-a");
    const token = await accessToken(hooked, parent, hooked.agent);
    const creationRequestId = crypto.randomUUID();
    const first = await created(hooked, await createChild(hooked, parent, "child-a", { token, creationRequestId }));
    permits.creation.delete("child-a");
    const reason = await refused(await createChild(hooked, parent, "child-a", { token, creationRequestId }));
    expect(reason).toMatch(/does not authorize the recorded child/);
    expect(hooked.as.kernel.findChildren(parent.id)).toHaveLength(1);
    permits.creation.add("child-a");
    const again = await created(hooked, await createChild(hooked, parent, "child-a", { token, creationRequestId }));
    expect(again.id).toBe(first.id);
  });
});

describe("child-actor eligibility at Child Mission Carryover (@spec child-delegation#fanout, #carryover-generations, #1304)", () => {
  /** A predecessor under the payments read entry (no list) with one child, carry-a, created while the policy permits it. */
  function predecessorWithChild(): { predecessor: MissionRecord; child: MissionRecord } {
    const predecessor = approve(hooked, [pEntry()]);
    permits.creation.add("carry-a");
    const child = kernelChild(hooked, predecessor.id, "carry-a", [childEntry()]);
    permits.creation.clear();
    asked.length = 0;
    return { predecessor, child };
  }

  describe("the successor entry defers the child actor to policy, with a list the expansion's proposal added", () => {
    const successorRead = () => pEntry({ allowed_child_actors: [{ sub: "carry-a" }] });

    it("policy denies, list permits: the child is rendered and committed as a cascade, with no replacement", async () => {
      const { predecessor, child } = predecessorWithChild();
      const code = await openExpansion(hooked, predecessor, successorRead());
      const manifest = manifestOf(hooked, code);
      expect(rowOf(manifest, child.id)).toMatchObject({ outcome: "cascade", reason: "child_actor_not_allowed" });
      expect(carryoverAsks().at(-1)).toMatchObject({
        operation: "carryover",
        parent: { id: manifest.successor.mission_id },
        child_actor: { sub: "carry-a" },
        depth: 1,
      });
      const done = await completed(await poll(hooked, code));
      // The successor retains its policy origin and the list the expansion's proposal added.
      const successor = hooked.as.kernel.get(done.mission_id);
      expect(successor?.child_actor_provenance?.[0]).toBe("policy");
      expect((successor?.authority_set[0]?.delegation?.children as Children).allowed_child_actors).toEqual([{ sub: "carry-a" }]);
      notCarried(hooked, child.id);
    });

    it("policy permits, list omits: cascaded with no replacement", async () => {
      const { predecessor, child } = predecessorWithChild();
      permits.carryover.add("carry-a");
      const code = await openExpansion(hooked, predecessor, pEntry({ allowed_child_actors: [{ sub: "other-agent" }] }));
      expect(rowOf(manifestOf(hooked, code), child.id)).toMatchObject({ outcome: "cascade", reason: "child_actor_not_allowed" });
      await completed(await poll(hooked, code));
      notCarried(hooked, child.id);
    });

    it("policy and list both permit: carried, asked at rendering and again at the completion commit, the replacement keeping the policy origin", async () => {
      const { predecessor, child } = predecessorWithChild();
      permits.carryover.add("carry-a");
      const code = await openExpansion(hooked, predecessor, successorRead());
      expect(rowOf(manifestOf(hooked, code), child.id)?.outcome).toBe("carry");
      const done = await completed(await poll(hooked, code));
      const replacement = carried(hooked, child.id, done.mission_id);
      expect(carryoverAsks()).toHaveLength(2);
      expect(replacement.child_actor_provenance).toEqual(["policy"]);
    });
  });

  it("the policy is asked again at the completion commit: a permit given at rendering that is withdrawn before completion fails the whole batch", async () => {
    const { predecessor, child } = predecessorWithChild();
    permits.carryover.add("carry-a");
    const code = await openExpansion(hooked, predecessor, pEntry());
    const manifest = manifestOf(hooked, code);
    expect(rowOf(manifest, child.id)?.outcome).toBe("carry");
    permits.carryover.delete("carry-a");
    const res = await poll(hooked, code);
    const body = (await res.json()) as { error?: string; access_token?: string };
    expect(body.error, JSON.stringify(body)).toBe("access_denied");
    expect(body).not.toHaveProperty("access_token");
    // Nothing committed: no successor, no replacement, the old subtree untouched.
    expect(hooked.as.kernel.get(manifest.successor.mission_id)).toBeUndefined();
    expect(hooked.as.kernel.get(predecessor.id)?.state).toBe("active");
    expect(hooked.as.kernel.get(child.id)?.state).toBe("active");
    expect(hooked.as.kernel.allMissions().some((m) => m.related_to === child.id)).toBe(false);
    expect(carryoverAsks()).toHaveLength(2);
  });

  it("an absent list on the successor entry defers to the policy: cascaded while it permits nobody", async () => {
    const { predecessor, child } = predecessorWithChild();
    const code = await openExpansion(hooked, predecessor, pEntry());
    expect(rowOf(manifestOf(hooked, code), child.id)).toMatchObject({ outcome: "cascade", reason: "child_actor_not_allowed" });
    await completed(await poll(hooked, code));
    notCarried(hooked, child.id);
  });

  it("an explicit empty list on the successor entry admits nobody, though the policy permits the actor", async () => {
    const { predecessor, child } = predecessorWithChild();
    permits.carryover.add("carry-a");
    const code = await openExpansion(hooked, predecessor, pEntry({ allowed_child_actors: [] }));
    expect(rowOf(manifestOf(hooked, code), child.id)).toMatchObject({ outcome: "cascade", reason: "child_actor_not_allowed" });
    await completed(await poll(hooked, code));
    notCarried(hooked, child.id);
  });

  it("an explicit list keeps deciding at carryover: a list-origin child is carried without asking the policy", async () => {
    const predecessor = approve(hooked, [lEntry()]);
    const child = kernelChild(hooked, predecessor.id, "child-l", [lChildEntry()]);
    const code = await openExpansion(hooked, predecessor, lEntry());
    expect(rowOf(manifestOf(hooked, code), child.id)?.outcome).toBe("carry");
    const done = await completed(await poll(hooked, code));
    expect(carried(hooked, child.id, done.mission_id).child_actor_provenance).toEqual(["list"]);
    expect(asked).toHaveLength(0);
  });

  it("an explicit list keeps deciding at carryover under the reference default: no default-deny is imposed on a list-origin child", async () => {
    const predecessor = approve(bare, [lEntry()]);
    const child = kernelChild(bare, predecessor.id, "child-l", [lChildEntry()]);
    const code = await openExpansion(bare, predecessor, lEntry());
    expect(rowOf(manifestOf(bare, code), child.id)?.outcome).toBe("carry");
    const done = await completed(await poll(bare, code));
    carried(bare, child.id, done.mission_id);
  });

  describe("a deeper generation inherits through its replacement parent", () => {
    /** A predecessor, a child carry-a whose proposal names gc-a, and a grandchild gc-a, created while the policy permits both. */
    function subtree(): { predecessor: MissionRecord; child: MissionRecord; grandchild: MissionRecord } {
      const predecessor = approve(hooked, [pEntry()]);
      permits.creation.add("carry-a").add("gc-a");
      const child = kernelChild(hooked, predecessor.id, "carry-a", [
        childEntry({ max_children: 1, max_child_depth: 2, allowed_child_actors: [{ sub: "gc-a" }] }),
      ]);
      const grandchild = kernelChild(hooked, child.id, "gc-a", [childEntry()]);
      permits.creation.clear();
      asked.length = 0;
      return { predecessor, child, grandchild };
    }

    it("multiple retained origins: the grandchild is carried only where the policy and its replacement parent's list both permit", async () => {
      const denied = subtree();
      permits.carryover.add("carry-a");
      const code = await openExpansion(hooked, denied.predecessor, pEntry());
      const manifest = manifestOf(hooked, code);
      expect(rowOf(manifest, denied.child.id)?.outcome).toBe("carry");
      // The replacement parent's list names gc-a; the policy denies it.
      expect(rowOf(manifest, denied.grandchild.id)).toMatchObject({ outcome: "cascade", reason: "child_actor_not_allowed" });
      await completed(await poll(hooked, code));
      notCarried(hooked, denied.grandchild.id);

      const permitted = subtree();
      permits.carryover.add("carry-a").add("gc-a");
      const code2 = await openExpansion(hooked, permitted.predecessor, pEntry());
      const done = await completed(await poll(hooked, code2));
      const childReplacement = carried(hooked, permitted.child.id, done.mission_id);
      expect(childReplacement.child_actor_provenance).toEqual(["policy"]);
      carried(hooked, permitted.grandchild.id, childReplacement.id);
    });

    it("missing provenance: a replacement parent that inherits an unresolved origin carries no grandchild, and the policy is not asked for it", async () => {
      const { predecessor, child, grandchild } = subtree();
      hooked.as.kernel.db.prepare("UPDATE missions SET child_actor_provenance_json = NULL WHERE id = ?").run(child.id);
      permits.carryover.add("carry-a").add("gc-a");
      const code = await openExpansion(hooked, predecessor, pEntry());
      const manifest = manifestOf(hooked, code);
      // The child itself is gated against the successor's own retained origins.
      expect(rowOf(manifest, child.id)?.outcome).toBe("carry");
      expect(rowOf(manifest, grandchild.id)).toMatchObject({ outcome: "cascade", reason: "child_actor_not_allowed" });
      expect(carryoverAsks().some((r) => r.child_actor.sub === "gc-a")).toBe(false);
      const done = await completed(await poll(hooked, code));
      // No permissive backfill: the replacement retains the unresolved origin.
      expect(carried(hooked, child.id, done.mission_id).child_actor_provenance).toEqual([null]);
      notCarried(hooked, grandchild.id);
    });
  });
});
