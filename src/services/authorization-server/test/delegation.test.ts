/**
 * Token-level integration tests for M2 delegated issuance: mint real Client
 * Instance Assertions with jose, validate them, and construct conformant
 * delegation chains. Covers the M2 exit criteria (rejection of an
 * actor_token carrying `act`; conformant chain construction; instance claims).
 */

import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { flattenActChain } from "@mission/actor-chain";
import type { AuthorityEntry } from "../src/index.js";
import {
  constructDelegatedIssuance,
  delegatedContextActor,
  gateDelegableAuthority,
} from "../src/kernel/delegation.js";
import {
  CLIENT_INSTANCE_JWT_TYP,
  InstanceAssertionError,
  type InstanceIssuer,
  newReplayCache,
  validateInstanceAssertion,
} from "../src/kernel/instance-assertion.js";

const AS = "https://as.test";
const ATTESTER = "https://attester.agents.example";

let instanceKeys: { privateKey: CryptoKey; publicKey: CryptoKey };
let instanceJkt: string;
let issuers: InstanceIssuer[];

beforeAll(async () => {
  instanceKeys = await generateKeyPair("ES256", { extractable: true });
  const pub = await exportJWK(instanceKeys.publicKey);
  pub.kid = "inst-key";
  instanceJkt = await calculateJwkThumbprint(pub);
  issuers = [{ iss: ATTESTER, jwks: { keys: [pub] } }];
});

async function mintAssertion(over: Record<string, unknown> = {}, omit: string[] = []): Promise<string> {
  const base: Record<string, unknown> = {
    sub: "inst-sess-9f2c",
    client_id: "ap-agent",
    agent_instance_id: "inst-sess-9f2c",
    sub_profile: "ai_agent client_instance",
    cnf: { jkt: instanceJkt },
    agent_model: { id: "urn:example:model:atlas", version: "7.3" },
    ...over,
  };
  for (const k of omit) delete base[k];
  const jwt = new SignJWT(base)
    .setProtectedHeader({ alg: "ES256", kid: "inst-key", typ: CLIENT_INSTANCE_JWT_TYP })
    .setIssuer(ATTESTER)
    .setAudience(AS)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID());
  return jwt.sign(instanceKeys.privateKey);
}

const validateCtx = () => ({
  audience: AS,
  clientId: "ap-agent",
  issuers,
  presenterJkt: instanceJkt,
  replay: newReplayCache(),
});

describe("instance assertion validation (@spec cia-core / ai-agent-instance)", () => {
  it("validates a well-formed assertion and surfaces instance identity", async () => {
    const inst = await validateInstanceAssertion(await mintAssertion(), validateCtx());
    expect(inst.agentInstanceId).toBe("inst-sess-9f2c");
    expect(inst.subProfile).toBe("ai_agent client_instance");
    expect(inst.cnf.jkt).toBe(instanceJkt);
    expect(inst.agentModel?.id).toBe("urn:example:model:atlas");
  });

  it("rejects an assertion that carries act (MUST NOT)", async () => {
    const withAct = await mintAssertion({ act: { iss: AS, sub: "x" } });
    await expect(validateInstanceAssertion(withAct, validateCtx())).rejects.toMatchObject({
      code: "invalid_grant",
    });
  });

  it("rejects client_id mismatch, missing agent_instance_id, and sub != agent_instance_id", async () => {
    await expect(
      validateInstanceAssertion(await mintAssertion({ client_id: "other" }), validateCtx()),
    ).rejects.toThrow(/client_id/);
    await expect(
      validateInstanceAssertion(await mintAssertion({}, ["agent_instance_id"]), validateCtx()),
    ).rejects.toThrow(/agent_instance_id/);
    await expect(
      validateInstanceAssertion(await mintAssertion({ sub: "different" }), validateCtx()),
    ).rejects.toThrow(/sub must equal agent_instance_id/);
  });

  it("rejects a missing per-instance cnf and a presenter-key mismatch", async () => {
    await expect(
      validateInstanceAssertion(await mintAssertion({}, ["cnf"]), validateCtx()),
    ).rejects.toThrow(/cnf/);
    await expect(
      validateInstanceAssertion(await mintAssertion(), { ...validateCtx(), presenterJkt: "different-jkt" }),
    ).rejects.toMatchObject({ code: "invalid_request" });
  });

  it("rejects replay of the same (iss, jti)", async () => {
    const replay = newReplayCache();
    const assertion = await mintAssertion();
    const ctx = { audience: AS, clientId: "ap-agent", issuers, presenterJkt: instanceJkt, replay };
    const inst = await validateInstanceAssertion(assertion, ctx);
    replay.record(inst.iss, jtiOf(assertion));
    await expect(validateInstanceAssertion(assertion, ctx)).rejects.toThrow(/replay/);
  });

  it("rejects an unknown instance issuer", async () => {
    const other = { ...validateCtx(), issuers: [] as InstanceIssuer[] };
    await expect(validateInstanceAssertion(await mintAssertion(), other)).rejects.toThrow(/unknown instance issuer/);
  });
});

describe("delegated chain construction (@spec actor-profile#delegation-chains, O-27)", () => {
  it("self-acting subject: new actor is a depth-1 chain, cnf rebinds to the instance", async () => {
    const inst = await validateInstanceAssertion(await mintAssertion(), validateCtx());
    const issuance = constructDelegatedIssuance({ instance: inst, subjectSub: "alice" });
    expect(issuance.sub).toBe("alice");
    expect(issuance.cnf.jkt).toBe(instanceJkt);
    const flat = flattenActChain(issuance.act);
    expect(flat).toHaveLength(1);
    expect(flat[0]?.sub).toBe("inst-sess-9f2c");
    // act.cnf equals top-level cnf by construction (D21).
    expect((issuance.act.cnf as { jkt: string }).jkt).toBe(instanceJkt);
  });

  it("sub-agent spawn: instance becomes outermost over the inbound chain (presenter rebind)", async () => {
    const inst = await validateInstanceAssertion(await mintAssertion(), validateCtx());
    const inbound = { iss: AS, sub: "orchestrator", sub_profile: "ai_agent" };
    const issuance = constructDelegatedIssuance({ instance: inst, subjectSub: "alice", inboundAct: inbound });
    const actor = delegatedContextActor(issuance, "ap-agent");
    expect(actor.act?.map((e) => e.sub)).toEqual(["orchestrator", "inst-sess-9f2c"]);
    expect(actor.client_instance_id).toBe("inst-sess-9f2c");
  });

  it("rejects a resulting chain exceeding the local maximum depth (no truncation)", async () => {
    const inst = await validateInstanceAssertion(await mintAssertion(), validateCtx());
    const deepInbound = { iss: AS, sub: "a", act: { iss: AS, sub: "b", act: { iss: AS, sub: "c", act: { iss: AS, sub: "d" } } } };
    expect(() =>
      constructDelegatedIssuance({ instance: inst, subjectSub: "alice", inboundAct: deepInbound }),
    ).toThrow(InstanceAssertionError);
  });
});

function jtiOf(jwt: string): string {
  return JSON.parse(Buffer.from(jwt.split(".")[1] as string, "base64url").toString()).jti as string;
}

// ---------------------------------------------------------------------------
// The core allowed_delegates runtime gate (@spec oauth-mission#per-entry-enforcement).
// ---------------------------------------------------------------------------

const entry = (over: Partial<AuthorityEntry>): AuthorityEntry => ({
  type: "mission_resource_access",
  resource: "https://api.example/mcp",
  actions: ["read"],
  ...over,
});

// The validated instance surfaces sub_profile "ai_agent client_instance", AS-asserted.
const aiAgentDelegate = { sub: "ap-agent", assertedProfile: "ai_agent client_instance" };

describe("gateDelegableAuthority — core allowed_delegates enforcement (@spec per-entry-enforcement)", () => {
  it("(1) narrows out an entry that carries NO delegation member (non-delegable default)", () => {
    expect(gateDelegableAuthority([entry({})], aiAgentDelegate, 1)).toEqual([]);
  });

  it("(2) narrows out an entry when depth EXCEEDS delegation.max_depth", () => {
    const e = entry({ delegation: { max_depth: 1, allowed_delegates: [{ sub_profile: "ai_agent" }] } });
    expect(gateDelegableAuthority([e], aiAgentDelegate, 2)).toEqual([]); // depth 2 > max_depth 1
    expect(gateDelegableAuthority([e], aiAgentDelegate, 1)).toHaveLength(1); // depth 1 <= 1
  });

  it("(3) includes an entry when the delegate matches allowed_delegates by sub_profile MEMBERSHIP", () => {
    const e = entry({ delegation: { max_depth: 2, allowed_delegates: [{ sub_profile: "ai_agent" }] } });
    expect(gateDelegableAuthority([e], aiAgentDelegate, 1)).toEqual([e]);
  });

  it("(3) an ABSENT allowed_delegates list DENIES the entry (fail-closed, never blanket-grant)", () => {
    const e = entry({ delegation: { max_depth: 2 } }); // delegation present, no allowed_delegates
    expect(gateDelegableAuthority([e], aiAgentDelegate, 1)).toEqual([]);
  });

  it("a { sub } matcher permits by CLIENT IDENTIFIER (the delegate's sub), and rejects a different sub", () => {
    const e = entry({ delegation: { max_depth: 2, allowed_delegates: [{ sub: "ap-agent" }] } });
    expect(gateDelegableAuthority([e], aiAgentDelegate, 1)).toEqual([e]);
    expect(gateDelegableAuthority([e], { sub: "other-client" }, 1)).toEqual([]);
  });

  it("a SELF-ASSERTED profile (no asserted class) does NOT satisfy a sub_profile matcher", () => {
    const e = entry({ delegation: { max_depth: 2, allowed_delegates: [{ sub_profile: "ai_agent" }] } });
    expect(gateDelegableAuthority([e], { sub: "ap-agent" }, 1)).toEqual([]);
  });

  it("filters a mixed set to only the entries this delegate may carry", () => {
    const ok = entry({
      resource: "https://a.example/mcp",
      delegation: { max_depth: 2, allowed_delegates: [{ sub_profile: "ai_agent" }] },
    });
    const nonDelegable = entry({ resource: "https://b.example/mcp" });
    const wrongClass = entry({
      resource: "https://c.example/mcp",
      delegation: { max_depth: 2, allowed_delegates: [{ sub_profile: "human" }] },
    });
    expect(gateDelegableAuthority([ok, nonDelegable, wrongClass], aiAgentDelegate, 1)).toEqual([ok]);
  });
});

describe("constructDelegatedIssuance — authority narrowing + empty-result refusal (@spec per-entry-enforcement, empty-result)", () => {
  it("narrows the delegated authority to the entries the delegate may carry", async () => {
    const inst = await validateInstanceAssertion(await mintAssertion(), validateCtx());
    const authoritySet = [
      entry({
        resource: "https://a.example/mcp",
        delegation: { max_depth: 2, allowed_delegates: [{ sub_profile: "ai_agent" }] },
      }),
      entry({ resource: "https://b.example/mcp" }), // non-delegable
    ];
    const issuance = constructDelegatedIssuance({ instance: inst, subjectSub: "alice", authoritySet });
    expect(issuance.delegatedAuthority).toHaveLength(1);
    expect(issuance.delegatedAuthority?.[0]?.resource).toBe("https://a.example/mcp");
  });

  it("refuses with invalid_target when narrowing leaves NO authority (empty result)", async () => {
    const inst = await validateInstanceAssertion(await mintAssertion(), validateCtx());
    // Only a non-delegable entry: the delegate can carry nothing.
    const authoritySet = [entry({ resource: "https://b.example/mcp" })];
    expect(() => constructDelegatedIssuance({ instance: inst, subjectSub: "alice", authoritySet })).toThrow(
      /invalid_target|empty authority/,
    );
    try {
      constructDelegatedIssuance({ instance: inst, subjectSub: "alice", authoritySet });
    } catch (e) {
      expect((e as InstanceAssertionError).code).toBe("invalid_target");
    }
  });

  it("omits delegatedAuthority entirely when no authoritySet is supplied (unchanged act-chain path)", async () => {
    const inst = await validateInstanceAssertion(await mintAssertion(), validateCtx());
    const issuance = constructDelegatedIssuance({ instance: inst, subjectSub: "alice" });
    expect(issuance.delegatedAuthority).toBeUndefined();
  });
});
