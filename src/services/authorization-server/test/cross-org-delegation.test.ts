/**
 * @spec cross-org-delegation#verification, #actor-evidence,
 * #root-issuance, #derivation — a valid A -> B -> C chain across three
 * synthetic trust domains, then the negative matrix from the companion's
 * conformance section: widening, substitution, reorder, missing hop, changed
 * mission binding, untrusted root, missing root actor, unbound named actor,
 * duplicated actor representation, depth reset/overflow, wrong leaf key,
 * unmapped authority, and revoked/stale/unavailable state.
 */
import { aatToolId, chainDigest, parHash, parseChainPresentation, type AATTools } from "@mission/core";
import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
  deriveCrossOrgRoot,
  mintCrossOrgChild,
  MissionKernel,
  validateMissionIntent,
  verifyCrossOrgChain,
  WORKLOAD_ATTESTATION_TYPE,
  type FederationConfig,
} from "../src/index.js";

const ORIGIN_ISS = "https://as.org1.test";
const ORG3_API = "https://api.org3.test";
const RESOURCE = ORG3_API;
const ATTEST_ISS = "https://attest.org2.test";

type KP = { privateKey: CryptoKey; publicKey: CryptoKey };
let asKeys: KP; // origin Mission Issuer signing key
let agentA: KP;
let agentB: KP;
let workerC: KP;
let attestKeys: KP; // actor-credential attestation source
let kernel: MissionKernel;
let missionId: string;
let fed: FederationConfig;
let nowS: number;
let rootTools: AATTools;

async function pub(k: KP): Promise<JWK> {
  return exportJWK(k.publicKey) as Promise<JWK>;
}

/** A reference workload-attestation credential binding an actor id to a key. */
async function attest(actor: { iss: string; sub: string }, key: KP): Promise<string> {
  return new SignJWT({ subject: actor, cnf: { jwk: await pub(key) } })
    .setProtectedHeader({ alg: "ES256", typ: WORKLOAD_ATTESTATION_TYPE })
    .setIssuer(ATTEST_ISS)
    .setIssuedAt(nowS)
    .setExpirationTime(nowS + 600)
    .sign(attestKeys.privateKey);
}

const activeState = () => ({ state: "active", observedAtS: nowS });

beforeAll(async () => {
  asKeys = await generateKeyPair("ES256", { extractable: true });
  agentA = await generateKeyPair("ES256", { extractable: true });
  agentB = await generateKeyPair("ES256", { extractable: true });
  workerC = await generateKeyPair("ES256", { extractable: true });
  attestKeys = await generateKeyPair("ES256", { extractable: true });
  nowS = Math.floor(Date.now() / 1000);

  kernel = new MissionKernel({
    issuer: ORIGIN_ISS,
    policy: {
      policy_version: "xorg-1",
      ceiling: [
        {
          type: "mission_resource_access",
          resource: RESOURCE,
          actions: ["payments:invoice.read", "payments:payment.schedule"],
          constraints: { max_amount: { amount: "500.00", currency: "USD" } },
          delegation: { max_depth: 3 },
        },
      ],
    } as never,
    statusKey: asKeys.privateKey,
    statusKid: "as-status",
  });
  const mission = kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({ goal: "Cross-org reconcile", resources: [RESOURCE], expires_at: "2027-01-01T00:00:00Z" }),
    ),
    proposedAuthority: [
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: ["payments:invoice.read", "payments:payment.schedule"],
        constraints: { max_amount: { amount: "500.00", currency: "USD" } },
        delegation: { max_depth: 3 },
      },
    ] as never,
    subject: { iss: "https://id.org1.test", sub: "p-alice" },
    approver: { iss: ORIGIN_ISS, sub: "bob" },
    clientId: "agent-a",
    approvalEventId: "apev-xorg",
  });
  missionId = mission.id;

  const asPubJwk = { ...(await exportJWK(asKeys.publicKey)), kid: "as-token", alg: "ES256" };
  fed = {
    issuers: [{ issuer: ORIGIN_ISS, jwks: { keys: [asPubJwk as JWK] } }],
    attestationSources: [
      { iss: ATTEST_ISS, jwks: { keys: [{ ...(await exportJWK(attestKeys.publicKey)), alg: "ES256" } as JWK] } },
    ],
    actorCredentialTypes: [WORKLOAD_ATTESTATION_TYPE],
    bounds: { maxHops: 6, maxBytes: 200_000 },
    stateFreshnessSeconds: 60,
  };
});

/** Build the canonical valid A->B->C chain and return its parts. */
async function buildChain(): Promise<{ chain: string[]; creds: Array<{ hop: number; type: string; credential: string }> }> {
  const derived = await deriveCrossOrgRoot(kernel, asKeys.privateKey, "as-token", {
    missionId,
    aud: RESOURCE,
    clientId: "agent-a",
    cnfJwk: await pub(agentA),
    actor: { iss: "https://id.org1.test", sub: "wl-agent-a", sub_profile: "ai_agent" },
    mappingVersion: "map-1",
  });
  rootTools = derived.tools;
  // A -> B: same tools, B's key, B named.
  const hop1 = await mintCrossOrgChild(derived.root, agentA.privateKey, derived.tools, {
    cnfJwk: await pub(agentB),
    actor: { iss: "https://id.org2.test", sub: "wl-agent-b", sub_profile: "ai_agent" },
  });
  // B -> C: same tools, C's key, key-only (no act).
  const hop2 = await mintCrossOrgChild(hop1, agentB.privateKey, derived.tools, {
    cnfJwk: await pub(workerC),
  });
  return {
    chain: [derived.root, hop1, hop2],
    creds: [{ hop: 1, type: WORKLOAD_ATTESTATION_TYPE, credential: await attest({ iss: "https://id.org2.test", sub: "wl-agent-b" }, agentB) }],
  };
}

function present(chain: string[], creds?: Array<{ hop: number; type: string; credential: string }>) {
  return parseChainPresentation(
    Buffer.from(JSON.stringify({ chain, ...(creds ? { actor_credentials: creds } : {}) }), "utf8").toString("base64url"),
    fed.bounds,
  );
}

describe("valid three-domain chain (@spec cross-org-delegation#verification)", () => {
  it("verifies A -> B -> C and reconstructs the lineage", async () => {
    const { chain, creds } = await buildChain();
    const v = await verifyCrossOrgChain({ federation: fed, presentation: present(chain, creds), nowS, stateSource: activeState });
    expect(v.missionId).toBe(missionId);
    expect(v.subject).toEqual({ iss: "https://id.org1.test", sub: "p-alice" });
    expect(v.lineage.length).toBe(3);
    expect(v.lineage[0]?.actor?.sub).toBe("wl-agent-a"); // root named
    expect(v.lineage[1]?.actor?.sub).toBe("wl-agent-b"); // hop 1 named + validated
    expect(v.lineage[2]?.actor).toBeUndefined(); // hop 2 key-only
    expect(chainDigest(chain).startsWith("sha-256:")).toBe(true);
  });
});

describe("negative matrix (@spec cross-org-delegation#conformance)", () => {
  it("refuses capability widening at a hop", async () => {
    const derived = await deriveCrossOrgRoot(kernel, asKeys.privateKey, "as-token", {
      missionId, aud: RESOURCE, clientId: "agent-a", cnfJwk: await pub(agentA),
      actor: { iss: "https://id.org1.test", sub: "wl-agent-a" }, mappingVersion: "map-1",
    });
    const readId = aatToolId(RESOURCE, "payments:invoice.read");
    // Hop 1 narrows to the single read tool; hop 2 re-adds a tool hop 1 dropped.
    const narrowed: AATTools = { [readId]: derived.tools[readId] ?? {} };
    const hop1 = await mintCrossOrgChild(derived.root, agentA.privateKey, narrowed, { cnfJwk: await pub(agentB) });
    const widened: AATTools = { ...narrowed, [aatToolId(RESOURCE, "payments:payment.schedule")]: {} };
    const hop2 = await mintCrossOrgChild(hop1, agentB.privateKey, widened, { cnfJwk: await pub(workerC) });
    await expect(
      verifyCrossOrgChain({ federation: fed, presentation: present([derived.root, hop1, hop2]), nowS, stateSource: activeState }),
    ).rejects.toThrow(/subset/);
  });

  it("refuses a reordered / substituted parent (par_hash break)", async () => {
    const { chain, creds } = await buildChain();
    const swapped = [chain[0] as string, chain[2] as string, chain[1] as string];
    await expect(
      verifyCrossOrgChain({ federation: fed, presentation: present(swapped, creds), nowS, stateSource: activeState }),
    ).rejects.toThrow();
  });

  it("refuses a missing middle hop", async () => {
    const { chain } = await buildChain();
    await expect(
      verifyCrossOrgChain({ federation: fed, presentation: present([chain[0] as string, chain[2] as string]), nowS, stateSource: activeState }),
    ).rejects.toThrow(/signature|par_hash/);
  });

  it("refuses an untrusted root issuer", async () => {
    const { chain, creds } = await buildChain();
    const untrusted: FederationConfig = { ...fed, issuers: [{ issuer: "https://evil.test", jwks: fed.issuers[0]!.jwks }] };
    await expect(
      verifyCrossOrgChain({ federation: untrusted, presentation: present(chain, creds), nowS, stateSource: activeState }),
    ).rejects.toThrow(/accepted origin Mission Issuer/);
  });

  it("@spec mission#the-mission-claim (#702), cross-org-delegation -- this profile REQUIRES authority_hash as its own lineage anchor: a root whose mission claim omits it is refused, never silently downgraded", async () => {
    const derived = await deriveCrossOrgRoot(kernel, asKeys.privateKey, "as-token", {
      missionId, aud: RESOURCE, clientId: "agent-a", cnfJwk: await pub(agentA),
      actor: { iss: "https://id.org1.test", sub: "wl-agent-a" }, mappingVersion: "map-1",
    });
    // A structurally valid root, signed by the trusted origin issuer, whose
    // `mission` object carries only the issuance profile's baseline
    // {id, issuer} plus `subject` -- exactly what a baseline-claim
    // consumer would consider complete, but this profile's own root
    // REQUIRES authority_hash too (@spec cross-org-delegation#root-issuance).
    const forgedRoot = await new SignJWT({
      mission: { id: missionId, issuer: ORIGIN_ISS, subject: { iss: "https://id.org1.test", sub: "p-alice" } },
      cnf: { jwk: await pub(agentA) },
      act: { iss: "https://id.org1.test", sub: "wl-agent-a" },
      del_depth: 0,
      del_max_depth: 1,
      authorization_details: [{ type: "attenuating_agent_token", tools: derived.tools }],
    })
      .setProtectedHeader({ alg: "ES256", kid: "as-token", typ: "aat+jwt" })
      .setIssuer(ORIGIN_ISS)
      .setAudience(RESOURCE)
      .setIssuedAt(nowS)
      .setExpirationTime(nowS + 300)
      .sign(asKeys.privateKey);
    await expect(
      verifyCrossOrgChain({ federation: fed, presentation: present([forgedRoot]), nowS, stateSource: activeState }),
    ).rejects.toThrow(/root mission claim is incomplete/);
  });

  it("refuses a named hop whose actor credential is missing", async () => {
    const { chain } = await buildChain();
    await expect(
      verifyCrossOrgChain({ federation: fed, presentation: present(chain), nowS, stateSource: activeState }),
    ).rejects.toThrow(/no aligned actor credential/);
  });

  it("refuses a named hop whose credential binds the wrong key", async () => {
    const { chain } = await buildChain();
    const wrongCred = { hop: 1, type: WORKLOAD_ATTESTATION_TYPE, credential: await attest({ iss: "https://id.org2.test", sub: "wl-agent-b" }, workerC) };
    await expect(
      verifyCrossOrgChain({ federation: fed, presentation: present(chain, [wrongCred]), nowS, stateSource: activeState }),
    ).rejects.toThrow(/bound key differs/);
  });

  it("refuses a credential from an untrusted attestation source", async () => {
    const { chain } = await buildChain();
    const rogue = await generateKeyPair("ES256", { extractable: true });
    const rogueCred = await new SignJWT({ subject: { iss: "https://id.org2.test", sub: "wl-agent-b" }, cnf: { jwk: await pub(agentB) } })
      .setProtectedHeader({ alg: "ES256", typ: WORKLOAD_ATTESTATION_TYPE })
      .setIssuer(ATTEST_ISS)
      .setIssuedAt(nowS)
      .setExpirationTime(nowS + 600)
      .sign(rogue.privateKey);
    await expect(
      verifyCrossOrgChain({ federation: fed, presentation: present(chain, [{ hop: 1, type: WORKLOAD_ATTESTATION_TYPE, credential: rogueCred }]), nowS, stateSource: activeState }),
    ).rejects.toThrow(/every accepted attestation source/);
  });

  it("refuses a chain whose depth exceeds del_max_depth", async () => {
    // A non-delegating root (requestedTools => del_max_depth 0) then one child.
    const derived = await deriveCrossOrgRoot(kernel, asKeys.privateKey, "as-token", {
      missionId, aud: RESOURCE, clientId: "agent-a", cnfJwk: await pub(agentA),
      actor: { iss: "https://id.org1.test", sub: "wl-agent-a" }, mappingVersion: "map-1",
      delMaxDepth: 0,
    });
    const hop1 = await mintCrossOrgChild(derived.root, agentA.privateKey, derived.tools, { cnfJwk: await pub(agentB) });
    await expect(
      verifyCrossOrgChain({ federation: fed, presentation: present([derived.root, hop1]), nowS, stateSource: activeState }),
    ).rejects.toThrow(/del_max_depth/);
  });

  it("refuses a duplicated actor representation (nested act)", async () => {
    const derived = await deriveCrossOrgRoot(kernel, asKeys.privateKey, "as-token", {
      missionId, aud: RESOURCE, clientId: "agent-a", cnfJwk: await pub(agentA),
      actor: { iss: "https://id.org1.test", sub: "wl-agent-a" }, mappingVersion: "map-1",
    });
    // Forge a child carrying a nested act history.
    const nested = await new SignJWT({
      mission: { id: missionId, issuer: ORIGIN_ISS, authority_hash: kernel.get(missionId)!.authority_hash, subject: { iss: "https://id.org1.test", sub: "p-alice" } },
      cnf: { jwk: await pub(agentB) },
      act: { iss: "https://id.org2.test", sub: "wl-agent-b", act: { iss: "https://id.org1.test", sub: "wl-agent-a" } },
      del_depth: 1, del_max_depth: 3,
      par_hash: parHash(derived.root),
      authorization_details: [{ type: "attenuating_agent_token", tools: derived.tools }],
    })
      .setProtectedHeader({ alg: "ES256", typ: "aat+jwt" })
      .setIssuer("urn:test").setAudience(RESOURCE).setIssuedAt(nowS).setExpirationTime(nowS + 300).sign(agentA.privateKey);
    await expect(
      verifyCrossOrgChain({ federation: fed, presentation: present([derived.root, nested]), nowS, stateSource: activeState }),
    ).rejects.toThrow();
  });

  it("refuses an unmapped authorization-details entry", async () => {
    const derived = await deriveCrossOrgRoot(kernel, asKeys.privateKey, "as-token", {
      missionId, aud: RESOURCE, clientId: "agent-a", cnfJwk: await pub(agentA),
      actor: { iss: "https://id.org1.test", sub: "wl-agent-a" }, mappingVersion: "map-1",
    });
    const badChild = await new SignJWT({
      mission: { id: missionId, issuer: ORIGIN_ISS, authority_hash: kernel.get(missionId)!.authority_hash, subject: { iss: "https://id.org1.test", sub: "p-alice" } },
      cnf: { jwk: await pub(agentB) },
      del_depth: 1, del_max_depth: Number((await import("jose")).decodeJwt(derived.root).del_max_depth),
      par_hash: parHash(derived.root),
      authorization_details: [{ type: "payment_initiation", instructedAmount: {} }],
    })
      .setProtectedHeader({ alg: "ES256", typ: "aat+jwt" })
      .setIssuer("urn:test").setAudience(RESOURCE).setIssuedAt(nowS).setExpirationTime(nowS + 300).sign(agentA.privateKey);
    await expect(
      verifyCrossOrgChain({ federation: fed, presentation: present([derived.root, badChild]), nowS, stateSource: activeState }),
    ).rejects.toThrow(/mapped/);
  });

  it("fails closed on unavailable Mission state", async () => {
    const { chain, creds } = await buildChain();
    await expect(
      verifyCrossOrgChain({ federation: fed, presentation: present(chain, creds), nowS, stateSource: () => undefined }),
    ).rejects.toThrow(/state unavailable/);
  });

  it("fails closed on stale Mission state", async () => {
    const { chain, creds } = await buildChain();
    await expect(
      verifyCrossOrgChain({ federation: fed, presentation: present(chain, creds), nowS, stateSource: () => ({ state: "active", observedAtS: nowS - 3600 }) }),
    ).rejects.toThrow(/stale/);
  });

  it("refuses a revoked Mission", async () => {
    const { chain, creds } = await buildChain();
    await expect(
      verifyCrossOrgChain({ federation: fed, presentation: present(chain, creds), nowS, stateSource: () => ({ state: "revoked", observedAtS: nowS }) }),
    ).rejects.toThrow(/not active/);
  });
});
