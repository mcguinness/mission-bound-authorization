/**
 * @spec cross-org-delegation#verification, #actor-evidence,
 * #root-issuance, #derivation — a valid A -> B -> C chain across three
 * synthetic trust domains, then the negative matrix from the companion's
 * conformance section: widening, substitution, reorder, missing hop, changed
 * mission binding, untrusted root, missing root actor, unbound named actor,
 * duplicated actor representation, depth reset/overflow, wrong leaf key,
 * unmapped authority, Mission constraints missing, widened or not
 * understood, and revoked/stale/unavailable state. The chain is the AAT -02
 * wire with `mission_constraints` (#1759).
 */
import { aatJwkThumbprintUri, aatToolId, aatUuidV7, chainDigest, parHash, parseChainPresentation } from "@mission/core";
import { calculateJwkThumbprint, decodeJwt, exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  deriveCrossOrgRoot,
  mintCrossOrgChild,
  MissionKernel,
  validateMissionIntent,
  verifyCrossOrgChain,
  WORKLOAD_ATTESTATION_TYPE,
  type FederationConfig,
} from "../src/index.js";
import { TEST_OPERATIONS } from "./attenuation.helper.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

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

/**
 * A -02 child of `parentToken` signed under `parentKeys` (the parent's
 * cnf.jwk), with the parent's claims as defaults and `claims` over them: for
 * the hops a mint helper does not build.
 */
async function rawChild(parentToken: string, parentKeys: KP, claims: Record<string, unknown>): Promise<string> {
  const parent = decodeJwt(parentToken);
  return new SignJWT({
    mission: parent.mission,
    cnf: { jwk: await pub(agentB) },
    del_depth: Number(parent.del_depth) + 1,
    del_max_depth: Number(parent.del_max_depth),
    par_hash: parHash(parentToken),
    authorization_details: parent.authorization_details,
    ...claims,
  })
    .setProtectedHeader({ alg: "ES256", typ: "aat+jwt" })
    .setIssuer(aatJwkThumbprintUri((await pub(parentKeys)) as Record<string, unknown>))
    .setAudience(parent.aud as string | string[])
    .setIssuedAt(Math.floor(Date.now() / 1000))
    .setExpirationTime(Number(parent.exp))
    .setJti(aatUuidV7())
    .sign(parentKeys.privateKey);
}

/** A cross-organization root for the suite's Mission, named for agent A. */
function rootFor(extra: { delMaxDepth?: number } = {}) {
  return pub(agentA).then((cnfJwk) =>
    deriveCrossOrgRoot(kernel, asKeys.privateKey, "as-token", {
      missionId, aud: RESOURCE, clientId: "agent-a", cnfJwk, operations: TEST_OPERATIONS,
      actor: { iss: "https://id.org1.test", sub: "wl-agent-a" }, mappingVersion: "map-1", ...extra,
    }),
  );
}

beforeAll(async () => {
  asKeys = await generateKeyPair("ES256", { extractable: true });
  agentA = await generateKeyPair("ES256", { extractable: true });
  agentB = await generateKeyPair("ES256", { extractable: true });
  workerC = await generateKeyPair("ES256", { extractable: true });
  attestKeys = await generateKeyPair("ES256", { extractable: true });
  nowS = Math.floor(Date.now() / 1000);

  const originPolicy = {
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
  };
  kernel = new MissionKernel({
    issuer: ORIGIN_ISS,
    policy: originPolicy as never,
    // The origin org's principals are issued by its own identity provider,
    // distinct from the AS that issues its Missions (#829).
    principalIssuer: "https://id.org1.test",
    authoritySourceCatalog: testAuthoritySourceCatalog(originPolicy.ceiling, ["agent-a"], ["bob"]),
    statusKey: asKeys.privateKey,
    statusKid: "as-status",
  });
  const mission = kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({
        goal: "Cross-org reconcile",
        target_resources: [RESOURCE],
        expires_at: "2027-01-01T00:00:00Z",
      }),
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
    approver: { iss: "https://id.org1.test", sub: "bob" },
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

// The substrate bounds a root's iat by the verifier's clock (AAT -02 Section
// 8 step 3f), so each case verifies at its own time, not the suite's start.
beforeEach(() => {
  nowS = Math.floor(Date.now() / 1000);
});

/** Build the canonical valid A->B->C chain and return its parts. */
async function buildChain(): Promise<{ chain: string[]; creds: Array<{ hop: number; type: string; credential: string }> }> {
  const derived = await deriveCrossOrgRoot(kernel, asKeys.privateKey, "as-token", {
    missionId,
    aud: RESOURCE,
    clientId: "agent-a",
    cnfJwk: await pub(agentA),
    operations: TEST_OPERATIONS,
    actor: { iss: "https://id.org1.test", sub: "wl-agent-a", sub_profile: "ai_agent" },
    mappingVersion: "map-1",
  });
  // A -> B: same tools and Mission constraints, B's key, B named.
  const hop1 = await mintCrossOrgChild(derived.root, agentA.privateKey, derived, {
    cnfJwk: await pub(agentB),
    actor: { iss: "https://id.org2.test", sub: "wl-agent-b", sub_profile: "ai_agent" },
  });
  // B -> C: same tools, C's key, key-only (no act).
  const hop2 = await mintCrossOrgChild(hop1, agentB.privateKey, derived, {
    cnfJwk: await pub(workerC),
  });
  return {
    chain: [derived.root, hop1, hop2],
    creds: [{ hop: 1, type: WORKLOAD_ATTESTATION_TYPE, credential: await attest({ iss: "https://id.org2.test", sub: "wl-agent-b" }, agentB) }],
  };
}

function present(chain: string[], creds?: Array<{ hop: number; type: string; credential: string }>) {
  return parseChainPresentation(
    Buffer.from(JSON.stringify({ aat_chain: chain, ...(creds ? { actor_credentials: creds } : {}) }), "utf8").toString("base64url"),
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
    // The leaf's Mission constraints are the root's, carried unchanged.
    expect(v.leaf.missionConstraints).toEqual((await rootFor()).missionConstraints);
  });
});

describe("Mission constraints at every hop (@spec cross-org-delegation#verification step 5, attenuation#mission-constraints, #1759)", () => {
  it("refuses a hop whose mission_constraints member is missing", async () => {
    const derived = await rootFor();
    const hop1 = await mintCrossOrgChild(derived.root, agentA.privateKey, { tools: derived.tools, missionConstraints: undefined as never }, {
      cnfJwk: await pub(agentB),
    });
    await expect(
      verifyCrossOrgChain({ federation: fed, presentation: present([derived.root, hop1]), nowS, stateSource: activeState }),
    ).rejects.toThrow(/mission_constraints is missing/);
  });

  it("refuses a hop whose mission_constraints widen the parent's", async () => {
    const derived = await rootFor();
    const widened = Object.fromEntries(
      Object.entries(derived.missionConstraints).map(([t, v]) => [
        t,
        { ...v, constraints: { ...v.constraints, max_amount: { amount: "900.00", currency: "USD" } } },
      ]),
    );
    const hop1 = await mintCrossOrgChild(derived.root, agentA.privateKey, { tools: derived.tools, missionConstraints: widened }, {
      cnfJwk: await pub(agentB),
    });
    await expect(
      verifyCrossOrgChain({ federation: fed, presentation: present([derived.root, hop1]), nowS, stateSource: activeState }),
    ).rejects.toThrow(/not within its parent's/);
  });

  it("refuses a hop whose mission_constraints carry a key the verifier does not understand", async () => {
    const derived = await rootFor();
    const unknownConstraint = Object.fromEntries(
      Object.entries(derived.missionConstraints).map(([t, v]) => [t, { ...v, constraints: { ...v.constraints, frobnicate: true } }]),
    );
    const unknownMember = Object.fromEntries(
      Object.entries(derived.missionConstraints).map(([t, v]) => [t, { ...v, extra: {} }]),
    );
    for (const [label, missionConstraints, pattern] of [
      ["an unknown constraint", unknownConstraint, /mission_constraints/],
      ["an unknown member", unknownMember, /is not understood/],
    ] as const) {
      const hop1 = await mintCrossOrgChild(derived.root, agentA.privateKey, { tools: derived.tools, missionConstraints }, {
        cnfJwk: await pub(agentB),
      });
      await expect(
        verifyCrossOrgChain({ federation: fed, presentation: present([derived.root, hop1]), nowS, stateSource: activeState }),
        label,
      ).rejects.toThrow(pattern);
    }
  });
});

describe("negative matrix (@spec cross-org-delegation#conformance)", () => {
  it("refuses capability widening at a hop", async () => {
    const derived = await rootFor();
    const readId = aatToolId(RESOURCE, "payments:invoice.read");
    const scheduleId = aatToolId(RESOURCE, "payments:payment.schedule");
    // Hop 1 narrows to the single read tool; hop 2 re-adds a tool hop 1 dropped.
    const only = (ids: string[]) => ({
      tools: Object.fromEntries(ids.map((id) => [id, derived.tools[id] ?? {}])),
      missionConstraints: Object.fromEntries(ids.map((id) => [id, derived.missionConstraints[id] ?? { constraints: {} }])),
    });
    const hop1 = await mintCrossOrgChild(derived.root, agentA.privateKey, only([readId]), { cnfJwk: await pub(agentB) });
    const hop2 = await mintCrossOrgChild(hop1, agentB.privateKey, only([readId, scheduleId]), { cnfJwk: await pub(workerC) });
    await expect(
      verifyCrossOrgChain({ federation: fed, presentation: present([derived.root, hop1, hop2]), nowS, stateSource: activeState }),
    ).rejects.toThrow(/substrate step 4p1/);
  });

  it("refuses a reordered / substituted parent (par_hash break)", async () => {
    const { chain, creds } = await buildChain();
    const swapped = [chain[0] as string, chain[2] as string, chain[1] as string];
    await expect(
      verifyCrossOrgChain({ federation: fed, presentation: present(swapped, creds), nowS, stateSource: activeState }),
    ).rejects.toThrow();
  });

  it("refuses a hop whose cnf carries a thumbprint-only confirmation", async () => {
    const derived = await rootFor();
    const jkt = await calculateJwkThumbprint(await pub(agentB));
    const hop1 = await rawChild(derived.root, agentA, { cnf: { jkt } });
    await expect(
      verifyCrossOrgChain({ federation: fed, presentation: present([derived.root, hop1]), nowS, stateSource: activeState }),
    ).rejects.toThrow(/substrate step 4b/);
  });

  it("refuses a missing middle hop", async () => {
    const { chain } = await buildChain();
    await expect(
      verifyCrossOrgChain({ federation: fed, presentation: present([chain[0] as string, chain[2] as string]), nowS, stateSource: activeState }),
    ).rejects.toThrow(/substrate step 4b|par_hash/);
  });

  it("refuses an untrusted root issuer", async () => {
    const { chain, creds } = await buildChain();
    const untrusted: FederationConfig = { ...fed, issuers: [{ issuer: "https://evil.test", jwks: fed.issuers[0]!.jwks }] };
    await expect(
      verifyCrossOrgChain({ federation: untrusted, presentation: present(chain, creds), nowS, stateSource: activeState }),
    ).rejects.toThrow(/substrate step 3k/);
  });

  it("@spec mission#the-mission-claim (#702), cross-org-delegation -- this profile REQUIRES authority_hash as its own lineage anchor: a root whose mission claim omits it is refused, never silently downgraded", async () => {
    const derived = await rootFor();
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
      authorization_details: [
        { type: "attenuating_agent_token", tools: derived.tools, mission_constraints: derived.missionConstraints },
      ],
    })
      .setProtectedHeader({ alg: "ES256", kid: "as-token", typ: "aat+jwt" })
      .setIssuer(ORIGIN_ISS)
      .setAudience(RESOURCE)
      .setIssuedAt(nowS)
      .setExpirationTime(nowS + 300)
      .setJti(aatUuidV7())
      .sign(asKeys.privateKey);
    await expect(
      verifyCrossOrgChain({ federation: fed, presentation: present([forgedRoot]), nowS, stateSource: activeState }),
    ).rejects.toThrow(/no well-formed mission claim/);
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
    // A non-delegating root (del_max_depth 0) then one child.
    const derived = await rootFor({ delMaxDepth: 0 });
    const hop1 = await mintCrossOrgChild(derived.root, agentA.privateKey, derived, { cnfJwk: await pub(agentB) });
    await expect(
      verifyCrossOrgChain({ federation: fed, presentation: present([derived.root, hop1]), nowS, stateSource: activeState }),
    ).rejects.toThrow(/del_max_depth/);
  });

  it("refuses a duplicated actor representation (nested act)", async () => {
    const derived = await rootFor();
    // A substrate-valid child carrying a nested act history.
    const nested = await rawChild(derived.root, agentA, {
      act: { iss: "https://id.org2.test", sub: "wl-agent-b", act: { iss: "https://id.org1.test", sub: "wl-agent-a" } },
    });
    const cred = { hop: 1, type: WORKLOAD_ATTESTATION_TYPE, credential: await attest({ iss: "https://id.org2.test", sub: "wl-agent-b" }, agentB) };
    await expect(
      verifyCrossOrgChain({ federation: fed, presentation: present([derived.root, nested], [cred]), nowS, stateSource: activeState }),
    ).rejects.toThrow(/nested history/);
  });

  it("refuses an unmapped authorization-details entry", async () => {
    const derived = await rootFor();
    const mapped = (decodeJwt(derived.root).authorization_details as unknown[])[0];
    // The substrate ignores an entry of another type beside the mapped one
    // (AAT -02 Section 8 step 4n); this profile refuses the Chain.
    const badChild = await rawChild(derived.root, agentA, {
      authorization_details: [mapped, { type: "payment_initiation", instructedAmount: {} }],
    });
    await expect(
      verifyCrossOrgChain({ federation: fed, presentation: present([derived.root, badChild]), nowS, stateSource: activeState }),
    ).rejects.toThrow(/exactly the mapped/);
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
      verifyCrossOrgChain({ federation: fed, presentation: present(chain, creds), nowS, stateSource: () => ({ state: "terminated", observedAtS: nowS }) }),
    ).rejects.toThrow(/not active/);
  });
});
