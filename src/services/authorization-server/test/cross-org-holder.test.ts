/**
 * @spec cross-org-delegation#derivation (#1822): the holder side of
 * cross-organizational Per-Hop Derivation, through the checked child mint
 * (deriveCrossOrgChild). A chain minted only through it verifies at the
 * destination; each rule a holder can check refuses a non-conforming
 * request with its own reason; and the rules that hold by construction
 * (par_hash, del_depth, del_max_depth, one authorization-details entry, the
 * invariant mission claim) are asserted on the minted values. The
 * unchecked builder (mintCrossOrgChild) still mints what the checked one
 * refuses, for the negative suites.
 */
import { aatJwkThumbprintUri, aatToolId, parHash, parseChainPresentation } from "@mission/core";
import { decodeJwt, exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  type AttenuatedAuthority,
  deriveAttenuationRoot,
  deriveCrossOrgChild,
  deriveCrossOrgRoot,
  type FederationConfig,
  MissionKernel,
  mintCrossOrgChild,
  validateMissionIntent,
  verifyCrossOrgChain,
  WORKLOAD_ATTESTATION_TYPE,
} from "../src/index.js";
import { TEST_OPERATIONS } from "./attenuation.helper.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const ORIGIN_ISS = "https://as.org1.test";
const RESOURCE = "https://api.org3.test";
const ATTEST_ISS = "https://attest.org2.test";
const AGENT_B = { iss: "https://id.org2.test", sub: "wl-agent-b", sub_profile: "ai_agent" };

type KP = { privateKey: CryptoKey; publicKey: CryptoKey };
let asKeys: KP;
let agentA: KP;
let agentB: KP;
let workerC: KP;
let attestKeys: KP;
let kernel: MissionKernel;
let missionId: string;
let fed: FederationConfig;
let nowS: number;

const READ = aatToolId(RESOURCE, "payments:invoice.read");
const SCHEDULE = aatToolId(RESOURCE, "payments:payment.schedule");

async function pub(k: KP): Promise<JWK> {
  return exportJWK(k.publicKey) as Promise<JWK>;
}

async function attest(actor: { iss: string; sub: string }, key: KP): Promise<string> {
  return new SignJWT({ subject: actor, cnf: { jwk: await pub(key) } })
    .setProtectedHeader({ alg: "ES256", typ: WORKLOAD_ATTESTATION_TYPE })
    .setIssuer(ATTEST_ISS)
    .setIssuedAt(nowS)
    .setExpirationTime(nowS + 600)
    .sign(attestKeys.privateKey);
}

const activeState = () => ({ state: "active", observedAtS: nowS });

function present(chain: string[], creds?: Array<{ hop: number; type: string; credential: string }>) {
  return parseChainPresentation(
    Buffer.from(JSON.stringify({ aat_chain: chain, ...(creds ? { actor_credentials: creds } : {}) }), "utf8").toString("base64url"),
    fed.bounds,
  );
}

function rootFor(extra: { delMaxDepth?: number } = {}) {
  return pub(agentA).then((cnfJwk) =>
    deriveCrossOrgRoot(kernel, asKeys.privateKey, "as-token", {
      missionId, aud: RESOURCE, clientId: "agent-a", cnfJwk, operations: TEST_OPERATIONS,
      actor: { iss: "https://id.org1.test", sub: "wl-agent-a" }, mappingVersion: "map-1", ...extra,
    }),
  );
}

/** The authority restricted to `ids`, each tool's argument map optionally replaced. */
function only(
  from: AttenuatedAuthority,
  ids: string[],
  args: Record<string, Record<string, unknown>> = {},
): AttenuatedAuthority {
  return {
    tools: Object.fromEntries(ids.map((id) => [id, args[id] ?? from.tools[id] ?? {}])),
    missionConstraints: Object.fromEntries(ids.map((id) => [id, from.missionConstraints[id] ?? { constraints: {} }])),
  } as AttenuatedAuthority;
}

/** `target_id` pinned to one invoice: narrower than the ceiling's explicit wildcard. */
const PINNED = { target_id: { constraint_type: "exact", value: "inv-1", optional: true } };

beforeAll(async () => {
  asKeys = await generateKeyPair("ES256", { extractable: true });
  agentA = await generateKeyPair("ES256", { extractable: true });
  agentB = await generateKeyPair("ES256", { extractable: true });
  workerC = await generateKeyPair("ES256", { extractable: true });
  attestKeys = await generateKeyPair("ES256", { extractable: true });
  nowS = Math.floor(Date.now() / 1000);

  const ceiling = [
    {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: ["payments:invoice.read", "payments:payment.schedule"],
      constraints: { max_amount: { amount: "500.00", currency: "USD" } },
      delegation: { max_depth: 3 },
    },
  ];
  kernel = new MissionKernel({
    issuer: ORIGIN_ISS,
    policy: { policy_version: "xorg-holder-1", ceiling } as never,
    principalIssuer: "https://id.org1.test",
    authoritySourceCatalog: testAuthoritySourceCatalog(ceiling, ["agent-a"], ["bob"]),
    statusKey: asKeys.privateKey,
    statusKid: "as-status",
  });
  missionId = kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({ goal: "Cross-org holder", target_resources: [RESOURCE], expires_at: "2027-01-01T00:00:00Z" }),
    ),
    proposedAuthority: ceiling as never,
    subject: { iss: "https://id.org1.test", sub: "p-alice" },
    approver: { iss: "https://id.org1.test", sub: "bob" },
    clientId: "agent-a",
    approvalEventId: "apev-xorg-holder",
  }).id;

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

beforeEach(() => {
  nowS = Math.floor(Date.now() / 1000);
});

describe("checked cross-org child mint (@spec cross-org-delegation#derivation, #1822)", () => {
  it("mints a chain the destination verifies: a named hop with its credential, then a narrowed key-only hop", async () => {
    const root = await rootFor();
    const hop1 = await deriveCrossOrgChild(root.root, agentA.privateKey, root, { cnfJwk: await pub(agentB), actor: AGENT_B });
    const leafAuthority = only(root, [READ], { [READ]: PINNED });
    const hop2 = await deriveCrossOrgChild(hop1, agentB.privateKey, leafAuthority, { cnfJwk: await pub(workerC) });
    const creds = [{ hop: 1, type: WORKLOAD_ATTESTATION_TYPE, credential: await attest(AGENT_B, agentB) }];
    const v = await verifyCrossOrgChain({
      federation: fed,
      presentation: present([root.root, hop1, hop2], creds),
      nowS,
      stateSource: activeState,
    });
    expect(v.lineage.map((h) => h.actor?.sub)).toEqual(["wl-agent-a", "wl-agent-b", undefined]);
    expect(v.leaf.tools).toEqual(leafAuthority.tools);
    expect(v.leaf.missionConstraints).toEqual(leafAuthority.missionConstraints);
  });

  it("binds the exact parent, counts depth, keeps the mission claim and carries one entry, the recipient's key and this hop's actor", async () => {
    const root = await rootFor();
    const hop1 = await deriveCrossOrgChild(root.root, agentA.privateKey, root, { cnfJwk: await pub(agentB), actor: AGENT_B });
    const keyOnly = await deriveCrossOrgChild(hop1, agentB.privateKey, root, { cnfJwk: await pub(workerC) });
    const r = decodeJwt(root.root);
    const c = decodeJwt(hop1);
    // Rule 1: signed under the key the parent's cnf.jwk binds, named by its thumbprint URI.
    expect(c.iss).toBe(aatJwkThumbprintUri((await pub(agentA)) as Record<string, unknown>));
    // Rule 2: par_hash over the exact parent.
    expect(c.par_hash).toBe(parHash(root.root));
    // Rule 6: del_depth the parent's plus one, del_max_depth preserved.
    expect(c.del_depth).toBe(Number(r.del_depth) + 1);
    expect(c.del_max_depth).toBe(r.del_max_depth);
    expect(decodeJwt(keyOnly).del_depth).toBe(2);
    // Rule 7: the mission claim unchanged, including subject.
    expect(c.mission).toEqual(r.mission);
    expect((c.mission as { subject: unknown }).subject).toEqual({ iss: "https://id.org1.test", sub: "p-alice" });
    // Rule 3: exactly one authorization-details entry, the narrowed capability entry.
    expect(c.authorization_details).toEqual([
      { type: "attenuating_agent_token", tools: root.tools, mission_constraints: root.missionConstraints },
    ]);
    // Rule 9: the recipient's own public key as cnf.jwk.
    expect((c.cnf as { jwk: JWK }).jwk).toEqual(await pub(agentB));
    // Rule 8: this hop's actor only; a key-only hop carries no act.
    expect(c.act).toEqual(AGENT_B);
    expect(decodeJwt(keyOnly).act).toBeUndefined();
  });

  it("refuses to sign with any key but the one the parent's cnf.jwk binds (rule 1)", async () => {
    const root = await rootFor();
    await expect(
      deriveCrossOrgChild(root.root, agentB.privateKey, root, { cnfJwk: await pub(workerC) }),
    ).rejects.toThrow(/the signing key is not the key the parent's cnf.jwk binds/);
  });

  it("refuses a child broader than its parent in tools, argument maps or mission_constraints (rule 3)", async () => {
    const root = await rootFor();
    const pinned = only(root, [READ], { [READ]: PINNED });
    const hop1 = await deriveCrossOrgChild(root.root, agentA.privateKey, pinned, { cnfJwk: await pub(agentB) });
    await expect(
      deriveCrossOrgChild(hop1, agentB.privateKey, only(root, [READ, SCHEDULE], { [READ]: PINNED }), { cnfJwk: await pub(workerC) }),
      "a tool the parent dropped",
    ).rejects.toThrow(/names .* which its parent does not/);
    await expect(
      deriveCrossOrgChild(hop1, agentB.privateKey, only(root, [READ]), { cnfJwk: await pub(workerC) }),
      "an argument map wider than the parent's",
    ).rejects.toThrow(/is broader than its parent's/);
    const widened = {
      tools: root.tools,
      missionConstraints: Object.fromEntries(
        Object.entries(root.missionConstraints).map(([t, v]) => [
          t,
          { ...v, constraints: { ...v.constraints, max_amount: { amount: "900.00", currency: "USD" } } },
        ]),
      ),
    } as AttenuatedAuthority;
    await expect(
      deriveCrossOrgChild(root.root, agentA.privateKey, widened, { cnfJwk: await pub(agentB) }),
      "mission_constraints wider than the parent's",
    ).rejects.toThrow(/mission_constraints for .* is not within its parent's/);
  });

  it("refuses an aud wider than its parent's (rule 4)", async () => {
    const root = await rootFor();
    await expect(
      deriveCrossOrgChild(root.root, agentA.privateKey, root, {
        cnfJwk: await pub(agentB),
        aud: [RESOURCE, "https://api.elsewhere.test"],
      }),
    ).rejects.toThrow(/the child aud is not within its parent's/);
  });

  it("refuses an exp after the parent's or after the destination trust policy's ceiling, and defaults within both (rule 5)", async () => {
    const root = await rootFor();
    const parentExp = Number(decodeJwt(root.root).exp);
    await expect(
      deriveCrossOrgChild(root.root, agentA.privateKey, root, { cnfJwk: await pub(agentB), exp: parentExp + 60 }),
      "after the parent's",
    ).rejects.toThrow(/the child exp is after its parent's/);
    const ceiling = parentExp - 120;
    await expect(
      deriveCrossOrgChild(root.root, agentA.privateKey, root, {
        cnfJwk: await pub(agentB),
        exp: ceiling + 60,
        expCeiling: ceiling,
      }),
      "after the destination ceiling",
    ).rejects.toThrow(/the child exp is after the destination trust policy permits/);
    const capped = await deriveCrossOrgChild(root.root, agentA.privateKey, root, {
      cnfJwk: await pub(agentB),
      expCeiling: ceiling,
    });
    expect(decodeJwt(capped).exp).toBe(ceiling);
  });

  it("refuses a hop past the parent's del_max_depth (rule 6)", async () => {
    const root = await rootFor({ delMaxDepth: 1 });
    const hop1 = await deriveCrossOrgChild(root.root, agentA.privateKey, root, { cnfJwk: await pub(agentB) });
    await expect(
      deriveCrossOrgChild(hop1, agentB.privateKey, root, { cnfJwk: await pub(workerC) }),
    ).rejects.toThrow(/del_max_depth permits no further derivation/);
  });

  it("refuses a parent whose mission claim lacks the origin principal subject (rule 7)", async () => {
    const inOrg = await deriveAttenuationRoot(kernel, asKeys.privateKey, "as-token", {
      missionId,
      aud: RESOURCE,
      clientId: "agent-a",
      cnfJwk: await pub(agentA),
      operations: TEST_OPERATIONS,
    });
    await expect(
      deriveCrossOrgChild(inOrg.root, agentA.privateKey, inOrg, { cnfJwk: await pub(agentB) }),
    ).rejects.toThrow(/the parent's mission claim lacks id, issuer, authority_hash or subject/);
  });

  it("refuses an act without both iss and sub, or carrying a nested history (rule 8)", async () => {
    const root = await rootFor();
    await expect(
      deriveCrossOrgChild(root.root, agentA.privateKey, root, {
        cnfJwk: await pub(agentB),
        actor: { iss: "https://id.org2.test", sub: "" },
      }),
      "no sub",
    ).rejects.toThrow(/a named hop's act needs both iss and sub/);
    await expect(
      deriveCrossOrgChild(root.root, agentA.privateKey, root, {
        cnfJwk: await pub(agentB),
        actor: { ...AGENT_B, act: { iss: "https://id.org1.test", sub: "wl-agent-a" } } as never,
      }),
      "a nested act",
    ).rejects.toThrow(/never a nested history/);
  });

  it("refuses a child without the recipient's own full public cnf.jwk (rule 9)", async () => {
    const root = await rootFor();
    const privateJwk = await exportJWK(agentB.privateKey);
    await expect(
      deriveCrossOrgChild(root.root, agentA.privateKey, root, { cnfJwk: undefined as never }),
      "no key",
    ).rejects.toThrow(/the recipient's own cnf.jwk/);
    // A null or non-object key is refused, never replaced by the parent's key
    // the shared check falls back to (#1840 review): no child is signed.
    await expect(
      deriveCrossOrgChild(root.root, agentA.privateKey, root, { cnfJwk: null as never }),
      "a null key",
    ).rejects.toThrow(/the recipient's own cnf.jwk/);
    await expect(
      deriveCrossOrgChild(root.root, agentA.privateKey, root, { cnfJwk: "not-a-jwk" as never }),
      "a non-object key",
    ).rejects.toThrow(/the recipient's own cnf.jwk/);
    await expect(
      deriveCrossOrgChild(root.root, agentA.privateKey, root, { cnfJwk: privateJwk as JWK }),
      "a private key",
    ).rejects.toThrow(/child cnf.jwk: jwk carries the private member d/);
    await expect(
      deriveCrossOrgChild(root.root, agentA.privateKey, root, { cnfJwk: { jkt: "thumbprint-only" } as never }),
      "a thumbprint only",
    ).rejects.toThrow(/child cnf.jwk: unsupported key type/);
  });

  it("leaves the unchecked builder unchecked, for the suites that build refused chains", async () => {
    const root = await rootFor();
    const wider = await mintCrossOrgChild(root.root, agentA.privateKey, root, {
      cnfJwk: await pub(agentB),
      aud: [RESOURCE, "https://api.elsewhere.test"],
    });
    expect(decodeJwt(wider).aud).toEqual([RESOURCE, "https://api.elsewhere.test"]);
  });
});
