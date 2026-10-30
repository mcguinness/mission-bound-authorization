/**
 * @spec mission#transformation-capabilities, resource-access#qualified-narrowing,
 * cross-domain#conveyed-delegation (#1377, D1025)
 *
 * Cross-domain issuance under the declared `narrowing`. "Issuing an entry to an
 * audience other than its original approved audience, including audience
 * projection to a Resource AS, counts as narrowing and needs `narrowing`", so a
 * grant conveys an entry, changed (by containment, or by the conveyed copy
 * dropping `delegation`) or not, only where the declaration permits narrowing
 * it. A grant left with none is refused: by the derivation gate
 * (`authority_contained`) where containment leaves the Mission no entry that
 * issuance may carry, before anything is reserved, and otherwise at signing. Each case runs under a kernel declaring narrowing in full, one with
 * narrowing undeclared, and one whose narrowing domain covers `exact` entries
 * only.
 *
 * Pure, in-memory kernel, no network.
 */

import {
  type JsonValue,
  NARROWING_IN_FULL,
  NARROWING_UNDECLARED,
  type NarrowingDeclaration,
  narrowingDomainDigest,
  resolveNarrowing,
} from "@mission/core";
import { type CryptoKey, decodeJwt, generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  AuthorityNarrowedToEmptyError,
  issueCrossDomainGrant,
  MissionKernel,
  type MissionRecord,
  validateMissionIntent,
} from "../src/index.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const ISS = "https://as.test";
const RAS = "https://ras.partner.test";
const EXP = "2099-01-01T00:00:00Z";
const R_PLAIN = "https://api.partner.test/plain";
const R_POLICY = "https://api.partner.test/policy";
const R_PREFIX = "https://api.partner.test/files/";
const READ = "res.read";
const LIST = "res.list";

const PLAIN: AuthorityEntry = { type: "mission_resource_access", resource: R_PLAIN, actions: [READ, LIST] };
/** `delegation` with no `allowed_delegates`: eligibility defers to policy, so the conveyed copy drops it. */
const POLICY: AuthorityEntry = {
  type: "mission_resource_access",
  resource: R_POLICY,
  actions: [READ],
  delegation: { max_depth: 2 },
};
const PREFIX = {
  type: "mission_resource_access",
  resource: R_PREFIX,
  resource_match: "prefix",
  actions: [READ, LIST],
} as AuthorityEntry;
const CEILING: AuthorityEntry[] = [PLAIN, POLICY, PREFIX];

/** An exact-only narrowing domain over this implementation's members and keys. */
const EXACT_ONLY = {
  id: "https://mission-reference.example/narrowing-domains/test-exact-only/xd",
  type: "mission_resource_access",
  capability: "narrowing",
  resource_match: ["exact"],
  members: ["type", "resource", "resource_match", "actions", "constraints", "delegation", "capability_sources", "resource_contract"],
  constraints: [],
};

function exactOnly(): NarrowingDeclaration {
  const value = { domain: { id: EXACT_ONLY.id, digest: narrowingDomainDigest(EXACT_ONLY as unknown as JsonValue) } };
  const resolved = resolveNarrowing(value, (id) => (id === EXACT_ONLY.id ? EXACT_ONLY : undefined));
  if (resolved?.declaration.kind !== "domain") throw new Error("the exact-only domain does not resolve");
  return resolved.declaration;
}

let signKey: CryptoKey;
beforeAll(async () => {
  ({ privateKey: signKey } = await generateKeyPair("ES256", { extractable: true }));
});

function kernelWith(narrowing: NarrowingDeclaration): MissionKernel {
  return new MissionKernel({
    issuer: ISS,
    policy: { policy_version: "qualified-narrowing-xd-1", ceiling: CEILING },
    authoritySourceCatalog: testAuthoritySourceCatalog(CEILING, ["agent"], ["approver"]),
    statusKey: signKey,
    statusKid: "as-status",
    narrowing,
  });
}

let events = 0;
function approve(kernel: MissionKernel, proposal: AuthorityEntry[]): MissionRecord {
  return kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({
        goal: "Work at a partner domain",
        target_resources: [...new Set(proposal.map((e) => e.resource))],
        expires_at: EXP,
      }),
    ),
    proposedAuthority: proposal,
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "approver" },
    clientId: "agent",
    approvalEventId: `apev-qn-xd-${events++}`,
  });
}

function contain(kernel: MissionKernel, missionId: string, resource: string, actions: string[]): void {
  kernel.contain(missionId, {
    event: { type: "test.narrowing", source: "qualified-narrowing-cross-domain.test", observed_at: new Date().toISOString(), event_id: crypto.randomUUID() },
    remove: [{ resource, actions }],
  });
}

async function conveyed(kernel: MissionKernel, missionId: string): Promise<AuthorityEntry[]> {
  const { grant } = await issueCrossDomainGrant(kernel, signKey, "as-xd", {
    missionId,
    targetAs: RAS,
    clientId: "agent",
    cnfJkt: "jkt-agent",
    resourceToAs: () => RAS,
  });
  return decodeJwt(grant).authorization_details as AuthorityEntry[];
}

describe("audience projection to a Resource AS counts as narrowing: a grant conveys an entry only where the declared narrowing permits it (@spec mission#transformation-capabilities, resource-access#qualified-narrowing, #1377, D1025)", () => {
  it("narrowing in full conveys an unchanged entry; with narrowing undeclared the grant is refused, the entry unchanged notwithstanding", async () => {
    const full = kernelWith(NARROWING_IN_FULL);
    const m = approve(full, [structuredClone(PLAIN)]);
    expect(await conveyed(full, m.id)).toEqual([PLAIN]);

    const undeclared = kernelWith(NARROWING_UNDECLARED);
    const u = approve(undeclared, [structuredClone(PLAIN)]);
    await expect(conveyed(undeclared, u.id)).rejects.toBeInstanceOf(AuthorityNarrowedToEmptyError);
  });

  it("after partial containment, narrowing in full and an exact-only domain convey an exact entry narrowed", async () => {
    for (const kernel of [kernelWith(NARROWING_IN_FULL), kernelWith(exactOnly())]) {
      const m = approve(kernel, [structuredClone(PLAIN)]);
      contain(kernel, m.id, R_PLAIN, [LIST]);
      expect(await conveyed(kernel, m.id)).toEqual([{ ...PLAIN, actions: [READ] }]);
    }
  });

  it("under an exact-only domain, a prefix entry outside it is refused, unchanged or partially contained, while the effective set keeps the contained entry's remainder", async () => {
    const domain = kernelWith(exactOnly());
    const unchanged = approve(domain, [structuredClone(PREFIX)]);
    await expect(conveyed(domain, unchanged.id)).rejects.toBeInstanceOf(AuthorityNarrowedToEmptyError);
    const partial = approve(domain, [structuredClone(PREFIX)]);
    contain(domain, partial.id, R_PREFIX, [LIST]);
    expect(domain.effectiveAuthoritySet(domain.get(partial.id) as MissionRecord)).toEqual([
      { ...PREFIX, actions: PREFIX.actions.filter((a) => a !== LIST) },
    ]);
    // Nothing is left that issuance may carry: the derivation gate refuses first.
    await expect(conveyed(domain, partial.id)).rejects.toMatchObject({ reason: "authority_contained" });

    const full = kernelWith(NARROWING_IN_FULL);
    const m = approve(full, [structuredClone(PREFIX)]);
    expect(await conveyed(full, m.id)).toEqual([PREFIX]);
  });

  it("an entry whose conveyed copy drops `delegation` is conveyed without it where narrowing is permitted, and refused undeclared", async () => {
    for (const kernel of [kernelWith(NARROWING_IN_FULL), kernelWith(exactOnly())]) {
      const m = approve(kernel, [structuredClone(POLICY)]);
      expect(await conveyed(kernel, m.id)).toEqual([{ type: "mission_resource_access", resource: R_POLICY, actions: [READ] }]);
    }
    const undeclared = kernelWith(NARROWING_UNDECLARED);
    const u = approve(undeclared, [structuredClone(POLICY)]);
    await expect(conveyed(undeclared, u.id)).rejects.toBeInstanceOf(AuthorityNarrowedToEmptyError);
  });
});

/** The derivation gate's outcome: "derivable", or the refusal's reason. */
function gateOutcome(kernel: MissionKernel, missionId: string): string {
  try {
    kernel.gateDerivation(missionId);
    return "derivable";
  } catch (e) {
    return (e as { reason?: string }).reason ?? String(e);
  }
}

describe("the effective set keeps a partially contained entry's remainder; issuance carries it only where the declared narrowing permits it (@spec containment#visibility, resource-access#qualified-narrowing, #1377, D1025)", () => {
  it("narrowing undeclared: the reported set keeps the remainder, the issuable set omits it, and derivation is refused authority_contained; in full, both carry the remainder and derivation proceeds", () => {
    const undeclared = kernelWith(NARROWING_UNDECLARED);
    const u = approve(undeclared, [structuredClone(PLAIN)]);
    const [approved] = u.authority_set as [AuthorityEntry];
    contain(undeclared, u.id, R_PLAIN, [LIST]);
    const record = undeclared.get(u.id) as MissionRecord;
    expect(undeclared.effectiveAuthoritySet(record)).toEqual([{ ...approved, actions: [READ] }]);
    expect(undeclared.issuableAuthoritySet(record)).toEqual([]);
    expect(gateOutcome(undeclared, u.id)).toBe("authority_contained");

    const full = kernelWith(NARROWING_IN_FULL);
    const f = approve(full, [structuredClone(PLAIN)]);
    contain(full, f.id, R_PLAIN, [LIST]);
    const fr = full.get(f.id) as MissionRecord;
    expect(full.issuableAuthoritySet(fr)).toEqual([{ ...(f.authority_set[0] as AuthorityEntry), actions: [READ] }]);
    expect(gateOutcome(full, f.id)).toBe("derivable");
  });

  it("an untouched entry stays issuable beside one the declaration does not let issuance carry, and derivation proceeds", () => {
    const undeclared = kernelWith(NARROWING_UNDECLARED);
    const m = approve(undeclared, [structuredClone(PLAIN), structuredClone(POLICY)]);
    const [plain, policy] = m.authority_set as [AuthorityEntry, AuthorityEntry];
    contain(undeclared, m.id, R_PLAIN, [LIST]);
    const record = undeclared.get(m.id) as MissionRecord;
    expect(undeclared.effectiveAuthoritySet(record)).toEqual([{ ...plain, actions: [READ] }, policy]);
    expect(undeclared.issuableAuthoritySet(record)).toEqual([policy]);
    expect(gateOutcome(undeclared, m.id)).toBe("derivable");
  });

  it("under an exact-only domain, a partially contained exact entry is issuable narrowed, and a partially contained prefix entry is reported but not issuable", () => {
    const domain = kernelWith(exactOnly());
    const m = approve(domain, [structuredClone(PLAIN), structuredClone(PREFIX)]);
    const [plain, prefix] = m.authority_set as [AuthorityEntry, AuthorityEntry];
    contain(domain, m.id, R_PLAIN, [LIST]);
    contain(domain, m.id, R_PREFIX, [LIST]);
    const record = domain.get(m.id) as MissionRecord;
    expect(domain.effectiveAuthoritySet(record)).toEqual([
      { ...plain, actions: [READ] },
      { ...prefix, actions: [READ] },
    ]);
    expect(domain.issuableAuthoritySet(record)).toEqual([{ ...plain, actions: [READ] }]);
  });
});
