/**
 * @spec mission#transformation-capabilities, resource-access#qualified-narrowing,
 * cross-domain#conveyed-delegation (#1377, D1025)
 *
 * Cross-domain issuance under the declared `narrowing`. A grant conveys an
 * entry changed from its approved entry (by containment, or by the conveyed
 * copy dropping `delegation`) only where the declaration permits narrowing it;
 * otherwise the entry does not cross the domain, and a grant left with none is
 * refused: by the derivation gate (`authority_contained`) where containment
 * leaves the Mission no entry, before anything is reserved. Each case runs under a kernel declaring narrowing in full, one with
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

describe("a cross-domain grant conveys a changed entry only where the declared narrowing permits it (@spec mission#transformation-capabilities, resource-access#qualified-narrowing, #1377, D1025)", () => {
  it("after partial containment, narrowing in full conveys the narrowed entry; undeclared, the grant is refused", async () => {
    const full = kernelWith(NARROWING_IN_FULL);
    const m = approve(full, [structuredClone(PLAIN)]);
    contain(full, m.id, R_PLAIN, [LIST]);
    expect(await conveyed(full, m.id)).toEqual([{ ...PLAIN, actions: [READ] }]);

    const undeclared = kernelWith(NARROWING_UNDECLARED);
    const u = approve(undeclared, [structuredClone(PLAIN)]);
    expect(await conveyed(undeclared, u.id)).toEqual([PLAIN]);
    contain(undeclared, u.id, R_PLAIN, [LIST]);
    await expect(conveyed(undeclared, u.id)).rejects.toThrow(/effective authority is fully contained/);
  });

  it("an entry whose conveyed copy drops `delegation` is conveyed without it under narrowing in full, and refused undeclared", async () => {
    const full = kernelWith(NARROWING_IN_FULL);
    const m = approve(full, [structuredClone(POLICY)]);
    expect(await conveyed(full, m.id)).toEqual([{ type: "mission_resource_access", resource: R_POLICY, actions: [READ] }]);

    const undeclared = kernelWith(NARROWING_UNDECLARED);
    const u = approve(undeclared, [structuredClone(POLICY)]);
    await expect(conveyed(undeclared, u.id)).rejects.toBeInstanceOf(AuthorityNarrowedToEmptyError);
  });

  it("under an exact-only domain, a partially contained exact entry is conveyed narrowed and a partially contained prefix entry is refused", async () => {
    const domain = kernelWith(exactOnly());
    const exact = approve(domain, [structuredClone(PLAIN)]);
    contain(domain, exact.id, R_PLAIN, [LIST]);
    expect(await conveyed(domain, exact.id)).toEqual([{ ...PLAIN, actions: [READ] }]);

    const prefix = approve(domain, [structuredClone(PREFIX)]);
    expect(await conveyed(domain, prefix.id)).toEqual([PREFIX]);
    contain(domain, prefix.id, R_PREFIX, [LIST]);
    await expect(conveyed(domain, prefix.id)).rejects.toThrow(/effective authority is fully contained/);
  });
});
