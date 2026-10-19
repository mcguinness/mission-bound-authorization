/**
 * @spec resource-access (#1258, D452): the reference implementation's reader for the
 * Mission Resource Access expected-outcome cases in `vectors/mission-resource-access/`.
 *
 * It validates every case file, then runs each case whose `requires` capabilities
 * this implementation has and none of whose `unless` capabilities it has, and reports
 * every other case as skipped, naming the missing capability or the implemented one
 * that makes the case inapplicable. A skipped case is not evidence; a run case is helper-level
 * evidence only (it does not establish endpoint or resource-server enforcement), so
 * ledger rows cite these runs only where the row's role and surface match.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { establishOperationTarget, matchResource, resolveOperationTarget } from "@mission/core";
import { type CryptoKey, generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  delegatePermitted,
  deriveAuthoritySet,
  IntentError,
  isSubsetEntry,
  type MissionIntent,
  MissionKernel,
  type OriginProjection,
  validateMissionIntent,
} from "../src/index.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const DIR = fileURLToPath(new URL("../../../../vectors/mission-resource-access/", import.meta.url));
const FORMAT = "mission-resource-access-cases/1";

/**
 * The deployment capability configuration: what this reference implementation implements.
 *
 * `operation-target` and `resource-match.exact` (#1276, D457): the payments PEP and the
 * SaaS resource establish each operation's target from an explicit service-level
 * operation contract and refuse a missing, unsupported or ambiguous one; the PDP, the
 * payments PEP and the SaaS resource match entries against that target with the one
 * Resource Access matcher in `@mission/core`. The executors below run that same matcher
 * and contract evaluation (helper level). `resource-match.prefix` stays unimplemented: a
 * prefix entry provides no authority.
 */
const IMPLEMENTED = new Set([
  "subset.exact-resource",
  "constraint.max_amount",
  "constraint.requires_action_approval",
  "constraint.resource_issued_after",
  "constraint.resource_issued_before",
  "constraint.tenant",
  "constraint.time_window",
  "constraint.recipient_domain",
  "constraint.data_classification",
  "constraint.allowed_tools",
  "refusal.unsupported-input",
  "refusal.locations",
  "delegate-matcher",
  "operation-target",
  "resource-match.exact",
  // #1275 (D457): retained eligibility provenance and the delegation-authorization policy hook.
  "delegation.policy",
  "delegation.inherited-eligibility",
]);

/** The declared capability vocabulary (README.md). */
const KNOWN_CAPABILITIES = new Set([
  ...IMPLEMENTED,
  "resource-match.prefix",
  "action-families",
  "constraint.resource_issued_after",
  "constraint.resource_issued_before",
  "constraint.tenant",
  "constraint.recipient_domain",
  "constraint.time_window",
  "constraint.data_classification",
  "constraint.allowed_tools",
  "rs.enforcement",
  "rs.alternative-grants",
  "rs.member-roles",
  "rs.extension-members",
  "delegation.policy",
  "delegation.inherited-eligibility",
  "transformation-capabilities",
  "scope-projection",
]);

/** The outcomes each check may expect. */
const OUTCOMES: Record<string, readonly string[]> = {
  "resource-match": ["match", "no-match"],
  "target-resolution": ["refuse-resolution", "no-match"],
  subset: ["subset", "not-subset"],
  derive: ["derived", "refuse"],
  "delegate-matcher": ["permitted", "not-permitted"],
  "delegate-eligibility": ["eligible", "not-eligible", "narrowed-out"],
  "rs-authorize": ["allow", "deny", "reject-token"],
  "capability-declaration": ["declared", "invalid-claim"],
  issuance: ["issue", "refuse-issuance", "refuse"],
  projection: ["safe", "unsafe"],
};

interface Case {
  id: string;
  description: string;
  role: string;
  requires: string[];
  unless?: string[];
  check: string;
  input: Record<string, unknown>;
  expected: { outcome: string; reason: string; error?: string; entries?: AuthorityEntry[] };
  refs: string[];
}
interface CaseFile {
  format: string;
  group: string;
  description: string;
  cases: Case[];
}

const files = readdirSync(DIR)
  .filter((f) => f.endsWith(".json"))
  .sort()
  .map((f) => ({ name: f, doc: JSON.parse(readFileSync(join(DIR, f), "utf8")) as CaseFile }));

const intent = { target_resources: ["https://api.example/orders", "https://erp.example.com"] } as unknown as MissionIntent;

/** Runs one case against this implementation; called only when every required capability is implemented. */
function run(c: Case): void {
  const input = c.input;
  switch (c.check) {
    case "subset": {
      const result = isSubsetEntry(input.candidate as AuthorityEntry, input.reference as AuthorityEntry);
      expect(result, c.expected.reason).toBe(c.expected.outcome === "subset");
      return;
    }
    case "derive": {
      const derive = () =>
        deriveAuthoritySet(
          intent,
          { policy_version: "resource-access-cases", ceiling: input.ceiling as AuthorityEntry[] },
          input.proposal as AuthorityEntry[] | undefined,
        );
      if (c.expected.outcome === "refuse") {
        let error: unknown;
        try {
          derive();
        } catch (e) {
          error = e;
        }
        expect(error, c.expected.reason).toBeInstanceOf(IntentError);
        expect((error as IntentError).code).toBe(c.expected.error);
      } else if (c.expected.entries === undefined) {
        expect(derive, c.expected.reason).not.toThrow();
      } else {
        expect(derive(), c.expected.reason).toEqual(c.expected.entries);
      }
      return;
    }
    case "delegate-matcher": {
      const delegate = input.delegate as { sub: string; sub_profile?: string };
      const matchers = (input.allowed_delegates ?? undefined) as Parameters<typeof delegatePermitted>[1];
      // Only an AS-asserted profile reaches the matcher; a self-asserted one never does.
      const permitted = delegatePermitted({ sub: delegate.sub, assertedProfile: delegate.sub_profile }, matchers);
      expect(permitted, c.expected.reason).toBe(c.expected.outcome === "permitted");
      return;
    }
    case "resource-match": {
      // The matcher the PDP and the resource servers enforce with (#1276). An entry
      // given as JSON text is compared after JSON decoding, never reserialized.
      const entry = input.entry as { resource: string; resource_match?: string };
      const text = input.entry_resource_json_text;
      const resource = typeof text === "string" ? (JSON.parse(text) as string) : entry.resource;
      const target = input.target as string;
      // An explicit service-level contract establishes the target the case names.
      if ((input.contract as { service_level?: boolean } | undefined)?.service_level === true) {
        expect(establishOperationTarget({ service: target })).toEqual({ ok: true, target });
      }
      expect(matchResource({ ...entry, resource }, target), c.expected.reason).toBe(c.expected.outcome);
      return;
    }
    case "target-resolution": {
      // Establishment from the operation contract (#1276): each refusal must be
      // the one the case describes, never another path's refusal.
      const contract = input.contract as { candidates?: unknown[] } | null;
      if (c.expected.outcome !== "refuse-resolution") throw new Error(`${c.id}: no executor for ${c.expected.outcome}`);
      if (contract === null) {
        expect(establishOperationTarget(undefined), c.expected.reason).toEqual({ ok: false, reason: "no_contract" });
      } else if (Array.isArray(contract.candidates)) {
        expect(resolveOperationTarget(contract.candidates), c.expected.reason).toEqual({ ok: false, reason: "ambiguous" });
      } else {
        throw new Error(`${c.id}: no executor for this contract form`);
      }
      return;
    }
    case "delegate-eligibility":
      runDelegateEligibility(c);
      return;
    default:
      throw new Error(`${c.id}: no executor for check ${c.check}`);
  }
}

/** The Mission Issuer, resource and action a delegate-eligibility case's kernel runs with. */
const CASE_ISSUER = "https://as.cases.example";
const CASE_RESOURCE = "https://erp.example.com";
const CASE_ACTION = "invoices.read";
let statusKey: CryptoKey;
beforeAll(async () => {
  ({ privateKey: statusKey } = await generateKeyPair("ES256", { extractable: true }));
});

type DelegationMember = { max_depth: number; allowed_delegates?: Array<{ sub?: string; sub_profile?: string }> };

/**
 * #1275 (D457): a `delegate-eligibility` case through the real derivation,
 * persistence and gate. A kernel whose ceiling holds the case's ceiling entry
 * derives the approved entry from a proposal carrying the approved entry's
 * `delegation`, retains its provenance with the Mission, and decides the
 * presented entry's eligibility for the authenticated delegate at the accounted
 * depth, under a policy hook permitting exactly `policy.permit` (the reference
 * default denies every delegate). The two unresolvable contexts are produced
 * on the same path: a presented entry no approved entry backs, and a Mission
 * whose stored provenance is gone.
 */
function runDelegateEligibility(c: Case): void {
  const input = c.input as {
    ceiling_entry_delegation: DelegationMember | null;
    approved_entry_delegation: DelegationMember | null;
    entry_delegation?: DelegationMember;
    context?: "approved-entry-unresolvable" | "provenance-unresolvable";
    policy: { permit?: string[]; deny?: string[] };
    delegate: { sub: string; sub_profile?: string };
    depth: number;
  };
  const entryWith = (delegation: DelegationMember | null | undefined, action = CASE_ACTION): AuthorityEntry => ({
    type: "mission_resource_access",
    resource: CASE_RESOURCE,
    actions: [action],
    ...(delegation ? { delegation } : {}),
  });
  // A case naming no ceiling entry (its provenance is what cannot be
  // resolved) derives the approved entry under a ceiling entry carrying it.
  const ceiling = [entryWith(input.ceiling_entry_delegation ?? input.approved_entry_delegation)];
  const permit = input.policy.permit ?? [];
  const deny = input.policy.deny ?? [];
  const kernel = new MissionKernel({
    issuer: CASE_ISSUER,
    policy: { policy_version: "resource-access-cases", ceiling },
    authoritySourceCatalog: testAuthoritySourceCatalog(ceiling, ["agent"], ["bob"]),
    statusKey,
    statusKid: "cases-status",
    delegationPolicy: ({ delegate }) => permit.includes(delegate.sub) && !deny.includes(delegate.sub),
  });
  const mission = kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({
        goal: "Decide one delegate-eligibility case",
        target_resources: [CASE_RESOURCE],
        expires_at: "2099-01-01T00:00:00Z",
      }),
    ),
    proposedAuthority: [entryWith(input.approved_entry_delegation ?? input.ceiling_entry_delegation)],
    subject: { iss: CASE_ISSUER, sub: "alice" },
    approver: { iss: CASE_ISSUER, sub: "bob" },
    clientId: "agent",
    approvalEventId: `apev-${c.id}`,
  });
  if (input.approved_entry_delegation) {
    expect(mission.authority_set[0]?.delegation, `${c.id}: the derived approved entry`).toEqual(
      input.approved_entry_delegation,
    );
  }
  if (input.context === "provenance-unresolvable") {
    kernel.db.prepare("UPDATE missions SET eligibility_provenance_json = NULL WHERE id = ?").run(mission.id);
  }
  const record = kernel.get(mission.id);
  if (!record) throw new Error(`${c.id}: no Mission`);
  let candidates: Array<OriginProjection<AuthorityEntry>>;
  if (input.context === "approved-entry-unresolvable") {
    // A presented entry the Mission holds no approved entry for resolves to none.
    const presented = entryWith(input.ceiling_entry_delegation, "invoices.approve");
    expect(kernel.projectCredentialWithOrigin(record, [presented])).toEqual([]);
    candidates = [{ entry: presented, origins: [] }];
  } else if (input.entry_delegation) {
    // The entry presented at the exchange, resolved to its approved entries.
    candidates = kernel.projectCredentialWithOrigin(record, [entryWith(input.entry_delegation)]);
  } else {
    candidates = kernel.effectiveDelegationCandidates(record);
  }
  expect(candidates, `${c.id}: one candidate entry`).toHaveLength(1);
  const delegate = { sub: input.delegate.sub, assertedProfile: input.delegate.sub_profile };
  const [decision] = kernel.delegationEligibility(record, candidates, delegate, input.depth);
  expect(decision?.outcome, c.expected.reason).toBe(c.expected.outcome);
}

const EXECUTABLE_CHECKS = new Set([
  "subset",
  "derive",
  "delegate-matcher",
  "delegate-eligibility",
  "resource-match",
  "target-resolution",
]);

/** A capability is known when the README names it, or it is one `constraints` key or entry member. */
const knownCapability = (cap: string) => KNOWN_CAPABILITIES.has(cap) || /^(constraint|member)\.[a-z0-9_]+$/.test(cap);

/** Why a case does not run for a consumer implementing `implemented`, or undefined when it applies. */
function skipReason(c: Case, implemented: ReadonlySet<string> = IMPLEMENTED): string | undefined {
  const missing = c.requires.filter((cap) => !implemented.has(cap));
  if (!EXECUTABLE_CHECKS.has(c.check) && missing.length === 0) missing.push(`executor:${c.check}`);
  if (missing.length > 0) return `requires ${missing.join(", ")}`;
  const excluded = (c.unless ?? []).filter((cap) => implemented.has(cap));
  if (excluded.length > 0) return `not applicable: implements ${excluded.join(", ")}`;
  return undefined;
}

/**
 * Cases the conformance ledger cites as witnesses. Each runs once, in the static
 * block below, under a literal test name the ledger can resolve; the loop skips it.
 */
const CITED = new Set([
  "sub-res-01",
  "sub-res-02",
  "sub-res-03",
  "sub-ra-01",
  "sub-ra-02",
  "dg-inherit-01",
  "dg-inherit-02",
  "dg-inherit-03",
  "dg-inherit-04",
  "dg-inherit-05",
  "dg-inherit-06",
  "dg-inherit-07",
]);
const byId = new Map(files.flatMap(({ doc }) => doc.cases.map((c) => [c.id, c] as const)));
function runCited(id: string): void {
  const c = byId.get(id);
  if (!c) throw new Error(`no case ${id}`);
  expect(skipReason(c), `${id} must apply to this implementation`).toBeUndefined();
  run(c);
}

describe("Mission Resource Access expected-outcome cases (#1258, D452)", () => {
  it("validates every case file: format, group, unique ids, roles, checks, outcomes, capabilities and applicability", () => {
    expect(files.length).toBeGreaterThan(0);
    const ids = new Set<string>();
    for (const { name, doc } of files) {
      expect(doc.format, name).toBe(FORMAT);
      expect(`${doc.group}.json`, name).toBe(name);
      expect(doc.cases.length, name).toBeGreaterThan(0);
      for (const c of doc.cases) {
        expect(ids.has(c.id), `${name}: duplicate id ${c.id}`).toBe(false);
        ids.add(c.id);
        expect(["authorization-server", "resource-server"], c.id).toContain(c.role);
        expect(Object.keys(OUTCOMES), c.id).toContain(c.check);
        expect(OUTCOMES[c.check], c.id).toContain(c.expected.outcome);
        expect(typeof c.expected.reason, c.id).toBe("string");
        expect(Array.isArray(c.requires) && Array.isArray(c.refs) && c.refs.length > 0, c.id).toBe(true);
        for (const cap of [...c.requires, ...(c.unless ?? [])]) {
          expect(knownCapability(cap), `${c.id}: unknown capability ${cap}`).toBe(true);
        }
        if (c.unless !== undefined) expect(c.unless.length, `${c.id}: empty unless`).toBeGreaterThan(0);
        // A refusal of unsupported input names the capability whose absence it tests.
        if (c.requires.includes("refusal.unsupported-input")) {
          expect(c.unless?.length ?? 0, `${c.id}: an unsupported-input case needs unless`).toBeGreaterThan(0);
        }
        if (c.expected.outcome === "refuse") expect(typeof c.expected.error, c.id).toBe("string");
      }
    }
  });

  it("never runs a refusal of unsupported input for a consumer that implements the input", () => {
    const refusals = [...byId.values()].filter((c) => c.requires.includes("refusal.unsupported-input"));
    expect(refusals.length).toBeGreaterThan(0);
    for (const c of refusals) {
      for (const cap of c.unless ?? []) {
        expect(skipReason(c, new Set([...IMPLEMENTED, cap])), `${c.id} with ${cap}`).toBe(
          `not applicable: implements ${cap}`,
        );
      }
    }
  });

  describe("witnesses the conformance ledger cites", () => {
    it("sub-res-01: an exact candidate is within an exact reference with the identical resource", () => {
      runCited("sub-res-01");
    });
    it("sub-res-02: an exact candidate differing only in host case is not within an exact reference", () => {
      runCited("sub-res-02");
    });
    it("sub-res-03: an exact candidate carrying a query its exact reference lacks is not within it", () => {
      runCited("sub-res-03");
    });
    it("sub-ra-01: a candidate omitting requires_action_approval is within a reference carrying false", () => {
      runCited("sub-ra-01");
    });
    it("sub-ra-02: a candidate omitting requires_action_approval is not within a reference carrying true", () => {
      runCited("sub-ra-02");
    });
    it("dg-inherit-01: the inherited policy denies Carol although the derived entry's list names her", () => {
      runCited("dg-inherit-01");
    });
    it("dg-inherit-02: the list omits Bob although the inherited policy permits him", () => {
      runCited("dg-inherit-02");
    });
    it("dg-inherit-03: a presented entry no approved entry backs narrows out", () => {
      runCited("dg-inherit-03");
    });
    it("dg-inherit-04: a list the proposal added over a policy-deferring ceiling entry does not admit a delegate the policy denies", () => {
      runCited("dg-inherit-04");
    });
    it("dg-inherit-05: a delegate the inherited policy and the list both permit is eligible within the depth bound", () => {
      runCited("dg-inherit-05");
    });
    it("dg-inherit-06: an approved entry whose provenance is gone narrows out though list and policy would permit", () => {
      runCited("dg-inherit-06");
    });
    it("dg-inherit-07: a proposal-added list over a policy-deferring ceiling entry admits a delegate both permit", () => {
      runCited("dg-inherit-07");
    });
  });

  for (const { name, doc } of files) {
    describe(`${doc.group} (${name})`, () => {
      for (const c of doc.cases) {
        if (CITED.has(c.id)) continue;
        const reason = skipReason(c);
        if (reason !== undefined) {
          it.skip(`${c.id}: ${c.description} [skipped: ${reason}]`, () => {});
        } else {
          it(`${c.id}: ${c.description}`, () => run(c));
        }
      }
    });
  }
});
