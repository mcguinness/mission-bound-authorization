/**
 * @spec mission#record-content-members, mission#integrity-anchors,
 * mission#approval-commit (#1917, D1061): the Mission Record's three
 * integrity anchors are OPTIONAL members with implied values, within the
 * owner's five boundaries:
 *
 * 1. stable construction: the specified sha-256 anchor with the fixed `typ`
 *    values and `iss` = the record's `issuer`;
 * 2. authoritative inputs: `intent`, `authority_set` in stored order, and
 *    `proposed_authority` when present, never a served or effective set;
 * 3. present values: a recorded anchor that differs is refused, never
 *    replaced;
 * 4. creation-time binding: every ceremony and artifact still gets its
 *    anchor at approval;
 * 5. record bytes: resolving never inserts a member into the approval event
 *    preimage and never removes one.
 *
 * `KernelOptions.recordAnchors: false` is the deployment that does not
 * retain the anchors; the default retains them.
 */
import { createHash } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  approvalContextCommitment,
  approvalContextManifest,
  authorityHash,
  canonicalize,
  intentHash,
  type JsonValue,
  LocalApprovedSetVerificationError,
  proposalHash,
  verifyLocalApprovedSet,
} from "@mission/core";
import { APPROVAL_FLOOR, DERIVATION_POLICY, TOPOLOGY, WRITE_ACTIONS } from "@mission/demo-data";
import { openStore } from "@mission/store";
import { type CryptoKey, generateKeyPair } from "jose";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { approvalContext } from "../src/adapters/approval-render-revision.js";
import {
  AnchorMismatchError,
  type ApprovalGovernanceRecord,
  approvalEventPreimage,
  type AuthorityEntry,
  createChildMission,
  directApprovalRuleFrom,
  isSubsetEntry,
  MissionKernel,
  type MissionRecord,
  recheckApprovalGovernanceRecord,
  resolvedAnchors,
  validateMissionIntent,
  verifyApprovalGovernanceRecord,
} from "../src/index.js";
import { aiAgents } from "./actor-profiles.helper.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const ISS = "https://as.test";
const T0 = Date.parse("2026-07-01T00:00:00Z");
const now = () => new Date(T0);
const EXP = "2027-01-01T00:00:00Z";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
const LEDGER = TOPOLOGY.resources.saas;
const ALICE = { iss: ISS, sub: "alice" };
const BOB = { iss: ISS, sub: "bob" };
const CATALOG = testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["ap-agent"], ["bob"]);

/** Two entries on two resources, so the stored array has an order to keep. */
const PROPOSAL: AuthorityEntry[] = [
  {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions: ["payments:invoice.read", "payments:payment.execute"],
    constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  },
  { type: "mission_resource_access", resource: LEDGER, actions: ["ledger:entry.read"], constraints: { vendors: ["acme"] } },
] as AuthorityEntry[];
const AUTH = { acr: "mfa", auth_time: Math.floor(T0 / 1000) - 60, interactive: true };

let key: CryptoKey;
beforeAll(async () => {
  key = (await generateKeyPair("ES256")).privateKey;
});
afterEach(() => {
  vi.restoreAllMocks();
});

const makeKernel = (opts: { recordAnchors?: boolean; file?: string; recording?: boolean } = {}) =>
  new MissionKernel({
    issuer: ISS,
    policy: DERIVATION_POLICY as never,
    authoritySourceCatalog: CATALOG,
    statusKey: key,
    statusKid: "as-status",
    now,
    actorProfiles: aiAgents("subagent-extractor"),
    ...(opts.recordAnchors !== undefined ? { recordAnchors: opts.recordAnchors } : {}),
    ...(opts.file ? { store: { file: opts.file } } : {}),
    ...(opts.recording
      ? {
          directApprovalRecording: {
            rule: directApprovalRuleFrom({
              floor: APPROVAL_FLOOR,
              knownSubjects: new Set(["alice", "bob"]),
              approverApprovesFor: new Map([["bob", new Set(["alice"])]]),
              approverRoleSubs: new Set(["bob"]),
              writeActions: WRITE_ACTIONS,
              catalog: CATALOG,
            }),
          },
        }
      : {}),
  });

let seq = 0;
type ApproveInput = Parameters<MissionKernel["approve"]>[0];
/** `null` submits no proposal. */
const approveInput = (proposal: AuthorityEntry[] | null, over: Partial<ApproveInput> = {}): ApproveInput => ({
  intent: validateMissionIntent(
    JSON.stringify({ goal: "Pay Acme invoices for Q3", target_resources: [RESOURCE, LEDGER], expires_at: EXP }),
    { now: now() },
  ),
  ...(proposal ? { proposedAuthority: structuredClone(proposal) } : {}),
  subject: ALICE,
  approver: BOB,
  clientId: "ap-agent",
  approvalEventId: `apev-1917-${seq++}`,
  ...over,
});
const approve = (kernel: MissionKernel, proposal: AuthorityEntry[] | null = PROPOSAL, over: Partial<ApproveInput> = {}) =>
  kernel.approve(approveInput(proposal, over));

const anchorColumns = (kernel: MissionKernel, id: string) =>
  kernel.db.prepare("SELECT intent_hash, authority_hash, proposal_hash FROM missions WHERE id = ?").get(id) as Record<
    string,
    unknown
  >;
const stored = (kernel: MissionKernel, id: string) => kernel.get(id) as MissionRecord;
const refusal = (f: () => unknown): unknown => {
  try {
    f();
  } catch (e) {
    return e;
  }
  throw new Error("expected a refusal");
};

describe("genuine omission (@spec mission#record-content-members, #1917)", () => {
  it("a recordAnchors: false kernel stores NULL for all three anchors, reads the record back without them, and resolves each to the anchor over the stored object", () => {
    const kernel = makeKernel({ recordAnchors: false });
    const created = approve(kernel);
    expect(anchorColumns(kernel, created.id)).toEqual({ intent_hash: null, authority_hash: null, proposal_hash: null });
    const record = stored(kernel, created.id);
    for (const member of ["intent_hash", "authority_hash", "proposal_hash"]) {
      expect(record, member).not.toHaveProperty(member);
      // The record the creating body holds is the one committed.
      expect(created, member).not.toHaveProperty(member);
    }
    expect(record.proposed_authority).toBeDefined();
    expect(resolvedAnchors(record)).toStrictEqual({
      intent_hash: intentHash(record.issuer, record.intent as never),
      authority_hash: authorityHash(record.issuer, record.authority_set as never),
      proposal_hash: proposalHash(record.issuer, record.proposed_authority as never),
    });
    // Resolving reads only.
    expect(record).not.toHaveProperty("intent_hash");
  });
});

describe("recorded anchors: a match resolves to itself, a mismatch is refused and never replaced (@spec mission#integrity-anchors, #1917)", () => {
  it("a recorded anchor that equals its implied value resolves to itself", () => {
    const kernel = makeKernel();
    const record = stored(kernel, approve(kernel).id);
    const { intent_hash, authority_hash, proposal_hash } = record;
    expect(typeof intent_hash).toBe("string");
    expect(resolvedAnchors(record)).toStrictEqual({ intent_hash, authority_hash, proposal_hash });
  });

  for (const member of ["intent_hash", "authority_hash", "proposal_hash"] as const) {
    // Mutation: dropping the comparison in resolvedAnchors returns the fresh
    // value instead, and these refusals no longer throw.
    it(`a recorded ${member} altered in storage is refused, and the stored value is never replaced`, () => {
      const kernel = makeKernel();
      const id = approve(kernel).id;
      const altered = "sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
      kernel.db.prepare(`UPDATE missions SET ${member} = ? WHERE id = ?`).run(altered, id);
      const record = stored(kernel, id);
      const e = refusal(() => resolvedAnchors(record));
      expect(e).toBeInstanceOf(AnchorMismatchError);
      expect((e as AnchorMismatchError).member).toBe(member);
      expect((e as AnchorMismatchError).code).toBe("anchor_mismatch");
      expect(record[member]).toBe(altered);
      expect(anchorColumns(kernel, id)[member]).toBe(altered);
    });
  }

  it("a recorded proposal_hash on a record without proposed_authority has no implied value and is refused", () => {
    const kernel = makeKernel();
    const id = approve(kernel, null).id;
    expect(stored(kernel, id)).not.toHaveProperty("proposed_authority");
    kernel.db.prepare("UPDATE missions SET proposal_hash = ? WHERE id = ?").run("sha-256:stray", id);
    const e = refusal(() => resolvedAnchors(stored(kernel, id)));
    expect(e).toBeInstanceOf(AnchorMismatchError);
    expect((e as AnchorMismatchError).member).toBe("proposal_hash");
  });

  it("a path that emits an anchor refuses a mismatching recorded one rather than emitting a fresh value", () => {
    const kernel = makeKernel();
    const id = approve(kernel).id;
    kernel.db.prepare("UPDATE missions SET authority_hash = ? WHERE id = ?").run("sha-256:altered", id);
    const record = stored(kernel, id);
    const provenance = { disclose: new Set(["provenance"]) };
    expect(refusal(() => kernel.introspectionProjection(record, provenance))).toBeInstanceOf(AnchorMismatchError);
    expect(refusal(() => kernel.introspectionMission(record))).toBeInstanceOf(AnchorMismatchError);
    expect(refusal(() => kernel.approvalContextInput(record))).toBeInstanceOf(AnchorMismatchError);
    expect(
      refusal(() => kernel.statusObservation(id, { requester: "svc:test", discloseProvenance: true })),
    ).toBeInstanceOf(AnchorMismatchError);
    expect(refusal(() => kernel.approvedSetRetrieval(id))).toBeInstanceOf(AnchorMismatchError);
    // A caller without the disclosure privilege is shown no anchor, so nothing is resolved for it.
    expect(kernel.introspectionProjection(record, { disclose: new Set() })).not.toHaveProperty("authority_hash");
  });
});

describe("proposal_hash present exactly with proposed_authority (@spec mission#integrity-anchors, #1917)", () => {
  it("with a proposal, proposal_hash resolves both recorded and omitted, to the same value", () => {
    const recordedKernel = makeKernel();
    const omittedKernel = makeKernel({ recordAnchors: false });
    const recorded = stored(recordedKernel, approve(recordedKernel).id);
    const omitted = stored(omittedKernel, approve(omittedKernel).id);
    expect(recorded.proposal_hash).toBe(proposalHash(ISS, recorded.proposed_authority as never));
    expect(omitted).not.toHaveProperty("proposal_hash");
    expect(resolvedAnchors(recorded).proposal_hash).toBe(recorded.proposal_hash);
    expect(resolvedAnchors(omitted).proposal_hash).toBe(proposalHash(ISS, omitted.proposed_authority as never));
    expect(resolvedAnchors(omitted).proposal_hash).toBe(recorded.proposal_hash);
  });

  it("without a proposal, proposal_hash is absent from the record and from the resolver, recorded or omitted", () => {
    for (const recordAnchors of [true, false]) {
      const kernel = makeKernel({ recordAnchors });
      const record = stored(kernel, approve(kernel, null).id);
      expect(record, String(recordAnchors)).not.toHaveProperty("proposed_authority");
      expect(record, String(recordAnchors)).not.toHaveProperty("proposal_hash");
      expect(resolvedAnchors(record), String(recordAnchors)).not.toHaveProperty("proposal_hash");
      expect(kernel.approvalContextInput(record), String(recordAnchors)).not.toHaveProperty("proposal_hash");
    }
  });
});

describe("authoritative inputs (@spec mission#integrity-anchors, #1917)", () => {
  // Mutation: computing authority_hash over the effective set (in the
  // resolver, or at a reader) moves every value below off the creation-time
  // one once containment applies.
  it("a contained Mission resolves authority_hash over its approved authority_set, the creation-time value, never its effective set", () => {
    const kernel = makeKernel({ recordAnchors: false });
    const created = approve(kernel);
    // The value computed at approval, retained on the basis as its root.
    const atCreation = created.approval_basis.root_commitment as string;
    kernel.contain(created.id, {
      event: { type: "anomaly.detected", source: "svc:soc", observed_at: now().toISOString(), event_id: "evt-1917" },
      remove: [{ resource: RESOURCE, actions: ["payments:payment.execute"] }],
    });
    const record = stored(kernel, created.id);
    const effective = kernel.effectiveAuthoritySet(record);
    expect(authorityHash(ISS, effective as never)).not.toBe(atCreation);
    expect(resolvedAnchors(record).authority_hash).toBe(atCreation);
    expect(kernel.introspectionProjection(record, { disclose: new Set(["provenance"]) }).authority_hash).toBe(atCreation);
    expect(kernel.introspectionMission(record).authority_hash).toBe(atCreation);
    expect(kernel.approvalContextInput(record).authority_hash).toBe(atCreation);
    const status = kernel.statusObservation(created.id, { requester: "svc:test", discloseProvenance: true });
    expect((status.payload.mission as Record<string, unknown>).authority_hash).toBe(atCreation);
  });

  it("reordering the stored authority_set changes the implied value: array order is kept", () => {
    const kernel = makeKernel({ recordAnchors: false });
    const id = approve(kernel).id;
    const before = stored(kernel, id);
    expect(before.authority_set.length).toBeGreaterThan(1);
    const reversed = [...before.authority_set].reverse();
    kernel.db.prepare("UPDATE missions SET authority_set_json = ? WHERE id = ?").run(JSON.stringify(reversed), id);
    const after = stored(kernel, id);
    expect(resolvedAnchors(after).authority_hash).toBe(authorityHash(ISS, reversed as never));
    expect(resolvedAnchors(after).authority_hash).not.toBe(resolvedAnchors(before).authority_hash);
    // Where the anchor is recorded, the same reorder is a mismatch.
    const recordedKernel = makeKernel();
    const rid = approve(recordedKernel).id;
    const rset = [...stored(recordedKernel, rid).authority_set].reverse();
    recordedKernel.db.prepare("UPDATE missions SET authority_set_json = ? WHERE id = ?").run(JSON.stringify(rset), rid);
    expect(refusal(() => resolvedAnchors(stored(recordedKernel, rid)))).toBeInstanceOf(AnchorMismatchError);
  });

  // Mutation: taking the retrieval's authority_hash from the served set
  // (authorityHash over the projection) lets the substituted set verify.
  it("Approved-Set Verification Tier 1: a retrieval whose served set differs from the approved one fails closed against the stored record's anchor", () => {
    for (const recordAnchors of [true, false]) {
      const kernel = makeKernel({ recordAnchors });
      const id = approve(kernel).id;
      const carried = [stored(kernel, id).authority_set[0]] as unknown as JsonValue[];
      const subset = (c: JsonValue, g: JsonValue) => isSubsetEntry(c as never, g as never);
      // Unaltered, the retrieval verifies.
      const honest = kernel.approvedSetRetrieval(id);
      expect(honest?.authority_hash).toBe(resolvedAnchors(stored(kernel, id)).authority_hash);
      expect(() => verifyLocalApprovedSet(honest as never, carried, subset)).not.toThrow();
      // The served set loses an entry between the record store and the response.
      vi.spyOn(kernel, "approvedSetProjection").mockImplementation((record) => record.authority_set.slice(0, 1));
      const substituted = kernel.approvedSetRetrieval(id);
      expect(substituted?.authority_set).toHaveLength(1);
      const e = refusal(() => verifyLocalApprovedSet(substituted as never, carried, subset));
      expect(e, String(recordAnchors)).toBeInstanceOf(LocalApprovedSetVerificationError);
      expect((e as LocalApprovedSetVerificationError).reason).toBe("commitment_mismatch");
      vi.restoreAllMocks();
    }
  });
});

describe("creation-time binding with anchors not retained (@spec mission#approval-commit, #1917)", () => {
  it("the Approval Governance Record carries the anchors computed at approval and verifies against the omitted-anchor Mission", () => {
    const kernel = makeKernel({ recordAnchors: false, recording: true });
    const created = approve(kernel, PROPOSAL, { authentication: AUTH });
    const mission = stored(kernel, created.id);
    expect(mission).not.toHaveProperty("authority_hash");
    const agr = kernel.governanceRecords.forMission(mission.id) as ApprovalGovernanceRecord;
    expect(agr.mission).toStrictEqual({
      issuer: ISS,
      intent_hash: intentHash(ISS, mission.intent as never),
      authority_hash: created.approval_basis.root_commitment,
    });
    const anchors = resolvedAnchors(mission);
    expect(agr.mission.intent_hash).toBe(anchors.intent_hash);
    expect(agr.mission.authority_hash).toBe(anchors.authority_hash);
    const resolveKey = (kid: string) => (kid === "as-status" ? kernel.statusVerificationKey() : undefined);
    expect(() => verifyApprovalGovernanceRecord(agr, { resolveKey, mission })).not.toThrow();
    expect(recheckApprovalGovernanceRecord(kernel, mission.id, { resolveKey })).toEqual({ rechecked: true });
  });

  it("the consent rendering's approval context and render revision carry the anchors computed at approval, and the decision's recomputation verifies", () => {
    const kernel = makeKernel({ recordAnchors: false });
    const input = approveInput(PROPOSAL);
    const prepared = kernel.prepareApproval(input);
    const contextInput = {
      kernel,
      issuer: ISS,
      intent: input.intent,
      proposal: prepared.proposal,
      authority: prepared.authoritySet,
      clientId: input.clientId,
      subject: input.subject.sub,
      scopeProjection: undefined,
      expiresAt: EXP,
    };
    const rendering = approvalContext(contextInput);
    const record = stored(kernel, kernel.approve({ ...input, renderedExpiresAt: EXP }).id);
    expect(record).not.toHaveProperty("intent_hash");
    const anchors = resolvedAnchors(record);
    expect(rendering.context.intent_hash).toBe(anchors.intent_hash);
    expect(rendering.context.proposal_hash).toBe(anchors.proposal_hash);
    expect(rendering.context.authority_hash).toBe(anchors.authority_hash);
    // The decision re-establishes the context from the same inputs; nothing
    // in it reads the record, so the commitment the revision binds matches.
    expect(approvalContext(contextInput).commitment).toBe(rendering.commitment);
  });

  it("the approval context manifest carries the anchors computed at approval", () => {
    const kernel = makeKernel({ recordAnchors: false });
    const created = approve(kernel);
    const record = stored(kernel, created.id);
    const manifest = approvalContextManifest(kernel.approvalContextInput(record));
    expect(manifest.intent_hash).toBe(intentHash(ISS, created.intent as never));
    expect(manifest.authority_hash).toBe(created.approval_basis.root_commitment);
    expect(manifest.proposal_hash).toBe(proposalHash(ISS, created.proposed_authority as never));
  });

  it("Child Delegation's parent.authority_hash equals the parent's resolved authority_hash", () => {
    const kernel = makeKernel({ recordAnchors: false });
    const parent = approve(kernel);
    const { child, evidence } = createChildMission(kernel, {
      parentId: parent.id,
      intent: validateMissionIntent(JSON.stringify({ goal: "Extract Acme invoices", target_resources: [RESOURCE], expires_at: EXP })),
      proposedAuthority: [
        {
          type: "mission_resource_access",
          resource: RESOURCE,
          actions: ["payments:invoice.read"],
          constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
        },
      ] as AuthorityEntry[],
      childActor: { sub: "subagent-extractor", sub_profile: "ai_agent" },
    });
    const parentAnchor = resolvedAnchors(stored(kernel, parent.id)).authority_hash;
    expect(parentAnchor).toBe(parent.approval_basis.root_commitment);
    expect(stored(kernel, child.id).parent?.authority_hash).toBe(parentAnchor);
    expect(evidence.parent.authority_hash).toBe(parentAnchor);
    expect(stored(kernel, child.id)).not.toHaveProperty("authority_hash");
  });
});

describe("Approval Context Manifest v1 unchanged (@spec mission#integrity-anchors, #1917)", () => {
  /** One Mission inserted, byte for byte, into a kernel that retains anchors and one that does not. */
  const sameMissionTwice = (proposal: AuthorityEntry[] | null) => {
    const source = makeKernel();
    const template = source.approve(approveInput(proposal));
    const pair = [makeKernel(), makeKernel({ recordAnchors: false })].map((kernel) => {
      // A Mission approved here only to lend the copy its committed source binding.
      const sibling = kernel.approve(approveInput(proposal));
      const copy: MissionRecord = structuredClone(template);
      kernel.insertRecord(copy, undefined, { source: { inherited: kernel.committedSourceBinding(sibling.id) }, audiences: "fresh" });
      return { kernel, record: stored(kernel, copy.id) };
    });
    return pair as [{ kernel: MissionKernel; record: MissionRecord }, { kernel: MissionKernel; record: MissionRecord }];
  };

  for (const [label, proposal] of [
    ["with a proposal", PROPOSAL],
    ["without a proposal", null],
  ] as const) {
    it(`a manifest built for a Mission that omits its anchors is byte-identical to the same Mission with them recorded, ${label}`, () => {
      const [recorded, omitted] = sameMissionTwice(proposal);
      expect(recorded.record).toHaveProperty("authority_hash");
      expect(omitted.record).not.toHaveProperty("authority_hash");
      const a = approvalContextManifest(recorded.kernel.approvalContextInput(recorded.record));
      const b = approvalContextManifest(omitted.kernel.approvalContextInput(omitted.record));
      expect(canonicalize(b)).toBe(canonicalize(a));
      expect(approvalContextCommitment(ISS, b)).toBe(approvalContextCommitment(ISS, a));
      expect("proposal_hash" in b).toBe(proposal !== null);
    });
  }
});

describe("record bytes (@spec mission#record-content-members, #1917)", () => {
  // Mutation: building the preimage from a record with resolvedAnchors
  // spread into it gives the omitted-anchor record anchor members.
  it("approvalEventPreimage keeps each record's members as recorded, and resolving anchors changes neither preimage", () => {
    const omittedKernel = makeKernel({ recordAnchors: false });
    const recordedKernel = makeKernel();
    const created = approve(omittedKernel);
    const omitted = stored(omittedKernel, created.id);
    const recorded = stored(recordedKernel, approve(recordedKernel).id);
    const omittedBytes = approvalEventPreimage(omitted);
    const recordedBytes = approvalEventPreimage(recorded);
    const omittedParsed = JSON.parse(omittedBytes) as Record<string, unknown>;
    const recordedParsed = JSON.parse(recordedBytes) as Record<string, unknown>;
    for (const member of ["intent_hash", "authority_hash", "proposal_hash"] as const) {
      expect(omittedParsed, member).not.toHaveProperty(member);
      expect(recordedParsed[member], member).toBe(recorded[member]);
    }
    expect(omittedParsed).not.toHaveProperty("state");
    expect(recordedParsed).not.toHaveProperty("termination");
    // The creating body's record and the stored one give the same bytes.
    expect(approvalEventPreimage(created)).toBe(omittedBytes);
    // Resolving reads only.
    resolvedAnchors(omitted);
    resolvedAnchors(recorded);
    expect(approvalEventPreimage(omitted)).toBe(omittedBytes);
    expect(approvalEventPreimage(recorded)).toBe(recordedBytes);
  });
});

/** The `missions` table as every store created before #1917 declares it: both anchors NOT NULL. */
const PRE_1917_MISSIONS = `
CREATE TABLE IF NOT EXISTS missions (
  id TEXT PRIMARY KEY,
  issuer TEXT NOT NULL,
  state TEXT NOT NULL,
  intent_json TEXT NOT NULL,
  proposed_authority_json TEXT,
  authority_set_json TEXT NOT NULL,
  intent_hash TEXT NOT NULL,
  proposal_hash TEXT,
  authority_hash TEXT NOT NULL,
  subject_iss TEXT NOT NULL,
  subject_sub TEXT NOT NULL,
  approver_iss TEXT NOT NULL,
  approver_sub TEXT NOT NULL,
  approval_basis_json TEXT NOT NULL,
  authority_source_json TEXT NOT NULL,
  client_id TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  approval_event_id TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  derivation_limit INTEGER,
  derivation_count INTEGER NOT NULL DEFAULT 0,
  grant_id TEXT,
  status_list_idx INTEGER UNIQUE,
  predecessor TEXT,
  successor TEXT,
  related_to TEXT,
  carried_to TEXT,
  parent_id TEXT,
  parent_json TEXT,
  template_id TEXT,
  template_json TEXT,
  projected_from TEXT,
  containment_json TEXT,
  discharged_json TEXT,
  submission_evidence_json TEXT,
  termination_json TEXT,
  ceiling_json TEXT,
  schedule_json TEXT,
  eligibility_provenance_json TEXT,
  child_actor_provenance_json TEXT,
  approved_audiences_json TEXT,
  extensions_json TEXT
) STRICT;
`;

describe("migration: nullable anchor columns (@spec mission#record-content-members, #1917)", () => {
  /** A file-backed store created with the pre-#1917 table, holding Missions a kernel approved, with their anchors. */
  const preRebuildStore = () => {
    const dir = mkdtempSync(join(tmpdir(), "implied-anchors-"));
    const source = makeKernel({ file: join(dir, "source.db") });
    const ids = [approve(source).id, approve(source, null).id];
    const records = ids.map((id) => stored(source, id));
    const rows = source.db.prepare("SELECT * FROM missions ORDER BY id").all() as Array<Record<string, unknown>>;
    source.db.close();
    const file = join(dir, "kernel.db");
    const db = openStore(PRE_1917_MISSIONS, { file });
    const columns = Object.keys(rows[0] as object);
    const insert = db.prepare(
      `INSERT INTO missions (${columns.join(", ")}) VALUES (${columns.map(() => "?").join(", ")})`,
    );
    for (const row of rows) insert.run(...columns.map((c) => row[c]));
    db.close();
    return { file, ids, records };
  };
  /** The store's schema facts and every row, read without opening a kernel. */
  const inspect = (file: string) => {
    const db = openStore("", { file });
    try {
      return {
        schemaVersion: db.pragma("schema_version", { simple: true }) as number,
        columns: db.prepare("PRAGMA table_info(missions)").all() as Array<{ name: string; notnull: number }>,
        indexes: db.prepare("PRAGMA index_list(missions)").all() as Array<Record<string, unknown>>,
        sql: (db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'missions'").get() as { sql: string }).sql,
        rows: db.prepare("SELECT rowid AS _rowid, * FROM missions ORDER BY rowid").all(),
      };
    } finally {
      db.close();
    }
  };
  const notnull = (facts: ReturnType<typeof inspect>, name: string) => facts.columns.find((c) => c.name === name)?.notnull;

  it("rebuilds a store whose anchor columns are NOT NULL once, keeping every record byte-identical with its anchors present", () => {
    const { file, ids, records } = preRebuildStore();
    const before = inspect(file);
    expect(notnull(before, "intent_hash")).toBe(1);
    expect(notnull(before, "authority_hash")).toBe(1);
    const kernel = makeKernel({ file });
    try {
      for (const [i, id] of ids.entries()) {
        const record = stored(kernel, id);
        expect(canonicalize(record as never)).toBe(canonicalize(records[i] as never));
        expect(typeof record.intent_hash).toBe("string");
        expect(resolvedAnchors(record).authority_hash).toBe(record.authority_hash);
      }
    } finally {
      kernel.db.close();
    }
    const after = inspect(file);
    expect(notnull(after, "intent_hash")).toBe(0);
    expect(notnull(after, "authority_hash")).toBe(0);
    // Every other column, the PRIMARY KEY, both UNIQUE constraints, the
    // defaults and STRICT: the definition differs only by the two clauses
    // (and the table name, which SQLite's RENAME writes quoted).
    expect(after.sql.replace('CREATE TABLE "missions"', "CREATE TABLE missions")).toBe(
      before.sql
        .replace("intent_hash TEXT NOT NULL", "intent_hash TEXT")
        .replace("authority_hash TEXT NOT NULL", "authority_hash TEXT"),
    );
    expect(after.indexes.map(({ seq: _s, ...i }) => i)).toEqual(before.indexes.map(({ seq: _s, ...i }) => i));
    expect(after.columns.filter((c) => !["intent_hash", "authority_hash"].includes(c.name))).toEqual(
      before.columns.filter((c) => !["intent_hash", "authority_hash"].includes(c.name)),
    );
    // Every stored value, rowids included, is unchanged.
    expect(after.rows).toEqual(before.rows);
  });

  // Mutation: removing the notnull guard rebuilds on every open, and the
  // schema version moves on the second open.
  it("a second open is a no-op", () => {
    const { file, ids } = preRebuildStore();
    makeKernel({ file }).db.close();
    const first = inspect(file);
    const kernel = makeKernel({ file });
    try {
      expect(stored(kernel, ids[0] as string)).toHaveProperty("authority_hash");
    } finally {
      kernel.db.close();
    }
    const second = inspect(file);
    expect(second.schemaVersion).toBe(first.schemaVersion);
    expect(second.sql).toBe(first.sql);
    expect(second.rows).toEqual(first.rows);
  });
});

describe("stable construction (@spec mission#integrity-anchors, #1917)", () => {
  /** An independent reference: JCS by sorted-key JSON, sha-256, the literal `typ` strings. */
  const sorted = (v: unknown): unknown =>
    Array.isArray(v)
      ? v.map(sorted)
      : v !== null && typeof v === "object"
        ? Object.fromEntries(
            Object.keys(v as object)
              .sort()
              .map((k) => [k, sorted((v as Record<string, unknown>)[k])]),
          )
        : v;
  const reference = (typ: string, iss: string, value: unknown) =>
    `sha-256:${createHash("sha256").update(JSON.stringify(sorted({ typ, iss, value }))).digest("base64url")}`;

  // Mutation: any change to the resolver's construction (another algorithm,
  // another typ, another iss, a configurable construction) breaks this
  // equality.
  it("each implied value equals an independent sha-256 reference over the same object with the fixed typ values", () => {
    const kernel = makeKernel({ recordAnchors: false });
    const record = stored(kernel, approve(kernel).id);
    const anchors = resolvedAnchors(record);
    expect(anchors.intent_hash).toBe(reference("mission-intent", record.issuer, record.intent));
    expect(anchors.authority_hash).toBe(reference("mission-authority-set", record.issuer, record.authority_set));
    expect(anchors.proposal_hash).toBe(reference("mission-proposed-authority", record.issuer, record.proposed_authority));
    expect(anchors.authority_hash).toMatch(/^sha-256:[A-Za-z0-9_-]{43}$/);
  });
});
