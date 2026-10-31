/**
 * @spec mission#mission-record, mission#record-principal-members (#1923,
 * D1059): what the AS keeps, refuses and infers for record content it does
 * not recognize.
 *
 * - An unrecognized top-level member is neither interpreted nor removed: the
 *   store keeps it through insertion, every lifecycle write and a reopen, and
 *   a stored extension never overwrites or supplies a recognized member.
 * - Where `adjudication` is present on a `direct` basis, its `kind` is
 *   `human`: the creation funnel refuses anything else before any write. An
 *   omitted `adjudication` stays valid.
 * - An unrecognized `approval_basis.type` or `adjudication.kind` is stored,
 *   read and returned unchanged, and the Mission stays usable; an operation
 *   that needs the basis's semantics refuses, and the direct-creation guard
 *   does not reject unrecognized provenance on any other basis.
 */
import { DERIVATION_POLICY } from "@mission/demo-data";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair } from "jose";
import { afterAll, describe, expect, it } from "vitest";
import {
  type ApprovalBasis,
  type ApprovalBasisDirect,
  type AuthorityEntry,
  ChildDelegationError,
  createChildMission,
  DirectAdjudicationError,
  MissionKernel,
  type MissionRecord,
  newMissionId,
  validateMissionIntent,
} from "../src/index.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const ISSUER = "https://as.test";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource as string;

const storeDirs: string[] = [];
afterAll(() => {
  for (const dir of storeDirs) rmSync(dir, { recursive: true, force: true });
});
const storeFile = (): string => {
  const dir = mkdtempSync(join(tmpdir(), "mission-1923-"));
  storeDirs.push(dir);
  return join(dir, "kernel.db");
};

const inOneHour = (): string => new Date(Date.now() + 3_600_000).toISOString();

async function makeKernel(file?: string): Promise<MissionKernel> {
  const { privateKey } = await generateKeyPair("ES256");
  return new MissionKernel({
    issuer: ISSUER,
    policy: DERIVATION_POLICY as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["ap-agent"], ["bob"]),
    statusKey: privateKey,
    statusKid: "as-status",
    actorProfiles: { "child-agent": "ai_agent" },
    ...(file ? { store: { file } } : {}),
  } as never);
}

/** One approved direct Mission: the source every copy below inherits. */
function approveOne(kernel: MissionKernel, event: string): MissionRecord {
  return kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({ goal: "Review", target_resources: [RESOURCE], expires_at: inOneHour() }),
    ),
    subject: { iss: ISSUER, sub: "alice" },
    approver: { iss: ISSUER, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: event,
  });
}

/** Commit `record` through the creation funnel, inheriting `original`'s source. */
function create(kernel: MissionKernel, original: MissionRecord, record: MissionRecord): void {
  kernel.insertRecord(record, undefined, {
    source: { inherited: kernel.committedSourceBinding(original.id) },
    audiences: "fresh",
  });
}

/**
 * A copy of `original` under its own approval event, with `over` applied. Its
 * default basis is `direct` with the implied members omitted, so the copy
 * names no other approval event.
 */
function copyOf(original: MissionRecord, event: string, over: Record<string, unknown> = {}): MissionRecord {
  return {
    ...original,
    id: newMissionId(),
    approval_event_id: event,
    approval_basis: { type: "direct", consent_principal: original.approval_basis.consent_principal },
    ...over,
  } as MissionRecord;
}

/** Run `fn`; return what it threw, or undefined. */
function thrown(fn: () => unknown): unknown {
  try {
    fn();
  } catch (e) {
    return e;
  }
  return undefined;
}

// Two members this issuer does not define, as a later issuer version or a
// companion profile could record them: a structured one and a URI-named one.
const EXTENSIONS = {
  x_lineage: { predecessor_ref: "msn_elsewhere", depth: 2, notes: ["kept", "as is"] },
  "urn:example:mission:label": "quarter-close",
};

describe("unrecognized top-level record members (@spec mission#mission-record, #1923)", () => {
  it("keeps them through insertion, every lifecycle write and a store reopen, exactly as recorded", async () => {
    const file = storeFile();
    const kernel = await makeKernel(file);
    const original = approveOne(kernel, "ext-original");
    const record = copyOf(original, "ext-copy", EXTENSIONS);
    create(kernel, original, record);
    const read = (k: MissionKernel) => k.get(record.id) as unknown as Record<string, unknown>;
    expect(read(kernel)).toMatchObject(EXTENSIONS);
    expect(kernel.findByApprovalEvent("ext-copy")).toMatchObject(EXTENSIONS);
    expect(kernel.allMissions().find((m) => m.id === record.id)).toMatchObject(EXTENSIONS);
    // Lifecycle writes set named columns; none drops the extensions.
    kernel.gateDerivation(record.id);
    expect(read(kernel).derivation_count).toBe(1);
    kernel.transition(record.id, "suspend");
    kernel.transition(record.id, "resume");
    expect(read(kernel)).toMatchObject({ state: "active", ...EXTENSIONS });
    kernel.transition(record.id, "revoke");
    expect(read(kernel)).toMatchObject({ state: "terminated", ...EXTENSIONS });
    kernel.close();
    // A restart reads the same members back.
    const after = await makeKernel(file);
    try {
      const reopened = after.get(record.id) as unknown as Record<string, unknown>;
      expect(reopened).toMatchObject({ state: "terminated", ...EXTENSIONS });
      for (const [name, value] of Object.entries(EXTENSIONS)) expect(reopened[name], name).toStrictEqual(value);
    } finally {
      after.close();
    }
  });

  it("stores only the unrecognized members, and none for a record that carries none", async () => {
    const kernel = await makeKernel();
    try {
      const original = approveOne(kernel, "ext-original");
      const record = copyOf(original, "ext-copy", EXTENSIONS);
      create(kernel, original, record);
      const column = (id: string) =>
        (kernel.db.prepare("SELECT extensions_json FROM missions WHERE id = ?").get(id) as { extensions_json: string | null })
          .extensions_json;
      expect(JSON.parse(column(record.id) as string)).toStrictEqual(EXTENSIONS);
      expect(column(original.id)).toBeNull();
      // The original, which carries no extension, reads back with none.
      expect(Object.keys(kernel.get(original.id) as object)).not.toContain("x_lineage");
    } finally {
      kernel.close();
    }
  });

  it("never lets a stored extension overwrite or supply a recognized member, or widen authority", async () => {
    const kernel = await makeKernel();
    try {
      const original = approveOne(kernel, "ext-original");
      kernel.transition(original.id, "revoke");
      const terminated = kernel.get(original.id) as MissionRecord;
      // A stored extension naming recognized members: one present (state,
      // authority_set) and one the record lacks (template), beside a real one.
      const wider: AuthorityEntry[] = [
        { type: "mission_resource_access", resource: RESOURCE, actions: ["*"] } as AuthorityEntry,
      ];
      kernel.db
        .prepare("UPDATE missions SET extensions_json = ? WHERE id = ?")
        .run(
          JSON.stringify({
            state: "active",
            authority_set: wider,
            template: { id: "tmpl-forged", version: "1" },
            x_kept: true,
          }),
          original.id,
        );
      const read = kernel.get(original.id) as unknown as Record<string, unknown>;
      expect(read.state).toBe("terminated");
      expect(read.authority_set).toStrictEqual(terminated.authority_set);
      expect(read).not.toHaveProperty("template");
      expect(read.x_kept).toBe(true);
      // The Mission stays terminated: no derivation is admitted.
      expect(thrown(() => kernel.gateDerivation(original.id))).toBeDefined();
    } finally {
      kernel.close();
    }
  });
});

describe("direct adjudication at record creation (@spec mission#record-principal-members, #1923)", () => {
  const directBasis = (original: MissionRecord, adjudication?: unknown): ApprovalBasisDirect =>
    ({
      type: "direct",
      consent_principal: original.approval_basis.consent_principal,
      ...(adjudication === undefined ? {} : { adjudication }),
    }) as ApprovalBasisDirect;

  it.each([
    ["kind policy", { kind: "policy", policy: { id: "p", version: "1" } }],
    ["kind policy with governance_record", { kind: "policy", governance_record: true }],
    ["kind service", { kind: "service" }],
    ["an unrecognized kind", { kind: "x_oracle" }],
    ["no kind", { governance_record: true }],
    ["a non-object", "human"],
  ])("refuses a direct record whose adjudication has %s, committing no Mission", async (_label, adjudication) => {
    const kernel = await makeKernel();
    try {
      const original = approveOne(kernel, "adj-original");
      const record = copyOf(original, "adj-copy", { approval_basis: directBasis(original, adjudication) });
      const before = kernel.allMissions().length;
      const error = thrown(() => create(kernel, original, record));
      expect(error).toBeInstanceOf(DirectAdjudicationError);
      expect(kernel.get(record.id)).toBeUndefined();
      expect(kernel.findByApprovalEvent("adj-copy")).toBeUndefined();
      expect(kernel.allMissions()).toHaveLength(before);
    } finally {
      kernel.close();
    }
  });

  it.each([
    ["omitted", undefined],
    ["kind human", { kind: "human" }],
    ["kind human with governance_record", { kind: "human", governance_record: true }],
  ])("stores a direct record whose adjudication is %s, exactly as submitted", async (_label, adjudication) => {
    const kernel = await makeKernel();
    try {
      const original = approveOne(kernel, "adj-original");
      const basis = directBasis(original, adjudication);
      const record = copyOf(original, "adj-copy", { approval_basis: basis });
      create(kernel, original, record);
      const stored = kernel.get(record.id) as MissionRecord;
      expect(stored.approval_basis).toStrictEqual(basis);
      if (adjudication === undefined) expect(stored.approval_basis).not.toHaveProperty("adjudication");
    } finally {
      kernel.close();
    }
  });
});

describe("unrecognized approval basis discriminators (@spec mission#record-principal-members, #1923)", () => {
  /** A basis this issuer does not define, with an adjudication kind it does not define either. */
  const unrecognizedBasis = (original: MissionRecord, event: string) =>
    ({
      type: "x_quorum",
      consent_principal: original.approval_basis.consent_principal,
      activation: { approval_event_id: event, quorum: 3 },
      adjudication: { kind: "x_oracle", oracle: { id: "o", version: "2" } },
      approved_at: "2026-10-01T00:00:00Z",
    }) as unknown as ApprovalBasis;

  it("stores, reads and returns them unchanged through a reopen, and the Mission stays active and derivable", async () => {
    const file = storeFile();
    const kernel = await makeKernel(file);
    const original = approveOne(kernel, "disc-original");
    const basis = unrecognizedBasis(original, "disc-copy");
    const record = copyOf(original, "disc-copy", { approval_basis: basis });
    // Not a blanket rejection: the direct-creation guard is not applied, and
    // nothing else at creation reads the basis's semantics.
    create(kernel, original, record);
    expect(kernel.get(record.id)?.approval_basis).toStrictEqual(basis);
    expect(kernel.findByApprovalEvent("disc-copy")?.approval_basis).toStrictEqual(basis);
    // Ordinary derivation and introspection need no basis semantics.
    expect(kernel.checkDerivation(record.id).state).toBe("active");
    const view = kernel.introspectionMission(kernel.get(record.id) as MissionRecord) as unknown as Record<string, unknown>;
    expect(view.state).toBe("active");
    kernel.close();
    const after = await makeKernel(file);
    try {
      expect(after.get(record.id)?.approval_basis).toStrictEqual(basis);
      expect(after.get(record.id)?.state).toBe("active");
    } finally {
      after.close();
    }
  });

  it("reports an activation policy commitment it cannot judge as unrecognized, never not_applicable", async () => {
    const kernel = await makeKernel();
    try {
      const original = approveOne(kernel, "disc-original");
      // The control: a recognized direct basis has no activation policy.
      expect(kernel.verifyActivationPolicyCommitment(original)).toStrictEqual({ status: "not_applicable" });
      const record = copyOf(original, "disc-copy", { approval_basis: unrecognizedBasis(original, "disc-copy") });
      create(kernel, original, record);
      expect(kernel.verifyActivationPolicyCommitment(kernel.get(record.id) as MissionRecord)).toStrictEqual({
        status: "unrecognized_basis",
        type: "x_quorum",
      });
    } finally {
      kernel.close();
    }
  });

  it("refuses a Child Mission whose parent's basis it does not recognize, creating nothing and leaving the parent active", async () => {
    const kernel = await makeKernel();
    try {
      const childInput = (parentId: string) =>
        ({
          parentId,
          intent: validateMissionIntent(
            JSON.stringify({ goal: "Read one invoice", target_resources: [RESOURCE], expires_at: inOneHour() }),
          ),
          proposedAuthority: [
            { type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"], constraints: { vendors: ["acme"] } },
          ],
          childActor: { sub: "child-agent", sub_profile: "ai_agent" },
        }) as never;
      // The control: the same request under a recognized direct parent creates a child.
      const control = approveOne(kernel, "disc-control");
      expect(createChildMission(kernel, childInput(control.id)).child.parent?.id).toBe(control.id);
      // The same parent shape, its stored basis rewritten to an unrecognized type.
      const parent = approveOne(kernel, "disc-parent");
      kernel.db
        .prepare("UPDATE missions SET approval_basis_json = ? WHERE id = ?")
        .run(JSON.stringify(unrecognizedBasis(parent, "disc-parent")), parent.id);
      const before = kernel.allMissions().length;
      const error = thrown(() => createChildMission(kernel, childInput(parent.id)));
      expect(error).toBeInstanceOf(ChildDelegationError);
      expect((error as ChildDelegationError).reason).toBe("delegation_not_permitted");
      expect((error as Error).message).toMatch(/unrecognized approval_basis\.type 'x_quorum'/);
      expect(kernel.allMissions()).toHaveLength(before);
      expect(kernel.get(parent.id)?.state).toBe("active");
    } finally {
      kernel.close();
    }
  });
});
