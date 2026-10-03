import { approvalContextManifest } from "@mission/core";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  assertLocalPrincipal,
  type AuthorityEntry,
  type AuthoritySourceCatalog,
  type AuthoritySourceResolver,
  bindAuthoritySourceCatalog,
  catalogAuthoritySourceResolver,
  createChildMission,
  createExpansion,
  createTemplate,
  dispatchFromTemplate,
  IntentError,
  MissionKernel,
  type MissionRecord,
  parseAuthoritySource,
  TemplateError,
  TemplateStore,
  validateAuthoritySourceCatalog,
  validateMissionIntent,
  validateMissionIntentSubmission,
} from "../src/index.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const ISS = "https://as.test";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource as string;
const READ_ACTIONS = ["payments:invoice.list", "payments:invoice.read"];

let key: CryptoKey;
beforeAll(async () => {
  key = (await generateKeyPair("ES256")).privateKey;
});

// File-backed kernel stores, so a kernel can be reopened over the same rows
// (a restart) with a changed catalog.
const storeDirs: string[] = [];
afterAll(() => {
  for (const dir of storeDirs) rmSync(dir, { recursive: true, force: true });
});
const storeFile = (): string => {
  const dir = mkdtempSync(join(tmpdir(), "mission-827-"));
  storeDirs.push(dir);
  return join(dir, "kernel.db");
};

const entry = (actions: string[], over: Record<string, unknown> = {}): AuthorityEntry =>
  ({
    type: "mission_resource_access",
    resource: RESOURCE,
    actions,
    constraints: { vendors: ["acme"] },
    ...over,
  }) as AuthorityEntry;

/** The deployment's own ceiling as a source ceiling: the user-delegated case,
 *  where the source's authority IS the deployment's. */
const DEPLOYMENT_CEILING = DERIVATION_POLICY.ceiling as unknown as AuthorityEntry[];

const catalog = (over: Partial<AuthoritySourceCatalog> = {}): AuthoritySourceCatalog => ({
  humanPrincipals: ["alice", "bob"],
  entries: [
    {
      id: "people",
      type: "user_delegated",
      clients: ["ap-agent"],
      activators: ["bob"],
      ceiling: DEPLOYMENT_CEILING,
    },
    {
      id: "reconciler",
      type: "service_owned",
      clients: ["svc-agent"],
      activators: ["bob"],
      principals: ["svc-reconciler"],
      ceiling: DEPLOYMENT_CEILING,
    },
    {
      id: "ap-controls",
      type: "organizational",
      clients: ["governed-agent"],
      activators: ["bob"],
      principals: ["acme-accounts-payable"],
      ceiling: DEPLOYMENT_CEILING,
      policy: { id: "ap-controls", version: "1", digest: "sha-256:policy-digest" },
    },
  ],
  ...over,
});

const makeKernel = (over: Record<string, unknown> = {}) =>
  new MissionKernel({
    issuer: ISS,
    policy: DERIVATION_POLICY as never,
    statusKey: key,
    statusKid: "as-status",
    authoritySourceCatalog: catalog() as never,
    ...over,
  });

let seq = 0;
const intent = (over: Record<string, unknown> = {}) =>
  validateMissionIntent(
    JSON.stringify({
      goal: "Reconcile Acme invoices",
      target_resources: [RESOURCE],
      expires_at: "2027-01-01T00:00:00Z",
      ...over,
    }),
  );

const approve = (
  kernel: MissionKernel,
  over: { clientId?: string; subject?: string; approver?: string } = {},
): MissionRecord =>
  kernel.approve({
    intent: intent(),
    subject: { iss: ISS, sub: over.subject ?? "alice" },
    approver: { iss: ISS, sub: over.approver ?? "bob" },
    clientId: over.clientId ?? "ap-agent",
    approvalEventId: `apev-as-${seq++}`,
  });

describe("authority source establishment (@spec mission#authority-sources, mission#approval-event)", () => {
  it("records the established source on the direct approval path", () => {
    const record = approve(makeKernel());
    expect(record.authority_source).toEqual({ type: "user_delegated" });
    // Provenance, not enforcement input: outside both integrity anchors.
    expect(JSON.stringify(record.intent)).not.toContain("authority_source");
  });

  it("records the organizational policy reference with its digest", () => {
    const record = approve(makeKernel(), {
      clientId: "governed-agent",
      subject: "acme-accounts-payable",
    });
    expect(record.authority_source).toEqual({
      type: "organizational",
      policy: { id: "ap-controls", version: "1", digest: "sha-256:policy-digest" },
    });
  });

  it("refuses access_denied when no trusted source is declared for the client", () => {
    expect(() => approve(makeKernel(), { clientId: "unknown-agent" })).toThrow(
      /no trusted authority source is declared/,
    );
    try {
      approve(makeKernel(), { clientId: "unknown-agent" });
    } catch (e) {
      expect((e as IntentError).code).toBe("access_denied");
    }
  });

  it("refuses access_denied when the Approver may not activate the source", () => {
    try {
      approve(makeKernel(), { approver: "alice" });
      expect.unreachable("a non-activator Approver must be refused");
    } catch (e) {
      expect((e as IntentError).code).toBe("access_denied");
      expect((e as Error).message).toMatch(/not authorized to activate/);
    }
  });

  it("admits an activator holding none of the ceiling's operational permissions (activation is not possession)", () => {
    // `bob` activates the service-owned source without appearing anywhere in
    // its authority: gates 2 and 3 are separate checks, so activation
    // authority is never read as possession.
    const record = approve(makeKernel(), { clientId: "svc-agent", subject: "svc-reconciler" });
    expect(record.authority_source).toEqual({ type: "service_owned" });
    expect(record.approver).toEqual({ iss: ISS, sub: "bob" });
    expect(record.authority_set.length).toBeGreaterThan(0);
  });

  it("refuses access_denied when the derived Authority Set exceeds the source ceiling", () => {
    const narrow = catalog();
    (narrow.entries as { ceiling: AuthorityEntry[] }[])[0].ceiling = [
      entry(["payments:invoice.read"]),
    ];
    const kernel = makeKernel({ authoritySourceCatalog: narrow as never });
    try {
      approve(kernel);
      expect.unreachable("a set outside the source ceiling must be refused");
    } catch (e) {
      expect((e as IntentError).code).toBe("access_denied");
      expect((e as Error).message).toMatch(/exceeds the authority of the user_delegated source/);
    }
  });

  it("refuses a service_owned or organizational Mission that records a human Subject", () => {
    for (const clientId of ["svc-agent", "governed-agent"]) {
      try {
        approve(makeKernel(), { clientId, subject: "alice" });
        expect.unreachable("a human Subject must be refused outside user_delegated");
      } catch (e) {
        expect((e as IntentError).code).toBe("access_denied");
        expect((e as Error).message).toMatch(/MUST NOT record the human principal/);
      }
    }
  });

  it("refuses a Subject the deployment does not recognize as a resource owner in its own right", () => {
    try {
      approve(makeKernel(), { clientId: "svc-agent", subject: "svc-unregistered" });
      expect.unreachable("an unrecognized workload principal must be refused");
    } catch (e) {
      expect((e as IntentError).code).toBe("access_denied");
      expect((e as Error).message).toMatch(/resource owner in its own right/);
    }
  });

  it("refuses access_denied when the governed policy digest has drifted", () => {
    const file = storeFile();
    const kernel = makeKernel({ store: { file } });
    const record = approve(kernel, {
      clientId: "governed-agent",
      subject: "acme-accounts-payable",
    });
    kernel.db.close();
    // The governed policy is edited after approval, and the deployment
    // restarts with it: the root the record committed now resolves a digest
    // that no longer matches the one the Mission committed.
    const drifted = catalog();
    (drifted.entries as { policy?: { digest: string } }[])[2].policy = {
      id: "ap-controls",
      version: "1",
      digest: "sha-256:edited-policy",
    } as never;
    const after = makeKernel({ authoritySourceCatalog: drifted as never, store: { file } });
    try {
      expect(() => after.assertInheritedAuthoritySource(after.committedSourceBinding(record.id), [])).toThrow(
        /has drifted from the reference the Mission committed/,
      );
    } finally {
      after.db.close();
    }
  });

  it("establishes the source from configuration alone: ApproveInput carries no source member", () => {
    const kernel = makeKernel();
    const record = kernel.approve({
      intent: intent(),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: `apev-as-${seq++}`,
      // A caller-supplied source is not part of the input contract; it is
      // ignored rather than recorded.
      authority_source: { type: "organizational" },
    } as never);
    expect(record.authority_source).toEqual({ type: "user_delegated" });
  });

  it("gates activation on the shared suite fixture: an Approver outside its activators is refused", () => {
    // The fixture every other suite injects declares its activators, so gate 2
    // is a live check there and not a vacuous one: the Approver a suite names
    // activates, and any other Approver is refused.
    const kernel = makeKernel({
      authoritySourceCatalog: testAuthoritySourceCatalog(
        DEPLOYMENT_CEILING,
        ["ap-agent"],
        ["bob"],
      ) as never,
    });
    expect(approve(kernel, { approver: "bob" }).authority_source).toEqual({
      type: "user_delegated",
    });
    expect(() => approve(kernel, { approver: "mallory" })).toThrow(IntentError);
    expect(() => approve(kernel, { approver: "mallory" })).toThrow(/is not authorized to activate/);
  });

  it("refuses kernel construction when the deployment declares no catalog", () => {
    // There is no implicit source. A deployment that declares no catalog has
    // declared no authority for an approval to activate, so construction
    // refuses rather than standing a permissive source up on its behalf.
    // A plain Error, not an IntentError: deployment misconfiguration is never
    // an `access_denied` an Agent sees, and the five gates stay the only
    // producers of that code.
    let thrown: unknown;
    try {
      makeKernel({ authoritySourceCatalog: undefined });
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(Error);
    expect(thrown).not.toBeInstanceOf(IntentError);
    expect((thrown as Error).message).toMatch(/authoritySourceCatalog is required/);
  });

  it("refuses every approval when the catalog declares no source at all", () => {
    // The other half of the same rule: an empty catalog is still a catalog,
    // and gate 1 refuses every Agent under it. No approval path reaches a
    // record without a declared source.
    const kernel = makeKernel({
      authoritySourceCatalog: { humanPrincipals: [], entries: [] } as never,
    });
    expect(() => approve(kernel)).toThrow(IntentError);
    expect(() => approve(kernel)).toThrow(/no trusted authority source is declared/);
  });
});

describe("authority source intake (@spec mission#submission-via-par, mission#authority-sources)", () => {
  it("refuses a client-supplied authority_source in the submission envelope with invalid_request", () => {
    try {
      validateMissionIntentSubmission(
        JSON.stringify({
          intent: { goal: "g", target_resources: [RESOURCE], expires_at: "2027-01-01T00:00:00Z" },
          authority_source: { type: "organizational" },
        }),
      );
      expect.unreachable("an unknown envelope member must be refused");
    } catch (e) {
      expect((e as IntentError).code).toBe("invalid_request");
      expect((e as Error).message).toMatch(/unknown submission member: authority_source/);
    }
  });

  it("refuses a client-supplied authority_source inside the Mission Intent with invalid_request", () => {
    try {
      validateMissionIntent(
        JSON.stringify({
          goal: "g",
          target_resources: [RESOURCE],
          expires_at: "2027-01-01T00:00:00Z",
          authority_source: { type: "organizational" },
        }),
      );
      expect.unreachable("an unknown top-level member must be refused");
    } catch (e) {
      expect((e as IntentError).code).toBe("invalid_request");
      expect((e as Error).message).toMatch(/unknown top-level member: authority_source/);
    }
  });
});

describe("authority source discriminator (@spec mission#mission-record, mission#lifecycle)", () => {
  it("refuses an unrecognized type at hydration rather than widening the union", () => {
    const kernel = makeKernel();
    const record = approve(kernel);
    kernel.db
      .prepare("UPDATE missions SET authority_source_json = ? WHERE id = ?")
      .run(JSON.stringify({ type: "delegated_by_vibes" }), record.id);
    expect(() => kernel.get(record.id)).toThrow(/unrecognized authority_source.type/);
  });

  it("refuses a stored organizational source with no policy reference", () => {
    const kernel = makeKernel();
    const record = approve(kernel);
    kernel.db
      .prepare("UPDATE missions SET authority_source_json = ? WHERE id = ?")
      .run(JSON.stringify({ type: "organizational" }), record.id);
    expect(() => kernel.get(record.id)).toThrow(/policy is required for organizational/);
  });

  it("refuses a policy reference outside organizational", () => {
    expect(() =>
      parseAuthoritySource(
        { type: "user_delegated", policy: { id: "p", version: "1", digest: "sha-256:x" } },
        "t",
      ),
    ).toThrow(/policy is absent outside organizational/);
  });

  it("refuses an unrecognized type at catalog load rather than widening the union", () => {
    expect(() =>
      validateAuthoritySourceCatalog({
        humanPrincipals: [],
        entries: [
          { id: "x", type: "delegated_by_vibes", clients: [], activators: [], ceiling: [] } as never,
        ],
      }),
    ).toThrow(/unrecognized type/);
  });

  it("refuses a source that declares no activator, rather than admitting every Approver", () => {
    // An empty list means nobody, never everybody: gate 2 has no vacuous form,
    // so the refusal is at load, before any approval can rely on it.
    const empty = catalog();
    (empty.entries as { activators: string[] }[])[0].activators = [];
    expect(() => validateAuthoritySourceCatalog(empty)).toThrow(
      /'people': activators must be non-empty/,
    );
    const missing = catalog();
    delete (missing.entries as { activators?: string[] }[])[0].activators;
    expect(() => validateAuthoritySourceCatalog(missing)).toThrow(
      /'people': activators must be non-empty/,
    );
    expect(() => makeKernel({ authoritySourceCatalog: empty as never })).toThrow(
      /activators must be non-empty/,
    );
  });

  it("refuses kernel construction on a catalog whose invariants do not hold", () => {
    // The selection rule is what makes gate 1 resolve one root, so it is
    // enforced in production (the kernel constructor), not only over the
    // shipped file.
    const duplicateRoot = catalog();
    (duplicateRoot.entries as { id: string }[])[1].id = "people";
    expect(() => makeKernel({ authoritySourceCatalog: duplicateRoot as never })).toThrow(
      /duplicate root id/,
    );
    const sharedClient = catalog();
    (sharedClient.entries as { clients: string[] }[])[1].clients = ["ap-agent"];
    expect(() => makeKernel({ authoritySourceCatalog: sharedClient as never })).toThrow(
      /must each declare disjoint subjects/,
    );
  });

  it("refuses a duplicate root id or an overlapping selection, and admits repeated modes on disjoint Subjects", () => {
    const duplicateRoot = catalog();
    (duplicateRoot.entries as { id: string }[])[2].id = "reconciler";
    expect(() => validateAuthoritySourceCatalog(duplicateRoot)).toThrow(/duplicate root id/);
    // A client shared with an entry that selects every Subject overlaps it.
    const unselected = catalog();
    (unselected.entries as { clients: string[]; subjects?: string[] }[])[1].clients = ["ap-agent"];
    (unselected.entries as { subjects?: string[] }[])[1].subjects = ["svc-reconciler"];
    expect(() => validateAuthoritySourceCatalog(unselected)).toThrow(
      /'people' and 'reconciler' both select client 'ap-agent'/,
    );
    // Two selectors on one client that share a Subject overlap too.
    const intersecting = catalog();
    (intersecting.entries as { subjects?: string[] }[])[0].subjects = ["alice", "bob"];
    (intersecting.entries as { clients: string[]; subjects?: string[]; type: string }[])[1] = {
      ...(intersecting.entries[1] as never),
      type: "user_delegated",
      clients: ["ap-agent"],
      subjects: ["bob", "carol"],
    } as never;
    expect(() => validateAuthoritySourceCatalog(intersecting)).toThrow(
      /both select subject 'bob' of client 'ap-agent'/,
    );
    const empty = catalog();
    (empty.entries as { subjects?: string[] }[])[0].subjects = [];
    expect(() => validateAuthoritySourceCatalog(empty)).toThrow(/subjects, when present, must be non-empty/);
    // Repeated user_delegated mode on one client across disjoint Subjects.
    const disjoint = catalog();
    (disjoint.entries as { subjects?: string[] }[])[0].subjects = ["alice"];
    (disjoint.entries as unknown[]).push({
      ...(disjoint.entries[0] as object),
      id: "people-bob",
      subjects: ["bob"],
    });
    expect(() => validateAuthoritySourceCatalog(disjoint)).not.toThrow();
  });
});

describe("authority source drawdown (@spec mission#authority-sources, child-delegation#child-creation)", () => {
  const childIntent = () =>
    intent({ goal: "Read one invoice", expires_at: "2026-11-01T00:00:00Z" });

  it("a Child Mission carries the parent's source verbatim", () => {
    const kernel = makeKernel({ actorProfiles: { "child-agent": "ai_agent" } });
    const parent = approve(kernel);
    const { child } = createChildMission(kernel, {
      parentId: parent.id,
      intent: childIntent(),
      proposedAuthority: [entry(["payments:invoice.read"])],
      childActor: { sub: "child-agent", sub_profile: "ai_agent" },
    } as never);
    expect(child.authority_source).toEqual(parent.authority_source);
  });

  it("a drawdown refuses access_denied when the source narrowed since approval", () => {
    const file = storeFile();
    const kernel = makeKernel({ actorProfiles: { "child-agent": "ai_agent" }, store: { file } });
    const parent = approve(kernel);
    kernel.db.close();
    const narrowed = catalog();
    (narrowed.entries as { ceiling: AuthorityEntry[] }[])[0].ceiling = [
      entry(["payments:vendor.read"]),
    ];
    const after = makeKernel({
      authoritySourceCatalog: narrowed as never,
      actorProfiles: { "child-agent": "ai_agent" },
      store: { file },
    });
    // The deployment restarts with a narrowed catalog. The parent's committed
    // root survives and still resolves, so provenance is untouched, but the
    // ceiling assertion refuses, at the kernel gate and at a real child drawdown.
    try {
      expect(() =>
        after.assertInheritedAuthoritySource(after.committedSourceBinding(parent.id), parent.authority_set),
      ).toThrow(/exceeds the authority of the user_delegated source/);
      expect(() =>
        createChildMission(after, {
          parentId: parent.id,
          intent: childIntent(),
          proposedAuthority: [entry(["payments:invoice.read"])],
          childActor: { sub: "child-agent", sub_profile: "ai_agent" },
        } as never),
      ).toThrow(/exceeds the authority of the user_delegated source/);
    } finally {
      after.db.close();
    }
  });

  it("a template instance carries the template's source verbatim", () => {
    const kernel = makeKernel();
    const store = new TemplateStore();
    const template = createTemplate(
      store,
      {
        template_version: "t1",
        issuer: ISS,
        approver: { iss: ISS, sub: "bob" },
        ceiling: [entry(READ_ACTIONS)],
        dispatch_policy: "read-only",
        dispatchers: ["ap-agent"],
        recipients: { subjects: [{ iss: ISS, sub: "alice" }], agents: ["ap-agent"] },
        per_instance_lifetime_s: 900,
        max_active: 5,
        rate_per_min: 30,
        review_cadence_s: 86400,
        approval_event_id: `tmpl-${seq++}`,
        expires_at: "2099-01-01T00:00:00Z",
      } as never,
      kernel.authoritySourceOptions(),
    );
    expect(template.authority_source).toEqual({ type: "user_delegated" });
    const { mission } = dispatchFromTemplate(kernel, store, {
      templateId: template.id,
      dispatchEventId: `dsp-${seq++}`,
      dispatcher: "ap-agent",
      intent: intent({ expires_at: "2026-11-01T00:00:00Z" }),
      subject: { iss: ISS, sub: "alice" },
      policyVersion: DERIVATION_POLICY.policy_version,
    } as never);
    expect(mission.authority_source).toEqual(template.authority_source);
  });

  it("refuses a template whose recipients draw on more than one authority source", () => {
    const kernel = makeKernel();
    const store = new TemplateStore();
    expect(() =>
      createTemplate(
        store,
        {
          template_version: "t2",
          issuer: ISS,
          approver: { iss: ISS, sub: "bob" },
          ceiling: [entry(READ_ACTIONS)],
          dispatch_policy: "read-only",
          dispatchers: ["ap-agent"],
          recipients: { subjects: [{ iss: ISS, sub: "alice" }], agents: ["ap-agent", "svc-agent"] },
          per_instance_lifetime_s: 900,
          max_active: 5,
          rate_per_min: 30,
          review_cadence_s: 86400,
          approval_event_id: `tmpl-${seq++}`,
          expires_at: "2099-01-01T00:00:00Z",
        } as never,
        kernel.authoritySourceOptions(),
      ),
    ).toThrow(TemplateError);
  });
});

describe("authority source disclosure (@spec mission#introspection, mission#authority-sources)", () => {
  it("discloses the source to a provenance caller and withholds it from a bare caller", () => {
    const kernel = makeKernel();
    const record = approve(kernel, {
      clientId: "governed-agent",
      subject: "acme-accounts-payable",
    });
    const withPrivilege = kernel.introspectionProjection(record, {
      disclose: new Set(["provenance"]),
    });
    // `type` and the governed policy's id/version; the policy digest belongs to
    // record access, never introspection.
    expect(withPrivilege.authority_source).toEqual({
      type: "organizational",
      policy: { id: "ap-controls", version: "1" },
    });
    const bare = kernel.introspectionProjection(record, { disclose: new Set() });
    expect(bare).not.toHaveProperty("authority_source");
  });

  it("the ungated issuer view carries the source unconditionally", () => {
    const kernel = makeKernel();
    const record = approve(kernel);
    expect(kernel.introspectionMission(record).authority_source).toEqual({
      type: "user_delegated",
    });
  });

  it("the baseline mission claim carries no source: it is not on access tokens", () => {
    const kernel = makeKernel();
    const record = approve(kernel);
    expect(kernel.missionClaim(record)).not.toHaveProperty("authority_source");
  });
});

describe("authority source in the Approval Context Manifest (@spec approval-governance#approval-context-manifest)", () => {
  it("takes the REQUIRED manifest input from the Mission Record", () => {
    const kernel = makeKernel();
    const record = approve(kernel);
    const manifest = approvalContextManifest(kernel.approvalContextInput(record));
    expect(manifest.authority_source).toEqual(record.authority_source);
  });
});

describe("issuer-qualified principals at the source gates (@spec mission#authority-sources, mission#approval-event, #829)", () => {
  const FOREIGN = "https://untrusted.example";

  const approveTuple = (
    kernel: MissionKernel,
    subject: unknown,
    approver: unknown,
    clientId = "ap-agent",
    approvalEventId = `apev-829-${seq++}`,
  ): MissionRecord =>
    kernel.approve({
      intent: intent(),
      subject: subject as { iss: string; sub: string },
      approver: approver as { iss: string; sub: string },
      clientId,
      approvalEventId,
    });

  const refused = (run: () => unknown, pattern: RegExp): void => {
    try {
      run();
      expect.unreachable("a principal outside the deployment's issuer namespace must be refused");
    } catch (e) {
      expect(e).toBeInstanceOf(IntentError);
      expect((e as IntentError).code).toBe("access_denied");
      expect((e as Error).message).toMatch(pattern);
    }
  };

  it("refuses a direct approval whose Approver is a foreign-issuer bob against local bob's activator, creating no Mission and publishing nothing", () => {
    const commits: unknown[] = [];
    const kernel = makeKernel({ onLifecycleCommit: (c: unknown) => commits.push(c) });
    const before = kernel.allMissions().length;
    const eventId = `apev-829-foreign-bob-${seq++}`;
    refused(
      () => approveTuple(kernel, { iss: ISS, sub: "alice" }, { iss: FOREIGN, sub: "bob" }, "ap-agent", eventId),
      /approver is not a principal of this deployment's issuer namespace/,
    );
    expect(kernel.allMissions().length).toBe(before);
    expect(kernel.findByApprovalEvent(eventId)).toBeUndefined();
    expect(commits).toHaveLength(0);
    // Control: the same approval with local bob succeeds.
    expect(approveTuple(kernel, { iss: ISS, sub: "alice" }, { iss: ISS, sub: "bob" }).approver).toEqual({ iss: ISS, sub: "bob" });
  });

  it("refuses a foreign principal before derivation runs: an approval whose derivation would also fail reports the namespace refusal", () => {
    const kernel = makeKernel();
    const bogus = [{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:bogus.action"] }] as AuthorityEntry[];
    // Control: with local principals the same request fails in derivation.
    expect(() =>
      kernel.approve({ intent: intent(), proposedAuthority: bogus, subject: { iss: ISS, sub: "alice" }, approver: { iss: ISS, sub: "bob" }, clientId: "ap-agent", approvalEventId: `apev-829-${seq++}` }),
    ).toThrow(IntentError);
    refused(
      () =>
        kernel.approve({ intent: intent(), proposedAuthority: bogus, subject: { iss: ISS, sub: "alice" }, approver: { iss: FOREIGN, sub: "bob" }, clientId: "ap-agent", approvalEventId: `apev-829-${seq++}` }),
      /approver is not a principal of this deployment's issuer namespace/,
    );
  });

  it("refuses a foreign-issuer Subject in every source mode, including user_delegated", () => {
    const kernel = makeKernel();
    for (const [clientId, sub] of [
      ["ap-agent", "alice"],
      ["svc-agent", "svc-reconciler"],
      ["governed-agent", "acme-accounts-payable"],
    ] as const) {
      refused(
        () => approveTuple(kernel, { iss: FOREIGN, sub }, { iss: ISS, sub: "bob" }, clientId),
        /subject is not a principal of this deployment's issuer namespace/,
      );
      // Control: the local tuple for the same mode is admitted.
      expect(approveTuple(kernel, { iss: ISS, sub }, { iss: ISS, sub: "bob" }, clientId).subject).toEqual({ iss: ISS, sub });
    }
  });

  it("refuses a missing, malformed, or byte-distinct issuer, never normalizing it into the local namespace", () => {
    const kernel = makeKernel();
    const variants: unknown[] = [
      { sub: "bob" },
      { iss: "", sub: "bob" },
      { iss: 123, sub: "bob" },
      { iss: ISS, sub: "" },
      { iss: `${ISS}/`, sub: "bob" },
      { iss: ISS.toUpperCase(), sub: "bob" },
      { iss: ` ${ISS}`, sub: "bob" },
      null,
      "bob",
    ];
    for (const approver of variants) {
      refused(() => approveTuple(kernel, { iss: ISS, sub: "alice" }, approver), /approver/);
    }
    for (const subject of variants) {
      refused(() => approveTuple(kernel, subject, { iss: ISS, sub: "bob" }), /subject/);
    }
  });

  it("holds the exported kernel gates to the namespace on their own, not only through approve", () => {
    const kernel = makeKernel();
    refused(
      () => kernel.establishAuthoritySource({ clientId: "ap-agent", subject: { iss: ISS, sub: "alice" }, approver: { iss: FOREIGN, sub: "bob" } }),
      /approver is not a principal/,
    );
    refused(
      () => kernel.establishAuthoritySource({ clientId: "ap-agent", subject: { iss: FOREIGN, sub: "alice" }, approver: { iss: ISS, sub: "bob" } }),
      /subject is not a principal/,
    );
    const record = approve(kernel);
    const root = kernel.committedSourceBinding(record.id);
    refused(
      () => kernel.assertInheritedSubjectDiscipline(kernel.resolveCommittedSource(root), { iss: FOREIGN, sub: "alice" }),
      /subject is not a principal/,
    );
    refused(
      () =>
        kernel.assertRenderedAuthoritySource({
          binding: root,
          source: record.authority_source,
          subject: { iss: ISS, sub: "alice" },
          approver: { iss: FOREIGN, sub: "bob" },
          authoritySet: record.authority_set,
        }),
      /approver is not a principal/,
    );
    const bound = bindAuthoritySourceCatalog(catalog(), ISS, ISS);
    expect(assertLocalPrincipal(bound, { iss: ISS, sub: "bob" }, "approver")).toEqual({ iss: ISS, sub: "bob" });
    refused(() => assertLocalPrincipal(bound, { iss: FOREIGN, sub: "bob" }, "approver"), /approver is not a principal/);
  });

  it("keeps two kernels with equal local subject names isolated: neither accepts the other's qualified principal or catalog", () => {
    const ISS_B = "https://as-b.test";
    const a = makeKernel();
    const b = makeKernel({ issuer: ISS_B });
    refused(() => approveTuple(a, { iss: ISS_B, sub: "alice" }, { iss: ISS_B, sub: "bob" }), /not a principal/);
    refused(() => approveTuple(b, { iss: ISS, sub: "alice" }, { iss: ISS, sub: "bob" }), /not a principal/);
    expect(approveTuple(a, { iss: ISS, sub: "alice" }, { iss: ISS, sub: "bob" }).issuer).toBe(ISS);
    expect(approveTuple(b, { iss: ISS_B, sub: "alice" }, { iss: ISS_B, sub: "bob" }).issuer).toBe(ISS_B);
    // A catalog bound to B's namespace never becomes A's.
    const boundB = bindAuthoritySourceCatalog(catalog(), ISS_B, ISS_B);
    expect(() => bindAuthoritySourceCatalog(boundB, ISS, ISS_B)).toThrow(/bound to issuer 'https:\/\/as-b\.test'/);
    expect(() => makeKernel({ authoritySourceCatalog: boundB })).toThrow(/bound to issuer/);
  });

  it("binds a configured principalIssuer distinct from the Mission issuer, admitting its principals and refusing the Mission issuer's", () => {
    const IDP = "https://id.test";
    const kernel = makeKernel({ principalIssuer: IDP });
    const record = approveTuple(kernel, { iss: IDP, sub: "alice" }, { iss: IDP, sub: "bob" });
    expect(record.issuer).toBe(ISS);
    expect(record.approver).toEqual({ iss: IDP, sub: "bob" });
    refused(() => approveTuple(kernel, { iss: ISS, sub: "alice" }, { iss: ISS, sub: "bob" }), /not a principal/);
    expect(() => makeKernel({ principalIssuer: "" })).toThrow(/principal issuer must be a non-empty string/);
  });

  it("admits an upstream identity only after an explicit trusted mapping to a local principal; rewriting its issuer is not a mapping", () => {
    const PARTNER = "https://id.partner.example";
    // The deployment's separately trusted, injective mapping: upstream tuple to
    // canonical local principal. Nothing maps by equal `sub`.
    const TRUSTED_MAPPING = new Map([[`${PARTNER}|p-bob`, "bob"]]);
    const mapToLocal = (upstream: { iss: string; sub: string }) => {
      const local = TRUSTED_MAPPING.get(`${upstream.iss}|${upstream.sub}`);
      if (!local) throw new Error("no trusted mapping");
      return { iss: ISS, sub: local };
    };
    const kernel = makeKernel();
    const upstream = { iss: PARTNER, sub: "p-bob" };
    const mapped = approveTuple(kernel, { iss: ISS, sub: "alice" }, mapToLocal(upstream));
    expect(mapped.approver).toEqual({ iss: ISS, sub: "bob" });
    refused(() => approveTuple(kernel, { iss: ISS, sub: "alice" }, upstream), /approver is not a principal/);
    // Changing only the issuer does not authenticate a mapping: the upstream
    // `sub` is not a local activator.
    refused(() => approveTuple(kernel, { iss: ISS, sub: "alice" }, { iss: ISS, sub: "p-bob" }), /not authorized to activate/);
  });

  const templateInput = (approvalEventId: string, approver: unknown) =>
    ({
      template_version: "t829",
      issuer: ISS,
      approver,
      ceiling: [entry(READ_ACTIONS)],
      dispatch_policy: "read-only",
      dispatchers: ["ap-agent"],
      recipients: { subjects: [{ iss: ISS, sub: "alice" }], agents: ["ap-agent"] },
      per_instance_lifetime_s: 900,
      max_active: 5,
      rate_per_min: 30,
      review_cadence_s: 86400,
      approval_event_id: approvalEventId,
      expires_at: "2099-01-01T00:00:00Z",
    }) as never;

  it("refuses a template-consent retry whose approver is foreign or malformed before returning the template its event created, and still returns it for a legitimate retry after revocation", () => {
    const kernel = makeKernel();
    const store = new TemplateStore();
    const eventId = `tmpl-829-${seq++}`;
    const original = createTemplate(store, templateInput(eventId, { iss: ISS, sub: "bob" }), kernel.authoritySourceOptions());
    for (const approver of [{ iss: FOREIGN, sub: "bob" }, { iss: "", sub: "bob" }, { sub: "bob" }]) {
      try {
        createTemplate(store, templateInput(eventId, approver), kernel.authoritySourceOptions());
        expect.unreachable("a retry with a foreign or malformed approver must be refused");
      } catch (e) {
        expect(e).toBeInstanceOf(TemplateError);
        expect((e as Error).message).toMatch(/approver/);
      }
    }
    store.revoke(original.id);
    const retried = createTemplate(store, templateInput(eventId, { iss: ISS, sub: "bob" }), kernel.authoritySourceOptions());
    expect(retried.id).toBe(original.id);
  });

  it("refuses a dispatch retry whose Subject is foreign or malformed before returning the instance its dispatch id created, and still returns it for a legitimate retry after revocation", () => {
    const kernel = makeKernel();
    const store = new TemplateStore();
    const template = createTemplate(store, templateInput(`tmpl-829-${seq++}`, { iss: ISS, sub: "bob" }), kernel.authoritySourceOptions());
    const dispatchEventId = `dsp-829-${seq++}`;
    const dispatchWith = (subject: unknown) =>
      dispatchFromTemplate(kernel, store, {
        templateId: template.id,
        dispatchEventId,
        dispatcher: "ap-agent",
        recipient: "ap-agent",
        intent: intent({ expires_at: "2026-11-01T00:00:00Z" }),
        subject,
        policyVersion: DERIVATION_POLICY.policy_version,
      } as never);
    const first = dispatchWith({ iss: ISS, sub: "alice" });
    for (const subject of [{ iss: FOREIGN, sub: "alice" }, { iss: ISS, sub: "" }, { sub: "alice" }]) {
      refused(() => dispatchWith(subject), /subject/);
    }
    store.revoke(template.id);
    expect(dispatchWith({ iss: ISS, sub: "alice" }).mission.id).toBe(first.mission.id);
  });
});

describe("principal-specific source resolution (@spec mission#authority-sources, mission#approval-event, #827)", () => {
  // A derivation policy admitting two vendors, so two Subjects sharing one
  // client can be held to different ones by their sources alone.
  const POLICY = (() => {
    const p = structuredClone(DERIVATION_POLICY) as unknown as { ceiling: AuthorityEntry[] };
    for (const c of p.ceiling) {
      const constraints = c.constraints as { vendors?: string[] } | undefined;
      if (c.resource === RESOURCE && constraints?.vendors) constraints.vendors = ["acme", "globex"];
    }
    return p;
  })();
  const READS = ["payments:invoice.list", "payments:invoice.read"];
  const SCHEDULE = ["payments:payment.schedule"];
  const grant = (actions: string[], vendor: string, maxAmount?: string): AuthorityEntry =>
    entry(actions, {
      constraints: {
        vendors: [vendor],
        ...(maxAmount ? { max_amount: { amount: maxAmount, currency: "USD" } } : {}),
      },
    });
  // A source ceiling entry: a grant plus the policy's delegation grant, which
  // a derived entry inherits when its proposal omits one.
  const DELEGATION = (DERIVATION_POLICY.ceiling[0] as unknown as AuthorityEntry).delegation;
  const cap = (actions: string[], vendor: string, maxAmount?: string): AuthorityEntry => ({
    ...grant(actions, vendor, maxAmount),
    delegation: DELEGATION,
  });

  // Two people sharing one agent registration, and two workloads sharing
  // another, each with its own root and ceiling. `bob-delegated` comes first,
  // so a first-match lookup for any user_delegated provenance lands on bob.
  const shared = (): AuthoritySourceCatalog => ({
    humanPrincipals: ["alice", "bob", "carol", "rita", "ops-reviewer"],
    entries: [
      {
        id: "bob-delegated",
        type: "user_delegated",
        clients: ["ap-agent", "mixed-agent"],
        subjects: ["bob"],
        activators: ["rita"],
        ceiling: [cap(READS, "globex"), cap(SCHEDULE, "globex", "400.00")],
      },
      {
        id: "alice-delegated",
        type: "user_delegated",
        clients: ["ap-agent"],
        subjects: ["alice"],
        activators: ["rita"],
        ceiling: [cap(READS, "acme"), cap(SCHEDULE, "acme", "100.00")],
      },
      {
        id: "wl-recon",
        type: "service_owned",
        clients: ["svc-agent"],
        subjects: ["wl-recon"],
        principals: ["wl-recon"],
        activators: ["ops-reviewer"],
        ceiling: [cap(READS, "acme")],
      },
      {
        id: "wl-payer",
        type: "service_owned",
        clients: ["svc-agent"],
        subjects: ["wl-payer"],
        principals: ["wl-payer"],
        activators: ["ops-reviewer"],
        ceiling: [cap(SCHEDULE, "globex", "250.00")],
      },
      {
        id: "ap-controls",
        type: "organizational",
        clients: ["mixed-agent"],
        subjects: ["acme-accounts-payable"],
        principals: ["acme-accounts-payable"],
        activators: ["rita"],
        ceiling: [cap(READS, "acme")],
        policy: { id: "ap-controls", version: "1", digest: "sha-256:policy-digest" },
      },
    ],
  });

  const k = (over: Record<string, unknown> = {}) =>
    makeKernel({ policy: POLICY as never, authoritySourceCatalog: shared() as never, ...over });

  const approveFor = (
    kernel: MissionKernel,
    sub: string,
    clientId: string,
    proposal: AuthorityEntry[],
    approver = "rita",
    approvalEventId = `apev-827-${seq++}`,
  ): MissionRecord =>
    kernel.approve({
      intent: intent(),
      proposedAuthority: proposal,
      subject: { iss: ISS, sub },
      approver: { iss: ISS, sub: approver },
      clientId,
      approvalEventId,
    });

  const refusedWith = (run: () => unknown, pattern: RegExp): void => {
    try {
      run();
      expect.unreachable("the source gates must refuse");
    } catch (e) {
      expect(e).toBeInstanceOf(IntentError);
      expect((e as IntentError).code).toBe("access_denied");
      expect((e as Error).message).toMatch(pattern);
    }
  };

  it("holds two Subjects sharing one client to their own source ceilings, never the union", () => {
    const kernel = k();
    expect(approveFor(kernel, "alice", "ap-agent", [grant(READS, "acme")]).authority_source).toEqual({
      type: "user_delegated",
    });
    expect(approveFor(kernel, "bob", "ap-agent", [grant(READS, "globex")]).subject).toEqual({ iss: ISS, sub: "bob" });
    expect(approveFor(kernel, "alice", "ap-agent", [grant(SCHEDULE, "acme", "100.00")]).authority_set).toHaveLength(1);
    // Each Subject's request inside the OTHER Subject's ceiling refuses at gate 3.
    refusedWith(
      () => approveFor(kernel, "alice", "ap-agent", [grant(READS, "globex")]),
      /exceeds the authority of the user_delegated source 'alice-delegated'/,
    );
    refusedWith(
      () => approveFor(kernel, "bob", "ap-agent", [grant(READS, "acme")]),
      /exceeds the authority of the user_delegated source 'bob-delegated'/,
    );
    // bob's amount under alice's vendor: alice's own limit binds.
    refusedWith(
      () => approveFor(kernel, "alice", "ap-agent", [grant(SCHEDULE, "acme", "400.00")]),
      /source 'alice-delegated'/,
    );
    // Within the union of both ceilings, but neither alone: refused.
    refusedWith(
      () => approveFor(kernel, "alice", "ap-agent", [grant(READS, "acme"), grant(SCHEDULE, "globex", "400.00")]),
      /source 'alice-delegated'/,
    );
  });

  it("holds two workloads sharing one client to their own source ceilings", () => {
    const kernel = k();
    const recon = approveFor(kernel, "wl-recon", "svc-agent", [grant(READS, "acme")], "ops-reviewer");
    expect(recon.authority_source).toEqual({ type: "service_owned" });
    expect(recon.subject).toEqual({ iss: ISS, sub: "wl-recon" });
    expect(
      approveFor(kernel, "wl-payer", "svc-agent", [grant(SCHEDULE, "globex", "200.00")], "ops-reviewer").subject,
    ).toEqual({ iss: ISS, sub: "wl-payer" });
    refusedWith(
      () => approveFor(kernel, "wl-recon", "svc-agent", [grant(SCHEDULE, "globex", "200.00")], "ops-reviewer"),
      /source 'wl-recon'/,
    );
    refusedWith(
      () => approveFor(kernel, "wl-payer", "svc-agent", [grant(READS, "acme")], "ops-reviewer"),
      /source 'wl-payer'/,
    );
    refusedWith(
      () => approveFor(kernel, "wl-payer", "svc-agent", [grant(SCHEDULE, "globex", "300.00")], "ops-reviewer"),
      /source 'wl-payer'/,
    );
  });

  it("lets an authorized reviewer activate workload authority it does not hold, and refuses one who may not", () => {
    const kernel = k();
    // ops-reviewer is in no ceiling and owns no resource: activation is not possession.
    const record = approveFor(kernel, "wl-payer", "svc-agent", [grant(SCHEDULE, "globex", "200.00")], "ops-reviewer");
    expect(record.approver).toEqual({ iss: ISS, sub: "ops-reviewer" });
    refusedWith(
      () => approveFor(kernel, "wl-payer", "svc-agent", [grant(SCHEDULE, "globex", "200.00")], "rita"),
      /approver 'rita' is not authorized to activate the service_owned authority source 'wl-payer'/,
    );
  });

  it("refuses an absent root, an undeclared client, an overlapping selection, another deployment's catalog, an unavailable resolver and an inconsistent one, before any record or commit", () => {
    const commits: unknown[] = [];
    const onLifecycleCommit = (c: unknown) => commits.push(c);
    const probe = (kernel: MissionKernel, sub: string, clientId: string, pattern: RegExp): void => {
      const eventId = `apev-827-refused-${seq++}`;
      refusedWith(() => approveFor(kernel, sub, clientId, [grant(READS, "acme")], "rita", eventId), pattern);
      expect(kernel.findByApprovalEvent(eventId)).toBeUndefined();
      expect(kernel.allMissions()).toHaveLength(0);
    };
    probe(k({ onLifecycleCommit }), "carol", "ap-agent", /no trusted authority source is declared for 'carol' through client 'ap-agent'/);
    probe(k({ onLifecycleCommit }), "alice", "unknown-agent", /no trusted authority source is declared for client 'unknown-agent'/);
    // Another tenant's catalog never answers for this deployment, whether
    // injected as its resolver or handed to the kernel as its catalog.
    const otherTenant = bindAuthoritySourceCatalog(shared(), ISS, "https://as-other.test");
    probe(
      k({ onLifecycleCommit, authoritySourceResolver: catalogAuthoritySourceResolver(otherTenant) }),
      "alice",
      "ap-agent",
      /catalog serves another deployment/,
    );
    expect(() => k({ authoritySourceCatalog: otherTenant })).toThrow(/bound to deployment 'https:\/\/as-other\.test'/);
    const down = (): never => {
      throw new Error("connect ECONNREFUSED");
    };
    probe(
      k({
        onLifecycleCommit,
        authoritySourceResolver: { resolveForApproval: down, resolveForRendering: down, resolveCommittedRoot: down },
      }),
      "alice",
      "ap-agent",
      /resolver is unavailable/,
    );
    // A resolver that answers for bob when asked about alice is not trusted.
    const base = catalogAuthoritySourceResolver(bindAuthoritySourceCatalog(shared(), ISS, ISS));
    const crossed: AuthoritySourceResolver = {
      ...base,
      resolveForApproval: (input) => base.resolveForApproval({ ...input, subject: { iss: ISS, sub: "bob" } }),
    };
    probe(
      k({ onLifecycleCommit, authoritySourceResolver: crossed }),
      "alice",
      "ap-agent",
      /answered for a different Subject, client, deployment or source/,
    );
    // An overlapping selection refuses at load, and a resolver over one that
    // skipped validation refuses as ambiguous rather than taking the first.
    const overlapping = shared();
    (overlapping.entries as { subjects?: string[] }[])[1].subjects = ["alice", "bob"];
    expect(() => k({ authoritySourceCatalog: overlapping as never })).toThrow(
      /both select subject 'bob' of client 'ap-agent'/,
    );
    refusedWith(
      () =>
        catalogAuthoritySourceResolver(bindAuthoritySourceCatalog(overlapping, ISS, ISS)).resolveForApproval({
          deployment: ISS,
          subject: { iss: ISS, sub: "bob" },
          clientId: "ap-agent",
        }),
      /through client 'ap-agent' is ambiguous/,
    );
    expect(commits).toHaveLength(0);
  });

  it("holds the Subject to the bound namespace before any resolver runs, an injected one included", () => {
    let calls = 0;
    const base = catalogAuthoritySourceResolver(bindAuthoritySourceCatalog(shared(), ISS, ISS));
    // A resolver that would answer any principal with alice's root, echoing
    // back whatever principal it was asked about.
    const permissive: AuthoritySourceResolver = {
      ...base,
      resolveForApproval: (input) => {
        calls++;
        return { ...base.resolveForApproval({ ...input, subject: { iss: ISS, sub: "alice" } }), principal: input.subject };
      },
    };
    const kernel = k({ authoritySourceResolver: permissive });
    const foreign = { iss: "https://untrusted.example", sub: "alice" };
    refusedWith(
      () => kernel.resolveAuthoritySource({ clientId: "ap-agent", subject: foreign }),
      /subject is not a principal of this deployment's issuer namespace/,
    );
    expect(() =>
      createTemplate(
        new TemplateStore(),
        {
          template_version: "t827-ns",
          issuer: ISS,
          approver: { iss: ISS, sub: "rita" },
          ceiling: [grant(READS, "acme")],
          dispatch_policy: "read-only",
          dispatchers: ["ap-agent"],
          recipients: { subjects: [foreign], agents: ["ap-agent"] },
          per_instance_lifetime_s: 900,
          max_active: 5,
          rate_per_min: 30,
          review_cadence_s: 86400,
          approval_event_id: `tmpl-827-${seq++}`,
          expires_at: "2099-01-01T00:00:00Z",
        } as never,
        kernel.authoritySourceOptions(),
      ),
    ).toThrow(/subject is not a principal of this deployment's issuer namespace/);
    expect(calls).toBe(0);
  });

  it("refuses at the creation funnel a record whose source is not the one its approval resolved", () => {
    const kernel = k();
    const resolved = kernel.resolveAuthoritySource({ clientId: "ap-agent", subject: { iss: ISS, sub: "alice" } });
    const record = approveFor(kernel, "alice", "ap-agent", [grant(READS, "acme")]);
    const forged = { ...record, id: `${record.id}x`, approval_event_id: `apev-827-forged-${seq++}` };
    refusedWith(
      () => kernel.insertRecord({ ...forged, authority_source: { type: "service_owned" } } as never, undefined, { source: resolved }),
      /is not the source its approval resolved/,
    );
    refusedWith(
      () =>
        kernel.insertRecord({ ...forged, authority_set: [grant(READS, "globex")] } as never, undefined, {
          source: resolved,
        }),
      /exceeds the authority of the user_delegated source 'alice-delegated'/,
    );
    expect(kernel.allMissions()).toHaveLength(1);
    expect(() => kernel.insertRecord(forged as never, undefined, {} as never)).toThrow(/requires the source the record was established from/);
  });

  it("resolves once per approval completion, so gate 3 asserts the resolution gates 1, 2, 4 and 5 ran on", () => {
    const base = catalogAuthoritySourceResolver(bindAuthoritySourceCatalog(shared(), ISS, ISS));
    let calls = 0;
    const counting: AuthoritySourceResolver = {
      ...base,
      resolveForApproval: (input) => {
        calls++;
        return base.resolveForApproval(input);
      },
    };
    const kernel = k({ authoritySourceResolver: counting });
    const predecessor = approveFor(kernel, "alice", "ap-agent", [grant(READS, "acme")]);
    expect(calls).toBe(1);
    // Expansion is a fresh approval event for the predecessor's Subject: one more.
    const { successor } = createExpansion(kernel, {
      predecessorId: predecessor.id,
      intent: intent(),
      proposedAuthority: [grant(READS, "acme"), grant(SCHEDULE, "acme", "100.00")],
      approver: { iss: ISS, sub: "rita" },
      approvalEventId: `apev-827-exp-${seq++}`,
      approvedUntil: "2027-01-01T00:00:00Z",
    });
    expect(calls).toBe(2);
    expect(successor.authority_source).toEqual({ type: "user_delegated" });
    // The successor resolves alice's root, never the first user_delegated entry (bob's).
    expect(() =>
      createExpansion(kernel, {
        predecessorId: predecessor.id,
        intent: intent(),
        proposedAuthority: [grant(READS, "globex")],
        approver: { iss: ISS, sub: "rita" },
        approvalEventId: `apev-827-exp-${seq++}`,
        approvedUntil: "2027-01-01T00:00:00Z",
      }),
    ).toThrow(/source 'alice-delegated'/);
  });

  it("recovers the parent's committed root for a child, never the first root of that provenance, with the root's own context", () => {
    const kernel = k({ actorProfiles: { "child-agent": "ai_agent" } });
    const parent = approveFor(kernel, "alice", "ap-agent", [grant(READS, "acme")]);
    // bob-delegated is the first user_delegated root in the catalog, and
    // alice's acme read lies outside it: the child succeeds only on alice's.
    const { child } = createChildMission(kernel, {
      parentId: parent.id,
      intent: intent({ goal: "Read one invoice", expires_at: "2026-11-01T00:00:00Z" }),
      proposedAuthority: [grant(["payments:invoice.read"], "acme")],
      childActor: { sub: "child-agent", sub_profile: "ai_agent" },
    } as never);
    const root = kernel.committedSourceBinding(child.id);
    expect(root).toEqual(kernel.committedSourceBinding(parent.id));
    expect(root.rootId).toBe("alice-delegated");
    // The root's own context, not the child's: the root still selects it.
    expect(root.clientId).toBe("ap-agent");
    expect(kernel.sourceBindings.basisOf(child.id)).toBe("inherited");
    expect(kernel.sourceBindings.basisOf(parent.id)).toBe("resolved");
    // A grandchild beyond alice's root refuses against that same root.
    refusedWith(
      () => kernel.assertInheritedAuthoritySource(root, [grant(READS, "globex")]),
      /source 'alice-delegated'/,
    );
    // Provenance compares member by member: a policy id and version whose
    // delimiter-joined forms collide are a changed provenance, not the same root.
    const colliding = shared();
    (colliding.entries as unknown[]).push({
      ...(colliding.entries[4] as object),
      id: "split",
      clients: ["split-agent"],
      subjects: ["acme-accounts-payable"],
      policy: { id: "p", version: "q:r", digest: "sha-256:two" },
    });
    const resolver = catalogAuthoritySourceResolver(bindAuthoritySourceCatalog(colliding, ISS, ISS));
    refusedWith(
      () =>
        resolver.resolveCommittedRoot({
          deployment: ISS,
          binding: {
            rootId: "split",
            deployment: ISS,
            principal: { iss: ISS, sub: "acme-accounts-payable" },
            clientId: "split-agent",
            provenance: { type: "organizational", policy: { id: "p:q", version: "r", digest: "sha-256:two" } },
          },
        }),
      /has changed provenance/,
    );
  });
  it("records each recipient's own root at template consent, and dispatch draws on the dispatching Subject's root, never another recipient's", () => {
    const kernel = k();
    const store = new TemplateStore();
    const consent = (subjects: string[], agents = ["ap-agent"]) =>
      createTemplate(
        store,
        {
          template_version: "t827",
          issuer: ISS,
          approver: { iss: ISS, sub: "rita" },
          ceiling: [grant(READS, "acme")],
          dispatch_policy: "read-only",
          dispatchers: agents,
          recipients: { subjects: subjects.map((sub) => ({ iss: ISS, sub })), agents },
          per_instance_lifetime_s: 900,
          max_active: 5,
          rate_per_min: 30,
          review_cadence_s: 86400,
          approval_event_id: `tmpl-827-${seq++}`,
          expires_at: "2099-01-01T00:00:00Z",
        } as never,
        kernel.authoritySourceOptions(),
      );
    // Two people sharing one agent registration: one provenance, two roots.
    const template = consent(["alice", "bob"]);
    expect(template.authority_source).toEqual({ type: "user_delegated" });
    expect(store.sourceBinding(template.id, { iss: ISS, sub: "alice" }, "ap-agent")?.rootId).toBe("alice-delegated");
    expect(store.sourceBinding(template.id, { iss: ISS, sub: "bob" }, "ap-agent")?.rootId).toBe("bob-delegated");
    // A recipient listed twice is one pair with one root, not a refusal.
    const twice = consent(["alice", "alice"]);
    expect(store.sourceBinding(twice.id, { iss: ISS, sub: "alice" }, "ap-agent")?.rootId).toBe("alice-delegated");
    const dispatch = (sub: string) =>
      dispatchFromTemplate(kernel, store, {
        templateId: template.id,
        dispatchEventId: `dsp-827-${seq++}`,
        dispatcher: "ap-agent",
        intent: intent({ expires_at: "2026-11-01T00:00:00Z" }),
        subject: { iss: ISS, sub },
        policyVersion: DERIVATION_POLICY.policy_version,
      } as never);
    const { mission } = dispatch("alice");
    expect(kernel.committedSourceBinding(mission.id).rootId).toBe("alice-delegated");
    // bob's instance draws on bob's root, whose ceiling holds no acme read.
    refusedWith(() => dispatch("bob"), /source 'bob-delegated'/);
    // Recipients whose roots differ in provenance still refuse: a template has one.
    expect(() => consent(["bob", "acme-accounts-payable"], ["mixed-agent"])).toThrow(
      /draw on more than one authority source/,
    );
    expect(() => consent(["alice", "carol"])).toThrow(/no trusted authority source is declared for 'carol'/);
    // Gate 2 runs for every distinct root: an approver who may activate
    // alice's root but not bob's cannot consent for both.
    const split = shared();
    (split.entries as { activators: string[] }[])[0].activators = ["ops-reviewer"];
    const splitKernel = k({ authoritySourceCatalog: split as never });
    expect(() =>
      createTemplate(
        new TemplateStore(),
        {
          template_version: "t827-split",
          issuer: ISS,
          approver: { iss: ISS, sub: "rita" },
          ceiling: [grant(READS, "acme")],
          dispatch_policy: "read-only",
          dispatchers: ["ap-agent"],
          recipients: { subjects: [{ iss: ISS, sub: "alice" }, { iss: ISS, sub: "bob" }], agents: ["ap-agent"] },
          per_instance_lifetime_s: 900,
          max_active: 5,
          rate_per_min: 30,
          review_cadence_s: 86400,
          approval_event_id: `tmpl-827-${seq++}`,
          expires_at: "2099-01-01T00:00:00Z",
        } as never,
        splitKernel.authoritySourceOptions(),
      ),
    ).toThrow(/approver 'rita' is not authorized to activate the user_delegated authority source 'bob-delegated'/);
  });
  it("renders the source of the Subject it names, and refuses a client whose sources differ in provenance when it names none", () => {
    const kernel = k();
    expect(kernel.renderAuthoritySource({ clientId: "ap-agent" })).toEqual({ type: "user_delegated" });
    expect(() => kernel.renderAuthoritySource({ clientId: "mixed-agent" })).toThrow(/depends on the Subject/);
    expect(kernel.renderAuthoritySource({ clientId: "mixed-agent", subject: { iss: ISS, sub: "bob" } })).toEqual({
      type: "user_delegated",
    });
    expect(
      kernel.renderAuthoritySource({ clientId: "mixed-agent", subject: { iss: ISS, sub: "acme-accounts-payable" } }),
    ).toEqual({ type: "organizational", policy: { id: "ap-controls", version: "1", digest: "sha-256:policy-digest" } });
  });

  it("renders through the configured resolver the decision consults, never the static catalog behind it", () => {
    // The kernel's own catalog declares governed-agent organizational; the
    // deployment's resolver serves it as a delegated source. A rendering read
    // from the catalog would show a provenance the decision never establishes.
    const served: AuthoritySourceCatalog = {
      humanPrincipals: ["alice", "bob"],
      entries: [
        {
          id: "governed-delegated",
          type: "user_delegated",
          clients: ["governed-agent"],
          activators: ["bob"],
          ceiling: DEPLOYMENT_CEILING,
        },
      ],
    };
    const resolver = catalogAuthoritySourceResolver(bindAuthoritySourceCatalog(served, ISS, ISS));
    const kernel = makeKernel({ authoritySourceResolver: resolver });
    const rendered = kernel.renderAuthoritySource({ clientId: "governed-agent" });
    expect(rendered).toEqual({ type: "user_delegated" });
    expect(approve(kernel, { clientId: "governed-agent" }).authority_source).toEqual(rendered);
    // An unavailable resolver, or one answering with no valid source, renders nothing.
    const down = (): never => {
      throw new Error("connect ECONNREFUSED");
    };
    refusedWith(
      () => makeKernel({ authoritySourceResolver: { ...resolver, resolveForRendering: down } }).renderAuthoritySource({ clientId: "governed-agent" }),
      /resolver is unavailable/,
    );
    refusedWith(
      () =>
        makeKernel({
          authoritySourceResolver: { ...resolver, resolveForRendering: () => ({ type: "self_asserted" }) as never },
        }).renderAuthoritySource({ clientId: "governed-agent" }),
      /answered with no valid source/,
    );
  });

  it("runs gate 4 at dispatch on the recipient's own root, refusing a human Subject of a workload source", () => {
    // Consent establishes each pair's root and runs gate 2; the Subject an
    // instance acts for is held to the root's subject discipline at dispatch.
    const kernel = makeKernel();
    const store = new TemplateStore();
    const template = createTemplate(
      store,
      {
        template_version: "t827-gate4",
        issuer: ISS,
        approver: { iss: ISS, sub: "bob" },
        ceiling: [entry(READ_ACTIONS)],
        dispatch_policy: "read-only",
        dispatchers: ["svc-agent"],
        recipients: { subjects: [{ iss: ISS, sub: "alice" }, { iss: ISS, sub: "svc-reconciler" }], agents: ["svc-agent"] },
        per_instance_lifetime_s: 900,
        max_active: 5,
        rate_per_min: 30,
        review_cadence_s: 86400,
        approval_event_id: `tmpl-827-${seq++}`,
        expires_at: "2099-01-01T00:00:00Z",
      } as never,
      kernel.authoritySourceOptions(),
    );
    expect(template.authority_source).toEqual({ type: "service_owned" });
    const dispatch = (sub: string) =>
      dispatchFromTemplate(kernel, store, {
        templateId: template.id,
        dispatchEventId: `dsp-827-${seq++}`,
        dispatcher: "svc-agent",
        intent: intent({ expires_at: "2026-11-01T00:00:00Z" }),
        subject: { iss: ISS, sub },
        policyVersion: DERIVATION_POLICY.policy_version,
      } as never);
    expect(dispatch("svc-reconciler").mission.subject).toEqual({ iss: ISS, sub: "svc-reconciler" });
    refusedWith(() => dispatch("alice"), /MUST NOT record the human principal 'alice'/);
  });

  it("draws down under a configured resolver from that resolver's committed root, never the catalog behind the kernel", () => {
    // The configured resolver serves ap-agent a narrow delegated root; the
    // kernel's own catalog carries a wider entry with the same provenance. A
    // drawdown checked against that catalog would admit authority the
    // approved root never held.
    const narrow: AuthoritySourceCatalog = {
      humanPrincipals: ["alice", "bob", "rita"],
      entries: [
        { id: "narrow-people", type: "user_delegated", clients: ["ap-agent"], activators: ["rita"], ceiling: [cap(READS, "acme")] },
      ],
    };
    const kernel = k({
      authoritySourceCatalog: catalog() as never,
      authoritySourceResolver: catalogAuthoritySourceResolver(bindAuthoritySourceCatalog(narrow, ISS, ISS)),
      actorProfiles: { "child-agent": "ai_agent" },
    });
    const parent = approveFor(kernel, "alice", "ap-agent", [grant(READS, "acme")]);
    const { child } = createChildMission(kernel, {
      parentId: parent.id,
      intent: intent({ goal: "Read one invoice", expires_at: "2026-11-01T00:00:00Z" }),
      proposedAuthority: [grant(["payments:invoice.read"], "acme")],
      childActor: { sub: "child-agent", sub_profile: "ai_agent" },
    } as never);
    expect(kernel.committedSourceBinding(child.id).rootId).toBe("narrow-people");
    // Template consent resolves through the resolver; dispatch is a drawdown
    // whose instance set (vendor.read included) exceeds the resolver's root.
    const store = new TemplateStore();
    const template = createTemplate(
      store,
      {
        template_version: "t827-drawdown",
        issuer: ISS,
        approver: { iss: ISS, sub: "rita" },
        ceiling: [grant(["payments:invoice.list", "payments:invoice.read", "payments:vendor.read"], "acme")],
        dispatch_policy: "read-only",
        dispatchers: ["ap-agent"],
        recipients: { subjects: [{ iss: ISS, sub: "alice" }], agents: ["ap-agent"] },
        per_instance_lifetime_s: 900,
        max_active: 5,
        rate_per_min: 30,
        review_cadence_s: 86400,
        approval_event_id: `tmpl-827-${seq++}`,
        expires_at: "2099-01-01T00:00:00Z",
      } as never,
      kernel.authoritySourceOptions(),
    );
    refusedWith(
      () =>
        dispatchFromTemplate(kernel, store, {
          templateId: template.id,
          dispatchEventId: `dsp-827-${seq++}`,
          dispatcher: "ap-agent",
          intent: intent({ expires_at: "2026-11-01T00:00:00Z" }),
          subject: { iss: ISS, sub: "alice" },
          policyVersion: DERIVATION_POLICY.policy_version,
        } as never),
      /source 'narrow-people'/,
    );
    expect(kernel.allMissions()).toHaveLength(2);
    // The committed-root answer is verified like an approval answer: one for
    // another root, an unavailable resolver, or another deployment refuses.
    const base = catalogAuthoritySourceResolver(bindAuthoritySourceCatalog(narrow, ISS, ISS));
    const root = kernel.committedSourceBinding(parent.id);
    const other = { ...base.resolveCommittedRoot({ deployment: ISS, binding: root }), rootId: "elsewhere" };
    const crossed = k({
      authoritySourceCatalog: catalog() as never,
      authoritySourceResolver: { ...base, resolveCommittedRoot: () => other },
    });
    refusedWith(() => crossed.resolveCommittedSource(root), /answered for a different root, deployment, root context or source/);
    const down = (): never => {
      throw new Error("connect ECONNREFUSED");
    };
    const unavailable = k({
      authoritySourceCatalog: catalog() as never,
      authoritySourceResolver: { ...base, resolveCommittedRoot: down },
    });
    refusedWith(() => unavailable.resolveCommittedSource(root), /resolver is unavailable/);
    const permissive = k({
      authoritySourceCatalog: catalog() as never,
      authoritySourceResolver: { ...base, resolveCommittedRoot: (input) => ({ ...base.resolveCommittedRoot({ ...input, deployment: ISS, binding: root }) }) },
    });
    refusedWith(
      () => permissive.resolveCommittedSource({ ...root, deployment: "https://as-other.test" }),
      /belongs to another deployment/,
    );
  });
  it("accepts a source request only as confirmation of the root that resolves, never as a choice of root", () => {
    const resolver = catalogAuthoritySourceResolver(bindAuthoritySourceCatalog(shared(), ISS, ISS));
    const ask = { deployment: ISS, subject: { iss: ISS, sub: "bob" }, clientId: "mixed-agent" };
    expect(resolver.resolveForApproval({ ...ask, sourceRequest: { type: "user_delegated" } }).rootId).toBe("bob-delegated");
    refusedWith(
      () =>
        resolver.resolveForApproval({
          ...ask,
          sourceRequest: { type: "organizational", policy: { id: "ap-controls", version: "1" } },
        }),
      /requested organizational authority source is not the one declared for 'bob'/,
    );
  });

  it("recovers a committed root by its id, and refuses a missing root, changed provenance or policy, another deployment, or a root that no longer selects its Subject", () => {
    const bound = bindAuthoritySourceCatalog(shared(), ISS, ISS);
    const resolver = catalogAuthoritySourceResolver(bound);
    const alice = { iss: ISS, sub: "alice" };
    const committed = resolver.resolveForApproval({ deployment: ISS, subject: alice, clientId: "ap-agent" });
    expect(committed.rootId).toBe("alice-delegated");
    expect(committed.catalogRevision).toBe(bound.revision);
    const binding = { rootId: committed.rootId, deployment: ISS, principal: alice, clientId: "ap-agent", provenance: committed.provenance };
    expect(resolver.resolveCommittedRoot({ deployment: ISS, binding }).entry).toBe(committed.entry);
    const later = (edit: (c: AuthoritySourceCatalog) => void) => {
      const c = shared();
      edit(c);
      return catalogAuthoritySourceResolver(bindAuthoritySourceCatalog(c, ISS, ISS));
    };
    refusedWith(
      () => later((c) => (c.entries as unknown[]).splice(1, 1)).resolveCommittedRoot({ deployment: ISS, binding }),
      /no longer declared/,
    );
    refusedWith(
      () =>
        later((c) => {
          (c.entries as { subjects?: string[] }[])[1].subjects = ["dave"];
        }).resolveCommittedRoot({ deployment: ISS, binding }),
      /no longer applies to 'alice' through client 'ap-agent'/,
    );
    refusedWith(
      () => resolver.resolveCommittedRoot({ deployment: ISS, binding: { ...binding, provenance: { type: "service_owned" } } }),
      /has changed provenance/,
    );
    refusedWith(() => resolver.resolveCommittedRoot({ deployment: "https://as-other.test", binding }), /serves another deployment/);
    refusedWith(
      () => resolver.resolveCommittedRoot({ deployment: ISS, binding: { ...binding, deployment: "https://as-other.test" } }),
      /belongs to another deployment/,
    );
    const org = resolver.resolveForApproval({
      deployment: ISS,
      subject: { iss: ISS, sub: "acme-accounts-payable" },
      clientId: "mixed-agent",
    });
    const orgBinding = { rootId: org.rootId, deployment: ISS, principal: org.principal, clientId: "mixed-agent", provenance: org.provenance };
    refusedWith(
      () =>
        later((c) => {
          (c.entries as { policy?: unknown }[])[4].policy = { id: "ap-controls", version: "1", digest: "sha-256:edited" };
        }).resolveCommittedRoot({ deployment: ISS, binding: orgBinding }),
      /has drifted from the reference the Mission committed/,
    );
  });
  const CHILD_ACTORS = { "child-agent": "ai_agent" };
  const childOf = (kernel: MissionKernel, parentId: string) =>
    createChildMission(kernel, {
      parentId,
      intent: intent({ goal: "Read one invoice", expires_at: "2026-11-01T00:00:00Z" }),
      proposedAuthority: [grant(["payments:invoice.read"], "acme")],
      childActor: { sub: "child-agent", sub_profile: "ai_agent" },
    } as never);

  it("preserves every committed root across a restart, and a child drawn after it recovers its parent's", () => {
    const file = storeFile();
    const before = k({ actorProfiles: CHILD_ACTORS, store: { file } });
    const parent = approveFor(before, "alice", "ap-agent", [grant(READS, "acme")]);
    const root = before.committedSourceBinding(parent.id);
    before.db.close();
    const after = k({ actorProfiles: CHILD_ACTORS, store: { file } });
    try {
      expect(after.committedSourceBinding(parent.id)).toEqual(root);
      const { child } = childOf(after, parent.id);
      expect(after.committedSourceBinding(child.id)).toEqual(root);
    } finally {
      after.db.close();
    }
  });

  it("records a fresh root for an Expansion successor, never the predecessor's", () => {
    const file = storeFile();
    const before = k({ store: { file } });
    const predecessor = approveFor(before, "alice", "ap-agent", [grant(READS, "acme")]);
    before.db.close();
    // The deployment restarts with alice's delegated authority declared under a
    // new root. Expansion is a fresh approval, so the successor resolves that
    // root rather than copying the predecessor's binding.
    const renamed = shared();
    (renamed.entries as { id: string }[])[1].id = "alice-delegated-v2";
    const after = k({ authoritySourceCatalog: renamed as never, store: { file } });
    try {
      const { successor } = createExpansion(after, {
        predecessorId: predecessor.id,
        intent: intent(),
        proposedAuthority: [grant(READS, "acme"), grant(SCHEDULE, "acme", "100.00")],
        approver: { iss: ISS, sub: "rita" },
        approvalEventId: `apev-827-exp-${seq++}`,
        approvedUntil: "2027-01-01T00:00:00Z",
      });
      expect(after.committedSourceBinding(successor.id).rootId).toBe("alice-delegated-v2");
      expect(after.sourceBindings.basisOf(successor.id)).toBe("resolved");
      expect(after.committedSourceBinding(predecessor.id).rootId).toBe("alice-delegated");
    } finally {
      after.db.close();
    }
  });

  // A store whose rows predate committed-root bindings: approved and drawn
  // down as usual, then the bindings table emptied, as an upgraded store has it.
  const preBindingStore = () => {
    const file = storeFile();
    const kernel = k({ actorProfiles: CHILD_ACTORS, store: { file } });
    const parent = approveFor(kernel, "alice", "ap-agent", [grant(READS, "acme")]);
    const { child } = childOf(kernel, parent.id);
    kernel.db.prepare("DELETE FROM authority_source_bindings").run();
    kernel.db.close();
    return { file, parent, child };
  };
  const reopen = (file: string, over: Record<string, unknown> = {}) =>
    k({ actorProfiles: CHILD_ACTORS, store: { file }, ...over });

  it("binds a pre-binding row only from a reconciliation mapping or a declared historical catalog, and a derived row from its origin", () => {
    // No evidence: nothing binds, and a drawdown refuses.
    {
      const { file, parent, child } = preBindingStore();
      const kernel = reopen(file);
      try {
        expect(kernel.sourceBindings.get(parent.id)).toBeUndefined();
        expect(kernel.sourceBindings.get(child.id)).toBeUndefined();
        refusedWith(() => childOf(kernel, parent.id), /has no committed authority-source root/);
      } finally {
        kernel.db.close();
      }
    }
    // An explicit mapping binds the root row; its child takes the parent's
    // root, even listed before it (a skewed clock), since passes repeat.
    {
      const { file, parent, child } = preBindingStore();
      const skew = k({ store: { file } });
      skew.db.prepare("UPDATE missions SET created_at = ? WHERE id = ?").run("2000-01-01T00:00:00.000Z", child.id);
      skew.db.close();
      const kernel = reopen(file, { authoritySourceReconciliation: { mappings: { [parent.id]: "alice-delegated" } } });
      try {
        expect(kernel.committedSourceBinding(parent.id).rootId).toBe("alice-delegated");
        expect(kernel.sourceBindings.basisOf(parent.id)).toBe("reconciled");
        expect(kernel.committedSourceBinding(child.id)).toEqual(kernel.committedSourceBinding(parent.id));
        expect(kernel.sourceBindings.basisOf(child.id)).toBe("reconciled");
        expect(childOf(kernel, parent.id).child.authority_source).toEqual({ type: "user_delegated" });
      } finally {
        kernel.db.close();
      }
    }
    // A declared historical catalog in force at the approval binds it too.
    {
      const { file, parent } = preBindingStore();
      const kernel = reopen(file, {
        authoritySourceReconciliation: { history: [{ catalog: shared(), from: "2000-01-01T00:00:00Z" }] },
      });
      try {
        expect(kernel.committedSourceBinding(parent.id).rootId).toBe("alice-delegated");
      } finally {
        kernel.db.close();
      }
    }
    // A historical root with another provenance is no evidence for this row.
    {
      const { file, parent } = preBindingStore();
      const otherMode = shared();
      Object.assign((otherMode.entries as object[])[1] as object, { type: "service_owned", principals: ["alice"] });
      const kernel = reopen(file, {
        authoritySourceReconciliation: { history: [{ catalog: otherMode, from: "2000-01-01T00:00:00Z" }] },
      });
      try {
        expect(kernel.sourceBindings.get(parent.id)).toBeUndefined();
      } finally {
        kernel.db.close();
      }
    }
    // A historical catalog whose interval does not contain the approval is no evidence.
    {
      const { file, parent } = preBindingStore();
      const kernel = reopen(file, {
        authoritySourceReconciliation: {
          history: [{ catalog: shared(), from: "2000-01-01T00:00:00Z", until: "2001-01-01T00:00:00Z" }],
        },
      });
      try {
        expect(kernel.sourceBindings.get(parent.id)).toBeUndefined();
      } finally {
        kernel.db.close();
      }
    }
  });

  it("never binds a pre-binding row to a replacement root that merely matches it in the current catalog", () => {
    // Root A (alice-delegated) approved the row; the deployment then removed A
    // and declared B for the same Subject, client and provenance.
    const replaced = () => {
      const c = shared();
      (c.entries as { id: string }[])[1].id = "alice-delegated-b";
      return c;
    };
    // No evidence: B is the unique current match, and the row still does not bind to it.
    {
      const { file, parent } = preBindingStore();
      const kernel = reopen(file, { authoritySourceCatalog: replaced() as never });
      try {
        expect(kernel.sourceBindings.get(parent.id)).toBeUndefined();
        refusedWith(() => childOf(kernel, parent.id), /has no committed authority-source root/);
      } finally {
        kernel.db.close();
      }
    }
    // A mapping naming A binds A, which is no longer declared: the drawdown refuses.
    {
      const { file, parent } = preBindingStore();
      const kernel = reopen(file, {
        authoritySourceCatalog: replaced() as never,
        authoritySourceReconciliation: { mappings: { [parent.id]: "alice-delegated" } },
      });
      try {
        expect(kernel.committedSourceBinding(parent.id).rootId).toBe("alice-delegated");
        refusedWith(() => childOf(kernel, parent.id), /committed is no longer declared/);
      } finally {
        kernel.db.close();
      }
    }
    // The catalog in force at the approval names A as well; never B.
    {
      const { file, parent } = preBindingStore();
      const kernel = reopen(file, {
        authoritySourceCatalog: replaced() as never,
        authoritySourceReconciliation: { history: [{ catalog: shared(), from: "2000-01-01T00:00:00Z" }] },
      });
      try {
        expect(kernel.committedSourceBinding(parent.id).rootId).toBe("alice-delegated");
        refusedWith(() => childOf(kernel, parent.id), /committed is no longer declared/);
      } finally {
        kernel.db.close();
      }
    }
  });

  it("refuses construction on reconciliation evidence it cannot trust", () => {
    expect(() =>
      k({
        authoritySourceReconciliation: {
          history: [
            { catalog: shared(), from: "2000-01-01T00:00:00Z" },
            { catalog: shared(), from: "2010-01-01T00:00:00Z" },
          ],
        },
      }),
    ).toThrow(/intervals overlap/);
    expect(() =>
      k({ authoritySourceReconciliation: { history: [{ catalog: shared(), from: "2010-01-01T00:00:00Z", until: "2000-01-01T00:00:00Z" }] } }),
    ).toThrow(/from must precede until/);
    const overlapping = shared();
    (overlapping.entries as { subjects?: string[] }[])[1].subjects = ["alice", "bob"];
    expect(() =>
      k({ authoritySourceReconciliation: { history: [{ catalog: overlapping, from: "2000-01-01T00:00:00Z" }] } }),
    ).toThrow(/both select subject 'bob'/);
    expect(() => k({ authoritySourceReconciliation: { mappings: { "msn-x": "" } } })).toThrow(/must name a root/);
  });
});
