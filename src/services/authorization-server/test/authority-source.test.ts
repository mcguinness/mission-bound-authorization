import { approvalContextManifest } from "@mission/core";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  type AuthoritySourceCatalog,
  createChildMission,
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
    const kernel = makeKernel();
    const record = approve(kernel, {
      clientId: "governed-agent",
      subject: "acme-accounts-payable",
    });
    // The governed policy is edited after approval: the record's committed
    // digest no longer matches what the catalog now resolves.
    const drifted = catalog();
    (drifted.entries as { policy?: { digest: string } }[])[2].policy = {
      id: "ap-controls",
      version: "1",
      digest: "sha-256:edited-policy",
    } as never;
    const after = makeKernel({ authoritySourceCatalog: drifted as never });
    expect(() => after.assertInheritedAuthoritySource(record.authority_source, [])).toThrow(
      /has drifted from the reference the Mission committed/,
    );
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
    // The uniqueness rule is what makes a drawdown's re-resolution
    // unambiguous, so it is enforced in production (the kernel constructor),
    // not only over the shipped file.
    const duplicateIdentity = catalog();
    (duplicateIdentity.entries as { type: string }[])[1].type = "user_delegated";
    expect(() => makeKernel({ authoritySourceCatalog: duplicateIdentity as never })).toThrow(
      /duplicate source identity/,
    );
    const duplicateClient = catalog();
    (duplicateClient.entries as { clients: string[] }[])[1].clients = ["ap-agent"];
    expect(() => makeKernel({ authoritySourceCatalog: duplicateClient as never })).toThrow(
      /declared twice/,
    );
  });

  it("refuses a catalog that declares one client or one source identity twice", () => {
    const duplicateClient = catalog();
    (duplicateClient.entries as { clients: string[] }[])[1].clients = ["ap-agent"];
    expect(() => validateAuthoritySourceCatalog(duplicateClient)).toThrow(/declared twice/);
    const duplicateIdentity = catalog();
    (duplicateIdentity.entries as { type: string }[])[1].type = "user_delegated";
    expect(() => validateAuthoritySourceCatalog(duplicateIdentity)).toThrow(
      /duplicate source identity/,
    );
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
    const kernel = makeKernel({ actorProfiles: { "child-agent": "ai_agent" } });
    const parent = approve(kernel);
    const narrowed = catalog();
    (narrowed.entries as { ceiling: AuthorityEntry[] }[])[0].ceiling = [
      entry(["payments:vendor.read"]),
    ];
    const after = makeKernel({
      authoritySourceCatalog: narrowed as never,
      actorProfiles: { "child-agent": "ai_agent" },
    });
    // The parent record is re-presented to a kernel whose catalog narrowed; the
    // inherited source identity still resolves, so provenance is untouched, but
    // the ceiling assertion refuses.
    expect(() =>
      after.assertInheritedAuthoritySource(parent.authority_source, parent.authority_set),
    ).toThrow(/exceeds the authority of the user_delegated source/);
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
        recipients: ["ap-agent"],
        per_instance_lifetime_s: 900,
        max_active: 5,
        rate_per_min: 30,
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
      recipient: "ap-agent",
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
          recipients: ["ap-agent", "svc-agent"],
          per_instance_lifetime_s: 900,
          max_active: 5,
          rate_per_min: 30,
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
