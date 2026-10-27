/**
 * @spec resource-access#resource-contract, resource-access#entry-validation,
 * resource-access#subset, resource-access#scope-projection,
 * txn-authorization#resource-challenge (#249, D553): the authorization
 * server's half of the resource contract reference.
 *
 * The reference is assembled from trusted configuration before approval (a
 * proposed one is validated, a required one recorded), committed by
 * `authority_hash`, preserved exactly by derivation and projection, refused
 * (never dropped) by a surface that does not implement it, and resolved by
 * the Transaction Authorization Server to the Operation Profile version it
 * names, with no version read from the entry's `type`.
 */

import { type Server } from "node:http";
import {
  authorityHash,
  type JsonValue,
  projectScope,
  ResourceContractDeclarations,
  type ResourceContractRef,
  resourceContractDigest,
} from "@mission/core";
import { DERIVATION_POLICY, RESOURCE_CONTRACTS } from "@mission/demo-data";
import { importJWK, SignJWT, type CryptoKey, generateKeyPair } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  ApprovalSessionStore,
  type AuthorityEntry,
  type BuiltAs,
  buildAuthorizationServer,
  ChildDelegationError,
  DispatchError,
  dispatchFromTemplate,
  createChildMission,
  createTemplate,
  deriveAuthoritySet,
  IntentError,
  MissionKernel,
  missionResourceAccessProfile,
  OperationProfileRegistry,
  projectThroughEffective,
  TemplateError,
  TemplateStore,
  validateMissionIntent,
  validateMissionResourceAccessSchema,
} from "../src/index.js";
import { TemplateConsentProposals, templateConsentDisclosure } from "../src/adapters/template-consent.js";
import { inheritResourceContract } from "../src/kernel/child-delegation.js";
import { pinDispatchPolicy, templateContracts } from "../src/kernel/template.js";
import { aiAgents } from "./actor-profiles.helper.js";
import { TEST_APPROVAL_PRINCIPALS } from "./approval-fixture.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
const CONTRACT = "https://payments.test/contracts/payments";
const READ = "payments:invoice.read";
const ACTIONS = [...new Set(DERIVATION_POLICY.ceiling.filter((e) => e.resource === RESOURCE).flatMap((e) => e.actions))];
const NOW = new Date("2026-10-20T12:00:00Z");

const doc = (version: string, actions: readonly string[] = ACTIONS, profile = `profile-${version}`) => ({
  id: CONTRACT,
  version,
  operation_profile: profile,
  operations: Object.fromEntries(actions.map((a, i) => [`op_${i}`, { action: a }])),
});
const ref = (version: string, actions?: readonly string[], profile?: string): ResourceContractRef => ({
  id: CONTRACT,
  version,
  digest: resourceContractDigest(doc(version, actions, profile)),
});
const declared = (version: string, state: string, extra: Record<string, unknown> = {}, actions?: readonly string[], profile?: string) => ({
  version,
  state,
  digest: ref(version, actions, profile).digest,
  document: doc(version, actions, profile),
  ...extra,
});
const declarations = (versions: unknown[], requires: string[] = []) =>
  new ResourceContractDeclarations([
    { resource: RESOURCE, resource_match: "prefix", id: CONTRACT, requires_reference: requires, versions },
  ]);

const V1 = ref("v1");
const V2 = ref("v2");
/** v1 superseded within retention, v2 current. */
const SUPERSEDED = declarations([declared("v1", "superseded", { retained_until: "2027-01-01T00:00:00Z" }), declared("v2", "current")]);
/** v2 current and required for the read. */
const REQUIRED = declarations([declared("v1", "superseded", { retained_until: "2027-01-01T00:00:00Z" }), declared("v2", "current")], [READ]);

const TASK_INTENT = { goal: "Read Acme's Q3 invoices", target_resources: [RESOURCE], expires_at: "2027-01-01T00:00:00Z" };
const proposal = (r?: ResourceContractRef, actions = [READ]): AuthorityEntry[] => [
  { type: "mission_resource_access", resource: RESOURCE, actions, constraints: { vendors: ["acme"] }, ...(r ? { resource_contract: r } : {}) },
];

function refusal(fn: () => unknown): IntentError {
  try {
    fn();
  } catch (e) {
    if (e instanceof IntentError) return e;
    throw e;
  }
  throw new Error("expected an IntentError");
}

describe("the authorization server assembles the reference from configuration before approval (@spec resource-access#resource-contract, #249)", () => {
  let key: CryptoKey;
  let seq = 0;
  beforeAll(async () => {
    key = (await generateKeyPair("ES256")).privateKey;
  });
  const kernelWith = (resourceContracts: ResourceContractDeclarations) =>
    new MissionKernel({
      issuer: "https://as.test",
      policy: DERIVATION_POLICY as never,
      authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["ap-agent"], ["bob"]),
      statusKey: key,
      statusKid: "as-status",
      resourceContracts,
      now: () => NOW,
    });
  const approve = (kernel: MissionKernel, proposedAuthority?: AuthorityEntry[]) =>
    kernel.approve({
      intent: validateMissionIntent(JSON.stringify(TASK_INTENT)),
      ...(proposedAuthority ? { proposedAuthority } : {}),
      subject: { iss: "https://as.test", sub: "alice" },
      approver: { iss: "https://as.test", sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: `rc-apev-${seq++}`,
    });

  it("records the current contract's reference in an entry whose resource requires one when the proposal carries none, so the Approver approves it with it", () => {
    const kernel = kernelWith(REQUIRED);
    // The rendered set (kernel.derive) and the approved record agree.
    expect(kernel.derive(validateMissionIntent(JSON.stringify(TASK_INTENT)), proposal())[0]?.resource_contract).toEqual(V2);
    const record = approve(kernel, proposal());
    expect(record.authority_set[0]?.resource_contract).toEqual(V2);
    // Not required: nothing is attached.
    expect(approve(kernelWith(SUPERSEDED), proposal()).authority_set[0]).not.toHaveProperty("resource_contract");
  });

  it("authority_hash commits the reference: the record's anchor is computed over the set carrying it", () => {
    const record = approve(kernelWith(REQUIRED), proposal());
    expect(record.authority_hash).toBe(authorityHash("https://as.test", record.authority_set as unknown as JsonValue[]));
    const { resource_contract: _r, ...unpinned } = record.authority_set[0] as AuthorityEntry;
    expect(record.authority_hash).not.toBe(authorityHash("https://as.test", [unpinned as unknown as JsonValue]));
  });

  it.each([
    ["a superseded version", SUPERSEDED, V1],
    ["an unknown version", SUPERSEDED, ref("v9")],
    ["the current version under another digest", SUPERSEDED, { ...V2, digest: V1.digest }],
    ["a contract that does not define the entry's action", declarations([declared("v2", "current", {}, ["payments:invoice.list"])]), ref("v2", ["payments:invoice.list"])],
    ["any reference, where no contract is configured", ResourceContractDeclarations.NONE, V2],
  ])("refuses invalid_authorization_details at intake and at approval for a proposed %s, creating no Mission", (_label, contracts, proposed) => {
    const kernel = kernelWith(contracts as ResourceContractDeclarations);
    const before = kernel.allMissions().length;
    const atIntake = refusal(() => kernel.validateProposal(JSON.stringify(proposal(proposed as ResourceContractRef)), [RESOURCE]));
    expect(atIntake.code).toBe("invalid_authorization_details");
    expect(atIntake.message).toMatch(/resource_contract/);
    const atApproval = refusal(() => approve(kernel, proposal(proposed as ResourceContractRef)));
    expect(atApproval.code).toBe("invalid_authorization_details");
    expect(kernel.allMissions().length).toBe(before);
  });

  it("admits and records verbatim a proposed reference configuration names as current (control)", () => {
    const kernel = kernelWith(SUPERSEDED);
    expect(kernel.validateProposal(JSON.stringify(proposal(V2)), [RESOURCE])[0]?.resource_contract).toEqual(V2);
    expect(approve(kernel, proposal(V2)).authority_set[0]?.resource_contract).toEqual(V2);
  });
});

describe("the reference is preserved exactly by derivation and projection (@spec resource-access#subset step 4, #249)", () => {
  const intent = validateMissionIntent(JSON.stringify(TASK_INTENT));
  const approvedCeiling = (r: ResourceContractRef) => ({ policy_version: "t", ceiling: proposal(r, ACTIONS) });

  it("derivation carries a proposed reference under a policy ceiling that has none, and an approved ceiling's reference to an entry derived from it", () => {
    expect(deriveAuthoritySet(intent, DERIVATION_POLICY as never, proposal(V2))[0]?.resource_contract).toEqual(V2);
    expect(deriveAuthoritySet(intent, approvedCeiling(V1), proposal())[0]?.resource_contract).toEqual(V1);
    expect(deriveAuthoritySet(intent, approvedCeiling(V1), proposal(V1))[0]?.resource_contract).toEqual(V1);
  });

  it("derivation refuses a proposal replacing an approved entry's reference: replacing is never narrowing", () => {
    const e = refusal(() => deriveAuthoritySet(intent, approvedCeiling(V1), proposal(V2)));
    expect(e.code).toBe("invalid_authorization_details");
    expect(e.message).toMatch(/replacing a reference is never narrowing/);
  });

  it("the effective-set projection (refresh, code and introspection re-projection) keeps the reference, and yields nothing for a candidate that removes, replaces or adds one", () => {
    const effective = proposal(V1, [READ]);
    expect(projectThroughEffective(proposal(V1), effective)[0]?.resource_contract).toEqual(V1);
    expect(projectThroughEffective(proposal(), effective)).toEqual([]);
    expect(projectThroughEffective(proposal(V2), effective)).toEqual([]);
    expect(projectThroughEffective(proposal(V1), proposal(undefined, [READ]))).toEqual([]);
  });

  it("scope projection never drops it: an entry carrying a reference projects only to a value the mapping states is performed under exactly that contract", () => {
    const mapping = (extra: Record<string, unknown>) => ({
      audiences: {
        [RESOURCE]: {
          version: "1",
          mission_aware: true,
          mode: "scope_only" as const,
          scopes: {
            "invoices.read": {
              rights: { type: "mission_resource_access" as const, resource: RESOURCE, match: "exact" as const, actions: [READ] },
              mandatory_controls: { vendors: ["acme"] },
              ...extra,
            },
          },
        },
      },
    });
    const emit = (extra: Record<string, unknown>, r?: ResourceContractRef) =>
      projectScope({ mapping: mapping(extra), audiences: [RESOURCE], entries: proposal(r) });
    expect(emit({ resource_contract: V1 }, V1)).toMatchObject({ outcome: "emit", values: ["invoices.read"] });
    expect(emit({}, V1).outcome).toBe("refuse");
    expect(emit({ resource_contract: V2 }, V1).outcome).toBe("refuse");
    expect(emit({ requires_resource_contract: true }).outcome).toBe("refuse");
    expect(emit({}).outcome).toBe("emit");
  });
});

// @spec resource-access#resource-contract (#249, D875): template consent is a
// new approval, so its ceiling's references are assembled from configuration
// at the proposal, the consent page and the commit, and never substituted
// after the Approver saw the ceiling; a Dispatch from the template preserves
// them, preservation-only.
describe("template consent assembles the ceiling's references and Dispatch preserves them (@spec resource-access#resource-contract, #249, D875)", () => {
  const TISS = "https://as.test";
  const POLICIES = {
    rc: { version: "1", content_type: "application/json", content: JSON.stringify({ id: "rc", rule: "dispatch within the template ceiling" }) },
  };
  /** v2 current, required for the read, and a v3 configuration that supersedes v2. */
  const LATER = declarations(
    [declared("v1", "superseded", { retained_until: "2027-01-01T00:00:00Z" }), declared("v2", "superseded", { retained_until: "2027-01-01T00:00:00Z" }), declared("v3", "current")],
    [READ],
  );
  const CURRENT_V1 = declarations([declared("v1", "current")]);
  const RETIRED = declarations([declared("v1", "retired"), declared("v2", "current")]);
  let tkey: CryptoKey;
  beforeAll(async () => {
    tkey = (await generateKeyPair("ES256")).privateKey;
  });
  const kernelFor = (resourceContracts: ResourceContractDeclarations) => {
    const opts: ConstructorParameters<typeof MissionKernel>[0] = {
      issuer: TISS,
      policy: DERIVATION_POLICY as never,
      authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["ap-agent", "worker", "orchestrator"], ["bob"]),
      statusKey: tkey,
      statusKid: "as-status",
      resourceContracts,
      now: () => NOW,
    };
    return { opts, kernel: new MissionKernel(opts) };
  };
  let seq = 0;
  const body = (ceiling: AuthorityEntry[]) => ({
    template_version: "tmpl-rc-1",
    issuer: TISS,
    approver: { iss: TISS, sub: "bob" },
    ceiling,
    dispatch_policy: { id: "rc", version: "1" },
    dispatchers: ["orchestrator"],
    recipients: { subjects: [{ iss: TISS, sub: "alice" }], agents: ["worker"] },
    per_instance_lifetime_s: 3600,
    max_active: 3,
    rate_per_min: 5,
    review_cadence_s: 86400,
    expires_at: "2027-01-01T00:00:00Z",
  });
  const create = (kernel: MissionKernel, store: TemplateStore, ceiling: AuthorityEntry[], resourceContracts?: ResourceContractDeclarations) =>
    createTemplate(store, { ...body(ceiling), approval_event_id: `tmpl-rc-${seq++}` } as never, {
      ...kernel.authoritySourceOptions(),
      dispatchPolicies: POLICIES,
      ...(resourceContracts ? { resourceContracts } : {}),
    });
  const dispatch = (kernel: MissionKernel, store: TemplateStore, templateId: string, proposedAuthority?: AuthorityEntry[]) =>
    dispatchFromTemplate(kernel, store, {
      templateId,
      dispatchEventId: `dsp-rc-${seq++}`,
      dispatcher: "orchestrator",
      intent: validateMissionIntent(JSON.stringify(TASK_INTENT)),
      subject: { iss: TISS, sub: "alice" },
      policyVersion: DERIVATION_POLICY.policy_version,
      dispatchPolicies: POLICIES,
      ...(proposedAuthority ? { proposedAuthority } : {}),
    });

  it("records the current reference in a ceiling entry whose resource requires one, at a commit with no consent page", () => {
    const { kernel } = kernelFor(REQUIRED);
    const template = create(kernel, new TemplateStore(), proposal(), REQUIRED);
    expect(template.ceiling[0]?.resource_contract).toEqual(V2);
  });

  it("keeps a carried current reference, and refuses a carried reference configuration does not name as current, or one with no declarations", () => {
    const { kernel } = kernelFor(SUPERSEDED);
    expect(create(kernel, new TemplateStore(), proposal(V2), SUPERSEDED).ceiling[0]?.resource_contract).toEqual(V2);
    expect(() => create(kernel, new TemplateStore(), proposal(V1), SUPERSEDED)).toThrow(TemplateError);
    expect(() => create(kernel, new TemplateStore(), proposal(V2))).toThrow(TemplateError);
  });

  it("the consent page refuses a ceiling whose references configuration would now assemble differently, never substituting one", () => {
    const proposals = new TemplateConsentProposals(() => NOW.getTime());
    const pinned = pinDispatchPolicy(TISS, POLICIES, { id: "rc", version: "1" });
    const disclose = (ceiling: AuthorityEntry[], resourceContracts: ResourceContractDeclarations) =>
      templateConsentDisclosure(proposals.propose({ ...body(ceiling) } as never, pinned), POLICIES, {
        issuer: TISS,
        asyncDelegation: false,
        resourceContracts,
      });
    // As proposed: assembled under REQUIRED, rendered under REQUIRED.
    const assembled = templateContracts(proposal(), REQUIRED);
    expect(assembled[0]?.resource_contract).toEqual(V2);
    expect("disclosure" in disclose(assembled, REQUIRED)).toBe(true);
    // v2 superseded before the page renders: refused, not re-pinned to v3.
    const changed = disclose(assembled, LATER);
    expect("refusal" in changed && changed.refusal).toMatch(/configured contract references of the Template Ceiling changed/);
    // Proposed while nothing was required, rendered once a reference is: refused, never added.
    const added = disclose(proposal(), REQUIRED);
    expect("refusal" in added && added.refusal).toMatch(/configured contract references of the Template Ceiling changed/);
  });

  it("a Dispatch from a pinned ceiling carries the ceiling's reference without the Dispatcher restating it", () => {
    const { kernel } = kernelFor(SUPERSEDED);
    const store = new TemplateStore();
    const template = create(kernel, store, proposal(V2), SUPERSEDED);
    const { mission } = dispatch(kernel, store, template.id);
    expect(mission.authority_set[0]?.resource_contract).toEqual(V2);
  });

  it("a Dispatcher reference the template ceiling does not carry is refused, never added", () => {
    const { kernel } = kernelFor(SUPERSEDED);
    const store = new TemplateStore();
    const template = create(kernel, store, proposal(), SUPERSEDED);
    expect(() => dispatch(kernel, store, template.id, proposal(V2))).toThrow(DispatchError);
  });

  it("a superseded ceiling reference within its retention survives the Dispatch, and a retired one refuses", () => {
    const { opts, kernel } = kernelFor(CURRENT_V1);
    const store = new TemplateStore();
    const template = create(kernel, store, proposal(V1), CURRENT_V1);
    opts.resourceContracts = SUPERSEDED;
    expect(dispatch(kernel, store, template.id).mission.authority_set[0]?.resource_contract).toEqual(V1);
    opts.resourceContracts = RETIRED;
    expect(() => dispatch(kernel, store, template.id)).toThrow(IntentError);
  });
});

describe("the reference's shape is validated at intake (@spec resource-access#entry-validation, #249)", () => {
  it.each([
    ["an extra member", { ...V2, note: "x" }],
    ["a relative id", { ...V2, id: "contracts/payments" }],
    ["an empty version", { ...V2, version: "" }],
    ["a digest not in the integrity-anchor form", { ...V2, digest: "sha-512:abc" }],
    ["a missing digest", { id: CONTRACT, version: "v2" }],
    ["a string", "v2"],
  ])("refuses %s", (_label, bad) => {
    expect(validateMissionResourceAccessSchema({ ...proposal()[0], resource_contract: bad })).toMatch(/resource_contract/);
  });
});

describe("the Transaction Authorization Server resolves the Operation Profile version from the reference, never from type (@spec txn-authorization#resource-challenge, #249)", () => {
  const ISS = RESOURCE;
  const operation = (r?: ResourceContractRef) =>
    ({ type: "mission_resource_access", resource: ISS, actions: [READ], ...(r ? { resource_contract: r } : {}) }) as unknown as JsonValue;

  it("admits an entry without a reference under the resource's current version, records it, and completes under it after a later version supersedes it", () => {
    const registry = new OperationProfileRegistry(ResourceContractDeclarations.NONE).register(ISS, missionResourceAccessProfile("v12"));
    const admitted = registry.admit(ISS, operation(), NOW);
    expect(admitted).toMatchObject({ ok: true, version: "v12", operation: { action: READ } });
    // Same `type`, a new version: new admissions take it, the recorded one still completes.
    registry.supersede(ISS, "v12");
    registry.register(ISS, missionResourceAccessProfile("v13"));
    expect(registry.admit(ISS, operation(), NOW)).toMatchObject({ ok: true, version: "v13" });
    expect(registry.complete(ISS, "v12", operation(), NOW)).toMatchObject({ ok: true, version: "v12" });
    expect(registry.complete(ISS, "v11", operation(), NOW)).toMatchObject({ ok: false });
  });

  it("admits an entry carrying a reference under the version its contract names, refuses one that does not resolve at admission, and refuses completion once it stops resolving", () => {
    const contracts = declarations([
      declared("v1", "superseded", { retained_until: "2026-11-01T00:00:00Z" }, ACTIONS, "v12"),
      declared("v2", "current", {}, ACTIONS, "v13"),
    ]);
    const registry = new OperationProfileRegistry(contracts)
      .register(ISS, missionResourceAccessProfile("v12"))
      .register(ISS, missionResourceAccessProfile("v13"));
    const v1 = ref("v1", ACTIONS, "v12");
    const v2 = ref("v2", ACTIONS, "v13");
    // The current version is v13, but a v1 reference names v12, superseded and retained.
    expect(registry.admit(ISS, operation(v1), NOW)).toMatchObject({ ok: true, version: "v12" });
    expect(registry.admit(ISS, operation(v2), NOW)).toMatchObject({ ok: true, version: "v13" });
    // Unknown, or a changed digest: refused at admission.
    expect(registry.admit(ISS, operation(ref("v9", ACTIONS, "v13")), NOW)).toMatchObject({ ok: false });
    expect(registry.admit(ISS, operation({ ...v1, digest: v2.digest }), NOW)).toMatchObject({ ok: false });
    // Completion re-resolves: past v1's retention the workflow admitted under it is refused.
    expect(registry.complete(ISS, "v12", operation(v1), NOW)).toMatchObject({ ok: true });
    expect(registry.complete(ISS, "v12", operation(v1), new Date("2026-11-01T00:00:01Z"))).toMatchObject({ ok: false });
  });

  it("the shipped payments contract names the payments profile version the deployment registers", () => {
    const [d] = RESOURCE_CONTRACTS.declarations;
    const current = d?.versions.find((v) => v.state === "current");
    const registry = new OperationProfileRegistry().register(ISS, missionResourceAccessProfile(current?.operation_profile));
    const shipped = { id: d?.id as string, version: current?.version as string, digest: current?.digest as string };
    expect(registry.admit(ISS, operation(shipped), NOW)).toMatchObject({ ok: true, version: current?.operation_profile });
  });
});

// ---------------------------------------------------------------------------
// PAR intake, end to end over the shipped configuration.
// ---------------------------------------------------------------------------

const PORT = 14249;
const ISSUER = `http://localhost:${PORT}`;
let as: BuiltAs;
let asServer: Server;
let agentKey: CryptoKey;

async function pushPar(params: Record<string, string>): Promise<Response> {
  const assertion = await new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
    .setIssuer("ap-agent")
    .setSubject("ap-agent")
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(agentKey);
  const challenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode("resource-contract-verifier-0123456789-0123456789")),
  ).toString("base64url");
  return fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: "http://localhost:9999/cb",
      resource: RESOURCE,
      code_challenge: challenge,
      code_challenge_method: "S256",
      login_hint: "alice",
      ...params,
      client_assertion: assertion,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
}

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    approvalSessions: new ApprovalSessionStore(),
  });
  asServer = as.provider.listen(PORT);
  agentKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
});

afterAll(() => {
  asServer?.close();
});

describe("PAR intake validates a proposed reference against the shipped configuration (@spec resource-access#resource-contract, #249)", () => {
  const [shipped] = RESOURCE_CONTRACTS.declarations;
  const current = shipped?.versions.find((v) => v.state === "current");
  const SHIPPED: ResourceContractRef = { id: shipped?.id as string, version: current?.version as string, digest: current?.digest as string };
  const par = (r: unknown) =>
    pushPar({
      mission_intent: JSON.stringify({ intent: TASK_INTENT }),
      authorization_details: JSON.stringify([{ ...proposal()[0], resource_contract: r }]),
    });

  it("admits a proposal carrying the configured current reference", async () => {
    const res = await par(SHIPPED);
    expect(res.status, await res.clone().text()).toBe(201);
    expect(((await res.json()) as { request_uri?: string }).request_uri).toBeDefined();
  });

  it("refuses an unconfigured or malformed reference with invalid_authorization_details before any interaction, creating no Mission", async () => {
    for (const bad of [{ ...SHIPPED, version: "1999-01-01" }, { ...SHIPPED, digest: V1.digest }, { ...SHIPPED, extra: 1 }]) {
      const before = as.kernel.allMissions().length;
      const res = await par(bad);
      const body = (await res.json()) as { error: string; error_description?: string; request_uri?: string };
      expect(res.status, JSON.stringify(bad)).toBe(400);
      expect(body.error).toBe("invalid_authorization_details");
      expect(body.error_description).toMatch(/resource_contract/);
      expect(body.request_uri).toBeUndefined();
      expect(as.kernel.allMissions().length).toBe(before);
    }
  });

  // #249 (D712, D865): "a contract its configuration names as current for the
  // entry's `resource`": the shipped current reference, proposed on a resource
  // the configuration names no contract current for, is refused.
  it("refuses the configured current reference on a resource the configuration does not name it current for", async () => {
    const OTHER = "https://ledger.example/mcp";
    const before = as.kernel.allMissions().length;
    const res = await pushPar({
      mission_intent: JSON.stringify({ intent: { ...TASK_INTENT, target_resources: [RESOURCE, OTHER] } }),
      authorization_details: JSON.stringify([{ ...proposal()[0], resource: OTHER, resource_contract: SHIPPED }]),
    });
    const body = (await res.json()) as { error: string; error_description?: string; request_uri?: string };
    expect(res.status).toBe(400);
    expect(body.error).toBe("invalid_authorization_details");
    expect(body.error_description).toMatch(/current for the entry's resource/);
    expect(body.request_uri).toBeUndefined();
    expect(as.kernel.allMissions().length).toBe(before);
  });
});

// @spec resource-access#resource-contract (#1751, D875): "Every derivation,
// narrowing, and delegation preserves it exactly". A child entry carries the
// reference of the parent entry that authorizes the whole child entry, without
// restating it; a superseded reference survives while supported.
describe("a child Mission preserves its parent entry's reference (@spec resource-access#resource-contract, #1751, D875)", () => {
  const CHILD = "subagent-contract";
  const CURRENT_V1 = declarations([declared("v1", "current")]);
  /** v1 retired, v2 current: a v1 reference is no longer supported. */
  const RETIRED = declarations([declared("v1", "retired"), declared("v2", "current")]);
  let key: CryptoKey;
  beforeAll(async () => {
    key = (await generateKeyPair("ES256")).privateKey;
  });
  /** A kernel whose configuration a test may change between the parent's approval and the child's creation. */
  const kernelFor = (resourceContracts: ResourceContractDeclarations) => {
    const opts: ConstructorParameters<typeof MissionKernel>[0] = {
      issuer: "https://as.test",
      policy: DERIVATION_POLICY as never,
      authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["ap-agent"], ["bob"]),
      statusKey: key,
      statusKid: "as-status",
      resourceContracts,
      now: () => NOW,
      actorProfiles: aiAgents(CHILD),
    };
    return { opts, kernel: new MissionKernel(opts) };
  };
  let seq = 0;
  const approveParent = (kernel: MissionKernel, r?: ResourceContractRef) =>
    kernel.approve({
      intent: validateMissionIntent(JSON.stringify(TASK_INTENT)),
      proposedAuthority: proposal(r),
      subject: { iss: "https://as.test", sub: "alice" },
      approver: { iss: "https://as.test", sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: `rc-child-apev-${seq++}`,
    });
  const createChild = (kernel: MissionKernel, parentId: string, r?: ResourceContractRef) =>
    createChildMission(kernel, {
      parentId,
      intent: validateMissionIntent(JSON.stringify({ ...TASK_INTENT, goal: "Read one Acme invoice" })),
      proposedAuthority: proposal(r),
      childActor: { sub: CHILD, sub_profile: "ai_agent" },
    });

  it("a child of a parent entry carrying a reference carries the same reference without restating it, under authority_hash", () => {
    const { kernel } = kernelFor(SUPERSEDED);
    const parent = approveParent(kernel, V2);
    expect(parent.authority_set[0]?.resource_contract).toEqual(V2);
    const { child } = createChild(kernel, parent.id);
    expect(child.authority_set[0]?.resource_contract).toEqual(V2);
    expect(child.authority_hash).toBe(authorityHash(child.issuer, child.authority_set as never));
  });

  it("a superseded reference within its declared retention survives the derivation", () => {
    const { opts, kernel } = kernelFor(CURRENT_V1);
    const parent = approveParent(kernel, V1);
    // The deployment supersedes v1 after the parent's approval.
    opts.resourceContracts = SUPERSEDED;
    const { child } = createChild(kernel, parent.id);
    expect(child.authority_set[0]?.resource_contract).toEqual(V1);
  });

  it("a reference no longer supported refuses the child at creation, invalid_authorization_details", () => {
    const { opts, kernel } = kernelFor(CURRENT_V1);
    const parent = approveParent(kernel, V1);
    opts.resourceContracts = RETIRED;
    const refused = (() => {
      try {
        createChild(kernel, parent.id);
      } catch (e) {
        return e;
      }
      return undefined;
    })();
    expect(refused).toBeInstanceOf(IntentError);
    expect((refused as IntentError).code).toBe("invalid_authorization_details");
  });

  it("a conflicting proposed reference is refused by the strict-subset proof, never replaced", () => {
    const { kernel } = kernelFor(SUPERSEDED);
    const parent = approveParent(kernel, V2);
    expect(() => createChild(kernel, parent.id, V1)).toThrow(ChildDelegationError);
  });

  it("a child of a parent entry without a reference carries none", () => {
    const { kernel } = kernelFor(SUPERSEDED);
    const parent = approveParent(kernel);
    const { child } = createChild(kernel, parent.id);
    expect(child.authority_set[0]?.resource_contract).toBeUndefined();
  });

  describe("inheritResourceContract selects only a parent entry that authorizes the whole child entry", () => {
    const LIST = "payments:invoice.list";
    const entry = (actions: string[], r?: ResourceContractRef): AuthorityEntry => ({
      type: "mission_resource_access",
      resource: RESOURCE,
      actions,
      constraints: { vendors: ["acme"] },
      ...(r ? { resource_contract: r } : {}),
    });

    it("takes the reference of the one parent entry covering the child entry, never another resource entry's", () => {
      const parents = [entry([READ], V1), entry([LIST], V2)];
      expect(inheritResourceContract([entry([READ])], parents)[0]?.resource_contract).toEqual(V1);
      expect(inheritResourceContract([entry([LIST])], parents)[0]?.resource_contract).toEqual(V2);
    });

    it("combines nothing: a child entry only two parent entries together cover gains no reference", () => {
      expect(inheritResourceContract([entry([READ, LIST])], [entry([READ], V2), entry([LIST], V2)])[0]?.resource_contract).toBeUndefined();
    });

    it("chooses nothing when the covering parent entries disagree, and leaves a proposed reference as proposed", () => {
      expect(inheritResourceContract([entry([READ])], [entry([READ], V1), entry([READ, LIST], V2)])[0]?.resource_contract).toBeUndefined();
      expect(inheritResourceContract([entry([READ])], [entry([READ]), entry([READ], V2)])[0]?.resource_contract).toBeUndefined();
      expect(inheritResourceContract([entry([READ], V1)], [entry([READ], V2)])[0]?.resource_contract).toEqual(V1);
    });
  });
});
