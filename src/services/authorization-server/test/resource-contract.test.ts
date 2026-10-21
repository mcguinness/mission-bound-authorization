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
  createTemplate,
  deriveAuthoritySet,
  IntentError,
  MissionKernel,
  missionResourceAccessProfile,
  OperationProfileRegistry,
  projectThroughEffective,
  TemplateStore,
  validateMissionIntent,
  validateMissionResourceAccessSchema,
} from "../src/index.js";
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

describe("a surface that does not implement the reference refuses it and never drops it (@spec resource-access#resource-contract, #249)", () => {
  it("template consent refuses a ceiling entry carrying resource_contract, naming it", () => {
    expect(() =>
      createTemplate(
        new TemplateStore(),
        {
          template_version: "tmpl-rc-1",
          issuer: "https://as.test",
          approver: { iss: "https://as.test", sub: "bob" },
          ceiling: proposal(V2),
          dispatch_policy: { id: "rc", version: "1" },
          dispatchers: ["orchestrator"],
          recipients: { subjects: [{ iss: "https://as.test", sub: "alice" }], agents: ["worker"] },
          per_instance_lifetime_s: 3600,
          max_active: 1,
          rate_per_min: 1,
          review_cadence_s: 86400,
          approval_event_id: "tmpl-rc",
          expires_at: "2027-01-01T00:00:00Z",
        } as never,
        {} as never,
      ),
    ).toThrow(/ceiling\[0\] carries resource_contract, which template consent does not assemble/);
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
});
