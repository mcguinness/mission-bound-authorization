/**
 * @spec runtime#boundary-identifier, runtime#boundary-identifier-change,
 * runtime-oauth#boundary-audience, runtime-evidence#decision-evidence-integrity
 * (#853, D487): the payments resource end to end. Each PEP establishes its
 * enforcement boundary from the declared statement, never from `aud`; the
 * server checks `aud` against it by membership under trusted, issuer- and
 * profile-scoped aliases; every decision input, binding and record carries
 * the boundary byte for byte; and a declared change of identifier
 * invalidates old permits while records made under the old identifier keep
 * their bytes and verify as historical evidence.
 *
 * FGA-independent: an allowing stub stands in for the Resource-policy
 * relationship check, and a counting one proves where it is never reached.
 */

import { randomUUID } from "node:crypto";
import { canonicalize, type JsonValue } from "@mission/core";
import {
  type BoundaryEvidenceKey,
  buildBoundaryEvidenceKeyResolver,
  createDecisionChannel,
  createEphemeralDecisionPoint,
  DECISION_EVIDENCE_MEDIA_TYPE,
  type DecisionOptions,
  decisionCacheKey,
  EnforcementBoundaryContext,
  type EnforcementBoundaries,
  type EvaluationRequest,
  EXECUTION_EVIDENCE_MEDIA_TYPE,
  type Fga,
  isDecisionChannelRefusal,
  loadRuntimePosture,
  type MissionView,
  REFUSAL_RECORD_MEDIA_TYPE,
  RUNTIME_POSTURE,
  relationForAction,
  type RuntimePosture,
  stalenessBound,
  verifyEvidenceEnvelope,
} from "@mission/pdp";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
  type ActionMapping,
  BOUNDARY_CUTOVER_ERROR,
  BOUNDARY_UNRESOLVABLE,
  boundaryEvidenceAuthorization,
  CANONICAL_RESOURCE,
  createEphemeralEvidenceKeys,
  createMediatedClient,
  credentialAuthorityFrom,
  type DecisionEvidence,
  EvidenceStore,
  type ExecutionEvidence,
  McpPaymentsServer,
  openEphemeralWriteReservationStore,
  PaymentsStore,
  Pep,
  type RefusalRecord,
  TOOL_ACTIONS,
  TOOLS,
  type TokenFacts,
  TokenAudienceError,
} from "../src/index.js";

const ISSUER = "https://as.test";
const OTHER_ISSUER = "https://other-as.test";
const AS_TXN_ISSUER = "https://tas.test";
const EMITTER = CANONICAL_RESOURCE;
const LEDGER = "https://ledger.example/mcp";
const ALIAS = "payments-api";
const LEDGER_ALIAS = "ledger-api";
const LEGACY = "urn:legacy:payments";
const ADMIN = `${CANONICAL_RESOURCE}/admin`;
const ALL_ACTIONS = [...new Set(TOOLS.map((t) => t.action))];
const MODEL = "model-853";

const PEP_KEYS = [
  { kid: "ephemeral-pdp", emitter: EMITTER, role: "pdp" as const },
  { kid: "ephemeral-pep", emitter: EMITTER, role: "pep" as const },
  { kid: "ephemeral-executor", emitter: EMITTER, role: "executor" as const },
];

/** Two boundaries, CANONICAL_RESOURCE served by two PEP locations and LEDGER by a third, with aliases scoped per issuer and profile. */
const TWO_BOUNDARIES: EnforcementBoundaries = {
  versions: [
    {
      version: "v1",
      effective_at: "1970-01-01T00:00:00Z",
      boundaries: [
        {
          boundary: CANONICAL_RESOURCE,
          pep_locations: ["mcp-payments-pep", "mcp-payments-pep-2"],
          audience_aliases: [
            { issuer: ISSUER, token_profile: "at+jwt", alias: ALIAS },
            { issuer: ISSUER, token_profile: "at+jwt", alias: "urn:payments" },
            { issuer: OTHER_ISSUER, token_profile: "at+jwt", alias: "other-issuer-alias" },
            { issuer: ISSUER, token_profile: "aat+jwt", alias: "root-only-alias" },
          ],
          evidence_keys: PEP_KEYS,
        },
        {
          boundary: LEDGER,
          pep_locations: ["ledger-pep"],
          audience_aliases: [{ issuer: ISSUER, token_profile: "at+jwt", alias: LEDGER_ALIAS }],
          // The PDP may sign for the ledger; this PEP's own keys may not.
          evidence_keys: [PEP_KEYS[0] as (typeof PEP_KEYS)[number]],
        },
      ],
    },
  ],
};

const CUTOVER_MS = Date.parse("2026-06-01T00:00:00Z");

/** A declared change: the legacy logical identifier (v1) to the protected resource's identifier (v2), the old value kept as an alias. */
const CHANGE: EnforcementBoundaries = {
  versions: [
    {
      version: "payments-boundary-v1",
      effective_at: "1970-01-01T00:00:00Z",
      boundaries: [{ boundary: LEGACY, pep_locations: ["mcp-payments-pep"], evidence_keys: PEP_KEYS }],
    },
    {
      version: "payments-boundary-v2",
      effective_at: "2026-06-01T00:00:00Z",
      boundaries: [
        {
          boundary: CANONICAL_RESOURCE,
          pep_locations: ["mcp-payments-pep"],
          audience_aliases: [{ issuer: ISSUER, token_profile: "at+jwt", alias: LEGACY }],
          evidence_keys: PEP_KEYS,
        },
      ],
      replaces: [{ boundary: CANONICAL_RESOURCE, previous_version: "payments-boundary-v1", previous_boundary: LEGACY }],
    },
  ],
};

function statementWith(boundaries: EnforcementBoundaries): RuntimePosture {
  return loadRuntimePosture({
    ...RUNTIME_POSTURE,
    mediated_scope: {
      ...RUNTIME_POSTURE.mediated_scope,
      resources: [CANONICAL_RESOURCE, LEDGER],
      pep_locations: [...RUNTIME_POSTURE.mediated_scope.pep_locations, "mcp-payments-pep-2", "ledger-pep"],
    },
    enforcement_boundaries: boundaries,
  });
}

const viewOf = (resource = CANONICAL_RESOURCE): MissionView => ({
  id: "msn_853",
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:m853",
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
  authority_set: [{ type: "mission_resource_access", resource, actions: ALL_ACTIONS }],
});

let asKey: CryptoKey;
let asJwk: Record<string, unknown>;
let txnKey: CryptoKey;
let txnJwk: Record<string, unknown>;

beforeAll(async () => {
  const kp = await generateKeyPair("ES256", { extractable: true });
  asKey = kp.privateKey;
  asJwk = { ...(await exportJWK(kp.publicKey)), kid: "as-token", alg: "ES256" };
  const txn = await generateKeyPair("ES256", { extractable: true });
  txnKey = txn.privateKey;
  txnJwk = { ...(await exportJWK(txn.publicKey)), kid: "as-txn", alg: "ES256" };
});

/** A Mission access token; `aud: undefined` removes the claim. */
async function mint(aud: unknown, credentialResource = CANONICAL_RESOURCE): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = {
    iss: ISSUER,
    aud,
    sub: "alice",
    client_id: "ap-agent",
    jti: randomUUID(),
    iat: now,
    exp: now + 300,
    cnf: { jkt: "jkt-853" },
    mission: { id: "msn_853", issuer: ISSUER },
    authorization_details: [{ type: "mission_resource_access", resource: credentialResource, actions: ALL_ACTIONS }],
  };
  if (aud === undefined) delete payload.aud;
  return new SignJWT(payload).setProtectedHeader({ alg: "ES256", kid: "as-token", typ: "at+jwt" }).sign(asKey);
}

const factsFor = (credentialResource = CANONICAL_RESOURCE): TokenFacts => ({
  sub: "alice",
  iss: ISSUER,
  clientId: "ap-agent",
  cnfJkt: "jkt-853",
  mission: { id: "msn_853", issuer: ISSUER },
  credentialAuthority: credentialAuthorityFrom([{ type: "mission_resource_access", resource: credentialResource, actions: ALL_ACTIONS }]),
});

/** One decision point and key bundle over `statement`, shared by every PEP a test builds on it. */
function deployment(statement: RuntimePosture, clock: () => Date = () => new Date()) {
  const authority = new EnforcementBoundaryContext(statement, "mcp-payments-pep", clock);
  const point = createEphemeralDecisionPoint({
    emitterId: EMITTER,
    audience: CANONICAL_RESOURCE,
    resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
    authorizesAudience: (audience) =>
      authority.authorizesEvidence({ audience, kid: "ephemeral-pdp", emitter: EMITTER, role: "pdp" }, "current", clock()),
  });
  const keys = createEphemeralEvidenceKeys({ decisionPoint: point });
  const published: BoundaryEvidenceKey[] = keys.verification.flatMap((k) =>
    k.role === "receipt_issuer" ? [] : [{ kid: k.kid, publicKey: k.publicKey, emitterId: k.emitterId, role: k.role }],
  );
  const declaration = statement.enforcement_boundaries as EnforcementBoundaries;
  const resolver = buildBoundaryEvidenceKeyResolver(declaration, published);
  return { statement, clock, point, keys, resolver, declaration };
}

interface Built {
  server: McpPaymentsServer;
  pep: Pep;
  evidence: EvidenceStore;
  decided: EvaluationRequest[];
  options: DecisionOptions[];
  fgaCalls: () => number;
}

function buildPep(
  d: ReturnType<typeof deployment>,
  pepLocation: string,
  opts: { view?: MissionView; profile?: Record<string, ActionMapping> } = {},
): Built {
  const view = opts.view ?? viewOf();
  const boundary = new EnforcementBoundaryContext(d.statement, pepLocation, d.clock);
  const evidence = new EvidenceStore(d.keys.signing, d.resolver, undefined, boundaryEvidenceAuthorization(boundary, d.clock));
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
  );
  let calls = 0;
  const fga = {
    checkWithContext: async () => {
      calls += 1;
      return true;
    },
  } as unknown as Fga;
  const loadView = (ref: { id: string; issuer: string }) =>
    ref.id === view.id && ref.issuer === view.issuer
      ? { view, observation: { state: view.state, version: view.version, mode: "fresh", freshness_at: d.clock().toISOString() } }
      : undefined;
  const decided: EvaluationRequest[] = [];
  const options: DecisionOptions[] = [];
  const pep = new Pep({
    payments,
    evidence,
    fga,
    modelId: MODEL,
    loadView,
    instanceEpoch: `epoch-${pepLocation}`,
    now: d.clock,
    boundary,
    ...(opts.profile ? { operationProfile: () => opts.profile as Record<string, ActionMapping> } : {}),
    decide: (req, o) => {
      decided.push(req);
      options.push(o);
      return d.keys.decide(req, o);
    },
    claims: d.keys.claims,
  });
  const server = new McpPaymentsServer({
    pep,
    payments,
    loadView,
    issuer: ISSUER,
    jwks: { keys: [asJwk as never] },
    txnTokenJwks: { keys: [txnJwk as never] },
    asIssuer: AS_TXN_ISSUER,
    keyRoles: { accessToken: ["as-token"], attenuationRoot: [], transactionToken: ["as-txn"] },
    writeReservations: openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" }),
  });
  return { server, pep, evidence, decided, options, fgaCalls: () => calls };
}

async function call(x: Built, tool: string, args: Record<string, unknown>, token: string) {
  const { client } = await createMediatedClient(x.server);
  try {
    return await client.callTool(tool, args, token);
  } finally {
    await client.close();
  }
}

const decisions = (x: Built) =>
  x.evidence.all().filter((e): e is DecisionEvidence => e.kind === "decision").map((e) => e.content);
const refusals = (x: Built) =>
  x.evidence.all().filter((e): e is RefusalRecord => e.kind === "refusal").map((e) => e.content);
const executions = (x: Built) =>
  x.evidence.all().filter((e): e is ExecutionEvidence => e.kind === "execution").map((e) => e.content);

describe("each PEP establishes its boundary from configuration, and every consumer carries it byte for byte (@spec runtime#boundary-identifier, runtime-oauth#boundary-audience, #853)", () => {
  it("two PEPs at one boundary produce byte-identical boundary values for direct, aliased, permuted and multi-recipient audiences", async () => {
    const d = deployment(statementWith(TWO_BOUNDARIES));
    const peps = [buildPep(d, "mcp-payments-pep"), buildPep(d, "mcp-payments-pep-2")];
    const auds: unknown[] = [
      CANONICAL_RESOURCE,
      ALIAS,
      [LEDGER_ALIAS, ALIAS],
      [ALIAS, CANONICAL_RESOURCE, ALIAS],
      ["urn:payments", LEDGER_ALIAS],
      [LEDGER, "https://unrelated.example", "urn:payments"],
    ];
    for (const x of peps) {
      for (const aud of auds) {
        const res = await call(x, "get_invoice", { invoice_id: "inv-1" }, await mint(aud));
        expect(res.ok, JSON.stringify(aud)).toBe(true);
      }
      // A pre-decision refusal under an aliased token: no permit, same boundary.
      const missing = await call(x, "get_invoice", { invoice_id: "inv-missing" }, await mint([LEDGER_ALIAS, ALIAS]));
      expect(missing).toMatchObject({ ok: false });
    }
    // Every decision request's `resource`, its boundary included, is the same bytes at both PEPs for every audience form.
    const resources = peps.flatMap((x) => x.decided.map((r) => JSON.stringify(r.resource)));
    expect(resources).toHaveLength(auds.length * 2);
    expect(new Set(resources).size).toBe(1);
    expect(peps.flatMap((x) => x.decided.map((r) => r.resource.properties.audience))).toEqual(
      Array.from({ length: auds.length * 2 }, () => CANONICAL_RESOURCE),
    );
    for (const x of peps) {
      expect(decisions(x).map((r) => r.audience)).toEqual(auds.map(() => CANONICAL_RESOURCE));
      expect(refusals(x).map((r) => r.audience)).toEqual([CANONICAL_RESOURCE]);
    }
  });

  it("a token naming several recipients is evaluated at each PEP's own boundary, never at whichever member comes first", async () => {
    const d = deployment(statementWith(TWO_BOUNDARIES));
    const payments = buildPep(d, "mcp-payments-pep");
    const ledger = buildPep(d, "ledger-pep");
    for (const aud of [[LEDGER_ALIAS, ALIAS], [ALIAS, LEDGER_ALIAS]]) {
      expect((await call(payments, "get_invoice", { invoice_id: "inv-1" }, await mint(aud))).ok).toBe(true);
      expect((await call(ledger, "get_invoice", { invoice_id: "inv-1" }, await mint(aud))).ok).toBe(true);
    }
    expect(payments.decided.map((r) => r.resource.properties.audience)).toEqual([CANONICAL_RESOURCE, CANONICAL_RESOURCE]);
    expect(ledger.decided.map((r) => r.resource.properties.audience)).toEqual([LEDGER, LEDGER]);
    expect(decisions(ledger).map((r) => r.audience)).toEqual([LEDGER, LEDGER]);
    // The ledger PEP refuses a token that names only the payments boundary.
    const refused = await call(ledger, "get_invoice", { invoice_id: "inv-1" }, await mint(ALIAS));
    expect(refused).toMatchObject({ ok: false, denial_reason: "invalid_credential" });
    expect(ledger.decided).toHaveLength(2);
  });

  it("refuses an absent, malformed, nonmatching, issuer-confused or profile-confused aud at token validation, before any PDP decision and with no record", async () => {
    const d = deployment(statementWith(TWO_BOUNDARIES));
    const x = buildPep(d, "mcp-payments-pep");
    const cases: [unknown, string][] = [
      [undefined, "audience_absent"],
      [[], "audience_malformed"],
      [[""], "audience_malformed"],
      [[ALIAS, 7], "audience_malformed"],
      [42, "audience_malformed"],
      [LEDGER, "audience_mismatch"],
      [[LEDGER_ALIAS], "audience_mismatch"],
      [`${CANONICAL_RESOURCE}/`, "audience_mismatch"],
      ["other-issuer-alias", "audience_mismatch"],
      ["root-only-alias", "audience_mismatch"],
    ];
    for (const [aud, reason] of cases) {
      const token = await mint(aud);
      await expect(x.server.validateMissionToken(token), JSON.stringify(aud)).rejects.toThrow(new TokenAudienceError(reason));
      expect(await call(x, "get_invoice", { invoice_id: "inv-1" }, token), JSON.stringify(aud)).toMatchObject({
        ok: false,
        denial_reason: "invalid_credential",
      });
    }
    expect(x.decided).toHaveLength(0);
    expect(x.evidence.all()).toHaveLength(0);
  });

  it("refuses every token of an issuer and profile whose aliases map one value to two boundaries, the directly named one included", async () => {
    const ambiguous = structuredClone(TWO_BOUNDARIES) as unknown as {
      versions: { boundaries: { audience_aliases: { issuer: string; token_profile: string; alias: string }[] }[] }[];
    };
    ambiguous.versions[0]?.boundaries[1]?.audience_aliases.push({ issuer: ISSUER, token_profile: "at+jwt", alias: ALIAS });
    const d = deployment(statementWith(ambiguous as unknown as EnforcementBoundaries));
    const x = buildPep(d, "mcp-payments-pep");
    for (const aud of [CANONICAL_RESOURCE, ALIAS, "urn:payments", [CANONICAL_RESOURCE, LEDGER_ALIAS]]) {
      const token = await mint(aud);
      await expect(x.server.validateMissionToken(token), JSON.stringify(aud)).rejects.toThrow(new TokenAudienceError("alias_ambiguous"));
      expect((await call(x, "get_invoice", { invoice_id: "inv-1" }, token)).ok).toBe(false);
    }
    expect(x.decided).toHaveLength(0);
    expect(x.evidence.all()).toHaveLength(0);
  });

  it("keeps the transaction token's stricter single-audience rule, and its aliases scoped to its own profile", async () => {
    const d = deployment(statementWith(TWO_BOUNDARIES));
    const x = buildPep(d, "mcp-payments-pep");
    const txnToken = async (aud: unknown) => {
      const now = Math.floor(Date.now() / 1000);
      return new SignJWT({
        iss: AS_TXN_ISSUER,
        aud,
        sub: "alice",
        client_id: "ap-agent",
        jti: randomUUID(),
        iat: now,
        exp: now + 60,
        txn: "txn-853",
        parameter_digest: "sha-256:p853",
        cnf: { jkt: "jkt-853" },
        mission: { id: "msn_853", issuer: ISSUER },
        authorization_details: [],
      })
        .setProtectedHeader({ alg: "ES256", kid: "as-txn", typ: "mission-txn-token+jwt" })
        .sign(txnKey);
    };
    const pop = { proof: "not-a-proof", htu: CANONICAL_RESOURCE, htm: "POST" };
    for (const aud of [[CANONICAL_RESOURCE], [CANONICAL_RESOURCE, CANONICAL_RESOURCE], ALIAS, LEDGER]) {
      expect(await x.server.verifyTransactionCredential(await txnToken(aud), pop), JSON.stringify(aud)).toEqual({
        ok: false,
        refusal_reason: "txn_invalid",
      });
    }
    // A singleton naming the boundary passes the audience gate and meets the next check.
    expect(await x.server.verifyTransactionCredential(await txnToken(CANONICAL_RESOURCE), pop)).toEqual({
      ok: false,
      refusal_reason: "txn_cnf_mismatch",
    });
  });

  it("carries the boundary, never the aud value or alias, in all three evidence forms, and signs each only under a key authorized for it", async () => {
    const d = deployment(statementWith(TWO_BOUNDARIES));
    const x = buildPep(d, "mcp-payments-pep");
    const token = await mint([LEDGER_ALIAS, ALIAS]);
    const facts = await x.server.validateMissionToken(token);
    // Refusal Record, before any decision.
    expect(await x.pep.enforce("get_invoice", { invoice_id: "inv-missing" }, facts)).toMatchObject({ permitted: false });
    // Decision Evidence, and Execution Evidence for a disposition of the permit.
    const permitted = await x.pep.enforce("hold_transfer", { invoice_id: "inv-1" }, facts);
    expect(permitted.permitted).toBe(true);
    expect(permitted.attempt?.audience).toBe(CANONICAL_RESOURCE);
    await x.pep.suppressExecution(permitted.attempt as NonNullable<typeof permitted.attempt>, "parameter_mismatch");
    const records = [
      [refusals(x), REFUSAL_RECORD_MEDIA_TYPE],
      [decisions(x), DECISION_EVIDENCE_MEDIA_TYPE],
      [executions(x), EXECUTION_EVIDENCE_MEDIA_TYPE],
    ] as const;
    for (const [list, cty] of records) {
      expect(list.map((r) => r.audience), cty).toEqual([CANONICAL_RESOURCE]);
      for (const r of list) expect(await verifyEvidenceEnvelope(r, cty, d.resolver), cty).toEqual({ valid: true });
    }
    // This PEP's key is not authorized for the ledger boundary: nothing is signed or retained.
    const before = x.evidence.all().length;
    await expect(
      x.evidence.recordRefusal(EMITTER, "pep", {
        missionId: "msn_853",
        audience: LEDGER,
        action: { name: "payments:invoice.read" },
        denial_reason: "target_unresolvable",
      }),
    ).rejects.toThrow(/not authorized/);
    expect(x.evidence.all()).toHaveLength(before);
  });

  it("keeps two operation targets under one boundary independently matched, and never lets an alias make an entry match", async () => {
    const d = deployment(statementWith(TWO_BOUNDARIES));
    const profile = { ...TOOL_ACTIONS, lookup_vendor: { ...(TOOL_ACTIONS.lookup_vendor as ActionMapping), target: Object.freeze({ service: ADMIN }) } };
    const x = buildPep(d, "mcp-payments-pep", { profile });
    const facts = factsFor();
    const read = await x.pep.enforce("get_invoice", { invoice_id: "inv-1" }, { ...facts, credentialAuthority: credentialAuthorityFrom([
      { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ALL_ACTIONS },
      { type: "mission_resource_access", resource: ADMIN, actions: ALL_ACTIONS },
    ]) });
    const admin = await x.pep.enforce("lookup_vendor", { vendor_id: "acme" }, { ...facts, credentialAuthority: credentialAuthorityFrom([
      { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ALL_ACTIONS },
      { type: "mission_resource_access", resource: ADMIN, actions: ALL_ACTIONS },
    ]) });
    expect(read.permitted).toBe(true);
    expect(admin).toMatchObject({ permitted: false, denial_reason: "out_of_authority" });
    expect(x.decided.map((r) => [r.resource.properties.audience, r.resource.properties.operation_target])).toEqual([
      [CANONICAL_RESOURCE, CANONICAL_RESOURCE],
      [CANONICAL_RESOURCE, ADMIN],
    ]);

    // An entry naming the alias is not an entry for the target the alias's boundary serves.
    const aliasMission = buildPep(d, "mcp-payments-pep", { view: viewOf(ALIAS) });
    const denied = await call(aliasMission, "get_invoice", { invoice_id: "inv-1" }, await mint(ALIAS));
    expect(denied).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
    expect(aliasMission.fgaCalls()).toBe(0);
    const aliasCredential = buildPep(d, "mcp-payments-pep");
    const refused = await call(aliasCredential, "get_invoice", { invoice_id: "inv-1" }, await mint(ALIAS, ALIAS));
    expect(refused).toMatchObject({ ok: false });
    expect(aliasCredential.decided).toHaveLength(0);
    expect(refusals(aliasCredential).map((r) => [r.audience, r.denial_reason])).toEqual([[CANONICAL_RESOURCE, "credential_authority_insufficient"]]);
  });

  it("refuses a request whose boundary cannot be established, supplying none from the credential or a default, and emits no record of any form", async () => {
    for (const [statement, location] of [
      [statementWith(TWO_BOUNDARIES), "undeclared-pep"],
      [statementWith({ versions: [{ ...(CHANGE.versions[1] as EnforcementBoundaries["versions"][number]), replaces: [] }] }), "mcp-payments-pep"],
    ] as const) {
      // The second statement's only version is not yet in force before the cutover instant.
      const d = deployment(statement, () => new Date(CUTOVER_MS - 1000));
      const x = buildPep(d, location);
      expect(x.pep.boundary().ok).toBe(false);
      await expect(x.server.validateMissionToken(await mint(CANONICAL_RESOURCE))).rejects.toThrow(TokenAudienceError);
      expect(await x.pep.intake("get_invoice", { invoice_id: "inv-1" }, factsFor())).toEqual({ ok: false, refusal_reason: BOUNDARY_UNRESOLVABLE });
      expect(await x.pep.enforce("get_invoice", { invoice_id: "inv-missing" }, factsFor())).toEqual({
        permitted: false,
        refusal_reason: BOUNDARY_UNRESOLVABLE,
      });
      expect(x.decided).toHaveLength(0);
      expect(x.evidence.all()).toHaveLength(0);
    }
  });

  it("ships a boundary identifier that is the protected resource's RFC 9728 resource string and a mediated scope entry", () => {
    const pep = new Pep({
      payments: new PaymentsStore(),
      evidence: new EvidenceStore(),
      fga: {} as unknown as Fga,
      modelId: MODEL,
      loadView: () => undefined,
      instanceEpoch: "epoch-shipped",
    });
    const server = new McpPaymentsServer({
      pep,
      payments: new PaymentsStore(),
      loadView: () => undefined,
      issuer: ISSUER,
      jwks: { keys: [] },
      keyRoles: { accessToken: [], attenuationRoot: [], transactionToken: [] },
      writeReservations: openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" }),
    });
    expect(pep.boundary()).toEqual({ ok: true, boundary: CANONICAL_RESOURCE, version: "payments-boundary-v1" });
    expect(server.protectedResourceMetadata().resource).toBe(CANONICAL_RESOURCE);
    expect(RUNTIME_POSTURE.mediated_scope.resources).toContain(CANONICAL_RESOURCE);
  });
});

describe("a declared change of boundary identifier (@spec runtime#boundary-identifier-change, runtime-evidence#decision-evidence-integrity, #853)", () => {
  it("invalidates permits decided before the cutover, switches every producer together, keeps aliased tokens usable and old records verifiable byte for byte", async () => {
    let nowMs = CUTOVER_MS - 60_000;
    const d = deployment(statementWith(CHANGE), () => new Date(nowMs));
    const x = buildPep(d, "mcp-payments-pep");
    const token = await mint(LEGACY);

    // Before the cutover: the legacy identifier is the boundary.
    expect((await call(x, "get_invoice", { invoice_id: "inv-1" }, token)).ok).toBe(true);
    const facts = await x.server.validateMissionToken(token);
    const read = await x.pep.enforce("get_invoice", { invoice_id: "inv-1" }, facts);
    const prepare = await x.pep.enforce("hold_transfer", { invoice_id: "inv-1" }, facts);
    expect([read.attempt?.audience, prepare.attempt?.audience]).toEqual([LEGACY, LEGACY]);
    const [oldDecision] = decisions(x);
    const oldBytes = canonicalize(oldDecision as unknown as JsonValue);
    const oldRequest = x.decided[0] as EvaluationRequest;
    expect(oldDecision?.audience).toBe(LEGACY);

    nowMs = CUTOVER_MS + 60_000;

    // Old permits, a cacheable read's and a compound action's prepare phase, refuse at use.
    for (const p of [read, prepare]) {
      const used = await x.pep.verifyPermitAtUse(p.attempt as NonNullable<typeof p.attempt>);
      expect(used).toMatchObject({ ok: false, error: BOUNDARY_CUTOVER_ERROR });
    }
    // Their dispositions keep the original identifier and verify as historical evidence.
    const suppressed = executions(x);
    expect(suppressed.map((r) => [r.audience, r.outcome, r.error])).toEqual([
      [LEGACY, "suppressed", BOUNDARY_CUTOVER_ERROR],
      [LEGACY, "suppressed", BOUNDARY_CUTOVER_ERROR],
    ]);
    for (const r of suppressed) expect(await verifyEvidenceEnvelope(r, EXECUTION_EVIDENCE_MEDIA_TYPE, d.resolver)).toEqual({ valid: true });

    // After it: the same token is accepted through the declared alias, and every new decision carries the new identifier.
    expect((await call(x, "get_invoice", { invoice_id: "inv-1" }, token)).ok).toBe(true);
    const newRequest = x.decided[x.decided.length - 1] as EvaluationRequest;
    expect(newRequest.resource.properties.audience).toBe(CANONICAL_RESOURCE);
    expect(decisions(x).at(-1)?.audience).toBe(CANONICAL_RESOURCE);
    // The audience is in the authorization binding, so no cached decision crosses the change.
    expect(decisionCacheKey(newRequest, viewOf(), MODEL)).not.toBe(decisionCacheKey(oldRequest, viewOf(), MODEL));

    // Producers switched together: the PDP no longer signs for the old identifier, nor the PEP a new refusal under it.
    await expect(d.point.decide(oldRequest, x.options[0] as DecisionOptions)).rejects.toThrow(/refusing to sign/);
    await expect(
      x.evidence.recordRefusal(EMITTER, "pep", {
        missionId: "msn_853",
        audience: LEGACY,
        action: { name: "payments:invoice.read" },
        denial_reason: "target_unresolvable",
      }),
    ).rejects.toThrow(/not authorized/);

    // The record from before the cutover is unchanged and still verifies under its own version.
    expect(canonicalize(oldDecision as unknown as JsonValue)).toBe(oldBytes);
    expect(await verifyEvidenceEnvelope(oldDecision, DECISION_EVIDENCE_MEDIA_TYPE, d.resolver)).toEqual({ valid: true });
    expect(await verifyEvidenceEnvelope({ ...oldDecision, audience: CANONICAL_RESOURCE }, DECISION_EVIDENCE_MEDIA_TYPE, d.resolver)).toEqual({
      valid: false,
      reason: "byte_mismatch",
    });
  });

  it("never rewrites an approved entry through the alias: an entry naming the old identifier is refused after the change", async () => {
    let nowMs = CUTOVER_MS - 60_000;
    const d = deployment(statementWith(CHANGE), () => new Date(nowMs));
    nowMs = CUTOVER_MS + 60_000;
    const x = buildPep(d, "mcp-payments-pep", { view: viewOf(LEGACY) });
    const denied = await call(x, "get_invoice", { invoice_id: "inv-1" }, await mint(LEGACY));
    expect(denied).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
    expect(x.decided.map((r) => r.resource.properties)).toEqual([
      { vendor_id: "acme", audience: CANONICAL_RESOURCE, operation_target: CANONICAL_RESOURCE },
    ]);
    expect(x.fgaCalls()).toBe(0);
  });

  it("has the PDP accept a boundary identifier only from a PEP authorized for it under the version in force", async () => {
    let nowMs = CUTOVER_MS - 60_000;
    const d = deployment(statementWith(CHANGE), () => new Date(nowMs));
    const authority = new EnforcementBoundaryContext(d.statement, "mcp-payments-pep", d.clock);
    const view = viewOf();
    const channel = await createDecisionChannel(d.point, {
      mode: "remote",
      pepId: "mcp-payments-pep",
      audience: CANONICAL_RESOURCE,
      operationTargets: [CANONICAL_RESOURCE],
      scopes: () => {
        const established = authority.establish();
        return established.ok ? [established.boundary] : [];
      },
      getOptions: () => ({
        view,
        fga: { checkWithContext: async () => true } as unknown as Fga,
        modelId: MODEL,
        now: d.clock,
        stalenessBound,
        relationForAction,
        stateSourcePlacement: "pep" as const,
      }),
    });
    try {
      const x = buildPep(d, "mcp-payments-pep", { view });
      const token = await mint(LEGACY);
      expect((await call(x, "get_invoice", { invoice_id: "inv-1" }, token)).ok).toBe(true);
      const request = x.decided[0] as EvaluationRequest;
      const before = await channel.decide(request, {} as DecisionOptions);
      expect(isDecisionChannelRefusal(before), JSON.stringify(before.context)).toBe(false);
      nowMs = CUTOVER_MS + 60_000;
      const refused = await channel.decide(request, {} as DecisionOptions);
      expect(isDecisionChannelRefusal(refused)).toBe(true);
      const moved = { ...request, resource: { ...request.resource, properties: { ...request.resource.properties, audience: CANONICAL_RESOURCE } } };
      expect(isDecisionChannelRefusal(await channel.decide(moved, {} as DecisionOptions))).toBe(false);
    } finally {
      await channel.close();
    }
  });
});
