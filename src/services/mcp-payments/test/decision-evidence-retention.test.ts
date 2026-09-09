/**
 * @spec draft-mcguinness-mission-runtime-evidence.md#decision-evidence-object,
 * #decision-evidence-integrity; draft-mcguinness-mission-runtime.md#agent-isolated-evidence-emission
 * (issue #741).
 *
 * The PEP side of the emission boundary: it stores what the PDP emitted, and
 * builds nothing. These cases assert that the enforcement path holds no PDP
 * evidence key at all, that retention verifies the key-to-emitter and
 * key-to-audience binding rather than the `kid` alone, that a permit whose
 * decision left no verifiable Decision Evidence is refused rather than
 * executed, and that a record survives the remote decision channel
 * byte-identically and still verifies at the PEP that receives it.
 *
 * Issue #594 (W4-8) adds the retention half: the durable record and key store
 * behind the process-local array, the audit window a record is held for, the
 * published key sets a verifier resolves a `kid` through, and the deployment's
 * own evidence declaration. The shipped statement claims no Evidence
 * capability and keeps its disclaimer; the claiming statement here is an
 * explicitly scoped TEST deployment derived from it.
 *
 * Unconditional: `alwaysAllowFga` stands in for OpenFGA, so this file never
 * skips.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { AUDIT_HORIZON_SECONDS, RUNTIME_SCOPE_CONFIG } from "@mission/demo-data";
import { canonicalDigest, type JsonValue } from "@mission/core";
import {
  createDecisionEvidenceEmitter,
  createEphemeralDecisionPoint,
  createPdpHttpServer,
  type EnforcementScopeStatement,
  evaluateRemote,
  type EvaluationRequest,
  type Fga,
  loadRuntimePosture,
  type MissionView,
  type PdpHttpServerHandle,
  PostureConfigError,
  relationForAction,
  retentionWindowSeconds,
  stalenessBound,
} from "@mission/pdp";
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import {
  buildAndSignMissionReceipt,
  buildEvidenceKeyResolver,
  CANONICAL_RESOURCE,
  createEphemeralEvidenceKeys,
  DECISION_EVIDENCE_MEDIA_TYPE,
  type DecisionEvidence,
  deploymentReceiptIssuerScope,
  deploymentRetentionWindowSeconds,
  EVIDENCE_KEY_SET_LOCATION,
  EvidenceRetentionStore,
  EvidenceStore,
  EXECUTION_EVIDENCE_MEDIA_TYPE,
  McpPaymentsServer,
  PaymentsStore,
  Pep,
  REFUSAL_RECORD_MEDIA_TYPE,
  type TokenFacts,
  verifyEvidenceEnvelope,
  verifyMissionReceipt,
} from "../src/index.js";

const ISSUER = "https://as.test";
const NOW = new Date("2026-07-22T12:00:00Z");
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

const TOKEN: TokenFacts = {
  sub: "alice",
  clientId: "ap-agent",
  mission: { id: "msn_ret", issuer: ISSUER, authority_hash: "sha-256:rethash" },
  cnfJkt: "jkt-1",
};

const view = (): MissionView => ({
  id: "msn_ret",
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:rethash",
  authority_set: [
    { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] },
  ],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
});

/**
 * One decision point (the PDP side: it decides, and it emits) paired with the
 * enforcement-side key bundle that verifies what it emits (#741, PR #753
 * review). `pdp.emitter` stands in for a PDP that already decided, where a
 * case needs the record itself rather than a decision; nothing the PEP below
 * receives exposes it.
 */
function decisionPointAndKeys(options: { emitterId?: string; audience?: string } = {}) {
  const emitterId = options.emitterId ?? CANONICAL_RESOURCE;
  const audience = options.audience ?? CANONICAL_RESOURCE;
  const pdp = createEphemeralDecisionPoint({ emitterId, audience });
  return { pdp, keys: createEphemeralEvidenceKeys({ emitterId, audience, decisionPoint: pdp }) };
}

function seededPayments(): PaymentsStore {
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [{ id: "inv-1", vendor_id: "acme", amount: "100.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
  );
  return payments;
}

/** One PEP/server pair; `keys` supplies the store's resolver and (optionally) the decision function. */
function buildServer(keys: ReturnType<typeof createEphemeralEvidenceKeys>, withDecisionPoint: boolean, jwks: { keys: Record<string, unknown>[] } = { keys: [] }) {
  const payments = seededPayments();
  const evidence = new EvidenceStore(keys.signing, keys.resolver);
  const missionView = view();
  const loadView = (ref: { id: string; issuer: string }) =>
    ref.id === missionView.id && ref.issuer === missionView.issuer
      ? { view: missionView, freshness: { observed_at: new Date().toISOString(), source: "load_view" } }
      : undefined;
  const pep = new Pep({
    payments,
    evidence,
    ...(withDecisionPoint ? { decide: keys.decide } : {}),
    fga: alwaysAllowFga,
    modelId: "unit-test-model",
    loadView,
    instanceEpoch: "epoch-1",
    allowedFreshnessSources: new Set(["load_view"]),
  });
  const server = new McpPaymentsServer({
    pep,
    payments,
    loadView,
    jwks,
    issuer: ISSUER,
  });
  return { server, evidence };
}

describe("the enforcement path holds no PDP evidence key (@spec runtime-evidence#decision-evidence-object, #741)", () => {
  it("carries issuer and expiry only from a verified credential through the PEP into signed Decision Evidence", async () => {
    const { privateKey, publicKey } = await generateKeyPair("ES256");
    const jwk = await exportJWK(publicKey); jwk.kid = "credential-test";
    const { keys } = decisionPointAndKeys();
    const { server, evidence } = buildServer(keys, true, { keys: [jwk] });
    const exp = Math.floor(Date.now() / 1000) + 600;
    const sign = (key: CryptoKey) => new SignJWT({ sub: "alice", client_id: "ap-agent", mission: TOKEN.mission, cnf: { jkt: "jkt-1" }, raw_claim: "PRIVATE-CREDENTIAL-CLAIM" })
      .setProtectedHeader({ alg: "ES256", kid: jwk.kid }).setIssuer(ISSUER).setAudience(CANONICAL_RESOURCE).setExpirationTime(exp).sign(key);
    const other = await generateKeyPair("ES256");
    await expect(server.validateMissionToken(await sign(other.privateKey))).rejects.toThrow();
    expect(evidence.all()).toEqual([]);
    const credential = await sign(privateKey);
    const facts = await server.validateMissionToken(credential);
    const result = await server.callReadTool("get_invoice", { invoice_id: "inv-1", credential: { issuer: "https://attacker.test", expires_at: "2099-01-01T00:00:00Z" } }, facts);
    expect(result.isError).not.toBe(true);
    const record = evidence.all().find((e): e is DecisionEvidence => e.kind === "decision")!.content;
    expect(record.credential).toEqual({ issuer: ISSUER, expires_at: new Date(exp * 1000).toISOString() });
    const signed = Buffer.from(record.evidence_envelope.value.split(".")[1]!, "base64url").toString("utf8");
    expect(signed).not.toContain("PRIVATE-CREDENTIAL-CLAIM");
    expect(signed).not.toContain("attacker.test");
    expect(signed).not.toContain(credential);
  });

  it("the signer configuration has no `pdp` role to configure", () => {
    const keys = createEphemeralEvidenceKeys();
    expect(Object.keys(keys.signing).sort()).toEqual(["executor", "pep", "receipt_issuer"]);
  });

  it("a store asked to sign a `pdp`-role record fails closed rather than minting one", async () => {
    const keys = createEphemeralEvidenceKeys();
    const evidence = new EvidenceStore(keys.signing, keys.resolver);
    await expect(
      evidence.recordRefusal(CANONICAL_RESOURCE, "pdp", {
        missionId: "msn_ret",
        audience: CANONICAL_RESOURCE,
        action: { name: "payments:invoice.read" },
        denial_reason: "unknown_mission",
      }),
    ).rejects.toThrow(/no signer configured for emitter role "pdp"/);
  });
});

describe("retainDecision verifies before it retains (@spec runtime-evidence#decision-evidence-integrity, #741)", () => {
  it("refuses a genuinely signed record whose emitter id is not the one the key is published for", async () => {
    const keys = createEphemeralEvidenceKeys();
    const impostor = createDecisionEvidenceEmitter({
      // Same key material as nothing the resolver knows: a different emitter
      // claiming this deployment's audience.
      signer: { kid: "ephemeral-pdp", key: generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey },
      emitterId: "https://impersonator.example.com/mcp",
      audience: CANONICAL_RESOURCE,
    });
    const record = await impostor.emit({
      mission: { id: "msn_ret", issuer: ISSUER, policy_view_id: "pv_1" },
      subject: { id: "alice" },
      resource: { type: "invoice", id: "inv-1" },
      action: { name: "payments:invoice.read" },
      audience: CANONICAL_RESOURCE,
      evaluation_id: "dec_impostor",
      decision: "permit",
      entry_digest: "sha-256:fixture-entry",
      conditions: { valid_until: NOW.toISOString() },
      evaluated_at: NOW.toISOString(),
    });
    const evidence = new EvidenceStore(keys.signing, keys.resolver);
    await expect(evidence.retainDecision(record)).resolves.toEqual({
      retained: false,
      reason: "key_not_resolvable",
    });
    expect(evidence.all()).toHaveLength(0);
  });

  it("refuses a record for an audience the emitter's key is not published for", async () => {
    const foreign = createEphemeralDecisionPoint({
      emitterId: CANONICAL_RESOURCE,
      audience: "https://other-scope.example.com",
    });
    // The store's resolver is this deployment's, bound to its own audience.
    const deploymentKeys = createEphemeralEvidenceKeys();
    const record = await foreign.emitter.emit({
      mission: { id: "msn_ret", issuer: ISSUER, policy_view_id: "pv_1" },
      subject: { id: "alice" },
      resource: { type: "invoice", id: "inv-1" },
      action: { name: "payments:invoice.read" },
      audience: "https://other-scope.example.com",
      evaluation_id: "dec_scope",
      decision: "permit",
      entry_digest: "sha-256:fixture-entry",
      conditions: { valid_until: NOW.toISOString() },
      evaluated_at: NOW.toISOString(),
    });
    const evidence = new EvidenceStore(deploymentKeys.signing, deploymentKeys.resolver);
    await expect(evidence.retainDecision(record)).resolves.toEqual({
      retained: false,
      reason: "key_not_resolvable",
    });
  });

  it("refuses when no verification keys are configured at all, rather than retaining an unverified record", async () => {
    const { pdp, keys } = decisionPointAndKeys();
    const record = await pdp.emitter.emit({
      mission: { id: "msn_ret", issuer: ISSUER, policy_view_id: "pv_1" },
      subject: { id: "alice" },
      resource: { type: "invoice", id: "inv-1" },
      action: { name: "payments:invoice.read" },
      audience: CANONICAL_RESOURCE,
      evaluation_id: "dec_nokeys",
      decision: "permit",
      entry_digest: "sha-256:fixture-entry",
      conditions: { valid_until: NOW.toISOString() },
      evaluated_at: NOW.toISOString(),
    });
    const evidence = new EvidenceStore(keys.signing);
    await expect(evidence.retainDecision(record)).resolves.toEqual({
      retained: false,
      reason: "no_verification_keys",
    });
  });

  it("retains the verified record VERBATIM: the retained bytes are the object the PDP signed", async () => {
    const { pdp, keys } = decisionPointAndKeys();
    const record = await pdp.emitter.emit({
      mission: { id: "msn_ret", issuer: ISSUER, policy_view_id: "pv_1" },
      subject: { id: "alice" },
      resource: { type: "invoice", id: "inv-1" },
      action: { name: "payments:invoice.read" },
      audience: CANONICAL_RESOURCE,
      evaluation_id: "dec_verbatim",
      decision: "permit",
      entry_digest: "sha-256:fixture-entry",
      conditions: { valid_until: NOW.toISOString() },
      evaluated_at: NOW.toISOString(),
    });
    const evidence = new EvidenceStore(keys.signing, keys.resolver);
    const result = await evidence.retainDecision(record);
    expect(result.retained).toBe(true);
    const retained = evidence.all().find((e): e is DecisionEvidence => e.kind === "decision");
    expect(retained?.content).toBe(record);
    expect(Object.isFrozen(retained?.content)).toBe(true);
  });
});

describe("a permit the PDP did not evidence is refused, never executed (#741)", () => {
  it("a genuinely signed Decision Evidence claiming permit does not flip an otherwise-DENY decision to executed", async () => {
    const keys = createEphemeralEvidenceKeys();
    const decide = keys.decide;
    keys.decide = async (request, options) => {
      const permitted = await decide(request, options);
      expect(permitted.decision).toBe(true);
      // Keep the genuine, correctly scoped signed permit evidence. Only the
      // live decision denies, so failed signature verification cannot prove
      // this invariant by accident.
      return { ...permitted, decision: false, context: { ...permitted.context, denial_reason: "out_of_authority" } };
    };
    const { server, evidence } = buildServer(keys, true);
    const execute = vi.spyOn(server as unknown as { execute(tool: string, args: Record<string, unknown>): unknown }, "execute");
    const res = await server.callReadTool("get_invoice", { invoice_id: "inv-1" }, TOKEN);
    expect(res).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
    const retained = evidence.all().find((e): e is DecisionEvidence => e.kind === "decision");
    expect(retained?.content.decision).toBe("permit");
    expect(retained?.content.emitter).toEqual({ id: CANONICAL_RESOURCE, role: "pdp" });
    expect(execute).not.toHaveBeenCalled();
    expect(res.result).toBeUndefined();
  });

  it("refuses the action when the decision carries no Decision Evidence", async () => {
    const keys = createEphemeralEvidenceKeys();
    const { server, evidence } = buildServer(keys, false);
    const res = await server.callReadTool("get_invoice", { invoice_id: "inv-1" }, TOKEN);
    expect(res.ok).toBe(false);
    expect(evidence.all().some((e) => e.kind === "decision")).toBe(false);
    const refusal = evidence.all().find((e) => e.kind === "refusal");
    expect(refusal).toBeDefined();
    // @spec runtime-evidence#pre-decision-refusal (#786): "a response whose
    // Decision Evidence the enforcing component could not verify is not a
    // decision that component obtained", so this is a PRE-decision Refusal
    // Record carrying the enumerated value, not a disposition of a permit
    // that was never accepted.
    expect(refusal?.kind === "refusal" && refusal.content.denial_reason).toBe("decision_evidence_unverifiable");
    expect(evidence.all().some((e) => e.kind === "execution")).toBe(false);
  });

  it("permits and retains when the same decision IS evidenced: the refusal above is the missing record, not the fixture", async () => {
    const keys = createEphemeralEvidenceKeys();
    const { server, evidence } = buildServer(keys, true);
    const res = await server.callReadTool("get_invoice", { invoice_id: "inv-1" }, TOKEN);
    expect(res.ok, JSON.stringify(res)).toBe(true);
    const retained = evidence.all().find((e): e is DecisionEvidence => e.kind === "decision");
    expect(retained?.content.decision).toBe("permit");
    expect(retained?.content.emitter).toEqual({ id: CANONICAL_RESOURCE, role: "pdp" });
  });
});

describe("the record survives the remote decision channel byte-identically (@spec runtime#decision-channel, #741)", () => {
  let handle: PdpHttpServerHandle | undefined;
  afterEach(async () => {
    await handle?.close();
    handle = undefined;
  });

  it("a record signed at an out-of-process PDP verifies and is retained at the PEP that received it over the MAC'd hop", async () => {
    const PEP_ID = "mcp-payments-pep";
    const SECRET = "test-shared-secret-do-not-reuse";
    const { pdp, keys } = decisionPointAndKeys();
    const missionView = view();
    handle = await createPdpHttpServer({
      peps: new Map([[PEP_ID, { secret: SECRET, scopes: [CANONICAL_RESOURCE] }]]),
      getOptions: () => ({
        view: missionView,
        fga: alwaysAllowFga,
        modelId: "unit-test-model",
        now: () => NOW,
        stalenessBound,
        relationForAction,
      }),
      // The emitter is bound HERE, in the PDP server's own construction, on
      // the PDP side of the network hop: it is reachable from no options
      // object, and the PEP below could not sign a record if it wanted to.
      evidence: pdp.emitter,
      replayWindowSeconds: 30,
    });

    const request: EvaluationRequest = {
      subject: { id: "alice" },
      resource: { type: "invoice", id: "inv-1", properties: { vendor_id: "acme" } },
      action: { name: "payments:invoice.read" },
      context: { audience: CANONICAL_RESOURCE, mission: { id: "msn_ret", issuer: ISSUER } },
    };
    const decision = await evaluateRemote(request, { url: handle.url, pepId: PEP_ID, secret: SECRET });
    expect(decision.decision, JSON.stringify(decision.context)).toBe(true);

    // The PEP holds only public verification keys, and retains what crossed
    // the hop: JSON transport preserved every byte the signature covers.
    const evidence = new EvidenceStore(keys.signing, buildEvidenceKeyResolver(keys.verification));
    const result = await evidence.retainDecision(
      decision.context.decision_evidence as Parameters<typeof evidence.retainDecision>[0],
    );
    expect(result).toMatchObject({ retained: true });
    const retained = evidence.all().find((e): e is DecisionEvidence => e.kind === "decision");
    expect(retained?.content.evaluation_id).toBe(decision.context.evaluation_id);
    expect(retained?.content.emitter).toEqual({ id: CANONICAL_RESOURCE, role: "pdp" });
  });
});

// ---------------------------------------------------------------------------
// Issue #594 W4-8: the audit retention window, the deployment's published key
// sets, and its own (deliberately unclaimed) evidence declaration.
// ---------------------------------------------------------------------------

/** Short enough for a controlled clock to cross it; the shipped deployment's own window is its audit horizon. */
const WINDOW_SECONDS = 3600;
const T0 = Math.floor(NOW.getTime() / 1000);

const SHIPPED = RUNTIME_SCOPE_CONFIG as EnforcementScopeStatement;
/** The PEP location the SHIPPED statement declares: what a receipt-issuer designation has to name. */
const PEP_LOCATION = SHIPPED.mediated_scope.pep_locations[0]!;
const MISSION_REF = { id: "msn_ret", issuer: ISSUER };
type EvidenceDeclaration = NonNullable<NonNullable<EnforcementScopeStatement["extensions"]>["evidence"]>;

/**
 * The claiming TEST deployment: the SHIPPED statement plus the evidence claim
 * and the declaration that goes with it, naming this deployment's own PEP
 * location and its own key-set location, so the designation is checked against
 * what the deployment actually declares rather than against invented
 * fixture components.
 *
 * `config/enforcement-scope.json` itself claims nothing and keeps its
 * disclaimer: the mandatory Evidence producer and consumer duties (#594's
 * W4-3, W4-4 and W4-16) are not met, so the shipped deployment must not assert
 * the capability. A tested conditional requirement may have a claiming fixture
 * without the default deployment making an unsupported claim.
 */
function claimingDeployment(overrides: Partial<EvidenceDeclaration> = {}): EnforcementScopeStatement {
  const declaration: EvidenceDeclaration = {
    mechanism: "emitter-signed append-only runtime evidence",
    retention_window: "P400D",
    signing_key_locations: [EVIDENCE_KEY_SET_LOCATION],
    receipt_issuers: [{ emitter: PEP_LOCATION, key_set: EVIDENCE_KEY_SET_LOCATION }],
  };
  return {
    ...(structuredClone(SHIPPED) as EnforcementScopeStatement),
    claims: ["evidence"],
    extensions: { evidence: { ...declaration, ...overrides } as EvidenceDeclaration },
  };
}

const decisionInput = (evaluation_id: string) => ({
  mission: { id: MISSION_REF.id, issuer: ISSUER, policy_view_id: "pv_1" },
  subject: { id: "alice" },
  resource: { type: "invoice", id: "inv-1" },
  action: { name: "payments:invoice.read" },
  audience: CANONICAL_RESOURCE,
  evaluation_id,
  decision: "permit" as const,
  entry_digest: "sha-256:fixture-entry",
  conditions: { valid_until: NOW.toISOString() },
  evaluated_at: NOW.toISOString(),
});

const refusalInput = (n: number) => ({
  missionId: MISSION_REF.id,
  audience: CANONICAL_RESOURCE,
  action: { name: "payments:invoice.read" },
  denial_reason: "out_of_authority",
  mission: { ...MISSION_REF, authority_hash: "sha-256:rethash" },
  parameter_digest: `sha-256:refusal-${n}`,
});

const executionInput = (n: number) => ({
  permitId: `permit-${n}`,
  opKey: `op-${n}`,
  evaluation_id: `dec_${n}`,
  mission_id: MISSION_REF.id,
  audience: CANONICAL_RESOURCE,
  outcome: "completed" as const,
});

/**
 * This deployment's evidence plane over a durable retention store: its own
 * per-role signing keys, the SAME keys published at the key-set location its
 * claiming statement declares, and a store whose verification resolver reads
 * that published document.
 */
function retainingDeployment(
  options: { clock?: () => number; file?: string; capacity?: number } = {},
): {
  pdp: ReturnType<typeof createEphemeralDecisionPoint>;
  keys: ReturnType<typeof createEphemeralEvidenceKeys>;
  retention: EvidenceRetentionStore;
  evidence: EvidenceStore;
} {
  const pdp = createEphemeralDecisionPoint({ emitterId: CANONICAL_RESOURCE, audience: CANONICAL_RESOURCE });
  const keys = createEphemeralEvidenceKeys({ decisionPoint: pdp });
  const clock = options.clock ?? (() => NOW.getTime());
  const retention = new EvidenceRetentionStore({
    retentionWindowSeconds: WINDOW_SECONDS,
    ...(options.file !== undefined ? { store: { file: options.file } } : {}),
    ...(options.capacity !== undefined ? { capacity: options.capacity } : {}),
    now: () => new Date(clock()),
  });
  publishDeploymentKeys(retention, keys);
  const evidence = new EvidenceStore(
    keys.signing,
    retention.resolver({ locations: [EVIDENCE_KEY_SET_LOCATION] }),
    retention,
  );
  return { pdp, keys, retention, evidence };
}

function publishDeploymentKeys(
  retention: EvidenceRetentionStore,
  keys: ReturnType<typeof createEphemeralEvidenceKeys>,
): void {
  for (const key of keys.verification) {
    retention.publishKey({
      location: EVIDENCE_KEY_SET_LOCATION,
      kid: key.kid,
      emitterId: key.emitterId,
      role: key.role,
      ...(key.audience !== undefined ? { audience: key.audience } : {}),
      publicKey: key.publicKey,
    });
  }
}

/** One receipt-issuer identity published for the emitter the statement designates. */
function designatedReceiptSigner(retention: EvidenceRetentionStore): { kid: string; key: KeyObject } {
  const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
  retention.publishKey({
    location: EVIDENCE_KEY_SET_LOCATION,
    kid: "deployment-receipts-1",
    emitterId: PEP_LOCATION,
    role: "receipt_issuer",
    publicKey: pair.publicKey,
  });
  return { kid: "deployment-receipts-1", key: pair.privateKey };
}

describe("retention honors the declared audit window (@spec runtime-evidence#receipt-retention)", () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  });

  it("retains all three record kinds for the declared window and refuses to evict one inside it", async () => {
    let clock = NOW.getTime();
    const { pdp, evidence, retention } = retainingDeployment({ clock: () => clock });
    const decision = await pdp.emitter.emit(decisionInput("dec_all"));
    expect((await evidence.retainDecision(decision)).retained).toBe(true);
    const refusal = await evidence.recordRefusal(CANONICAL_RESOURCE, "pep", refusalInput(1));
    const execution = await evidence.recordExecution(CANONICAL_RESOURCE, "pep", executionInput(1));
    expect(retention.count()).toBe(3);
    const held = [
      ["decision", decision.evidence_id],
      ["refusal", refusal.content.refusal_id],
      ["execution", execution.content.execution_id],
    ] as const;
    for (const [kind, id] of held) {
      expect(retention.get(kind, id)?.retain_until).toBe(T0 + WINDOW_SECONDS);
      // The refusal is observable, not a silently skipped delete: the caller
      // learns the record is still owed to an auditor.
      expect(() => retention.evict(kind, id)).toThrow(/audit retention window/);
      expect(retention.get(kind, id)).toBeDefined();
    }
    expect(retention.prune()).toBe(0);
    // The window this deployment runs with is the floor the runtime profile
    // puts under it: its own declared Mission audit horizon, since its
    // statement claims no evidence capability and declares no longer window.
    expect(deploymentRetentionWindowSeconds(SHIPPED, AUDIT_HORIZON_SECONDS)).toBe(AUDIT_HORIZON_SECONDS);
    clock += (WINDOW_SECONDS + 1) * 1000;
    expect(retention.prune()).toBe(3);
    retention.close();
  });

  it("recovers the retained records, the emitter sequences and the key retirement metadata after a restart", async () => {
    const dir = mkdtempSync(join(tmpdir(), "evidence-retention-"));
    dirs.push(dir);
    const file = join(dir, "evidence.db");
    let clock = NOW.getTime();
    const first = retainingDeployment({ clock: () => clock, file });
    const decision = await first.pdp.emitter.emit(decisionInput("dec_restart"));
    await first.evidence.retainDecision(decision);
    const refusal = await first.evidence.recordRefusal(CANONICAL_RESOURCE, "pep", refusalInput(1));
    expect(refusal.content.sequence).toBe(0);
    clock += 60_000;
    first.retention.retireKey("ephemeral-executor");
    const retiredUntil = first.retention.keyResolvableUntil("ephemeral-executor");
    first.retention.close(); // the process dies with the window still open

    const reopened = new EvidenceRetentionStore({
      retentionWindowSeconds: WINDOW_SECONDS,
      store: { file },
      now: () => new Date(clock),
    });
    const resolve = reopened.resolver({ locations: [EVIDENCE_KEY_SET_LOCATION] });
    const recovered = new EvidenceStore(first.keys.signing, resolve, reopened);
    expect(recovered.all().map((r) => r.kind)).toEqual(["decision", "refusal"]);
    // The rehydrated record still verifies under the envelope it was signed
    // with, through the key set the reopened store still publishes.
    const rehydrated = recovered.all().find((r): r is DecisionEvidence => r.kind === "decision")!.content;
    expect(rehydrated.evidence_id).toBe(decision.evidence_id);
    expect(await verifyEvidenceEnvelope(rehydrated, DECISION_EVIDENCE_MEDIA_TYPE, resolve)).toEqual({ valid: true });
    // The emitter's sequence continues the stream rather than reissuing 0 for
    // a Mission whose earlier records are still retained.
    const next = await recovered.recordRefusal(CANONICAL_RESOURCE, "pep", refusalInput(2));
    expect(next.content.sequence).toBe(1);
    expect(reopened.keyResolvableUntil("ephemeral-executor")).toBe(retiredUntil);
    reopened.close();
  });

  it("releases a record only once the window has passed, and fails closed at capacity rather than evicting one still inside it", async () => {
    let clock = NOW.getTime();
    const { evidence, retention } = retainingDeployment({ clock: () => clock, capacity: 1 });
    const held = await evidence.recordRefusal(CANONICAL_RESOURCE, "pep", refusalInput(1));
    await expect(evidence.recordRefusal(CANONICAL_RESOURCE, "pep", refusalInput(2))).rejects.toThrow(/at capacity/);
    expect(retention.count()).toBe(1);
    expect(retention.get("refusal", held.content.refusal_id)).toBeDefined();
    // Nothing reached this process's read model either: a record the
    // deployment cannot retain is not a record it reports having.
    expect(evidence.all()).toHaveLength(1);
    clock += (WINDOW_SECONDS + 1) * 1000;
    const later = await evidence.recordRefusal(CANONICAL_RESOURCE, "pep", refusalInput(3));
    expect(retention.get("refusal", held.content.refusal_id)).toBeUndefined();
    expect(retention.get("refusal", later.content.refusal_id)).toBeDefined();
    retention.close();
  });

  it("a retired signing key stays resolvable until the window past the last artifact it signed", async () => {
    let clock = NOW.getTime();
    const { evidence, retention } = retainingDeployment({ clock: () => clock });
    clock += 600_000; // T0 + 600: the last artifact this key signs
    const refusal = await evidence.recordRefusal(CANONICAL_RESOURCE, "pep", refusalInput(1));
    clock += 600_000; // T0 + 1200: the key is retired
    retention.retireKey("ephemeral-pep");
    // Not the key's creation (T0 + window) and not its retirement
    // (T0 + 1200 + window): the LAST artifact it signed.
    expect(retention.keyResolvableUntil("ephemeral-pep")).toBe(T0 + 600 + WINDOW_SECONDS);
    const resolve = retention.resolver({ locations: [EVIDENCE_KEY_SET_LOCATION] });
    const pep = { kid: "ephemeral-pep", emitter: { id: CANONICAL_RESOURCE, role: "pep" }, audience: CANONICAL_RESOURCE };
    clock = (T0 + WINDOW_SECONDS) * 1000; // past a creation-anchored window
    expect(resolve(pep)).toBeDefined();
    clock = (T0 + 600 + WINDOW_SECONDS) * 1000; // the last artifact's own window, inclusive
    expect(resolve(pep)).toBeDefined();
    expect(await verifyEvidenceEnvelope(refusal.content, REFUSAL_RECORD_MEDIA_TYPE, resolve)).toEqual({ valid: true });
    clock += 1000;
    expect(resolve(pep)).toBeUndefined();
    expect(await verifyEvidenceEnvelope(refusal.content, REFUSAL_RECORD_MEDIA_TYPE, resolve)).toEqual({
      valid: false,
      reason: "key_not_resolvable",
    });
    retention.close();
  });

  it("resolves the PDP, PEP and executor keys through the published document at the declared location, never past it", async () => {
    const { pdp, evidence, retention } = retainingDeployment();
    const published = retention.publishedKeySet(EVIDENCE_KEY_SET_LOCATION);
    expect(published.keys.map((k) => k.kid).sort()).toEqual([
      "ephemeral-executor",
      "ephemeral-pdp",
      "ephemeral-pep",
      "ephemeral-receipt_issuer",
    ]);
    expect(published.keys.every((k) => k.d === undefined && k.use === "sig")).toBe(true);
    // Every producer role's record verifies through that document: the PDP's
    // on the retention path, the PEP's and the executor's on emission.
    const decision = await pdp.emitter.emit(decisionInput("dec_published"));
    expect((await evidence.retainDecision(decision)).retained).toBe(true);
    const refusal = await evidence.recordRefusal(CANONICAL_RESOURCE, "pep", refusalInput(1));
    const execution = await evidence.recordExecution(CANONICAL_RESOURCE, "executor", executionInput(1));
    const resolve = retention.resolver({ locations: [EVIDENCE_KEY_SET_LOCATION] });
    expect(await verifyEvidenceEnvelope(refusal.content, REFUSAL_RECORD_MEDIA_TYPE, resolve)).toEqual({ valid: true });
    expect(await verifyEvidenceEnvelope(execution.content, EXECUTION_EVIDENCE_MEDIA_TYPE, resolve)).toEqual({
      valid: true,
    });
    // The location is a declaration, not a side channel: the same kid reached
    // through a location this statement does not declare resolves to nothing,
    // and inside the declared set the binding still has to match.
    const pep = { kid: "ephemeral-pep", emitter: { id: CANONICAL_RESOURCE, role: "pep" }, audience: CANONICAL_RESOURCE };
    expect(retention.resolver({ locations: ["https://other.test/evidence-keys"] })(pep)).toBeUndefined();
    expect(resolve(pep)).toBeDefined();
    expect(resolve({ ...pep, emitter: { id: "https://impostor.test/mcp", role: "pep" } })).toBeUndefined();
    expect(resolve({ ...pep, emitter: { id: CANONICAL_RESOURCE, role: "executor" } })).toBeUndefined();
    expect(resolve({ ...pep, audience: "https://other-scope.example.com" })).toBeUndefined();
    retention.close();
  });

  it("a Mission Receipt over retained evidence still verifies once the key that signed it is retired", async () => {
    let clock = NOW.getTime();
    const { pdp, evidence, retention } = retainingDeployment({ clock: () => clock });
    const signer = designatedReceiptSigner(retention);
    const decision = await pdp.emitter.emit(decisionInput("dec_receipt"));
    await evidence.retainDecision(decision);
    const receipt = await buildAndSignMissionReceipt(
      { kind: "decision", mission: MISSION_REF, decisionEvidence: decision },
      PEP_LOCATION,
      signer,
    );
    retention.retainReceipt(receipt, signer.kid);
    const verify = () =>
      verifyMissionReceipt(
        receipt,
        retention.recordResolver(),
        deploymentReceiptIssuerScope(claimingDeployment(), retention)!,
        retention.resolver({ locations: [EVIDENCE_KEY_SET_LOCATION] }),
        undefined,
        retention.receiptResolver(),
      );
    expect(await verify()).toEqual({ valid: true });
    clock += 60_000;
    retention.retireKey(signer.kid);
    // The referenced evidence and the historical verification key both stay
    // resolvable for as long as a verifier is expected to validate the receipt.
    clock = (T0 + WINDOW_SECONDS) * 1000;
    expect(retention.get("decision", decision.evidence_id)).toBeDefined();
    expect(await verify()).toEqual({ valid: true });
    clock += 1000;
    expect(await verify()).toEqual({ valid: false, reason: "envelope_invalid" });
    retention.close();
  });

  it("a receipt whose chain names an older retained predecessor resolves it from the retention store", async () => {
    const { pdp, evidence, retention } = retainingDeployment();
    const signer = designatedReceiptSigner(retention);
    const first = await pdp.emitter.emit(decisionInput("dec_chain_1"));
    const second = await pdp.emitter.emit(decisionInput("dec_chain_2"));
    await evidence.retainDecision(first);
    await evidence.retainDecision(second);
    const older = await buildAndSignMissionReceipt(
      { kind: "decision", mission: MISSION_REF, decisionEvidence: first, chain: { stream: "msn_ret/receipts", sequence: 0 } },
      PEP_LOCATION,
      signer,
    );
    retention.retainReceipt(older, signer.kid);
    const newer = await buildAndSignMissionReceipt(
      {
        kind: "decision",
        mission: MISSION_REF,
        decisionEvidence: second,
        chain: {
          stream: "msn_ret/receipts",
          sequence: 1,
          previous: [{ digest: canonicalDigest(older as unknown as JsonValue) }],
        },
      },
      PEP_LOCATION,
      signer,
    );
    const scope = deploymentReceiptIssuerScope(claimingDeployment(), retention)!;
    const resolveKey = retention.resolver({ locations: [EVIDENCE_KEY_SET_LOCATION] });
    expect(
      await verifyMissionReceipt(newer, retention.recordResolver(), scope, resolveKey, undefined, retention.receiptResolver()),
    ).toEqual({ valid: true });
    // A predecessor no store retains fails chain verification rather than
    // being treated as absent.
    const empty = new EvidenceRetentionStore({ retentionWindowSeconds: WINDOW_SECONDS });
    expect(
      await verifyMissionReceipt(newer, retention.recordResolver(), scope, resolveKey, undefined, empty.receiptResolver()),
    ).toEqual({ valid: false, reason: "predecessor_unresolvable" });
    empty.close();
    retention.close();
  });
});

describe("the deployment's evidence declaration and published key sets (@spec runtime#runtime-conformance)", () => {
  it("the shipped statement claims no Evidence capability, so this deployment designates no receipt issuer", () => {
    const { retention } = retainingDeployment();
    expect(SHIPPED.claims).toBeUndefined();
    expect(SHIPPED.extensions).toBeUndefined();
    expect(SHIPPED.record_integrity_mechanism).toContain("full Evidence capability not claimed");
    expect(deploymentReceiptIssuerScope(SHIPPED, retention)).toBeUndefined();
    // The claiming TEST deployment, over the SAME published key sets, does
    // designate one: the mechanism is exercised without the shipped
    // deployment asserting a capability it does not meet.
    const scope = deploymentReceiptIssuerScope(claimingDeployment(), retention)!;
    expect(scope.issuers.map((issuer) => issuer.emitter)).toEqual([PEP_LOCATION]);
    retention.close();
  });

  it("designates only the published keys bound to the designated issuer", () => {
    const { retention } = retainingDeployment();
    // This deployment's own receipt-issuer key is published for the canonical
    // resource, not for the PEP location the statement designates, so the
    // designation binds none of it.
    expect(deploymentReceiptIssuerScope(claimingDeployment(), retention)!.issuers[0]!.keys).toHaveLength(0);
    const signer = designatedReceiptSigner(retention);
    const bound = deploymentReceiptIssuerScope(claimingDeployment(), retention)!.issuers[0]!.keys;
    expect(bound.map((key) => key.kid)).toEqual([signer.kid]);
    retention.close();
  });

  it("refuses a retention window shorter than the declared Mission audit horizon, at load", () => {
    expect(() => loadRuntimePosture(claimingDeployment({ retention_window: "PT1H" }), { auditHorizonSeconds: 7200 })).toThrow(
      PostureConfigError,
    );
    expect(() =>
      loadRuntimePosture(claimingDeployment({ retention_window: "PT2H" }), { auditHorizonSeconds: 7200 }),
    ).not.toThrow();
    // Against this deployment's own declared horizon, not merely a nonempty string.
    expect(() => loadRuntimePosture(claimingDeployment({ retention_window: "P30D" }))).toThrow(/shorter than/);
    expect(() => loadRuntimePosture(claimingDeployment())).not.toThrow();
    expect(AUDIT_HORIZON_SECONDS).toBeGreaterThan(30 * 86400);
  });

  it("refuses a retention window that names no resolvable duration", () => {
    for (const bad of ["test-only", "", "P", "PT", "P1Y", "P1M", "3600", "P0D"]) {
      expect(() => loadRuntimePosture(claimingDeployment({ retention_window: bad }))).toThrow(/resolvable/);
    }
    expect(retentionWindowSeconds("P1DT2H3M4S")).toBe(93_784);
    expect(retentionWindowSeconds("P400D")).toBe(34_560_000);
  });

  it("refuses a receipt issuer or key set this statement does not declare", () => {
    expect(() =>
      loadRuntimePosture(
        claimingDeployment({ receipt_issuers: [{ emitter: "receipts.example.com", key_set: EVIDENCE_KEY_SET_LOCATION }] }),
      ),
    ).toThrow(/not a declared PDP or PEP location/);
    expect(() =>
      loadRuntimePosture(claimingDeployment({ receipt_issuers: [{ emitter: PEP_LOCATION, key_set: "https://other.test/keys" }] })),
    ).toThrow(/not a declared signing-key location/);
    // A PDP is as good a receipt issuer as a PEP, if the statement names it.
    expect(() =>
      loadRuntimePosture(
        claimingDeployment({ receipt_issuers: [{ emitter: SHIPPED.pdps[0]!, key_set: EVIDENCE_KEY_SET_LOCATION }] }),
      ),
    ).not.toThrow();
  });

  it("refuses a declaration attached under no claim, and a claim with no declaration", () => {
    const attached = claimingDeployment();
    delete attached.claims;
    expect(() => loadRuntimePosture(attached)).toThrow(/claims no evidence capability/);
    expect(() => loadRuntimePosture({ ...structuredClone(SHIPPED), claims: ["evidence"] })).toThrow(
      /no attached declaration/,
    );
    expect(() => loadRuntimePosture(SHIPPED)).not.toThrow();
  });

  it("refuses to publish private key material, or an audience-unbound enforcement key, in a key set", () => {
    const { retention } = retainingDeployment();
    const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
    expect(() =>
      retention.publishKey({
        location: EVIDENCE_KEY_SET_LOCATION,
        kid: "leaked",
        emitterId: PEP_LOCATION,
        role: "receipt_issuer",
        publicKey: pair.privateKey,
      }),
    ).toThrow(/must not carry private key material/);
    expect(() =>
      retention.publishKey({
        location: EVIDENCE_KEY_SET_LOCATION,
        kid: "unbound",
        emitterId: CANONICAL_RESOURCE,
        role: "pep",
        publicKey: pair.publicKey,
      }),
    ).toThrow(/requires the audience/);
    expect(retention.publishedKeySet(EVIDENCE_KEY_SET_LOCATION).keys.map((k) => k.kid)).not.toContain("leaked");
    retention.close();
  });
});
