/**
 * @spec runtime#boundary-identifier-change, runtime#idempotency,
 * runtime-evidence#decision-evidence-integrity (#853 review, decisions 7 and
 * 9): a declared change of boundary identifier through the assembled
 * consumers `composeStack` wires: the payments server and PEP, the decision
 * channel (co-resident and a real remote hop with its scope registration),
 * the PDP with its emitter authorization and Exact claim domain, the
 * evidence store and its published key sets, the settlement verifier, and
 * the write reservations.
 *
 * The statement under test keeps the shipped version and appends one that
 * moves the payments PEP's boundary to {@link NEW}. Only `Date` is faked, so
 * the remote hop's timers stay real; only the OpenFGA client is stubbed, as
 * the other composed-stack tests do, so this file never skips.
 */

import { generateKeyPairSync, randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { exportJWK } from "jose";
import { afterAll, beforeAll, describe, expect, it, type MockInstance, vi } from "vitest";
import {
  BOUNDARY_UNPROVISIONED,
  CANONICAL_RESOURCE,
  credentialAuthorityFrom,
  evidenceKeySetLocation,
  type TokenFacts,
} from "@mission/mcp-payments";
import {
  type BoundaryEvidenceKeyAuthorization,
  type ClaimChannel,
  DECISION_EVIDENCE_MEDIA_TYPE,
  type EnforcementBoundaries,
  Fga,
  loadRuntimePosture,
  RUNTIME_POSTURE,
  type RuntimePosture,
  verifyEvidenceEnvelope,
} from "@mission/pdp";
import { approveDemoMission, composeStack, type DemoStack } from "../src/stack.js";

const NEW = "https://payments.example/mcp";
/** Ten minutes after the file loads: inside the demo Mission's lifetime, and never before the real clock. */
const CUTOVER_MS = Date.now() + 600_000;

const shipped = (RUNTIME_POSTURE.enforcement_boundaries as EnforcementBoundaries).versions[0] as EnforcementBoundaries["versions"][number];
const shippedKeys = (shipped.boundaries[0] as EnforcementBoundaries["versions"][number]["boundaries"][number]).evidence_keys;

/** The shipped statement with a declared change of the payments boundary to {@link NEW}, its keys `keys`. */
function changeTo(keys: readonly BoundaryEvidenceKeyAuthorization[]): RuntimePosture {
  return loadRuntimePosture({
    ...RUNTIME_POSTURE,
    mediated_scope: { ...RUNTIME_POSTURE.mediated_scope, resources: [...RUNTIME_POSTURE.mediated_scope.resources, NEW] },
    enforcement_boundaries: {
      versions: [
        shipped,
        {
          version: "payments-boundary-v2",
          effective_at: new Date(CUTOVER_MS).toISOString(),
          boundaries: [{ boundary: NEW, pep_locations: ["mcp-payments-pep"], audience_aliases: [], evidence_keys: keys }],
          replaces: [{ boundary: NEW, previous_version: shipped.version, previous_boundary: CANONICAL_RESOURCE }],
        },
      ],
    },
  });
}

/** One key the statement authorizes in `role` replaced by a rotated key this stack does not hold. */
const rotating = (role: "pdp" | "pep"): BoundaryEvidenceKeyAuthorization[] =>
  shippedKeys.map((k) => (k.role === role ? { ...k, kid: `${role}-rotated` } : { ...k }));

async function compose(pdpMode: "co-resident" | "remote", statement: RuntimePosture): Promise<DemoStack> {
  return composeStack({
    openfgaUrl: "http://unused.test",
    presharedKey: "unused",
    pdpMode,
    claimsFile: join(mkdtempSync(join(tmpdir(), "demo-claims-")), "claims.sqlite"),
    writeReservationsFile: join(mkdtempSync(join(tmpdir(), "demo-reservations-")), "write-reservations.sqlite"),
    resourcePolicyStore: { bootstrap: "development" },
    statement,
  });
}

async function close(stack: DemoStack): Promise<void> {
  await stack.reconciler.stop();
  await stack.decisionChannel.close();
  await stack.masGovernedChannel?.close();
  stack.pdpClaims.close();
  stack.writeReservations.close();
  stack.payments.db.close();
  stack.kernel.db.close();
}

function demoCredential(stack: DemoStack): { token: TokenFacts; missionId: string } {
  const mission = approveDemoMission(stack);
  const view = stack.viewFor(mission.id);
  if (!view) throw new Error("the demo Mission did not load");
  return {
    missionId: view.id,
    token: {
      sub: "alice",
      iss: stack.issuer,
      clientId: "ap-agent",
      cnfJkt: "jkt-853",
      mission: { id: view.id, issuer: view.issuer, authority_hash: view.authority_hash },
      credentialAuthority: credentialAuthorityFrom(view.authority_set),
    },
  };
}

const decisionsOf = (stack: DemoStack, missionId: string) =>
  stack.evidence
    .forMission(missionId)
    .filter((e) => e.kind === "decision")
    .map((e) => e.content as unknown as { audience: string });

const atLocation = (stack: DemoStack, boundary: string) =>
  stack.evidenceRetention.resolver({ locations: [evidenceKeySetLocation(boundary)] });

/** A declared change whose new version keeps the stack's keys, completed over `mode`. */
async function completeCutover(mode: "co-resident" | "remote"): Promise<void> {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(CUTOVER_MS - 60_000);
  const stack = await compose(mode, changeTo(shippedKeys));
  try {
    const { token, missionId } = demoCredential(stack);
    expect((await stack.server.callReadTool("get_invoice", { invoice_id: "inv-seed" }, token)).ok).toBe(true);
    const key = randomUUID();
    const scheduled = await stack.server.callWriteTool("schedule_payment", { invoice_id: "inv-seed", idempotency_key: key }, token);
    expect(scheduled.ok, JSON.stringify(scheduled)).toBe(true);

    vi.setSystemTime(CUTOVER_MS + 60_000);
    expect(stack.pep.boundary()).toEqual({ ok: true, boundary: NEW, version: "payments-boundary-v2" });
    // Over the remote hop this is the PDP's scope registration and operation-target registration at work.
    const read = await stack.server.callReadTool("get_invoice", { invoice_id: "inv-seed" }, token);
    expect(read.ok, JSON.stringify(read)).toBe(true);
    // The keyed write retried after the change meets its original disposition.
    const retried = await stack.server.callWriteTool("schedule_payment", { invoice_id: "inv-seed", idempotency_key: key }, token);
    expect(retried).toEqual({ ok: true, deduped: true, result: scheduled.result });
    expect(stack.writeReservations.schedules()).toHaveLength(1);
    // A high-consequence write at the new identifier settles its claim: its Execution Evidence
    // verifies under the settlement verifier, so the key's retry is refused as completed.
    let lastDecision: Record<string, unknown> | undefined;
    stack.onEnforce(({ decision }) => {
      lastDecision = decision.context;
    });
    const wireKey = `idem_${randomUUID()}`;
    const wired = await stack.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-seed", idempotency_key: wireKey }, token);
    expect(wired.ok, JSON.stringify(wired)).toBe(true);
    const rewired = await stack.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-seed", idempotency_key: wireKey }, token);
    expect(rewired).toMatchObject({ ok: false, denial_reason: "duplicate_suppressed" });
    expect(lastDecision).toMatchObject({ denial_reason: "duplicate_suppressed", next_action: "none" });

    const decisions = decisionsOf(stack, missionId);
    expect(decisions.map((d) => d.audience)).toEqual([CANONICAL_RESOURCE, CANONICAL_RESOURCE, NEW, NEW, NEW, NEW]);
    // Each record verifies under its own boundary's published key set, and never under the other.
    for (const d of decisions) {
      const other = d.audience === NEW ? CANONICAL_RESOURCE : NEW;
      expect(await verifyEvidenceEnvelope(d, DECISION_EVIDENCE_MEDIA_TYPE, atLocation(stack, d.audience))).toEqual({ valid: true });
      expect(await verifyEvidenceEnvelope(d, DECISION_EVIDENCE_MEDIA_TYPE, atLocation(stack, other))).toMatchObject({ valid: false });
    }
    if (mode === "remote") {
      // Settlement and reconciliation are scoped to the boundary in force: the request reaches the claim domain.
      const claims = (stack.decisionChannel as unknown as { claims: ClaimChannel }).claims;
      expect(await claims.reconcile(`dec_${randomUUID()}`, { kind: "unredeemed" })).toEqual({
        accepted: false,
        reason: "unknown_evaluation",
      });
    }
  } finally {
    vi.useRealTimers();
    await close(stack);
  }
}

describe("a declared change of boundary identifier through the composed stack (@spec runtime#boundary-identifier-change, #853)", () => {
  let fgaBootstrap: MockInstance;
  beforeAll(() => {
    fgaBootstrap = vi.spyOn(Fga, "bootstrap").mockResolvedValue({
      fga: { checkWithContext: async () => true, checkStored: async () => true, client: { write: async () => ({}) }, modelId: "test" } as unknown as Fga,
      storeId: "test",
      modelId: "test",
    });
  });
  afterAll(() => fgaBootstrap.mockRestore());

  it("moves every assembled consumer to the new identifier together over the co-resident channel, keeps old records verifiable and keyed writes deduplicated", async () => {
    await completeCutover("co-resident");
  });

  it("moves every assembled consumer to the new identifier together over the remote channel, keeps old records verifiable and keyed writes deduplicated", async () => {
    await completeCutover("remote");
  });

  it("holds the cutover while the settlement verifier lacks a key the new version authorizes, even with that key published", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(CUTOVER_MS - 60_000);
    const stack = await compose("co-resident", changeTo(rotating("pep")));
    try {
      const { token, missionId } = demoCredential(stack);
      expect((await stack.server.callReadTool("get_invoice", { invoice_id: "inv-seed" }, token)).ok).toBe(true);
      // The rotated key is published for the new boundary; the settlement verifier still does not hold it.
      stack.evidenceRetention.publishKey({
        location: evidenceKeySetLocation(NEW),
        kid: "pep-rotated",
        emitterId: CANONICAL_RESOURCE,
        role: "pep",
        audience: NEW,
        publicKey: await exportJWK(generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey),
      });
      vi.setSystemTime(CUTOVER_MS + 60_000);
      expect(stack.pep.boundaryContext.unprovisioned()).toEqual(["pdp-settlement-keys"]);
      const recorded = stack.evidence.forMission(missionId).length;
      expect(await stack.server.callReadTool("get_invoice", { invoice_id: "inv-seed" }, token)).toMatchObject({
        ok: false,
        refusal_reason: BOUNDARY_UNPROVISIONED,
      });
      expect(stack.evidence.forMission(missionId)).toHaveLength(recorded);
    } finally {
      vi.useRealTimers();
      await close(stack);
    }
  });

  it("holds the cutover while the new boundary's key set lacks a key the new version authorizes", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(CUTOVER_MS - 60_000);
    const stack = await compose("co-resident", changeTo(rotating("pdp")));
    try {
      const { token, missionId } = demoCredential(stack);
      expect((await stack.server.callReadTool("get_invoice", { invoice_id: "inv-seed" }, token)).ok).toBe(true);
      vi.setSystemTime(CUTOVER_MS + 60_000);
      expect(stack.pep.boundaryContext.unprovisioned()).toEqual(["published-evidence-keys"]);
      const recorded = stack.evidence.forMission(missionId).length;
      expect(await stack.server.callReadTool("get_invoice", { invoice_id: "inv-seed" }, token)).toMatchObject({
        ok: false,
        refusal_reason: BOUNDARY_UNPROVISIONED,
      });
      expect(stack.evidence.forMission(missionId)).toHaveLength(recorded);
      // The earlier boundary's set is untouched, and its record still verifies.
      const [before] = decisionsOf(stack, missionId);
      expect(await verifyEvidenceEnvelope(before, DECISION_EVIDENCE_MEDIA_TYPE, atLocation(stack, CANONICAL_RESOURCE))).toEqual({ valid: true });
    } finally {
      vi.useRealTimers();
      await close(stack);
    }
  });
});
