/**
 * @spec draft-mcguinness-mission-runtime.md#evidence (pre-effect durability)
 * (#821, D814): the transaction tier's attempt record, written before its
 * connector effect is released.
 *
 * Every case acts as the executing PEP, the component that releases the
 * effect: its real redemption store, connectors, evidence store and durable
 * write-reservation file, against a real PDP claim domain on a real file.
 * The FGA layer is a stub that always permits, so this file never skips.
 */

import { randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalDigest, type JsonValue } from "@mission/core";
import { DurableStoreError } from "@mission/store";
import {
  createDecisionChannel,
  createEphemeralDecisionPoint,
  type EvidenceKeyResolver,
  type Fga,
  type MissionView,
  openIdempotencyClaimDomain,
  relationForAction,
  RUNTIME_POSTURE,
  stalenessBound,
} from "@mission/pdp";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";
import { describe, expect, it, vi } from "vitest";
import {
  CANONICAL_RESOURCE,
  CollectingAlertSink,
  Connectors,
  createEphemeralEvidenceKeys,
  EVIDENCE_UNAVAILABLE_ERROR,
  EvidenceStore,
  McpPaymentsServer,
  openEvidenceRetentionStore,
  openWriteReservationStore,
  PaymentsStore,
  Pep,
  redemptionStatusFor,
  type TokenFacts,
  TransactionEngine,
  type WriteReservationStore,
} from "../src/index.js";
import { ALL_ACTIONS_CREDENTIAL } from "./credential-fixtures.js";

const MISSION = "msn_821";
const ISSUER = "https://as.test";
const PEP_LOCATION = "mcp-payments-pep";
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;
const key = (): string => `idem_${randomUUID()}`;
const tempFile = (prefix: string, name: string): string => join(mkdtempSync(join(tmpdir(), prefix)), name);

const TOKEN: TokenFacts = {
  sub: "alice",
  clientId: "ap-agent",
  mission: { id: MISSION, issuer: ISSUER, authority_hash: "sha-256:m821" },
  cnfJkt: "jkt-821",
  credentialAuthority: ALL_ACTIONS_CREDENTIAL,
};

const view = (): MissionView => ({
  id: MISSION,
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:m821",
  authority_set: [
    {
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:payment.execute"],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    },
  ],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
});

/**
 * One executing PEP over its durable files, and the PDP it asks: the
 * write-reservation file (attempt records) and the evidence retention file
 * (retained records and per-emitter sequences). A second harness on the same
 * files is a restarted PEP.
 */
async function harness(
  files: { reservations?: string; retention?: string; now?: () => Date } = {},
) {
  const reservationsFile = files.reservations ?? tempFile("pep-attempts-", "write-reservations.sqlite");
  const retentionFile = files.retention ?? tempFile("pep-retention-", "evidence-retention.sqlite");
  const now = files.now ?? (() => new Date());
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
  );
  const loadView = (ref: { id: string; issuer: string }) =>
    ref.id === MISSION && ref.issuer === ISSUER
      ? { view: view(), observation: { state: "active", version: 1, mode: "fresh", freshness_at: now().toISOString() } }
      : undefined;
  let pepKeys: EvidenceKeyResolver | undefined;
  const claims = openIdempotencyClaimDomain({
    file: tempFile("claims-821-", "claims.sqlite"),
    owner: RUNTIME_POSTURE.pdps[0] as string,
    statement: RUNTIME_POSTURE,
    settlementKeys: (params) => pepKeys?.(params),
    now,
  });
  const point = createEphemeralDecisionPoint({
    resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
    emitterId: CANONICAL_RESOURCE,
    audience: CANONICAL_RESOURCE,
    claims,
  });
  const keys = createEphemeralEvidenceKeys({ decisionPoint: point });
  pepKeys = keys.resolver;
  const engine = new TransactionEngine("epoch-821", now);
  const redemption = redemptionStatusFor(engine);
  const channel = await createDecisionChannel(point, {
    mode: "co-resident",
    pepId: PEP_LOCATION,
    audience: CANONICAL_RESOURCE,
    pepEpoch: redemption.epoch,
    consumptionStatus: redemption.status,
    redeemingExecution: redemption.redeemer,
    getOptions: () => ({
      view: view(),
      fga: alwaysAllowFga,
      modelId: "model-821",
      now,
      stalenessBound,
      relationForAction,
      stateSourcePlacement: "pep" as const,
    }),
  });
  const retention = openEvidenceRetentionStore({ file: retentionFile, owner: PEP_LOCATION, retentionWindowSeconds: 3_600, now });
  const evidence = new EvidenceStore(keys.signing, keys.resolver, retention);
  const connectors = new Connectors(now);
  const writeReservations: WriteReservationStore = openWriteReservationStore({ file: reservationsFile, owner: PEP_LOCATION, now });
  const alerts = new CollectingAlertSink();
  const pep = new Pep({
    decide: channel.decide,
    claims: channel.claims,
    payments,
    evidence,
    fga: alwaysAllowFga,
    modelId: "model-821",
    loadView,
    instanceEpoch: "epoch-821",
    now,
  });
  const server = new McpPaymentsServer({
    writeReservations,
    pep,
    payments,
    loadView,
    jwks: { keys: [] },
    keyRoles: { accessToken: [], attenuationRoot: [], transactionToken: [] },
    issuer: ISSUER,
    transaction: { engine, connectors, evidence },
    alerts,
  });
  return {
    reservationsFile,
    retentionFile,
    retention,
    alerts,
    payments,
    connectors,
    evidence,
    writeReservations,
    server,
    pep,
    close: async () => {
      await channel.close();
      claims.close();
      writeReservations.close();
      retention.close();
    },
  };
}
type Harness = Awaited<ReturnType<typeof harness>>;

const wire = (h: Harness, idempotencyKey: string) =>
  h.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: idempotencyKey }, TOKEN);

const executionsOf = (h: Harness) => h.evidence.all().flatMap((e) => (e.kind === "execution" ? [e.content] : []));
const decisionsOf = (h: Harness) => h.evidence.all().flatMap((e) => (e.kind === "decision" ? [e.content] : []));

describe("the transaction tier records each attempt before its effect (@spec runtime#evidence pre-effect durability, #821)", () => {
  it("before the connector commits, the attempt's operation identity and its retained Decision Evidence are recorded in the PEP's durable file, and a reopened file still names them", async () => {
    const h = await harness();
    let atCommit: ReturnType<WriteReservationStore["attempts"]> | undefined;
    let decisionAtCommit: string | undefined;
    const postWire = h.connectors.postWire.bind(h.connectors);
    vi.spyOn(h.connectors, "postWire").mockImplementation((input) => {
      // What the PEP's files hold at the instant the effect is released.
      atCommit = h.writeReservations.attempts();
      decisionAtCommit = h.retention.get("decision", atCommit[0]?.decisionEvidence.evidenceId ?? "")?.digest;
      return postWire(input);
    });
    try {
      const done = await wire(h, key());
      expect(done.ok).toBe(true);
      const [decision] = decisionsOf(h);
      const [completed] = executionsOf(h);
      const [entry] = h.connectors.ledgerEntries();
      expect(atCommit).toEqual([
        {
          executionId: completed?.execution_id,
          opKey: entry?.op_key,
          evaluationId: decision?.evaluation_id,
          missionId: MISSION,
          action: "payments:payment.execute",
          decisionEvidence: { evidenceId: decision?.evidence_id, digest: canonicalDigest(decision as unknown as JsonValue) },
          attemptedAtMs: expect.any(Number),
        },
      ]);
      // The permit's Decision Evidence was already in the retention file.
      expect(decisionAtCommit).toBe(canonicalDigest(decision as unknown as JsonValue));
      // The completed record carries the instant the attempt was recorded.
      expect(completed?.attempted_at).toBe(new Date(atCommit?.[0]?.attemptedAtMs as number).toISOString());
    } finally {
      await h.close();
    }
    // The files outlive the process that wrote them.
    const reopened = openWriteReservationStore({ file: h.reservationsFile, owner: PEP_LOCATION });
    const retained = openEvidenceRetentionStore({ file: h.retentionFile, owner: PEP_LOCATION, retentionWindowSeconds: 3_600 });
    try {
      expect(reopened.attempts()).toEqual(atCommit);
      const evidenceId = atCommit?.[0]?.decisionEvidence.evidenceId as string;
      expect(retained.get("decision", evidenceId)?.digest).toBe(atCommit?.[0]?.decisionEvidence.digest);
    } finally {
      reopened.close();
      retained.close();
    }
  });

  it("an attempt record that cannot be written prevents the effect: the action is refused, nothing reaches the connector, and the disposition is recorded suppressed", async () => {
    const h = await harness();
    const recordAttempt = vi.spyOn(h.writeReservations, "recordAttempt").mockImplementation(() => {
      throw new Error("SQLITE_FULL: database or disk is full");
    });
    try {
      const refused = await wire(h, key());
      expect(refused).toMatchObject({ ok: false, refusal_reason: "evidence_unavailable" });
      expect(recordAttempt).toHaveBeenCalledTimes(1);
      expect(h.connectors.ledgerEntries()).toEqual([]);
      expect(executionsOf(h).map((r) => [r.outcome, r.error])).toEqual([["suppressed", EVIDENCE_UNAVAILABLE_ERROR]]);
      expect(h.writeReservations.attempts()).toEqual([]);
    } finally {
      await h.close();
    }
  });
});

/** Fail every Execution Evidence write under `role` until restored. */
function failWrites(h: Harness, role: "pep" | "executor"): { restore: () => void } {
  const original = h.evidence.recordExecution.bind(h.evidence);
  const spy = vi.spyOn(h.evidence, "recordExecution").mockImplementation(async (emitterId, writeRole, input) => {
    if (writeRole === role) throw new Error("evidence store unavailable");
    return original(emitterId, writeRole, input);
  });
  return { restore: () => spy.mockRestore() };
}

describe("nothing slow sits between the last check and the effect (@spec runtime#execution-reverification, runtime#evidence, #821 review)", () => {
  /** A clock the test moves; the permit is valid 30 s and the published lease is 30 s. */
  const movable = () => {
    let at = Date.parse("2026-10-26T12:00:00.000Z");
    return { now: () => new Date(at), advance: (ms: number) => void (at += ms) };
  };

  it("a slow attempt write cannot release an effect after the lease: the clock passes the lease inside the write, and the action is refused permit_expired with zero effects and a suppressed disposition", async () => {
    const clock = movable();
    const h = await harness({ now: clock.now });
    const recordAttempt = h.writeReservations.recordAttempt.bind(h.writeReservations);
    vi.spyOn(h.writeReservations, "recordAttempt").mockImplementation((input) => {
      const recorded = recordAttempt(input);
      clock.advance(120_000); // the durable write takes 120 s
      return recorded;
    });
    try {
      const refused = await wire(h, key());
      expect(refused).toEqual({ ok: false, refusal_reason: "permit_expired" });
      expect(h.connectors.ledgerEntries()).toEqual([]);
      expect(executionsOf(h).map((r) => [r.outcome, r.error])).toEqual([["suppressed", "permit_expired"]]);
      // The attempt is recorded, and its disposition says it released nothing.
      expect(h.writeReservations.attempts().map((a) => a.executionId)).toEqual(executionsOf(h).map((r) => r.execution_id));
    } finally {
      await h.close();
    }
  });

  it("time that passes after the last awaited check still releases nothing: the permit and the lease are compared again, synchronously, before the connector call", async () => {
    const clock = movable();
    const h = await harness({ now: clock.now });
    const verify = h.pep.verifyPermitAtUse.bind(h.pep);
    let calls = 0;
    vi.spyOn(h.pep, "verifyPermitAtUse").mockImplementation(async (attempt) => {
      const outcome = await verify(attempt);
      calls += 1;
      // After the final awaited check passes, a store write that follows it
      // (the `txn` consumption, on a challenged operation) takes 120 s.
      if (calls === 2) clock.advance(120_000);
      return outcome;
    });
    try {
      const refused = await wire(h, key());
      expect(calls).toBe(2);
      expect(refused).toEqual({ ok: false, refusal_reason: "permit_expired" });
      expect(h.connectors.ledgerEntries()).toEqual([]);
      expect(executionsOf(h).map((r) => [r.outcome, r.error])).toEqual([["suppressed", "permit_expired"]]);
    } finally {
      await h.close();
    }
  });
});

describe("the PEP's per-Mission sequence across a restart (@spec runtime#record-integrity, #821)", () => {
  it("a PEP restarted on the same files continues its per-Mission sequence: no value is issued twice, a value it could not use stays a gap, and no second writer shares the store", async () => {
    // A request for an invoice the resource does not hold is refused before
    // any decision, with a Refusal Record the PEP signs under the Mission.
    const refuse = (h: Harness) =>
      h.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-404", idempotency_key: key() }, TOKEN);
    const refusals = (h: Harness) => h.evidence.all().flatMap((e) => (e.kind === "refusal" ? [e.content] : []));
    const first = await harness();
    let before: number[];
    try {
      await refuse(first);
      // A second process cannot act as this emitter on the same store: the
      // file refuses a second writer, so no replica allocates from it.
      expect(() =>
        openEvidenceRetentionStore({ file: first.retentionFile, owner: PEP_LOCATION, retentionWindowSeconds: 3_600 }),
      ).toThrow(DurableStoreError);
      // A record that cannot be retained takes its value with it: the value
      // is a gap, never issued again.
      vi.spyOn(first.retention, "retain").mockImplementationOnce(() => {
        throw new Error("SQLITE_FULL: database or disk is full");
      });
      await expect(refuse(first)).rejects.toThrow(/SQLITE_FULL/);
      await refuse(first);
      before = refusals(first).map((r) => r.sequence as number);
      expect(before).toHaveLength(2);
      expect(before[1]).toBeGreaterThan((before[0] as number) + 1);
    } finally {
      await first.close(); // the process dies
    }
    const restarted = await harness({ reservations: first.reservationsFile, retention: first.retentionFile });
    try {
      await refuse(restarted);
      const all = refusals(restarted).map((r) => r.sequence as number);
      // The first process's records came back from the file, and the new one
      // takes the next value: no value is issued twice for the Mission.
      expect(all).toEqual([...before, (before.at(-1) as number) + 1]);
      expect(new Set(all).size).toBe(all.length);
    } finally {
      await restarted.close();
    }
  });
});

describe("a transaction-tier disposition record that cannot be written is surfaced, never dropped (@spec runtime-evidence#execution-evidence-object, #821)", () => {
  it("a refusal after the permit whose suppressed record cannot be written still refuses, says the record is missing, and alerts the operator once; nothing executes", async () => {
    const h = await harness();
    try {
      // Another operation already settled the invoice, so the connector refuses this wire with no effect.
      const other = { opKey: "op:msn_other:payments:payment.execute:other", invoiceId: "inv-1", payeeAccount: "acct-acme", amount: "125.00", currency: "USD", permitId: "evl_other", missionId: "msn_other" };
      expect(h.connectors.postWire(other).committed).toBe(true);
      const failing = failWrites(h, "pep");
      const refused = await wire(h, key());
      failing.restore();
      expect(refused).toEqual({ ok: false, refusal_reason: "already_settled", gap: "emission_failed" });
      const [decision] = decisionsOf(h);
      expect(h.alerts.alerts).toEqual([
        {
          kind: "evidence_emission_failed",
          evaluation_id: decision?.evaluation_id,
          mission_id: MISSION,
          cause: "suppressed_disposition_unrecorded",
          at: expect.any(String),
        },
      ]);
      expect(executionsOf(h)).toEqual([]);
      expect(h.connectors.ledgerEntries().map((e) => e.op_key)).toEqual([other.opKey]);
    } finally {
      await h.close();
    }
  });

  it("an effect whose completed record cannot be written reports the gap with its result and alerts the operator once", async () => {
    const h = await harness();
    try {
      const failing = failWrites(h, "executor");
      const done = await wire(h, key());
      failing.restore();
      expect(done).toMatchObject({ ok: false, gap: "emission_failed" });
      expect(done).not.toHaveProperty("refusal_reason");
      const [decision] = decisionsOf(h);
      expect(h.alerts.alerts.map((a) => [a.kind, a.evaluation_id, a.cause])).toEqual([
        ["evidence_emission_failed", decision?.evaluation_id, "completed_disposition_unrecorded"],
      ]);
      expect(h.connectors.ledgerEntries()).toHaveLength(1);
    } finally {
      await h.close();
    }
  });

  it("the same holds at a reverification refusal and at a failed attempt write: each refusal carries the gap and one alert, and nothing executes", async () => {
    const h = await harness();
    try {
      // The invoice moves after the permit: reverification refuses target_drift.
      const failing = failWrites(h, "pep");
      const drifted = await h.server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: key() }, TOKEN, () =>
        h.payments.bumpInvoiceAmount("inv-1", "150.00"),
      );
      expect(drifted).toEqual({ ok: false, refusal_reason: "target_drift", gap: "emission_failed" });
      // The attempt record cannot be written: refused evidence_unavailable.
      h.payments.bumpInvoiceAmount("inv-1", "125.00");
      vi.spyOn(h.writeReservations, "recordAttempt").mockImplementation(() => {
        throw new Error("SQLITE_FULL: database or disk is full");
      });
      const unrecorded = await wire(h, key());
      failing.restore();
      expect(unrecorded).toEqual({ ok: false, refusal_reason: "evidence_unavailable", gap: "emission_failed" });
      expect(h.alerts.alerts.map((a) => [a.kind, a.cause])).toEqual([
        ["evidence_emission_failed", "suppressed_disposition_unrecorded"],
        ["evidence_emission_failed", "suppressed_disposition_unrecorded"],
      ]);
      expect(h.connectors.ledgerEntries()).toEqual([]);
    } finally {
      await h.close();
    }
  });

  it("a refusal whose suppressed record is written carries no gap and raises no alert", async () => {
    const h = await harness();
    try {
      const other = { opKey: "op:msn_other:payments:payment.execute:other", invoiceId: "inv-1", payeeAccount: "acct-acme", amount: "125.00", currency: "USD", permitId: "evl_other", missionId: "msn_other" };
      h.connectors.postWire(other);
      expect(await wire(h, key())).toEqual({ ok: false, refusal_reason: "already_settled" });
      expect(h.alerts.alerts).toEqual([]);
      expect(executionsOf(h).map((r) => r.outcome)).toEqual(["suppressed"]);
    } finally {
      await h.close();
    }
  });
});
