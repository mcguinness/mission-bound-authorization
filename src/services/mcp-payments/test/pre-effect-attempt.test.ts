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
  Connectors,
  createEphemeralEvidenceKeys,
  EVIDENCE_UNAVAILABLE_ERROR,
  EvidenceStore,
  McpPaymentsServer,
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

/** One executing PEP over a durable write-reservation file, and the PDP it asks. */
async function harness(reservationsFile = tempFile("pep-attempts-", "write-reservations.sqlite")) {
  const now = () => new Date();
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
  const evidence = new EvidenceStore(keys.signing, keys.resolver);
  const connectors = new Connectors(now);
  const writeReservations: WriteReservationStore = openWriteReservationStore({ file: reservationsFile, owner: PEP_LOCATION });
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
  });
  return {
    reservationsFile,
    connectors,
    evidence,
    writeReservations,
    server,
    close: async () => {
      await channel.close();
      claims.close();
      writeReservations.close();
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
    const postWire = h.connectors.postWire.bind(h.connectors);
    vi.spyOn(h.connectors, "postWire").mockImplementation((input) => {
      // What the PEP's file holds at the instant the effect is released.
      atCommit = h.writeReservations.attempts();
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
      // The completed record carries the instant the attempt was recorded.
      expect(completed?.attempted_at).toBe(new Date(atCommit?.[0]?.attemptedAtMs as number).toISOString());
    } finally {
      await h.close();
    }
    // The file outlives the process that wrote it.
    const reopened = openWriteReservationStore({ file: h.reservationsFile, owner: PEP_LOCATION });
    try {
      expect(reopened.attempts()).toEqual(atCommit);
    } finally {
      reopened.close();
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
