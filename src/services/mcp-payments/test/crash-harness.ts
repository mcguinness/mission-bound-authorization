/**
 * @spec runtime#evidence (pre-effect durability, outcome reconciliation)
 * (#821 review P2-2): one executing PEP and the PDP it asks, on durable files,
 * for the crash witnesses in `pre-effect-crash.test.ts`. The child process the
 * test kills and the fresh process that reopens the files after it build the
 * same composition from the same three files: the PDP's claim file, and the
 * PEP's write-reservation file (attempt records) and evidence retention file
 * (retained records and sequences). Everything else is in memory and dies with
 * its process, the connector ledger included. Not a test file.
 */

import { generateKeyPairSync } from "node:crypto";
import {
  createDecisionChannel,
  createDecisionPoint,
  type EvidenceKeyResolver,
  type Fga,
  type MissionView,
  openIdempotencyClaimDomain,
  relationForAction,
  RUNTIME_POSTURE,
  stalenessBound,
} from "@mission/pdp";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";
import {
  CANONICAL_RESOURCE,
  CollectingAlertSink,
  Connectors,
  createEphemeralEvidenceKeys,
  EvidenceStore,
  indeterminateClaimAlert,
  McpPaymentsServer,
  openEvidenceRetentionStore,
  openWriteReservationStore,
  OutcomeReconciler,
  PaymentsStore,
  Pep,
  redemptionStatusFor,
  type TokenFacts,
  TransactionEngine,
} from "../src/index.js";
import { ALL_ACTIONS_CREDENTIAL } from "./credential-fixtures.js";
import { pinnedToCurrentContract } from "@mission/demo-data";

export const CRASH_MISSION = "msn_821_crash";
const ISSUER = "https://as.test";
const PEP_LOCATION = "mcp-payments-pep";
/** The instant the killed child runs at. */
export const CRASH_BASE_MS = Date.parse("2026-10-26T12:00:00.000Z");
/** The permit's `valid_until` (30 s), its lease (30 s), then the PT15M window. */
export const CRASH_WINDOW_CLOSE_MS = CRASH_BASE_MS + 30_000 + 30_000 + 15 * 60_000;
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

export const CRASH_TOKEN: TokenFacts = {
  sub: "alice",
  clientId: "ap-agent",
  mission: { id: CRASH_MISSION, issuer: ISSUER, authority_hash: "sha-256:m821crash" },
  cnfJkt: "jkt-821-crash",
  credentialAuthority: ALL_ACTIONS_CREDENTIAL,
};

const view = (): MissionView => ({
  id: CRASH_MISSION,
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:m821crash",
  authority_set: [
    pinnedToCurrentContract({
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:payment.execute"],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    }),
  ],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
});

export interface CrashFiles {
  claims: string;
  reservations: string;
  retention: string;
}

/** One process of the composition on `files`, on the clock `now`. */
export async function crashProcess(files: CrashFiles, now: () => Date) {
  const alerts = new CollectingAlertSink();
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
  );
  const loadView = (ref: { id: string; issuer: string }) =>
    ref.id === CRASH_MISSION && ref.issuer === ISSUER
      ? { view: view(), observation: { state: "active", version: 1, mode: "fresh", freshness_at: now().toISOString() } }
      : undefined;
  let pepKeys: EvidenceKeyResolver | undefined;
  const claims = openIdempotencyClaimDomain({
    file: files.claims,
    owner: RUNTIME_POSTURE.pdps[0] as string,
    statement: RUNTIME_POSTURE,
    now,
    settlementKeys: (params) => pepKeys?.(params),
    onIndeterminate: (claim) => alerts.alert(indeterminateClaimAlert(claim)),
  });
  // The PDP as composeStack binds it: its Decision Evidence counters in its
  // own claim file, with a key generated per boot.
  const pdpKey = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const point = createDecisionPoint({
    evidence: {
      signer: { kid: "pdp-decision-evidence", key: pdpKey.privateKey },
      verificationKey: pdpKey.publicKey,
      emitterId: CANONICAL_RESOURCE,
      audience: CANONICAL_RESOURCE,
      sequences: claims.evidenceSequences(),
    },
    resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
    claims,
  });
  const keys = createEphemeralEvidenceKeys({ decisionPoint: point });
  pepKeys = keys.resolver;
  const engine = new TransactionEngine("epoch-821-crash", now);
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
      modelId: "model-821-crash",
      now,
      stalenessBound,
      relationForAction,
      stateSourcePlacement: "pep" as const,
    }),
  });
  const retention = openEvidenceRetentionStore({ file: files.retention, owner: PEP_LOCATION, retentionWindowSeconds: 3_600, now });
  const evidence = new EvidenceStore(keys.signing, keys.resolver, retention);
  const connectors = new Connectors(now);
  const writeReservations = openWriteReservationStore({ file: files.reservations, owner: PEP_LOCATION, now });
  const pep = new Pep({
    decide: channel.decide,
    claims: channel.claims,
    payments,
    evidence,
    fga: alwaysAllowFga,
    modelId: "model-821-crash",
    loadView,
    instanceEpoch: "epoch-821-crash",
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
  const reconciler = new OutcomeReconciler({
    statement: RUNTIME_POSTURE,
    component: PEP_LOCATION,
    claims: channel.claims,
    evidence,
    redemption,
    connectors,
    writeReservations,
    alerts,
    now,
  });
  return {
    alerts,
    connectors,
    evidence,
    retention,
    writeReservations,
    server,
    reconciler,
    wire: (idempotencyKey: string) =>
      server.callTransactionTool("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: idempotencyKey }, CRASH_TOKEN),
    close: async () => {
      await reconciler.stop();
      await channel.close();
      claims.close();
      writeReservations.close();
      retention.close();
    },
  };
}
