/**
 * @spec authzen#requestable-denials, authzen#context-approval (#2067, D1313):
 * where an `out_of_authority` denial is realized as a Mission expansion, the
 * fresh evaluation runs under the successor Mission, with the successor's
 * `context.mission` and a credential bound to it, and a permit rests on the
 * successor's authority. The expansion's approval is not an action-bound
 * approval: where policy gates the action on one, an approval bound to the
 * predecessor does not satisfy the gate under the successor.
 *
 * Cross-component: the PEP over a decision point holding the Access Request
 * Service's approval-state trust anchor. `fga` is a stub that always permits,
 * so this file never skips.
 */

import { randomUUID } from "node:crypto";
import { currentContractRef, pinnedToCurrentContract } from "@mission/demo-data";
import type { EvaluationRequest, Fga, MissionView } from "@mission/pdp";
import { approvalSignerFixture, RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  buildEffectiveParams,
  CANONICAL_RESOURCE,
  createEphemeralEvidenceKeys,
  EvidenceStore,
  parameterDigest,
  PaymentsStore,
  Pep,
  type TokenFacts,
} from "../src/index.js";
import { ALL_ACTIONS_CREDENTIAL } from "./credential-fixtures.js";

const ISSUER = "https://as.test";
const ACTION = "payments:payment.schedule";
const ARS = await approvalSignerFixture();
const EVIDENCE_KEYS = createEphemeralEvidenceKeys({
  resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
  approvalVerification: ARS.verification,
});
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;
const idem = (): string => `idem_${randomUUID()}`;
// date-literal: controlled-clock
const CLOCK_MS = Date.parse("2026-10-20T12:00:00Z");

beforeAll(() => {
  vi.useFakeTimers({ toFake: ["Date"], shouldAdvanceTime: true });
  vi.setSystemTime(CLOCK_MS);
});

afterAll(() => {
  vi.useRealTimers();
});

/** The predecessor's authority reads invoices only; the successor's adds the gated schedule action. */
const mission = (id: string, actions: string[], version = 1): MissionView => ({
  id,
  issuer: ISSUER,
  state: "active",
  version,
  authority_hash: `sha-256:${id}`,
  authority_set: actions.map((a) =>
    pinnedToCurrentContract({
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: [a],
      ...(a === ACTION ? { constraints: { requires_action_approval: true } } : {}),
    }),
  ),
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
});
const PREDECESSOR = mission("msn_2067_pre", ["payments:invoice.read"]);
const SUCCESSOR = mission("msn_2067_succ", ["payments:invoice.read", ACTION]);

/** A credential bound to `m`, as the authorization server issues one for it. */
const tokenFor = (m: MissionView): TokenFacts => ({
  sub: "alice",
  clientId: "ap-agent",
  mission: { id: m.id, issuer: m.issuer, authority_hash: m.authority_hash },
  cnfJkt: "jkt-1",
  credentialAuthority: ALL_ACTIONS_CREDENTIAL,
});

function harness() {
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
  );
  const views = new Map([PREDECESSOR, SUCCESSOR].map((v) => [`${v.issuer} ${v.id}`, v]));
  const decided: EvaluationRequest[] = [];
  const pep = new Pep({
    decide: (req, o) => {
      decided.push(req);
      return EVIDENCE_KEYS.decide(req, o);
    },
    payments,
    evidence: new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver),
    fga: alwaysAllowFga,
    modelId: "model-2067",
    // Both Missions resolve: the expansion created the successor beside the predecessor.
    loadView: (ref) => {
      const view = views.get(`${ref.issuer} ${ref.id}`);
      return view
        ? { view, observation: { state: view.state, version: view.version, mode: "fresh", freshness_at: new Date().toISOString() } }
        : undefined;
    },
    instanceEpoch: "epoch-2067",
  });
  const invoice = payments.getInvoice("inv-1");
  const vendor = invoice ? payments.getVendor(invoice.vendor_id) : undefined;
  if (!invoice || !vendor) throw new Error("seed missing");
  const digest = parameterDigest(buildEffectiveParams({ action: ACTION, invoice, vendor, resource: CANONICAL_RESOURCE }));
  const approvalFor = (m: MissionView) =>
    ARS.approve(
      {
        id: `apr_${m.id}`,
        approved_at: new Date().toISOString(),
        approved_until: new Date(Date.now() + 240_000).toISOString(),
        parameter_digest: digest,
        resource: { properties: { resource_contract: currentContractRef({ resource: CANONICAL_RESOURCE, actions: [ACTION] }) } },
      },
      { issuer: m.issuer, id: m.id },
    );
  return { pep, decided, approvalFor };
}

describe("re-evaluation after a Mission expansion runs under the successor (@spec authzen#requestable-denials, authzen#context-approval, #2067)", () => {
  it("the action out of the predecessor's authority is decided under the successor's context.mission and credential, and permitted on the successor's authority only with an approval bound to the successor", async () => {
    const h = harness();
    const args = () => ({ invoice_id: "inv-1", idempotency_key: idem() });
    // Under the predecessor the action is outside the Authority Set.
    const before = await h.pep.enforce("schedule_payment", args(), tokenFor(PREDECESSOR));
    expect(before).toMatchObject({ permitted: false, denial_reason: "out_of_authority" });
    // The expansion's approval supplies no action-bound approval: under the
    // successor the gated action still needs one.
    const gated = await h.pep.enforce("schedule_payment", args(), tokenFor(SUCCESSOR));
    expect(gated).toMatchObject({ permitted: false, denial_reason: "action_approval_required" });
    expect(h.decided.at(-1)?.context.mission).toMatchObject({ id: SUCCESSOR.id, issuer: SUCCESSOR.issuer });
    // A predecessor-bound action approval does not satisfy it.
    const predecessorBound = await h.pep.enforce("schedule_payment", args(), tokenFor(SUCCESSOR), await h.approvalFor(PREDECESSOR));
    expect(predecessorBound).toMatchObject({ permitted: false, denial_reason: "out_of_scope" });
    // One bound to the successor does, on the successor's authority.
    const permitted = await h.pep.enforce("schedule_payment", args(), tokenFor(SUCCESSOR), await h.approvalFor(SUCCESSOR));
    expect(permitted.permitted, JSON.stringify(permitted)).toBe(true);
    expect(h.decided.at(-1)?.context.mission).toMatchObject({ id: SUCCESSOR.id, issuer: SUCCESSOR.issuer });
  });
});
