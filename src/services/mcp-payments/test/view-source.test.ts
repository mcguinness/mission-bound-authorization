/**
 * @spec authority-server#mission-join rule 2, authzen#failure-condition-coverage (#818, D560)
 *
 * A PEP whose Mission state source is remote reads the referenced Mission
 * once, asynchronously, at the start of each enforcement
 * (`PepDeps.viewSource`); its synchronous `loadView` then answers from that
 * read. A read that established nothing refuses before any decision with the
 * source's reason, and a later synchronous read that finds the view lapsed
 * fails closed for its purpose. The FGA layer is a stub, so this file never
 * skips.
 */

import { authorityHash } from "@mission/core";
import { describe, expect, it } from "vitest";
import { committedEntry, type Fga, type MissionView, viewHoldsCommittedSet } from "@mission/pdp";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";
import {
  CANONICAL_RESOURCE,
  createEphemeralEvidenceKeys,
  credentialAuthorityFrom,
  EvidenceStore,
  McpPaymentsServer,
  type MissionViewSource,
  openEphemeralWriteReservationStore,
  PaymentsStore,
  Pep,
  type TokenFacts,
  type ViewPreparation,
} from "../src/index.js";

const EVIDENCE_KEYS = createEphemeralEvidenceKeys({ resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE });
const MISSION = "msn_view_source";
const ISSUER = "https://mas.test";
const READS = ["payments:invoice.read", "payments:invoice.list"];

/** No `vendors` constraint, so a list read's scope is every vendor, recomputable from no view at all. */
const VIEW: MissionView = {
  id: MISSION,
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:view-source",
  authority_set: [{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: READS }],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
};

function harness(opts: { source?: (ref: { id: string; issuer: string }) => ViewPreparation; view?: MissionView; credentialActions?: string[] }) {
  const view = opts.view ?? VIEW;
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct", status: "payable" }],
  );
  const state = { available: true, decisions: 0, prepared: [] as Array<{ id: string; issuer: string }> };
  const loadView = (ref: { id: string; issuer: string }) =>
    state.available && ref.id === MISSION && ref.issuer === ISSUER
      ? { view, observation: { state: view.state, version: view.version, mode: "fresh", freshness_at: new Date().toISOString() } }
      : undefined;
  const viewSource: MissionViewSource | undefined = opts.source
    ? {
        prepare: async (ref) => {
          state.prepared.push(ref);
          return (opts.source as NonNullable<typeof opts.source>)(ref);
        },
      }
    : undefined;
  const evidence = new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver);
  const pep = new Pep({
    decide: async (req, options) => {
      state.decisions++;
      return EVIDENCE_KEYS.decide(req, options);
    },
    payments,
    evidence,
    fga: { checkWithContext: async () => true } as unknown as Fga,
    modelId: "view-source-model",
    loadView,
    ...(viewSource ? { viewSource } : {}),
    instanceEpoch: "epoch-view-source",
  });
  const server = new McpPaymentsServer({
    pep,
    payments,
    loadView,
    jwks: { keys: [] },
    keyRoles: { accessToken: [], attenuationRoot: [], transactionToken: [] },
    issuer: ISSUER,
    writeReservations: openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" }),
  });
  const token: TokenFacts = {
    sub: "alice",
    clientId: "ap-agent",
    mission: { id: MISSION, issuer: ISSUER, authority_hash: view.authority_hash },
    cnfJkt: "jkt-view-source",
    credentialAuthority: credentialAuthorityFrom([{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: opts.credentialActions ?? READS }]),
  };
  return { server, evidence, state, token };
}

describe("a remote Mission view source at the PEP (#818, D560)", () => {
  it("refuses a read the source could not establish before any decision, with the source's reason on a signed Refusal Record", async () => {
    for (const refusal of ["state_unavailable", "unknown_mission"] as const) {
      const h = harness({ source: () => ({ ok: false, refusal }) });
      h.state.available = false;
      const res = await h.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, h.token);
      expect(res, refusal).toMatchObject({ ok: false, refusal_reason: refusal });
      expect(h.state.decisions, refusal).toBe(0);
      expect(h.state.prepared, refusal).toEqual([{ id: MISSION, issuer: ISSUER }]);
      const records = h.evidence.all().filter((e) => e.kind === "refusal");
      expect(records.map((e) => (e.kind === "refusal" ? e.content.denial_reason : undefined)), refusal).toEqual(["state_unavailable"]);
    }
    // Control: with no source the in-process miss is unknown_mission, as before.
    const local = harness({});
    local.state.available = false;
    expect(await local.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, local.token)).toMatchObject({
      ok: false,
      refusal_reason: "unknown_mission",
    });
  });

  it("proposes a never-granted action back only where the view proves it holds the committed set (#818 slice 4b review)", async () => {
    const entries = VIEW.authority_set;
    // The committed set itself: authority_hash recomputes over the view's entries.
    const complete: MissionView = { ...VIEW, authority_hash: authorityHash(ISSUER, entries.map(committedEntry) as never) };
    // An effective projection: the issuer committed one more action than the view carries.
    const projected: MissionView = {
      ...VIEW,
      authority_hash: authorityHash(ISSUER, [{ ...committedEntry(entries[0] as never), actions: [...READS, "payments:vendor.read"] }] as never),
    };
    expect(viewHoldsCommittedSet(complete)).toBe(true);
    expect(viewHoldsCommittedSet(projected)).toBe(false);
    const remediationFor = async (view: MissionView, source: boolean) => {
      // The credential carries the action; the Mission does not.
      const h = harness({ view, credentialActions: [...READS, "payments:vendor.read"], ...(source ? { source: () => ({ ok: true }) } : {}) });
      const res = await h.server.callReadTool("lookup_vendor", { vendor_id: "acme" }, h.token);
      expect(res, JSON.stringify(res)).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
      return res.insufficient_authorization;
    };
    expect(await remediationFor(complete, true)).toBeDefined();
    expect(await remediationFor(projected, true)).toBeUndefined();
    // An in-process loader's view is read as the committed set, as before.
    expect(await remediationFor(projected, false)).toBeDefined();
  });

  it("a list read whose view lapses between the decision and its re-verification is suppressed target_drift, recording no observation it did not make", async () => {
    const h = harness({ source: () => ({ ok: true }) });
    const res = await h.server.callReadTool("list_invoices", {}, h.token, () => {
      h.state.available = false;
    });
    expect(res).toMatchObject({ ok: false, refusal_reason: "target_drift" });
    expect(h.state.decisions).toBe(1);
    // The suppression could not observe the effective parameters, so no
    // Execution Evidence asserts an observation.
    expect(h.evidence.all().filter((e) => e.kind === "execution")).toEqual([]);
    // Control: the same read with the view still in place executes.
    const ok = harness({ source: () => ({ ok: true }) });
    expect(await ok.server.callReadTool("list_invoices", {}, ok.token)).toMatchObject({ ok: true });
  });
});
