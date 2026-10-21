import { APPROVAL_FLOOR, DERIVATION_POLICY, WRITE_ACTIONS } from "@mission/demo-data";
import { type CryptoKey, generateKeyPair } from "jose";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  type AuthorityEntry,
  type AuthoritySourceCatalog,
  directApprovalRuleFrom,
  type GovernedPolicyRoot,
  recheckApprovalGovernanceRecord,
  DELIVERY_CLAIM_STALE_S,
  MissionApprovalDeferralError,
  MissionApprovalDeferralStore,
  type MissionApprovalDeferralOptions,
  MissionKernel,
  type ModelAdvisorRequest,
  recordGovernedPolicyConsent,
  type RegisteredActivationPolicy,
  validateMissionIntent,
} from "../src/index.js";

/**
 * @spec deferred-approval#policy-completion: a pending Mission approval
 * completed under the `governed_policy` basis. The issuer selects a
 * configured governed policy whose root admits the proposal; the policy
 * decides at the creation commit; a refused evaluation creates no Mission and
 * leaves the approval for a full `direct` human approval (or denies it); each
 * pending approval resolves under one approval event.
 */

const ISS = "https://as.test";
const T0 = Date.parse("2026-07-01T00:00:00Z");
let clockMs = T0;
const now = () => new Date(clockMs);

let key: CryptoKey;
let seq = 0;

beforeAll(async () => {
  key = (await generateKeyPair("ES256")).privateKey;
});

beforeEach(() => {
  clockMs = T0;
});

const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
const DEPLOYMENT_CEILING = DERIVATION_POLICY.ceiling as unknown as AuthorityEntry[];
const JKT = "jkt-svc-agent";

const readEntry = (actions = ["payments:invoice.list", "payments:invoice.read", "payments:vendor.read"]): AuthorityEntry => ({
  type: "mission_resource_access",
  resource: RESOURCE,
  actions,
  constraints: { vendors: ["acme"] },
});

const catalog = (): AuthoritySourceCatalog => ({
  humanPrincipals: ["alice", "bob", "dana"],
  entries: [
    {
      id: "reconciler",
      type: "service_owned",
      clients: ["svc-agent", "svc-other"],
      subjects: ["svc-reconciler"],
      activators: ["dana"],
      principals: ["svc-reconciler"],
      ceiling: DEPLOYMENT_CEILING,
    },
  ],
});

const rootDoc = (over: Partial<GovernedPolicyRoot> = {}): GovernedPolicyRoot => ({
  admits: { clients: ["svc-agent"], subjects: ["svc-reconciler"], authority_sources: ["service_owned"] },
  authority_ceiling: [readEntry()],
  lifetime: { max_lifetime_s: 3600 },
  rules: { max_entries: 3 },
  recency: { ceilings: { default: 30 * 86400 }, clock_skew_s: 60 },
  classification: {
    standard: [
      "payments:invoice.list",
      "payments:invoice.read",
      "payments:vendor.read",
      "payments:payment.schedule",
      "payments:payment.schedule.cancel",
    ],
    irreversible_action: ["payments:payment.execute"],
    external_commitment: ["payments:remittance.send"],
  },
  ...over,
});

const held = (doc: GovernedPolicyRoot): RegisteredActivationPolicy => ({
  version: "1",
  content_type: "application/json",
  content: JSON.stringify(doc),
});

const setup = (
  roots: Record<string, GovernedPolicyRoot> = { "urn:root:reconciler": rootDoc() },
  opts: MissionApprovalDeferralOptions = {},
  kernelOpts: Partial<ConstructorParameters<typeof MissionKernel>[0]> = {},
) => {
  const kernel = new MissionKernel({
    issuer: ISS,
    policy: DERIVATION_POLICY as never,
    statusKey: key,
    statusKid: "as-status",
    authoritySourceCatalog: catalog() as never,
    governedPolicyApproval: {
      roots: Object.fromEntries(Object.entries(roots).map(([id, doc]) => [id, held(doc)])),
      approvers: Object.fromEntries(Object.keys(roots).map((id) => [id, ["dana"]])),
    },
    now,
    ...kernelOpts,
  });
  const consents = Object.keys(roots).map((id) =>
    recordGovernedPolicyConsent(kernel, {
      root: { id, version: "1" },
      approver: { iss: ISS, sub: "dana" },
      consentEventId: `gpce-${seq++}`,
    }),
  );
  return { kernel, consents, store: new MissionApprovalDeferralStore(kernel, { now, ...opts }) };
};

const intent = (over: Record<string, unknown> = {}) =>
  validateMissionIntent(
    JSON.stringify({ goal: "Reconcile Acme invoices", target_resources: [RESOURCE], expires_at: "2027-01-01T00:00:00Z", ...over }),
    { now: now() },
  );

const open = (store: MissionApprovalDeferralStore, over: Record<string, unknown> = {}) =>
  store.open({ intent: intent(), clientId: "svc-agent", jkt: JKT, ...over } as never).deferral_code;

const presenter = { clientId: "svc-agent", jkt: JKT };
const DANA = { iss: ISS, sub: "dana" };
const SUBJECT = { iss: ISS, sub: "svc-reconciler" };

describe("deferred approval policy completion (@spec deferred-approval#policy-completion)", () => {
  it("completes a pending proposal under a configured governed policy whose root admits it, never one the client names", async () => {
    const { kernel, consents, store } = setup({
      "urn:root:other-client": rootDoc({ admits: { clients: ["svc-other"], subjects: ["svc-reconciler"], authority_sources: ["service_owned"] } }),
      "urn:root:reconciler": rootDoc(),
    });
    const [otherClient, admitting] = consents as [{ consent_id: string; root: { id: string } }, { consent_id: string; root: { id: string } }];
    // A client-supplied selector rides nowhere: the store records none.
    const code = open(store, { consentId: otherClient.consent_id, approval_basis: "governed_policy", policy: otherClient.root });
    const result = await store.completeByPolicy(code);
    expect(result.outcome).toBe("approved");
    if (result.outcome !== "approved" || result.mission.approval_basis.type !== "governed_policy") throw new Error("approved");
    expect(result.mission.approval_basis.adjudication.policy.id).toBe(admitting.root.id);
    expect(result.record.approval_policy.id).toBe("urn:root:reconciler");
    expect(result.mission.approval_event_id).toBe(store.approvalEventId(code));
    expect(store.state(code)).toBe("approved");
    expect(kernel.allMissions()).toHaveLength(1);
  });

  it("creates no Mission when the evaluation does not authorize activation, leaving the approval pending or, when configured, denied", async () => {
    const refusing = rootDoc({ rules: { max_entries: 3, require_purpose: true } });
    const awaiting = setup({ "urn:root:reconciler": refusing });
    const code = open(awaiting.store);
    expect(await awaiting.store.completeByPolicy(code)).toEqual({ outcome: "not_authorized", reason: "purpose_required", state: "pending" });
    expect(awaiting.kernel.allMissions()).toHaveLength(0);
    expect(awaiting.kernel.governanceRecords.count()).toBe(0);
    expect(awaiting.store.state(code)).toBe("pending");
    expect(awaiting.store.resolutionReason(code)).toBe("purpose_required");
    clockMs += 10_000;
    expect(awaiting.store.poll(code, presenter)).toMatchObject({ error: "authorization_pending" });

    const denying = setup({ "urn:root:reconciler": refusing }, { onPolicyRefusal: "deny" });
    const denied = open(denying.store);
    expect(await denying.store.completeByPolicy(denied)).toEqual({ outcome: "not_authorized", reason: "purpose_required", state: "denied" });
    expect(denying.kernel.allMissions()).toHaveLength(0);
    expect(denying.store.poll(denied, presenter)).toEqual({ error: "access_denied" });

    // With no eligible policy at all, nothing activates either.
    const none = setup({ "urn:root:reconciler": rootDoc({ admits: { clients: ["svc-other"], subjects: ["svc-reconciler"], authority_sources: ["service_owned"] } }) });
    const unmatched = open(none.store);
    expect(await none.store.completeByPolicy(unmatched)).toEqual({ outcome: "not_authorized", reason: "no_eligible_policy", state: "pending" });
    expect(none.kernel.allMissions()).toHaveLength(0);
  });

  it("makes a human approval after a refused evaluation a direct approval event, never a governed_policy activation", async () => {
    const { kernel, store } = setup({ "urn:root:reconciler": rootDoc({ rules: { max_entries: 3, require_purpose: true } }) });
    const code = open(store);
    expect((await store.completeByPolicy(code)).outcome).toBe("not_authorized");
    const mission = store.approveDirect(code, { approver: DANA, subject: SUBJECT });
    expect(mission.approval_basis).toEqual({
      type: "direct",
      consent_principal: DANA,
      activation: { approval_event_id: store.approvalEventId(code) },
      activation_actor: DANA,
      root_commitment: mission.authority_hash,
    });
    expect(mission.approval_basis).not.toHaveProperty("adjudication");
    expect(kernel.governanceRecords.forMission(mission.id)).toBeUndefined();
    // The settled approval admits no later policy completion.
    expect(await store.completeByPolicy(code)).toEqual({ outcome: "not_pending", state: "approved" });
    expect(kernel.allMissions()).toHaveLength(1);
    expect(kernel.governanceRecords.count()).toBe(0);
  });

  it("records a reviewer's direct approval where the deployment records direct approvals, and refuses one without the reviewer's authentication (@spec approval-governance#atomic-commitment, #1470)", () => {
    const rule = directApprovalRuleFrom({
      floor: APPROVAL_FLOOR,
      knownSubjects: new Set(["svc-reconciler"]),
      approverApprovesFor: new Map([["dana", new Set(["svc-reconciler"])]]),
      approverRoleSubs: new Set(["dana"]),
      writeActions: WRITE_ACTIONS,
    });
    const { kernel, store } = setup(undefined, {}, { directApprovalRecording: { rule } });
    const code = open(store);
    expect(() => store.approveDirect(code, { approver: DANA, subject: SUBJECT })).toThrow(/needs the authentication the approval surface verified/);
    expect(kernel.allMissions()).toHaveLength(0);
    expect(kernel.governanceRecords.count()).toBe(0);
    expect(store.state(code)).toBe("pending");
    const authentication = { acr: "mfa", auth_time: Math.floor(clockMs / 1000) - 10, interactive: true };
    const mission = store.approveDirect(code, { approver: DANA, subject: SUBJECT, authentication });
    expect(kernel.governanceRecords.forMission(mission.id)?.assertions).toEqual([
      expect.objectContaining({ kind: "human", principal: DANA, authority: { auth_time: new Date(authentication.auth_time * 1000).toISOString(), acr: "mfa" } }),
    ]);
    expect(recheckApprovalGovernanceRecord(kernel, mission.id, { resolveKey: () => kernel.statusVerificationKey() })).toEqual({ rechecked: true });
  });

  it("resolves retried and concurrent completions of one pending approval to one Mission and one record", async () => {
    const advisor = vi.fn(async (_r: ModelAdvisorRequest) => {
      await new Promise((r) => setTimeout(r, 5));
      return [];
    });
    const { kernel, store } = setup(undefined, { modelAdvisor: advisor });
    const code = open(store);
    const [a, b] = await Promise.all([store.completeByPolicy(code), store.completeByPolicy(code)]);
    expect(advisor).toHaveBeenCalledTimes(2);
    if (a.outcome !== "approved" || b.outcome !== "approved") throw new Error(`${a.outcome} ${b.outcome}`);
    expect(b.mission.id).toBe(a.mission.id);
    expect(b.record).toEqual(a.record);
    const retry = await store.completeByPolicy(code);
    expect(retry.outcome === "approved" && retry.mission.id).toBe(a.mission.id);
    expect(kernel.allMissions()).toHaveLength(1);
    expect(kernel.governanceRecords.count()).toBe(1);

    // A human approval that lands while a policy completion awaits its model
    // settles the approval; the policy completion then creates nothing.
    const raced = setup(undefined, { modelAdvisor: advisor });
    const racedCode = open(raced.store);
    const pending = raced.store.completeByPolicy(racedCode);
    const human = raced.store.approveDirect(racedCode, { approver: DANA, subject: SUBJECT });
    expect(await pending).toEqual({ outcome: "not_pending", state: "approved" });
    expect(raced.kernel.allMissions().map((m) => m.id)).toEqual([human.id]);
    expect(raced.kernel.governanceRecords.count()).toBe(0);
  });

  it("keeps polling, cancellation, client binding, and single delivery for a policy-completed approval", async () => {
    const { kernel, store } = setup();
    const code = open(store);
    expect(store.poll(code, presenter)).toMatchObject({ error: "authorization_pending", deferral_code: code });
    expect(store.poll(code, presenter)).toMatchObject({ error: "slow_down" });
    expect(store.poll(code, { ...presenter, clientId: "svc-other" })).toEqual({ error: "invalid_grant" });
    expect(store.poll(code, { ...presenter, jkt: "another-key" })).toEqual({ error: "invalid_dpop_proof" });
    expect(store.poll(code, { clientId: "svc-other", jkt: "another-key" })).toEqual({ error: "invalid_grant" });
    const done = await store.completeByPolicy(code);
    if (done.outcome !== "approved") throw new Error(done.outcome);
    // Delivered once, to the bound client and key only.
    expect(store.poll(code, { ...presenter, clientId: "svc-other" })).toEqual({ error: "invalid_grant" });
    const claim = store.poll(code, presenter);
    expect(claim).toEqual({ mission: kernel.get(done.mission.id), delivery: expect.stringMatching(/^dlv_/) });
    if (!("delivery" in claim)) throw new Error("no claim");
    expect(store.confirmDelivery(code, claim.delivery)).toBe("confirmed");
    expect(store.poll(code, presenter)).toEqual({ error: "invalid_grant" });

    // Cancellation by the bound client only; a cancelled approval completes nothing.
    const cancelled = open(store);
    expect(store.cancel(cancelled, "svc-other")).toBe(false);
    expect(store.cancel(cancelled, "svc-agent")).toBe(true);
    expect(await store.completeByPolicy(cancelled)).toEqual({ outcome: "not_pending", state: "cancelled" });
    // The deferred substrate's polling rule: a cancelled request is access_denied.
    expect(store.poll(cancelled, presenter)).toEqual({ error: "access_denied" });

    // The pending lifetime still bounds it.
    const lapsed = open(store);
    clockMs += 601_000;
    expect(store.poll(lapsed, presenter)).toEqual({ error: "expired_token" });
    expect(await store.completeByPolicy(lapsed)).toEqual({ outcome: "not_pending", state: "expired" });
    expect(kernel.allMissions()).toHaveLength(1);
  });

  it("leaves the approval pending with no Mission and nothing to deliver when the record cannot be signed", async () => {
    const { kernel, store } = setup();
    const code = open(store);
    const sign = vi.spyOn(kernel, "statusSigner").mockImplementation(() => {
      throw new Error("signing key unavailable");
    });
    await expect(store.completeByPolicy(code)).rejects.toThrow(/signing key unavailable/);
    sign.mockRestore();
    expect(kernel.allMissions()).toHaveLength(0);
    expect(kernel.governanceRecords.count()).toBe(0);
    expect(store.state(code)).toBe("pending");
    expect(store.poll(code, presenter)).toMatchObject({ error: "authorization_pending" });
    // Completion succeeds once the fault clears, under the same event.
    const done = await store.completeByPolicy(code);
    expect(done.outcome === "approved" && done.mission.approval_event_id).toBe(store.approvalEventId(code));
  });

  it("denies, with no Mission, an approval whose requested expiry passed while it pended", async () => {
    const { kernel, store } = setup(undefined, { pendingLifetimeS: 7200 });
    const code = open(store, { intent: intent({ expires_at: new Date(T0 + 60_000).toISOString() }) });
    clockMs = T0 + 61_000;
    expect(await store.completeByPolicy(code)).toEqual({ outcome: "not_authorized", reason: "mission_expiry_passed", state: "denied" });
    expect(() => store.approveDirect(code, { approver: DANA, subject: SUBJECT })).toThrow(MissionApprovalDeferralError);
    expect(kernel.allMissions()).toHaveLength(0);
    expect(store.poll(code, presenter)).toEqual({ error: "access_denied" });
  });
});

describe("deferred approval store bounds and cancellation (@spec deferred-approval#queue-pressure, deferred-approval#state-machine)", () => {
  it("refuses a client's further submissions at its pending bound until the queue drains, other clients unaffected", () => {
    const { store } = setup(undefined, { maxPendingPerClient: 2 });
    const first = open(store);
    open(store);
    expect(() => open(store)).toThrow(expect.objectContaining({ code: "queue_full" }));
    // Another client has its own bound.
    expect(open(store, { clientId: "svc-other" })).toMatch(/^mdfr_/);
    // A cancellation drains one place; a lapsed approval no longer counts.
    expect(store.cancel(first, "svc-agent")).toBe(true);
    const third = open(store);
    expect(() => open(store)).toThrow(expect.objectContaining({ code: "queue_full" }));
    clockMs += 601_000;
    expect(open(store)).toMatch(/^mdfr_/);
    expect(store.state(third)).toBe("expired");
  });

  it("treats a cancellation after approval but before delivery as redeemed and then cancelled", async () => {
    const { kernel, store } = setup();
    const code = open(store);
    const done = await store.completeByPolicy(code);
    if (done.outcome !== "approved") throw new Error(done.outcome);
    expect(store.cancel(code, "svc-other")).toBe(false);
    expect(store.cancel(code, "svc-agent")).toBe(true);
    expect(store.poll(code, presenter)).toEqual({ error: "access_denied" });
    expect(store.poll(code, presenter)).toEqual({ error: "access_denied" });
    // The Mission exists, but nothing was delivered for it.
    expect(kernel.get(done.mission.id)?.grant_id).toBeNull();

    // After delivery, a cancellation changes nothing.
    const delivered = open(store);
    await store.completeByPolicy(delivered);
    const claim = store.poll(delivered, presenter);
    if (!("delivery" in claim)) throw new Error("no claim");
    expect(store.confirmDelivery(delivered, claim.delivery)).toBe("confirmed");
    expect(store.cancel(delivered, "svc-agent")).toBe(false);
    expect(store.poll(delivered, presenter)).toEqual({ error: "invalid_grant" });

    // A cancellation while a delivery is in flight: the claim cannot
    // confirm, so the credential is never sent.
    const racing = open(store);
    await store.completeByPolicy(racing);
    const inFlight = store.poll(racing, presenter);
    if (!("delivery" in inFlight)) throw new Error("no claim");
    expect(store.cancel(racing, "svc-agent")).toBe(true);
    expect(store.confirmDelivery(racing, inFlight.delivery)).toBe("cancelled");
    expect(store.poll(racing, presenter)).toEqual({ error: "access_denied" });
  });

  it("refuses a human direct approval of evidence-bearing submissions without verified facts, and records the facts it is given", async () => {
    const { kernel, store } = setup();
    const evidence = [{ type: "urn:test:unregistered-evidence", assertion: "artifact" }];
    // Policy completion verifies the presented evidence again; a type this
    // issuer does not support refuses, with no Mission.
    const byPolicy = open(store, { evidence });
    expect(await store.completeByPolicy(byPolicy)).toMatchObject({
      outcome: "not_authorized",
      reason: "invalid_mission_intent_evidence",
    });
    expect(kernel.allMissions()).toHaveLength(0);
    // The human path takes the facts its review surface verified, and is
    // refused without them.
    const byHuman = open(store, { evidence });
    expect(() => store.approveDirect(byHuman, { approver: DANA, subject: SUBJECT })).toThrow(
      expect.objectContaining({ code: "evidence_unverified" }),
    );
    expect(kernel.allMissions()).toHaveLength(0);
    const facts = [{ type: "urn:test:unregistered-evidence", artifact_hash: "sha-256:x", verified_at: now().toISOString(), facts: { ok: true } }];
    const mission = store.approveDirect(byHuman, { approver: DANA, subject: SUBJECT, submissionEvidence: facts });
    expect(mission.submission_evidence).toEqual(facts);
    expect(kernel.get(mission.id)?.submission_evidence).toEqual(facts);
  });

  it("redeems an approval only when its delivery confirms: a failed delivery stays deliverable, and one claim delivers at a time", async () => {
    const { kernel, store } = setup();
    const code = open(store);
    const done = await store.completeByPolicy(code);
    if (done.outcome !== "approved") throw new Error(done.outcome);
    // A delivery that fails before the response releases its claim.
    const failed = store.poll(code, presenter);
    if (!("delivery" in failed)) throw new Error("no claim");
    // While it is claimed, another poll is told the request is still pending.
    expect(store.poll(code, presenter)).toMatchObject({ error: "authorization_pending" });
    store.releaseDelivery(code, failed.delivery);
    const retried = store.poll(code, presenter);
    expect(retried).toMatchObject({ mission: kernel.get(done.mission.id) });
    if (!("delivery" in retried)) throw new Error("no claim");
    // The released claim cannot settle anything; the live one delivers once.
    expect(store.confirmDelivery(code, failed.delivery)).toBe("superseded");
    expect(store.confirmDelivery(code, retried.delivery)).toBe("confirmed");
    expect(store.confirmDelivery(code, retried.delivery)).toBe("superseded");
    expect(store.poll(code, presenter)).toEqual({ error: "invalid_grant" });

    // A claim that lapses (its delivery crashed) can be taken again, and only
    // one of the two claims ever confirms.
    const stale = open(store);
    await store.completeByPolicy(stale);
    const first = store.poll(stale, presenter);
    if (!("delivery" in first)) throw new Error("no claim");
    clockMs += (DELIVERY_CLAIM_STALE_S + 1) * 1000;
    const second = store.poll(stale, presenter);
    if (!("delivery" in second)) throw new Error("no second claim");
    expect(store.confirmDelivery(stale, first.delivery)).toBe("superseded");
    expect(store.confirmDelivery(stale, second.delivery)).toBe("confirmed");
  });

  it("runs policy completion from the bound presenter's poll only, at most once per interval, and once per evaluation", async () => {
    const advisor = vi.fn(async (_r: ModelAdvisorRequest) => []);
    const refusing = setup({ "urn:root:reconciler": rootDoc({ rules: { max_entries: 3, require_purpose: true } }) }, { modelAdvisor: advisor });
    const code = open(refusing.store);
    // Another client: invalid_grant, whatever key; the opening client under
    // another key: invalid_dpop_proof (#1357). No evaluation runs for any.
    expect(await refusing.store.pollAndComplete(code, { ...presenter, clientId: "svc-other" })).toEqual({ error: "invalid_grant" });
    expect(await refusing.store.pollAndComplete(code, { clientId: "svc-other", jkt: "another-key" })).toEqual({ error: "invalid_grant" });
    expect(await refusing.store.pollAndComplete(code, { ...presenter, jkt: "another-key" })).toEqual({ error: "invalid_dpop_proof" });
    expect(advisor).not.toHaveBeenCalled();
    expect(refusing.store.resolutionReason(code)).toBeUndefined();
    // The bound presenter's poll evaluates; a refusal is recorded and never re-evaluated.
    expect(await refusing.store.pollAndComplete(code, presenter)).toMatchObject({ error: "authorization_pending" });
    expect(refusing.store.resolutionReason(code)).toBe("purpose_required");
    expect(advisor).toHaveBeenCalledTimes(1);
    // Too soon: slow_down, with no evaluation.
    expect(await refusing.store.pollAndComplete(code, presenter)).toMatchObject({ error: "slow_down" });
    clockMs += 6_000;
    expect(await refusing.store.pollAndComplete(code, presenter)).toMatchObject({ error: "authorization_pending" });
    expect(advisor).toHaveBeenCalledTimes(1);
    expect(refusing.kernel.allMissions()).toHaveLength(0);

    // An approving evaluation delivers on the same poll.
    const { kernel, store } = setup();
    const approving = open(store);
    const r = await store.pollAndComplete(approving, presenter);
    expect(r).toEqual({ mission: kernel.allMissions()[0], delivery: expect.stringMatching(/^dlv_/) });
    if (!("delivery" in r)) throw new Error("no claim");
    expect(store.confirmDelivery(approving, r.delivery)).toBe("confirmed");
    expect(await store.pollAndComplete(approving, presenter)).toEqual({ error: "invalid_grant" });
  });
});
