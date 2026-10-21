import { approvalPolicyDigest } from "@mission/core";
import { APPROVAL_FLOOR, DERIVATION_POLICY, WRITE_ACTIONS } from "@mission/demo-data";
import { type CryptoKey, generateKeyPair } from "jose";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  type AgrAssertion,
  type ApprovalGovernanceRecord,
  approvalGovernanceRecordDigest,
  assertAccountableApprover,
  assertDirectApprovalRecord,
  type AuthorityEntry,
  directApprovalRuleFrom,
  directApprovalRuleRef,
  IntentError,
  MissionKernel,
  type MissionRecord,
  parseDirectApprovalRule,
  recheckApprovalGovernanceRecord,
  signApprovalGovernanceRecord,
  type UnsignedApprovalGovernanceRecord,
  validateMissionIntent,
  verifyApprovalGovernanceRecord,
} from "../src/index.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

/**
 * @spec approval-governance#triggers, approval-governance#accountable-assertion,
 * approval-governance#atomic-commitment, approval-governance#re-check (#1470
 * slice 1, D597): the default-off voluntary Approval Governance Record for a
 * `direct` approval. The record names the direct approval rule (the
 * approval-authentication floor and approver eligibility), carries the
 * Approver's `human` assertion, and commits with the rule snapshot and the
 * evaluated inputs in the Mission's creation transaction; a Relying Auditor
 * re-checks it by replaying the rule.
 */

const ISS = "https://as.test";
const T0 = Date.parse("2026-07-01T00:00:00Z");
let clockMs = T0;
const now = () => new Date(clockMs);
const iso = (ms: number) => new Date(ms).toISOString();
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
const BOB = { iss: ISS, sub: "bob" };
const ALICE = { iss: ISS, sub: "alice" };

/** The rule, built the way the assembly builds it from the approval surface's configuration. */
const RULE = directApprovalRuleFrom({
  floor: APPROVAL_FLOOR,
  knownSubjects: new Set(["alice", "bob", "carol"]),
  approverApprovesFor: new Map([
    ["bob", new Set(["alice"])],
    ["carol", new Set(["alice"])],
  ]),
  approverRoleSubs: new Set(["bob"]),
  writeActions: WRITE_ACTIONS,
});
const RULE_REF = directApprovalRuleRef(ISS, RULE);

/** An irreversible payment: it invokes the floor and needs a distinct Approver holding write. */
const EXECUTE: AuthorityEntry[] = [
  {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions: ["payments:payment.execute"],
    constraints: { max_amount: { amount: "100.00", currency: "USD" }, vendors: ["acme"] },
  },
];
const AUTH = { acr: "mfa", auth_time: Math.floor(T0 / 1000) - 60, interactive: true };

let key: CryptoKey;
let seq = 0;
beforeAll(async () => {
  key = (await generateKeyPair("ES256")).privateKey;
});
beforeEach(() => {
  clockMs = T0;
  vi.restoreAllMocks();
});

const makeKernel = (recording = true) =>
  new MissionKernel({
    issuer: ISS,
    policy: DERIVATION_POLICY as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["ap-agent"], ["bob", "carol"]),
    statusKey: key,
    statusKid: "as-status",
    now,
    ...(recording ? { directApprovalRecording: { rule: RULE } } : {}),
  });

const approve = (kernel: MissionKernel, over: Partial<Parameters<MissionKernel["approve"]>[0]> = {}): MissionRecord =>
  kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({ goal: "Pay Acme invoices", target_resources: [RESOURCE], expires_at: "2027-01-01T00:00:00Z" }),
      { now: now() },
    ),
    proposedAuthority: EXECUTE,
    subject: ALICE,
    approver: BOB,
    clientId: "ap-agent",
    approvalEventId: `apev-${seq++}`,
    authentication: AUTH,
    ...over,
  });

/** The refusal code an approval raises, or "approved". */
const outcome = (fn: () => unknown): string => {
  try {
    fn();
  } catch (e) {
    if (e instanceof IntentError) return `intent:${e.code}`;
    return `error:${(e as Error).message}`;
  }
  return "approved";
};

const nothingCommitted = (kernel: MissionKernel) => {
  expect(kernel.allMissions()).toHaveLength(0);
  expect(kernel.governanceRecords.count()).toBe(0);
  expect((kernel.db.prepare("SELECT COUNT(*) AS n FROM direct_approval_inputs").get() as { n: number }).n).toBe(0);
};

const resolveKey = (kernel: MissionKernel) => (kid: string) => (kid === "as-status" ? kernel.statusVerificationKey() : undefined);
const recheck = (kernel: MissionKernel, missionId: string) => recheckApprovalGovernanceRecord(kernel, missionId, { resolveKey: resolveKey(kernel) });

/** Re-sign the committed record with `edit` applied: a record that verifies but says something else. */
const resign = (kernel: MissionKernel, missionId: string, edit: (r: UnsignedApprovalGovernanceRecord) => void) => {
  const { envelope: _drop, ...unsigned } = kernel.governanceRecords.forMission(missionId) as ApprovalGovernanceRecord;
  const copy = structuredClone(unsigned);
  edit(copy);
  const signed = signApprovalGovernanceRecord(copy, kernel.statusSigner());
  kernel.db
    .prepare("UPDATE approval_governance_records SET record_json = ?, record_digest = ? WHERE mission_id = ?")
    .run(JSON.stringify(signed), approvalGovernanceRecordDigest(signed), missionId);
};

describe("a voluntary direct approval record (@spec approval-governance#triggers, approval-governance#atomic-commitment)", () => {
  it("records nothing by default: a direct approval carries no adjudication and commits no record", () => {
    const kernel = makeKernel(false);
    const mission = approve(kernel);
    expect(mission.approval_basis).not.toHaveProperty("adjudication");
    expect(kernel.governanceRecords.count()).toBe(0);
    expect(kernel.directApprovalRecords.inputs(mission.id)).toBeUndefined();
  });

  it("commits one signed record with the Mission when configured: the Approver's human assertion under the direct approval rule", () => {
    const kernel = makeKernel();
    const mission = approve(kernel);
    expect(mission.approval_basis).toMatchObject({ type: "direct", adjudication: { kind: "human", governance_record: true } });
    const record = kernel.governanceRecords.forMission(mission.id) as ApprovalGovernanceRecord;
    expect(() => verifyApprovalGovernanceRecord(record, { resolveKey: resolveKey(kernel), mission })).not.toThrow();
    expect(record.approval_event_id).toBe(mission.approval_event_id);
    expect(record.approval_policy).toEqual(RULE_REF);
    expect(record.assertions).toEqual([
      {
        assertion_id: "ast_human",
        principal: BOB,
        kind: "human",
        decision: "approve",
        decided_at: mission.created_at,
        authority: { auth_time: iso(AUTH.auth_time * 1000), acr: "mfa" },
      },
    ]);
    expect(record.evaluation).toEqual({ decision: "approved", evaluated_at: mission.created_at, contributing: ["ast_human"] });
    // The accountable-approver rule for direct holds on the committed record.
    expect(assertAccountableApprover(record, mission.approval_basis)?.assertion_id).toBe("ast_human");
  });

  it("retains the rule snapshot that reproduces approval_policy.digest, and the inputs the rule evaluated", () => {
    const kernel = makeKernel();
    const mission = approve(kernel);
    const snapshot = kernel.directApprovalRecords.ruleSnapshot(ISS, RULE_REF);
    expect(snapshot && approvalPolicyDigest(ISS, snapshot)).toBe(RULE_REF.digest);
    const rule = parseDirectApprovalRule((snapshot as { content: Uint8Array }).content);
    expect(rule.floor).toEqual(APPROVAL_FLOOR);
    expect(rule.approvers).toEqual({ bob: { approves_for: ["alice"], write: true }, carol: { approves_for: ["alice"], write: false } });
    expect(rule.write_actions).toEqual([...WRITE_ACTIONS].sort());
    expect(kernel.directApprovalRecords.inputs(mission.id)).toEqual({
      approval_event_id: mission.approval_event_id,
      inputs: {
        approval_event_id: mission.approval_event_id,
        intent_hash: mission.intent_hash,
        approver: BOB,
        subject: ALICE,
        authority: mission.authority_set,
        authentication: AUTH,
      },
    });
  });

  it("evaluates the rule again at the commit: an Approver it does not admit, write-bearing self-approval, or an authentication the floor refuses creates no Mission and no record", () => {
    const kernel = makeKernel();
    const denies = (fn: () => unknown, why: RegExp) => {
      let caught: unknown;
      try {
        fn();
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(IntentError);
      expect((caught as IntentError).code).toBe("access_denied");
      expect((caught as Error).message).toMatch(/^the direct approval rule denies: /);
      expect((caught as Error).message).toMatch(why);
    };
    const READ_ONLY = [{ ...(EXECUTE[0] as AuthorityEntry), actions: ["payments:invoice.read"], constraints: { vendors: ["acme"] } }];
    // Carol may approve for Alice, but not write-bearing authority.
    denies(() => approve(kernel, { approver: { iss: ISS, sub: "carol" } }), /distinct Approver holding write/);
    // Carol may not approve for Bob, even read-only.
    denies(() => approve(kernel, { approver: { iss: ISS, sub: "carol" }, subject: BOB, proposedAuthority: READ_ONLY }), /carol may not approve for bob/);
    // Bob may not approve write-bearing authority for himself.
    denies(() => approve(kernel, { subject: BOB }), /distinct Approver holding write/);
    // The floor: an acr it does not accept, an authentication older than it allows, a headless approval.
    denies(() => approve(kernel, { authentication: { ...AUTH, acr: "pwd" } }), /acr does not satisfy/);
    denies(() => approve(kernel, { authentication: { ...AUTH, auth_time: Math.floor(T0 / 1000) - 301 } }), /older than/);
    denies(() => approve(kernel, { authentication: { ...AUTH, interactive: false } }), /browser approval surface/);
    nothingCommitted(kernel);
    // Each is the rule's own refusal: the same approvals commit with recording off.
    const off = makeKernel(false);
    expect(outcome(() => approve(off, { approver: { iss: ISS, sub: "carol" } }))).toBe("approved");
    expect(outcome(() => approve(off, { approver: { iss: ISS, sub: "carol" }, subject: BOB, proposedAuthority: READ_ONLY }))).toBe("approved");
    expect(outcome(() => approve(off, { authentication: { ...AUTH, acr: "pwd" } }))).toBe("approved");
    // The same approval inside the rule commits.
    expect(outcome(() => approve(kernel))).toBe("approved");
  });

  it("refuses an approval without the Approver's verified authentication when recording is configured", () => {
    const kernel = makeKernel();
    expect(outcome(() => approve(kernel, { authentication: undefined }))).toMatch(/needs the authentication the approval surface verified/);
    nothingCommitted(kernel);
  });

  it("leaves no Mission, no record and no retained inputs when signing or persistence fails", () => {
    for (const fault of ["sign", "record", "evidence"] as const) {
      const kernel = makeKernel();
      const spy =
        fault === "sign"
          ? vi.spyOn(kernel, "statusSigner")
          : fault === "record"
            ? vi.spyOn(kernel.governanceRecords, "retainInCallerTx")
            : vi.spyOn(kernel.directApprovalRecords, "retainInCallerTx");
      spy.mockImplementation(() => {
        throw new Error(`${fault} unavailable`);
      });
      expect(outcome(() => approve(kernel, { approvalEventId: `apev-fault-${fault}` }))).toBe(`error:${fault} unavailable`);
      spy.mockRestore();
      nothingCommitted(kernel);
      // The same event commits once the fault clears.
      expect(approve(kernel, { approvalEventId: `apev-fault-${fault}` }).state).toBe("active");
      expect(kernel.governanceRecords.count()).toBe(1);
    }
  });

  it("returns the committed Mission for a repeated approval event, with no second record", () => {
    const kernel = makeKernel();
    const first = approve(kernel, { approvalEventId: "apev-once" });
    const again = approve(kernel, { approvalEventId: "apev-once" });
    expect(again.id).toBe(first.id);
    expect(kernel.governanceRecords.count()).toBe(1);
  });
});

describe("the direct record commit gate (@spec approval-governance#accountable-assertion, approval-governance#issuance-relationship)", () => {
  const committed = () => {
    const kernel = makeKernel();
    const mission = approve(kernel);
    const { envelope: _e, ...unsigned } = kernel.governanceRecords.forMission(mission.id) as ApprovalGovernanceRecord;
    return { basis: mission.approval_basis as never, unsigned };
  };
  const human = (unsigned: UnsignedApprovalGovernanceRecord) => unsigned.assertions[0] as AgrAssertion;

  it("admits exactly one human approve assertion of the consent principal, counted, under the rule this issuer holds", () => {
    const { basis, unsigned } = committed();
    expect(assertDirectApprovalRecord(unsigned, basis, RULE_REF).assertion_id).toBe("ast_human");
    // Contributing policy or service assertions beside it are accepted.
    const service: AgrAssertion = {
      assertion_id: "ast_svc",
      principal: { iss: ISS, sub: "risk-service" },
      kind: "service",
      decision: "approve",
      decided_at: human(unsigned).decided_at,
      authority: { logic_id: "risk", logic_version: "1" },
    };
    const both = { ...unsigned, assertions: [...unsigned.assertions, service], evaluation: { ...unsigned.evaluation, contributing: ["ast_human", "ast_svc"] } };
    expect(() => assertDirectApprovalRecord(both, basis, RULE_REF)).not.toThrow();
  });

  it("refuses a record whose consent principal approves only through another kind, twice, or not at all; an uncounted accountable assertion; another rule; or a kind that is not adjudication.kind", () => {
    const { basis, unsigned } = committed();
    const h = human(unsigned);
    const variants: Array<[string, UnsignedApprovalGovernanceRecord, unknown, RegExp]> = [
      [
        "service",
        { ...unsigned, assertions: [{ ...h, kind: "service", authority: { logic_id: "x", logic_version: "1" } }] },
        basis,
        /direct record/,
      ],
      ["twice", { ...unsigned, assertions: [h, { ...h, assertion_id: "ast_human_2" }], evaluation: { ...unsigned.evaluation, contributing: ["ast_human", "ast_human_2"] } }, basis, /direct record/],
      ["none", { ...unsigned, assertions: [], evaluation: { ...unsigned.evaluation, contributing: [] } }, basis, /direct record/],
      ["deny", { ...unsigned, assertions: [{ ...h, decision: "deny" }], evaluation: { ...unsigned.evaluation, contributing: [] } }, basis, /direct record/],
      [
        "uncounted",
        {
          ...unsigned,
          assertions: [h, { ...h, assertion_id: "ast_other", principal: { iss: ISS, sub: "carol" } }],
          evaluation: { ...unsigned.evaluation, contributing: ["ast_other"] },
        },
        basis,
        /does not count the accountable assertion/,
      ],
      ["rule", { ...unsigned, approval_policy: { ...RULE_REF, version: "other" } }, basis, /not the direct approval rule this issuer holds/],
      ["kind", unsigned, { ...(basis as object), adjudication: { kind: "policy", governance_record: true } }, /not adjudication.kind/],
    ];
    for (const [name, record, b, why] of variants) {
      expect(() => assertDirectApprovalRecord(record, b as never, RULE_REF), name).toThrow(why);
    }
  });
});

describe("re-checking a direct record (@spec approval-governance#re-check)", () => {
  const committed = () => {
    const kernel = makeKernel();
    clockMs = T0 + 30_000;
    return { kernel, mission: approve(kernel) };
  };

  it("re-checks a committed direct record by replaying the rule over the retained inputs", () => {
    const { kernel, mission } = committed();
    expect(recheck(kernel, mission.id)).toEqual({ rechecked: true });
  });

  it("step 1: refuses a record altered after signing", () => {
    const { kernel, mission } = committed();
    kernel.db
      .prepare("UPDATE approval_governance_records SET record_json = json_set(record_json, '$.evaluation.evaluated_at', ?)")
      .run(iso(T0 + 1));
    expect(recheck(kernel, mission.id)).toEqual({ rechecked: false, step: 1, reason: "record differs from its signed payload" });
  });

  it("step 2: refuses when the rule snapshot is missing or does not reproduce approval_policy.digest", () => {
    const altered = committed();
    altered.kernel.db.prepare("UPDATE direct_approval_rules SET content = ?").run(Buffer.from("{}", "utf8"));
    expect(recheck(altered.kernel, altered.mission.id)).toEqual({
      rechecked: false,
      step: 2,
      reason: "the retained rule snapshot does not reproduce approval_policy.digest",
    });
    const missing = committed();
    missing.kernel.db.prepare("DELETE FROM direct_approval_rules").run();
    expect(recheck(missing.kernel, missing.mission.id)).toEqual({ rechecked: false, step: 2, reason: "the rule snapshot the record names is not retained" });
  });

  it("step 4: refuses missing inputs, inputs not bound to this event and Intent, and inputs naming another Approver or Subject", () => {
    const missing = committed();
    missing.kernel.db.prepare("DELETE FROM direct_approval_inputs").run();
    expect(recheck(missing.kernel, missing.mission.id)).toEqual({ rechecked: false, step: 4, reason: "no recorded inputs to replay" });
    const unbound = { rechecked: false, step: 4, reason: "the recorded inputs are not bound to this approval event and Intent" };
    const event = committed();
    event.kernel.db.prepare("UPDATE direct_approval_inputs SET approval_event_id = 'apev-other'").run();
    expect(recheck(event.kernel, event.mission.id)).toEqual(unbound);
    const eventMember = committed();
    eventMember.kernel.db.prepare("UPDATE direct_approval_inputs SET inputs_json = json_set(inputs_json, '$.approval_event_id', 'apev-other')").run();
    expect(recheck(eventMember.kernel, eventMember.mission.id)).toEqual(unbound);
    const intent = committed();
    intent.kernel.db
      .prepare("UPDATE direct_approval_inputs SET inputs_json = json_set(inputs_json, '$.intent_hash', ?)")
      .run("sha-256:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU");
    expect(recheck(intent.kernel, intent.mission.id)).toEqual(unbound);
    const parties = { rechecked: false, step: 4, reason: "the recorded inputs do not name this Mission's Approver and Subject" };
    const approver = committed();
    approver.kernel.db.prepare("UPDATE direct_approval_inputs SET inputs_json = json_set(inputs_json, '$.approver.sub', 'carol')").run();
    expect(recheck(approver.kernel, approver.mission.id)).toEqual(parties);
    const subject = committed();
    subject.kernel.db.prepare("UPDATE direct_approval_inputs SET inputs_json = json_set(inputs_json, '$.subject.sub', 'bob')").run();
    expect(recheck(subject.kernel, subject.mission.id)).toEqual(parties);
  });

  it("step 5: refuses a record failing the commit gate, a human assertion that is not the recorded authentication, a replay that denies or approves another set, and other contributing", () => {
    const gate = committed();
    resign(gate.kernel, gate.mission.id, (r) => {
      r.assertions = [];
      r.evaluation.contributing = [];
    });
    expect(recheck(gate.kernel, gate.mission.id)).toMatchObject({ rechecked: false, step: 5 });
    const notAuth = { rechecked: false, step: 5, reason: "the human assertion is not the authentication the inputs record" };
    const acr = committed();
    resign(acr.kernel, acr.mission.id, (r) => {
      (r.assertions[0] as { authority: { acr: string } }).authority.acr = "pwd";
    });
    expect(recheck(acr.kernel, acr.mission.id)).toEqual(notAuth);
    const authTime = committed();
    resign(authTime.kernel, authTime.mission.id, (r) => {
      (r.assertions[0] as { authority: { auth_time: string } }).authority.auth_time = iso(T0);
    });
    expect(recheck(authTime.kernel, authTime.mission.id)).toEqual(notAuth);
    // The replay: headless authority the floor refuses, and the floor's age at the recorded evaluation instant.
    const headless = committed();
    headless.kernel.db
      .prepare("UPDATE direct_approval_inputs SET inputs_json = json_set(inputs_json, '$.authentication.interactive', json('false'))")
      .run();
    expect(recheck(headless.kernel, headless.mission.id)).toMatchObject({ rechecked: false, step: 5, reason: expect.stringMatching(/^the replay does not approve/) });
    const late = committed();
    resign(late.kernel, late.mission.id, (r) => {
      r.evaluation.evaluated_at = iso((AUTH.auth_time + 301) * 1000);
    });
    expect(recheck(late.kernel, late.mission.id)).toMatchObject({ rechecked: false, step: 5, reason: expect.stringMatching(/older than the high-risk-authority floor allows/) });
    const otherSet = committed();
    otherSet.kernel.db
      .prepare("UPDATE direct_approval_inputs SET inputs_json = json_set(inputs_json, '$.authority', json(?))")
      .run(JSON.stringify([{ ...(EXECUTE[0] as AuthorityEntry), actions: ["payments:invoice.read"] }]));
    expect(recheck(otherSet.kernel, otherSet.mission.id)).toEqual({ rechecked: false, step: 5, reason: "the replay approves a different Authority Set" });
    // A second human approval counted beside the Approver's is not what the rule counts.
    const extra = committed();
    resign(extra.kernel, extra.mission.id, (r) => {
      const h = r.assertions[0] as AgrAssertion;
      r.assertions.push({ ...h, assertion_id: "ast_carol", principal: { iss: ISS, sub: "carol" } });
      r.evaluation.contributing = ["ast_human", "ast_carol"];
    });
    expect(recheck(extra.kernel, extra.mission.id)).toEqual({ rechecked: false, step: 5, reason: "contributing is not the set the replay counts" });
  });
});
