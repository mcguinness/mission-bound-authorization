/**
 * @spec authority-server#join-assertion-pdp, authority-server#join-authzen,
 * authority-server#discovery (#1454)
 *
 * The PDP's consumption of a Mission Join Assertion (`EvaluateOptions.joinAssertion`):
 * a carried assertion that verifies is the join, in place of the mapping
 * checks of rules 3 and 4, with the joining client, disposition and depth
 * from its `join` claim; one that fails any check, and a reported
 * `delegate_depth` that disagrees with it, deny `mission_binding_failed`
 * with no fallback to the mapping join; a declared requirement denies a
 * joined request that carries none; and a PDP that does not consume
 * assertions ignores the members. Assertions here are signed by a test key
 * standing in for the MAS's Status key.
 */

import { generateKeyPairSync } from "node:crypto";
import { createLocalJWKSet, exportJWK, generateKeyPair, type JWTPayload, SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { evaluate as evaluateRequest, type EvaluateOptions, type EvaluationRequest } from "../src/evaluate.js";
import type { Fga } from "../src/fga.js";
import {
  createDecisionEvidenceEmitter,
  type DecisionEvidenceObject,
  type JoinAssertionPolicy,
  type JoinMappingContract,
  joinViewId,
  UNRESOLVED_JOIN_MAPPING,
} from "../src/index.js";
import { type AuthorityEntry, MISSION_RESOURCE_ACCESS_TYPE, type MissionView } from "../src/policy-view.js";
import { relationForAction, stalenessBound } from "../src/policy.js";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "../src/test-support.js";

const RESOURCE = "http://localhost:4403/mcp";
const NOW = new Date("2026-10-22T12:00:00Z");
const NOW_S = Math.floor(NOW.getTime() / 1000);
const READ = "payments:invoice.read";
const LIST = "payments:invoice.list";
const MAS = "https://mas.test";
const ESTATE = "https://estate.test";
const PDP = "pdp-1454";
const KID = "mas-status-1";
const SHA = "rN2kQ4mZ7tP3xR9sQ7nM2vL4tY6bD1eF8jC5wH0pV2n";
const JKT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

const READ_ENTRY: AuthorityEntry = { type: MISSION_RESOURCE_ACCESS_TYPE, resource: RESOURCE, actions: [READ] };
const LIST_ENTRY: AuthorityEntry = {
  type: MISSION_RESOURCE_ACCESS_TYPE,
  resource: RESOURCE,
  actions: [LIST],
  join_delegation: { max_depth: 1, allowed_delegates: ["helper-agent"] },
};
const view: MissionView = {
  id: "msn_1454_pdp",
  issuer: MAS,
  state: "active",
  version: 1,
  authority_hash: "sha-256:m1454",
  authority_set: [READ_ENTRY, LIST_ENTRY],
  subject: { iss: MAS, sub: "alice" },
  client_id: "ap-agent",
};

/** A mapping double that joins the estate credential: a fallback to it would permit. */
const MAPPED: JoinMappingContract = {
  id: "double",
  version: 1,
  usable: () => true,
  resolveIdentity: (input) =>
    input.subject.sub === "u-1001" && input.client.clientId === "estate-bot" ? { subject: { iss: MAS, sub: "alice" }, clientId: "ap-agent" } : undefined,
  clientFor: () => undefined,
  credentialAuthority: () => undefined,
};

let signer: CryptoKey;
let otherSigner: CryptoKey;
let es384Signer: CryptoKey;
let policy: JoinAssertionPolicy;

beforeAll(async () => {
  const masKey = await generateKeyPair("ES256", { extractable: true });
  const p384 = await generateKeyPair("ES384", { extractable: true });
  signer = masKey.privateKey;
  otherSigner = (await generateKeyPair("ES256")).privateKey;
  es384Signer = p384.privateKey;
  const keys = createLocalJWKSet({
    keys: [
      { ...(await exportJWK(masKey.publicKey)), kid: KID },
      { ...(await exportJWK(p384.publicKey)), kid: "mas-status-384" },
    ],
  });
  policy = { audience: PDP, keys, algorithms: ["ES256", "ES384"] };
});

const CLAIMS = (): JWTPayload => ({
  iss: MAS,
  mission: { id: view.id, issuer: MAS, authority_hash: view.authority_hash },
  token: { sha256: SHA, jkt: JKT },
  join: { client_id: "ap-agent", disposition: "client" },
  aud: PDP,
  mapping_version: "contract@1",
  iat: NOW_S - 10,
  exp: NOW_S + 290,
});

/** An assertion: the claims with `edit` applied, under `key` and `header`. */
async function mint(
  edit: (c: JWTPayload) => void = () => {},
  opts: { key?: CryptoKey; header?: Record<string, unknown> } = {},
): Promise<string> {
  const claims = CLAIMS();
  edit(claims);
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "ES256", kid: KID, typ: "mission-join+jwt", ...opts.header } as never)
    .sign(opts.key ?? signer);
}

/** A joined request from an estate credential, carrying `mission_join`. */
const joinedReq = (missionJoin: Record<string, unknown>, action = READ, actionClass = "consequential_read"): EvaluationRequest =>
  ({
    subject: { id: "u-1001", properties: { iss: ESTATE } },
    resource: { type: "invoice", id: "inv-1", properties: { audience: RESOURCE, operation_target: RESOURCE, vendor_id: "acme" } },
    action: { name: action },
    context: {
      mission: { id: view.id, issuer: view.issuer },
      actor: { client_id: "estate-bot" },
      mission_join: missionJoin,
      mission_state_observation: { state: "active", mode: "fresh", freshness_at: NOW.toISOString() },
      action_class: actionClass,
      credential: { issuer: ESTATE, authority: [{ type: MISSION_RESOURCE_ACCESS_TYPE, resource: RESOURCE, actions: [READ, LIST] }] },
    },
  }) as EvaluationRequest;

const carrying = (assertion: string, extra: Record<string, unknown> = {}) => ({ assertion, token_sha256: SHA, token_jkt: JKT, ...extra });

const opts = (extra: Partial<EvaluateOptions> = {}): EvaluateOptions => ({
  view,
  fga: alwaysAllowFga,
  modelId: "unit-test-model",
  now: () => NOW,
  stalenessBound,
  relationForAction,
  resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
  stateSourcePlacement: "pep" as const,
  joinAssertion: policy,
  ...extra,
});

async function decide(req: EvaluationRequest, o: EvaluateOptions) {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const emitter = createDecisionEvidenceEmitter({ signer: { kid: "k1454", key: privateKey }, emitterId: RESOURCE, audience: RESOURCE });
  const decision = await evaluateRequest(req, { ...o, evidence: emitter });
  return { decision, record: decision.context.decision_evidence as DecisionEvidenceObject };
}

async function expectBindingFailed(req: EvaluationRequest, o: EvaluateOptions, label: string) {
  const { decision, record } = await decide(req, o);
  expect(decision.decision, label).toBe(false);
  expect(decision.context.denial_reason, label).toBe("mission_binding_failed");
  expect(record.join_view_id, label).toBeUndefined();
}

describe("evaluate(): a verified Join Assertion is the join (@spec authority-server#join-assertion-pdp, #1454)", () => {
  it("joins on the assertion alone, under a mapping that resolves nothing: the joining client, disposition and depth come from the join claim, and so does the commitment", async () => {
    const client = await decide(joinedReq(carrying(await mint())), opts({ joinMapping: UNRESOLVED_JOIN_MAPPING }));
    expect(client.decision.decision, JSON.stringify(client.decision)).toBe(true);
    // Rule 9's commitment changes with the join claim's client and disposition.
    expect(client.record.join_view_id).toBe(
      joinViewId(view, "unit-test-model", { disposition: "direct", clientId: "ap-agent", authoritySet: view.authority_set }),
    );

    const delegate = await mint((c) => {
      c.join = { client_id: "helper-agent", disposition: "delegate", depth: 1 };
    });
    // Rule 5 with the claim's delegate and depth: the delegable entry permits,
    // the other is narrowed away.
    const list = await decide(joinedReq(carrying(delegate), LIST), opts({ joinMapping: UNRESOLVED_JOIN_MAPPING }));
    expect(list.decision.decision, JSON.stringify(list.decision)).toBe(true);
    expect(list.record.join_view_id).toBe(
      joinViewId(view, "unit-test-model", { disposition: "delegate", clientId: "helper-agent", authoritySet: [LIST_ENTRY] }),
    );
    const read = await decide(joinedReq(carrying(delegate), READ), opts({ joinMapping: UNRESOLVED_JOIN_MAPPING }));
    expect(read.decision.decision).toBe(false);
    expect(read.decision.context.denial_reason).toBe("out_of_authority");

    // The claim's depth, not a mapping: depth 2 exceeds the entry's max_depth 1.
    const deep = await mint((c) => {
      c.join = { client_id: "helper-agent", disposition: "delegate", depth: 2 };
    });
    await expectBindingFailed(joinedReq(carrying(deep), LIST), opts({ joinMapping: UNRESOLVED_JOIN_MAPPING }), "depth 2");
  });

  it("joins a certificate-bound credential on token_x5t against the assertion's x5t#S256, and an assertion with no authority_hash", async () => {
    const x5t = await mint((c) => {
      c.token = { sha256: SHA, "x5t#S256": "cert-thumb" };
      (c.mission as Record<string, unknown>).authority_hash = undefined;
    });
    const { decision } = await decide(joinedReq({ assertion: x5t, token_sha256: SHA, token_x5t: "cert-thumb" }), opts());
    expect(decision.decision, JSON.stringify(decision)).toBe(true);
  });
});

describe("evaluate(): an assertion that fails a check denies mission_binding_failed, never falling back to the mapping join (@spec authority-server#join-assertion-pdp, #1454)", () => {
  it("denies each failed check, though the mapping contract would join the same credential", async () => {
    // The mapping join alone permits this credential.
    const floor = await decide(joinedReq({}), opts({ joinMapping: MAPPED }));
    expect(floor.decision.decision, JSON.stringify(floor.decision)).toBe(true);

    const cases: Array<[string, Promise<string>, string?]> = [
      ["typ", mint(() => {}, { header: { typ: "JWT" } })],
      ["no exp", mint((c) => { delete c.exp; })],
      ["no iat", mint((c) => { delete c.iat; })],
      ["signature under another key", mint(() => {}, { key: otherSigner })],
      ["iss", mint((c) => { c.iss = "https://other-mas.test"; })],
      ["mission.id", mint((c) => { (c.mission as Record<string, unknown>).id = "msn_other"; })],
      ["mission.issuer", mint((c) => { (c.mission as Record<string, unknown>).issuer = "https://other-mas.test"; })],
      ["authority_hash", mint((c) => { (c.mission as Record<string, unknown>).authority_hash = "sha-256:other"; })],
      ["expired", mint((c) => { c.exp = NOW_S - 1; })],
      ["join without client_id", mint((c) => { c.join = { disposition: "client" }; })],
      // The delegable action: each of these would join as the delegate if read as one.
      ["join with an unknown disposition", mint((c) => { c.join = { client_id: "helper-agent", disposition: "owner", depth: 1 }; }), LIST],
      ["delegate with no depth", mint((c) => { c.join = { client_id: "helper-agent", disposition: "delegate" }; }), LIST],
      ["delegate with a negative depth", mint((c) => { c.join = { client_id: "helper-agent", disposition: "delegate", depth: -1 }; }), LIST],
    ];
    for (const [label, assertion, action] of cases) {
      await expectBindingFailed(joinedReq(carrying(await assertion), action), opts({ joinMapping: MAPPED }), label);
    }
  });

  it("denies an assertion whose aud names another PDP, or that carries no aud", async () => {
    const other = await mint((c) => { c.aud = "another-pdp"; });
    await expectBindingFailed(joinedReq(carrying(other)), opts({ joinMapping: MAPPED }), "another PDP");
    const none = await mint((c) => { delete c.aud; });
    await expectBindingFailed(joinedReq(carrying(none)), opts({ joinMapping: MAPPED }), "no aud");
  });

  it("denies a token binding that differs from the PEP-reported digest or thumbprint", async () => {
    const assertion = await mint();
    const cases: Array<[string, Record<string, unknown>]> = [
      ["another token's digest", { assertion, token_sha256: "another-digest", token_jkt: JKT }],
      ["no digest", { assertion, token_jkt: JKT }],
      ["no digest reported or asserted", { assertion: await mint((c) => { c.token = { jkt: JKT }; }), token_jkt: JKT }],
      ["another key's thumbprint", { assertion, token_sha256: SHA, token_jkt: "another-jkt" }],
      ["no thumbprint", { assertion, token_sha256: SHA }],
      ["both thumbprints", { assertion, token_sha256: SHA, token_jkt: JKT, token_x5t: "cert-thumb" }],
      ["a thumbprint of the other method", { assertion, token_sha256: SHA, token_x5t: JKT }],
    ];
    for (const [label, missionJoin] of cases) {
      await expectBindingFailed(joinedReq(missionJoin), opts({ joinMapping: MAPPED }), label);
    }
  });

  it("denies a reported delegate_depth that differs from join.depth, and permits one that agrees", async () => {
    const delegate = await mint((c) => {
      c.join = { client_id: "helper-agent", disposition: "delegate", depth: 1 };
    });
    await expectBindingFailed(joinedReq(carrying(delegate, { delegate_depth: 2 }), LIST), opts(), "delegate depth 2 vs 1");
    await expectBindingFailed(joinedReq(carrying(await mint(), { delegate_depth: 1 }), READ), opts(), "client with a reported depth");
    const agrees = await decide(joinedReq(carrying(delegate, { delegate_depth: 1 }), LIST), opts());
    expect(agrees.decision.decision, JSON.stringify(agrees.decision)).toBe(true);
    // The Mission's own client is depth 0 in the PEP's actor records.
    const client = await decide(joinedReq(carrying(await mint(), { delegate_depth: 0 }), READ), opts());
    expect(client.decision.decision, JSON.stringify(client.decision)).toBe(true);
  });
});

describe("evaluate(): the assertion's alg is one this PDP accepts (@spec authority-server#discovery, #1454)", () => {
  it("denies an assertion signed with an algorithm the PDP's list does not name, and one with alg none", async () => {
    const es256 = await mint();
    await expectBindingFailed(joinedReq(carrying(es256)), opts({ joinAssertion: { ...policy, algorithms: ["ES384"] }, joinMapping: MAPPED }), "ES256 unlisted");
    const es384 = await mint(() => {}, { key: es384Signer, header: { alg: "ES384", kid: "mas-status-384" } });
    await expectBindingFailed(joinedReq(carrying(es384)), opts({ joinAssertion: { ...policy, algorithms: ["ES256"] }, joinMapping: MAPPED }), "ES384 unlisted");
    const allowed = await decide(joinedReq(carrying(es384)), opts({ joinAssertion: { ...policy, algorithms: ["ES384"] } }));
    expect(allowed.decision.decision, JSON.stringify(allowed.decision)).toBe(true);
    const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");
    const unsecured = `${b64({ alg: "none", typ: "mission-join+jwt" })}.${b64(CLAIMS())}.`;
    await expectBindingFailed(joinedReq(carrying(unsecured)), opts({ joinAssertion: { ...policy, algorithms: ["ES256", "none"] }, joinMapping: MAPPED }), "none");
  });
});

describe("evaluate(): whether a joined decision requires an assertion is declared (@spec authority-server#join-assertion-pdp, #1454)", () => {
  it("denies a joined request with no assertion where the deployment, or the request's action class, requires one; otherwise the mapping join runs", async () => {
    await expectBindingFailed(joinedReq({}), opts({ joinAssertion: { ...policy, required: true }, joinMapping: MAPPED }), "deployment");
    const byClass = { ...policy, requiredActionClasses: new Set(["consequential_read"]) };
    await expectBindingFailed(joinedReq({}), opts({ joinAssertion: byClass, joinMapping: MAPPED }), "class");
    const writesOnly = { ...policy, requiredActionClasses: new Set(["consequential_write"]) };
    const otherClass = await decide(joinedReq({}), opts({ joinAssertion: writesOnly, joinMapping: MAPPED }));
    expect(otherClass.decision.decision, JSON.stringify(otherClass.decision)).toBe(true);
  });

  it("ignores the assertion members where the PDP does not consume assertions, and joins under the mapping rules", async () => {
    const { joinAssertion: _consumed, ...nonConsuming } = opts({ joinMapping: MAPPED });
    const { decision } = await decide(joinedReq(carrying("not-an-assertion")), nonConsuming);
    expect(decision.decision, JSON.stringify(decision)).toBe(true);
  });
});
