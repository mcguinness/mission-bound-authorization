/**
 * @spec mission#submission-processing (#1411, D559): the Submission Processing
 * Order's refusal precedence at PAR. A submission that fails more than one
 * check is refused with the error of the earliest failing step: the envelope,
 * including each evidence entry's structure and the size bounds (step 1,
 * #1503 finding 12), and the Intent (step 2) before the authority proposal
 * (step 3), and the proposal before required evidence (step 5) and evidence
 * dispatch and verification (step 6). Each combined case runs beside each of
 * its single failures, so the combined result is attributable to the order
 * alone.
 *
 * @spec mission#derivation-modes (#1411): the candidate Authority Set is
 * complete before the approval rendering, and the approved set is fixed when
 * the Mission Record is created, not recomputed afterwards.
 */

import { type Server } from "node:http";
import { DEMO_AGENT_PROPOSAL, DERIVATION_POLICY } from "@mission/demo-data";
import { importJWK, SignJWT, type CryptoKey } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  ApprovalSessionStore,
  buildAuthorizationServer,
  type BuiltAs,
  DEFAULT_MAX_EVIDENCE_ENTRIES,
  IntentError,
  registerIntentSubmissionEvidenceType,
  unregisterIntentSubmissionEvidenceType,
} from "../src/index.js";
import { floorApprovalHeaders, renderedRevision, TEST_APPROVAL_PRINCIPALS } from "./approval-fixture.js";

const PORT = 14751;
const ISSUER = `http://localhost:${PORT}`;
const REQUIRED_PORT = 14752;
const REQUIRED_ISSUER = `http://localhost:${REQUIRED_PORT}`;
const DERIVE_PORT = 14753;
const DERIVE_ISSUER = `http://localhost:${DERIVE_PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
const OTHER_RESOURCE = "https://elsewhere.example/api";

const INTENT = {
  goal: "Reconcile Q3 invoices",
  target_resources: [RESOURCE],
  expires_at: new Date(Date.now() + 86_400_000).toISOString().replace(/\.\d{3}Z$/, "Z"),
};

/** A test evidence type: closed {type, assertion}; an assertion of "fail" fails verification. */
const EVIDENCE_TYPE = "urn:test:intent-evidence:precedence";
registerIntentSubmissionEvidenceType(EVIDENCE_TYPE, {
  validate(entry) {
    if (typeof entry.assertion !== "string") {
      throw new IntentError("invalid_mission_intent_evidence", "precedence: assertion (string) required");
    }
    for (const k of Object.keys(entry)) {
      if (k !== "type" && k !== "assertion") {
        throw new IntentError("invalid_mission_intent_evidence", `precedence: unknown member: ${k}`);
      }
    }
  },
  async verify(input) {
    if (input.entry.assertion === "fail") throw new Error("precedence artifact expired");
    return { verified: true };
  },
});
afterAll(() => unregisterIntentSubmissionEvidenceType(EVIDENCE_TYPE));

const VALID_EVIDENCE = { type: EVIDENCE_TYPE, assertion: "ok" };
const FAILING_EVIDENCE = { type: EVIDENCE_TYPE, assertion: "fail" };
const UNKNOWN_EVIDENCE = { type: "urn:test:intent-evidence:unregistered", assertion: "ok" };
const INVALID_EVIDENCE = { type: EVIDENCE_TYPE, assertion: 5 };
const UNTYPED_EVIDENCE = { assertion: "x" };
const OVERSIZE_EVIDENCE = { ...UNKNOWN_EVIDENCE, assertion: "A".repeat(17_000) };

/**
 * The step 1 evidence failures, as evidence arrays: an entry's structure,
 * and the evidence size bounds. None presents the test type, so each also
 * leaves a required type absent.
 */
const STRUCTURAL_FAILURES: [label: string, evidence: unknown[]][] = [
  ["an evidence entry without a type", [UNTYPED_EVIDENCE]],
  ["an evidence entry that is not an object", ["x"]],
  ["an entry of an unsupported type before an entry without a type", [UNKNOWN_EVIDENCE, UNTYPED_EVIDENCE]],
];
const EVIDENCE_SIZE_FAILURES: [label: string, evidence: unknown[]][] = [
  ["an evidence entry over the size bound", [OVERSIZE_EVIDENCE]],
  ["evidence over the entry-count bound", Array.from({ length: DEFAULT_MAX_EVIDENCE_ENTRIES + 1 }, () => UNKNOWN_EVIDENCE)],
];
/** An Intent over the reference AS's array-length bound (64 `target_resources`). */
const OVERSIZE_INTENT = {
  ...INTENT,
  target_resources: [RESOURCE, ...Array.from({ length: 64 }, (_, i) => `https://r${i}.example/api`)],
};

const VALID_PROPOSAL = [{ type: "mission_resource_access", resource: RESOURCE, actions: ["invoices.read"] }];
const MALFORMED_PROPOSAL = [{ type: "mission_resource_access", resource: RESOURCE, actions: 17 }];
const UNSUPPORTED_PROPOSAL = [{ type: "urn:example:unsupported", resource: RESOURCE }];
const OUTSIDE_PROPOSAL = [{ type: "mission_resource_access", resource: OTHER_RESOURCE, actions: ["invoices.read"] }];

let as: BuiltAs;
let server: Server;
let requiredAs: BuiltAs;
let requiredServer: Server;
let agentKey: CryptoKey;
let requiredAgentKey: CryptoKey;
let deriveAs: BuiltAs;
let deriveServer: Server;
let deriveAgentKey: CryptoKey;
const SESSIONS = new ApprovalSessionStore();
/** The derivation tests' own policy, which the last of them changes after creation. */
const DERIVE_POLICY = structuredClone(DERIVATION_POLICY);

const PKCE_VERIFIER = "submission-precedence-verifier-0123456789-0123456789";
async function pkceChallenge(): Promise<string> {
  return Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(PKCE_VERIFIER)),
  ).toString("base64url");
}

async function clientAssertion(issuer: string, key: CryptoKey): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
    .setIssuer("ap-agent")
    .setSubject("ap-agent")
    .setAudience(issuer)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(key);
}

/** One pushed submission: the envelope (or a raw value) and an optional proposal. */
async function push(
  issuer: string,
  key: CryptoKey,
  envelope: unknown,
  proposal?: unknown,
  extra: Record<string, string> = {},
): Promise<{ status: number; error?: string; body: unknown }> {
  const res = await fetch(`${issuer}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      resource: RESOURCE,
      code_challenge: await pkceChallenge(),
      code_challenge_method: "S256",
      mission_intent: JSON.stringify(envelope),
      ...(proposal === undefined ? {} : { authorization_details: JSON.stringify(proposal) }),
      ...extra,
      client_assertion: await clientAssertion(issuer, key),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const body = (await res.json()) as { error?: string };
  return { status: res.status, ...(body.error ? { error: body.error } : {}), body };
}

/** Each case: a label, the pushed envelope and proposal, and the error the AS must return. */
type Case = [label: string, envelope: unknown, proposal: unknown, expected: string];

async function expectRefusals(issuer: string, key: CryptoKey, cases: Case[]): Promise<void> {
  for (const [label, envelope, proposal, expected] of cases) {
    const res = await push(issuer, key, envelope, proposal);
    expect(res.status, `${label}: ${JSON.stringify(res.body)}`).toBe(400);
    expect(res.error, `${label}: ${JSON.stringify(res.body)}`).toBe(expected);
  }
}

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
  });
  server = as.provider.listen(PORT);
  agentKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  // A second AS whose policy requires the test evidence type.
  requiredAs = await buildAuthorizationServer({
    issuer: REQUIRED_ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    requiredIntentEvidenceTypes: [EVIDENCE_TYPE],
  });
  requiredServer = requiredAs.provider.listen(REQUIRED_PORT);
  requiredAgentKey = (await importJWK(requiredAs.agentClientJwk as never, "ES256")) as CryptoKey;
  deriveAs = await buildAuthorizationServer({
    issuer: DERIVE_ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    approvalSessions: SESSIONS,
    derivationPolicy: DERIVE_POLICY,
  });
  deriveServer = deriveAs.provider.listen(DERIVE_PORT);
  deriveAgentKey = (await importJWK(deriveAs.agentClientJwk as never, "ES256")) as CryptoKey;
});

afterAll(() => {
  server?.close();
  requiredServer?.close();
  deriveServer?.close();
});

describe("Submission Processing Order refusal precedence at PAR (@spec mission#submission-processing)", () => {
  it("accepts a valid submission with a valid proposal and verified evidence", async () => {
    const res = await push(ISSUER, agentKey, { intent: INTENT, evidence: [VALID_EVIDENCE] }, VALID_PROPOSAL);
    expect(res.status, JSON.stringify(res.body)).toBe(201);
  });

  it("checks a proposal pushed with an empty mission_intent, which the provider reads as absent", async () => {
    const res = await push(ISSUER, agentKey, { intent: INTENT }, MALFORMED_PROPOSAL, { mission_intent: "" });
    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(res.error, JSON.stringify(res.body)).toBe("invalid_authorization_details");
  });

  it("an intent object that fails validation together with a malformed proposal is refused at step 2, with invalid_request", async () => {
    const invalidIntent = { intent: { ...INTENT, goal: 17 } };
    await expectRefusals(ISSUER, agentKey, [
      ["invalid Intent only", invalidIntent, VALID_PROPOSAL, "invalid_request"],
      ["malformed proposal only", { intent: INTENT }, MALFORMED_PROPOSAL, "invalid_authorization_details"],
      ["unsupported proposal type only", { intent: INTENT }, UNSUPPORTED_PROPOSAL, "invalid_authorization_details"],
      ["invalid Intent and malformed proposal", invalidIntent, MALFORMED_PROPOSAL, "invalid_request"],
      ["invalid Intent and unsupported proposal type", invalidIntent, UNSUPPORTED_PROPOSAL, "invalid_request"],
    ]);
  });

  it("a malformed Submission envelope together with a malformed proposal is refused at step 1, with invalid_request", async () => {
    const bare = INTENT;
    const unknownMember = { intent: INTENT, note: "x" };
    await expectRefusals(ISSUER, agentKey, [
      ["bare Intent only", bare, VALID_PROPOSAL, "invalid_request"],
      ["unknown envelope member only", unknownMember, VALID_PROPOSAL, "invalid_request"],
      ["bare Intent and malformed proposal", bare, MALFORMED_PROPOSAL, "invalid_request"],
      ["unknown envelope member and malformed proposal", unknownMember, MALFORMED_PROPOSAL, "invalid_request"],
    ]);
  });

  it("a malformed proposal together with a missing required evidence type is refused at step 3, with invalid_authorization_details", async () => {
    await expectRefusals(REQUIRED_ISSUER, requiredAgentKey, [
      ["required evidence absent only", { intent: INTENT }, VALID_PROPOSAL, "invalid_mission_intent_evidence"],
      ["malformed proposal only", { intent: INTENT, evidence: [VALID_EVIDENCE] }, MALFORMED_PROPOSAL, "invalid_authorization_details"],
      ["malformed proposal and required evidence absent", { intent: INTENT }, MALFORMED_PROPOSAL, "invalid_authorization_details"],
    ]);
  });

  it("a proposed entry outside target_resources together with a presented evidence entry that fails verification is refused at step 3, with invalid_request", async () => {
    await expectRefusals(ISSUER, agentKey, [
      ["evidence failing verification only", { intent: INTENT, evidence: [FAILING_EVIDENCE] }, VALID_PROPOSAL, "invalid_mission_intent_evidence"],
      ["entry outside target_resources only", { intent: INTENT }, OUTSIDE_PROPOSAL, "invalid_request"],
      ["entry outside target_resources and evidence failing verification", { intent: INTENT, evidence: [FAILING_EVIDENCE] }, OUTSIDE_PROPOSAL, "invalid_request"],
    ]);
  });

  it("validates the authority proposal before evidence dispatch: a proposal failure precedes an unknown evidence type or an entry failing its type's validation", async () => {
    await expectRefusals(ISSUER, agentKey, [
      ["unknown evidence type only", { intent: INTENT, evidence: [UNKNOWN_EVIDENCE] }, VALID_PROPOSAL, "invalid_mission_intent_evidence"],
      ["evidence failing its type's validation only", { intent: INTENT, evidence: [INVALID_EVIDENCE] }, VALID_PROPOSAL, "invalid_mission_intent_evidence"],
      ["entry outside target_resources and unknown evidence type", { intent: INTENT, evidence: [UNKNOWN_EVIDENCE] }, OUTSIDE_PROPOSAL, "invalid_request"],
      ["entry outside target_resources and evidence failing its type's validation", { intent: INTENT, evidence: [INVALID_EVIDENCE] }, OUTSIDE_PROPOSAL, "invalid_request"],
      ["unsupported proposal type and unknown evidence type", { intent: INTENT, evidence: [UNKNOWN_EVIDENCE] }, UNSUPPORTED_PROPOSAL, "invalid_authorization_details"],
      ["malformed proposal and unknown evidence type", { intent: INTENT, evidence: [UNKNOWN_EVIDENCE] }, MALFORMED_PROPOSAL, "invalid_authorization_details"],
      ["malformed proposal and evidence failing its type's validation", { intent: INTENT, evidence: [INVALID_EVIDENCE] }, MALFORMED_PROPOSAL, "invalid_authorization_details"],
      ["malformed proposal and evidence failing verification", { intent: INTENT, evidence: [FAILING_EVIDENCE] }, MALFORMED_PROPOSAL, "invalid_authorization_details"],
    ]);
  });

  it("reads an empty request parameter as absent, as the provider does, and keeps the order", async () => {
    const withEmptyRequest = await push(ISSUER, agentKey, { intent: INTENT }, VALID_PROPOSAL, { request: "" });
    expect(withEmptyRequest.status, JSON.stringify(withEmptyRequest.body)).toBe(201);
    const ordered = await push(ISSUER, agentKey, { intent: { ...INTENT, goal: 17 } }, MALFORMED_PROPOSAL, { request: "" });
    expect(ordered.status, JSON.stringify(ordered.body)).toBe(400);
    expect(ordered.error, JSON.stringify(ordered.body)).toBe("invalid_request");
  });

  it("reads an empty authorization_details parameter as no proposal, as the provider does", async () => {
    const withEmptyProposal = await push(ISSUER, agentKey, { intent: INTENT }, undefined, { authorization_details: "" });
    expect(withEmptyProposal.status, JSON.stringify(withEmptyProposal.body)).toBe(201);
  });

  it("a structurally invalid evidence entry together with a malformed proposal is refused at step 1, with invalid_request", async () => {
    await expectRefusals(ISSUER, agentKey, [
      ...STRUCTURAL_FAILURES.map(([label, evidence]): Case => [`${label} only`, { intent: INTENT, evidence }, VALID_PROPOSAL, "invalid_request"]),
      ["malformed proposal only", { intent: INTENT, evidence: [VALID_EVIDENCE] }, MALFORMED_PROPOSAL, "invalid_authorization_details"],
      ["unsupported proposal type only", { intent: INTENT, evidence: [VALID_EVIDENCE] }, UNSUPPORTED_PROPOSAL, "invalid_authorization_details"],
      ...STRUCTURAL_FAILURES.flatMap(([label, evidence]): Case[] => [
        [`malformed proposal and ${label}`, { intent: INTENT, evidence }, MALFORMED_PROPOSAL, "invalid_request"],
        [`unsupported proposal type and ${label}`, { intent: INTENT, evidence }, UNSUPPORTED_PROPOSAL, "invalid_request"],
      ]),
    ]);
  });

  it("a submission over a size bound together with a malformed proposal is refused at step 1, with invalid_request", async () => {
    const failures: [label: string, envelope: unknown][] = [
      ...EVIDENCE_SIZE_FAILURES.map(([label, evidence]): [string, unknown] => [label, { intent: INTENT, evidence }]),
      ["an Intent array over the length bound", { intent: OVERSIZE_INTENT }],
    ];
    await expectRefusals(ISSUER, agentKey, [
      ...failures.map(([label, envelope]): Case => [`${label} only`, envelope, VALID_PROPOSAL, "invalid_request"]),
      ["malformed proposal only", { intent: INTENT }, MALFORMED_PROPOSAL, "invalid_authorization_details"],
      ["unsupported proposal type only", { intent: INTENT }, UNSUPPORTED_PROPOSAL, "invalid_authorization_details"],
      ...failures.flatMap(([label, envelope]): Case[] => [
        [`malformed proposal and ${label}`, envelope, MALFORMED_PROPOSAL, "invalid_request"],
        [`unsupported proposal type and ${label}`, envelope, UNSUPPORTED_PROPOSAL, "invalid_request"],
      ]),
    ]);
  });

  it("a structurally invalid evidence entry, or evidence over a size bound, together with a missing required evidence type is refused at step 1, with invalid_request", async () => {
    await expectRefusals(REQUIRED_ISSUER, requiredAgentKey, [
      ["required type present and an entry without a type", { intent: INTENT, evidence: [VALID_EVIDENCE, UNTYPED_EVIDENCE] }, VALID_PROPOSAL, "invalid_request"],
      ["required type absent only", { intent: INTENT }, VALID_PROPOSAL, "invalid_mission_intent_evidence"],
      ...[...STRUCTURAL_FAILURES, ...EVIDENCE_SIZE_FAILURES].map(([label, evidence]): Case => [`required type absent and ${label}`, { intent: INTENT, evidence }, VALID_PROPOSAL, "invalid_request"]),
    ]);
  });
});

/** Push the demo proposal, render its approval, approve it, and return the rendered set and the record. */
async function renderAndApprove(): Promise<{ rendered: unknown; recordId: string; approved: unknown }> {
  const cookies = new Map<string, string>();
  const cookieHeader = () => [...cookies.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
  const storeCookies = (res: Response) => {
    for (const line of res.headers.getSetCookie()) {
      const [pair] = line.split(";");
      const eq = (pair as string).indexOf("=");
      cookies.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
    }
  };
  const par = await push(DERIVE_ISSUER, deriveAgentKey, { intent: INTENT }, DEMO_AGENT_PROPOSAL, { login_hint: "alice" });
  expect(par.status, JSON.stringify(par.body)).toBe(201);
  const { request_uri } = par.body as { request_uri: string };
  let res = await fetch(`${DERIVE_ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri })}`, {
    redirect: "manual",
  });
  storeCookies(res);
  const uid = (res.headers.get("location") as string).split("/interaction/")[1] as string;
  const page = await fetch(`${DERIVE_ISSUER}/interaction/${uid}`, { headers: { cookie: cookieHeader() } });
  const html = await page.text();
  const block = (html.split("<h2>Derived authority (what approval grants)</h2><pre>")[1] as string).split("</pre>")[0] as string;
  const rendered: unknown = JSON.parse(block.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&"));
  const decideHeaders = { ...floorApprovalHeaders(SESSIONS, uid, cookieHeader()), "content-type": "application/json" };
  const render_revision = await renderedRevision(DERIVE_ISSUER, uid, decideHeaders);
  res = await fetch(`${DERIVE_ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: decideHeaders,
    body: JSON.stringify({ decision: "approve", render_revision }),
  });
  expect(res.status, await res.clone().text()).toBe(303);
  const record = deriveAs.kernel.findByApprovalEvent(`apev_${uid}`);
  expect(record).toBeDefined();
  return { rendered, recordId: record?.id as string, approved: record?.authority_set };
}

describe("Authority Set derivation timing (@spec mission#derivation-modes)", () => {
  it("renders the complete candidate Authority Set for approval, and the Mission Record commits exactly the rendered set", async () => {
    const { rendered, approved } = await renderAndApprove();
    // The complete candidate: the full derivation of this Intent and proposal,
    // more than one entry, not a partial set.
    const full = deriveAs.kernel.derive(deriveAs.kernel.validateSubmission(JSON.stringify({ intent: INTENT })).intent, DEMO_AGENT_PROPOSAL as never);
    expect(full.length).toBeGreaterThan(1);
    expect(rendered).toEqual(full);
    // The record commits the rendered entries. The only member it adds is
    // the Capability Binding companion's capability_sources, which
    // kernel.approve binds at the commit (docs/provider-integration-port.md
    // section 3.3) and the rendering does not show.
    const committed = (approved as Record<string, unknown>[]).map(({ capability_sources: _, ...rest }) => rest);
    expect(committed).toEqual(rendered);
  });

  it("keeps the approved Authority Set fixed after creation: a later derivation-policy change does not recompute it", async () => {
    const { recordId, approved } = await renderAndApprove();
    const intent = deriveAs.kernel.validateSubmission(JSON.stringify({ intent: INTENT })).intent;
    // Narrow the policy after creation: drop invoice.list from every ceiling entry.
    for (const entry of DERIVE_POLICY.ceiling) {
      (entry as { actions: string[] }).actions = (entry as { actions: string[] }).actions.filter((a) => a !== "payments:invoice.list");
    }
    // The change takes effect: a fresh derivation now differs from the approved set.
    expect(deriveAs.kernel.derive(intent, DEMO_AGENT_PROPOSAL as never)).not.toEqual(approved);
    // The created Mission's Authority Set is unchanged.
    expect(deriveAs.kernel.get(recordId)?.authority_set).toEqual(approved);
  });
});
