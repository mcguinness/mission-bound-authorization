/**
 * @spec mission#authority-proposal, mission#integrity-anchors,
 * mission#downgrade-by-omission, mission#introspection (issue #475)
 *
 * The RAR-carriage contract: the client's authority proposal rides the
 * STANDARD `authorization_details` request parameter pushed through PAR
 * alongside `mission_intent`; the Intent is pure task context. Covers:
 *  - the pinned `proposal_hash` test vector (core test vector 5);
 *  - an Intent carrying the retired `proposed_authority` member is refused
 *    as an unknown top-level member (unit + wire);
 *  - bare authorization_details from an UNgoverned client is an ordinary
 *    RFC 9396 request this profile does not govern (PAR accepts it);
 *  - bare authorization_details from a Mission-governed client is rejected
 *    (the AS-side anti-downgrade hook);
 *  - a template-mode Mission (no proposal) records NEITHER
 *    `proposed_authority` nor `proposal_hash`;
 *  - a narrowing-mode Mission records both; introspection surfaces
 *    `proposal_hash` (issuer-only) and the `mission` token claim NEVER does;
 *  - the remediation loop closes natively: `authorization_remediation`
 *    output feeds the standard parameter with no re-wrapping.
 */

import { browserApprovalHeaders, floorApprovalHeaders, renderedRevision, TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";

import { type Server } from "node:http";
import { computeAnchor, PROPOSED_AUTHORITY_TYP, proposalHash } from "@mission/core";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { buildInsufficientAuthorization } from "@mission/mcp-payments";
import { exportJWK, generateKeyPair, importJWK, SignJWT, type CryptoKey } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  ApprovalSessionStore,
  buildAuthorizationServer,
  IntentError,
  MissionKernel,
  validateAuthorityProposal,
  validateMissionIntent,
  type AuthorityEntry,
  type BuiltAs,
} from "../src/index.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const PORT = 14502;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;

// ---------------------------------------------------------------------------
// Unit level: anchors, intake, record shape (network-free kernel).
// ---------------------------------------------------------------------------

/** The core draft's test vector 5 inputs, byte-for-byte. */
const VECTOR_ISS = "https://as.example.com";
const VECTOR_VALUE = [
  {
    type: "mission_resource_access",
    resource: "https://erp.example.com",
    actions: ["invoices.*"],
  },
  {
    type: "mission_resource_access",
    resource: "https://erp.example.com",
    actions: ["journal-entries.write"],
    constraints: { max_amount: { amount: "1000.00", currency: "USD" } },
  },
];
const VECTOR_ANCHOR = "sha-256:udzftXYQy0pvYNxz4KgtmyL_EV8ry4DhIbBFfwILEBA";

describe("proposal_hash anchor (@spec mission#integrity-anchors, test vector 5)", () => {
  it("pins typ mission-proposed-authority", () => {
    expect(PROPOSED_AUTHORITY_TYP).toBe("mission-proposed-authority");
  });

  it("reproduces the core draft's pinned vector exactly", () => {
    expect(computeAnchor(PROPOSED_AUTHORITY_TYP, VECTOR_ISS, VECTOR_VALUE)).toBe(VECTOR_ANCHOR);
    expect(proposalHash(VECTOR_ISS, VECTOR_VALUE)).toBe(VECTOR_ANCHOR);
  });
});

const TASK_INTENT = {
  goal: "Pay Acme invoices for Q3",
  target_resources: [RESOURCE],
  expires_at: "2027-01-01T00:00:00Z",
};

const PROPOSAL: AuthorityEntry[] = [
  {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions: ["payments:invoice.read", "payments:remittance.send"],
    constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  },
];

describe("Intent carries no authority members (@spec mission#authority-proposal)", () => {
  it("refuses an Intent carrying proposed_authority as an unknown top-level member", () => {
    try {
      validateMissionIntent(JSON.stringify({ ...TASK_INTENT, proposed_authority: PROPOSAL }));
      expect.unreachable("intent with proposed_authority must be refused");
    } catch (e) {
      expect(e).toBeInstanceOf(IntentError);
      expect((e as IntentError).code).toBe("invalid_request");
      expect((e as IntentError).message).toContain("unknown top-level member: proposed_authority");
    }
  });
});

describe("record + introspection vs claim (@spec mission#mission-record, #introspection)", () => {
  let key: CryptoKey;
  let kernel: MissionKernel;
  let seq = 0;

  beforeAll(async () => {
    key = (await generateKeyPair("ES256")).privateKey;
    kernel = new MissionKernel({
      issuer: ISSUER,
      policy: DERIVATION_POLICY as never,
      authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["ap-agent"], ["bob"]),
      statusKey: key,
      statusKid: "as-status",
    });
  });

  const approve = (proposedAuthority?: AuthorityEntry[]) =>
    kernel.approve({
      intent: validateMissionIntent(JSON.stringify(TASK_INTENT)),
      ...(proposedAuthority ? { proposedAuthority } : {}),
      subject: { iss: ISSUER, sub: "alice" },
      approver: { iss: ISSUER, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: `rar-apev-${seq++}`,
    });

  it("a template-mode Mission records NEITHER proposed_authority nor proposal_hash", () => {
    const record = approve();
    expect(record.proposed_authority).toBeUndefined();
    expect(record.proposal_hash).toBeUndefined();
    const persisted = kernel.get(record.id);
    expect(persisted).toBeDefined();
    expect("proposed_authority" in (persisted as object)).toBe(false);
    expect("proposal_hash" in (persisted as object)).toBe(false);
    expect(kernel.introspectionMission(record).proposal_hash).toBeUndefined();
  });

  it("a narrowing-mode Mission records the submitted array and its commitment", () => {
    const record = approve(PROPOSAL);
    expect(record.proposed_authority).toEqual(PROPOSAL);
    expect(record.proposal_hash).toBe(proposalHash(ISSUER, PROPOSAL as never));
    // Round-trips through the store.
    const persisted = kernel.get(record.id);
    expect(persisted?.proposed_authority).toEqual(PROPOSAL);
    expect(persisted?.proposal_hash).toBe(record.proposal_hash);
    // Narrowing mode: every derived entry is a same-type subset of a proposal.
    for (const entry of record.authority_set) {
      expect(entry.type).toBe("mission_resource_access");
      expect(PROPOSAL.some((p) => p.resource === entry.resource)).toBe(true);
    }
  });

  it("introspection surfaces proposal_hash; the mission claim NEVER carries it", () => {
    const record = approve(PROPOSAL);
    const introspected = kernel.introspectionMission(record);
    expect(introspected.proposal_hash).toBe(record.proposal_hash);
    // @spec mission#the-mission-claim (#702) — the baseline claim is exactly
    // {id, issuer}: authority_hash, expires_at and approval_basis are NOT
    // part of it (they are added only by a companion profile that owns them).
    const claim = kernel.missionClaim(record);
    expect(Object.keys(claim).sort()).toEqual(["id", "issuer"]);
  });

  it("closes the remediation loop natively (@spec I-D.draft-zehavi-oauth-rar-metadata)", () => {
    // The RS's insufficient_authorization grain names the actionable entries...
    const grain = buildInsufficientAuthorization(PROPOSAL);
    const decoded = JSON.parse(
      Buffer.from(grain.authorization_remediation, "base64url").toString("utf8"),
    ) as { authorization_details: AuthorityEntry[] };
    // ...and its output vocabulary IS this document's input carriage: the
    // decoded entries feed the standard parameter directly (validated by the
    // ordinary intake) and derive under the ordinary narrowing rules.
    const proposal = validateAuthorityProposal(
      JSON.stringify(decoded.authorization_details),
      TASK_INTENT.target_resources,
    );
    expect(proposal).toEqual(PROPOSAL);
    const record = approve(proposal);
    expect(record.proposal_hash).toBe(proposalHash(ISSUER, PROPOSAL as never));
    expect(record.authority_set.length).toBeGreaterThan(0);
  });

  it("intake refuses an unadvertised type / schema failure / foreign resource", () => {
    expect(() =>
      validateAuthorityProposal(
        JSON.stringify([{ type: "payment_initiation", resource: RESOURCE, actions: ["x"] }]),
        TASK_INTENT.target_resources,
      ),
    ).toThrowError(/unsupported authorization details type/);
    try {
      validateAuthorityProposal(
        JSON.stringify([{ type: "mission_resource_access", resource: RESOURCE, actions: [] }]),
        TASK_INTENT.target_resources,
      );
      expect.unreachable("schema failure must refuse");
    } catch (e) {
      expect((e as IntentError).code).toBe("invalid_authorization_details");
    }
    try {
      validateAuthorityProposal(
        JSON.stringify([
          { type: "mission_resource_access", resource: "https://other.example", actions: ["a"] },
        ]),
        TASK_INTENT.target_resources,
      );
      expect.unreachable("foreign resource must refuse");
    } catch (e) {
      expect((e as IntentError).code).toBe("invalid_request");
    }
  });
});

// ---------------------------------------------------------------------------
// Wire level: PAR carriage, the governed-client hook, end-to-end issuance.
// ---------------------------------------------------------------------------

let as: BuiltAs;
let asServer: Server;
let agentKey: CryptoKey;
let governedKey: CryptoKey;

const cookies = new Map<string, string>();
function cookieHeader(): string {
  return [...cookies.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
}
function storeCookies(res: Response): void {
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const eq = (pair as string).indexOf("=");
    cookies.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
  }
}

async function clientAssertion(clientId: string, kid: string, key: CryptoKey): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid })
    .setIssuer(clientId)
    .setSubject(clientId)
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(key);
}

const PKCE_VERIFIER = "rar-carriage-verifier-0123456789-0123456789-01234";
async function pkceChallenge(): Promise<string> {
  return Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(PKCE_VERIFIER)),
  ).toString("base64url");
}

async function pushPar(
  clientId: string,
  kid: string,
  key: CryptoKey,
  params: Record<string, string>,
): Promise<Response> {
  return fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: clientId,
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      resource: RESOURCE,
      code_challenge: await pkceChallenge(),
      code_challenge_method: "S256",
      ...params,
      client_assertion: await clientAssertion(clientId, kid, key),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
}

// The trusted browser login: an Approver authenticated in the user agent
// itself, the only approval an ID Token can describe (#826).
const SESSIONS = new ApprovalSessionStore();

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    approvalSessions: SESSIONS,
  });
  asServer = as.provider.listen(PORT);
  agentKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  governedKey = (await importJWK(as.governedClientJwk as never, "ES256")) as CryptoKey;
});

afterAll(() => {
  asServer?.close();
});

describe("PAR carriage (@spec mission#authority-proposal, #downgrade-by-omission)", () => {
  it("accepts authorization_details alongside mission_intent as the proposal", async () => {
    const res = await pushPar("ap-agent", "ap-agent-auth", agentKey, {
      login_hint: "alice",
      mission_intent: JSON.stringify({ intent: TASK_INTENT }),
      authorization_details: JSON.stringify(PROPOSAL),
    });
    expect(res.status).toBe(201);
    expect(((await res.json()) as { request_uri?: string }).request_uri).toBeDefined();
  });

  it("bare authorization_details from an UNgoverned client is the ordinary OAuth path", async () => {
    const res = await pushPar("ap-agent", "ap-agent-auth", agentKey, {
      authorization_details: JSON.stringify(PROPOSAL),
    });
    // This document does not govern the request: PAR accepts it as ordinary
    // RFC 9396 input (no Mission is involved).
    expect(res.status).toBe(201);
  });

  it("rejects bare authorization_details from a Mission-governed client", async () => {
    const res = await pushPar("governed-agent", "governed-agent-auth", governedKey, {
      authorization_details: JSON.stringify(PROPOSAL),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    // Authority Proposal names invalid_request for this rejection.
    expect(body.error).toBe("invalid_request");
  });

  it("a governed client submitting the proposal WITH mission_intent proceeds", async () => {
    const res = await pushPar("governed-agent", "governed-agent-auth", governedKey, {
      login_hint: "alice",
      mission_intent: JSON.stringify({ intent: TASK_INTENT }),
      authorization_details: JSON.stringify(PROPOSAL),
    });
    expect(res.status).toBe(201);
  });

  it("refuses a pushed Intent that carries the retired proposed_authority member", async () => {
    const res = await pushPar("ap-agent", "ap-agent-auth", agentKey, {
      login_hint: "alice",
      mission_intent: JSON.stringify({ intent: { ...TASK_INTENT, proposed_authority: PROPOSAL } }),
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe("invalid_request");
  });

  it("refuses an already-past requested expires_at at submission acceptance (invalid_request)", async () => {
    // @spec mission#mission-intent (issue #647) — the requested ceiling is
    // refused at submission acceptance, not rewritten forward and not accepted
    // into a Mission that would be expired the instant it committed.
    const res = await pushPar("ap-agent", "ap-agent-auth", agentKey, {
      login_hint: "alice",
      mission_intent: JSON.stringify({
        intent: { ...TASK_INTENT, expires_at: "2020-01-01T00:00:00Z" },
      }),
      authorization_details: JSON.stringify(PROPOSAL),
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe("invalid_request");
  });

  it("refuses an unparseable requested expires_at at submission acceptance (invalid_request)", async () => {
    const res = await pushPar("ap-agent", "ap-agent-auth", agentKey, {
      login_hint: "alice",
      mission_intent: JSON.stringify({ intent: { ...TASK_INTENT, expires_at: "whenever" } }),
      authorization_details: JSON.stringify(PROPOSAL),
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe("invalid_request");
  });

  it("refuses a proposal entry whose resource is not among the Intent resources", async () => {
    const res = await pushPar("ap-agent", "ap-agent-auth", agentKey, {
      login_hint: "alice",
      mission_intent: JSON.stringify({ intent: TASK_INTENT }),
      authorization_details: JSON.stringify([
        { type: "mission_resource_access", resource: "https://other.example", actions: ["a"] },
      ]),
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe("invalid_request");
  });

  // @spec resource-access#entry-validation, resource-access#resource-access-type
  // (#1276): "A `resource` value under `prefix` MUST NOT carry a query or
  // fragment component; the authorization server MUST refuse such an entry
  // with the `invalid_authorization_details` error code." A well-formed `prefix`
  // entry is admitted at intake, and an unrecognized value is refused.
  it("refuses a prefix entry whose resource carries a query or a fragment, and an unrecognized resource_match, with invalid_authorization_details before any interaction, creating no Mission; a well-formed prefix entry is admitted", async () => {
    const QUERIED = `${RESOURCE}?tenant=a`;
    const variants: Array<[string, Record<string, unknown>, RegExp]> = [
      ["query", { resource: QUERIED, resource_match: "prefix" }, /carries a query component/],
      ["fragment", { resource: `${RESOURCE}#invoices`, resource_match: "prefix" }, /not an RFC 3986 absolute URI/],
      ["unrecognized", { resource: RESOURCE, resource_match: "glob" }, /resource_match "glob" is not a value Resource Access defines/],
    ];
    for (const [label, over, description] of variants) {
      const before = as.kernel.allMissions().length;
      const res = await pushPar("ap-agent", "ap-agent-auth", agentKey, {
        login_hint: "alice",
        // The queried resource is also an Intent target, so only the prefix rule refuses it.
        mission_intent: JSON.stringify({ intent: { ...TASK_INTENT, target_resources: [RESOURCE, QUERIED] } }),
        authorization_details: JSON.stringify([{ type: "mission_resource_access", actions: ["payments:invoice.read"], ...over }]),
      });
      expect(res.status, label).toBe(400);
      const body = (await res.json()) as { error: string; error_description?: string };
      expect(body.error, label).toBe("invalid_authorization_details");
      expect(body.error_description, label).toMatch(description);
      expect(as.kernel.allMissions().length, label).toBe(before);
    }
    // Control: the same queried resource as an exact entry, and a prefix entry
    // naming the Intent's target without a query, are admitted.
    for (const over of [{ resource: QUERIED }, { resource: RESOURCE, resource_match: "prefix" }]) {
      const res = await pushPar("ap-agent", "ap-agent-auth", agentKey, {
        login_hint: "alice",
        mission_intent: JSON.stringify({ intent: { ...TASK_INTENT, target_resources: [RESOURCE, QUERIED] } }),
        authorization_details: JSON.stringify([{ type: "mission_resource_access", actions: ["payments:invoice.read"], ...over }]),
      });
      expect(res.status, JSON.stringify(over)).toBe(201);
    }
  });

  it("accepts an explicit resource_match exact, the default (positive control for the prefix refusal)", async () => {
    const res = await pushPar("ap-agent", "ap-agent-auth", agentKey, {
      login_hint: "alice",
      mission_intent: JSON.stringify({ intent: TASK_INTENT }),
      authorization_details: JSON.stringify([
        { type: "mission_resource_access", resource: RESOURCE, resource_match: "exact", actions: ["payments:invoice.read"] },
      ]),
    });
    expect(res.status).toBe(201);
  });

  // @spec resource-access#entry-validation (#1278, D457): this type does not
  // use the RFC 9396 `locations` field, so an entry carrying it is refused at
  // intake by presence, before any interaction or Mission, never admitted and
  // then dropped by derivation's rebuild. The provider's own common-field
  // check already refuses a `locations` that is not an array of strings; an
  // empty or populated array reaches this implementation's guard.
  it("refuses a proposal entry carrying locations, whatever its value, before any interaction, creating no Mission", async () => {
    for (const locations of [[], [RESOURCE], null, "", { uri: RESOURCE }]) {
      const before = as.kernel.allMissions().length;
      const res = await pushPar("ap-agent", "ap-agent-auth", agentKey, {
        login_hint: "alice",
        mission_intent: JSON.stringify({ intent: TASK_INTENT }),
        authorization_details: JSON.stringify([
          { type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"], locations },
        ]),
      });
      const body = (await res.json()) as { error: string; error_description?: string; request_uri?: string };
      expect(res.status, JSON.stringify(locations)).toBe(400);
      expect(body.error).toBe("invalid_authorization_details");
      expect(body.error_description).toMatch(/locations/);
      expect(body.request_uri).toBeUndefined();
      expect(as.kernel.allMissions().length).toBe(before);
    }
  });

  // @spec mission#subset (#1399, D538): a top-level member outside the type's
  // own members and capability_sources is refused at intake by presence,
  // before any interaction or Mission, never admitted and then dropped by
  // derivation's rebuild.
  it("refuses a proposal entry carrying an unsupported member, whatever its value, before any interaction, creating no Mission", async () => {
    for (const invoice_ids of [["INV-7"], [], null, ""]) {
      const before = as.kernel.allMissions().length;
      const res = await pushPar("ap-agent", "ap-agent-auth", agentKey, {
        login_hint: "alice",
        mission_intent: JSON.stringify({ intent: TASK_INTENT }),
        authorization_details: JSON.stringify([
          { type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"], invoice_ids },
        ]),
      });
      const body = (await res.json()) as { error: string; error_description?: string; request_uri?: string };
      expect(res.status, JSON.stringify(invoice_ids)).toBe(400);
      expect(body.error).toBe("invalid_authorization_details");
      expect(body.error_description).toMatch(/invoice_ids is not a supported member/);
      expect(body.request_uri).toBeUndefined();
      expect(as.kernel.allMissions().length).toBe(before);
    }
  });

  // @spec resource-access#entry-validation, mission#mission-intent (#1310,
  // D480): an entry's resource and each Intent target_resources value are one
  // RFC 3986 absolute URI under the shared check, refused at PAR before any
  // interaction or Mission. `new URL()` accepted both of these values.
  it("refuses a proposal entry whose resource is not an RFC 3986 absolute URI with invalid_authorization_details, creating no Mission", async () => {
    for (const resource of [`${RESOURCE}/%zz`, "https:x"]) {
      const before = as.kernel.allMissions().length;
      const res = await pushPar("ap-agent", "ap-agent-auth", agentKey, {
        login_hint: "alice",
        mission_intent: JSON.stringify({ intent: TASK_INTENT }),
        authorization_details: JSON.stringify([
          { type: "mission_resource_access", resource, actions: ["payments:invoice.read"] },
        ]),
      });
      const body = (await res.json()) as { error: string; error_description?: string; request_uri?: string };
      expect(res.status, resource).toBe(400);
      expect(body.error, resource).toBe("invalid_authorization_details");
      expect(body.error_description, resource).toMatch(/is not an RFC 3986 absolute URI/);
      expect(body.request_uri).toBeUndefined();
      expect(as.kernel.allMissions().length).toBe(before);
    }
  });

  it("refuses an Intent whose target_resources value is not an RFC 3986 absolute URI with invalid_request, creating no Mission", async () => {
    for (const target of [`${RESOURCE}/%zz`, "https:///x"]) {
      const before = as.kernel.allMissions().length;
      const res = await pushPar("ap-agent", "ap-agent-auth", agentKey, {
        login_hint: "alice",
        mission_intent: JSON.stringify({ intent: { ...TASK_INTENT, target_resources: [RESOURCE, target] } }),
      });
      const body = (await res.json()) as { error: string; error_description?: string; request_uri?: string };
      expect(res.status, target).toBe(400);
      expect(body.error, target).toBe("invalid_request");
      expect(body.error_description, target).toBe(`resource is not an absolute URI: ${target}`);
      expect(body.request_uri).toBeUndefined();
      expect(as.kernel.allMissions().length).toBe(before);
    }
  });

  it("admits a proposal entry carrying capability_sources, a member another specification defines for this type (positive control for the locations refusal)", async () => {
    const res = await pushPar("ap-agent", "ap-agent-auth", agentKey, {
      login_hint: "alice",
      mission_intent: JSON.stringify({ intent: TASK_INTENT }),
      authorization_details: JSON.stringify([
        {
          type: "mission_resource_access",
          resource: RESOURCE,
          actions: ["payments:invoice.read"],
          capability_sources: [
            {
              action: "payments:invoice.read",
              tool_id: "mcp://payments.test/tools/get_invoice",
              source_uri: "https://payments.test/.well-known/mcp",
              source_digest: "sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
              operation_ref: "get_invoice",
            },
          ],
        },
      ]),
    });
    expect(res.status).toBe(201);
  });
});

describe("Submission envelope carriage (@spec mission#submission-via-par, issue #506)", () => {
  it("refuses the retired bare-Intent parameter shape (invalid_request)", async () => {
    const res = await pushPar("ap-agent", "ap-agent-auth", agentKey, {
      login_hint: "alice",
      mission_intent: JSON.stringify(TASK_INTENT),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string; error_description?: string };
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toContain("bare Mission Intent shape");
  });

  it("refuses an unknown evidence type on the wire (no types are registered)", async () => {
    const res = await pushPar("ap-agent", "ap-agent-auth", agentKey, {
      login_hint: "alice",
      mission_intent: JSON.stringify({
        intent: TASK_INTENT,
        evidence: [
          {
            type: "urn:ietf:params:oauth:mission:intent-evidence:intent-admission",
            assertion: "eyJhbGciOiJFUzI1NiJ9..sig",
          },
        ],
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string; error_description?: string };
    // Type-dispatch failures carry the core-registered code; structural
    // envelope failures stay invalid_request (the two tests beside this one).
    expect(body.error).toBe("invalid_mission_intent_evidence");
    expect(body.error_description).toContain("unknown evidence type");
  });

  it("refuses a typeless evidence entry on the wire", async () => {
    const res = await pushPar("ap-agent", "ap-agent-auth", agentKey, {
      login_hint: "alice",
      mission_intent: JSON.stringify({ intent: TASK_INTENT, evidence: [{ assertion: "eyJ" }] }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string; error_description?: string };
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toContain("evidence entries require a type");
  });
});

describe("end-to-end issuance under the new carriage", () => {
  // An OVER-ASK: a cap above the policy ceiling (900 > 500) and an action the
  // ceiling does not grant. Derivation must narrow both; the record still
  // commits the proposal EXACTLY as submitted, so the client can diff the
  // granted echo against what proposal_hash commits.
  const OVER_ASK: AuthorityEntry[] = [
    {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: ["payments:invoice.read", "payments:remittance.send", "payments:acquire.company"],
      constraints: { max_amount: { amount: "900.00", currency: "USD" }, vendors: ["acme"] },
    },
  ];

  it("derives issuer-side, echoes the granted set, surfaces proposal_hash issuer-only", async () => {
    const par = await pushPar("ap-agent", "ap-agent-auth", agentKey, {
      login_hint: "alice",
      mission_intent: JSON.stringify({ intent: TASK_INTENT }),
      authorization_details: JSON.stringify(OVER_ASK),
    });
    expect(par.status).toBe(201);
    const { request_uri } = (await par.json()) as { request_uri: string };

    const authUrl = `${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri })}`;
    let res = await fetch(authUrl, { redirect: "manual" });
    storeCookies(res);
    let location = res.headers.get("location") as string;
    const uid = location.split("/interaction/")[1] as string;

    // The approval rendering distinguishes the submitted proposal from the
    // derived Authority Set (@spec mission#approval-event).
    const page = await fetch(`${ISSUER}/interaction/${uid}`, {
      headers: { cookie: cookieHeader() },
    });
    const html = await page.text();
    expect(html).toContain("Proposed authority (submitted, untrusted)");
    expect(html).toContain("Derived authority (what approval grants)");

    const decideHeaders = { ...floorApprovalHeaders(SESSIONS, uid, cookieHeader()), "content-type": "application/json" };
    const render_revision = await renderedRevision(ISSUER, uid, decideHeaders);
    res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
      method: "POST",
      redirect: "manual",
      headers: decideHeaders,
      body: JSON.stringify({ decision: "approve", render_revision }),
    });
    storeCookies(res);
    location = res.headers.get("location") as string;
    while (location?.startsWith(ISSUER)) {
      res = await fetch(location, { redirect: "manual", headers: { cookie: cookieHeader() } });
      storeCookies(res);
      location = res.headers.get("location") as string;
    }
    const code = new URL(location).searchParams.get("code") as string;

    const dpopKeys = await generateKeyPair("ES256", { extractable: true });
    const dpopPub = await exportJWK(dpopKeys.publicKey);
    const htu = `${ISSUER}/token`;
    const send = async (extra: Record<string, unknown> = {}): Promise<Response> =>
      fetch(htu, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          dpop: await new SignJWT({ htu, htm: "POST", ...extra })
            .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: dpopPub })
            .setIssuedAt()
            .setJti(crypto.randomUUID())
            .sign(dpopKeys.privateKey),
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: REDIRECT_URI,
          code_verifier: PKCE_VERIFIER,
          resource: RESOURCE,
          client_assertion: await clientAssertion("ap-agent", "ap-agent-auth", agentKey),
          client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        }).toString(),
      });
    let tok = await send();
    const nonce = tok.headers.get("dpop-nonce");
    if (tok.status === 400 && nonce) tok = await send({ nonce });
    expect(tok.status).toBe(200);
    const body = (await tok.json()) as {
      access_token: string;
      authorization_details: AuthorityEntry[];
      mission_id?: string;
      mission_expires_at?: string;
    };

    // The granted echo is the ISSUER-DERIVED set (a same-type subset of the
    // proposal), never the submission carried through by right: the over-asked
    // cap narrows to the policy ceiling and the ungrantable action is dropped.
    expect(body.authorization_details.length).toBeGreaterThan(0);
    for (const entry of body.authorization_details) {
      expect(entry.type).toBe("mission_resource_access");
      expect(entry.resource).toBe(RESOURCE);
      expect(entry.actions).not.toContain("payments:acquire.company");
    }
    // @spec mission#authorization-derivation (#743) — the payments ceiling is
    // now two entries (money-bearing / read-only), so this one over-broad
    // proposal derives two fragments. The over-asked cap (900) narrows to the
    // ceiling's 500 on the fragment the ceiling actually bounds
    // (remittance.send is in the money-bearing ceiling entry); selected by
    // action, not a blanket loop over every fragment.
    const payFragment = body.authorization_details.find((e) => e.actions.includes("payments:remittance.send"));
    expect(payFragment?.constraints?.max_amount?.amount).toBe("500.00");

    // The mission claim never carries the proposal members, and (#702) is
    // exactly the baseline {id, issuer}.
    const claims = JSON.parse(
      Buffer.from(body.access_token.split(".")[1] as string, "base64url").toString(),
    ) as { mission: Record<string, unknown> };
    expect(Object.keys(claims.mission).sort()).toEqual(["id", "issuer"]);

    // The record committed the submitted proposal; introspection (issuer-only
    // surface) reports proposal_hash beside state.
    const missionId = claims.mission.id as string;
    const record = as.kernel.get(missionId);
    // @spec mission#grant-binding (issue #647) — the DIRECT-creation success
    // response, the body that first delivers the new Mission's credential,
    // carries both common members: the identifier, and the COMMITTED effective
    // expiry verbatim off the record (not `expires_in`, which is the access
    // token's own lifetime).
    expect(body.mission_id).toBe(missionId);
    expect(body.mission_expires_at).toBe(record?.expires_at);
    expect(Date.parse(body.mission_expires_at as string)).toBeLessThanOrEqual(
      Date.parse(TASK_INTENT.expires_at),
    );
    expect(record?.proposed_authority).toEqual(OVER_ASK);
    expect(record?.proposal_hash).toBe(proposalHash(ISSUER, OVER_ASK as never));
    const introspection = await fetch(`${ISSUER}/introspect`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${Buffer.from("rs-payments:dev-introspection-rs-payments").toString("base64")}`,
      },
      body: new URLSearchParams({ token: body.access_token }).toString(),
    });
    const intro = (await introspection.json()) as {
      active: boolean;
      mission: Record<string, unknown>;
    };
    expect(intro.active).toBe(true);
    expect(intro.mission.proposal_hash).toBe(record?.proposal_hash);
    expect(intro.mission.state).toBe("active");
  });
});

// D284, #1328: the approval page tells the Approver that a per-action limit
// applies to each action and that the approval imposes no total spending cap.
// The wording is this deployment's, shown under the derived authority only
// when an entry the approval grants carries `max_amount`.
describe("approval page per-action limit wording (D284, #1328)", () => {
  const PER_ACTION = "These limits apply to each action.";
  const NO_TOTAL = "This approval does not impose a total spending cap across the Mission.";

  async function renderApproval(proposal: AuthorityEntry[]): Promise<{ status: number; html: string }> {
    const par = await pushPar("ap-agent", "ap-agent-auth", agentKey, {
      login_hint: "alice",
      mission_intent: JSON.stringify({ intent: TASK_INTENT }),
      authorization_details: JSON.stringify(proposal),
    });
    expect(par.status).toBe(201);
    const { request_uri } = (await par.json()) as { request_uri: string };
    const auth = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri })}`, {
      redirect: "manual",
    });
    storeCookies(auth);
    const uid = (auth.headers.get("location") as string).split("/interaction/")[1] as string;
    const page = await fetch(`${ISSUER}/interaction/${uid}`, { headers: { cookie: cookieHeader() } });
    return { status: page.status, html: await page.text() };
  }

  it("states that the limits apply to each action and impose no total spending cap when a derived entry carries max_amount", async () => {
    const { status, html } = await renderApproval([
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: ["payments:payment.schedule"],
        constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
      },
    ]);
    expect(status).toBe(200);
    const derived = html.split("Derived authority (what approval grants)")[1] as string;
    expect(derived).toContain('"max_amount"');
    expect(derived).toContain(`${PER_ACTION} ${NO_TOTAL}`);
  });

  it("does not state the per-action limit wording when no derived entry carries max_amount", async () => {
    const { status, html } = await renderApproval([
      { type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] },
    ]);
    expect(status).toBe(200);
    expect(html).toContain("Derived authority (what approval grants)");
    expect(html).toContain('"vendors"');
    expect(html).not.toContain('"max_amount"');
    expect(html).not.toContain(PER_ACTION);
    expect(html).not.toContain(NO_TOTAL);
  });
});

// @spec mission#error-mapping — the two derivation-refusal branches at the
// authorization decision: a submitted proposal that derives nothing is
// invalid_authorization_details; configured-mapping mode (no proposal
// submitted) that derives nothing is access_denied. Wire-level, following
// the same PAR -> /interaction -> decide flow as the end-to-end test above.
describe("derivation refusal at the authorization decision (@spec mission#error-mapping)", () => {
  async function decideAndGetErrorRedirect(missionIntent: unknown, authorizationDetails?: unknown) {
    const par = await pushPar("ap-agent", "ap-agent-auth", agentKey, {
      login_hint: "alice",
      mission_intent: JSON.stringify(missionIntent),
      ...(authorizationDetails ? { authorization_details: JSON.stringify(authorizationDetails) } : {}),
    });
    expect(par.status).toBe(201);
    const { request_uri } = (await par.json()) as { request_uri: string };

    const authUrl = `${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri })}`;
    let res = await fetch(authUrl, { redirect: "manual" });
    storeCookies(res);
    let location = res.headers.get("location") as string;
    const uid = location.split("/interaction/")[1] as string;

    // A request that derives nothing renders no approval page (#1446), so the
    // decision names no rendering: derivation refuses it before any is consulted.
    res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
      method: "POST",
      redirect: "manual",
      headers: { ...trustedApprovalHeaders(), "content-type": "application/json", cookie: cookieHeader() },
      body: JSON.stringify({ decision: "approve" }),
    });
    storeCookies(res);
    location = res.headers.get("location") as string;
    while (location?.startsWith(ISSUER)) {
      res = await fetch(location, { redirect: "manual", headers: { cookie: cookieHeader() } });
      storeCookies(res);
      location = res.headers.get("location") as string;
    }
    return new URL(location);
  }

  it("a submitted proposal that derives nothing is invalid_authorization_details", async () => {
    const badProposal: AuthorityEntry[] = [
      { type: "mission_resource_access", resource: RESOURCE, actions: ["not:a:real:action"] },
    ];
    const redirect = await decideAndGetErrorRedirect({ intent: TASK_INTENT }, badProposal);
    expect(redirect.searchParams.get("error")).toBe("invalid_authorization_details");
  });

  // @spec resource-access#initial-common-constraints (#1263, D446): differing
  // `max_amount` currencies have no intersection and the combination fails;
  // the derivation never answers with the ceiling's cap.
  it("refuses a proposal whose max_amount currency differs from the ceiling's, creating no Mission", async () => {
    const before = as.kernel.allMissions().length;
    const eurProposal: AuthorityEntry[] = [
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: ["payments:payment.schedule"],
        constraints: { max_amount: { amount: "100.00", currency: "EUR" }, vendors: ["acme"] },
      },
    ];
    const redirect = await decideAndGetErrorRedirect({ intent: TASK_INTENT }, eurProposal);
    expect(redirect.searchParams.get("error")).toBe("invalid_authorization_details");
    expect(redirect.searchParams.get("error_description")).toMatch(/currencies differ/);
    expect(as.kernel.allMissions().length).toBe(before);
  });

  it("configured-mapping mode (no proposal) that derives nothing is access_denied", async () => {
    const unmappedIntent = { ...TASK_INTENT, target_resources: ["https://unmapped.example.com"] };
    const redirect = await decideAndGetErrorRedirect({ intent: unmappedIntent });
    expect(redirect.searchParams.get("error")).toBe("access_denied");
  });
});

// @spec mission#approval-authentication — `acr_values`/`max_age` request the
// APPROVER's authentication strength, never the token Subject's. Covers the
// #636-adopted acceptance criterion: same-principal, split-principal,
// max_age=0, and unsupported-ACR, all wire-level through PAR -> /interaction
// -> decide. The trusted fixture establishes achieved context in its registered
// service principal; the decide body cannot assert identity or authentication.
describe("Approver Authentication Strength (@spec mission#approval-authentication, issue #636)", () => {
  const READ_ONLY_PROPOSAL: AuthorityEntry[] = [
    { type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] },
  ];

  // Every approval here is a trusted BROWSER approval: the Approver
  // authenticated in this user agent, with the achieved acr and time the
  // trusted login recorded. `subject` is that login's selection; absent, a
  // self-approval. oidc-provider accepts `acr_values`/`max_age` only with
  // `openid` (lib/actions/authorization/check_openid_scope.js, 9.10.0), and
  // `openid` is available only to a self-approval (#826), so a requested
  // strength is exercised on self-approvals.
  async function runApproval(args: {
    parExtra?: Record<string, string>;
    scope?: string | null;
    approver: string;
    subject?: string;
    acr?: string;
    authTime?: number;
  }): Promise<URL> {
    // A fresh user agent per approval: an earlier test's provider session for
    // another account would otherwise meet this login with oidc-provider's
    // logout confirmation (lib/actions/authorization/resume.js, 9.10.0).
    cookies.clear();
    const par = await pushPar("ap-agent", "ap-agent-auth", agentKey, {
      mission_intent: JSON.stringify({ intent: TASK_INTENT }),
      authorization_details: JSON.stringify(READ_ONLY_PROPOSAL),
      ...(args.scope === null ? {} : { scope: args.scope ?? "openid" }),
      ...(args.parExtra ?? {}),
    });
    expect(par.status).toBe(201);
    const { request_uri } = (await par.json()) as { request_uri: string };

    const authUrl = `${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri })}`;
    let res = await fetch(authUrl, { redirect: "manual" });
    storeCookies(res);
    let location = res.headers.get("location") as string;
    const uid = location.split("/interaction/")[1] as string;

    const approval = browserApprovalHeaders(
      SESSIONS,
      uid,
      {
        sub: args.approver,
        ...(args.acr ? { acr: args.acr } : {}),
        ...(args.authTime !== undefined ? { auth_time: args.authTime } : {}),
        ...(args.subject ? { subject: args.subject } : {}),
      },
      cookieHeader(),
    );
    const decideHeaders = { ...approval, "content-type": "application/json" };
    const render_revision = await renderedRevision(ISSUER, uid, decideHeaders);
    res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
      method: "POST",
      redirect: "manual",
      headers: decideHeaders,
      body: JSON.stringify({ decision: "approve", render_revision }),
    });
    storeCookies(res);
    location = res.headers.get("location") as string;
    while (location?.startsWith(ISSUER)) {
      res = await fetch(location, { redirect: "manual", headers: { cookie: cookieHeader() } });
      storeCookies(res);
      location = res.headers.get("location") as string;
    }
    return new URL(location);
  }

  it("same-principal: a self-approved Mission satisfies a requested acr_values", async () => {
    const redirect = await runApproval({
      parExtra: { acr_values: "mfa" },
      approver: "alice",
      acr: "mfa",
    });
    expect(redirect.searchParams.get("error")).toBeNull();
    expect(redirect.searchParams.get("code")).toBeTruthy();
  });

  it("split-principal: the Approver's authentication never becomes the Subject's: openid refuses, and the token carries the Subject and none of the Approver's authentication", async () => {
    // Asking for an ID Token (and with it an Approver strength) while Bob
    // approves for Alice refuses `invalid_scope` before any Mission exists.
    const refused = await runApproval({ parExtra: { acr_values: "mfa" }, approver: "bob", subject: "alice", acr: "mfa" });
    expect(refused.searchParams.get("error")).toBe("invalid_scope");
    expect(refused.searchParams.get("code")).toBeNull();

    // Without openid the approval proceeds for Alice under Bob's authentication.
    const redirect = await runApproval({ scope: null, approver: "bob", subject: "alice", acr: "mfa" });
    expect(redirect.searchParams.get("error")).toBeNull();
    const code = redirect.searchParams.get("code") as string;
    expect(code).toBeTruthy();

    const dpopKeys = await generateKeyPair("ES256", { extractable: true });
    const dpopPub = await exportJWK(dpopKeys.publicKey);
    const htu = `${ISSUER}/token`;
    let tok = await fetch(htu, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        dpop: await new SignJWT({ htu, htm: "POST" })
          .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: dpopPub })
          .setIssuedAt()
          .setJti(crypto.randomUUID())
          .sign(dpopKeys.privateKey),
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: PKCE_VERIFIER,
        resource: RESOURCE,
        client_assertion: await clientAssertion("ap-agent", "ap-agent-auth", agentKey),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
    const nonce = tok.headers.get("dpop-nonce");
    if (tok.status === 400 && nonce) {
      tok = await fetch(htu, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          dpop: await new SignJWT({ htu, htm: "POST", nonce })
            .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: dpopPub })
            .setIssuedAt()
            .setJti(crypto.randomUUID())
            .sign(dpopKeys.privateKey),
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: REDIRECT_URI,
          code_verifier: PKCE_VERIFIER,
          resource: RESOURCE,
          client_assertion: await clientAssertion("ap-agent", "ap-agent-auth", agentKey),
          client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        }).toString(),
      });
    }
    expect(tok.status).toBe(200);
    const body = (await tok.json()) as { access_token: string; id_token?: string };
    expect(body.id_token).toBeUndefined();
    const [, payloadB64] = body.access_token.split(".");
    const claims = JSON.parse(Buffer.from(payloadB64 as string, "base64url").toString()) as Record<
      string,
      unknown
    >;
    // The token's Subject is Alice, whoever authenticated.
    expect(claims.sub).toBe("alice");
    // The Approver's achieved acr/auth_time is approval-time provenance,
    // never a token claim ({{approval-authentication}}): neither the
    // top-level RFC 9068 claims nor the mission claim carry it.
    expect(claims.acr).toBeUndefined();
    expect(claims.amr).toBeUndefined();
    expect(claims.auth_time).toBeUndefined();
    expect((claims.mission as Record<string, unknown>).acr).toBeUndefined();
  });

  it("max_age=0 refuses a stale Approver authentication", async () => {
    const redirect = await runApproval({
      parExtra: { max_age: "0" },
      approver: "alice",
      authTime: Math.floor((Date.now() - 5000) / 1000),
    });
    expect(redirect.searchParams.get("error")).toBe("access_denied");
  });

  it("an unsupported acr is refused", async () => {
    const redirect = await runApproval({
      parExtra: { acr_values: "passkey" },
      approver: "alice",
      acr: "password",
    });
    expect(redirect.searchParams.get("error")).toBe("access_denied");
  });
});


/**
 * @spec mission#approval-event (steps 3 and 5), mission#authority-sources —
 * the wire contract: the approval rendering identifies the established source,
 * and an establishment refusal completes through the pending front-channel
 * authorization request as `access_denied`.
 */
describe("authority source on the approval surface (@spec mission#authority-sources)", () => {
  const SOURCE_PROPOSAL: AuthorityEntry[] = [
    { type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] },
  ];

  async function renderApproval(args: {
    clientId: string;
    kid: string;
    key: () => CryptoKey;
  }): Promise<{ uid: string; html: string }> {
    const par = await pushPar(args.clientId, args.kid, args.key(), {
      login_hint: "alice",
      mission_intent: JSON.stringify({ intent: TASK_INTENT }),
      authorization_details: JSON.stringify(SOURCE_PROPOSAL),
    });
    expect(par.status, await par.clone().text()).toBe(201);
    const { request_uri } = (await par.json()) as { request_uri: string };
    const authUrl = `${ISSUER}/auth?${new URLSearchParams({
      client_id: args.clientId,
      request_uri,
    })}`;
    let res = await fetch(authUrl, { redirect: "manual" });
    storeCookies(res);
    let location = res.headers.get("location") as string;
    const uid = location.split("/interaction/")[1] as string;

    const page = await fetch(`${ISSUER}/interaction/${uid}`, {
      headers: { cookie: cookieHeader() },
    });
    return { uid, html: await page.text() };
  }

  // The Subject is established by the AS from the pushed login_hint; only the
  // resolving Approver is a fixture input.
  async function decideAt(uid: string, approver: string): Promise<URL> {
    const decideHeaders = { ...trustedApprovalHeaders(approver), "content-type": "application/json", cookie: cookieHeader() };
    const render_revision = await renderedRevision(ISSUER, uid, decideHeaders);
    let res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
      method: "POST",
      redirect: "manual",
      headers: decideHeaders,
      body: JSON.stringify({ decision: "approve", render_revision }),
    });
    storeCookies(res);
    let location = res.headers.get("location") as string;
    while (location?.startsWith(ISSUER)) {
      res = await fetch(location, { redirect: "manual", headers: { cookie: cookieHeader() } });
      storeCookies(res);
      location = res.headers.get("location") as string;
    }
    return new URL(location);
  }

  it("renders the user-delegated source and approves", async () => {
    const { uid, html } = await renderApproval({
      clientId: "ap-agent",
      kid: "ap-agent-auth",
      key: () => agentKey,
    });
    expect(html).toContain("Authority source (whose authority this draws on)");
    expect(html).toContain("user_delegated");
    const redirect = await decideAt(uid, "bob");
    expect(redirect.searchParams.get("code")).toBeTruthy();
  });

  it("renders the organizational source with the governed policy it draws on", async () => {
    const { html } = await renderApproval({
      clientId: "governed-agent",
      kid: "governed-agent-auth",
      key: () => governedKey,
    });
    expect(html).toContain("organizational");
    expect(html).toContain("acme-accounts-payable-controls");
    expect(html).toContain("2026-09-01");
    // The policy digest is record detail, never consent context.
    expect(html).not.toContain("digest");
  });

  it("refuses access_denied at the decision when the subject discipline fails", async () => {
    // An organizational Mission MUST NOT record a human principal as its
    // Subject: the gate refuses before any anchor is computed, and the refusal
    // completes through the pending authorization request.
    const { uid } = await renderApproval({
      clientId: "governed-agent",
      kid: "governed-agent-auth",
      key: () => governedKey,
    });
    const redirect = await decideAt(uid, "bob");
    expect(redirect.searchParams.get("error")).toBe("access_denied");
    expect(redirect.searchParams.get("code")).toBeNull();
  });

  it("refuses access_denied when the Approver may not activate the source", async () => {
    // `alice` holds no activation authority over the organizational source.
    const { uid } = await renderApproval({
      clientId: "governed-agent",
      kid: "governed-agent-auth",
      key: () => governedKey,
    });
    const redirect = await decideAt(uid, "alice");
    expect(redirect.searchParams.get("error")).toBe("access_denied");
  });
});

// @spec mission#approval-event (step 5, #1503): the rendering identifies the
// OAuth client that receives the authority from the AS's registration of it.
// Clients here are the deployment's static registrations, so the registered
// name is the AS's; text the request carries, in the Intent or in a parameter
// this AS does not accept, changes nothing in that section.
describe("receiving client on the approval surface (@spec mission#approval-event, #1503)", () => {
  const HEADING = "Client receiving this authority (from this authorization server's registration)";

  async function renderClient(args: {
    clientId: string;
    kid: string;
    key: () => CryptoKey;
    goal?: string;
    extra?: Record<string, string>;
  }): Promise<{ html: string; section: string }> {
    const par = await pushPar(args.clientId, args.kid, args.key(), {
      login_hint: "alice",
      mission_intent: JSON.stringify({ intent: { ...TASK_INTENT, ...(args.goal ? { goal: args.goal } : {}) } }),
      authorization_details: JSON.stringify([
        { type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] },
      ]),
      ...args.extra,
    });
    expect(par.status, await par.clone().text()).toBe(201);
    const { request_uri } = (await par.json()) as { request_uri: string };
    const auth = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: args.clientId, request_uri })}`, {
      redirect: "manual",
    });
    storeCookies(auth);
    const uid = (auth.headers.get("location") as string).split("/interaction/")[1] as string;
    const page = await fetch(`${ISSUER}/interaction/${uid}`, { headers: { cookie: cookieHeader() } });
    const html = await page.text();
    expect(page.status, html).toBe(200);
    const section = html.match(/<section class="receiving-client">([\s\S]*?)<\/section>/)?.[1] ?? "";
    return { html, section };
  }

  it("names the receiving client by its registered client_id and name, labeled as the AS's registration", async () => {
    const agent = await renderClient({ clientId: "ap-agent", kid: "ap-agent-auth", key: () => agentKey });
    expect(agent.section).toContain(HEADING);
    expect(agent.section).toContain('<code class="client-id">ap-agent</code>');
    expect(agent.section).toContain('Registered name: <span class="client-name">AP Agent</span>');
    // Each page names its own interaction's client, never a fixed one.
    const governed = await renderClient({ clientId: "governed-agent", kid: "governed-agent-auth", key: () => governedKey });
    expect(governed.section).toContain('<code class="client-id">governed-agent</code>');
    expect(governed.section).toContain(
      'Registered name: <span class="client-name">Governed Agent (Mission-governed registration)</span>',
    );
    expect(governed.section).not.toContain("AP Agent");
  });

  it("keeps the registered identification when the request carries a different client-supplied name", async () => {
    // Another registered client's name, claimed in the Intent the client
    // writes and in a `client_name` request parameter.
    const claimed = "Ledger Reconciler";
    const { html, section } = await renderClient({
      clientId: "ap-agent",
      kid: "ap-agent-auth",
      key: () => agentKey,
      goal: `Pay Acme invoices as ${claimed}`,
      extra: { client_name: claimed },
    });
    expect(section).toContain('<code class="client-id">ap-agent</code>');
    expect(section).toContain('Registered name: <span class="client-name">AP Agent</span>');
    expect(section).not.toContain(claimed);
    expect(section).not.toContain("ledger-reconciler");
    // The claim reaches the page only as untrusted task context.
    const intent = html.split("Intent (task context, untrusted)")[1] as string;
    expect(intent).toContain(claimed);
  });
});
