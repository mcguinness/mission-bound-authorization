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

import { type Server } from "node:http";
import { computeAnchor, PROPOSED_AUTHORITY_TYP, proposalHash } from "@mission/core";
import { DERIVATION_POLICY, DEV_SERVICE_TOKEN } from "@mission/demo-data";
import { buildInsufficientAuthorization } from "@mission/mcp-payments";
import { exportJWK, generateKeyPair, importJWK, SignJWT, type CryptoKey } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  buildAuthorizationServer,
  IntentError,
  MissionKernel,
  validateAuthorityProposal,
  validateMissionIntent,
  type AuthorityEntry,
  type BuiltAs,
} from "../src/index.js";

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
  resources: [RESOURCE],
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
    // @spec mission#the-mission-claim — zero claim changes: the exact key set.
    const claim = kernel.missionClaim(record);
    expect(Object.keys(claim).sort()).toEqual([
      "approval_basis",
      "authority_hash",
      "expires_at",
      "id",
      "issuer",
    ]);
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
      TASK_INTENT.resources,
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
        TASK_INTENT.resources,
      ),
    ).toThrowError(/unsupported authorization details type/);
    try {
      validateAuthorityProposal(
        JSON.stringify([{ type: "mission_resource_access", resource: RESOURCE, actions: [] }]),
        TASK_INTENT.resources,
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
        TASK_INTENT.resources,
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
      scope: "payments",
      resource: RESOURCE,
      code_challenge: await pkceChallenge(),
      code_challenge_method: "S256",
      ...params,
      client_assertion: await clientAssertion(clientId, kid, key),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
}

beforeAll(async () => {
  as = await buildAuthorizationServer({ issuer: ISSUER, allowHeadlessAdjudication: true });
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
      mission_intent: JSON.stringify(TASK_INTENT),
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
    // The spec deliberately pins no error code for this rejection (mirrors the
    // AAuth missionless-request rule); this implementation chose invalid_request.
    expect(body.error).toBe("invalid_request");
  });

  it("a governed client submitting the proposal WITH mission_intent proceeds", async () => {
    const res = await pushPar("governed-agent", "governed-agent-auth", governedKey, {
      mission_intent: JSON.stringify(TASK_INTENT),
      authorization_details: JSON.stringify(PROPOSAL),
    });
    expect(res.status).toBe(201);
  });

  it("refuses a pushed Intent that carries the retired proposed_authority member", async () => {
    const res = await pushPar("ap-agent", "ap-agent-auth", agentKey, {
      mission_intent: JSON.stringify({ ...TASK_INTENT, proposed_authority: PROPOSAL }),
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe("invalid_request");
  });

  it("refuses a proposal entry whose resource is not among the Intent resources", async () => {
    const res = await pushPar("ap-agent", "ap-agent-auth", agentKey, {
      mission_intent: JSON.stringify(TASK_INTENT),
      authorization_details: JSON.stringify([
        { type: "mission_resource_access", resource: "https://other.example", actions: ["a"] },
      ]),
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe("invalid_request");
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
      mission_intent: JSON.stringify(TASK_INTENT),
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

    res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
      method: "POST",
      redirect: "manual",
      headers: { "content-type": "application/json", cookie: cookieHeader() },
      body: JSON.stringify({ decision: "approve", approver: "bob", subject: "alice" }),
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
    };

    // The granted echo is the ISSUER-DERIVED set (a same-type subset of the
    // proposal), never the submission carried through by right: the over-asked
    // cap narrows to the policy ceiling and the ungrantable action is dropped.
    expect(body.authorization_details.length).toBeGreaterThan(0);
    for (const entry of body.authorization_details) {
      expect(entry.type).toBe("mission_resource_access");
      expect(entry.resource).toBe(RESOURCE);
      expect(entry.actions).not.toContain("payments:acquire.company");
      expect(entry.constraints?.max_amount?.amount).toBe("500.00");
    }

    // Zero claim changes: the mission claim never carries the proposal members.
    const claims = JSON.parse(
      Buffer.from(body.access_token.split(".")[1] as string, "base64url").toString(),
    ) as { mission: Record<string, unknown> };
    expect(Object.keys(claims.mission).sort()).toEqual([
      "approval_basis",
      "authority_hash",
      "expires_at",
      "id",
      "issuer",
    ]);

    // The record committed the submitted proposal; introspection (issuer-only
    // surface) reports proposal_hash beside state.
    const missionId = claims.mission.id as string;
    const record = as.kernel.get(missionId);
    expect(record?.proposed_authority).toEqual(OVER_ASK);
    expect(record?.proposal_hash).toBe(proposalHash(ISSUER, OVER_ASK as never));
    const introspection = await fetch(`${ISSUER}/introspect`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
      body: JSON.stringify({ token: body.access_token }),
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
