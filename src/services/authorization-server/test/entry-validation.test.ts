/**
 * @spec resource-access#entry-validation (#1376)
 *
 * The validity rules a `mission_resource_access` entry meets beyond each
 * member's type: a non-empty `actions` array whose every value matches the
 * action grammar, a non-negative integer `delegation.max_depth`, a
 * `time_window` whose `not_before` is not later than its `not_after`, a
 * `recipient_domain` in ASCII form without a trailing dot, and a `resource`
 * that is one RFC 3986 `absolute-URI` (no fragment; an `http` or `https`
 * value names a non-empty host). Each is refused at PAR with
 * `invalid_authorization_details`, before any interaction or Mission.
 *
 * Two values pass validation and carry a defined meaning instead: a
 * `max_depth` of 0 admits no delegated token yet leaves the entry's
 * child-creation grant intact, and an empty `allowed_delegates` admits no
 * delegate, unlike an absent list, which defers to the delegation policy.
 */

import { type Server } from "node:http";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { type CryptoKey, generateKeyPair, importJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  type BuiltAs,
  buildAuthorizationServer,
  createChildMission,
  MissionKernel,
  validateMissionIntent,
} from "../src/index.js";
import { aiAgents } from "./actor-profiles.helper.js";
import { TEST_APPROVAL_PRINCIPALS } from "./approval-fixture.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const PORT = 14376;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
const TASK_INTENT = {
  goal: "Pay Acme invoices for Q3",
  target_resources: [RESOURCE],
  expires_at: "2027-01-01T00:00:00Z",
};
const READ = "payments:invoice.read";

let as: BuiltAs;
let asServer: Server;
let agentKey: CryptoKey;

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

const PKCE_VERIFIER = "entry-validation-verifier-0123456789-0123456789-0";
async function pkceChallenge(): Promise<string> {
  return Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(PKCE_VERIFIER)),
  ).toString("base64url");
}

/** Push one proposal entry with the task Intent through PAR. */
async function pushEntry(entry: Record<string, unknown>): Promise<Response> {
  return fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      resource: RESOURCE,
      code_challenge: await pkceChallenge(),
      code_challenge_method: "S256",
      login_hint: "alice",
      mission_intent: JSON.stringify({ intent: TASK_INTENT }),
      authorization_details: JSON.stringify([entry]),
      client_assertion: await clientAssertion("ap-agent", "ap-agent-auth", agentKey),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
}

const entry = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  type: "mission_resource_access",
  resource: RESOURCE,
  actions: [READ],
  ...over,
});

/** PAR refuses the entry with invalid_authorization_details, issuing no request_uri and creating no Mission. */
async function expectRefused(proposal: Record<string, unknown>, description: RegExp): Promise<void> {
  const before = as.kernel.allMissions().length;
  const res = await pushEntry(proposal);
  const body = (await res.json()) as { error?: string; error_description?: string; request_uri?: string };
  const label = JSON.stringify(proposal);
  expect(res.status, label).toBe(400);
  expect(body.error, label).toBe("invalid_authorization_details");
  expect(body.error_description, label).toMatch(description);
  expect(body.request_uri, label).toBeUndefined();
  expect(as.kernel.allMissions().length, label).toBe(before);
}

/** PAR accepts the entry. */
async function expectAccepted(proposal: Record<string, unknown>): Promise<void> {
  const res = await pushEntry(proposal);
  const body = (await res.json()) as { error_description?: string; request_uri?: string };
  expect(res.status, `${JSON.stringify(proposal)}: ${body.error_description ?? ""}`).toBe(201);
  expect(body.request_uri).toBeDefined();
}

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
  });
  asServer = as.provider.listen(PORT);
  agentKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
});

afterAll(() => {
  asServer?.close();
});

describe("entry validation at PAR (@spec resource-access#entry-validation, #1376)", () => {
  it("refuses a proposal entry whose actions array is empty", async () => {
    await expectRefused(entry({ actions: [] }), /actions must be a non-empty array/);
  });

  // The provider's RFC 9396 common-field check already refuses an empty
  // string; every value below reaches this implementation's grammar check.
  it("refuses an action value outside the grammar, wherever the offending character sits", async () => {
    for (const bad of [
      "payments/invoice.read",
      "payments:invoice.read ",
      " payments:invoice.read",
      "payments:invoice.read\n",
      "payments:invoice.*.read",
      "*",
      "payments:facture.rédiger",
    ]) {
      await expectRefused(entry({ actions: [READ, bad] }), /is neither an action identifier nor an action family/);
    }
  });

  it("accepts action identifiers and an action family the grammar admits (positive control)", async () => {
    await expectAccepted(entry({ actions: [READ, "payments:invoice.list"] }));
    await expectAccepted(entry({ actions: ["payments:invoice.*"] }));
    await expectAccepted(entry({ actions: ["A_z-0.9:x"] }));
  });

  it("refuses a negative or fractional delegation.max_depth", async () => {
    for (const max_depth of [-1, 1.5]) {
      await expectRefused(
        entry({ delegation: { max_depth } }),
        /delegation\.max_depth must be a non-negative integer/,
      );
    }
  });

  it("accepts a delegation.max_depth of 0, with and without a children grant (positive control)", async () => {
    await expectAccepted(entry({ delegation: { max_depth: 0 } }));
    await expectAccepted(entry({ delegation: { max_depth: 0, children: { max_children: 2 } } }));
  });

  it("refuses a time_window whose not_before is later than its not_after, and accepts equal bounds", async () => {
    await expectRefused(
      entry({
        constraints: {
          time_window: { not_before: "2026-09-01T00:00:00Z", not_after: "2026-08-31T23:59:59Z" },
        },
      }),
      /constraints\.time_window is malformed/,
    );
    // Instants, not spellings: 02:00+02:00 is midnight UTC, earlier than 01:00Z.
    await expectRefused(
      entry({
        constraints: {
          time_window: { not_before: "2026-09-01T01:00:00Z", not_after: "2026-09-01T02:00:00+02:00" },
        },
      }),
      /constraints\.time_window is malformed/,
    );
    await expectAccepted(
      entry({
        constraints: {
          time_window: { not_before: "2026-09-01T00:00:00Z", not_after: "2026-09-01T02:00:00+02:00" },
        },
      }),
    );
  });

  it("refuses a recipient_domain that is not an ASCII DNS name or that ends in a dot", async () => {
    for (const recipient_domain of ["example.com.", "exämple.com", "example..com", ""]) {
      await expectRefused(
        entry({ constraints: { recipient_domain } }),
        /constraints\.recipient_domain is malformed/,
      );
    }
  });

  it("accepts a recipient_domain in A-label form, in any letter case (positive control)", async () => {
    for (const recipient_domain of ["xn--exmple-cua.com", "Mail.Example.COM"]) {
      await expectAccepted(entry({ constraints: { recipient_domain } }));
    }
  });

  it("refuses a resource carrying a fragment, or an https resource without the // form and a non-empty host", async () => {
    for (const resource of [`${RESOURCE}#tools`, "https:///mcp", "https:localhost/mcp"]) {
      await expectRefused(entry({ resource }), /is not an RFC 3986 absolute URI/);
    }
  });
});

describe("max_depth 0 and an empty allowed_delegates (@spec resource-access#entry-validation, #1376)", () => {
  const ISS = "https://as.entry-validation.test";
  const ERP = "https://erp.example.com";
  let key: CryptoKey;
  let seq = 0;

  beforeAll(async () => {
    key = (await generateKeyPair("ES256")).privateKey;
  });

  /** A kernel over one ceiling entry, with a delegation policy permitting exactly `permit`. */
  function kernelFor(ceiling: AuthorityEntry[], permit: string[] = []): MissionKernel {
    return new MissionKernel({
      issuer: ISS,
      policy: { policy_version: "entry-validation", ceiling },
      authoritySourceCatalog: testAuthoritySourceCatalog(ceiling, ["agent"], ["bob"]),
      statusKey: key,
      statusKid: "as-status",
      actorProfiles: aiAgents("subagent-extractor"),
      delegationPolicy: ({ delegate }) => permit.includes(delegate.sub),
    });
  }

  function approve(kernel: MissionKernel, proposal: AuthorityEntry[]) {
    return kernel.approve({
      intent: validateMissionIntent(
        JSON.stringify({ goal: "Read invoices", target_resources: [ERP], expires_at: "2099-01-01T00:00:00Z" }),
      ),
      proposedAuthority: proposal,
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "agent",
      approvalEventId: `apev-entry-validation-${seq++}`,
    });
  }

  const erpEntry = (delegation?: AuthorityEntry["delegation"]): AuthorityEntry => ({
    type: "mission_resource_access",
    resource: ERP,
    actions: ["invoices.read"],
    ...(delegation ? { delegation } : {}),
  });

  /** The eligibility outcome for `sub` at delegation depth `depth` over the Mission's one entry. */
  function eligibility(kernel: MissionKernel, missionId: string, sub: string, depth: number): string | undefined {
    const record = kernel.get(missionId);
    if (!record) throw new Error("no Mission");
    const candidates = kernel.effectiveDelegationCandidates(record);
    expect(candidates).toHaveLength(1);
    return kernel.delegationEligibility(record, candidates, { sub }, depth)[0]?.outcome;
  }

  it("max_depth 0 admits no delegated token, while the entry's children grant still creates a Child Mission", () => {
    const children = { max_children: 2, allowed_child_actors: [{ sub_profile: "ai_agent" }] };
    const kernel = kernelFor([erpEntry({ max_depth: 0, children })], ["bob"]);
    const parent = approve(kernel, [erpEntry({ max_depth: 0, children })]);
    // The committed entry keeps both: depth 0 does not void the child-creation grant.
    expect(parent.authority_set[0]?.delegation).toEqual({ max_depth: 0, children });
    // No delegated token, even for a delegate the policy permits: depth 1 exceeds 0.
    expect(eligibility(kernel, parent.id, "bob", 1)).toBe("not-eligible");
    // The children grant, bounded on its own, still creates a Child Mission.
    const { child } = createChildMission(kernel, {
      parentId: parent.id,
      intent: validateMissionIntent(
        JSON.stringify({ goal: "Extract invoices", target_resources: [ERP], expires_at: "2099-01-01T00:00:00Z" }),
      ),
      proposedAuthority: [erpEntry()],
      childActor: { sub: "subagent-extractor", sub_profile: "ai_agent" },
    });
    expect(child.state).toBe("active");
  });

  it("an empty allowed_delegates admits no delegate the policy permits, where an absent list defers to that policy", () => {
    const listed = kernelFor([erpEntry({ max_depth: 2, allowed_delegates: [] })], ["bob"]);
    const empty = approve(listed, [erpEntry({ max_depth: 2, allowed_delegates: [] })]);
    expect(empty.authority_set[0]?.delegation).toEqual({ max_depth: 2, allowed_delegates: [] });
    expect(eligibility(listed, empty.id, "bob", 1)).toBe("not-eligible");

    const deferred = kernelFor([erpEntry({ max_depth: 2 })], ["bob"]);
    const absent = approve(deferred, [erpEntry({ max_depth: 2 })]);
    expect(eligibility(deferred, absent.id, "bob", 1)).toBe("eligible");
    expect(eligibility(deferred, absent.id, "carol", 1)).toBe("not-eligible");
  });
});
