/**
 * @spec resource-access#resource-contract (#249, D553): approval-time
 * assembly and the unsupported-member refusal at the endpoints.
 *
 * - Where configuration requires a reference for the entry's `resource`
 *   and the proposal carries none, the authorization server records the
 *   current contract's reference before the Approver approves, and the
 *   issued token carries it.
 * - An authorization server with no contract configured refuses a pushed
 *   entry carrying `resource_contract` with `invalid_authorization_details`
 *   and never issues the entry without the member.
 */

import type { Server } from "node:http";
import { ResourceContractDeclarations, type ResourceContractRef } from "@mission/core";
import { DERIVATION_POLICY, RESOURCE_CONTRACTS } from "@mission/demo-data";
import { exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type AuthorityEntry, type BuiltAs, buildAuthorizationServer } from "../src/index.js";
import { TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";

const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = DERIVATION_POLICY.ceiling[0]?.resource as string;
const READ = "payments:invoice.read";
const VERIFIER = "resource-contract-assembly-verifier-0123456789-01234";

const [DECLARED] = RESOURCE_CONTRACTS.declarations;
const CURRENT = DECLARED?.versions.find((v) => v.state === "current");
const SHIPPED: ResourceContractRef = { id: DECLARED?.id as string, version: CURRENT?.version as string, digest: CURRENT?.digest as string };
/** The shipped declaration, requiring a reference for the read. */
const REQUIRED = new ResourceContractDeclarations([
  {
    resource: DECLARED?.resource,
    resource_match: DECLARED?.resource_match,
    id: DECLARED?.id,
    requires_reference: [READ],
    versions: [{ version: CURRENT?.version, state: "current", digest: CURRENT?.digest, document: CURRENT?.document }],
  },
]);

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };
type Json = Record<string, unknown>;

interface Harness {
  as: BuiltAs;
  issue(proposal: AuthorityEntry[]): Promise<{ at: string; missionId: string }>;
  push(proposal: AuthorityEntry[]): Promise<{ status: number; body: Json }>;
  close(): Promise<void>;
}

async function harness(port: number, resourceContracts: ResourceContractDeclarations): Promise<Harness> {
  const issuer = `http://localhost:${port}`;
  const as = await buildAuthorizationServer({
    issuer,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    resourceContracts,
  });
  const server: Server = as.provider.listen(port);
  await new Promise<void>((r) => server.once("listening", () => r()));
  const clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  const assertion = () =>
    new SignJWT({})
      .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
      .setIssuer("ap-agent")
      .setSubject("ap-agent")
      .setAudience(issuer)
      .setIssuedAt()
      .setExpirationTime("2m")
      .setJti(crypto.randomUUID())
      .sign(clientKey);
  const push = async (proposal: AuthorityEntry[]) => {
    const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER))).toString("base64url");
    const res = await fetch(`${issuer}/request`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: "ap-agent",
        response_type: "code",
        redirect_uri: REDIRECT_URI,
        resource: RESOURCE,
        code_challenge: challenge,
        code_challenge_method: "S256",
        login_hint: "alice",
        mission_intent: JSON.stringify({
          intent: { goal: "Review third-quarter Acme invoices", target_resources: [RESOURCE], expires_at: "2027-06-01T00:00:00Z" },
        }),
        authorization_details: JSON.stringify(proposal),
        client_assertion: await assertion(),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
    return { status: res.status, body: (await res.json()) as Json };
  };
  const token = async (params: Record<string, string>, keys: Keys) => {
    const proof = async (extra: Json = {}) =>
      new SignJWT({ htu: `${issuer}/token`, htm: "POST", ...extra })
        .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
        .setIssuedAt()
        .setJti(crypto.randomUUID())
        .sign(keys.privateKey);
    const send = async (extra: Json = {}) =>
      fetch(`${issuer}/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", dpop: await proof(extra) },
        body: new URLSearchParams({
          ...params,
          client_assertion: await assertion(),
          client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        }).toString(),
      });
    let res = await send();
    const nonce = res.headers.get("dpop-nonce");
    if (res.status === 400 && nonce) res = await send({ nonce });
    return { status: res.status, body: (await res.json()) as Json };
  };
  const issue = async (proposal: AuthorityEntry[]) => {
    const pushed = await push(proposal);
    expect(pushed.status, JSON.stringify(pushed.body)).toBe(201);
    const jar = new Map<string, string>();
    const keep = (res: Response) => {
      for (const line of res.headers.getSetCookie()) {
        const [pair] = line.split(";");
        const eq = (pair as string).indexOf("=");
        jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
      }
    };
    const cookie = () => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
    let res = await fetch(`${issuer}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: String(pushed.body.request_uri) })}`, {
      redirect: "manual",
    });
    keep(res);
    const uid = (res.headers.get("location") ?? "").split("/interaction/")[1] as string;
    res = await fetch(`${issuer}/interaction/${uid}/decide`, {
      method: "POST",
      redirect: "manual",
      headers: { ...trustedApprovalHeaders(), "content-type": "application/json", cookie: cookie() },
      body: JSON.stringify({ decision: "approve" }),
    });
    keep(res);
    let location = res.headers.get("location") ?? "";
    while (location.startsWith(issuer)) {
      res = await fetch(location, { redirect: "manual", headers: { cookie: cookie() } });
      keep(res);
      location = res.headers.get("location") ?? "";
    }
    const code = new URL(location).searchParams.get("code");
    expect(code, location).toBeTruthy();
    const keys = (await generateKeyPair("ES256", { extractable: true })) as Keys;
    const exchanged = await token(
      { grant_type: "authorization_code", code: code as string, redirect_uri: REDIRECT_URI, code_verifier: VERIFIER, resource: RESOURCE },
      keys,
    );
    expect(exchanged.status, JSON.stringify(exchanged.body)).toBe(200);
    const at = exchanged.body.access_token as string;
    return { at, missionId: (claims(at).mission as { id: string }).id };
  };
  return { as, issue, push, close: () => new Promise<void>((r) => server.close(() => r())) };
}

const claims = (jwt: string): Json => JSON.parse(Buffer.from(jwt.split(".")[1] as string, "base64url").toString()) as Json;
const read = (r?: ResourceContractRef): AuthorityEntry[] => [
  {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions: [READ],
    constraints: { vendors: ["acme"] },
    ...(r ? { resource_contract: r } : {}),
  } as AuthorityEntry,
];

describe("where configuration requires a reference, the authorization server records the current one before approval (@spec resource-access#resource-contract, #249)", () => {
  let h: Harness;
  beforeAll(async () => {
    h = await harness(14252, REQUIRED);
  });
  afterAll(async () => {
    await h.close();
  });

  it("an entry proposed without a reference is approved and issued carrying the configured current reference", async () => {
    const issued = await h.issue(read());
    expect(h.as.kernel.get(issued.missionId)?.authority_set.map((e) => e.resource_contract)).toEqual([SHIPPED]);
    expect((claims(issued.at).authorization_details as AuthorityEntry[]).map((e) => e.resource_contract)).toEqual([SHIPPED]);
  });
});

describe("an authorization server with no contract configured refuses the member and never drops it (@spec resource-access#resource-contract, #249)", () => {
  let h: Harness;
  beforeAll(async () => {
    h = await harness(14253, ResourceContractDeclarations.NONE);
  });
  afterAll(async () => {
    await h.close();
  });

  it("refuses a pushed entry carrying resource_contract with invalid_authorization_details, creating no Mission", async () => {
    const before = h.as.kernel.allMissions().length;
    const res = await h.push(read(SHIPPED));
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_authorization_details");
    expect(res.body.error_description).toMatch(/resource_contract/);
    expect(h.as.kernel.allMissions().length).toBe(before);
    // The same entry without the member is the ordinary path (control).
    const plain = await h.issue(read());
    expect((claims(plain.at).authorization_details as AuthorityEntry[]).map((e) => e.resource_contract)).toEqual([undefined]);
  });
});
